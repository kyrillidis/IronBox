#!/usr/bin/env python3
"""
SQL Injection check module.
Checks for SQL Injection vulnerabilities in web applications.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re
from bs4 import BeautifulSoup
from core.vulnerabilities import VulnerabilityCheck

class Check(VulnerabilityCheck):
    """SQL Injection vulnerability check"""
    
    def __init__(self):
        """Initialize the SQLi check"""
        super().__init__()
        self.name = "SQLi"
        self.description = "Checks for SQL Injection vulnerabilities which allow attackers to manipulate database queries."
        
        # SQLi test payloads
        self.payloads = [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "1' OR '1'='1' -- ",
            "1\" OR \"1\"=\"1\" -- ",
            "' OR 1=1 -- ",
            "\" OR 1=1 -- ",
            "' OR '1'='1' /*",
            "\" OR \"1\"=\"1\" /*",
            "') OR ('1'='1",
            "\") OR (\"1\"=\"1"
        ]
        
        # Error patterns that indicate SQL injection vulnerability
        self.error_patterns = [
            "SQL syntax",
            "mysql_fetch_array",
            "mysqli_fetch_array",
            "ORA-[0-9]",
            "MySQL server version",
            "You have an error in your SQL syntax",
            "SQLite3::query",
            "Microsoft OLE DB Provider for SQL Server",
            "PostgreSQL query failed",
            "pg_query()"
        ]
        
        # Request timeout
        self.timeout = 10
    
    def run(self, target_url):
        """Run the SQLi vulnerability check
        
        Args:
            target_url: URL to check for SQLi vulnerabilities
            
        Returns:
            dict: Check results
        """
        result = {
            'vulnerable': False,
            'details': [],
            'description': self.description
        }
        
        # Check URL parameters for SQLi
        self._check_url_parameters(target_url, result)
        
        # Scan the target URL for forms
        forms = self._extract_forms(target_url)
        
        # Check each form for SQLi
        for form in forms:
            self._check_form(form, result)
        
        return result
    
    def _check_url_parameters(self, url, result):
        """Check URL parameters for SQLi vulnerabilities
        
        Args:
            url: Target URL to check
            result: Result dictionary to update
        """
        parsed_url = urlparse(url)
        if not parsed_url.query:
            return
        
        params = parse_qs(parsed_url.query)
        for param_name, param_values in params.items():
            for payload in self.payloads:
                test_url = self._inject_payload_to_url(url, param_name, payload)
                
                try:
                    # Send request with the injected payload
                    response = requests.get(test_url, timeout=self.timeout)
                    
                    # Check if the response indicates an SQL injection vulnerability
                    if self._check_response_for_sqli(response):
                        result['vulnerable'] = True
                        result['details'].append({
                            'url': test_url,
                            'type': 'SQL Injection',
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': self._extract_evidence(response.text)
                        })
                        # Once we find a vulnerability with one payload, move to the next parameter
                        break
                
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
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                # Get form action
                action = form.get('action', '')
                if action:
                    # Make sure action URL is absolute
                    if not action.startswith(('http://', 'https://')):
                        action = self._make_absolute_url(url, action)
                else:
                    # If no action is specified, use the current page
                    action = url
                
                # Get form method
                method = form.get('method', 'get').lower()
                
                # Get form inputs
                inputs = []
                for input_field in form.find_all(['input', 'textarea', 'select']):
                    input_name = input_field.get('name')
                    if input_name:
                        input_type = input_field.get('type', '')
                        
                        # Skip submit/button/image/hidden inputs
                        if input_type not in ('submit', 'button', 'image', 'hidden'):
                            inputs.append({
                                'name': input_name,
                                'type': input_type
                            })
                
                # Add form to the list if it has inputs
                if inputs:
                    forms.append({
                        'action': action,
                        'method': method,
                        'inputs': inputs
                    })
            
        except (requests.RequestException, UnicodeDecodeError, ConnectionError):
            pass
        
        return forms
    
    def _check_form(self, form, result):
        """Check a form for SQLi vulnerabilities
        
        Args:
            form: Form dictionary with action, method, and inputs
            result: Result dictionary to update
        """
        action = form['action']
        method = form['method']
        inputs = form['inputs']
        
        # Test each input field with each payload
        for input_field in inputs:
            input_name = input_field['name']
            
            for payload in self.payloads:
                # Create form data with the test payload
                data = {}
                for inp in inputs:
                    if inp['name'] == input_name:
                        data[inp['name']] = payload
                    else:
                        data[inp['name']] = 'test'  # Default value for other inputs
                
                try:
                    # Send the request with the payload
                    if method == 'post':
                        response = requests.post(action, data=data, timeout=self.timeout)
                    else:  # GET method
                        response = requests.get(action, params=data, timeout=self.timeout)
                    
                    # Check if the response indicates an SQL injection vulnerability
                    if self._check_response_for_sqli(response):
                        result['vulnerable'] = True
                        result['details'].append({
                            'url': action,
                            'type': 'Form-based SQL Injection',
                            'parameter': input_name,
                            'payload': payload,
                            'method': method.upper(),
                            'evidence': self._extract_evidence(response.text)
                        })
                        # Once we find a vulnerability with one payload, move to the next input
                        break
                
                except (requests.RequestException, UnicodeDecodeError, ConnectionError):
                    continue
    
    def _check_response_for_sqli(self, response):
        """Check if a response indicates SQL injection vulnerability
        
        Args:
            response: HTTP response
            
        Returns:
            bool: True if the response indicates an SQL injection vulnerability, False otherwise
        """
        # Check for SQL error patterns in the response content
        for pattern in self.error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True
        
        # Additional checks can be implemented here:
        # - Check for unexpected number of results
        # - Check for boolean-based injection indicators
        # - Check for time-based injection indicators
        
        return False
    
    def _extract_evidence(self, response_text):
        """Extract evidence of SQL injection from response text
        
        Args:
            response_text: HTTP response text
            
        Returns:
            str: Evidence of SQL injection
        """
        for pattern in self.error_patterns:
            match = re.search(f'.{{0,50}}{pattern}.{{0,50}}', response_text, re.IGNORECASE)
            if match:
                return match.group(0)
        
        return "Response indicates possible SQL injection"
    
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
            parsed_base = urlparse(base_url)
            return f"{parsed_base.scheme}://{parsed_base.netloc}{relative_url}"
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