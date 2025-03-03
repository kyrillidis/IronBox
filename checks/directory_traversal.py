#!/usr/bin/env python3
"""
Directory Traversal vulnerability check module.
Checks for path traversal vulnerabilities that could expose sensitive files.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re
from core.vulnerabilities import VulnerabilityCheck

class Check(VulnerabilityCheck):
    """Directory Traversal vulnerability check"""
    
    def __init__(self):
        """Initialize the Directory Traversal check"""
        super().__init__()
        self.name = "Directory Traversal"
        self.description = "Checks for path traversal vulnerabilities that could allow attackers to access files outside the web root."
        
        # Test payloads - include various path traversal techniques
        self.payloads = [
            "../../../etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "....//....//....//etc/passwd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "/etc/passwd",
            "../../../../../../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "..%5c..%5c..%5cwindows%5cwin.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        # Patterns that may indicate successful directory traversal
        self.success_patterns = [
            # Linux /etc/passwd indicators
            "root:.*:0:0:",
            "nobody:.*:65534:",
            "daemon:.*:1:1:",
            
            # Windows win.ini indicators
            "\\[fonts\\]",
            "\\[extensions\\]",
            "\\[mci extensions\\]",
            
            # Common sensitive file snippets
            "DB_PASSWORD",
            "database_password",
            "AuthType",
            "AuthName",
            "AuthUserFile",
            "<web-app",
            "<?php",
            "<?xml version"
        ]
        
        self.timeout = 10
    
    def run(self, target_url):
        """Run the Directory Traversal vulnerability check
        
        Args:
            target_url: URL to check for directory traversal vulnerabilities
            
        Returns:
            dict: Check results
        """
        result = {
            'vulnerable': False,
            'details': [],
            'description': self.description
        }
        
        # Check URL parameters for directory traversal
        self._check_url_parameters(target_url, result)
        
        # Check path-based directory traversal
        self._check_path_traversal(target_url, result)
        
        return result
    
    def _check_url_parameters(self, url, result):
        """Check URL parameters for directory traversal
        
        Args:
            url: Target URL to check
            result: Result dictionary to update
        """
        parsed_url = urlparse(url)
        if not parsed_url.query:
            return
        
        params = parse_qs(parsed_url.query)
        for param_name, param_values in params.items():
            # Skip parameters that are unlikely to be used for file paths
            if param_name.lower() in ['id', 'page', 'p', 'post']:
                continue
                
            for payload in self.payloads:
                test_url = self._inject_payload_to_url(url, param_name, payload)
                
                try:
                    # Send request with the injected payload
                    response = requests.get(test_url, timeout=self.timeout)
                    
                    # Check if the response indicates successful directory traversal
                    if self._check_response_for_traversal(response):
                        result['vulnerable'] = True
                        result['details'].append({
                            'url': test_url,
                            'type': 'Parameter-based Directory Traversal',
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': self._extract_evidence(response.text)
                        })
                        # Once we find a vulnerability with one payload, move to the next parameter
                        break
                
                except (requests.RequestException, UnicodeDecodeError, ConnectionError):
                    continue
    
    def _check_path_traversal(self, url, result):
        """Check for path-based directory traversal
        
        Args:
            url: Target URL to check
            result: Result dictionary to update
        """
        parsed_url = urlparse(url)
        path_parts = parsed_url.path.split('/')
        
        # Skip if the path is just '/'
        if len(path_parts) <= 1:
            return
        
        # Test replacing the last path component with our payloads
        base_path = '/'.join(path_parts[:-1]) + '/'
        
        for payload in self.payloads:
            # Construct test URL with traversal payload in path
            test_path = base_path + payload
            test_url = urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                test_path,
                parsed_url.params,
                parsed_url.query,
                parsed_url.fragment
            ))
            
            try:
                # Send request with the injected payload
                response = requests.get(test_url, timeout=self.timeout)
                
                # Check if the response indicates successful directory traversal
                if self._check_response_for_traversal(response):
                    result['vulnerable'] = True
                    result['details'].append({
                        'url': test_url,
                        'type': 'Path-based Directory Traversal',
                        'path': test_path,
                        'payload': payload,
                        'evidence': self._extract_evidence(response.text)
                    })
                    # Once we find a vulnerability, stop testing this path
                    break
            
            except (requests.RequestException, UnicodeDecodeError, ConnectionError):
                continue
    
    def _check_response_for_traversal(self, response):
        """Check if a response indicates successful directory traversal
        
        Args:
            response: HTTP response
            
        Returns:
            bool: True if the response indicates directory traversal, False otherwise
        """
        # Check for successful HTTP status
        if response.status_code != 200:
            return False
        
        # Check content for patterns that indicate successful traversal
        for pattern in self.success_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True
        
        return False
    
    def _extract_evidence(self, response_text):
        """Extract evidence of directory traversal from response text
        
        Args:
            response_text: HTTP response text
            
        Returns:
            str: Evidence of directory traversal
        """
        for pattern in self.success_patterns:
            match = re.search(f'.{{0,50}}{pattern}.{{0,50}}', response_text, re.IGNORECASE)
            if match:
                return match.group(0)
        
        return "Response indicates possible directory traversal"
    
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