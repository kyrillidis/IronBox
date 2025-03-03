#!/usr/bin/env python3
"""
Security Headers check module.
Checks for proper implementation of HTTP security headers.
"""

import requests
from core.vulnerabilities import VulnerabilityCheck

class Check(VulnerabilityCheck):
    """Security Headers vulnerability check"""
    
    def __init__(self):
        """Initialize the Security Headers check"""
        super().__init__()
        self.name = "Security Headers"
        self.description = "Checks for missing or improperly configured HTTP security headers."
        
        # Security headers to check
        self.security_headers = {
            'Strict-Transport-Security': {
                'description': 'Helps protect against protocol downgrade attacks and cookie hijacking',
                'recommended': 'max-age=31536000; includeSubDomains',
                'severity': 'Medium'
            },
            'Content-Security-Policy': {
                'description': 'Helps prevent Cross-Site Scripting (XSS) and other code injection attacks',
                'recommended': "default-src 'self'",
                'severity': 'High'
            },
            'X-Content-Type-Options': {
                'description': 'Prevents browsers from MIME-sniffing a response away from the declared content-type',
                'recommended': 'nosniff',
                'severity': 'Medium'
            },
            'X-Frame-Options': {
                'description': 'Provides protection against clickjacking attacks',
                'recommended': 'SAMEORIGIN',
                'severity': 'Medium'
            },
            'X-XSS-Protection': {
                'description': 'Enables the XSS filter built into most recent web browsers',
                'recommended': '1; mode=block',
                'severity': 'Low'
            },
            'Referrer-Policy': {
                'description': 'Controls how much referrer information is included with requests',
                'recommended': 'no-referrer, strict-origin-when-cross-origin',
                'severity': 'Low'
            },
            'Permissions-Policy': {
                'description': 'Controls which browser features can be used in the document',
                'recommended': 'camera=(), microphone=(), geolocation=()',
                'severity': 'Low'
            }
        }
        
        # Request timeout
        self.timeout = 10
    
    def run(self, target_url):
        """Run the Security Headers vulnerability check
        
        Args:
            target_url: URL to check for security header vulnerabilities
            
        Returns:
            dict: Check results
        """
        result = {
            'vulnerable': False,
            'details': [],
            'description': self.description
        }
        
        try:
            # Send request to target URL
            response = requests.get(target_url, timeout=self.timeout, allow_redirects=True)
            
            # If the page redirects to HTTPS, follow that redirect
            if response.history and response.url.startswith('https://'):
                # Use the final URL after redirects
                target_url = response.url
                
            # Check for security headers
            for header, header_info in self.security_headers.items():
                if header not in response.headers:
                    result['vulnerable'] = True
                    result['details'].append({
                        'header': header,
                        'issue': 'Missing',
                        'description': header_info['description'],
                        'recommended': header_info['recommended'],
                        'severity': header_info['severity']
                    })
                elif not self._is_header_value_secure(header, response.headers[header]):
                    result['vulnerable'] = True
                    result['details'].append({
                        'header': header,
                        'issue': 'Insecure configuration',
                        'description': header_info['description'],
                        'current': response.headers[header],
                        'recommended': header_info['recommended'],
                        'severity': header_info['severity']
                    })
            
            # Check if HTTPS is used
            if not target_url.startswith('https://'):
                result['vulnerable'] = True
                result['details'].append({
                    'header': 'HTTPS',
                    'issue': 'Not using HTTPS',
                    'description': 'HTTPS encrypts data in transit and helps authenticate the website',
                    'recommended': 'Use HTTPS for all web traffic',
                    'severity': 'High'
                })
                
        except (requests.RequestException, ConnectionError) as e:
            result['error'] = str(e)
        
        return result
    
    def _is_header_value_secure(self, header, value):
        """Check if a security header has a secure value
        
        Args:
            header: Header name
            value: Header value
            
        Returns:
            bool: True if the header value is considered secure, False otherwise
        """
        if header == 'Strict-Transport-Security':
            # Check for max-age with a reasonable duration (at least 6 months)
            return 'max-age=' in value.lower() and self._get_max_age(value) >= 15768000
            
        elif header == 'Content-Security-Policy':
            # Basic check for default-src or script-src restriction
            return ("default-src" in value or "script-src" in value) and "'unsafe-inline'" not in value
            
        elif header == 'X-Content-Type-Options':
            return value.lower() == 'nosniff'
            
        elif header == 'X-Frame-Options':
            return value.upper() in ['DENY', 'SAMEORIGIN']
            
        elif header == 'X-XSS-Protection':
            return value in ['1', '1; mode=block']
            
        # For other headers, just check if they exist (already checked above)
        return True
    
    def _get_max_age(self, hsts_value):
        """Extract max-age value from HSTS header
        
        Args:
            hsts_value: HSTS header value
            
        Returns:
            int: max-age value or 0 if not found
        """
        try:
            # Extract max-age value
            if 'max-age=' in hsts_value:
                max_age_part = hsts_value.split('max-age=')[1]
                if ';' in max_age_part:
                    max_age = int(max_age_part.split(';')[0])
                else:
                    max_age = int(max_age_part)
                return max_age
        except (ValueError, IndexError):
            pass
            
        return 0