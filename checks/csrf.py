#!/usr/bin/env python3
"""
CSRF vulnerability check module.
Checks for Cross-Site Request Forgery vulnerabilities in web applications.
"""

import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse
from core.vulnerabilities import VulnerabilityCheck

class Check(VulnerabilityCheck):
    """Cross-Site Request Forgery (CSRF) vulnerability check"""
    
    def __init__(self):
        """Initialize the CSRF check"""
        super().__init__()
        self.name = "CSRF"
        self.description = "Checks for Cross-Site Request Forgery vulnerabilities which allow attackers to execute unauthorized actions on behalf of authenticated users."
        
        # Common CSRF token field names
        self.csrf_token_names = [
            'csrf', 'xsrf', 'token', '_token', 'csrf_token', 'xsrf_token',
            'authenticity_token', 'csrfmiddlewaretoken', '__RequestVerificationToken'
        ]
        
        # Request timeout
        self.timeout = 10
    
    def run(self, target_url):
        """Run the CSRF vulnerability check
        
        Args:
            target_url: URL to check for CSRF vulnerabilities
            
        Returns:
            dict: Check results
        """
        result = {
            'vulnerable': False,
            'details': [],
            'description': self.description
        }
        
        try:
            # Extract forms from the target URL
            forms = self._extract_forms(target_url)
            
            # Check each form for CSRF protection
            for form in forms:
                if form['method'].lower() == 'post':
                    if not self._has_csrf_protection(form):
                        result['vulnerable'] = True
                        result['details'].append({
                            'url': form['action'],
                            'form_id': form.get('id', 'Unknown'),
                            'issue': 'No CSRF token found in form'
                        })
        
        except (requests.RequestException, ConnectionError) as e:
            result['error'] = str(e)
        
        return result
    
    def _extract_forms(self, url):
        """Extract forms from a web page
        
        Args:
            url: URL to extract forms from
            
        Returns:
            list: Extracted forms
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
                method = form.get('method', 'get')
                
                # Add form to list
                forms.append({
                    'action': action,
                    'method': method,
                    'id': form.get('id', ''),
                    'name': form.get('name', ''),
                    'inputs': form.find_all(['input', 'textarea', 'select']),
                    'raw': str(form)
                })
            
        except (requests.RequestException, UnicodeDecodeError, ConnectionError):
            pass
        
        return forms
    
    def _has_csrf_protection(self, form):
        """Check if a form has CSRF protection
        
        Args:
            form: Form dictionary
            
        Returns:
            bool: True if the form has CSRF protection, False otherwise
        """
        # Check for CSRF token in form inputs
        for input_field in form['inputs']:
            input_name = input_field.get('name', '').lower()
            input_type = input_field.get('type', '').lower()
            
            # Check if input name matches common CSRF token patterns
            if any(token_name in input_name for token_name in self.csrf_token_names):
                return True
            
            # Check for hidden inputs with random-looking values (potential CSRF tokens)
            if input_type == 'hidden' and input_field.get('value'):
                value = input_field.get('value')
                if len(value) > 10 and self._is_random_looking(value):
                    return True
        
        # Check for CSRF meta tags
        if any(token_name in form['raw'].lower() for token_name in self.csrf_token_names):
            return True
        
        return False
    
    def _is_random_looking(self, value):
        """Check if a string looks like a random token
        
        Args:
            value: String to check
            
        Returns:
            bool: True if the string looks random, False otherwise
        """
        # Random tokens typically have good character distribution
        if len(value) < 10:
            return False
            
        # Check character variety (should have at least 5 unique characters)
        if len(set(value)) < 5:
            return False
            
        # Check for common token patterns (hex, base64, etc.)
        if re.match(r'^[a-zA-Z0-9_\-]+$', value):
            return True
            
        return False
    
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