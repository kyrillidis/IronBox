#!/usr/bin/env python3
"""
Authentication utility for the web vulnerability scanner.
Handles logging into websites to scan protected areas.
"""

import requests
from urllib.parse import urlparse
import time
import re
from bs4 import BeautifulSoup

class Authenticator:
    """Handles authentication to websites"""
    
    def __init__(self, session=None):
        """Initialize the authenticator
        
        Args:
            session: Existing requests session (creates a new one if None)
        """
        self.session = session or requests.Session()
        self.authenticated = False
        self.auth_url = None
        self.cookies = None
    
    def form_login(self, login_url, username_field, username, password_field, password, 
                   additional_fields=None, success_check=None, timeout=10):
        """Login using an HTML form
        
        Args:
            login_url: URL of the login form
            username_field: Name of the username/email input field
            username: Username or email to use
            password_field: Name of the password input field
            password: Password to use
            additional_fields: Dict of additional form fields to submit
            success_check: Function that takes the response and returns True if login was successful
            timeout: Request timeout in seconds
            
        Returns:
            bool: True if login was successful, False otherwise
        """
        self.auth_url = login_url
        try:
            # First, get the login page to extract any hidden fields
            response = self.session.get(login_url, timeout=timeout)
            
            # Extract CSRF token and other hidden fields
            form_data = self._extract_form_data(response.text, username_field, password_field)
            
            # Add credentials
            form_data[username_field] = username
            form_data[password_field] = password
            
            # Add any additional fields
            if additional_fields:
                form_data.update(additional_fields)
            
            # Submit the login form
            login_response = self.session.post(login_url, data=form_data, timeout=timeout)
            
            # Check if login was successful
            if success_check:
                self.authenticated = success_check(login_response)
            else:
                # Default success check: look for login form absence and presence of username
                self.authenticated = self._default_success_check(login_response, username)
            
            # Save cookies if authenticated
            if self.authenticated:
                self.cookies = self.session.cookies.get_dict()
            
            return self.authenticated
            
        except Exception as e:
            print(f"Login error: {str(e)}")
            return False
    
    def token_login(self, api_url, username_field, username, password_field, password,
                    token_field='token', method='post', json_data=True, timeout=10):
        """Login using an API endpoint that returns a token
        
        Args:
            api_url: URL of the login API
            username_field: Name of the username JSON field
            username: Username to use
            password_field: Name of the password JSON field
            password: Password to use
            token_field: Field in the response containing the token
            method: HTTP method to use (post, get)
            json_data: Whether to use JSON data (True) or form data (False)
            timeout: Request timeout in seconds
            
        Returns:
            bool: True if login was successful, False otherwise
        """
        self.auth_url = api_url
        try:
            # Prepare login data
            data = {
                username_field: username,
                password_field: password
            }
            
            # Make the request
            if method.lower() == 'post':
                if json_data:
                    response = self.session.post(api_url, json=data, timeout=timeout)
                else:
                    response = self.session.post(api_url, data=data, timeout=timeout)
            else:  # GET
                response = self.session.get(api_url, params=data, timeout=timeout)
            
            # Check if login was successful
            if response.status_code == 200:
                try:
                    # Parse response JSON
                    json_response = response.json()
                    
                    # Check for token
                    if token_field in json_response:
                        token = json_response[token_field]
                        
                        # Set authentication header
                        self.session.headers.update({
                            'Authorization': f'Bearer {token}'
                        })
                        
                        self.authenticated = True
                        return True
                except Exception:
                    pass
            
            return False
            
        except Exception as e:
            print(f"API login error: {str(e)}")
            return False
    
    def is_authenticated(self):
        """Check if currently authenticated
        
        Returns:
            bool: True if authenticated, False otherwise
        """
        return self.authenticated
    
    def _extract_form_data(self, html, username_field, password_field):
        """Extract form data from an HTML login page
        
        Args:
            html: HTML content of the login page
            username_field: Name of the username field
            password_field: Name of the password field
            
        Returns:
            dict: Form data with hidden fields
        """
        form_data = {}
        soup = BeautifulSoup(html, 'html.parser')
        
        # Find login form - usually contains username/password fields
        login_form = None
        for form in soup.find_all('form'):
            has_username = form.find('input', {'name': username_field})
            has_password = form.find('input', {'name': password_field, 'type': 'password'})
            
            if has_username and has_password:
                login_form = form
                break
        
        if not login_form:
            # If specific form not found, look for any form with password field
            for form in soup.find_all('form'):
                if form.find('input', {'type': 'password'}):
                    login_form = form
                    break
        
        # Extract hidden fields from the form
        if login_form:
            for input_field in login_form.find_all('input'):
                if input_field.get('type') == 'hidden' and input_field.get('name'):
                    form_data[input_field['name']] = input_field.get('value', '')
        
        # Look for CSRF token in meta tags if not in form
        if 'csrf' not in ''.join(form_data.keys()).lower():
            meta_csrf = soup.find('meta', attrs={'name': re.compile('csrf', re.I)})
            if meta_csrf and meta_csrf.get('content'):
                form_data['csrf_token'] = meta_csrf['content']
        
        return form_data
    
    def _default_success_check(self, response, username):
        """Default method to check if login was successful
        
        Args:
            response: Response from login attempt
            username: Username used for login
            
        Returns:
            bool: True if login appears successful, False otherwise
        """
        # Check for common indicators of successful login
        
        # 1. Check if redirected away from login page
        if self.auth_url and self.auth_url != response.url:
            return True
        
        # 2. Check if username appears on the page (common for "Welcome, username")
        if username in response.text:
            return True
        
        # 3. Check if login form is no longer present
        soup = BeautifulSoup(response.text, 'html.parser')
        login_form = soup.find('form', {'action': re.compile('login|signin', re.I)})
        if not login_form:
            return True
        
        # 4. Check for common error messages indicating failed login
        error_patterns = [
            'incorrect password',
            'login failed',
            'invalid username',
            'invalid password',
            'authentication failed'
        ]
        for pattern in error_patterns:
            if re.search(pattern, response.text, re.I):
                return False
        
        # Default to not authenticated if no positive indicators
        return False