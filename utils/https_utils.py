#!/usr/bin/env python3
"""
HTTP utilities for the web vulnerability scanner.
Provides helper functions for making HTTP requests and handling responses.
"""

import requests
import random
import time
from urllib.parse import urlparse, urljoin

# List of common user agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
]

class RequestsManager:
    """Manager for HTTP requests"""
    
    def __init__(self, timeout=10, delay=0, user_agent=None, proxy=None, cookies=None):
        """Initialize the requests manager
        
        Args:
            timeout: Request timeout in seconds
            delay: Delay between requests in seconds
            user_agent: User agent string to use
            proxy: Proxy URL to use
            cookies: Cookies to include with requests
        """
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()
        
        # Set user agent
        if user_agent:
            self.session.headers['User-Agent'] = user_agent
        else:
            self.session.headers['User-Agent'] = random.choice(USER_AGENTS)
        
        # Set proxy if provided
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
        
        # Set cookies if provided
        if cookies:
            self.session.cookies.update(cookies)
        
        # Last request time (for implementing delay)
        self.last_request_time = 0
    
    def get(self, url, params=None, headers=None, allow_redirects=True):
        """Send a GET request
        
        Args:
            url: URL to request
            params: Query parameters
            headers: Additional headers
            allow_redirects: Whether to follow redirects
            
        Returns:
            requests.Response: Response object
        """
        self._delay_if_needed()
        
        try:
            response = self.session.get(
                url, 
                params=params, 
                headers=headers, 
                timeout=self.timeout, 
                allow_redirects=allow_redirects
            )
            self.last_request_time = time.time()
            return response
        
        except requests.RequestException as e:
            # Log the error and return None
            # Could also re-raise the exception depending on your preference
            print(f"Error in GET request to {url}: {str(e)}")
            return None
    
    def post(self, url, data=None, json=None, headers=None, allow_redirects=True):
        """Send a POST request
        
        Args:
            url: URL to request
            data: Form data
            json: JSON data
            headers: Additional headers
            allow_redirects: Whether to follow redirects
            
        Returns:
            requests.Response: Response object
        """
        self._delay_if_needed()
        
        try:
            response = self.session.post(
                url, 
                data=data, 
                json=json, 
                headers=headers, 
                timeout=self.timeout, 
                allow_redirects=allow_redirects
            )
            self.last_request_time = time.time()
            return response
        
        except requests.RequestException as e:
            # Log the error and return None
            print(f"Error in POST request to {url}: {str(e)}")
            return None
    
    def _delay_if_needed(self):
        """Implement delay between requests if needed"""
        if self.delay > 0:
            elapsed = time.time() - self.last_request_time
            if elapsed < self.delay:
                time.sleep(self.delay - elapsed)

def normalize_url(url):
    """Normalize a URL
    
    Args:
        url: URL to normalize
        
    Returns:
        str: Normalized URL
    """
    parsed = urlparse(url)
    
    # Add scheme if missing
    if not parsed.scheme:
        url = 'http://' + url
        parsed = urlparse(url)
    
    # Remove default ports
    if (parsed.port == 80 and parsed.scheme == 'http') or (parsed.port == 443 and parsed.scheme == 'https'):
        netloc = parsed.netloc.split(':')[0]
        parts = list(parsed)
        parts[1] = netloc
        url = urlparse(parts).geturl()
    
    # Remove trailing slash from path
    if parsed.path.endswith('/') and parsed.path != '/':
        parts = list(parsed)
        parts[2] = parsed.path[:-1]
        url = urlparse(parts).geturl()
    
    return url

def get_domain(url):
    """Extract the domain from a URL
    
    Args:
        url: URL to extract domain from
        
    Returns:
        str: Domain
    """
    parsed = urlparse(url)
    return parsed.netloc

def make_absolute_url(base_url, relative_url):
    """Convert a relative URL to an absolute URL
    
    Args:
        base_url: Base URL
        relative_url: Relative URL to convert
        
    Returns:
        str: Absolute URL
    """
    return urljoin(base_url, relative_url)

def is_same_domain(url1, url2):
    """Check if two URLs have the same domain
    
    Args:
        url1: First URL
        url2: Second URL
        
    Returns:
        bool: True if the URLs have the same domain, False otherwise
    """
    domain1 = get_domain(url1)
    domain2 = get_domain(url2)
    
    # Strip 'www.' prefix for comparison
    if domain1.startswith('www.'):
        domain1 = domain1[4:]
    if domain2.startswith('www.'):
        domain2 = domain2[4:]
    
    return domain1 == domain2