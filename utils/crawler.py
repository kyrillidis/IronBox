#!/usr/bin/env python3
"""
Web crawler utility for the vulnerability scanner.
Crawls a website to discover all pages and forms for scanning.
"""

import requests
from bs4 import BeautifulSoup
import re
import time
from urllib.parse import urlparse, urljoin, urldefrag
from collections import deque
import robots
import logging

class WebCrawler:
    """Web crawler to discover pages on a website"""
    
    def __init__(self, start_url, max_depth=3, max_urls=100, respect_robots=True, 
                 timeout=10, delay=0.5, same_domain_only=True, 
                 user_agent=None, proxy=None, cookies=None):
        """Initialize the web crawler
        
        Args:
            start_url: URL to start crawling from
            max_depth: Maximum crawl depth
            max_urls: Maximum number of URLs to crawl
            respect_robots: Whether to respect robots.txt
            timeout: Request timeout in seconds
            delay: Delay between requests in seconds
            same_domain_only: Only crawl URLs on the same domain
            user_agent: User agent string to use
            proxy: Proxy URL to use
            cookies: Cookies to include with requests
        """
        self.start_url = self._normalize_url(start_url)
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.respect_robots = respect_robots
        self.timeout = timeout
        self.delay = delay
        self.same_domain_only = same_domain_only
        
        # Set up session with custom headers
        self.session = requests.Session()
        self.user_agent = user_agent or "WebVulScanner Bot"
        self.session.headers.update({
            'User-Agent': self.user_agent
        })
        
        # Set proxy if provided
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
        
        # Set cookies if provided
        if cookies:
            self.session.cookies.update(cookies)
        
        # Parse domain from start URL
        self.domain = urlparse(self.start_url).netloc
        
        # Set up containers for discovered URLs and forms
        self.discovered_urls = set()
        self.discovered_forms = []
        
        # Set up robots.txt parser if needed
        self.robots_parser = None
        if self.respect_robots:
            self._init_robots_parser()
        
        # Track last request time for rate limiting
        self.last_request_time = 0
    
    def crawl(self, progress_callback=None):
        """Start crawling the website
        
        Args:
            progress_callback: Function to call with progress updates
            
        Returns:
            tuple: (discovered_urls, discovered_forms)
        """
        # Queue for BFS traversal: (url, depth)
        queue = deque([(self.start_url, 0)])
        # Track visited URLs to avoid duplicates
        visited = set([self.start_url])
        
        while queue and len(self.discovered_urls) < self.max_urls:
            # Get next URL and depth from queue
            current_url, depth = queue.popleft()
            
            # Skip if we've reached max depth
            if depth > self.max_depth:
                continue
            
            # Respect robots.txt
            if self.respect_robots and self.robots_parser and not self.robots_parser.can_fetch(self.user_agent, current_url):
                logging.info(f"Skipping {current_url} (disallowed by robots.txt)")
                continue
            
            # Fetch the page
            response = self._make_request(current_url)
            if not response:
                continue
            
            # Add to discovered URLs
            self.discovered_urls.add(current_url)
            
            # Update progress if callback provided
            if progress_callback:
                progress_percentage = (len(self.discovered_urls) / self.max_urls) * 100
                progress_callback(progress_percentage, current_url)
            
            # Extract links and forms from the page
            links = self._extract_links(response, current_url)
            forms = self._extract_forms(response, current_url)
            
            # Add discovered forms
            self.discovered_forms.extend(forms)
            
            # Add new links to the queue
            for link in links:
                if link not in visited and len(visited) < self.max_urls:
                    visited.add(link)
                    queue.append((link, depth + 1))
        
        return (self.discovered_urls, self.discovered_forms)
    
    def _make_request(self, url):
        """Make an HTTP request with rate limiting
        
        Args:
            url: URL to request
            
        Returns:
            requests.Response or None: Response object or None if the request failed
        """
        # Implement rate limiting
        if self.delay > 0:
            elapsed = time.time() - self.last_request_time
            if elapsed < self.delay:
                time.sleep(self.delay - elapsed)
        
        try:
            logging.info(f"Crawling: {url}")
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            self.last_request_time = time.time()
            
            # Only return successful text responses
            if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                return response
            else:
                logging.warning(f"Failed to retrieve {url}: Status {response.status_code}")
                return None
                
        except requests.RequestException as e:
            logging.warning(f"Error crawling {url}: {str(e)}")
            return None
    
    def _extract_links(self, response, base_url):
        """Extract links from an HTML page
        
        Args:
            response: HTTP response object
            base_url: Base URL for resolving relative links
            
        Returns:
            list: Discovered links
        """
        links = []
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all links in the page
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                
                # Skip empty links and anchors
                if not href or href.startswith('#'):
                    continue
                
                # Build absolute URL
                absolute_url = urljoin(base_url, href)
                
                # Remove fragments
                absolute_url = urldefrag(absolute_url)[0]
                
                # Skip non-HTTP(S) links
                if not absolute_url.startswith(('http://', 'https://')):
                    continue
                
                # Only include links to the same domain if same_domain_only is True
                if self.same_domain_only and not self._is_same_domain(absolute_url):
                    continue
                
                # Normalize URL
                normalized_url = self._normalize_url(absolute_url)
                
                # Add to links list if not already discovered
                if normalized_url not in self.discovered_urls:
                    links.append(normalized_url)
            
        except Exception as e:
            logging.error(f"Error extracting links from {base_url}: {str(e)}")
        
        return links
    
    def _extract_forms(self, response, base_url):
        """Extract forms from an HTML page
        
        Args:
            response: HTTP response object
            base_url: Base URL for resolving relative form actions
            
        Returns:
            list: Discovered forms
        """
        forms = []
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all forms in the page
            for form_tag in soup.find_all('form'):
                # Get form attributes
                action = form_tag.get('action', '')
                method = form_tag.get('method', 'get').lower()
                
                # Make action URL absolute
                if action:
                    action = urljoin(base_url, action)
                else:
                    action = base_url
                
                # Get form inputs
                inputs = []
                for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
                    input_name = input_tag.get('name')
                    input_type = input_tag.get('type', '')
                    input_value = input_tag.get('value', '')
                    
                    if input_name:  # Only include inputs with names
                        inputs.append({
                            'name': input_name,
                            'type': input_type,
                            'value': input_value
                        })
                
                # Add form to the list
                forms.append({
                    'url': base_url,
                    'action': action,
                    'method': method,
                    'inputs': inputs
                })
            
        except Exception as e:
            logging.error(f"Error extracting forms from {base_url}: {str(e)}")
        
        return forms
    
    def _init_robots_parser(self):
        """Initialize the robots.txt parser"""
        try:
            # Construct robots.txt URL
            parsed_url = urlparse(self.start_url)
            robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"
            
            # Fetch robots.txt
            response = self.session.get(robots_url, timeout=self.timeout)
            if response.status_code == 200:
                self.robots_parser = robots.RobotsParser.from_string(response.text, robots_url)
                logging.info(f"Loaded robots.txt from {robots_url}")
            else:
                logging.warning(f"No robots.txt found at {robots_url}")
        
        except Exception as e:
            logging.warning(f"Error loading robots.txt: {str(e)}")
    
    def _is_same_domain(self, url):
        """Check if a URL is on the same domain as the start URL
        
        Args:
            url: URL to check
            
        Returns:
            bool: True if on the same domain, False otherwise
        """
        url_domain = urlparse(url).netloc
        
        # Handle www. prefix
        if url_domain.startswith('www.'):
            url_domain = url_domain[4:]
        if self.domain.startswith('www.'):
            domain = self.domain[4:]
        else:
            domain = self.domain
        
        return url_domain == domain
    
    def _normalize_url(self, url):
        """Normalize a URL to avoid duplicates
        
        Args:
            url: URL to normalize
            
        Returns:
            str: Normalized URL
        """
        parsed = urlparse(url)
        
        # Add trailing slash to path if it doesn't have one and doesn't have a query or fragment
        if not parsed.path:
            path = '/'
        else:
            path = parsed.path
        
        # Rebuild URL
        normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        
        return normalized


class SitemapCrawler:
    """Crawler that uses XML sitemaps to discover URLs"""
    
    def __init__(self, base_url, timeout=10):
        """Initialize the sitemap crawler
        
        Args:
            base_url: Base URL of the website
            timeout: Request timeout in seconds
        """
        self.base_url = base_url
        self.timeout = timeout
        self.session = requests.Session()
        self.discovered_urls = set()
    
    def crawl(self):
        """Crawl the sitemap and discover URLs
        
        Returns:
            set: Discovered URLs
        """
        # Try common sitemap locations
        sitemap_locations = [
            '/sitemap.xml',
            '/sitemap_index.xml',
            '/sitemap/',
            '/sitemaps/',
            '/sitemap/sitemap.xml'
        ]
        
        for location in sitemap_locations:
            sitemap_url = urljoin(self.base_url, location)
            urls = self._parse_sitemap(sitemap_url)
            if urls:
                self.discovered_urls.update(urls)
                break
        
        return self.discovered_urls
    
    def _parse_sitemap(self, sitemap_url):
        """Parse an XML sitemap and extract URLs
        
        Args:
            sitemap_url: URL of the sitemap
            
        Returns:
            set: URLs found in the sitemap
        """
        urls = set()
        try:
            response = self.session.get(sitemap_url, timeout=self.timeout)
            if response.status_code != 200:
                return urls
            
            soup = BeautifulSoup(response.text, 'xml')
            
            # Check if this is a sitemap index
            sitemaps = soup.find_all('sitemap')
            if sitemaps:
                # This is a sitemap index, recursively process each sitemap
                for sitemap in sitemaps:
                    loc = sitemap.find('loc')
                    if loc:
                        child_urls = self._parse_sitemap(loc.text)
                        urls.update(child_urls)
            else:
                # This is a regular sitemap, extract URLs
                locations = soup.find_all('loc')
                for loc in locations:
                    urls.add(loc.text)
        
        except Exception as e:
            logging.warning(f"Error parsing sitemap {sitemap_url}: {str(e)}")
        
        return urls


def crawl_website(url, max_depth=3, max_urls=100, respect_robots=True, timeout=10, delay=0.5, 
                  same_domain_only=True, user_agent=None, proxy=None, cookies=None, 
                  use_sitemap=True, progress_callback=None):
    """Crawl a website using both traditional crawling and sitemap crawling
    
    Args:
        url: URL to start crawling from
        max_depth: Maximum crawl depth
        max_urls: Maximum number of URLs to crawl
        respect_robots: Whether to respect robots.txt
        timeout: Request timeout in seconds
        delay: Delay between requests in seconds
        same_domain_only: Only crawl URLs on the same domain
        user_agent: User agent string to use
        proxy: Proxy URL to use
        cookies: Cookies to include with requests
        use_sitemap: Whether to also try sitemap crawling
        progress_callback: Function to call with progress updates
        
    Returns:
        tuple: (discovered_urls, discovered_forms)
    """
    discovered_urls = set()
    discovered_forms = []
    
    # Try sitemap crawling first if enabled
    if use_sitemap:
        sitemap_crawler = SitemapCrawler(url, timeout=timeout)
        sitemap_urls = sitemap_crawler.crawl()
        discovered_urls.update(sitemap_urls)
        
        if progress_callback and sitemap_urls:
            progress_callback(10, "Sitemap crawling completed")
    
    # Use traditional crawling to find additional URLs and forms
    crawler = WebCrawler(
        url, 
        max_depth=max_depth, 
        max_urls=max_urls, 
        respect_robots=respect_robots,
        timeout=timeout, 
        delay=delay, 
        same_domain_only=same_domain_only,
        user_agent=user_agent, 
        proxy=proxy, 
        cookies=cookies
    )
    
    urls, forms = crawler.crawl(progress_callback=progress_callback)
    
    # Combine results
    discovered_urls.update(urls)
    discovered_forms.extend(forms)
    
    return (discovered_urls, discovered_forms)