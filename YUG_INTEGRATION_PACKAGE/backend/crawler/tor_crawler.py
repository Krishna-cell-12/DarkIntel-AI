"""
Tor Crawler Module - Dark Web Scraper
Handles Tor SOCKS proxy connection and .onion site scraping
"""

import requests
import json
import time
from bs4 import BeautifulSoup
from typing import Optional, Dict, List
import logging
from datetime import datetime
import os

# Set up logging
logger = logging.getLogger(__name__)

class TorCrawler:
    """
    Connects to Tor SOCKS proxy and scrapes .onion sites
    """
    
    def __init__(self, tor_proxy: str = "127.0.0.1:9050", timeout: int = 30):
        """
        Initialize Tor crawler
        
        Args:
            tor_proxy: SOCKS5 proxy address (default: Tor default)
            timeout: Request timeout in seconds
        """
        self.tor_proxy = tor_proxy
        self.timeout = timeout
        self.connected = False
        self.session = None
        self.scraped_data = []
        
    def connect(self) -> bool:
        """
        Establish connection to Tor SOCKS proxy
        
        Returns:
            bool: True if connected, False otherwise
        """
        try:
            # Set up SOCKS5 proxy
            proxies = {
                'http': f'socks5://{self.tor_proxy}',
                'https': f'socks5://{self.tor_proxy}'
            }
            
            # Create session with proxy
            self.session = requests.Session()
            self.session.proxies = proxies
            
            # Test connection
            test_url = "http://check.torproject.org"
            response = self.session.get(test_url, timeout=self.timeout)
            
            if response.status_code == 200:
                self.connected = True
                logger.info("✓ Connected to Tor successfully")
                return True
            else:
                logger.error("✗ Failed to connect to Tor")
                return False
                
        except Exception as e:
            logger.error(f"✗ Tor connection error: {str(e)}")
            self.connected = False
            return False
    
    def fetch_onion_page(self, onion_url: str) -> Optional[str]:
        """
        Fetch content from .onion site
        
        Args:
            onion_url: Full .onion URL
            
        Returns:
            str: HTML content or None if failed
        """
        if not self.connected or not self.session:
            logger.error("Not connected to Tor")
            return None
            
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0'
            }
            
            response = self.session.get(
                onion_url,
                timeout=self.timeout,
                headers=headers
            )
            
            if response.status_code == 200:
                logger.info(f"✓ Fetched {onion_url}")
                return response.text
            else:
                logger.warning(f"✗ Failed to fetch {onion_url}: {response.status_code}")
                return None
                
        except requests.Timeout:
            logger.error(f"✗ Timeout fetching {onion_url}")
            return None
        except Exception as e:
            logger.error(f"✗ Error fetching {onion_url}: {str(e)}")
            return None
    
    def parse_html_content(self, html: str) -> Dict:
        """
        Extract text content from HTML
        
        Args:
            html: HTML string
            
        Returns:
            dict: Parsed content with text, links, etc.
        """
        try:
            soup = BeautifulSoup(html, 'lxml')
            
            # Remove script and style elements
            for script in soup(["script", "style"]):
                script.decompose()
            
            # Get text
            text = soup.get_text(separator='\n')
            
            # Extract paragraphs
            paragraphs = [p.get_text() for p in soup.find_all('p')]
            
            # Extract links
            links = [a.get('href') for a in soup.find_all('a', href=True)]
            
            return {
                'text': text[:5000],  # Limit to 5000 chars
                'paragraphs': paragraphs[:20],  # First 20 paragraphs
                'links': links[:30],  # First 30 links
                'title': soup.title.string if soup.title else 'No title'
            }
            
        except Exception as e:
            logger.error(f"✗ Error parsing HTML: {str(e)}")
            return {'error': str(e)}
    
    def crawl_site(self, onion_url: str) -> Optional[Dict]:
        """
        Complete crawl of a single .onion site
        
        Args:
            onion_url: .onion URL to crawl
            
        Returns:
            dict: Crawled data or None if failed
        """
        logger.info(f"🕷️  Crawling {onion_url}...")
        
        html = self.fetch_onion_page(onion_url)
        if not html:
            return None
        
        content = self.parse_html_content(html)
        
        result = {
            'url': onion_url,
            'timestamp': datetime.now().isoformat(),
            'status': 'success',
            'content': content
        }
        
        self.scraped_data.append(result)
        return result
    
    def batch_crawl(self, onion_urls: List[str]) -> Dict:
        """
        Crawl multiple .onion sites
        
        Args:
            onion_urls: List of .onion URLs
            
        Returns:
            dict: Results summary
        """
        results = {
            'total': len(onion_urls),
            'successful': 0,
            'failed': 0,
            'data': []
        }
        
        for url in onion_urls:
            try:
                result = self.crawl_site(url)
                if result:
                    results['successful'] += 1
                    results['data'].append(result)
                else:
                    results['failed'] += 1
                    
                # Be nice to the server
                time.sleep(2)
                
            except Exception as e:
                logger.error(f"✗ Batch crawl error: {str(e)}")
                results['failed'] += 1
        
        return results
    
    def get_results(self) -> List[Dict]:
        """Return all scraped data"""
        return self.scraped_data
    
    def save_results(self, filename: str = "scraped_data.json"):
        """Save results to JSON file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.scraped_data, f, indent=2, ensure_ascii=False)
            logger.info(f"✓ Saved {len(self.scraped_data)} results to {filename}")
            return True
        except Exception as e:
            logger.error(f"✗ Error saving results: {str(e)}")
            return False
    
    def disconnect(self):
        """Disconnect from Tor"""
        if self.session:
            self.session.close()
        self.connected = False
        logger.info("✓ Disconnected from Tor")
