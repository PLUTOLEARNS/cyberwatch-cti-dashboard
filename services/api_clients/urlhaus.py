"""
URLhaus (Abuse.ch) API Client
"""
import logging
from services.api_clients.base_client import BaseClient

logger = logging.getLogger(__name__)

class URLhausClient(BaseClient):
    """Client for URLhaus API (no API key required)"""
    
    def __init__(self):
        super().__init__(
            api_key=None,
            base_url="https://urlhaus-api.abuse.ch/v1",
            rate_limit=60  # Conservative rate limit for reasonable usage
        )
        
    def _get_headers(self):
        """Get headers for URLhaus API requests"""
        return {
            "User-Agent": "CyberWatch-CTI-Dashboard/1.0",
            "Content-Type": "application/x-www-form-urlencoded"
        }
    
    def get_recent_urls(self, limit=100):
        """
        Get recent malicious URLs
        
        Args:
            limit (int): Maximum number of URLs to retrieve (max 1000)
            
        Returns:
            dict: API response with recent URLs
        """
        try:
            # URLhaus uses POST requests with form data
            data = {'limit': min(limit, 1000)}  # API limit is 1000
            
            response = self._make_request(
                method='POST',
                endpoint='/urls/recent',
                headers=self._get_headers(),
                data=data,
                cache_key=f'urlhaus_recent_{limit}'
            )
            return response
        except Exception as e:
            logger.error(f"Error fetching URLhaus recent URLs: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def get_url_info(self, url):
        """
        Get information about a specific URL
        
        Args:
            url (str): URL to query
            
        Returns:
            dict: API response with URL information
        """
        try:
            data = {'url': url}
            
            response = self._make_request(
                method='POST',
                endpoint='/url',
                headers=self._get_headers(),
                data=data,
                cache_key=f'urlhaus_url_{hash(url)}'
            )
            return response
        except Exception as e:
            logger.error(f"Error fetching URLhaus info for {url}: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def get_recent_payloads(self, limit=100):
        """
        Get recent malware payloads
        
        Args:
            limit (int): Maximum number of payloads to retrieve
            
        Returns:
            dict: API response with recent payloads
        """
        try:
            data = {'limit': min(limit, 1000)}
            
            response = self._make_request(
                method='POST',
                endpoint='/payloads/recent',
                headers=self._get_headers(),
                data=data,
                cache_key=f'urlhaus_payloads_{limit}'
            )
            return response
        except Exception as e:
            logger.error(f"Error fetching URLhaus recent payloads: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def search_tag(self, tag):
        """
        Search URLs by tag
        
        Args:
            tag (str): Tag to search for
            
        Returns:
            dict: API response with tagged URLs
        """
        try:
            data = {'tag': tag}
            
            response = self._make_request(
                method='POST',
                endpoint='/tag',
                headers=self._get_headers(),
                data=data,
                cache_key=f'urlhaus_tag_{tag}'
            )
            return response
        except Exception as e:
            logger.error(f"Error searching URLhaus for tag {tag}: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def get_signature_info(self, signature):
        """
        Get URLs associated with a specific signature
        
        Args:
            signature (str): Signature to query
            
        Returns:
            dict: API response with signature information
        """
        try:
            data = {'signature': signature}
            
            response = self._make_request(
                method='POST',
                endpoint='/signature',
                headers=self._get_headers(),
                data=data,
                cache_key=f'urlhaus_signature_{signature}'
            )
            return response
        except Exception as e:
            logger.error(f"Error fetching URLhaus signature info for {signature}: {e}")
            return {'status': 'error', 'message': str(e)}
