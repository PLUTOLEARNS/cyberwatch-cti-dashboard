"""
Maltiverse API Client
"""
import logging
from services.api_clients.base_client import BaseClient

logger = logging.getLogger(__name__)

class MaltiverseClient(BaseClient):
    """Client for Maltiverse API"""
    
    def __init__(self, api_key=None):
        super().__init__(
            api_key=api_key,
            base_url="https://api.maltiverse.com",
            rate_limit=120  # 2 requests per second free tier
        )
        
    def _get_headers(self):
        """Get headers for Maltiverse API requests"""
        headers = {"User-Agent": "CyberWatch-CTI-Dashboard/1.0"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers
    
    def get_recent_samples(self, limit=10):
        """
        Get recent malware samples
        
        Args:
            limit (int): Maximum number of samples to retrieve
            
        Returns:
            dict: API response with recent samples
        """
        try:
            response = self._make_request(
                method='GET',
                endpoint='/feed/samples/recent',
                headers=self._get_headers(),
                params={'limit': limit},
                cache_key=f'maltiverse_samples_{limit}'
            )
            return response
        except Exception as e:
            logger.error(f"Error fetching Maltiverse samples: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def get_recent_iocs(self, limit=10):
        """
        Get recent indicators of compromise
        
        Args:
            limit (int): Maximum number of IOCs to retrieve
            
        Returns:
            dict: API response with recent IOCs
        """
        try:
            response = self._make_request(
                method='GET',
                endpoint='/feeds/recent',
                headers=self._get_headers(),
                params={'limit': limit},
                cache_key=f'maltiverse_iocs_{limit}'
            )
            return response
        except Exception as e:
            logger.error(f"Error fetching Maltiverse IOCs: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def search_ioc(self, indicator):
        """
        Search for information about a specific indicator
        
        Args:
            indicator (str): The indicator to search for
            
        Returns:
            dict: API response with indicator information
        """
        try:
            response = self._make_request(
                method='GET',
                endpoint=f'/search/{indicator}',
                headers=self._get_headers(),
                cache_key=f'maltiverse_search_{indicator}'
            )
            return response
        except Exception as e:
            logger.error(f"Error searching Maltiverse for {indicator}: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def get_feed_by_tag(self, tag, limit=10):
        """
        Get indicators by specific tag
        
        Args:
            tag (str): Tag to filter by
            limit (int): Maximum number of indicators to retrieve
            
        Returns:
            dict: API response with tagged indicators
        """
        try:
            response = self._make_request(
                method='GET',
                endpoint='/feeds/tag',
                headers=self._get_headers(),
                params={'tag': tag, 'limit': limit},
                cache_key=f'maltiverse_tag_{tag}_{limit}'
            )
            return response
        except Exception as e:
            logger.error(f"Error fetching Maltiverse feed for tag {tag}: {e}")
            return {'status': 'error', 'message': str(e)}
