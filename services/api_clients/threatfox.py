"""
ThreatFox (Abuse.ch) API Client - Free malware IOC database
"""
import logging
from services.api_clients.base_client import BaseClient

logger = logging.getLogger(__name__)

class ThreatFoxClient(BaseClient):
    """Client for ThreatFox API (no API key required)"""
    
    def __init__(self):
        super().__init__(
            api_key=None,
            base_url="https://threatfox-api.abuse.ch/api/v1",
            rate_limit=100  # Conservative rate limit for reasonable usage
        )
        
    def _get_headers(self):
        """Get headers for ThreatFox API requests"""
        return {
            "User-Agent": "CyberWatch-CTI-Dashboard/1.0",
            "Content-Type": "application/json"
        }
    
    def get_recent_iocs(self, days=3, limit=100):
        """
        Get recent malware IOCs from ThreatFox
        
        Args:
            days (int): Number of days to look back (max 7)
            limit (int): Maximum number of IOCs to retrieve
            
        Returns:
            dict: API response with recent IOCs
        """
        try:
            data = {
                "query": "get_iocs",
                "days": min(days, 7),  # API limit is 7 days
                "limit": min(limit, 1000)  # API limit is 1000
            }
            
            response = self._make_request(
                method='POST',
                endpoint='/',
                headers=self._get_headers(),
                data=data,
                cache_key=f'threatfox_recent_{days}_{limit}'
            )
            return response
        except Exception as e:
            logger.error(f"Error fetching ThreatFox recent IOCs: {e}")
            return {'status': 'error', 'message': str(e), 'data': []}
    
    def get_iocs_by_malware(self, malware_family, limit=50):
        """
        Get IOCs for a specific malware family
        
        Args:
            malware_family (str): Name of the malware family
            limit (int): Maximum number of IOCs to retrieve
            
        Returns:
            dict: API response with malware-specific IOCs
        """
        try:
            data = {
                "query": "get_iocs",
                "malware": malware_family,
                "limit": min(limit, 1000)
            }
            
            response = self._make_request(
                method='POST',
                endpoint='/',
                headers=self._get_headers(),
                data=data,
                cache_key=f'threatfox_malware_{malware_family}_{limit}'
            )
            return response
        except Exception as e:
            logger.error(f"Error fetching ThreatFox IOCs for {malware_family}: {e}")
            return {'status': 'error', 'message': str(e), 'data': []}
    
    def get_iocs_by_tag(self, tag, limit=50):
        """
        Get IOCs by tag
        
        Args:
            tag (str): Tag to search for
            limit (int): Maximum number of IOCs to retrieve
            
        Returns:
            dict: API response with tag-specific IOCs
        """
        try:
            data = {
                "query": "get_iocs",
                "tag": tag,
                "limit": min(limit, 1000)
            }
            
            response = self._make_request(
                method='POST',
                endpoint='/',
                headers=self._get_headers(),
                data=data,
                cache_key=f'threatfox_tag_{tag}_{limit}'
            )
            return response
        except Exception as e:
            logger.error(f"Error fetching ThreatFox IOCs for tag {tag}: {e}")
            return {'status': 'error', 'message': str(e), 'data': []}
    
    def search_ioc(self, ioc_value):
        """
        Search for a specific IOC
        
        Args:
            ioc_value (str): The IOC to search for
            
        Returns:
            dict: API response with IOC details
        """
        try:
            data = {
                "query": "search_ioc",
                "search_term": ioc_value
            }
            
            response = self._make_request(
                method='POST',
                endpoint='/',
                headers=self._get_headers(),
                data=data,
                cache_key=f'threatfox_search_{ioc_value}'
            )
            return response
        except Exception as e:
            logger.error(f"Error searching ThreatFox for {ioc_value}: {e}")
            return {'status': 'error', 'message': str(e), 'data': []}
