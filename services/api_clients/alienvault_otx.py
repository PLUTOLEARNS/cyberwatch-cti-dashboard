"""
AlienVault OTX (Open Threat Exchange) API Client
"""
import logging
from services.api_clients.base_client import BaseClient

logger = logging.getLogger(__name__)

class AlienVaultOTXClient(BaseClient):
    """Client for AlienVault OTX API"""
    
    def __init__(self, api_key=None):
        super().__init__(
            api_key=api_key,
            base_url="https://otx.alienvault.com/api/v1",
            rate_limit=20  # 1000 requests per day, so ~20 per hour to be safe
        )
        
    def _get_headers(self):
        """Get headers for OTX API requests"""
        headers = {"User-Agent": "CyberWatch-CTI-Dashboard/1.0"}
        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key
        return headers
    
    def get_pulses(self, limit=10):
        """
        Get recent threat intelligence pulses (reports)
        
        Args:
            limit (int): Maximum number of pulses to retrieve
            
        Returns:
            dict: API response with pulses data
        """
        if not self.api_key:
            logger.warning("No OTX API key provided, cannot fetch pulses")
            return {'status': 'error', 'message': 'No API key provided'}
            
        try:
            response = self._make_request(
                method='GET',
                endpoint='/pulses/subscribed',
                headers=self._get_headers(),
                params={'limit': limit},
                cache_key=f'otx_pulses_{limit}'
            )
            return response
        except Exception as e:
            logger.error(f"Error fetching OTX pulses: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def get_indicators(self, indicator_type, limit=10):
        """
        Get indicators of a specific type
        
        Args:
            indicator_type (str): Type of indicator (IPv4, domain, URL, etc.)
            limit (int): Maximum number of indicators to retrieve
            
        Returns:
            dict: API response with indicators data
        """
        if not self.api_key:
            logger.warning("No OTX API key provided, cannot fetch indicators")
            return {'status': 'error', 'message': 'No API key provided'}
            
        try:
            response = self._make_request(
                method='GET',
                endpoint=f'/indicators/{indicator_type}/recent',
                headers=self._get_headers(),
                params={'limit': limit},
                cache_key=f'otx_indicators_{indicator_type}_{limit}'
            )
            return response
        except Exception as e:
            logger.error(f"Error fetching OTX indicators: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def get_pulse_detail(self, pulse_id):
        """
        Get detailed information about a specific pulse
        
        Args:
            pulse_id (str): ID of the pulse to retrieve
            
        Returns:
            dict: Detailed pulse information
        """
        if not self.api_key:
            logger.warning("No OTX API key provided, cannot fetch pulse details")
            return {'status': 'error', 'message': 'No API key provided'}
            
        try:
            response = self._make_request(
                method='GET',
                endpoint=f'/pulses/{pulse_id}',
                headers=self._get_headers(),
                cache_key=f'otx_pulse_detail_{pulse_id}'
            )
            return response
        except Exception as e:
            logger.error(f"Error fetching OTX pulse detail: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def get_indicators_by_pulse(self, pulse_id):
        """
        Get indicators from a specific pulse
        
        Args:
            pulse_id (str): ID of the pulse
            
        Returns:
            dict: API response with indicators from the pulse
        """
        if not self.api_key:
            logger.warning("No OTX API key provided, cannot fetch pulse indicators")
            return {'status': 'error', 'message': 'No API key provided'}
            
        try:
            response = self._make_request(
                method='GET',
                endpoint=f'/pulses/{pulse_id}/indicators',
                headers=self._get_headers(),
                cache_key=f'otx_pulse_indicators_{pulse_id}'
            )
            return response
        except Exception as e:
            logger.error(f"Error fetching OTX pulse indicators: {e}")
            return {'status': 'error', 'message': str(e)}
