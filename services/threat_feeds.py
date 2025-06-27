"""
Threat feed integration service
"""
import time
import logging
from datetime import datetime
from services.api_clients.alienvault_otx import AlienVaultOTXClient
from services.api_clients.threatfox import ThreatFoxClient

logger = logging.getLogger(__name__)

class ThreatFeedService:
    def __init__(self, otx_api_key=None):
        self.otx_client = AlienVaultOTXClient(api_key=otx_api_key) if otx_api_key else None
        self.threatfox_client = ThreatFoxClient()
        self.cache = {}
        self.cache_time = 0
        self.cache_duration = 900  # 15 minutes for faster loading
        
    def get_threat_feeds(self):
        current_time = time.time()
        if self.cache and (current_time - self.cache_time) < self.cache_duration:
            return self.cache
            
        response = {
            'categories': set(),
            'sources': [],
            'recent_indicators': []
        }
        
        # Quick parallel-like execution by limiting data fetched
        if self.otx_client:
            otx_data = self._fetch_otx_indicators()
            if otx_data:
                response['sources'].append(otx_data['source_info'])
                response['recent_indicators'].extend(otx_data['indicators'])
                response['categories'].update(otx_data['categories'])
        
        threatfox_data = self._fetch_threatfox_indicators()
        if threatfox_data:
            response['sources'].append(threatfox_data['source_info'])
            response['recent_indicators'].extend(threatfox_data['indicators'])
            response['categories'].update(threatfox_data['categories'])
        
        response['categories'] = list(response['categories'])[:10]  # Limit categories
        response['recent_indicators'] = response['recent_indicators'][:30]  # Fewer indicators
        
        self.cache = response
        self.cache_time = current_time
        
        return response
        
    def _fetch_otx_indicators(self):
        try:
            pulses_data = self.otx_client.get_pulses(limit=3)  # Reduced from 5
            if not isinstance(pulses_data, dict) or 'results' not in pulses_data:
                return None
                
            indicators = []
            categories = set()
            total_indicators = 0
            
            for pulse in pulses_data['results']:
                tags = pulse.get('tags', [])
                for tag in tags[:2]:  # Limit tags processed
                    if len(tag) > 2:
                        categories.add(tag.title())
                
                pulse_id = pulse.get('id')
                if pulse_id:
                    indicator_data = self.otx_client.get_indicators_by_pulse(pulse_id)
                    if isinstance(indicator_data, dict) and 'results' in indicator_data:
                        for indicator in indicator_data['results'][:5]:  # Reduced from 10
                            indicators.append({
                                'value': indicator.get('indicator', 'N/A'),
                                'type': indicator.get('type', 'unknown').lower(),
                                'source': 'AlienVault OTX',
                                'tags': tags[:2],
                                'created': pulse.get('created', datetime.now().isoformat())
                            })
                            total_indicators += 1
            
            return {
                'source_info': {
                    'name': 'AlienVault OTX',
                    'last_updated': datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
                    'indicators_count': total_indicators,
                    'description': 'Open Threat Exchange'
                },
                'indicators': indicators,
                'categories': categories
            }
            
        except Exception as e:
            logger.error(f"OTX fetch error: {e}")
            return None
    
    def _fetch_threatfox_indicators(self):
        try:
            iocs_data = self.threatfox_client.get_recent_iocs(days=2, limit=15)  # Reduced
            if not isinstance(iocs_data, dict) or 'data' not in iocs_data:
                return None
                
            indicators = []
            categories = set()
            
            for ioc in iocs_data['data']:
                ioc_type = ioc.get('ioc_type', '').lower()
                if ioc_type == 'ip:port':
                    ioc_type = 'ip'
                elif 'hash' in ioc_type:
                    ioc_type = 'hash'
                elif ioc_type not in ['url', 'domain', 'ip']:
                    ioc_type = 'other'
                
                malware_family = ioc.get('malware', 'Unknown')
                if malware_family and malware_family != 'Unknown':
                    categories.add(malware_family)
                
                tags = ioc.get('tags', [])
                if isinstance(tags, list):
                    categories.update(tag for tag in tags[:2] if len(tag) > 2)
                
                indicators.append({
                    'value': ioc.get('ioc_value', 'N/A'),
                    'type': ioc_type,
                    'source': 'ThreatFox',
                    'tags': [malware_family] + (tags[:1] if isinstance(tags, list) else []),
                    'created': ioc.get('first_seen', datetime.now().isoformat()),
                    'confidence': ioc.get('confidence_level', 50)
                })
            
            return {
                'source_info': {
                    'name': 'ThreatFox',
                    'last_updated': datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
                    'indicators_count': len(indicators),
                    'description': 'Malware IOC database'
                },
                'indicators': indicators,
                'categories': categories
            }
            
        except Exception as e:
            logger.error(f"ThreatFox fetch error: {e}")
            return None
    
    def refresh_feeds(self):
        self.cache = {}
        self.cache_time = 0
        return self.get_threat_feeds()
