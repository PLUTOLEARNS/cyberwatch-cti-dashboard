"""
Threat reports service - optimized
"""
import time
import logging
from datetime import datetime, timedelta
from services.api_clients.alienvault_otx import AlienVaultOTXClient

logger = logging.getLogger(__name__)

class ThreatReportService:
    def __init__(self, otx_api_key=None):
        self.otx_client = AlienVaultOTXClient(api_key=otx_api_key) if otx_api_key else None
        self.cache = {}
        self.cache_time = 0
        self.cache_duration = 1800  # 30 minutes
        
    def get_threat_reports(self):
        current_time = time.time()
        if self.cache and (current_time - self.cache_time) < self.cache_duration:
            return self.cache
            
        reports = {
            'threat_reports': [],
            'report_categories': [],
            'trending_topics': []
        }
        
        if self.otx_client:
            try:
                pulses_data = self.otx_client.get_pulses(limit=8)  # Reduced
                
                if isinstance(pulses_data, dict) and 'results' in pulses_data:
                    for pulse in pulses_data['results']:
                        tags = pulse.get('tags', [])
                        
                        for tag in tags[:3]:  # Limit tags
                            if tag not in reports['report_categories'] and len(tag) > 3:
                                reports['report_categories'].append(tag)
                        
                        if pulse.get('name') and pulse.get('name') not in reports['trending_topics']:
                            reports['trending_topics'].append(pulse.get('name'))
                        
                        severity = self._calculate_severity(pulse)
                        
                        report = {
                            'title': pulse.get('name', 'Untitled Pulse'),
                            'date': pulse.get('modified', datetime.now().strftime('%Y-%m-%d')),
                            'author': pulse.get('author_name', 'AlienVault OTX'),
                            'summary': (pulse.get('description', '')[:150] + '...') if pulse.get('description') else 'No description',
                            'severity': severity,
                            'id': pulse.get('id', ''),
                            'source': 'AlienVault OTX'
                        }
                        
                        reports['threat_reports'].append(report)
            except Exception as e:
                logger.error(f"OTX pulses error: {e}")
        
        reports['report_categories'] = reports['report_categories'][:8]
        reports['trending_topics'] = reports['trending_topics'][:4]
        
        if not reports['threat_reports']:
            reports = {
                'threat_reports': [],
                'report_categories': ['Malware', 'APT', 'Phishing'],
                'trending_topics': ['Real-time Monitoring']
            }
        
        self.cache = reports
        self.cache_time = current_time
        
        return reports
        
    def get_report_detail(self, report_id, source=None):
        if source == 'AlienVault OTX' and self.otx_client:
            try:
                return self.otx_client.get_pulse_detail(report_id)
            except Exception as e:
                return {'status': 'error', 'message': str(e)}
                
        return {'status': 'error', 'message': 'Source not supported'}
        
    def _calculate_severity(self, pulse):
        score = 0
        
        indicator_count = pulse.get('indicator_count', 0)
        if indicator_count > 50:
            score += 3
        elif indicator_count > 20:
            score += 2
        elif indicator_count > 5:
            score += 1
        
        tags = [tag.lower() for tag in pulse.get('tags', [])]
        critical_tags = ['zero-day', 'rce', 'privilege-escalation']
        high_tags = ['apt', 'ransomware', 'backdoor', 'trojan', 'malware', 'exploit']
        
        for tag in tags:
            if any(ct in tag for ct in critical_tags):
                score += 3
                break
            elif any(ht in tag for ht in high_tags):
                score += 2
                break
        
        description = pulse.get('description', '').lower()
        if any(word in description for word in ['critical', 'zero-day', 'emergency']):
            score += 2
        elif any(word in description for word in ['high', 'important', 'urgent']):
            score += 1
        
        try:
            created = pulse.get('created')
            if created:
                created_date = datetime.fromisoformat(created.replace('Z', '+00:00'))
                if datetime.now().replace(tzinfo=created_date.tzinfo) - created_date < timedelta(days=7):
                    score += 1
        except:
            pass
        
        if score >= 7:
            return 'Critical'
        elif score >= 4:
            return 'High'
        elif score >= 2:
            return 'Medium'
        else:
            return 'Low'
