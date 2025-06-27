"""
VirusTotal API integration service
"""
import requests
import time
from flask import current_app
from functools import wraps

class RateLimiter:
    """Rate limiter to respect API quotas"""
    def __init__(self, calls_per_minute):
        self.calls_per_minute = calls_per_minute
        self.interval = 60.0 / calls_per_minute
        self.last_call = 0

    def __call__(self, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            now = time.time()
            elapsed = now - self.last_call
            
            if elapsed < self.interval:
                time.sleep(self.interval - elapsed)
                
            self.last_call = time.time()
            return func(*args, **kwargs)
        return wrapper


class VirusTotalService:
    """Service for interacting with VirusTotal API"""
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        self.rate_limit = RateLimiter(4)  # 4 requests per minute
    
    @RateLimiter(4)
    def check_ip(self, ip_address):
        """
        Check IP reputation
        
        Args:
            ip_address: The IP address to check
            
        Returns:
            dict: IP reputation data
        """
        url = f"{self.base_url}ip_addresses/{ip_address}"
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return self._process_response(response.json())
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"VirusTotal API error for IP {ip_address}: {str(e)}")
            return {"error": str(e), "status": "error"}
    
    @RateLimiter(4)
    def check_domain(self, domain):
        """
        Check domain reputation
        
        Args:
            domain: The domain to check
            
        Returns:
            dict: Domain reputation data
        """
        url = f"{self.base_url}domains/{domain}"
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return self._process_response(response.json())
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"VirusTotal API error for domain {domain}: {str(e)}")
            return {"error": str(e), "status": "error"}
    
    @RateLimiter(4)
    def check_url(self, url):
        """
        Check URL reputation
        
        Args:
            url: The URL to check
            
        Returns:
            dict: URL reputation data
        """
        # URL need to be submitted first, then analyzed
        url_id = self._get_url_id(url)
        if not url_id:
            return {"error": "Failed to submit URL", "status": "error"}
            
        analysis_url = f"{self.base_url}urls/{url_id}"
        try:
            response = requests.get(analysis_url, headers=self.headers)
            response.raise_for_status()
            return self._process_response(response.json())
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"VirusTotal API error for URL {url}: {str(e)}")
            return {"error": str(e), "status": "error"}
    
    @RateLimiter(4)
    def check_file(self, file_hash):
        """
        Check file hash reputation
        
        Args:
            file_hash: The file hash (MD5, SHA-1, or SHA-256)
            
        Returns:
            dict: File reputation data
        """
        url = f"{self.base_url}files/{file_hash}"
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return self._process_response(response.json())
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"VirusTotal API error for file hash {file_hash}: {str(e)}")
            return {"error": str(e), "status": "error"}
    
    def _get_url_id(self, url):
        """Submit a URL for scanning and get its ID"""
        submit_url = f"{self.base_url}urls"
        data = {"url": url}
        try:
            response = requests.post(submit_url, headers=self.headers, data=data)
            response.raise_for_status()
            return response.json().get("data", {}).get("id")
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"Error submitting URL to VirusTotal: {str(e)}")
            return None
    
    def _process_response(self, response_data):
        """Process and extract relevant information from API response"""
        result = {
            "status": "success",
            "source": "VirusTotal",
            "malicious_votes": 0,
            "total_votes": 0,
            "detection_ratio": 0,
            "last_analysis_date": None,
            "categories": [],
            "malware_families": [],
            "details": {}
        }
        
        data = response_data.get("data", {})
        attributes = data.get("attributes", {})
        
        # Process last analysis results
        last_analysis_results = attributes.get("last_analysis_results", {})
        if last_analysis_results:
            for engine, engine_result in last_analysis_results.items():
                result["total_votes"] += 1
                if engine_result.get("category") == "malicious":
                    result["malicious_votes"] += 1
            
            if result["total_votes"] > 0:
                result["detection_ratio"] = result["malicious_votes"] / result["total_votes"]
        
        # Get last analysis date
        result["last_analysis_date"] = attributes.get("last_analysis_date")
        
        # Get categories
        result["categories"] = attributes.get("categories", {})
        
        # Get malware families if available
        result["malware_families"] = attributes.get("popular_threat_classification", {}).get("suggested_threat_label", "")
        
        # Add full details for debugging
        result["details"] = attributes
        
        return result
