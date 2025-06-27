"""
AbuseIPDB API integration service
"""
import requests
import time
from flask import current_app
from functools import wraps
from services.virustotal import RateLimiter

class AbuseIPDBService:
    """Service for interacting with AbuseIPDB API"""
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2/"
        self.headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        self.rate_limit = RateLimiter(60)  # Approximately 1000 requests per day
    
    @RateLimiter(60)
    def check_ip(self, ip_address):
        """
        Check IP reputation in AbuseIPDB
        
        Args:
            ip_address: The IP address to check
            
        Returns:
            dict: IP reputation data
        """
        url = f"{self.base_url}check"
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90,
            "verbose": True
        }
        
        try:
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            return self._process_response(response.json())
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"AbuseIPDB API error for IP {ip_address}: {str(e)}")
            return {"error": str(e), "status": "error"}
    
    @RateLimiter(60)
    def get_blacklist(self, confidence_minimum=90):
        """
        Get blacklisted IPs from AbuseIPDB
        
        Args:
            confidence_minimum: Minimum confidence score (0-100)
            
        Returns:
            list: Blacklisted IP addresses
        """
        url = f"{self.base_url}blacklist"
        params = {
            "confidenceMinimum": confidence_minimum
        }
        
        try:
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            return response.json().get("data", [])
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"AbuseIPDB Blacklist API error: {str(e)}")
            return {"error": str(e), "status": "error"}
    
    def _process_response(self, response_data):
        """Process and extract relevant information from API response"""
        result = {
            "status": "success",
            "source": "AbuseIPDB",
            "abuse_score": 0,
            "total_reports": 0,
            "country_code": None,
            "isp": None,
            "usage_type": None,
            "last_reported": None,
            "categories": [],
            "details": {}
        }
        
        data = response_data.get("data", {})
        
        # Extract relevant fields
        result["abuse_score"] = data.get("abuseConfidenceScore", 0)
        result["total_reports"] = data.get("totalReports", 0)
        result["country_code"] = data.get("countryCode")
        result["isp"] = data.get("isp")
        result["usage_type"] = data.get("usageType")
        result["last_reported"] = data.get("lastReportedAt")
        
        # Extract report categories
        if "reports" in data:
            categories = set()
            for report in data.get("reports", []):
                for category in report.get("categories", []):
                    categories.add(category)
            result["categories"] = list(categories)
        
        # Full details for debugging
        result["details"] = data
        
        return result
