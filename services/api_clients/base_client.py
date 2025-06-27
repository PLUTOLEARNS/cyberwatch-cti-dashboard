"""
Base API Client with rate limiting, caching, and error handling
"""
import time
import logging
import requests
from typing import Optional, Dict, Any
from functools import wraps

logger = logging.getLogger(__name__)

class RateLimiter:
    """Simple rate limiter implementation"""
    
    def __init__(self, calls_per_hour: int):
        self.calls_per_hour = calls_per_hour
        self.calls = []
        
    def wait_if_needed(self):
        """Wait if rate limit would be exceeded"""
        now = time.time()
        # Remove calls older than 1 hour
        self.calls = [call_time for call_time in self.calls if now - call_time < 3600]
        
        if len(self.calls) >= self.calls_per_hour:
            # Need to wait
            oldest_call = min(self.calls)
            wait_time = 3600 - (now - oldest_call) + 1  # Add 1 second buffer
            if wait_time > 0:
                logger.info(f"Rate limit reached, waiting {wait_time:.2f} seconds")
                time.sleep(wait_time)
                
        self.calls.append(now)

class SimpleCache:
    """Simple in-memory cache with TTL"""
    
    def __init__(self):
        self.cache = {}
        
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache if not expired"""
        if key in self.cache:
            value, timestamp = self.cache[key]
            if time.time() - timestamp < 300:  # 5 minute TTL
                return value
            else:
                del self.cache[key]
        return None
        
    def set(self, key: str, value: Any):
        """Set value in cache with current timestamp"""
        self.cache[key] = (value, time.time())
        
    def clear(self):
        """Clear all cached values"""
        self.cache.clear()

class BaseClient:
    """Base API client with common functionality"""
    
    def __init__(self, api_key: Optional[str] = None, base_url: str = "", 
                 rate_limit: int = 60, timeout: int = 30):
        """
        Initialize base API client
        
        Args:
            api_key: API key for authentication
            base_url: Base URL for API endpoints
            rate_limit: Maximum calls per hour
            timeout: Request timeout in seconds
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.rate_limiter = RateLimiter(rate_limit)
        self.cache = SimpleCache()
        
    def _get_headers(self) -> Dict[str, str]:
        """Get default headers for requests"""
        return {
            "User-Agent": "CyberWatch-CTI-Dashboard/1.0",
            "Accept": "application/json"
        }
        
    def _make_request(self, method: str, endpoint: str, 
                     params: Optional[Dict] = None,
                     data: Optional[Dict] = None,
                     headers: Optional[Dict] = None,
                     cache_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Make HTTP request with rate limiting and caching
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (will be appended to base_url)
            params: Query parameters
            data: Request body data
            headers: Custom headers
            cache_key: Cache key for GET requests
            
        Returns:
            dict: Response data
        """
        # Check cache for GET requests
        if method.upper() == 'GET' and cache_key:
            cached_response = self.cache.get(cache_key)
            if cached_response is not None:
                logger.debug(f"Cache hit for {cache_key}")
                return cached_response
                
        # Apply rate limiting
        self.rate_limiter.wait_if_needed()
        
        # Prepare request
        url = f"{self.base_url}{endpoint}" if not endpoint.startswith('http') else endpoint
        request_headers = self._get_headers()
        if headers:
            request_headers.update(headers)
            
        try:
            logger.info(f"Making {method} request to {url}")
            
            # Handle different content types
            kwargs = {
                'method': method,
                'url': url,
                'params': params,
                'headers': request_headers,
                'timeout': self.timeout
            }
            
            if data:
                if request_headers.get('Content-Type') == 'application/x-www-form-urlencoded':
                    kwargs['data'] = data
                else:
                    kwargs['json'] = data
            
            response = requests.request(**kwargs)
            response.raise_for_status()
            
            result = response.json()
            
            # Cache successful GET responses
            if method.upper() == 'GET' and cache_key and response.status_code == 200:
                self.cache.set(cache_key, result)
                
            return result
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            return {
                'status': 'error',
                'message': f"Request failed: {str(e)}",
                'data': []
            }
        except ValueError as e:
            logger.error(f"Failed to parse JSON response: {e}")
            return {
                'status': 'error', 
                'message': f"Invalid JSON response: {str(e)}",
                'data': []
            }
            
    def clear_cache(self):
        """Clear the client's cache"""
        self.cache.clear()
        
    def test_connection(self) -> bool:
        """Test if the API is reachable (to be implemented by subclasses)"""
        return True
