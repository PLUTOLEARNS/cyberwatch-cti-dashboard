"""
Configuration settings for the CTI Dashboard
"""
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Configuration class for the application"""
    # Secret key for Flask sessions
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    
    # Database settings
    DATABASE_URI = os.environ.get('DATABASE_URI') or 'sqlite:///cti_dashboard.db'
    
    # API Keys
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
    ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY')
    SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY')
    ALIENVAULT_API_KEY = os.environ.get('ALIENVAULT_API_KEY')
    # Note: Maltiverse requires business account, so we use free alternatives
    
    # API rate limits (requests per minute)
    VIRUSTOTAL_RATE_LIMIT = 4  # 4 requests/minute (500/day)
    ABUSEIPDB_RATE_LIMIT = 60  # Roughly 1000 requests/day
    
    # Cache settings
    CACHE_TYPE = 'simple'
    CACHE_DEFAULT_TIMEOUT = 300  # 5 minutes
    
    # Feed refresh settings
    FEED_REFRESH_INTERVAL = 1800  # 30 minutes in seconds
