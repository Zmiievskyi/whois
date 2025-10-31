#!/usr/bin/env python3
"""
Configuration management for Provider Discovery Tool
Handles environment variables, .env files, and default settings
"""
import os
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from pathlib import Path

# Try to import python-dotenv for .env file support
try:
    from dotenv import load_dotenv
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False

@dataclass
class Settings:
    """Application settings with environment variable support"""
    
    # VirusTotal Configuration
    vt_api_key: Optional[str] = None
    vt_premium: bool = False
    vt_timeout: int = 30
    vt_cache_ttl: int = 3600
    
    # Censys Configuration (Phase 3B: Shodan alternative)
    censys_api_id: Optional[str] = None
    censys_api_secret: Optional[str] = None
    censys_cache_ttl: int = 7200  # 2 hours (longer due to rate limits)
    censys_rate_limit: int = 10  # requests per minute (conservative)
    
    # Shodan Configuration (Phase 3B: Premium WAF detection)
    shodan_api_key: Optional[str] = None
    shodan_cache_ttl: int = 14400  # 4 hours (very long due to cost)
    shodan_rate_limit: int = 1  # requests per minute (very conservative)

    # IPInfo Configuration (BGP/ASN/Geolocation)
    ipinfo_api_key: Optional[str] = None
    ipinfo_cache_ttl: int = 7200  # 2 hours
    ipinfo_rate_limit: int = 60  # requests per minute (50k/month = ~1666/day)

    # Application Settings
    app_debug: bool = False
    app_log_level: str = "INFO"
    app_cache_size: int = 1000
    
    # Rate Limiting
    rate_limit_enabled: bool = True
    vt_rate_limit_calls: int = 4
    vt_rate_limit_window: int = 60
    
    # Performance Settings
    dns_timeout: int = 15
    http_timeout: int = 20
    whois_timeout: int = 25
    
    # Feature Flags
    enable_dns_analysis: bool = True
    enable_virustotal: bool = True
    enable_caching: bool = True
    
    # Subdomain enumeration settings
    subdomain_wordlist_path: Optional[str] = None
    subdomain_dictionary_limit: int = 2000
    subdomain_analysis_limit: int = 300
    subdomain_max_concurrency: int = 60
    enable_ct_enumeration: bool = True
    ct_log_page_limit: int = 5
    enable_passive_dns_enumeration: bool = True
    enable_subfinder_enumeration: bool = False
    subfinder_binary_path: Optional[str] = None
    subfinder_timeout: int = 120
    enable_subdomain_detailed_analysis: bool = False  # Detailed DNS+HTTP analysis per subdomain (slow)
    
    # Streamlit Configuration
    streamlit_server_port: int = 8501
    streamlit_server_address: str = "localhost"
    
    # Internal settings
    _loaded_from_env: bool = field(default=False, init=False)
    
    def __post_init__(self):
        """Load environment variables after initialization"""
        self.load_from_env()
    
    def load_from_env(self):
        """Load settings from environment variables"""
        # Load .env file if available
        if DOTENV_AVAILABLE:
            env_file = Path(".env")
            if env_file.exists():
                load_dotenv(env_file)
                self._loaded_from_env = True
        
        # Load individual settings from environment
        self.vt_api_key = os.getenv("VT_API_KEY", self.vt_api_key)
        self.vt_premium = self._get_bool_env("VT_PREMIUM", self.vt_premium)
        self.vt_timeout = self._get_int_env("VT_TIMEOUT", self.vt_timeout)
        self.vt_cache_ttl = self._get_int_env("VT_CACHE_TTL", self.vt_cache_ttl)
        
        # Load Censys settings
        self.censys_api_id = os.getenv("CENSYS_API_ID", self.censys_api_id)
        self.censys_api_secret = os.getenv("CENSYS_API_SECRET", self.censys_api_secret)
        self.censys_cache_ttl = self._get_int_env("CENSYS_CACHE_TTL", self.censys_cache_ttl)
        self.censys_rate_limit = self._get_int_env("CENSYS_RATE_LIMIT", self.censys_rate_limit)
        
        # Load Shodan settings
        self.shodan_api_key = os.getenv("SHODAN_API_KEY", self.shodan_api_key)
        self.shodan_cache_ttl = self._get_int_env("SHODAN_CACHE_TTL", self.shodan_cache_ttl)
        self.shodan_rate_limit = self._get_int_env("SHODAN_RATE_LIMIT", self.shodan_rate_limit)

        # Load IPInfo settings
        self.ipinfo_api_key = os.getenv("IPINFO_API_KEY", self.ipinfo_api_key)
        self.ipinfo_cache_ttl = self._get_int_env("IPINFO_CACHE_TTL", self.ipinfo_cache_ttl)
        self.ipinfo_rate_limit = self._get_int_env("IPINFO_RATE_LIMIT", self.ipinfo_rate_limit)

        self.app_debug = self._get_bool_env("APP_DEBUG", self.app_debug)
        self.app_log_level = os.getenv("APP_LOG_LEVEL", self.app_log_level)
        self.app_cache_size = self._get_int_env("APP_CACHE_SIZE", self.app_cache_size)
        
        self.rate_limit_enabled = self._get_bool_env("RATE_LIMIT_ENABLED", self.rate_limit_enabled)
        self.vt_rate_limit_calls = self._get_int_env("VT_RATE_LIMIT_CALLS", self.vt_rate_limit_calls)
        self.vt_rate_limit_window = self._get_int_env("VT_RATE_LIMIT_WINDOW", self.vt_rate_limit_window)
        
        self.dns_timeout = self._get_int_env("DNS_TIMEOUT", self.dns_timeout)
        self.http_timeout = self._get_int_env("HTTP_TIMEOUT", self.http_timeout)
        self.whois_timeout = self._get_int_env("WHOIS_TIMEOUT", self.whois_timeout)
        
        self.enable_dns_analysis = self._get_bool_env("ENABLE_DNS_ANALYSIS", self.enable_dns_analysis)
        self.enable_virustotal = self._get_bool_env("ENABLE_VIRUSTOTAL", self.enable_virustotal)
        self.enable_caching = self._get_bool_env("ENABLE_CACHING", self.enable_caching)
        
        # Subdomain enumeration overrides
        self.subdomain_wordlist_path = os.getenv("SUBDOMAIN_WORDLIST_PATH", self.subdomain_wordlist_path)
        self.subdomain_dictionary_limit = self._get_int_env("SUBDOMAIN_DICTIONARY_LIMIT", self.subdomain_dictionary_limit)
        self.subdomain_analysis_limit = self._get_int_env("SUBDOMAIN_ANALYSIS_LIMIT", self.subdomain_analysis_limit)
        self.subdomain_max_concurrency = self._get_int_env("SUBDOMAIN_MAX_CONCURRENCY", self.subdomain_max_concurrency)
        self.enable_ct_enumeration = self._get_bool_env("ENABLE_CT_ENUMERATION", self.enable_ct_enumeration)
        self.ct_log_page_limit = self._get_int_env("CT_LOG_PAGE_LIMIT", self.ct_log_page_limit)
        self.enable_passive_dns_enumeration = self._get_bool_env("ENABLE_PASSIVE_DNS_ENUMERATION", self.enable_passive_dns_enumeration)
        self.enable_subfinder_enumeration = self._get_bool_env("ENABLE_SUBFINDER_ENUMERATION", self.enable_subfinder_enumeration)
        self.subfinder_binary_path = os.getenv("SUBFINDER_BINARY_PATH", self.subfinder_binary_path)
        self.subfinder_timeout = self._get_int_env("SUBFINDER_TIMEOUT", self.subfinder_timeout)
        self.enable_subdomain_detailed_analysis = self._get_bool_env("ENABLE_SUBDOMAIN_DETAILED_ANALYSIS", self.enable_subdomain_detailed_analysis)
        
        self.streamlit_server_port = self._get_int_env("STREAMLIT_SERVER_PORT", self.streamlit_server_port)
        self.streamlit_server_address = os.getenv("STREAMLIT_SERVER_ADDRESS", self.streamlit_server_address)
    
    def _get_bool_env(self, key: str, default: bool) -> bool:
        """Get boolean environment variable"""
        value = os.getenv(key)
        if value is None:
            return default
        return value.lower() in ("true", "1", "yes", "on")
    
    def _get_int_env(self, key: str, default: int) -> int:
        """Get integer environment variable"""
        value = os.getenv(key)
        if value is None:
            return default
        try:
            return int(value)
        except ValueError:
            return default
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary"""
        return {
            field.name: getattr(self, field.name) 
            for field in self.__dataclass_fields__.values()
            if not field.name.startswith('_')
        }
    
    def is_virustotal_enabled(self) -> bool:
        """Check if VirusTotal integration should be enabled"""
        return (
            self.enable_virustotal and 
            self.vt_api_key is not None and 
            len(self.vt_api_key.strip()) > 0
        )
    
    def is_censys_enabled(self) -> bool:
        """Check if Censys integration should be enabled"""
        return (
            self.censys_api_id is not None and 
            self.censys_api_secret is not None and
            len(self.censys_api_id.strip()) > 0 and
            len(self.censys_api_secret.strip()) > 0
        )
    
    def is_shodan_enabled(self) -> bool:
        """Check if Shodan integration should be enabled"""
        return (
            self.shodan_api_key is not None and
            len(self.shodan_api_key.strip()) > 0
        )

    def is_ipinfo_enabled(self) -> bool:
        """Check if IPInfo integration should be enabled"""
        # IPInfo works without API key (free tier), but better with token
        return True

    def get_virustotal_config(self) -> Dict[str, Any]:
        """Get VirusTotal-specific configuration"""
        return {
            "api_key": self.vt_api_key,
            "is_premium": self.vt_premium,
            "timeout": self.vt_timeout,
            "cache_ttl": self.vt_cache_ttl,
            "rate_limit_calls": self.vt_rate_limit_calls,
            "rate_limit_window": self.vt_rate_limit_window,
        }
    
    def get_censys_config(self) -> Dict[str, Any]:
        """Get Censys-specific configuration"""
        return {
            "api_id": self.censys_api_id,
            "api_secret": self.censys_api_secret,
            "cache_ttl": self.censys_cache_ttl,
            "rate_limit": self.censys_rate_limit,
        }
    
    def get_shodan_config(self) -> Dict[str, Any]:
        """Get Shodan-specific configuration"""
        return {
            "api_key": self.shodan_api_key,
            "cache_ttl": self.shodan_cache_ttl,
            "rate_limit": self.shodan_rate_limit,
        }

    def get_ipinfo_config(self) -> Dict[str, Any]:
        """Get IPInfo-specific configuration"""
        return {
            "api_key": self.ipinfo_api_key,
            "cache_ttl": self.ipinfo_cache_ttl,
            "rate_limit": self.ipinfo_rate_limit,
        }

    def get_performance_config(self) -> Dict[str, int]:
        """Get performance-related configuration"""
        return {
            "dns_timeout": self.dns_timeout,
            "http_timeout": self.http_timeout,
            "whois_timeout": self.whois_timeout,
            "cache_size": self.app_cache_size,
        }
    
    def validate(self) -> list[str]:
        """Validate configuration and return list of issues"""
        issues = []
        
        # Validate timeouts
        if self.dns_timeout <= 0:
            issues.append("DNS timeout must be positive")
        if self.http_timeout <= 0:
            issues.append("HTTP timeout must be positive")
        if self.whois_timeout <= 0:
            issues.append("WHOIS timeout must be positive")
        
        # Validate cache settings
        if self.app_cache_size <= 0:
            issues.append("Cache size must be positive")
        if self.vt_cache_ttl <= 0:
            issues.append("VirusTotal cache TTL must be positive")
        
        # Validate rate limiting
        if self.vt_rate_limit_calls <= 0:
            issues.append("VirusTotal rate limit calls must be positive")
        if self.vt_rate_limit_window <= 0:
            issues.append("VirusTotal rate limit window must be positive")
        
        # Validate VirusTotal API key format (basic check)
        if self.vt_api_key and len(self.vt_api_key) < 10:
            issues.append("VirusTotal API key appears to be too short")
        
        return issues

# Global settings instance
_settings: Optional[Settings] = None

def get_settings(reload: bool = False) -> Settings:
    """Get global settings instance (singleton pattern)"""
    global _settings
    if _settings is None or reload:
        _settings = Settings()
    return _settings

def configure_logging(settings: Settings):
    """Configure logging based on settings"""
    import logging
    
    # Set log level
    log_level = getattr(logging, settings.app_log_level.upper(), logging.INFO)
    
    # Configure basic logging
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Configure specific loggers if debug mode
    if settings.app_debug:
        logging.getLogger('provider_discovery').setLevel(logging.DEBUG)
        logging.getLogger('virustotal').setLevel(logging.DEBUG)

def print_configuration_info(settings: Settings):
    """Print configuration information for debugging"""
    print("🔧 Provider Discovery Configuration")
    print("=" * 50)
    
    print(f"🦠 VirusTotal: {'✅ Enabled' if settings.is_virustotal_enabled() else '❌ Disabled'}")
    if settings.vt_api_key:
        masked_key = settings.vt_api_key[:8] + "..." + settings.vt_api_key[-4:]
        print(f"   API Key: {masked_key}")
        print(f"   Premium: {'Yes' if settings.vt_premium else 'No'}")
    
    print(f"🔍 Censys: {'✅ Enabled' if settings.is_censys_enabled() else '❌ Disabled'}")
    if settings.censys_api_id:
        masked_id = settings.censys_api_id[:8] + "..." + settings.censys_api_id[-4:]
        print(f"   API ID: {masked_id}")
        print(f"   Rate Limit: {settings.censys_rate_limit}/min")
    
    print(f"🔍 Shodan: {'✅ Enabled' if settings.is_shodan_enabled() else '❌ Disabled'}")
    if settings.shodan_api_key:
        masked_key = settings.shodan_api_key[:8] + "..." + settings.shodan_api_key[-4:]
        print(f"   API Key: {masked_key}")
        print(f"   Rate Limit: {settings.shodan_rate_limit}/min")

    print(f"🌐 IPInfo: {'✅ Enabled' if settings.is_ipinfo_enabled() else '❌ Disabled'}")
    if settings.ipinfo_api_key:
        masked_key = settings.ipinfo_api_key[:8] + "..." + settings.ipinfo_api_key[-4:]
        print(f"   API Key: {masked_key} (50k/month)")
        print(f"   Rate Limit: {settings.ipinfo_rate_limit}/min")
    else:
        print(f"   Mode: Free tier (1000/day, shared IP limit)")

    print(f"🔍 DNS Analysis: {'✅ Enabled' if settings.enable_dns_analysis else '❌ Disabled'}")
    print(f"📊 Caching: {'✅ Enabled' if settings.enable_caching else '❌ Disabled'}")
    print(f"⚡ Rate Limiting: {'✅ Enabled' if settings.rate_limit_enabled else '❌ Disabled'}")
    
    print(f"\n⏱️  Timeouts: DNS={settings.dns_timeout}s, HTTP={settings.http_timeout}s, WHOIS={settings.whois_timeout}s")
    print(f"🗄️  Cache: Size={settings.app_cache_size}, VT TTL={settings.vt_cache_ttl}s")
    
    if settings.app_debug:
        print(f"\n🐛 Debug Mode: ✅ Enabled")
        print(f"📝 Log Level: {settings.app_log_level}")
    
    # Validate configuration
    issues = settings.validate()
    if issues:
        print(f"\n⚠️  Configuration Issues:")
        for issue in issues:
            print(f"   • {issue}")
    else:
        print(f"\n✅ Configuration is valid")

# Example usage and testing
if __name__ == "__main__":
    settings = get_settings()
    configure_logging(settings)
    print_configuration_info(settings)
