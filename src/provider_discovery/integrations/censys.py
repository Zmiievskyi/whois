"""
Censys integration for WAF detection and security analysis
Alternative to Shodan for Phase 3B implementation
"""

import logging
from typing import Dict, List, Optional, Any
from .base import APIKeyIntegration

logger = logging.getLogger(__name__)

try:
    from censys.search import CensysHosts
    from censys.common.exceptions import CensysException
    CENSYS_AVAILABLE = True
except ImportError:
    CENSYS_AVAILABLE = False
    CensysHosts = None
    CensysException = Exception

class CensysIntegration(APIKeyIntegration):
    """
    Censys integration for network and security analysis
    
    Free tier: 250 queries per month
    Features:
    - HTTP headers analysis for WAF detection
    - TLS/SSL certificate analysis
    - Service discovery and fingerprinting
    - Geographic distribution analysis
    """
    
    def __init__(self, api_id: Optional[str] = None, api_secret: Optional[str] = None):
        """
        Initialize Censys integration
        
        Args:
            api_id: Censys API ID
            api_secret: Censys API Secret
        """
        
        # Initialize parent with API settings
        super().__init__(
            service_name="censys",
            api_key=api_id  # Using api_key field for API ID
        )
        
        self.api_secret = api_secret
        self.client = None
        self.cache_ttl = 7200  # 2 hours default
        self.rate_limit = 10   # 10 requests per minute default
        
        # Initialize from settings if not provided
        if not api_id or not api_secret:
            self._init_from_settings()
        
        # Initialize client if we have credentials
        if self.api_key and self.api_secret:
            self._init_client()
    
    def _init_from_settings(self):
        """Initialize API credentials from settings"""
        try:
            from ..config.settings import get_settings
            settings = get_settings()
            
            if hasattr(settings, 'censys_api_id') and settings.censys_api_id:
                self.api_key = settings.censys_api_id
            
            if hasattr(settings, 'censys_api_secret') and settings.censys_api_secret:
                self.api_secret = settings.censys_api_secret
                
            if hasattr(settings, 'censys_cache_ttl'):
                self.cache_ttl = settings.censys_cache_ttl
                
            if hasattr(settings, 'censys_rate_limit'):
                self.rate_limit = settings.censys_rate_limit
                
            # Setup rate limiter for censys service
            if hasattr(self.rate_limiter, 'add_service'):
                self.rate_limiter.add_service('censys', self.rate_limit, 60)  # per minute
                
        except Exception as e:
            logger.debug(f"Could not load Censys settings: {e}")
    
    def _init_client(self):
        """Initialize Censys client"""
        if not CENSYS_AVAILABLE:
            logger.warning("Censys library not available. Install with: pip install censys")
            return
        
        try:
            self.client = CensysHosts(api_id=self.api_key, api_secret=self.api_secret)
            logger.info("Censys client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Censys client: {e}")
            self.client = None
    
    @property
    def is_enabled(self) -> bool:
        """Check if Censys integration is enabled and configured"""
        return (CENSYS_AVAILABLE and 
                self.client is not None and 
                self.api_key is not None and 
                self.api_secret is not None)
    
    def test_connection(self) -> Dict[str, Any]:
        """
        Test Censys API connection
        
        Returns:
            Dict with connection status and account info
        """
        if not self.is_enabled:
            return {
                'success': False,
                'error': 'Censys not enabled or configured',
                'available': CENSYS_AVAILABLE
            }
        
        try:
            account_info = self.client.account()
            return {
                'success': True,
                'account': {
                    'email': account_info.get('email', 'N/A'),
                    'quota': account_info.get('quota', {}),
                    'plan': account_info.get('plan', 'unknown')
                }
            }
        except CensysException as e:
            return {
                'success': False,
                'error': f'Censys API error: {str(e)}'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Unexpected error: {str(e)}'
            }
    
    def search_by_domain(self, domain: str, limit: int = 10) -> Dict[str, Any]:
        """
        Search for hosts serving a specific domain
        
        Args:
            domain: Domain to search for
            limit: Maximum number of results
            
        Returns:
            Dict with search results and analysis
        """
        if not self.is_enabled:
            return {'error': 'Censys not enabled'}
        
        cache_key = f"domain_search_{domain}_{limit}"
        cached_result = self.cache.get('domain_analysis', cache_key)
        if cached_result:
            return cached_result
        
        try:
            # Apply rate limiting
            self.rate_limiter.wait_if_needed('censys')
            
            # Search for hosts serving this domain
            query = f'services.http.request.headers.host: "{domain}"'
            result = self.client.search(query, per_page=min(limit, 100))
            
            hosts_data = []
            waf_detections = []
            cdn_detections = []
            
            for i, host in enumerate(result()):
                if i >= limit:
                    break
                
                host_info = self._analyze_host(host, domain)
                hosts_data.append(host_info)
                
                # Collect WAF/CDN detections
                if host_info.get('waf_detected'):
                    waf_detections.extend(host_info['waf_detected'])
                if host_info.get('cdn_detected'):
                    cdn_detections.extend(host_info['cdn_detected'])
            
            analysis_result = {
                'domain': domain,
                'total_hosts': result.count,
                'analyzed_hosts': len(hosts_data),
                'hosts': hosts_data,
                'summary': {
                    'waf_providers': list(set(waf_detections)),
                    'cdn_providers': list(set(cdn_detections)),
                    'has_waf': len(waf_detections) > 0,
                    'has_cdn': len(cdn_detections) > 0
                }
            }
            
            # Cache the result
            self.cache.set('domain_analysis', cache_key, analysis_result)
            
            return analysis_result
            
        except CensysException as e:
            logger.error(f"Censys search error for {domain}: {e}")
            return {'error': f'Search failed: {str(e)}'}
        except Exception as e:
            logger.error(f"Unexpected error searching {domain}: {e}")
            return {'error': f'Unexpected error: {str(e)}'}
    
    def _analyze_host(self, host: Dict, domain: str) -> Dict[str, Any]:
        """
        Analyze a single host for WAF/CDN detection
        
        Args:
            host: Host data from Censys
            domain: Domain being analyzed
            
        Returns:
            Dict with host analysis
        """
        ip = host.get('ip', 'unknown')
        services = host.get('services', [])
        
        host_info = {
            'ip': ip,
            'domain': domain,
            'location': host.get('location', {}),
            'autonomous_system': host.get('autonomous_system', {}),
            'services': [],
            'waf_detected': [],
            'cdn_detected': [],
            'security_headers': []
        }
        
        # Analyze HTTP services
        for service in services:
            if 'http' not in service:
                continue
            
            http_data = service.get('http', {})
            service_info = self._analyze_http_service(http_data)
            host_info['services'].append(service_info)
            
            # Collect detections
            if service_info.get('waf_indicators'):
                host_info['waf_detected'].extend(service_info['waf_indicators'])
            if service_info.get('cdn_indicators'):
                host_info['cdn_detected'].extend(service_info['cdn_indicators'])
            if service_info.get('security_headers'):
                host_info['security_headers'].extend(service_info['security_headers'])
        
        return host_info
    
    def _analyze_http_service(self, http_data: Dict) -> Dict[str, Any]:
        """
        Analyze HTTP service for WAF/CDN indicators
        
        Args:
            http_data: HTTP service data from Censys
            
        Returns:
            Dict with service analysis
        """
        response = http_data.get('response', {})
        headers = response.get('headers', {})
        
        service_info = {
            'port': http_data.get('port', 80),
            'protocol': http_data.get('protocol', 'http'),
            'headers': headers,
            'waf_indicators': [],
            'cdn_indicators': [],
            'security_headers': []
        }
        
        # WAF Detection patterns
        waf_patterns = {
            'cloudflare': ['cloudflare', 'cf-ray'],
            'akamai': ['akamai', 'akamaihost'],
            'aws_waf': ['awselb', 'cloudfront'],
            'fastly': ['fastly'],
            'imperva': ['imperva', 'incapsula'],
            'generic_waf': ['waf', 'firewall']
        }
        
        # CDN Detection patterns  
        cdn_patterns = {
            'cloudflare': ['cloudflare', 'cf-'],
            'akamai': ['akamai'],
            'aws_cloudfront': ['cloudfront', 'x-amz-cf-'],
            'fastly': ['fastly'],
            'maxcdn': ['maxcdn'],
            'keycdn': ['keycdn']
        }
        
        # Check headers for indicators
        for header_name, header_value in headers.items():
            header_lower = f"{header_name}:{header_value}".lower()
            
            # WAF detection
            for waf_type, patterns in waf_patterns.items():
                if any(pattern in header_lower for pattern in patterns):
                    service_info['waf_indicators'].append(waf_type)
            
            # CDN detection
            for cdn_type, patterns in cdn_patterns.items():
                if any(pattern in header_lower for pattern in patterns):
                    service_info['cdn_indicators'].append(cdn_type)
        
        # Security headers detection
        security_headers = [
            'x-frame-options', 'content-security-policy', 
            'x-content-type-options', 'strict-transport-security',
            'x-xss-protection', 'referrer-policy'
        ]
        
        for sec_header in security_headers:
            if sec_header in headers:
                service_info['security_headers'].append(sec_header)
        
        return service_info
    
    def get_waf_summary(self, domain: str) -> Dict[str, Any]:
        """
        Get WAF detection summary for a domain
        
        Args:
            domain: Domain to analyze
            
        Returns:
            Dict with WAF analysis summary
        """
        search_result = self.search_by_domain(domain, limit=5)
        
        if 'error' in search_result:
            return search_result
        
        summary = search_result.get('summary', {})
        
        return {
            'domain': domain,
            'waf_detected': summary.get('has_waf', False),
            'waf_providers': summary.get('waf_providers', []),
            'cdn_detected': summary.get('has_cdn', False),
            'cdn_providers': summary.get('cdn_providers', []),
            'confidence': self._calculate_confidence(summary),
            'data_source': 'censys'
        }
    
    def _calculate_confidence(self, summary: Dict) -> str:
        """Calculate confidence level for detection"""
        waf_count = len(summary.get('waf_providers', []))
        cdn_count = len(summary.get('cdn_providers', []))
        
        if waf_count >= 2 or cdn_count >= 2:
            return 'high'
        elif waf_count >= 1 or cdn_count >= 1:
            return 'medium'
        else:
            return 'low'
    
    def _make_api_request(self, endpoint: str, **kwargs) -> Dict[str, Any]:
        """
        Make API request to Censys (required by base class)
        
        Note: Censys uses its own client library, so this method
        is mainly for compatibility with the base class interface
        """
        if not self.is_enabled:
            return {'error': 'Censys not enabled'}
        
        # This is a generic wrapper - actual API calls are made
        # through the Censys client library in specific methods
        try:
            # Apply rate limiting
            self.rate_limiter.wait_if_needed('censys')
            
            # For now, return a generic response
            # Specific API calls are handled in dedicated methods
            return {'status': 'ok', 'message': 'Use specific Censys methods'}
            
        except Exception as e:
            logger.error(f"Censys API request failed: {e}")
            return {'error': str(e)}

# Singleton instance
_censys_integration = None

def get_censys_integration() -> CensysIntegration:
    """Get singleton Censys integration instance"""
    global _censys_integration
    if _censys_integration is None:
        _censys_integration = CensysIntegration()
    return _censys_integration
