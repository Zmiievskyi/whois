#!/usr/bin/env python3
"""
Shodan integration for WAF detection and security analysis
Phase 3B implementation for enhanced provider classification
"""

import logging
import time
from typing import Dict, List, Optional, Any, Set
from .base import APIKeyIntegration

logger = logging.getLogger(__name__)

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False
    shodan = None

class ShodanIntegration(APIKeyIntegration):
    """
    Shodan integration for advanced security and infrastructure analysis
    
    Free tier: 1 query credit per month (very limited)
    Developer tier: $59/month - 10,000 query credits
    Features:
    - WAF detection via HTTP signatures and headers
    - Port scanning and service discovery
    - SSL/TLS certificate analysis
    - Technology stack fingerprinting
    - Geographic distribution analysis
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Shodan integration
        
        Args:
            api_key: Shodan API key
        """
        
        # Initialize parent with API settings
        super().__init__(
            service_name="shodan",
            api_key=api_key
        )
        
        self.client = None
        self.cache_ttl = 14400  # 4 hours (longer due to cost)
        self.rate_limit = 1     # 1 request per minute (very conservative)
        
        # Initialize from settings if not provided
        if not api_key:
            self._init_from_settings()
        
        # Initialize client if we have credentials
        if self.api_key:
            self._init_client()
    
    def _init_from_settings(self):
        """Initialize API credentials from settings"""
        try:
            from ..config.settings import get_settings
            settings = get_settings()
            
            if hasattr(settings, 'shodan_api_key') and settings.shodan_api_key:
                self.api_key = settings.shodan_api_key
                
            if hasattr(settings, 'shodan_cache_ttl'):
                self.cache_ttl = settings.shodan_cache_ttl
                
            if hasattr(settings, 'shodan_rate_limit'):
                self.rate_limit = settings.shodan_rate_limit
                
            # Setup rate limiter for shodan service
            if hasattr(self.rate_limiter, 'add_service'):
                self.rate_limiter.add_service('shodan', self.rate_limit, 60)  # per minute
                
        except Exception as e:
            logger.debug(f"Could not load Shodan settings: {e}")
    
    def _init_client(self):
        """Initialize Shodan client"""
        if not SHODAN_AVAILABLE:
            logger.warning("Shodan library not available. Install with: pip install shodan")
            return
        
        try:
            self.client = shodan.Shodan(self.api_key)
            logger.info("Shodan client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Shodan client: {e}")
            self.client = None
    
    @property
    def is_enabled(self) -> bool:
        """Check if Shodan integration is enabled and configured"""
        return (SHODAN_AVAILABLE and 
                self.client is not None and 
                self.api_key is not None)
    
    def _make_api_request(self, endpoint: str, **kwargs) -> Dict[str, Any]:
        """
        Make API request to Shodan service
        
        Args:
            endpoint: API endpoint (method name on Shodan client)
            **kwargs: Additional arguments for the API call
            
        Returns:
            Dict with API response data
        """
        if not self.is_enabled:
            return {
                'success': False,
                'error': 'Shodan integration not available'
            }
        
        try:
            # Get the method from the client
            method = getattr(self.client, endpoint)
            
            # Make the API call
            result = method(**kwargs)
            
            self._requests_made += 1
            
            return {
                'success': True,
                'data': result
            }
            
        except shodan.APIError as e:
            self._errors += 1
            return {
                'success': False,
                'error': f'Shodan API error: {str(e)}'
            }
        except Exception as e:
            self._errors += 1
            return {
                'success': False,
                'error': f'Request failed: {str(e)}'
            }
    
    def test_connection(self) -> Dict[str, Any]:
        """
        Test Shodan API connection and get account info
        
        Returns:
            Dict with connection status and account info
        """
        if not self.is_enabled:
            return {
                'success': False,
                'error': 'Shodan not enabled or configured',
                'available': SHODAN_AVAILABLE
            }
        
        try:
            # Get account info (free API call)
            account_info = self.client.info()
            return {
                'success': True,
                'account': {
                    'plan': account_info.get('plan', 'unknown'),
                    'query_credits': account_info.get('query_credits', 0),
                    'scan_credits': account_info.get('scan_credits', 0),
                    'monitored_ips': account_info.get('monitored_ips', 0)
                },
                'rate_limits': {
                    'query_credits_remaining': account_info.get('query_credits', 0),
                    'scan_credits_remaining': account_info.get('scan_credits', 0)
                }
            }
        except shodan.APIError as e:
            return {
                'success': False,
                'error': f'Shodan API error: {str(e)}'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Unexpected error: {str(e)}'
            }
    
    def get_account_info(self) -> Dict[str, Any]:
        """
        Get detailed Shodan account information including credits and usage
        
        Returns:
            Dict with account details, credits, and usage information
        """
        if not self.is_enabled:
            return {
                'success': False,
                'error': 'Shodan integration not available',
                'credits_remaining': 0,
                'plan': 'Not Available'
            }
        
        try:
            # Get account information
            account_info = self.client.info()
            
            query_credits = account_info.get('query_credits', 0)
            scan_credits = account_info.get('scan_credits', 0)
            plan = account_info.get('plan', 'Unknown')
            
            # Calculate credit status
            credit_status = self._get_credit_status(query_credits)
            
            return {
                'success': True,
                'plan': plan,
                'query_credits': query_credits,
                'scan_credits': scan_credits,
                'credits_remaining': query_credits,
                'credit_status': credit_status,
                'usage_summary': self._format_usage_summary(account_info),
                'account_info': account_info
            }
            
        except shodan.APIError as e:
            return {
                'success': False,
                'error': f'Shodan API error: {str(e)}',
                'credits_remaining': 0,
                'plan': 'API Error'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to get account info: {str(e)}',
                'credits_remaining': 0,
                'plan': 'Connection Error'
            }
    
    def _format_usage_summary(self, account_info: Dict) -> str:
        """Format account usage summary for display"""
        plan = account_info.get('plan', 'Unknown')
        query_credits = account_info.get('query_credits', 0)
        scan_credits = account_info.get('scan_credits', 0)
        
        if plan.lower() == 'oss':
            return f"OSS Plan - {query_credits} query credits, {scan_credits} scan credits"
        elif plan.lower() == 'dev':
            return f"Developer Plan - {query_credits} query credits, {scan_credits} scan credits"
        elif plan.lower() == 'small':
            return f"Small Business Plan - {query_credits} query credits, {scan_credits} scan credits"
        elif plan.lower() == 'corp':
            return f"Corporate Plan - {query_credits} query credits, {scan_credits} scan credits"
        else:
            return f"{plan} Plan - {query_credits} query credits, {scan_credits} scan credits"
    
    def _get_credit_status(self, credits: int) -> Dict[str, Any]:
        """Determine credit status and warning level"""
        if credits >= 1000:
            return {
                'level': 'excellent',
                'color': 'green',
                'message': 'Excellent credit balance',
                'icon': '✅'
            }
        elif credits >= 500:
            return {
                'level': 'good',
                'color': 'green',
                'message': 'Good credit balance',
                'icon': '✅'
            }
        elif credits >= 100:
            return {
                'level': 'moderate',
                'color': 'orange',
                'message': 'Moderate credit balance',
                'icon': '⚠️'
            }
        elif credits >= 50:
            return {
                'level': 'low',
                'color': 'orange',
                'message': 'Low credit balance - consider upgrading',
                'icon': '⚠️'
            }
        elif credits > 0:
            return {
                'level': 'very_low',
                'color': 'red',
                'message': 'Very low credits - upgrade recommended',
                'icon': '🔴'
            }
        else:
            return {
                'level': 'depleted',
                'color': 'red',
                'message': 'No credits remaining',
                'icon': '❌'
            }
    
    def search_by_domain(self, domain: str, limit: int = 5) -> Dict[str, Any]:
        """
        Search for hosts serving a specific domain
        
        Args:
            domain: Domain to search for
            limit: Maximum number of results (limited due to cost)
            
        Returns:
            Dict with search results and analysis
        """
        if not self.is_enabled:
            return {
                'success': False,
                'error': 'Shodan integration not available'
            }
        
        # Check rate limiting
        if hasattr(self.rate_limiter, 'is_rate_limited'):
            if self.rate_limiter.is_rate_limited('shodan'):
                return {
                    'success': False,
                    'error': 'Rate limited',
                    'rate_limited': True
                }
        
        try:
            # Use hostname filter for domain search
            query = f'hostname:{domain}'
            
            # Search with limited results to conserve credits
            results = self.client.search(query, limit=limit)
            
            hosts = results.get('matches', [])
            
            return {
                'success': True,
                'total_results': results.get('total', 0),
                'hosts_returned': len(hosts),
                'query_used': query,
                'hosts': hosts[:limit],  # Ensure limit
                'analysis': self._analyze_search_results(hosts[:limit])
            }
            
        except shodan.APIError as e:
            return {
                'success': False,
                'error': f'Shodan API error: {str(e)}'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Search failed: {str(e)}'
            }
    
    def search_by_ip(self, ip: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific IP address
        
        Args:
            ip: IP address to analyze
            
        Returns:
            Dict with host information and security analysis
        """
        if not self.is_enabled:
            return {
                'success': False,
                'error': 'Shodan integration not available'
            }
        
        # Check rate limiting
        if hasattr(self.rate_limiter, 'is_rate_limited'):
            if self.rate_limiter.is_rate_limited('shodan'):
                return {
                    'success': False,
                    'error': 'Rate limited',
                    'rate_limited': True
                }
        
        try:
            # Get host information
            host = self.client.host(ip)
            
            return {
                'success': True,
                'ip': ip,
                'host_info': {
                    'org': host.get('org', 'Unknown'),
                    'isp': host.get('isp', 'Unknown'),
                    'asn': host.get('asn', 'Unknown'),
                    'country_code': host.get('country_code', 'Unknown'),
                    'country_name': host.get('country_name', 'Unknown'),
                    'city': host.get('city', 'Unknown'),
                    'region_code': host.get('region_code', 'Unknown'),
                    'postal_code': host.get('postal_code', 'Unknown'),
                    'latitude': host.get('latitude'),
                    'longitude': host.get('longitude'),
                    'last_update': host.get('last_update'),
                    'ports': host.get('ports', [])
                },
                'services': host.get('data', []),
                'analysis': self._analyze_host_data(host)
            }
            
        except shodan.APIError as e:
            return {
                'success': False,
                'error': f'Shodan API error: {str(e)}'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Host lookup failed: {str(e)}'
            }
    
    def detect_waf(self, domain: str) -> Dict[str, Any]:
        """
        Detect WAF (Web Application Firewall) for a domain
        
        Args:
            domain: Domain to analyze for WAF presence
            
        Returns:
            Dict with WAF detection results
        """
        if not self.is_enabled:
            return {
                'success': False,
                'error': 'Shodan integration not available',
                'waf_detected': False
            }
        
        try:
            # Search for WAF-related information
            waf_query = f'hostname:{domain} http.waf'
            results = self.client.search(waf_query, limit=3)
            
            hosts = results.get('matches', [])
            
            # Analyze results for WAF indicators
            waf_analysis = self._analyze_waf_indicators(hosts)
            
            return {
                'success': True,
                'domain': domain,
                'query_used': waf_query,
                'hosts_with_waf': len(hosts),
                'waf_detected': waf_analysis['waf_detected'],
                'waf_type': waf_analysis['waf_type'],
                'waf_indicators': waf_analysis['indicators'],
                'confidence': waf_analysis['confidence'],
                'security_headers': waf_analysis['security_headers'],
                'raw_hosts': hosts
            }
            
        except shodan.APIError as e:
            return {
                'success': False,
                'error': f'Shodan API error: {str(e)}',
                'waf_detected': False
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'WAF detection failed: {str(e)}',
                'waf_detected': False
            }
    
    def get_technology_stack(self, domain: str) -> Dict[str, Any]:
        """
        Enhanced technology stack and infrastructure analysis for a domain
        
        Args:
            domain: Domain to analyze
            
        Returns:
            Dict with comprehensive technology stack information
        """
        if not self.is_enabled:
            return {
                'success': False,
                'error': 'Shodan integration not available'
            }
        
        try:
            # Enhanced search with facets for technology trends
            tech_query = f'hostname:{domain}'
            results = self.client.search(
                tech_query, 
                limit=10,  # Get more results for better analysis
                facets=['product', 'port', 'org', 'country']
            )
            
            hosts = results.get('matches', [])
            facets = results.get('facets', {})
            
            if not hosts:
                return {
                    'success': True,
                    'domain': domain,
                    'technologies': [],
                    'web_servers': [],
                    'frameworks': [],
                    'cdn_providers': [],
                    'ssl_info': {},
                    'ports_services': {},
                    'confidence': 0,
                    'provider_classification': {},
                    'security_assessment': {},
                    'infrastructure_mapping': {}
                }
            
            # Enhanced analysis using new methods
            tech_analysis = self._analyze_technology_stack_enhanced(hosts)
            provider_classification = self._classify_providers_enhanced(hosts, facets)
            security_assessment = self._analyze_security_comprehensive(hosts)
            infrastructure_mapping = self._map_infrastructure_complete(hosts)
            
            return {
                'success': True,
                'domain': domain,
                'technologies': tech_analysis['technologies'],
                'web_servers': tech_analysis['web_servers'],
                'frameworks': tech_analysis['frameworks'],
                'cdn_providers': tech_analysis['cdn_providers'],
                'ssl_info': tech_analysis['ssl_info'],
                'ports_services': tech_analysis['ports_services'],
                'confidence': tech_analysis['confidence'],
                
                # Enhanced analysis
                'provider_classification': provider_classification,
                'security_assessment': security_assessment,
                'infrastructure_mapping': infrastructure_mapping,
                'vulnerability_analysis': self._analyze_vulnerabilities_enhanced(hosts),
                'ssl_trust_analysis': self._analyze_ssl_trust_enhanced(hosts),
                'data_richness_score': self._calculate_data_richness_score({
                    'tech': tech_analysis,
                    'providers': provider_classification,
                    'security': security_assessment,
                    'infrastructure': infrastructure_mapping
                }),
                'total_hosts_analyzed': len(hosts)
            }
            
        except shodan.APIError as e:
            return {
                'success': False,
                'error': f'Shodan API error: {str(e)}'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Technology analysis failed: {str(e)}'
            }
    
    def _analyze_search_results(self, hosts: List[Dict]) -> Dict[str, Any]:
        """Analyze search results for patterns and insights"""
        if not hosts:
            return {
                'countries': [],
                'organizations': [],
                'ports': [],
                'services': []
            }
        
        countries = {}
        organizations = {}
        ports = set()
        services = set()
        
        for host in hosts:
            # Count countries
            country = host.get('location', {}).get('country_name', 'Unknown')
            countries[country] = countries.get(country, 0) + 1
            
            # Count organizations
            org = host.get('org', 'Unknown')
            organizations[org] = organizations.get(org, 0) + 1
            
            # Collect ports
            if 'port' in host:
                ports.add(host['port'])
            
            # Collect services
            if 'product' in host:
                services.add(host['product'])
        
        return {
            'countries': sorted(countries.items(), key=lambda x: x[1], reverse=True),
            'organizations': sorted(organizations.items(), key=lambda x: x[1], reverse=True),
            'ports': sorted(list(ports)),
            'services': list(services)
        }
    
    def _analyze_host_data(self, host: Dict) -> Dict[str, Any]:
        """Analyze host data for security and infrastructure insights"""
        analysis = {
            'provider_classification': 'unknown',
            'security_score': 0,
            'waf_detected': False,
            'cdn_detected': False,
            'cloud_provider': None,
            'security_headers': [],
            'vulnerabilities': [],
            'open_ports': host.get('ports', [])
        }
        
        # Analyze organization for provider classification
        org = host.get('org', '').lower()
        if any(cloud in org for cloud in ['amazon', 'aws', 'ec2']):
            analysis['provider_classification'] = 'aws'
            analysis['cloud_provider'] = 'AWS'
        elif any(cloud in org for cloud in ['google', 'gcp']):
            analysis['provider_classification'] = 'google_cloud'
            analysis['cloud_provider'] = 'Google Cloud'
        elif any(cloud in org for cloud in ['microsoft', 'azure']):
            analysis['provider_classification'] = 'azure'
            analysis['cloud_provider'] = 'Microsoft Azure'
        elif 'cloudflare' in org:
            analysis['provider_classification'] = 'cloudflare'
            analysis['cdn_detected'] = True
        
        # Analyze services for security indicators
        services = host.get('data', [])
        for service in services:
            # Check for WAF indicators in HTTP data
            if service.get('product') and 'waf' in service.get('product', '').lower():
                analysis['waf_detected'] = True
            
            # Check HTTP headers for security
            http_data = service.get('http', {})
            if http_data:
                headers = http_data.get('headers', {})
                for header_name, header_value in headers.items():
                    if header_name.lower() in ['x-frame-options', 'content-security-policy', 
                                             'strict-transport-security', 'x-content-type-options']:
                        analysis['security_headers'].append(header_name)
                
                # Check for WAF headers
                waf_headers = ['x-sucuri-id', 'x-akamai-edgescape', 'cf-ray', 'x-amz-cf-id']
                for waf_header in waf_headers:
                    if waf_header in [h.lower() for h in headers.keys()]:
                        analysis['waf_detected'] = True
        
        # Calculate basic security score
        security_score = 50  # Base score
        if analysis['security_headers']:
            security_score += len(analysis['security_headers']) * 10
        if analysis['waf_detected']:
            security_score += 20
        if len(analysis['open_ports']) < 5:
            security_score += 10
        
        analysis['security_score'] = min(security_score, 100)
        
        return analysis
    
    def _analyze_waf_indicators(self, hosts: List[Dict]) -> Dict[str, Any]:
        """Analyze hosts for WAF indicators"""
        waf_detected = False
        waf_type = 'unknown'
        indicators = []
        confidence = 0
        security_headers = []
        
        if not hosts:
            return {
                'waf_detected': False,
                'waf_type': 'unknown',
                'indicators': [],
                'confidence': 0,
                'security_headers': []
            }
        
        # Known WAF patterns
        waf_patterns = {
            'cloudflare': ['cloudflare', 'cf-ray', 'cf-cache-status'],
            'akamai': ['akamai', 'akamaihost', 'x-akamai'],
            'aws_waf': ['awselb', 'cloudfront', 'x-amz-cf-id'],
            'fastly': ['fastly', 'x-served-by'],
            'imperva': ['imperva', 'incapsula', 'x-iinfo'],
            'sucuri': ['sucuri', 'x-sucuri-id'],
            'barracuda': ['barracuda', 'barra'],
            'f5': ['f5', 'bigip']
        }
        
        for host in hosts:
            services = host.get('data', [])
            
            for service in services:
                # Check HTTP headers
                http_data = service.get('http', {})
                if http_data:
                    headers = http_data.get('headers', {})
                    
                    # Check for WAF-specific headers
                    for waf_name, patterns in waf_patterns.items():
                        for pattern in patterns:
                            # Check header names and values
                            for header_name, header_value in headers.items():
                                if (pattern.lower() in header_name.lower() or 
                                    pattern.lower() in str(header_value).lower()):
                                    waf_detected = True
                                    waf_type = waf_name
                                    indicators.append(f"Header: {header_name} contains {pattern}")
                                    confidence += 20
                    
                    # Collect security headers
                    security_header_names = [
                        'x-frame-options', 'content-security-policy',
                        'strict-transport-security', 'x-content-type-options',
                        'x-xss-protection', 'referrer-policy'
                    ]
                    
                    for header_name in headers.keys():
                        if header_name.lower() in security_header_names:
                            security_headers.append(header_name)
                
                # Check product/banner for WAF indicators
                product = service.get('product', '')
                banner = service.get('banner', '')
                
                for waf_name, patterns in waf_patterns.items():
                    for pattern in patterns:
                        if (pattern.lower() in product.lower() or 
                            pattern.lower() in banner.lower()):
                            waf_detected = True
                            waf_type = waf_name
                            indicators.append(f"Product/Banner: {pattern}")
                            confidence += 15
        
        return {
            'waf_detected': waf_detected,
            'waf_type': waf_type,
            'indicators': list(set(indicators)),  # Remove duplicates
            'confidence': min(confidence, 100),
            'security_headers': list(set(security_headers))
        }
    
    def _analyze_technology_stack(self, hosts: List[Dict]) -> Dict[str, Any]:
        """Analyze technology stack from host data"""
        technologies = set()
        web_servers = set()
        frameworks = set()
        cdn_providers = set()
        ssl_info = {}
        ports_services = {}
        
        for host in hosts:
            # Handle different Shodan data structures
            if isinstance(host, dict):
                # If host is already a service object
                if 'port' in host or 'product' in host:
                    services = [host]
                else:
                    # If host contains a data array
                    services = host.get('data', [host])
            else:
                services = []
            
            for service in services:
                port = service.get('port')
                product = service.get('product', '')
                version = service.get('version', '')
                
                # Collect technologies
                if product:
                    technologies.add(product)
                    
                    # Categorize web servers
                    if any(server in product.lower() for server in ['nginx', 'apache', 'iis', 'lighttpd']):
                        web_servers.add(f"{product} {version}".strip())
                    
                    # Categorize frameworks
                    if any(fw in product.lower() for fw in ['django', 'rails', 'express', 'php']):
                        frameworks.add(f"{product} {version}".strip())
                
                # Collect port/service mapping
                if port:
                    if port not in ports_services:
                        ports_services[port] = []
                    ports_services[port].append(product)
                
                # SSL/TLS information
                ssl_data = service.get('ssl', {})
                if ssl_data:
                    cert = ssl_data.get('cert', {})
                    ssl_info = {
                        'subject': cert.get('subject', {}),
                        'issuer': cert.get('issuer', {}),
                        'version': ssl_data.get('version'),
                        'cipher': ssl_data.get('cipher', {})
                    }
                
                # Check for CDN indicators
                http_data = service.get('http', {})
                if http_data:
                    headers = http_data.get('headers', {})
                    
                    cdn_indicators = {
                        'cloudflare': ['cf-ray', 'cloudflare'],
                        'fastly': ['fastly', 'x-served-by'],
                        'akamai': ['akamai', 'x-akamai'],
                        'aws_cloudfront': ['cloudfront', 'x-amz-cf-id'],
                        'maxcdn': ['maxcdn', 'netdna']
                    }
                    
                    for cdn_name, patterns in cdn_indicators.items():
                        for pattern in patterns:
                            for header_name, header_value in headers.items():
                                if (pattern.lower() in header_name.lower() or 
                                    pattern.lower() in str(header_value).lower()):
                                    cdn_providers.add(cdn_name)
        
        # Calculate confidence based on data availability
        confidence = 0
        if technologies:
            confidence += 30
        if web_servers:
            confidence += 25
        if ssl_info:
            confidence += 20
        if ports_services:
            confidence += 15
        if cdn_providers:
            confidence += 10
        
        return {
            'technologies': list(technologies),
            'web_servers': list(web_servers),
            'frameworks': list(frameworks),
            'cdn_providers': list(cdn_providers),
            'ssl_info': ssl_info,
            'ports_services': ports_services,
            'confidence': min(confidence, 100)
        }
    
    def _classify_providers_enhanced(self, hosts: List[Dict], facets: Dict) -> Dict[str, Any]:
        """Enhanced provider classification using tags, org, and facet data"""
        classification = {
            'cloud_providers': set(),
            'cdn_providers': set(),
            'waf_providers': set(),
            'hosting_providers': set(),
            'confidence_indicators': [],
            'primary_infrastructure': 'unknown'
        }
        
        # Known provider patterns
        cloud_providers = {
            'aws': ['amazon', 'aws', 'amazon web services'],
            'gcp': ['google', 'gcp', 'google cloud'],
            'azure': ['microsoft', 'azure'],
            'cloudflare': ['cloudflare'],
            'akamai': ['akamai'],
            'digitalocean': ['digitalocean'],
            'linode': ['linode'],
            'vultr': ['vultr']
        }
        
        cdn_waf_indicators = {
            'cloudflare': ['cloudflare', 'cf-'],
            'akamai': ['akamai', 'akamaihost', 'akamaighost'],
            'fastly': ['fastly'],
            'maxcdn': ['maxcdn'],
            'keycdn': ['keycdn'],
            'imperva': ['imperva', 'incapsula']
        }
        
        # Analyze hosts for provider indicators
        for host in hosts:
            org = (host.get('org') or '').lower()
            isp = (host.get('isp') or '').lower()
            tags = host.get('tags', []) or []
            product = (host.get('product') or '').lower()
            
            # Check for CDN tags (most reliable)
            if 'cdn' in tags:
                classification['confidence_indicators'].append(f"CDN tag found: {host.get('org', 'Unknown')}")
                classification['cdn_providers'].add(host.get('org', 'Unknown'))
            
            # Check for cloud providers
            for provider, patterns in cloud_providers.items():
                if any(pattern in org or pattern in isp for pattern in patterns):
                    classification['cloud_providers'].add(provider.upper())
                    classification['confidence_indicators'].append(f"Cloud provider detected: {provider}")
            
            # Check for CDN/WAF providers
            for provider, patterns in cdn_waf_indicators.items():
                if any(pattern in product or pattern in org or pattern in isp for pattern in patterns):
                    classification['cdn_providers'].add(provider.upper())
                    if provider in ['imperva', 'cloudflare']:
                        classification['waf_providers'].add(provider.upper())
        
        # Use facet data for primary infrastructure determination
        org_facets = facets.get('org', [])
        if org_facets:
            primary_org = org_facets[0].get('value', 'unknown')
            classification['primary_infrastructure'] = primary_org
            classification['confidence_indicators'].append(f"Primary organization: {primary_org}")
        
        # Convert sets to lists for JSON serialization
        for key in ['cloud_providers', 'cdn_providers', 'waf_providers', 'hosting_providers']:
            classification[key] = list(classification[key])
        
        return classification
    
    def _analyze_technology_stack_enhanced(self, hosts: List[Dict]) -> Dict[str, Any]:
        """Enhanced technology stack analysis with versions and confidence"""
        tech_analysis = {
            'technologies': set(),
            'web_servers': {},
            'frameworks': {},
            'databases': {},
            'operating_systems': {},
            'security_products': {},
            'development_tools': {},
            'confidence': 0,
            'ssl_info': {},
            'ports_services': {},
            'cdn_providers': set()
        }
        
        # Enhanced categorization patterns
        categories = {
            'web_servers': ['nginx', 'apache', 'iis', 'lighttpd', 'cloudflare', 'akamaighost'],
            'frameworks': ['django', 'rails', 'express', 'php', 'asp.net', 'spring'],
            'databases': ['mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch'],
            'operating_systems': ['ubuntu', 'centos', 'windows', 'debian', 'amazon linux'],
            'security_products': ['cloudflare', 'imperva', 'sucuri', 'barracuda'],
            'development_tools': ['jenkins', 'gitlab', 'docker', 'kubernetes']
        }
        
        for host in hosts:
            # Handle different Shodan data structures
            if isinstance(host, dict):
                # If host is already a service object
                if 'port' in host or 'product' in host:
                    services = [host]
                else:
                    # If host contains a data array
                    services = host.get('data', [host])
            else:
                services = []
            
            for service in services:
                product = (service.get('product') or '').lower()
                version = service.get('version') or ''
                
                # Collect all technologies
                if product:
                    tech_analysis['technologies'].add(product)
                    
                    # Categorize products
                    for category, patterns in categories.items():
                        for pattern in patterns:
                            if pattern in product:
                                tech_key = f"{product} {version}".strip()
                                if category not in tech_analysis:
                                    tech_analysis[category] = {}
                                tech_analysis[category][tech_key] = tech_analysis[category].get(tech_key, 0) + 1
                
                # Port/service mapping
                port = service.get('port')
                if port:
                    if port not in tech_analysis['ports_services']:
                        tech_analysis['ports_services'][port] = []
                    tech_analysis['ports_services'][port].append(product)
                
                # SSL/TLS information (enhanced)
                ssl_data = service.get('ssl', {})
                if ssl_data:
                    cert = ssl_data.get('cert', {})
                    tech_analysis['ssl_info'] = {
                        'subject': cert.get('subject', {}),
                        'issuer': cert.get('issuer', {}),
                        'version': ssl_data.get('version'),
                        'cipher': ssl_data.get('cipher', {}),
                        'trust_score': self._calculate_ssl_trust_score(ssl_data)
                    }
                
                # CDN detection via HTTP headers
                http_data = service.get('http', {})
                if http_data:
                    headers = http_data.get('headers', {})
                    cdn_indicators = {
                        'cloudflare': ['cf-ray', 'cloudflare'],
                        'fastly': ['fastly', 'x-served-by'],
                        'akamai': ['akamai', 'x-akamai'],
                        'aws_cloudfront': ['cloudfront', 'x-amz-cf-id'],
                        'maxcdn': ['maxcdn', 'netdna']
                    }
                    
                    for cdn_name, patterns in cdn_indicators.items():
                        for pattern in patterns:
                            for header_name, header_value in headers.items():
                                if (pattern.lower() in header_name.lower() or 
                                    pattern.lower() in str(header_value).lower()):
                                    tech_analysis['cdn_providers'].add(cdn_name)
        
        # Calculate confidence based on data richness
        total_items = len(tech_analysis['technologies'])
        for category in ['web_servers', 'frameworks', 'databases', 'security_products']:
            total_items += len(tech_analysis.get(category, {}))
        
        tech_analysis['confidence'] = min(total_items * 8, 100)
        
        # Convert sets to lists for JSON serialization
        tech_analysis['technologies'] = list(tech_analysis['technologies'])
        tech_analysis['cdn_providers'] = list(tech_analysis['cdn_providers'])
        
        return tech_analysis
    
    def _analyze_security_comprehensive(self, hosts: List[Dict]) -> Dict[str, Any]:
        """Comprehensive security analysis including headers, vulnerabilities, and SSL"""
        security = {
            'security_headers': {},
            'ssl_configuration': {},
            'vulnerability_indicators': [],
            'security_score': 0,
            'recommendations': [],
            'waf_indicators': [],
            'response_analysis': {}
        }
        
        security_headers_to_check = [
            'x-frame-options', 'content-security-policy', 'x-content-type-options',
            'strict-transport-security', 'x-xss-protection', 'referrer-policy',
            'permissions-policy', 'expect-ct'
        ]
        
        for host in hosts:
            # Handle different data structures
            services = []
            if 'port' in host or 'product' in host:
                services = [host]
            else:
                services = host.get('data', [host])
            
            for service in services:
                # HTTP security headers analysis
                http_data = service.get('http', {})
                if http_data:
                    headers = http_data.get('headers', {})
                    
                    for header in security_headers_to_check:
                        if header in headers:
                            security['security_headers'][header] = headers[header]
                    
                    # Server security analysis
                    server = (http_data.get('server') or '').lower()
                    if 'cloudflare' in server:
                        security['security_score'] += 20
                        security['recommendations'].append("Cloudflare protection detected")
                        security['waf_indicators'].append("Cloudflare WAF")
                    
                    # Check for security-related response codes
                    status = http_data.get('status')
                    if status in [403, 406, 429]:  # Common WAF response codes
                        security['waf_indicators'].append(f"WAF-like response: {status}")
                        security['security_score'] += 10
                    
                    # Response analysis
                    security['response_analysis'] = {
                        'status_code': status,
                        'server': server,
                        'security_headers_count': len(security['security_headers'])
                    }
                
                # SSL analysis (enhanced)
                ssl_data = service.get('ssl', {})
                if ssl_data:
                    cert = ssl_data.get('cert', {})
                    security['ssl_configuration'] = {
                        'subject': cert.get('subject', {}),
                        'issuer': cert.get('issuer', {}),
                        'version': ssl_data.get('version'),
                        'cipher': ssl_data.get('cipher', {})
                    }
                    
                    # SSL scoring
                    cipher = ssl_data.get('cipher', {})
                    if cipher.get('version') == 'TLSv1.3':
                        security['security_score'] += 25
                    elif cipher.get('version') == 'TLSv1.2':
                        security['security_score'] += 15
                    
                    # Certificate authority scoring
                    issuer = cert.get('issuer', {}).get('CN') or ''
                    if any(ca in issuer.lower() for ca in ['let\'s encrypt', 'digicert', 'sectigo']):
                        security['security_score'] += 10
                
                # Vulnerability indicators
                vulns = service.get('vulns', [])
                if vulns:
                    security['vulnerability_indicators'].extend(vulns)
                    security['security_score'] -= len(vulns) * 5  # Penalty for vulnerabilities
        
        # Final security score calculation
        header_score = len(security['security_headers']) * 5
        security['security_score'] = max(0, min(100, security['security_score'] + header_score))
        
        # Generate recommendations
        if security['vulnerability_indicators']:
            security['recommendations'].append("Vulnerabilities detected - immediate patching required")
        
        if security['security_score'] > 80:
            security['recommendations'].append("Strong security posture detected")
        elif security['security_score'] < 50:
            security['recommendations'].append("Security improvements recommended")
        
        return security
    
    def _map_infrastructure_complete(self, hosts: List[Dict]) -> Dict[str, Any]:
        """Complete infrastructure landscape mapping"""
        infrastructure = {
            'geographic_distribution': {},
            'port_services': {},
            'asn_analysis': {},
            'hosting_patterns': [],
            'organization_analysis': {},
            'country_analysis': {}
        }
        
        for host in hosts:
            # Geographic analysis
            location = host.get('location', {})
            country = location.get('country_name') or 'Unknown'
            city = location.get('city') or 'Unknown'
            geo_key = f"{country}, {city}"
            infrastructure['geographic_distribution'][geo_key] = infrastructure['geographic_distribution'].get(geo_key, 0) + 1
            
            # Country-specific analysis
            if country != 'Unknown':
                infrastructure['country_analysis'][country] = infrastructure['country_analysis'].get(country, 0) + 1
            
            # Port and service mapping
            port = host.get('port')
            product = host.get('product') or 'Unknown'
            if port:
                if port not in infrastructure['port_services']:
                    infrastructure['port_services'][port] = []
                infrastructure['port_services'][port].append(product)
            
            # ASN analysis
            asn = host.get('asn')
            org = host.get('org') or 'Unknown'
            if asn:
                infrastructure['asn_analysis'][asn] = org
            
            # Organization analysis
            if org != 'Unknown':
                infrastructure['organization_analysis'][org] = infrastructure['organization_analysis'].get(org, 0) + 1
            
            # Hosting pattern analysis
            tags = host.get('tags', []) or []
            if tags:
                infrastructure['hosting_patterns'].extend(tags)
        
        # Remove duplicates and clean up
        infrastructure['hosting_patterns'] = list(set(infrastructure['hosting_patterns']))
        
        # Sort by frequency
        infrastructure['geographic_distribution'] = dict(sorted(
            infrastructure['geographic_distribution'].items(), 
            key=lambda x: x[1], reverse=True
        ))
        
        return infrastructure
    
    def _analyze_vulnerabilities_enhanced(self, hosts: List[Dict]) -> Dict[str, Any]:
        """Enhanced vulnerability analysis with risk scoring"""
        vuln_analysis = {
            'vulnerabilities_found': [],
            'risk_score': 0,
            'security_recommendations': [],
            'outdated_software': [],
            'severity_breakdown': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        }
        
        for host in hosts:
            # Direct vulnerability data
            vulns = host.get('vulns', [])
            if vulns:
                vuln_analysis['vulnerabilities_found'].extend(vulns)
                # Simplified severity scoring (would need CVE database for real scoring)
                vuln_analysis['risk_score'] += len(vulns) * 20
                vuln_analysis['severity_breakdown']['high'] += len(vulns)
            
            # Outdated software detection
            product = host.get('product') or ''
            version = host.get('version') or ''
            if product and version:
                software_info = f"{product} {version}"
                vuln_analysis['outdated_software'].append(software_info)
        
        # Generate recommendations
        if vuln_analysis['vulnerabilities_found']:
            vuln_analysis['security_recommendations'].append("Critical: Vulnerabilities detected - immediate patching required")
        
        if vuln_analysis['risk_score'] > 50:
            vuln_analysis['security_recommendations'].append("High risk: Enhanced monitoring recommended")
        elif vuln_analysis['risk_score'] == 0:
            vuln_analysis['security_recommendations'].append("No vulnerabilities detected via Shodan")
        
        vuln_analysis['risk_score'] = min(100, vuln_analysis['risk_score'])
        
        return vuln_analysis
    
    def _analyze_ssl_trust_enhanced(self, hosts: List[Dict]) -> Dict[str, Any]:
        """Enhanced SSL certificate trust chain analysis"""
        ssl_analysis = {
            'certificate_authorities': [],
            'trust_score': 0,
            'ssl_configurations': [],
            'recommendations': [],
            'certificate_analysis': {}
        }
        
        trusted_cas = [
            'let\'s encrypt', 'digicert', 'sectigo', 'globalsign', 'comodo',
            'godaddy', 'symantec', 'thawte', 'geotrust'
        ]
        
        for host in hosts:
            services = []
            if 'port' in host or 'ssl' in host:
                services = [host]
            else:
                services = host.get('data', [host])
            
            for service in services:
                ssl_data = service.get('ssl', {})
                if ssl_data:
                    cert = ssl_data.get('cert', {})
                    issuer_cn = (cert.get('issuer', {}).get('CN') or '').lower()
                    
                    # Certificate authority analysis
                    if issuer_cn:
                        ssl_analysis['certificate_authorities'].append(issuer_cn)
                        
                        # Trust scoring
                        if any(ca in issuer_cn for ca in trusted_cas):
                            ssl_analysis['trust_score'] += 20
                        
                        if 'let\'s encrypt' in issuer_cn:
                            ssl_analysis['recommendations'].append("Using Let's Encrypt - ensure auto-renewal is configured")
                    
                    # SSL configuration analysis
                    cipher = ssl_data.get('cipher', {})
                    if cipher:
                        config = {
                            'version': cipher.get('version', ''),
                            'cipher_name': cipher.get('name', ''),
                            'bits': cipher.get('bits', 0)
                        }
                        ssl_analysis['ssl_configurations'].append(config)
                        
                        # Version scoring
                        version = cipher.get('version', '')
                        if version == 'TLSv1.3':
                            ssl_analysis['trust_score'] += 30
                        elif version == 'TLSv1.2':
                            ssl_analysis['trust_score'] += 20
                        else:
                            ssl_analysis['recommendations'].append(f"Outdated TLS version detected: {version}")
                    
                    # Certificate details
                    ssl_analysis['certificate_analysis'] = {
                        'subject': cert.get('subject', {}),
                        'issuer': cert.get('issuer', {}),
                        'serial_number': cert.get('serial'),
                        'fingerprint': cert.get('fingerprint', {})
                    }
        
        ssl_analysis['trust_score'] = min(100, ssl_analysis['trust_score'])
        ssl_analysis['certificate_authorities'] = list(set(ssl_analysis['certificate_authorities']))
        
        return ssl_analysis
    
    def _calculate_ssl_trust_score(self, ssl_data: Dict) -> int:
        """Calculate SSL trust score"""
        score = 0
        cipher = ssl_data.get('cipher', {})
        
        # TLS version scoring
        version = cipher.get('version', '')
        if version == 'TLSv1.3':
            score += 40
        elif version == 'TLSv1.2':
            score += 30
        elif version == 'TLSv1.1':
            score += 10
        
        # Cipher strength
        bits = cipher.get('bits', 0)
        if bits >= 256:
            score += 30
        elif bits >= 128:
            score += 20
        
        # Certificate authority
        cert = ssl_data.get('cert', {})
        issuer = (cert.get('issuer', {}).get('CN') or '').lower()
        trusted_cas = ['digicert', 'let\'s encrypt', 'sectigo', 'globalsign']
        if any(ca in issuer for ca in trusted_cas):
            score += 30
        
        return min(100, score)
    
    def _calculate_data_richness_score(self, analysis_data: Dict) -> int:
        """Calculate comprehensive data richness score"""
        score = 0
        
        # Provider classification richness
        providers = analysis_data.get('providers', {})
        score += len(providers.get('cloud_providers', [])) * 10
        score += len(providers.get('cdn_providers', [])) * 15
        score += len(providers.get('waf_providers', [])) * 20
        
        # Technology analysis richness
        tech = analysis_data.get('tech', {})
        score += len(tech.get('technologies', [])) * 3
        score += len(tech.get('web_servers', {})) * 5
        score += len(tech.get('frameworks', {})) * 8
        
        # Security analysis richness
        security = analysis_data.get('security', {})
        score += len(security.get('security_headers', {})) * 3
        score += security.get('security_score', 0) // 5
        
        # Infrastructure mapping richness
        infra = analysis_data.get('infrastructure', {})
        score += len(infra.get('geographic_distribution', {})) * 2
        score += len(infra.get('port_services', {})) * 3
        score += len(infra.get('asn_analysis', {})) * 4
        
        return min(100, score)

def get_shodan_integration(api_key: Optional[str] = None) -> ShodanIntegration:
    """
    Factory function to create Shodan integration instance
    
    Args:
        api_key: Optional Shodan API key
        
    Returns:
        ShodanIntegration instance
    """
    return ShodanIntegration(api_key=api_key)

# For backwards compatibility
ShodanWAFDetector = ShodanIntegration
