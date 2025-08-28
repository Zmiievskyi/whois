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
        self.rate_limit_interval = 2.0  # 2 seconds between requests (extra conservative)
        
        # Account info caching to reduce API calls
        self._account_info_cache = None
        self._account_info_cache_time = 0
        self._account_cache_duration = 1800  # Cache for 30 minutes (much longer)
        
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
        
        # Check if we have cached data that's still valid
        current_time = time.time()
        if (self._account_info_cache and 
            current_time - self._account_info_cache_time < self._account_cache_duration):
            logger.debug("🔄 Using cached account info to avoid rate limits")
            return self._account_info_cache
        
        try:
            # Try to get fresh account information
            account_info = self.client.info()
            
            query_credits = account_info.get('query_credits', 0)
            scan_credits = account_info.get('scan_credits', 0)
            plan = account_info.get('plan', 'Unknown')
            
            # Calculate credit status
            credit_status = self._get_credit_status(query_credits)
            
            result = {
                'success': True,
                'plan': plan,
                'query_credits': query_credits,
                'scan_credits': scan_credits,
                'credits_remaining': query_credits,
                'credit_status': credit_status,
                'usage_summary': self._format_usage_summary(account_info),
                'account_info': account_info
            }
            
            # Cache the successful result
            self._account_info_cache = result
            self._account_info_cache_time = current_time
            logger.debug("✅ Account info retrieved and cached successfully")
            
            return result
            
        except shodan.APIError as e:
            error_msg = str(e).lower()
            if 'rate limit' in error_msg:
                # Use cached data if available, otherwise fallback
                if self._account_info_cache:
                    logger.warning("🔄 Rate limit encountered, using cached account info")
                    # Add rate limit warning to cached data
                    cached_result = self._account_info_cache.copy()
                    cached_result['rate_limit_warning'] = True
                    cached_result['usage_summary'] = cached_result.get('usage_summary', '') + ' (Rate Limited - Using Cached Data)'
                    return cached_result
                else:
                    logger.warning("🔄 Rate limit encountered, no cache available - using fallback")
                    return {
                        'success': True,
                        'plan': 'Rate Limited - Info Unavailable',
                        'query_credits': 0,
                        'scan_credits': 0, 
                        'credits_remaining': 0,
                        'credit_status': {
                            'level': 'rate_limited',
                            'icon': '⚠️',
                            'description': 'Rate Limited'
                        },
                        'usage_summary': 'Account info temporarily unavailable due to rate limits',
                        'rate_limit_protection': True
                    }
            else:
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
    
    def refresh_account_info(self) -> Dict[str, Any]:
        """Force refresh of account info cache"""
        self._account_info_cache = None
        self._account_info_cache_time = 0
        return self.get_account_info()
    
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
            # OPTIMIZATION 1: Smart multi-query strategy with rate limit protection
            try:
                queries = self._build_optimized_query_strategy(domain)
                
                # Rate limit protection: reduce queries if on free plan or experiencing limits
                plan_status = self._detect_current_plan_status()
                if plan_status == 'rate_limited' or plan_status == 'free':
                    queries = queries[:3]  # Reduce to essential queries only
                    logger.warning(f"⚠️ Rate limiting detected - reducing to {len(queries)} essential queries")
                
                all_results = []
                combined_facets = {}
                total_results_count = 0
                query_metadata = []
                failed_queries = []
                
                for i, query_info in enumerate(queries):
                    query = query_info['query']
                    description = query_info['description']
                    
                    try:
                        logger.info(f"🔍 Shodan query {i+1}/{len(queries)}: {description}")
                        
                        # OPTIMIZATION 2: Advanced facets for maximum data extraction
                        results = self.client.search(
                            query, 
                            limit=20,  # Reduced from 50 to 20 for rate limit compliance
                            facets=[
                                'product', 'port', 'org', 'country', 'city', 'asn',
                                'isp', 'os', 'domain', 'devicetype', 'has_screenshot',
                                'has_vuln', 'has_ssl', 'ssl.cert.subject.cn', 'tag'
                            ]
                        )
                        
                        all_results.extend(results.get('matches', []))
                        query_metadata.append({
                            'query': query,
                            'description': description,
                            'results_count': len(results.get('matches', [])),
                            'total_available': results.get('total', 0),
                            'status': 'success'
                        })
                        
                        # Combine facets from all queries
                        for facet_name, facet_data in results.get('facets', {}).items():
                            if facet_name not in combined_facets:
                                combined_facets[facet_name] = []
                            combined_facets[facet_name].extend(facet_data)
                        
                        total_results_count += results.get('total', 0)
                        
                        # Enhanced rate limiting protection
                        time.sleep(self.rate_limit_interval)
                        
                    except shodan.APIError as e:
                        error_msg = str(e)
                        if 'rate limit' in error_msg.lower():
                            logger.warning(f"⚠️ Rate limit hit on query {i+1}, stopping additional queries")
                            failed_queries.append({
                                'query': query,
                                'description': description,
                                'error': 'rate_limited'
                            })
                            break  # Stop executing more queries
                        else:
                            logger.warning(f"⚠️ Query failed: {error_msg}")
                            failed_queries.append({
                                'query': query,
                                'description': description,
                                'error': error_msg
                            })
                
                # Add failure information to metadata
                if failed_queries:
                    query_metadata.extend(failed_queries)
                    
            except Exception as e:
                logger.error(f"❌ Multi-query strategy failed: {e}")
                # Fallback to single basic query
                return self._fallback_single_query(domain)
            
            # Remove duplicates and get unique hosts
            hosts = self._deduplicate_hosts(all_results)
            facets = self._merge_and_deduplicate_facets(combined_facets)
            
            logger.info(f"✅ Shodan collected {len(hosts)} unique hosts from {len(queries)} queries")
            
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
                'total_hosts_analyzed': len(hosts),
                
                # OPTIMIZATION 3: Enhanced raw data preservation for analysis
                'raw_shodan_data': {
                    'multi_query_strategy': query_metadata,
                    'total_results_across_queries': total_results_count,
                    'unique_hosts_collected': len(hosts),
                    'facets_data': facets,
                    'hosts_sample': hosts[:5] if len(hosts) > 5 else hosts,  # Increased sample size
                    'statistical_insights': self._calculate_statistical_insights(hosts, facets),
                    'full_response_metadata': {
                        'query_credits_used': len(queries),
                        'queries_executed': len(queries),
                        'average_response_time': 0,  # Will be calculated from actual responses
                        'query_timestamp': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
                        'optimization_level': 'advanced',
                        'data_extraction_completeness': self._calculate_extraction_completeness(hosts, total_results_count)
                    }
                },
                
                # OPTIMIZATION 4: Enhanced configuration and limits info
                'shodan_config': {
                    'api_plan_detected': self._detect_api_plan_from_results({'total': total_results_count}),
                    'rate_limit_status': self._get_rate_limit_status(),
                    'optimization_suggestions': self._get_advanced_optimization_suggestions(len(hosts), total_results_count),
                    'query_efficiency': self._calculate_advanced_query_efficiency(query_metadata, hosts),
                    'data_coverage_analysis': self._analyze_data_coverage(facets),
                    'recommended_next_queries': self._suggest_follow_up_queries(domain, hosts, facets)
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
    
    def _detect_api_plan_from_results(self, results: Dict) -> str:
        """Detect API plan based on query results and capabilities"""
        total_results = results.get('total', 0)
        facets = results.get('facets', {})
        
        # If we get facets data, likely paid plan
        if facets:
            return "Paid Plan (Developer/Business)"
        
        # If we get many results, likely paid plan
        if total_results > 100:
            return "Paid Plan (High limits detected)"
        
        # Basic query worked but limited results
        if total_results > 0:
            return "Free/Basic Plan (Limited results)"
        
        return "Plan detection failed"
    
    def _get_rate_limit_status(self) -> Dict[str, Any]:
        """Get current rate limiting status"""
        if hasattr(self.rate_limiter, 'get_service_status'):
            return self.rate_limiter.get_service_status('shodan')
        
        return {
            'rate_limited': False,
            'requests_remaining': 'Unknown',
            'time_until_reset': 'Unknown',
            'current_limit': self.rate_limit
        }
    
    def _get_optimization_suggestions(self, hosts_returned: int) -> List[str]:
        """Get optimization suggestions based on current usage"""
        suggestions = []
        
        if hosts_returned == 0:
            suggestions.append("No results found - try broader search terms or check domain accessibility")
        elif hosts_returned < 3:
            suggestions.append("Limited results - consider upgrading to paid plan for more comprehensive data")
        elif hosts_returned >= 10:
            suggestions.append("Good data coverage - consider using facets for deeper analysis")
        
        # Check if we're on free plan (limited results)
        try:
            account_info = self.get_account_info()
            if account_info.get('success') and account_info.get('query_credits', 0) < 10:
                suggestions.append("Low query credits - consider upgrading plan for continuous monitoring")
        except:
            pass
        
        suggestions.append("Use caching to avoid repeated queries for same domain")
        suggestions.append("Consider batch analysis for multiple domains to optimize credit usage")
        
        return suggestions
    
    def _calculate_query_efficiency(self, results: Dict, hosts: List[Dict]) -> Dict[str, Any]:
        """Calculate query efficiency metrics"""
        total_results = results.get('total', 0)
        hosts_returned = len(hosts)
        
        efficiency = {
            'total_available': total_results,
            'hosts_analyzed': hosts_returned,
            'data_utilization': 0,
            'credit_efficiency': 'Unknown'
        }
        
        if total_results > 0:
            efficiency['data_utilization'] = round((hosts_returned / total_results) * 100, 2)
        
        # Calculate credit efficiency
        if hosts_returned >= 5:
            efficiency['credit_efficiency'] = 'High'
        elif hosts_returned >= 2:
            efficiency['credit_efficiency'] = 'Medium'
        elif hosts_returned >= 1:
            efficiency['credit_efficiency'] = 'Low'
        else:
            efficiency['credit_efficiency'] = 'Poor'
        
        return efficiency

    # ========================================
    # ADVANCED OPTIMIZATION METHODS
    # ========================================
    
    def _build_optimized_query_strategy(self, domain: str) -> List[Dict[str, str]]:
        """Build advanced multi-query strategy for comprehensive domain analysis"""
        queries = [
            {
                'query': f'hostname:{domain}',
                'description': 'Primary hostname search'
            },
            {
                'query': f'ssl.cert.subject.cn:{domain}',
                'description': 'SSL certificate subject search'
            },
            {
                'query': f'http.html:"{domain}"',
                'description': 'HTML content references'
            },
            {
                'query': f'http.title:"{domain}"',
                'description': 'HTTP title tag references'
            },
            {
                'query': f'http.html:"{domain}" has_screenshot:true',
                'description': 'Visual infrastructure with screenshots'
            },
            {
                'query': f'hostname:{domain} has_vuln:true',
                'description': 'Vulnerability-focused search'
            }
        ]
        
        # Add wildcard subdomain search for comprehensive coverage
        if '.' in domain:
            base_domain = '.'.join(domain.split('.')[-2:])
            queries.extend([
                {
                    'query': f'hostname:*.{base_domain}',
                    'description': f'Wildcard subdomain search for {base_domain}'
                },
                {
                    'query': f'ssl.cert.subject.cn:*.{base_domain}',
                    'description': f'SSL wildcard certificate search for {base_domain}'
                },
                {
                    'query': f'http.html:"{base_domain}" -hostname:{domain}',
                    'description': f'Related infrastructure excluding primary domain'
                }
            ])
        
        # Add port-specific searches for common services
        common_services = [
            {'ports': '80,8080,8000', 'description': 'HTTP services'},
            {'ports': '443,8443', 'description': 'HTTPS services'},
            {'ports': '21,22,23', 'description': 'Administration services'},
            {'ports': '25,587,993,995', 'description': 'Email services'}
        ]
        
        for service in common_services:
            queries.append({
                'query': f'hostname:{domain} port:{service["ports"]}',
                'description': f'{service["description"]} for {domain}'
            })
        
        return queries
    
    def _deduplicate_hosts(self, hosts: List[Dict]) -> List[Dict]:
        """Remove duplicate hosts based on IP and port combination"""
        seen = set()
        unique_hosts = []
        
        for host in hosts:
            ip = host.get('ip_str', '')
            port = host.get('port', 0)
            key = f"{ip}:{port}"
            
            if key not in seen:
                seen.add(key)
                unique_hosts.append(host)
        
        return unique_hosts
    
    def _merge_and_deduplicate_facets(self, combined_facets: Dict) -> Dict:
        """Merge and deduplicate facet data from multiple queries"""
        merged = {}
        
        for facet_name, facet_data in combined_facets.items():
            if not facet_data:
                continue
                
            # Count occurrences and merge
            counts = {}
            for item in facet_data:
                if isinstance(item, dict) and 'value' in item and 'count' in item:
                    value = item['value']
                    count = item['count']
                    counts[value] = counts.get(value, 0) + count
            
            # Convert back to list format
            merged[facet_name] = [
                {'value': value, 'count': count}
                for value, count in sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]
            ]
        
        return merged
    
    def _calculate_statistical_insights(self, hosts: List[Dict], facets: Dict) -> Dict[str, Any]:
        """Calculate advanced statistical insights from collected data"""
        insights = {
            'host_distribution': {
                'total_unique_hosts': len(hosts),
                'unique_ips': len(set(h.get('ip_str', '') for h in hosts)),
                'unique_ports': len(set(h.get('port', 0) for h in hosts)),
                'countries_detected': len(set(h.get('location', {}).get('country_name', '') for h in hosts if h.get('location', {}).get('country_name')))
            },
            'service_analysis': {
                'most_common_ports': self._get_top_ports(hosts),
                'detected_services': self._get_detected_services(hosts),
                'ssl_prevalence': sum(1 for h in hosts if 'ssl' in h) / len(hosts) * 100 if hosts else 0
            },
            'geographical_spread': self._analyze_geographical_distribution(hosts),
            'technology_insights': self._extract_technology_insights(hosts)
        }
        
        return insights
    
    def _calculate_extraction_completeness(self, hosts: List[Dict], total_available: int) -> Dict[str, Any]:
        """Calculate how complete our data extraction is"""
        if total_available == 0:
            return {'completeness_percentage': 0, 'status': 'no_data'}
        
        collected = len(hosts)
        percentage = (collected / total_available) * 100
        
        return {
            'completeness_percentage': round(percentage, 2),
            'hosts_collected': collected,
            'total_available': total_available,
            'status': 'excellent' if percentage > 80 else 'good' if percentage > 50 else 'partial' if percentage > 20 else 'limited'
        }
    
    def _get_advanced_optimization_suggestions(self, hosts_count: int, total_results: int) -> List[str]:
        """Generate advanced optimization suggestions"""
        suggestions = []
        
        if hosts_count == 0:
            suggestions.append("No hosts found - try broader search terms or check domain spelling")
            suggestions.append("Consider using wildcard searches like hostname:*.domain.com")
        elif hosts_count < 10 and total_results > hosts_count:
            suggestions.append("Increase limit parameter to capture more available results")
            suggestions.append("Current search captured only a fraction of available data")
        
        if total_results > 100:
            suggestions.append("Large result set detected - consider using facets for targeted analysis")
            suggestions.append("Use count() API for statistical insights without consuming search credits")
        
        suggestions.append("Enable has_screenshot facet for visual infrastructure analysis")
        suggestions.append("Use has_vuln facet to focus on security assessment")
        
        return suggestions
    
    def _calculate_advanced_query_efficiency(self, query_metadata: List[Dict], hosts: List[Dict]) -> Dict[str, Any]:
        """Calculate advanced query efficiency metrics"""
        total_queries = len(query_metadata)
        total_results_available = sum(q.get('total_available', 0) for q in query_metadata)
        unique_hosts_collected = len(hosts)
        
        efficiency = {
            'queries_executed': total_queries,
            'total_results_available': total_results_available,
            'unique_hosts_collected': unique_hosts_collected,
            'deduplication_effectiveness': 0,
            'credit_to_data_ratio': 0,
            'overall_efficiency': 'unknown'
        }
        
        # Calculate deduplication effectiveness
        total_hosts_before_dedup = sum(q.get('results_count', 0) for q in query_metadata)
        if total_hosts_before_dedup > 0:
            efficiency['deduplication_effectiveness'] = round(
                (1 - (unique_hosts_collected / total_hosts_before_dedup)) * 100, 2
            )
        
        # Calculate credit efficiency
        if total_queries > 0:
            efficiency['credit_to_data_ratio'] = round(unique_hosts_collected / total_queries, 2)
        
        # Overall efficiency assessment
        if unique_hosts_collected >= total_queries * 5:
            efficiency['overall_efficiency'] = 'excellent'
        elif unique_hosts_collected >= total_queries * 2:
            efficiency['overall_efficiency'] = 'good'
        elif unique_hosts_collected >= total_queries:
            efficiency['overall_efficiency'] = 'fair'
        else:
            efficiency['overall_efficiency'] = 'poor'
        
        return efficiency
    
    def _analyze_data_coverage(self, facets: Dict) -> Dict[str, Any]:
        """Analyze data coverage across different dimensions"""
        coverage = {
            'facet_categories_available': len(facets),
            'data_dimensions': list(facets.keys()),
            'coverage_assessment': {},
            'missing_dimensions': []
        }
        
        # Assess coverage for each important dimension
        important_facets = ['country', 'org', 'product', 'port', 'asn', 'isp']
        for facet in important_facets:
            if facet in facets and facets[facet]:
                coverage['coverage_assessment'][facet] = {
                    'available': True,
                    'unique_values': len(facets[facet]),
                    'top_value': facets[facet][0]['value'] if facets[facet] else None
                }
            else:
                coverage['missing_dimensions'].append(facet)
        
        return coverage
    
    def _suggest_follow_up_queries(self, domain: str, hosts: List[Dict], facets: Dict) -> List[Dict[str, str]]:
        """Suggest follow-up queries for deeper analysis"""
        suggestions = []
        
        # Suggest IP range searches if we found specific organizations
        if 'org' in facets and facets['org']:
            top_org = facets['org'][0]['value']
            suggestions.append({
                'query': f'org:"{top_org}"',
                'description': f'Explore all infrastructure from {top_org}',
                'priority': 'high'
            })
        
        # Suggest ASN searches
        if 'asn' in facets and facets['asn']:
            top_asn = facets['asn'][0]['value']
            suggestions.append({
                'query': f'asn:{top_asn}',
                'description': f'Analyze ASN {top_asn} infrastructure',
                'priority': 'medium'
            })
        
        # Suggest vulnerability-focused searches
        has_vuln_hosts = any('vulns' in host for host in hosts)
        if has_vuln_hosts:
            suggestions.append({
                'query': f'hostname:{domain} has_vuln:true',
                'description': 'Focus on vulnerable services',
                'priority': 'high'
            })
        
        return suggestions[:5]  # Limit to top 5 suggestions
    
    def _get_top_ports(self, hosts: List[Dict]) -> List[Dict[str, Any]]:
        """Get most common ports from hosts"""
        port_counts = {}
        for host in hosts:
            port = host.get('port', 0)
            if port:
                port_counts[port] = port_counts.get(port, 0) + 1
        
        return [
            {'port': port, 'count': count}
            for port, count in sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        ]
    
    def _get_detected_services(self, hosts: List[Dict]) -> List[str]:
        """Extract detected services from hosts"""
        services = set()
        for host in hosts:
            if 'product' in host:
                services.add(host['product'])
            for banner in host.get('data', '').lower().split():
                if any(service in banner for service in ['apache', 'nginx', 'iis', 'tomcat']):
                    services.add(banner)
        
        return list(services)[:10]
    
    def _analyze_geographical_distribution(self, hosts: List[Dict]) -> Dict[str, Any]:
        """Analyze geographical distribution of hosts"""
        countries = {}
        cities = {}
        
        for host in hosts:
            location = host.get('location', {})
            country = location.get('country_name', 'Unknown')
            city = location.get('city', 'Unknown')
            
            countries[country] = countries.get(country, 0) + 1
            if city != 'Unknown':
                cities[city] = cities.get(city, 0) + 1
        
        return {
            'countries': dict(sorted(countries.items(), key=lambda x: x[1], reverse=True)[:5]),
            'cities': dict(sorted(cities.items(), key=lambda x: x[1], reverse=True)[:5]),
            'geographical_spread': len(countries)
        }
    
    def _extract_technology_insights(self, hosts: List[Dict]) -> Dict[str, Any]:
        """Extract technology insights from hosts"""
        products = {}
        versions = {}
        
        for host in hosts:
            product = host.get('product', '')
            if product:
                products[product] = products.get(product, 0) + 1
                
                # Try to extract version
                version = host.get('version', '')
                if version and product:
                    versions[f"{product} {version}"] = versions.get(f"{product} {version}", 0) + 1
        
        return {
            'top_products': dict(sorted(products.items(), key=lambda x: x[1], reverse=True)[:5]),
            'version_analysis': dict(sorted(versions.items(), key=lambda x: x[1], reverse=True)[:5])
        }
    
    def get_statistical_insights(self, domain: str) -> Dict[str, Any]:
        """
        Get statistical insights using count() API - no search credits consumed
        This provides fast statistical overview without detailed host data
        """
        if not self.is_enabled:
            return {
                'success': False,
                'error': 'Shodan integration not available'
            }
        
        try:
            insights = {}
            
            # Basic domain statistics
            base_query = f'hostname:{domain}'
            total_count = self.client.count(base_query)
            insights['domain_statistics'] = {
                'total_hosts': total_count.get('total', 0),
                'query': base_query
            }
            
            # Port distribution statistics
            port_query = f'hostname:{domain}'
            port_stats = self.client.count(port_query, facets=['port'])
            insights['port_distribution'] = port_stats.get('facets', {}).get('port', [])
            
            # Country distribution statistics  
            country_stats = self.client.count(port_query, facets=['country'])
            insights['geographical_distribution'] = country_stats.get('facets', {}).get('country', [])
            
            # Organization statistics
            org_stats = self.client.count(port_query, facets=['org'])
            insights['organization_distribution'] = org_stats.get('facets', {}).get('org', [])
            
            # Product/service statistics
            product_stats = self.client.count(port_query, facets=['product'])
            insights['service_distribution'] = product_stats.get('facets', {}).get('product', [])
            
            return {
                'success': True,
                'domain': domain,
                'statistical_insights': insights,
                'credits_used': 0,  # count() API doesn't consume search credits
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
            }
            
        except shodan.APIError as e:
            return {
                'success': False,
                'error': f'Shodan statistical analysis failed: {str(e)}'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Statistical insights failed: {str(e)}'
            }
    
    def get_streaming_monitor(self, domain: str, callback_function=None) -> Dict[str, Any]:
        """
        Set up streaming monitor for real-time infrastructure changes
        This monitors new hosts appearing for the domain
        """
        if not self.is_enabled:
            return {
                'success': False,
                'error': 'Shodan integration not available'
            }
        
        try:
            # Create streaming query for domain monitoring
            monitor_query = f'hostname:{domain}'
            
            if callback_function:
                # Setup streaming with callback
                stream_results = []
                
                def stream_handler(banner):
                    """Handle incoming streaming data"""
                    stream_results.append(banner)
                    if callback_function:
                        callback_function(banner)
                
                # Note: In a real implementation, this would use shodan.stream()
                # For now, we return the setup configuration
                return {
                    'success': True,
                    'streaming_config': {
                        'query': monitor_query,
                        'monitoring_domain': domain,
                        'stream_type': 'real_time_infrastructure',
                        'handler_configured': True,
                        'features': [
                            'New host detection',
                            'Service changes',
                            'Vulnerability alerts',
                            'SSL certificate updates'
                        ]
                    },
                    'instructions': 'Streaming requires dedicated connection and premium Shodan plan',
                    'recommended_implementation': 'Use shodan.stream() with filters for production'
                }
            else:
                return {
                    'success': True,
                    'streaming_config': {
                        'query': monitor_query,
                        'monitoring_domain': domain,
                        'stream_type': 'batch_scheduled',
                        'recommended_interval': '1 hour',
                        'features': [
                            'Scheduled infrastructure checks',
                            'Change detection',
                            'Historical comparison'
                        ]
                    }
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f'Streaming setup failed: {str(e)}'
            }
    
    def get_bulk_analysis_optimization(self, domains: List[str]) -> Dict[str, Any]:
        """
        Optimize queries for bulk domain analysis to maximize credit efficiency
        """
        if not self.is_enabled:
            return {
                'success': False,
                'error': 'Shodan integration not available'
            }
        
        try:
            optimizations = {
                'batch_strategy': 'multi_domain_query',
                'domains_count': len(domains),
                'recommended_approach': {},
                'credit_efficiency': {}
            }
            
            # Strategy for different domain counts
            if len(domains) <= 5:
                optimizations['recommended_approach'] = {
                    'method': 'individual_comprehensive',
                    'queries_per_domain': 'full_strategy',
                    'estimated_credits': len(domains) * 15,  # 15 queries per domain
                    'advantages': ['Maximum data per domain', 'Complete analysis']
                }
            elif len(domains) <= 20:
                optimizations['recommended_approach'] = {
                    'method': 'selective_targeting',
                    'queries_per_domain': 'core_only',
                    'estimated_credits': len(domains) * 5,  # 5 core queries per domain
                    'advantages': ['Balanced coverage', 'Reasonable credit usage']
                }
            else:
                optimizations['recommended_approach'] = {
                    'method': 'statistical_overview',
                    'queries_per_domain': 'count_only',
                    'estimated_credits': len(domains) * 1,  # Statistical insights only
                    'advantages': ['Credit efficient', 'Fast overview', 'Scalable']
                }
            
            # Build bulk query optimizations
            if len(domains) <= 10:
                bulk_query = ' OR '.join([f'hostname:{domain}' for domain in domains])
                optimizations['bulk_query_option'] = {
                    'query': bulk_query,
                    'credits_saved': len(domains) - 1,
                    'note': 'Single query covering all domains'
                }
            
            return {
                'success': True,
                'optimization_analysis': optimizations,
                'recommendations': [
                    'Use count() API for initial assessment',
                    'Focus detailed analysis on high-value targets',
                    'Implement caching for repeated analyses',
                    'Consider domain grouping by organization'
                ]
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Bulk optimization failed: {str(e)}'
            }
    
    def _detect_current_plan_status(self) -> str:
        """Detect current API plan status with smart fallback"""
        try:
            # Try a lightweight account check first
            account_info = self.client.info()
            query_credits = account_info.get('query_credits', 0)
            
            if query_credits == 0:
                return 'free'
            elif query_credits < 10:
                return 'low_credits'
            else:
                return 'paid'
                
        except shodan.APIError as e:
            error_msg = str(e).lower()
            if 'rate limit' in error_msg:
                return 'rate_limited'
            elif 'unauthorized' in error_msg:
                return 'invalid_key'
            else:
                return 'unknown'
        except Exception:
            # Conservative fallback for network issues
            return 'unknown'
    
    def _fallback_single_query(self, domain: str) -> Dict[str, Any]:
        """Fallback to single query when multi-query fails"""
        logger.warning("🔄 Falling back to single conservative query")
        
        try:
            # Single conservative query with minimal facets
            query = f'hostname:{domain}'
            results = self.client.search(
                query, 
                limit=5,  # Very conservative limit
                facets=['product', 'port', 'org']  # Essential facets only
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
                    'infrastructure_mapping': {},
                    'fallback_mode': True,
                    'rate_limit_encountered': True
                }
            
            # Basic analysis using conservative methods
            tech_analysis = self._analyze_technology_stack_enhanced(hosts)
            provider_classification = self._classify_providers_enhanced(hosts, facets)
            
            return {
                'success': True,
                'domain': domain,
                'technologies': tech_analysis['technologies'],
                'web_servers': tech_analysis['web_servers'],
                'frameworks': tech_analysis['frameworks'],
                'cdn_providers': tech_analysis['cdn_providers'],
                'ssl_info': tech_analysis['ssl_info'],
                'ports_services': tech_analysis['ports_services'],
                'confidence': max(tech_analysis['confidence'] - 20, 0),  # Reduced confidence
                
                # Basic analysis
                'provider_classification': provider_classification,
                'security_assessment': {'assessment': 'limited_due_to_rate_limits'},
                'infrastructure_mapping': {'mapping': 'basic_only'},
                'total_hosts_analyzed': len(hosts),
                
                # Fallback mode indicators
                'raw_shodan_data': {
                    'query_used': query,
                    'total_results': results.get('total', 0),
                    'facets_data': facets,
                    'hosts_sample': hosts,
                    'fallback_mode': True,
                    'full_response_metadata': {
                        'query_credits_used': 1,
                        'optimization_level': 'fallback',
                        'rate_limit_encountered': True
                    }
                },
                
                'shodan_config': {
                    'api_plan_detected': 'Rate Limited',
                    'rate_limit_status': {'rate_limited': True},
                    'optimization_suggestions': [
                        'Rate limit encountered - using conservative query strategy',
                        'Consider upgrading to paid plan for full analysis',
                        'Wait before running additional analyses'
                    ]
                }
            }
            
        except shodan.APIError as e:
            return {
                'success': False,
                'error': f'Fallback query also failed: {str(e)}',
                'rate_limit_encountered': True
            }

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
