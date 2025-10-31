#!/usr/bin/env python3
"""
BGP Analysis Integration - Multi-Source Strategy
Provides ASN lookup, routing analysis, and network intelligence
Uses multiple free BGP data sources with intelligent fallback

Multi-Source Priority:
1. IPInfo.io (Primary) - Fast, reliable, includes geolocation
2. Hurricane Electric (Secondary) - Detailed BGP data when IPInfo fails
3. RIPE Stat (Tertiary) - European networks fallback
4. Advanced BGP Classifier (Local) - Pattern-based classification
"""

import logging
import socket
import requests
from typing import Dict, List, Optional, Any, Tuple
from .base import HTTPIntegration

logger = logging.getLogger(__name__)

class BGPAnalysisIntegration(HTTPIntegration):
    """
    BGP Analysis integration using multi-source strategy

    Data Sources (Priority Order):
    1. IPInfo.io - Primary source (replaced BGPView)
       - Fast and reliable
       - 50k requests/month with free token
       - Includes geolocation bonus data
    2. Hurricane Electric (bgp.he.net) - Secondary source
       - Detailed BGP data
       - Web scraping based
    3. RIPE Stat API - Tertiary source
       - European network intelligence
    4. Local BGP Classifier - Fallback
       - Pattern-based classification
    """

    def __init__(self, cache_ttl: int = 7200):
        """
        Initialize BGP Analysis integration with multi-source support

        Args:
            cache_ttl: Cache TTL in seconds (default 2 hours for better rate limiting)
        """
        super().__init__(
            service_name="bgp_analysis",
            base_url="https://stat.ripe.net/data"  # Changed from BGPView to RIPE
        )

        self.cache_ttl = cache_ttl

        # Initialize data sources (lazy loading)
        self._ipinfo = None
        self._hurricane_electric = None
        self._bgp_classifier = None

        # Setup rate limiting (very conservative for free APIs)
        if hasattr(self.rate_limiter, 'add_service'):
            self.rate_limiter.add_service('bgp_analysis', 10, 60)  # 10 requests per minute

        logger.info("BGP Analysis integration initialized (Multi-Source Strategy: IPInfo → HE → RIPE)")
    
    @property
    def is_enabled(self) -> bool:
        """BGP analysis is always enabled (uses free APIs)"""
        return True

    @property
    def ipinfo(self):
        """Lazy load IPInfo integration"""
        if self._ipinfo is None:
            try:
                from .ipinfo_integration import get_ipinfo_integration
                self._ipinfo = get_ipinfo_integration()
                logger.debug("IPInfo integration loaded")
            except Exception as e:
                logger.warning(f"Failed to load IPInfo integration: {e}")
                self._ipinfo = None
        return self._ipinfo

    @property
    def hurricane_electric(self):
        """Lazy load Hurricane Electric integration"""
        if self._hurricane_electric is None:
            try:
                from .hurricane_electric import get_hurricane_electric_integration
                self._hurricane_electric = get_hurricane_electric_integration()
                logger.debug("Hurricane Electric integration loaded")
            except Exception as e:
                logger.warning(f"Failed to load Hurricane Electric integration: {e}")
                self._hurricane_electric = None
        return self._hurricane_electric

    @property
    def bgp_classifier(self):
        """Lazy load Advanced BGP Classifier"""
        if self._bgp_classifier is None:
            try:
                from .advanced_bgp_classifier import get_advanced_bgp_classifier
                self._bgp_classifier = get_advanced_bgp_classifier()
                logger.debug("Advanced BGP Classifier loaded")
            except Exception as e:
                logger.warning(f"Failed to load Advanced BGP Classifier: {e}")
                self._bgp_classifier = None
        return self._bgp_classifier

    def _make_api_request(self, endpoint: str, base_url: str = None, **kwargs) -> Dict[str, Any]:
        """
        Make API request to BGP data sources with caching and rate limit handling
        
        Args:
            endpoint: API endpoint
            base_url: Base URL (defaults to bgpview)
            **kwargs: Additional request parameters
            
        Returns:
            API response data
        """
        if base_url is None:
            base_url = self.base_urls['bgpview']
        
        # Check cache first (aggressive caching for BGP data)
        cache_key = f"bgp_{hash(base_url + endpoint + str(kwargs))}"
        cached_result = self.cache.get('bgp_analysis', cache_key)
        if cached_result:
            return cached_result
        
        url = f"{base_url}/{endpoint.lstrip('/')}"
        
        try:
            # Check if we're rate limited first
            if hasattr(self.rate_limiter, 'is_rate_limited') and self.rate_limiter.is_rate_limited('bgp_analysis'):
                return {'error': 'Rate limited - please try again later', 'rate_limited': True}
            
            # Apply rate limiting
            self.rate_limiter.wait_if_needed('bgp_analysis')
            
            response = requests.get(url, timeout=10, **kwargs)
            
            # Handle 429 specifically to avoid spam logs
            if response.status_code == 429:
                logger.debug(f"BGPView API rate limited (429) - this is expected with free tier")
                error_result = {'error': 'BGPView API rate limited', 'rate_limited': True}
                # Cache the rate limit error for 5 minutes to avoid repeated requests
                self.cache.set('bgp_analysis', cache_key, error_result, 300)
                return error_result
            
            response.raise_for_status()
            result = response.json()
            
            # Cache successful results for longer period (2 hours)
            self.cache.set('bgp_analysis', cache_key, result, self.cache_ttl)
            return result
            
        except Exception as e:
            error_str = str(e)
            # Only log 429 errors once to avoid spam
            if '429' not in error_str:
                logger.error(f"BGP API request failed for {url}: {e}")
            else:
                logger.debug(f"BGP API rate limited: {e}")
                
            return {'error': error_str, 'rate_limited': '429' in error_str}
    
    def get_ip_asn_info(self, ip: str) -> Dict[str, Any]:
        """
        Get ASN information for an IP address using multi-source strategy

        Priority:
        1. IPInfo.io (Primary) - Fast, reliable, includes geolocation
        2. Hurricane Electric (Secondary) - Detailed BGP data
        3. RIPE Stat (Tertiary) - European networks
        4. Local classifier (Fallback) - Pattern matching

        Args:
            ip: IP address to lookup

        Returns:
            Dict with ASN information including data_source field
        """
        cache_key = f"asn_info_{ip}"
        cached_result = self.cache.get('bgp_analysis', cache_key)
        if cached_result:
            return cached_result

        # Try sources in priority order
        sources = [
            ('ipinfo', self._try_ipinfo_asn),
            ('hurricane_electric', self._try_hurricane_electric_asn),
            ('ripe', self._try_ripe_asn),
            ('local_classifier', self._try_local_classifier_asn)
        ]

        for source_name, source_func in sources:
            try:
                result = source_func(ip)
                if result and 'error' not in result and result.get('asn', 0) != 0:
                    result['data_source'] = source_name
                    # Cache successful result
                    self.cache.set('bgp_analysis', cache_key, result, self.cache_ttl)
                    logger.debug(f"ASN info for {ip} retrieved from {source_name}")
                    return result
            except Exception as e:
                logger.debug(f"Failed to get ASN from {source_name} for {ip}: {e}")
                continue

        # All sources failed
        error_result = {
            'error': 'All BGP sources failed',
            'ip': ip,
            'asn': 0,
            'data_source': 'none'
        }
        return error_result

    def _try_ipinfo_asn(self, ip: str) -> Optional[Dict[str, Any]]:
        """Try to get ASN info from IPInfo.io"""
        if not self.ipinfo:
            return None

        result = self.ipinfo.get_ip_info(ip)
        if 'error' in result:
            return None

        # IPInfo returns enriched data with parsed ASN
        return {
            'ip': ip,
            'asn': result.get('asn', 0),
            'asn_name': result.get('asn_name', ''),
            'asn_description': result.get('asn_description', ''),
            'country_code': result.get('country_code', ''),
            'city': result.get('city', ''),
            'region': result.get('region', ''),
            'latitude': result.get('latitude'),
            'longitude': result.get('longitude'),
            'hostname': result.get('hostname', ''),
            'org': result.get('org', ''),
            'postal': result.get('postal', ''),
            'timezone': result.get('timezone', ''),
            'anycast': result.get('anycast', False),
        }

    def _try_hurricane_electric_asn(self, ip: str) -> Optional[Dict[str, Any]]:
        """Try to get ASN info from Hurricane Electric"""
        if not self.hurricane_electric:
            return None

        try:
            result = self.hurricane_electric.get_ip_asn_info(ip)
            if result and 'error' not in result:
                return result
        except Exception as e:
            logger.debug(f"Hurricane Electric lookup failed for {ip}: {e}")
        return None

    def _try_ripe_asn(self, ip: str) -> Optional[Dict[str, Any]]:
        """Try to get ASN info from RIPE Stat"""
        try:
            # RIPE Stat API endpoint
            url = f"https://stat.ripe.net/data/network-info/data.json?resource={ip}"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                asn_info = data.get('data', {}).get('asns', [])

                if asn_info:
                    asn = asn_info[0]
                    return {
                        'ip': ip,
                        'asn': int(asn) if asn else 0,
                        'asn_name': data.get('data', {}).get('holder', ''),
                        'asn_description': data.get('data', {}).get('holder', ''),
                        'country_code': '',
                        'registry': 'RIPE',
                    }
        except Exception as e:
            logger.debug(f"RIPE lookup failed for {ip}: {e}")
        return None

    def _try_local_classifier_asn(self, ip: str) -> Optional[Dict[str, Any]]:
        """Try to classify ASN using local patterns"""
        if not self.bgp_classifier:
            return None

        try:
            result = self.bgp_classifier.classify_ip(ip)
            if result and result.get('asn', 0) != 0:
                return {
                    'ip': ip,
                    'asn': result.get('asn', 0),
                    'asn_name': result.get('name', ''),
                    'asn_description': result.get('description', ''),
                    'country_code': '',
                    'confidence': result.get('confidence', 'Low'),
                }
        except Exception as e:
            logger.debug(f"Local classifier failed for {ip}: {e}")
        return None
    
    def get_asn_details(self, asn: int) -> Dict[str, Any]:
        """
        Get detailed information about an ASN
        
        Args:
            asn: Autonomous System Number
            
        Returns:
            Dict with ASN details
        """
        cache_key = f"asn_details_{asn}"
        cached_result = self.cache.get('bgp_analysis', cache_key)
        if cached_result:
            return cached_result
        
        try:
            # BGPView API call
            endpoint = f"asn/{asn}"
            result = self._make_api_request(endpoint)
            
            if 'error' in result:
                return result
            
            # Extract ASN details
            data = result.get('data', {})
            asn_details = {
                'asn': asn,
                'name': data.get('name', ''),
                'description_short': data.get('description_short', ''),
                'description_full': data.get('description_full', ''),
                'country_code': data.get('country_code', ''),
                'website': data.get('website', ''),
                'email_contacts': data.get('email_contacts', []),
                'abuse_contacts': data.get('abuse_contacts', []),
                'looking_glass': data.get('looking_glass', ''),
                'traffic_estimation': data.get('traffic_estimation', ''),
                'traffic_ratio': data.get('traffic_ratio', ''),
                'owner_address': data.get('owner_address', []),
                'rir_allocation': data.get('rir_allocation', {}),
                'date_updated': data.get('date_updated', ''),
                'data_source': 'bgpview'
            }
            
            # Cache the result
            self.cache.set('bgp_analysis', cache_key, asn_details, self.cache_ttl)
            
            return asn_details
            
        except Exception as e:
            logger.error(f"Failed to get ASN details for {asn}: {e}")
            return {'error': str(e), 'asn': asn}
    
    def get_asn_prefixes(self, asn: int) -> Dict[str, Any]:
        """
        Get IP prefixes announced by an ASN
        
        Args:
            asn: Autonomous System Number
            
        Returns:
            Dict with prefix information
        """
        cache_key = f"asn_prefixes_{asn}"
        cached_result = self.cache.get('bgp_analysis', cache_key)
        if cached_result:
            return cached_result
        
        try:
            # BGPView API call
            endpoint = f"asn/{asn}/prefixes"
            result = self._make_api_request(endpoint)
            
            if 'error' in result:
                return result
            
            # Extract prefix information
            data = result.get('data', {})
            prefixes_info = {
                'asn': asn,
                'ipv4_prefixes': data.get('ipv4_prefixes', []),
                'ipv6_prefixes': data.get('ipv6_prefixes', []),
                'total_ipv4': len(data.get('ipv4_prefixes', [])),
                'total_ipv6': len(data.get('ipv6_prefixes', [])),
                'data_source': 'bgpview'
            }
            
            # Cache the result
            self.cache.set('bgp_analysis', cache_key, prefixes_info, self.cache_ttl)
            
            return prefixes_info
            
        except Exception as e:
            logger.error(f"Failed to get ASN prefixes for {asn}: {e}")
            return {'error': str(e), 'asn': asn}
    
    def get_domain_bgp_analysis(self, domain: str) -> Dict[str, Any]:
        """
        Comprehensive BGP analysis for a domain
        
        Args:
            domain: Domain to analyze
            
        Returns:
            Dict with comprehensive BGP analysis
        """
        cache_key = f"domain_bgp_{domain}"
        cached_result = self.cache.get('bgp_analysis', cache_key)
        if cached_result:
            return cached_result
        
        try:
            # Resolve domain to IP addresses
            ips = self._resolve_domain_ips(domain)
            if not ips:
                return {'error': 'Could not resolve domain', 'domain': domain}
            
            # Analyze each IP
            ip_analyses = []
            asn_summary = {}
            
            for ip in ips:
                asn_info = self.get_ip_asn_info(ip)
                if 'error' not in asn_info:
                    ip_analyses.append(asn_info)
                    
                    # Track ASN summary
                    asn = asn_info.get('asn')
                    if asn and asn != 0:
                        if asn not in asn_summary:
                            asn_summary[asn] = {
                                'asn': asn,
                                'name': asn_info.get('asn_name', ''),
                                'description': asn_info.get('asn_description', ''),
                                'country': asn_info.get('country_code', ''),
                                'ip_count': 0,
                                'ips': []
                            }
                        asn_summary[asn]['ip_count'] += 1
                        asn_summary[asn]['ips'].append(ip)
            
            # Build comprehensive analysis
            analysis = {
                'domain': domain,
                'resolved_ips': ips,
                'ip_analyses': ip_analyses,
                'asn_summary': list(asn_summary.values()),
                'total_asns': len(asn_summary),
                'primary_asn': self._get_primary_asn(asn_summary),
                'geographic_distribution': self._analyze_geographic_distribution(ip_analyses),
                'provider_analysis': self._analyze_providers(asn_summary),
                'data_source': 'bgp_analysis'
            }
            
            # Cache the result
            self.cache.set('bgp_analysis', cache_key, analysis, self.cache_ttl)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Failed BGP analysis for {domain}: {e}")
            return {'error': str(e), 'domain': domain}
    
    def _resolve_domain_ips(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses"""
        try:
            # Get all A records
            result = socket.getaddrinfo(domain, None, socket.AF_INET)
            ips = list(set([r[4][0] for r in result]))
            return ips
        except Exception as e:
            logger.error(f"Failed to resolve {domain}: {e}")
            return []
    
    def _get_primary_asn(self, asn_summary: Dict) -> Optional[Dict[str, Any]]:
        """Get the primary ASN (most IPs)"""
        if not asn_summary:
            return None
        
        primary = max(asn_summary.values(), key=lambda x: x['ip_count'])
        return primary
    
    def _analyze_geographic_distribution(self, ip_analyses: List[Dict]) -> Dict[str, Any]:
        """Analyze geographic distribution of IPs"""
        countries = {}
        
        for analysis in ip_analyses:
            country = analysis.get('country_code', 'Unknown')
            if country not in countries:
                countries[country] = 0
            countries[country] += 1
        
        return {
            'countries': countries,
            'total_countries': len(countries),
            'primary_country': max(countries.items(), key=lambda x: x[1])[0] if countries else None
        }
    
    def _analyze_providers(self, asn_summary: Dict) -> Dict[str, Any]:
        """Analyze hosting providers based on ASN data"""
        providers = []
        
        # Well-known hosting provider ASNs
        known_providers = {
            # Cloud providers
            16509: {'name': 'Amazon Web Services', 'type': 'Cloud', 'category': 'Major'},
            15169: {'name': 'Google Cloud', 'type': 'Cloud', 'category': 'Major'},
            8075: {'name': 'Microsoft Azure', 'type': 'Cloud', 'category': 'Major'},
            
            # CDN providers
            13335: {'name': 'Cloudflare', 'type': 'CDN', 'category': 'Major'},
            20940: {'name': 'Akamai', 'type': 'CDN', 'category': 'Major'},
            54113: {'name': 'Fastly', 'type': 'CDN', 'category': 'Major'},
            
            # Hosting providers
            26496: {'name': 'GoDaddy', 'type': 'Hosting', 'category': 'Shared'},
            394723: {'name': 'Hostinger', 'type': 'Hosting', 'category': 'Shared'},
        }
        
        for asn_data in asn_summary.values():
            asn = asn_data['asn']
            provider_info = {
                'asn': asn,
                'name': asn_data.get('name', ''),
                'description': asn_data.get('description', ''),
                'ip_count': asn_data.get('ip_count', 0),
                'type': 'Unknown',
                'category': 'Unknown'
            }
            
            # Check if it's a known provider
            if asn in known_providers:
                provider_info.update(known_providers[asn])
            else:
                # Try to classify based on name/description
                name_lower = provider_info['name'].lower()
                desc_lower = provider_info['description'].lower()
                
                if any(keyword in name_lower for keyword in ['cloud', 'aws', 'google', 'azure', 'gcp']):
                    provider_info['type'] = 'Cloud'
                elif any(keyword in name_lower for keyword in ['cdn', 'cloudflare', 'akamai', 'fastly']):
                    provider_info['type'] = 'CDN'
                elif any(keyword in name_lower for keyword in ['hosting', 'server', 'datacenter']):
                    provider_info['type'] = 'Hosting'
                elif any(keyword in name_lower for keyword in ['telecom', 'isp', 'internet']):
                    provider_info['type'] = 'ISP'
            
            providers.append(provider_info)
        
        return {
            'providers': providers,
            'total_providers': len(providers),
            'provider_types': self._count_provider_types(providers)
        }
    
    def _count_provider_types(self, providers: List[Dict]) -> Dict[str, int]:
        """Count providers by type"""
        types = {}
        for provider in providers:
            ptype = provider.get('type', 'Unknown')
            if ptype not in types:
                types[ptype] = 0
            types[ptype] += 1
        return types
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """
        Get authentication headers (required by HTTPIntegration)
        BGP APIs don't require authentication, so return empty dict
        """
        return {}
    
    def test_connection(self) -> Dict[str, Any]:
        """Test BGP multi-source strategy"""
        try:
            # Test with Google DNS
            result = self.get_ip_asn_info('8.8.8.8')

            if 'error' in result and result.get('asn', 0) == 0:
                return {
                    'success': False,
                    'error': result.get('error', 'All BGP sources failed'),
                    'sources_tested': ['ipinfo', 'hurricane_electric', 'ripe', 'local_classifier']
                }

            # Success case
            return {
                'success': True,
                'message': 'BGP multi-source analysis working',
                'test_ip': '8.8.8.8',
                'test_asn': result.get('asn'),
                'test_name': result.get('asn_name', 'Unknown'),
                'data_source': result.get('data_source', 'unknown'),
                'sources_available': self._check_available_sources(),
                'multi_source_enabled': True
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'multi_source_strategy': 'ipinfo → hurricane_electric → ripe → local'
            }

    def _check_available_sources(self) -> Dict[str, bool]:
        """Check which BGP sources are available"""
        return {
            'ipinfo': self.ipinfo is not None,
            'hurricane_electric': self.hurricane_electric is not None,
            'ripe': True,  # RIPE API is always available
            'local_classifier': self.bgp_classifier is not None
        }

# Singleton instance
_bgp_analysis_integration = None

def get_bgp_analysis_integration() -> BGPAnalysisIntegration:
    """Get singleton BGP analysis integration instance"""
    global _bgp_analysis_integration
    if _bgp_analysis_integration is None:
        _bgp_analysis_integration = BGPAnalysisIntegration()
    return _bgp_analysis_integration
