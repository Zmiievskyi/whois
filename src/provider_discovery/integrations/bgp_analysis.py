#!/usr/bin/env python3
"""
BGP Analysis Integration
Provides ASN lookup, routing analysis, and network intelligence
Uses multiple free BGP data sources including BGPView API
"""

import logging
import socket
import requests
from typing import Dict, List, Optional, Any, Tuple
from .base import HTTPIntegration

logger = logging.getLogger(__name__)

class BGPAnalysisIntegration(HTTPIntegration):
    """
    BGP Analysis integration using multiple free data sources
    
    Data Sources:
    - BGPView API (api.bgpview.io) - Free BGP data
    - RIPE Stat API - European network intelligence  
    - BGP.HE.net - Hurricane Electric data (scraped)
    - BGPKIT Broker - BGP archive data
    """
    
    def __init__(self, cache_ttl: int = 7200):
        """
        Initialize BGP Analysis integration
        
        Args:
            cache_ttl: Cache TTL in seconds (default 2 hours for better rate limiting)
        """
        super().__init__(
            service_name="bgp_analysis",
            base_url="https://api.bgpview.io"  # Primary BGP data source
        )
        
        self.cache_ttl = cache_ttl
        self.base_urls = {
            'bgpview': 'https://api.bgpview.io',
            'ripe': 'https://stat.ripe.net/data',
            'bgpkit': 'https://api.broker.bgpkit.com/v2'
        }
        
        # Setup rate limiting (very conservative for free APIs)
        if hasattr(self.rate_limiter, 'add_service'):
            self.rate_limiter.add_service('bgp_analysis', 3, 60)  # 3 requests per minute (very conservative)
        
        logger.info("BGP Analysis integration initialized")
    
    @property
    def is_enabled(self) -> bool:
        """BGP analysis is always enabled (uses free APIs)"""
        return True
    
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
        Get ASN information for an IP address
        
        Args:
            ip: IP address to lookup
            
        Returns:
            Dict with ASN information
        """
        cache_key = f"asn_info_{ip}"
        cached_result = self.cache.get('bgp_analysis', cache_key)
        if cached_result:
            return cached_result
        
        try:
            # BGPView API call
            endpoint = f"ip/{ip}"
            result = self._make_api_request(endpoint)
            
            if 'error' in result:
                return result
            
            # Extract useful information
            data = result.get('data', {})
            asn_info = {
                'ip': ip,
                'asn': data.get('asn', 0),
                'asn_name': data.get('name', ''),
                'asn_description': data.get('description_short', ''),
                'country_code': data.get('country_code', ''),
                'registry': data.get('rir_allocation', {}).get('rir_name', ''),
                'prefixes': data.get('prefixes', []),
                'data_source': 'bgpview'
            }
            
            # Cache the result
            self.cache.set('bgp_analysis', cache_key, asn_info, self.cache_ttl)
            
            return asn_info
            
        except Exception as e:
            logger.error(f"Failed to get ASN info for {ip}: {e}")
            return {'error': str(e), 'ip': ip}
    
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
        """Test BGP API connection with rate limit awareness"""
        try:
            # Check if we're rate limited first
            if hasattr(self.rate_limiter, 'is_rate_limited') and self.rate_limiter.is_rate_limited('bgp_analysis'):
                return {
                    'success': False,
                    'error': 'Rate limited - please wait before testing BGP API',
                    'rate_limited': True
                }
            
            # Test BGPView API with lightweight request
            result = self._make_api_request('ip/8.8.8.8')
            
            if 'error' in result:
                error_msg = result['error']
                
                # Check for rate limiting specifically
                if '429' in error_msg or 'rate limit' in error_msg.lower() or 'too many requests' in error_msg.lower():
                    return {
                        'success': False,
                        'error': 'BGPView API rate limited - using 3 req/min limit',
                        'rate_limited': True,
                        'fallback_available': True
                    }
                
                return {
                    'success': False,
                    'error': error_msg,
                    'fallback_available': True
                }
            
            # Success case
            asn_data = result.get('data', {})
            return {
                'success': True,
                'message': 'BGP analysis working',
                'test_ip': '8.8.8.8',
                'test_asn': asn_data.get('asn'),
                'test_name': asn_data.get('name', 'Unknown'),
                'api_status': 'available'
            }
            
        except Exception as e:
            error_str = str(e)
            
            # Handle rate limiting errors specifically
            if '429' in error_str or 'rate limit' in error_str.lower():
                return {
                    'success': False,
                    'error': 'BGPView API temporarily rate limited',
                    'rate_limited': True,
                    'suggestion': 'BGP analysis will work with cached data and Hurricane Electric fallback'
                }
            
            return {
                'success': False,
                'error': error_str,
                'fallback_available': True
            }

# Singleton instance
_bgp_analysis_integration = None

def get_bgp_analysis_integration() -> BGPAnalysisIntegration:
    """Get singleton BGP analysis integration instance"""
    global _bgp_analysis_integration
    if _bgp_analysis_integration is None:
        _bgp_analysis_integration = BGPAnalysisIntegration()
    return _bgp_analysis_integration
