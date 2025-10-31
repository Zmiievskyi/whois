#!/usr/bin/env python3
"""
Geographic Intelligence Integration
Free IP geolocation and geographic analysis using multiple sources
Provides location-based provider detection and infrastructure mapping
"""

import logging
import requests
import socket
from typing import Dict, List, Optional, Any, Tuple
from .base import HTTPIntegration

logger = logging.getLogger(__name__)

class GeoIntelligenceIntegration(HTTPIntegration):
    """
    Geographic Intelligence using free IP geolocation services
    
    Free Data Sources:
    - ip-api.com (1000 requests/month free)
    - ipapi.co (1000 requests/month free) 
    - ipinfo.io (50k requests/month free)
    - geojs.io (unlimited free)
    - ipwhois.app (10k requests/month free)
    """
    
    def __init__(self, cache_ttl: int = 3600):
        """
        Initialize Geographic Intelligence integration
        
        Args:
            cache_ttl: Cache TTL in seconds (default 1 hour)
        """
        super().__init__(
            service_name="geo_intelligence",
            base_url="http://ip-api.com/json"  # Primary free service
        )
        
        self.cache_ttl = cache_ttl
        
        # Configure free geolocation APIs
        self.geo_apis = {
            'ipapi_com': {
                'url': 'http://ip-api.com/json/{ip}',
                'free_limit': 1000,  # per month
                'rate_limit': 45,    # per minute
                'fields': 'status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,query'
            },
            'ipapi_co': {
                'url': 'https://ipapi.co/{ip}/json/',
                'free_limit': 1000,  # per month
                'rate_limit': 1000,  # per day
                'auth_required': False
            },
            'geojs_io': {
                'url': 'https://get.geojs.io/v1/ip/geo/{ip}.json',
                'free_limit': 'unlimited',
                'rate_limit': 'reasonable',
                'auth_required': False
            },
            'ipwhois_app': {
                'url': 'http://free.ipwhois.io/json/{ip}',
                'free_limit': 10000,  # per month
                'rate_limit': 1000,   # per day
                'auth_required': False
            }
        }
        
        # Setup conservative rate limiting
        if hasattr(self.rate_limiter, 'add_service'):
            self.rate_limiter.add_service('geo_intelligence', 30, 60)  # 30 requests per minute
        
        logger.info("Geographic Intelligence integration initialized")
    
    @property
    def is_enabled(self) -> bool:
        """Geographic intelligence is always enabled (uses free APIs)"""
        return True
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """No authentication needed for free geolocation APIs"""
        return {}
    
    def get_ip_geolocation(self, ip: str, provider: str = 'ipapi_com') -> Dict[str, Any]:
        """
        Get geolocation data for an IP address
        
        Args:
            ip: IP address to geolocate
            provider: Geolocation provider to use
            
        Returns:
            Dict with geolocation data
        """
        cache_key = f"geo_location_{ip}_{provider}"
        cached_result = self.cache.get('geo_intelligence', cache_key)
        if cached_result:
            return cached_result
        
        if provider not in self.geo_apis:
            return {'error': f'Unknown geolocation provider: {provider}'}
        
        api_config = self.geo_apis[provider]
        url = api_config['url'].format(ip=ip)
        
        try:
            # Apply rate limiting
            self.rate_limiter.wait_if_needed('geo_intelligence')
            
            # Add fields parameter for ip-api.com
            params = {}
            if provider == 'ipapi_com' and 'fields' in api_config:
                params['fields'] = api_config['fields']
            
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            geo_data = response.json()
            
            # Standardize response format
            standardized_data = self._standardize_geo_response(geo_data, provider)
            standardized_data.update({
                'ip': ip,
                'provider': provider,
                'raw_response': geo_data
            })
            
            # Cache the result
            self.cache.set('geo_intelligence', cache_key, standardized_data, self.cache_ttl)
            
            return standardized_data
            
        except Exception as e:
            logger.error(f"Geolocation failed for {ip} via {provider}: {e}")
            return {'error': str(e), 'ip': ip, 'provider': provider}
    
    def _standardize_geo_response(self, geo_data: Dict, provider: str) -> Dict[str, Any]:
        """Standardize different API responses to common format"""
        standardized = {
            'success': False,
            'country': None,
            'country_code': None,
            'region': None,
            'city': None,
            'latitude': None,
            'longitude': None,
            'timezone': None,
            'isp': None,
            'organization': None,
            'asn': None,
            'asn_name': None
        }
        
        try:
            if provider == 'ipapi_com':
                standardized.update({
                    'success': geo_data.get('status') == 'success',
                    'country': geo_data.get('country'),
                    'country_code': geo_data.get('countryCode'),
                    'region': geo_data.get('regionName'),
                    'city': geo_data.get('city'),
                    'latitude': geo_data.get('lat'),
                    'longitude': geo_data.get('lon'),
                    'timezone': geo_data.get('timezone'),
                    'isp': geo_data.get('isp'),
                    'organization': geo_data.get('org'),
                    'asn': geo_data.get('as', '').split(' ')[0].replace('AS', '') if geo_data.get('as') else None,
                    'asn_name': ' '.join(geo_data.get('as', '').split(' ')[1:]) if geo_data.get('as') else None
                })
            
            elif provider == 'ipapi_co':
                standardized.update({
                    'success': 'error' not in geo_data,
                    'country': geo_data.get('country_name'),
                    'country_code': geo_data.get('country'),
                    'region': geo_data.get('region'),
                    'city': geo_data.get('city'),
                    'latitude': geo_data.get('latitude'),
                    'longitude': geo_data.get('longitude'),
                    'timezone': geo_data.get('timezone'),
                    'isp': geo_data.get('org'),
                    'asn': str(geo_data.get('asn', '')).replace('AS', '') if geo_data.get('asn') else None
                })
            
            elif provider == 'geojs_io':
                standardized.update({
                    'success': True,
                    'country': geo_data.get('country'),
                    'country_code': geo_data.get('country_code'),
                    'region': geo_data.get('region'),
                    'city': geo_data.get('city'),
                    'latitude': geo_data.get('latitude'),
                    'longitude': geo_data.get('longitude'),
                    'timezone': geo_data.get('timezone'),
                    'organization': geo_data.get('organization_name')
                })
            
            elif provider == 'ipwhois_app':
                standardized.update({
                    'success': geo_data.get('success', False),
                    'country': geo_data.get('country'),
                    'country_code': geo_data.get('country_code'),
                    'region': geo_data.get('region'),
                    'city': geo_data.get('city'),
                    'latitude': geo_data.get('latitude'),
                    'longitude': geo_data.get('longitude'),
                    'timezone': geo_data.get('timezone'),
                    'isp': geo_data.get('isp'),
                    'organization': geo_data.get('org'),
                    'asn': str(geo_data.get('asn', '')).replace('AS', '') if geo_data.get('asn') else None
                })
            
        except Exception as e:
            logger.warning(f"Failed to standardize geo response from {provider}: {e}")
            standardized['parse_error'] = str(e)
        
        return standardized
    
    def get_multi_provider_geolocation(self, ip: str) -> Dict[str, Any]:
        """
        Get geolocation from multiple providers for cross-validation
        
        Args:
            ip: IP address to geolocate
            
        Returns:
            Dict with results from multiple providers
        """
        cache_key = f"multi_geo_{ip}"
        cached_result = self.cache.get('geo_intelligence', cache_key)
        if cached_result:
            return cached_result
        
        results = {
            'ip': ip,
            'provider_results': {},
            'consensus': {},
            'confidence_score': 0
        }
        
        # Query multiple providers
        providers_to_test = ['ipapi_com', 'geojs_io']  # Start with most reliable free ones
        
        for provider in providers_to_test:
            try:
                geo_result = self.get_ip_geolocation(ip, provider)
                results['provider_results'][provider] = geo_result
                
            except Exception as e:
                logger.debug(f"Geo provider {provider} failed for {ip}: {e}")
                results['provider_results'][provider] = {'error': str(e)}
        
        # Analyze consensus
        results['consensus'] = self._analyze_geo_consensus(results['provider_results'])
        results['confidence_score'] = self._calculate_geo_confidence(results['consensus'])
        
        # Cache the result
        self.cache.set('geo_intelligence', cache_key, results, self.cache_ttl)
        
        return results
    
    def _analyze_geo_consensus(self, provider_results: Dict) -> Dict[str, Any]:
        """Analyze consensus among geolocation providers"""
        successful_results = {
            name: result for name, result in provider_results.items()
            if result.get('success', False)
        }
        
        if not successful_results:
            return {'consensus_reached': False, 'reason': 'No successful geolocation'}
        
        # Collect values for each field
        field_values = {
            'country': [],
            'country_code': [],
            'region': [],
            'city': [],
            'isp': [],
            'organization': [],
            'asn': []
        }
        
        for result in successful_results.values():
            for field in field_values:
                value = result.get(field)
                if value:
                    field_values[field].append(str(value))
        
        # Find consensus values (most common)
        consensus_data = {}
        consensus_strength = {}
        
        for field, values in field_values.items():
            if values:
                # Count occurrences
                value_counts = {}
                for value in values:
                    value_counts[value] = value_counts.get(value, 0) + 1
                
                # Find most common
                most_common = max(value_counts.items(), key=lambda x: x[1])
                consensus_data[field] = most_common[0]
                consensus_strength[field] = most_common[1] / len(values)
        
        return {
            'consensus_reached': len(consensus_data) > 0,
            'consensus_data': consensus_data,
            'consensus_strength': consensus_strength,
            'successful_providers': len(successful_results),
            'total_providers': len(provider_results)
        }
    
    def _calculate_geo_confidence(self, consensus: Dict) -> int:
        """Calculate confidence score for geolocation data"""
        if not consensus.get('consensus_reached'):
            return 0
        
        # Base score
        score = 50
        
        # Provider agreement bonus
        successful_providers = consensus.get('successful_providers', 0)
        if successful_providers >= 2:
            score += 20 * successful_providers
        
        # Field consensus strength bonus
        strength_values = list(consensus.get('consensus_strength', {}).values())
        if strength_values:
            avg_strength = sum(strength_values) / len(strength_values)
            score += int(30 * avg_strength)
        
        return min(100, score)
    
    def analyze_domain_geography(self, domain: str) -> Dict[str, Any]:
        """
        Comprehensive geographic analysis for a domain
        
        Args:
            domain: Domain to analyze
            
        Returns:
            Dict with geographic intelligence
        """
        cache_key = f"domain_geo_{domain}"
        cached_result = self.cache.get('geo_intelligence', cache_key)
        if cached_result:
            return cached_result
        
        analysis = {
            'domain': domain,
            'resolved_ips': [],
            'ip_geolocation': {},
            'geographic_distribution': {},
            'infrastructure_insights': {},
            'hosting_patterns': {}
        }
        
        try:
            # Resolve domain to IPs
            ips = self._resolve_domain_ips(domain)
            analysis['resolved_ips'] = ips
            
            # Geolocate each IP
            for ip in ips:
                geo_result = self.get_multi_provider_geolocation(ip)
                analysis['ip_geolocation'][ip] = geo_result
            
            # Analyze geographic distribution
            analysis['geographic_distribution'] = self._analyze_geographic_distribution(analysis['ip_geolocation'])
            
            # Infrastructure insights
            analysis['infrastructure_insights'] = self._generate_infrastructure_insights(analysis)
            
            # Hosting patterns
            analysis['hosting_patterns'] = self._analyze_hosting_patterns(analysis['ip_geolocation'])
            
            # Cache the result
            self.cache.set('geo_intelligence', cache_key, analysis, self.cache_ttl)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Domain geographic analysis failed for {domain}: {e}")
            return {'error': str(e), 'domain': domain}
    
    def _resolve_domain_ips(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses using socket"""
        try:
            # Get all A records
            result = socket.getaddrinfo(domain, None, socket.AF_INET)
            ips = list(set([r[4][0] for r in result]))
            return ips
        except Exception as e:
            logger.error(f"Failed to resolve {domain}: {e}")
            return []
    
    def _analyze_geographic_distribution(self, ip_geolocation: Dict) -> Dict[str, Any]:
        """Analyze geographic distribution of IPs"""
        distribution = {
            'countries': {},
            'regions': {},
            'cities': {},
            'continents': {},
            'total_ips': len(ip_geolocation),
            'successful_geolocations': 0
        }
        
        # Continent mapping
        continent_mapping = {
            'US': 'North America', 'CA': 'North America', 'MX': 'North America',
            'GB': 'Europe', 'DE': 'Europe', 'FR': 'Europe', 'NL': 'Europe', 'IT': 'Europe',
            'CN': 'Asia', 'JP': 'Asia', 'IN': 'Asia', 'SG': 'Asia', 'KR': 'Asia',
            'AU': 'Oceania', 'NZ': 'Oceania',
            'BR': 'South America', 'AR': 'South America', 'CL': 'South America',
            'ZA': 'Africa', 'EG': 'Africa', 'NG': 'Africa'
        }
        
        for ip, geo_data in ip_geolocation.items():
            consensus = geo_data.get('consensus', {})
            if consensus.get('consensus_reached'):
                distribution['successful_geolocations'] += 1
                consensus_data = consensus.get('consensus_data', {})
                
                # Count countries
                country_code = consensus_data.get('country_code')
                if country_code:
                    distribution['countries'][country_code] = distribution['countries'].get(country_code, 0) + 1
                    
                    # Map to continent
                    continent = continent_mapping.get(country_code, 'Unknown')
                    distribution['continents'][continent] = distribution['continents'].get(continent, 0) + 1
                
                # Count regions
                region = consensus_data.get('region')
                if region:
                    distribution['regions'][region] = distribution['regions'].get(region, 0) + 1
                
                # Count cities
                city = consensus_data.get('city')
                if city:
                    distribution['cities'][city] = distribution['cities'].get(city, 0) + 1
        
        return distribution
    
    def _generate_infrastructure_insights(self, analysis: Dict) -> Dict[str, Any]:
        """Generate infrastructure insights from geographic data"""
        insights = {
            'global_distribution': False,
            'multi_region_setup': False,
            'cdn_indicators': [],
            'hosting_type': 'unknown',
            'performance_optimization': []
        }
        
        geo_dist = analysis.get('geographic_distribution', {})
        countries = geo_dist.get('countries', {})
        continents = geo_dist.get('continents', {})
        
        # Global distribution analysis
        if len(countries) >= 3:
            insights['global_distribution'] = True
        
        if len(continents) >= 2:
            insights['multi_region_setup'] = True
            insights['cdn_indicators'].append('Multi-continent presence')
        
        # CDN indicators
        if len(countries) >= 5:
            insights['cdn_indicators'].append('High geographic diversity (likely CDN)')
        
        # Hosting type classification
        if len(countries) == 1:
            insights['hosting_type'] = 'single_region'
        elif len(countries) <= 3:
            insights['hosting_type'] = 'multi_region'
        else:
            insights['hosting_type'] = 'global_cdn'
        
        # Performance optimization indicators
        if insights['multi_region_setup']:
            insights['performance_optimization'].append('Geographic load distribution')
        
        if len(countries) >= 4:
            insights['performance_optimization'].append('Latency optimization')
        
        return insights
    
    def _analyze_hosting_patterns(self, ip_geolocation: Dict) -> Dict[str, Any]:
        """Analyze hosting and provider patterns"""
        patterns = {
            'isps': {},
            'organizations': {},
            'asns': {},
            'cloud_providers': [],
            'hosting_classification': 'unknown'
        }
        
        # Known cloud provider patterns
        cloud_patterns = {
            'amazon': 'AWS',
            'google': 'Google Cloud',
            'microsoft': 'Microsoft Azure',
            'cloudflare': 'Cloudflare',
            'akamai': 'Akamai',
            'fastly': 'Fastly'
        }
        
        for ip, geo_data in ip_geolocation.items():
            consensus = geo_data.get('consensus', {})
            if consensus.get('consensus_reached'):
                consensus_data = consensus.get('consensus_data', {})
                
                # ISP analysis
                isp = consensus_data.get('isp', '').lower()
                if isp:
                    patterns['isps'][isp] = patterns['isps'].get(isp, 0) + 1
                    
                    # Check for cloud providers
                    for pattern, provider in cloud_patterns.items():
                        if pattern in isp:
                            patterns['cloud_providers'].append(provider)
                
                # Organization analysis
                org = consensus_data.get('organization', '').lower()
                if org:
                    patterns['organizations'][org] = patterns['organizations'].get(org, 0) + 1
                
                # ASN analysis
                asn = consensus_data.get('asn')
                if asn:
                    patterns['asns'][asn] = patterns['asns'].get(asn, 0) + 1
        
        # Classification
        if patterns['cloud_providers']:
            patterns['hosting_classification'] = 'cloud'
        elif len(set(patterns['isps'].keys())) == 1:
            patterns['hosting_classification'] = 'dedicated'
        elif len(set(patterns['isps'].keys())) > 1:
            patterns['hosting_classification'] = 'multi_provider'
        
        return patterns
    
    def test_connection(self) -> Dict[str, Any]:
        """Test geographic intelligence capabilities"""
        try:
            # Test with a known IP (Google DNS)
            test_result = self.get_ip_geolocation('8.8.8.8', 'ipapi_com')
            
            if 'error' in test_result:
                return {
                    'success': False,
                    'error': test_result['error']
                }
            
            return {
                'success': True,
                'message': 'Geographic intelligence working',
                'test_ip': '8.8.8.8',
                'test_country': test_result.get('country', 'Unknown'),
                'test_isp': test_result.get('isp', 'Unknown')
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def test_all_providers(self) -> Dict[str, Any]:
        """Test all geographic providers (alias for test_connection)"""
        return self.test_connection()

# Singleton instance
_geo_intelligence_integration = None

def get_geo_intelligence_integration() -> GeoIntelligenceIntegration:
    """Get singleton geographic intelligence integration instance"""
    global _geo_intelligence_integration
    if _geo_intelligence_integration is None:
        _geo_intelligence_integration = GeoIntelligenceIntegration()
    return _geo_intelligence_integration
