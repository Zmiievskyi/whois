#!/usr/bin/env python3
"""
Hurricane Electric BGP Toolkit Integration
Web scraping of Hurricane Electric's free BGP data and tools
Provides additional BGP intelligence and routing information
"""

import logging
import requests
import re
from bs4 import BeautifulSoup
from typing import Dict, List, Optional, Any, Tuple
from .base import HTTPIntegration

logger = logging.getLogger(__name__)

class HurricaneElectricIntegration(HTTPIntegration):
    """
    Hurricane Electric BGP Toolkit integration via web scraping
    
    Data Sources (100% Free):
    - bgp.he.net/ip/<ip> - IP prefix and ASN information
    - bgp.he.net/AS<asn> - ASN details and prefixes
    - bgp.he.net/net/<prefix> - Network prefix details
    - bgp.he.net/dns/<domain> - DNS and reverse DNS information
    """
    
    def __init__(self, cache_ttl: int = 7200):
        """
        Initialize Hurricane Electric BGP integration
        
        Args:
            cache_ttl: Cache TTL in seconds (default 2 hours)
        """
        super().__init__(
            service_name="hurricane_electric",
            base_url="https://bgp.he.net"
        )
        
        self.cache_ttl = cache_ttl
        
        # Configure endpoints
        self.endpoints = {
            'ip_lookup': '/ip/{ip}',
            'asn_lookup': '/AS{asn}',
            'prefix_lookup': '/net/{prefix}',
            'dns_lookup': '/dns/{domain}',
            'country_lookup': '/country/{country_code}'
        }
        
        # Setup conservative rate limiting (respectful scraping)
        if hasattr(self.rate_limiter, 'add_service'):
            self.rate_limiter.add_service('hurricane_electric', 6, 60)  # 6 requests per minute (very conservative)
        
        logger.info("Hurricane Electric BGP integration initialized")
    
    @property
    def is_enabled(self) -> bool:
        """Hurricane Electric is always enabled (free web scraping)"""
        return True
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Headers for web scraping"""
        return {
            'User-Agent': 'Mozilla/5.0 (compatible; BGP-Analysis/1.0; Research)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
    
    def get_ip_bgp_info(self, ip: str) -> Dict[str, Any]:
        """
        Get BGP information for an IP address from Hurricane Electric
        
        Args:
            ip: IP address to lookup
            
        Returns:
            Dict with BGP information
        """
        cache_key = f"he_ip_bgp_{ip}"
        cached_result = self.cache.get('hurricane_electric', cache_key)
        if cached_result:
            return cached_result
        
        try:
            # Apply rate limiting
            self.rate_limiter.wait_if_needed('hurricane_electric')
            
            url = f"{self.base_url}/ip/{ip}"
            
            response = requests.get(url, headers=self._get_auth_headers(), timeout=15)
            response.raise_for_status()
            
            # Parse HTML response
            soup = BeautifulSoup(response.text, 'html.parser')
            
            bgp_info = self._parse_ip_page(soup, ip)
            bgp_info['source'] = 'hurricane_electric'
            bgp_info['url'] = url
            
            # Cache the result
            self.cache.set('hurricane_electric', cache_key, bgp_info, self.cache_ttl)
            
            return bgp_info
            
        except Exception as e:
            logger.error(f"Hurricane Electric IP lookup failed for {ip}: {e}")
            return {'error': str(e), 'ip': ip}
    
    def _parse_ip_page(self, soup: BeautifulSoup, ip: str) -> Dict[str, Any]:
        """Parse Hurricane Electric IP page"""
        info = {
            'ip': ip,
            'asn': None,
            'asn_name': None,
            'prefix': None,
            'country': None,
            'registry': None,
            'allocation_date': None,
            'description': None,
            'organization': None,
            'raw_data': {}
        }
        
        try:
            # Look for ASN information
            asn_links = soup.find_all('a', href=re.compile(r'/AS\d+'))
            if asn_links:
                asn_link = asn_links[0]
                asn_match = re.search(r'/AS(\d+)', asn_link.get('href', ''))
                if asn_match:
                    info['asn'] = int(asn_match.group(1))
                    info['asn_name'] = asn_link.text.strip()
            
            # Look for prefix information
            prefix_links = soup.find_all('a', href=re.compile(r'/net/'))
            if prefix_links:
                prefix_link = prefix_links[0]
                prefix_text = prefix_link.text.strip()
                if '/' in prefix_text:
                    info['prefix'] = prefix_text
            
            # Look for country information
            country_links = soup.find_all('a', href=re.compile(r'/country/'))
            if country_links:
                country_link = country_links[0]
                country_match = re.search(r'/country/(\w+)', country_link.get('href', ''))
                if country_match:
                    info['country'] = country_match.group(1)
            
            # Look for organization/description in table data
            tables = soup.find_all('table')
            for table in tables:
                rows = table.find_all('tr')
                for row in rows:
                    cells = row.find_all(['td', 'th'])
                    if len(cells) >= 2:
                        header = cells[0].text.strip().lower()
                        value = cells[1].text.strip()
                        
                        if 'organization' in header or 'org' in header:
                            info['organization'] = value
                        elif 'description' in header or 'desc' in header:
                            info['description'] = value
                        elif 'registry' in header:
                            info['registry'] = value
                        elif 'allocated' in header or 'allocation' in header:
                            info['allocation_date'] = value
            
            # Extract any additional text data
            page_text = soup.get_text()
            
            # Look for "Announced by" pattern
            announced_match = re.search(r'Announced by AS(\d+)', page_text, re.IGNORECASE)
            if announced_match and not info['asn']:
                info['asn'] = int(announced_match.group(1))
            
            # Look for CIDR pattern
            cidr_matches = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b', page_text)
            if cidr_matches and not info['prefix']:
                # Find the most specific prefix (highest prefix length)
                prefixes = [(prefix, int(prefix.split('/')[1])) for prefix in cidr_matches]
                if prefixes:
                    most_specific = max(prefixes, key=lambda x: x[1])
                    info['prefix'] = most_specific[0]
            
        except Exception as e:
            logger.warning(f"Error parsing Hurricane Electric IP page for {ip}: {e}")
            info['parse_error'] = str(e)
        
        return info
    
    def get_asn_details(self, asn: int) -> Dict[str, Any]:
        """
        Get detailed ASN information from Hurricane Electric
        
        Args:
            asn: Autonomous System Number
            
        Returns:
            Dict with ASN details
        """
        cache_key = f"he_asn_details_{asn}"
        cached_result = self.cache.get('hurricane_electric', cache_key)
        if cached_result:
            return cached_result
        
        try:
            # Apply rate limiting
            self.rate_limiter.wait_if_needed('hurricane_electric')
            
            url = f"{self.base_url}/AS{asn}"
            
            response = requests.get(url, headers=self._get_auth_headers(), timeout=15)
            response.raise_for_status()
            
            # Parse HTML response
            soup = BeautifulSoup(response.text, 'html.parser')
            
            asn_details = self._parse_asn_page(soup, asn)
            asn_details['source'] = 'hurricane_electric'
            asn_details['url'] = url
            
            # Cache the result
            self.cache.set('hurricane_electric', cache_key, asn_details, self.cache_ttl)
            
            return asn_details
            
        except Exception as e:
            logger.error(f"Hurricane Electric ASN lookup failed for AS{asn}: {e}")
            return {'error': str(e), 'asn': asn}
    
    def _parse_asn_page(self, soup: BeautifulSoup, asn: int) -> Dict[str, Any]:
        """Parse Hurricane Electric ASN page"""
        details = {
            'asn': asn,
            'name': None,
            'description': None,
            'country': None,
            'organization': None,
            'website': None,
            'email': None,
            'phone': None,
            'prefixes_v4': [],
            'prefixes_v6': [],
            'peers': [],
            'upstreams': [],
            'downstreams': []
        }
        
        try:
            # Get ASN name from page title or header
            title = soup.find('title')
            if title:
                title_text = title.text.strip()
                # Extract ASN name from title like "AS15169 Google LLC"
                name_match = re.search(rf'AS{asn}\s+(.+?)(?:\s*-|\s*$)', title_text)
                if name_match:
                    details['name'] = name_match.group(1).strip()
            
            # Look for organization information in tables
            tables = soup.find_all('table')
            for table in tables:
                rows = table.find_all('tr')
                for row in rows:
                    cells = row.find_all(['td', 'th'])
                    if len(cells) >= 2:
                        header = cells[0].text.strip().lower()
                        value = cells[1].text.strip()
                        
                        if 'organization' in header or 'name' in header:
                            details['organization'] = value
                        elif 'description' in header:
                            details['description'] = value
                        elif 'country' in header:
                            details['country'] = value
                        elif 'website' in header or 'web' in header:
                            details['website'] = value
                        elif 'email' in header or 'e-mail' in header:
                            details['email'] = value
                        elif 'phone' in header:
                            details['phone'] = value
            
            # Look for IPv4 prefixes
            prefix_links = soup.find_all('a', href=re.compile(r'/net/\d+\.\d+\.\d+\.\d+/\d+'))
            for link in prefix_links:
                prefix_text = link.text.strip()
                if re.match(r'\d+\.\d+\.\d+\.\d+/\d+', prefix_text):
                    details['prefixes_v4'].append(prefix_text)
            
            # Look for IPv6 prefixes
            ipv6_links = soup.find_all('a', href=re.compile(r'/net/[0-9a-fA-F:]+/\d+'))
            for link in ipv6_links:
                prefix_text = link.text.strip()
                if ':' in prefix_text and '/' in prefix_text:
                    details['prefixes_v6'].append(prefix_text)
            
            # Look for peering information
            peer_links = soup.find_all('a', href=re.compile(r'/AS\d+'))
            for link in peer_links:
                peer_text = link.text.strip()
                asn_match = re.search(r'AS(\d+)', link.get('href', ''))
                if asn_match:
                    peer_asn = int(asn_match.group(1))
                    if peer_asn != asn:  # Don't include self
                        peer_info = {
                            'asn': peer_asn,
                            'name': peer_text,
                            'relationship': 'peer'  # Default, can be refined
                        }
                        
                        # Try to determine relationship from context
                        link_context = link.parent.text.lower() if link.parent else ''
                        if 'upstream' in link_context:
                            peer_info['relationship'] = 'upstream'
                            details['upstreams'].append(peer_info)
                        elif 'downstream' in link_context or 'customer' in link_context:
                            peer_info['relationship'] = 'downstream'
                            details['downstreams'].append(peer_info)
                        else:
                            details['peers'].append(peer_info)
            
            # Remove duplicates
            details['prefixes_v4'] = list(set(details['prefixes_v4']))
            details['prefixes_v6'] = list(set(details['prefixes_v6']))
            
        except Exception as e:
            logger.warning(f"Error parsing Hurricane Electric ASN page for AS{asn}: {e}")
            details['parse_error'] = str(e)
        
        return details
    
    def get_prefix_details(self, prefix: str) -> Dict[str, Any]:
        """
        Get network prefix details from Hurricane Electric
        
        Args:
            prefix: Network prefix (e.g., "8.8.8.0/24")
            
        Returns:
            Dict with prefix details
        """
        cache_key = f"he_prefix_{prefix.replace('/', '_')}"
        cached_result = self.cache.get('hurricane_electric', cache_key)
        if cached_result:
            return cached_result
        
        try:
            # Apply rate limiting
            self.rate_limiter.wait_if_needed('hurricane_electric')
            
            url = f"{self.base_url}/net/{prefix}"
            
            response = requests.get(url, headers=self._get_auth_headers(), timeout=15)
            response.raise_for_status()
            
            # Parse HTML response
            soup = BeautifulSoup(response.text, 'html.parser')
            
            prefix_details = self._parse_prefix_page(soup, prefix)
            prefix_details['source'] = 'hurricane_electric'
            prefix_details['url'] = url
            
            # Cache the result
            self.cache.set('hurricane_electric', cache_key, prefix_details, self.cache_ttl)
            
            return prefix_details
            
        except Exception as e:
            logger.error(f"Hurricane Electric prefix lookup failed for {prefix}: {e}")
            return {'error': str(e), 'prefix': prefix}
    
    def _parse_prefix_page(self, soup: BeautifulSoup, prefix: str) -> Dict[str, Any]:
        """Parse Hurricane Electric prefix page"""
        details = {
            'prefix': prefix,
            'asn': None,
            'asn_name': None,
            'description': None,
            'country': None,
            'registry': None,
            'allocation_date': None,
            'more_specific_routes': [],
            'less_specific_routes': []
        }
        
        try:
            # Look for ASN information
            asn_links = soup.find_all('a', href=re.compile(r'/AS\d+'))
            if asn_links:
                asn_link = asn_links[0]
                asn_match = re.search(r'/AS(\d+)', asn_link.get('href', ''))
                if asn_match:
                    details['asn'] = int(asn_match.group(1))
                    details['asn_name'] = asn_link.text.strip()
            
            # Parse table data
            tables = soup.find_all('table')
            for table in tables:
                rows = table.find_all('tr')
                for row in rows:
                    cells = row.find_all(['td', 'th'])
                    if len(cells) >= 2:
                        header = cells[0].text.strip().lower()
                        value = cells[1].text.strip()
                        
                        if 'description' in header:
                            details['description'] = value
                        elif 'country' in header:
                            details['country'] = value
                        elif 'registry' in header:
                            details['registry'] = value
                        elif 'allocated' in header:
                            details['allocation_date'] = value
            
            # Look for more specific and less specific routes
            route_links = soup.find_all('a', href=re.compile(r'/net/'))
            for link in route_links:
                route_text = link.text.strip()
                if '/' in route_text and route_text != prefix:
                    # Determine if more or less specific
                    try:
                        import ipaddress
                        current_net = ipaddress.ip_network(prefix, strict=False)
                        other_net = ipaddress.ip_network(route_text, strict=False)
                        
                        if other_net.subnet_of(current_net):
                            details['more_specific_routes'].append(route_text)
                        elif current_net.subnet_of(other_net):
                            details['less_specific_routes'].append(route_text)
                    except:
                        pass  # Skip invalid prefixes
            
            # Remove duplicates
            details['more_specific_routes'] = list(set(details['more_specific_routes']))
            details['less_specific_routes'] = list(set(details['less_specific_routes']))
            
        except Exception as e:
            logger.warning(f"Error parsing Hurricane Electric prefix page for {prefix}: {e}")
            details['parse_error'] = str(e)
        
        return details
    
    def comprehensive_bgp_analysis(self, target: str) -> Dict[str, Any]:
        """
        Comprehensive BGP analysis for IP, ASN, or domain
        
        Args:
            target: IP address, ASN number, or domain name
            
        Returns:
            Dict with comprehensive BGP analysis
        """
        cache_key = f"he_comprehensive_{target}"
        cached_result = self.cache.get('hurricane_electric', cache_key)
        if cached_result:
            return cached_result
        
        analysis = {
            'target': target,
            'target_type': self._determine_target_type(target),
            'ip_analysis': {},
            'asn_analysis': {},
            'prefix_analysis': {},
            'routing_insights': {},
            'provider_classification': {}
        }
        
        try:
            target_type = analysis['target_type']
            
            if target_type == 'ip':
                # IP address analysis
                ip_info = self.get_ip_bgp_info(target)
                analysis['ip_analysis'] = ip_info
                
                # Get ASN details if available
                if ip_info.get('asn'):
                    asn_details = self.get_asn_details(ip_info['asn'])
                    analysis['asn_analysis'] = asn_details
                
                # Get prefix details if available
                if ip_info.get('prefix'):
                    prefix_details = self.get_prefix_details(ip_info['prefix'])
                    analysis['prefix_analysis'] = prefix_details
                    
            elif target_type == 'asn':
                # ASN analysis
                asn_num = int(target.replace('AS', '').replace('as', ''))
                asn_details = self.get_asn_details(asn_num)
                analysis['asn_analysis'] = asn_details
                
            elif target_type == 'domain':
                # Domain to IP, then BGP analysis
                try:
                    import socket
                    ip = socket.gethostbyname(target)
                    analysis['resolved_ip'] = ip
                    
                    ip_info = self.get_ip_bgp_info(ip)
                    analysis['ip_analysis'] = ip_info
                    
                    if ip_info.get('asn'):
                        asn_details = self.get_asn_details(ip_info['asn'])
                        analysis['asn_analysis'] = asn_details
                        
                except Exception as e:
                    analysis['resolution_error'] = str(e)
            
            # Generate routing insights
            analysis['routing_insights'] = self._generate_routing_insights(analysis)
            
            # Provider classification
            analysis['provider_classification'] = self._classify_provider_from_bgp(analysis)
            
            # Cache the result
            self.cache.set('hurricane_electric', cache_key, analysis, self.cache_ttl)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Comprehensive BGP analysis failed for {target}: {e}")
            return {'error': str(e), 'target': target}
    
    def _determine_target_type(self, target: str) -> str:
        """Determine if target is IP, ASN, or domain"""
        import re
        
        # Check if it's an ASN
        if target.upper().startswith('AS') or target.isdigit():
            return 'asn'
        
        # Check if it's an IP address
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if re.match(ip_pattern, target):
            return 'ip'
        
        # Assume it's a domain
        return 'domain'
    
    def _generate_routing_insights(self, analysis: Dict) -> Dict[str, Any]:
        """Generate routing insights from BGP data"""
        insights = {
            'routing_security': 'unknown',
            'prefix_specificity': 'unknown',
            'peering_diversity': 'unknown',
            'geographic_presence': 'unknown',
            'recommendations': []
        }
        
        try:
            asn_analysis = analysis.get('asn_analysis', {})
            ip_analysis = analysis.get('ip_analysis', {})
            prefix_analysis = analysis.get('prefix_analysis', {})
            
            # Analyze prefix specificity
            if ip_analysis.get('prefix'):
                prefix = ip_analysis['prefix']
                prefix_len = int(prefix.split('/')[1]) if '/' in prefix else 0
                
                if prefix_len >= 24:
                    insights['prefix_specificity'] = 'high'
                elif prefix_len >= 20:
                    insights['prefix_specificity'] = 'medium'
                else:
                    insights['prefix_specificity'] = 'low'
            
            # Analyze peering diversity
            if asn_analysis.get('peers') or asn_analysis.get('upstreams'):
                peer_count = len(asn_analysis.get('peers', [])) + len(asn_analysis.get('upstreams', []))
                
                if peer_count >= 10:
                    insights['peering_diversity'] = 'high'
                elif peer_count >= 3:
                    insights['peering_diversity'] = 'medium'
                else:
                    insights['peering_diversity'] = 'low'
            
            # Geographic presence analysis
            if asn_analysis.get('country') or ip_analysis.get('country'):
                insights['geographic_presence'] = 'identified'
            
            # Generate recommendations
            if insights['prefix_specificity'] == 'low':
                insights['recommendations'].append('Consider more specific prefix announcements for better control')
            
            if insights['peering_diversity'] == 'low':
                insights['recommendations'].append('Consider increasing peering diversity for better redundancy')
            
        except Exception as e:
            logger.warning(f"Error generating routing insights: {e}")
            insights['analysis_error'] = str(e)
        
        return insights
    
    def _classify_provider_from_bgp(self, analysis: Dict) -> Dict[str, Any]:
        """Classify provider type based on BGP data"""
        classification = {
            'provider_type': 'unknown',
            'provider_name': None,
            'confidence': 0,
            'indicators': []
        }
        
        try:
            asn_analysis = analysis.get('asn_analysis', {})
            ip_analysis = analysis.get('ip_analysis', {})
            
            # Get provider name
            provider_name = (
                asn_analysis.get('name') or 
                asn_analysis.get('organization') or 
                ip_analysis.get('asn_name') or
                ip_analysis.get('organization')
            )
            
            if provider_name:
                classification['provider_name'] = provider_name
                provider_lower = provider_name.lower()
                
                # Known provider patterns
                if any(pattern in provider_lower for pattern in ['google', 'gcp']):
                    classification['provider_type'] = 'cloud'
                    classification['confidence'] = 95
                    classification['indicators'].append('Google Cloud Platform')
                    
                elif any(pattern in provider_lower for pattern in ['amazon', 'aws']):
                    classification['provider_type'] = 'cloud'
                    classification['confidence'] = 95
                    classification['indicators'].append('Amazon Web Services')
                    
                elif any(pattern in provider_lower for pattern in ['microsoft', 'azure']):
                    classification['provider_type'] = 'cloud'
                    classification['confidence'] = 95
                    classification['indicators'].append('Microsoft Azure')
                    
                elif any(pattern in provider_lower for pattern in ['cloudflare']):
                    classification['provider_type'] = 'cdn'
                    classification['confidence'] = 95
                    classification['indicators'].append('Cloudflare CDN')
                    
                elif any(pattern in provider_lower for pattern in ['akamai']):
                    classification['provider_type'] = 'cdn'
                    classification['confidence'] = 95
                    classification['indicators'].append('Akamai CDN')
                    
                elif any(pattern in provider_lower for pattern in ['fastly']):
                    classification['provider_type'] = 'cdn'
                    classification['confidence'] = 90
                    classification['indicators'].append('Fastly CDN')
                    
                elif any(pattern in provider_lower for pattern in ['hosting', 'server', 'datacenter']):
                    classification['provider_type'] = 'hosting'
                    classification['confidence'] = 70
                    classification['indicators'].append('Hosting provider pattern')
                    
                elif any(pattern in provider_lower for pattern in ['telecom', 'communications', 'internet']):
                    classification['provider_type'] = 'isp'
                    classification['confidence'] = 70
                    classification['indicators'].append('ISP pattern')
            
            # Additional indicators from BGP data
            prefixes_v4 = len(asn_analysis.get('prefixes_v4', []))
            prefixes_v6 = len(asn_analysis.get('prefixes_v6', []))
            
            if prefixes_v4 > 100 or prefixes_v6 > 50:
                classification['indicators'].append('Large prefix count (likely major provider)')
                classification['confidence'] = min(100, classification['confidence'] + 10)
            
            # Peer count analysis
            peer_count = len(asn_analysis.get('peers', [])) + len(asn_analysis.get('upstreams', []))
            if peer_count > 20:
                classification['indicators'].append('High peer count (likely tier-1 or major provider)')
                classification['confidence'] = min(100, classification['confidence'] + 10)
            
        except Exception as e:
            logger.warning(f"Error classifying provider from BGP: {e}")
            classification['classification_error'] = str(e)
        
        return classification
    
    def test_connection(self) -> Dict[str, Any]:
        """Test Hurricane Electric BGP toolkit access"""
        try:
            # Test with a known IP (Google DNS)
            test_result = self.get_ip_bgp_info('8.8.8.8')
            
            if 'error' in test_result:
                return {
                    'success': False,
                    'error': test_result['error']
                }
            
            return {
                'success': True,
                'message': 'Hurricane Electric BGP toolkit accessible',
                'test_ip': '8.8.8.8',
                'found_asn': test_result.get('asn'),
                'found_prefix': test_result.get('prefix')
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

# Singleton instance
_hurricane_electric_integration = None

def get_hurricane_electric_integration() -> HurricaneElectricIntegration:
    """Get singleton Hurricane Electric BGP integration instance"""
    global _hurricane_electric_integration
    if _hurricane_electric_integration is None:
        _hurricane_electric_integration = HurricaneElectricIntegration()
    return _hurricane_electric_integration
