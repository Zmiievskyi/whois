#!/usr/bin/env python3
"""
Main Provider Detection Engine
Combines all detection modules into a unified interface
"""
import re
import socket
import requests
import whois
import logging
from typing import Dict, List, Optional, Any, Set, Union
from urllib.parse import urlparse, urljoin
from datetime import datetime

# Internal modules
from ..config.settings import get_settings
from ..utils.cache import get_multi_cache
from ..utils.validators import validate_url
from .ip_ranges import get_ip_range_manager
from .dns_analyzer import get_dns_analyzer
from ..integrations.virustotal import get_virustotal_integration


class ProviderDetector:
    """
    Main provider detection engine combining all analysis methods
    """
    
    def __init__(self, vt_api_key: Optional[str] = None):
        """
        Initialize provider detector with all sub-modules
        
        Args:
            vt_api_key: Optional VirusTotal API key
        """
        self.settings = get_settings()
        self.cache = get_multi_cache()
        self.logger = logging.getLogger(__name__)
        
        # Initialize sub-modules
        self.ip_manager = get_ip_range_manager()
        self.dns_analyzer = get_dns_analyzer()
        self.vt_integration = get_virustotal_integration(vt_api_key)
        
        # Cache instances for compatibility
        self.ip_cache = {}
        self.dns_cache = {}
        
        self.logger.info("🚀 Provider Detector initialized with all modules")
        
        # Enhanced header patterns for provider detection
        self.header_patterns = self._get_header_patterns()
        self.organization_patterns = self._get_organization_patterns()
        
    def _get_header_patterns(self) -> Dict[str, Dict[str, List[str]]]:
        """Get enhanced header patterns for provider detection"""
        return {
            'server_headers': {
                'Cloudflare': [
                    'cloudflare', 'cf-ray', 'cf-cache-status', 'cf-request-id',
                    '__cfruid', 'cf-connecting-ip'
                ],
                'AWS': [
                    'amazon', 'aws', 'cloudfront', 'awselb', 'awsalb',
                    'x-amz-cf-id', 'x-amz-cf-pop', 'x-amz-request-id'
                ],
                'Google': [
                    'gws', 'google', 'gfe', 'x-goog-', 'x-google-',
                    'alt-svc.*quic', 'x-cloud-trace-context'
                ],
                'Microsoft': [
                    'microsoft', 'azure', 'outlook', 'office',
                    'x-ms-', 'arr-', 'x-azure-'
                ],
                'Fastly': [
                    'fastly', 'x-served-by.*fastly', 'x-cache.*fastly',
                    'x-fastly-request-id'
                ],
                'Akamai': [
                    'akamai', 'x-akamai-', 'x-cache.*akamai',
                    'x-check-cacheable'
                ]
            },
            'security_headers': {
                'Cloudflare': [
                    'cf-ray', 'cf-mitigated', 'cf-polished',
                    'cf-cache-status', 'cf-request-id'
                ],
                'AWS WAF': [
                    'x-amzn-requestid', 'x-amzn-trace-id'
                ],
                'Incapsula': [
                    'x-iinfo', 'incap_ses', 'incapsula-incident-id'
                ],
                'Sucuri': [
                    'x-sucuri-id', 'x-sucuri-cache'
                ]
            }
        }
    
    def _get_organization_patterns(self) -> Dict[str, List[str]]:
        """Get organization patterns for WHOIS analysis"""
        return {
            'AWS': [
                'amazon', 'aws', 'amazon.com', 'amazon data services',
                'amazon technologies', 'amazon web services'
            ],
            'Google': [
                'google', 'google inc', 'google llc', 'google cloud',
                'alphabet inc'
            ],
            'Microsoft': [
                'microsoft', 'microsoft corporation', 'microsoft azure',
                'azure'
            ],
            'Cloudflare': [
                'cloudflare', 'cloudflare inc'
            ],
            'DigitalOcean': [
                'digitalocean', 'digital ocean', 'digitalocean llc'
            ],
            'Linode': [
                'linode', 'linode llc', 'akamai technologies'
            ],
            'Vultr': [
                'vultr', 'choopa llc', 'vultr holdings'
            ],
            'Fastly': [
                'fastly', 'fastly inc'
            ],
            'Akamai': [
                'akamai', 'akamai technologies'
            ]
        }
    
    def get_headers(self, url: str) -> str:
        """
        Get HTTP headers from URL
        
        Args:
            url: URL to fetch headers from
            
        Returns:
            Header string or error message
        """
        # Validate URL first
        is_valid, validation_msg = validate_url(url)
        if not is_valid:
            return f"Invalid URL: {validation_msg}"
        
        cache_key = f"headers:{url}"
        cached_result = self.cache.get('headers', cache_key)
        if cached_result:
            return cached_result
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Provider Discovery Tool)',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            response = requests.get(
                url,
                headers=headers,
                timeout=self.settings.http_timeout,
                allow_redirects=True,
                verify=True
            )
            
            # Format headers for analysis
            header_lines = [f"{key}: {value}" for key, value in response.headers.items()]
            header_string = "\n".join(header_lines)
            
            # Cache result
            self.cache.set('headers', cache_key, header_string)
            
            return header_string
            
        except requests.RequestException as e:
            error_msg = f"Failed to fetch headers: {str(e)}"
            self.logger.error(f"Header fetch failed for {url}: {e}")
            return error_msg
    
    def get_ip(self, url: str) -> str:
        """
        Get IP address from URL
        
        Args:
            url: URL to resolve
            
        Returns:
            IP address or error message
        """
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or parsed.netloc
            
            if not hostname:
                return "Could not extract hostname from URL"
            
            cache_key = f"ip_resolve:{hostname}"
            cached_result = self.cache.get('dns', cache_key)
            if cached_result:
                return cached_result
            
            # Resolve IP
            ip = socket.gethostbyname(hostname)
            
            # Cache result
            self.cache.set('dns', cache_key, ip)
            
            return ip
            
        except socket.gaierror as e:
            error_msg = f"DNS resolution failed: {str(e)}"
            self.logger.error(f"IP resolution failed for {url}: {e}")
            return error_msg
        except Exception as e:
            error_msg = f"Failed to get IP: {str(e)}"
            self.logger.error(f"IP extraction failed for {url}: {e}")
            return error_msg
    
    def get_whois(self, ip: str) -> str:
        """
        Get WHOIS data for IP address
        
        Args:
            ip: IP address to query
            
        Returns:
            WHOIS data or error message
        """
        if not ip or 'failed' in ip.lower() or 'error' in ip.lower():
            return "Invalid IP address"
        
        cache_key = f"whois:{ip}"
        cached_result = self.cache.get('whois', cache_key)
        if cached_result:
            return cached_result
        
        try:
            # Use python-whois library
            whois_data = whois.whois(ip)
            
            if whois_data:
                # Convert to string format
                whois_string = str(whois_data)
                
                # Cache result
                self.cache.set('whois', cache_key, whois_string)
                
                return whois_string
            else:
                return "No WHOIS data available"
                
        except Exception as e:
            error_msg = f"WHOIS query failed: {str(e)}"
            self.logger.error(f"WHOIS query failed for {ip}: {e}")
            return error_msg
    
    def analyze_headers_comprehensive(self, headers: str) -> List[Dict[str, str]]:
        """
        Comprehensive header analysis for provider detection
        
        Args:
            headers: HTTP headers string
            
        Returns:
            List of detected providers with roles
        """
        providers = []
        
        if not headers or 'failed' in headers.lower():
            return providers
        
        headers_lower = headers.lower()
        
        # Analyze server headers
        for provider, patterns in self.header_patterns['server_headers'].items():
            for pattern in patterns:
                if re.search(pattern, headers_lower):
                    providers.append({
                        'name': provider,
                        'role': 'CDN' if provider in ['Cloudflare', 'Fastly', 'Akamai'] else 'Origin',
                        'confidence': 'High',
                        'source': 'HTTP Headers',
                        'evidence': pattern
                    })
                    break
        
        # Analyze security headers
        for provider, patterns in self.header_patterns['security_headers'].items():
            for pattern in patterns:
                if re.search(pattern, headers_lower):
                    role = 'WAF' if 'waf' in provider.lower() else 'Security'
                    providers.append({
                        'name': provider,
                        'role': role,
                        'confidence': 'High',
                        'source': 'Security Headers',
                        'evidence': pattern
                    })
                    break
        
        return providers
    
    def analyze_whois_enhanced(self, whois_data: str) -> List[Dict[str, str]]:
        """
        Enhanced WHOIS analysis for provider detection
        
        Args:
            whois_data: WHOIS data string
            
        Returns:
            List of detected providers
        """
        providers = []
        
        if not whois_data or 'failed' in whois_data.lower():
            return providers
        
        whois_lower = whois_data.lower()
        
        # Extract organization information
        org_patterns = [
            r'org(?:anization)?:\s*([^\n\r]+)',
            r'orgname:\s*([^\n\r]+)',
            r'owner:\s*([^\n\r]+)',
            r'registrant:\s*([^\n\r]+)'
        ]
        
        organizations = set()
        for pattern in org_patterns:
            matches = re.findall(pattern, whois_lower)
            for match in matches:
                org = match.strip()
                if org and len(org) > 2:
                    organizations.add(org)
        
        # Match organizations to providers
        for provider, org_patterns in self.organization_patterns.items():
            for org in organizations:
                for pattern in org_patterns:
                    if pattern in org:
                        providers.append({
                            'name': provider,
                            'role': 'Origin',
                            'confidence': 'Medium',
                            'source': 'WHOIS',
                            'evidence': org
                        })
                        break
                if providers and providers[-1]['name'] == provider:
                    break
        
        return providers
    
    def detect_provider_multi_layer_enhanced(self, headers: str, ip: str, whois_data: str, domain: str) -> Dict[str, Any]:
        """
        Enhanced multi-layer provider detection (Phase 2A + existing methods)
        
        Args:
            headers: HTTP headers
            ip: IP address
            whois_data: WHOIS data
            domain: Domain name
            
        Returns:
            Comprehensive detection results
        """
        result = {
            'url': domain,
            'ip_address': ip,
            'providers': [],
            'confidence_factors': [],
            'analysis_methods': []
        }
        
        # Method 1: Header analysis
        header_providers = self.analyze_headers_comprehensive(headers)
        result['providers'].extend(header_providers)
        if header_providers:
            result['confidence_factors'].append(f"HTTP header analysis identified {len(header_providers)} providers")
            result['analysis_methods'].append('HTTP Headers')
        
        # Method 2: IP range analysis
        ip_provider = self.ip_manager.get_provider_by_ip(ip)
        if ip_provider:
            result['providers'].append({
                'name': ip_provider,
                'role': 'Origin',
                'confidence': 'High',
                'source': 'Official IP Ranges',
                'evidence': ip
            })
            result['confidence_factors'].append(f"IP {ip} confirmed in {ip_provider} official ranges")
            result['analysis_methods'].append('IP Range Analysis')
        
        # Method 3: WHOIS analysis
        whois_providers = self.analyze_whois_enhanced(whois_data)
        result['providers'].extend(whois_providers)
        if whois_providers:
            result['confidence_factors'].append(f"WHOIS analysis identified {len(whois_providers)} providers")
            result['analysis_methods'].append('WHOIS Analysis')
        
        # Method 4: DNS chain analysis
        dns_chain = self.dns_analyzer.analyze_dns_chain(domain)
        dns_providers = []
        for step in dns_chain:
            if step.get('provider'):
                dns_providers.append({
                    'name': step['provider'],
                    'role': step['role'],
                    'confidence': 'Medium',
                    'source': 'DNS Chain',
                    'evidence': step.get('cname') or step.get('ip')
                })
        
        result['providers'].extend(dns_providers)
        if dns_providers:
            result['confidence_factors'].append(f"DNS chain analysis found {len(dns_providers)} providers")
            result['analysis_methods'].append('DNS Chain Analysis')
        
        # Phase 2A: Enhanced DNS Analysis
        ns_analysis = self.dns_analyzer.analyze_ns_records(domain)
        ttl_analysis = self.dns_analyzer.analyze_ttl_patterns(domain)
        reverse_dns = self.dns_analyzer.reverse_dns_lookup(ip) if ip and 'failed' not in ip else None
        
        # Add DNS providers
        dns_provider_list = []
        for dns_provider_info in ns_analysis.get('dns_providers', []):
            provider_name = dns_provider_info['provider']
            if provider_name:
                result['providers'].append({
                    'name': provider_name,
                    'role': 'DNS',
                    'confidence': 'High',
                    'source': 'NS Records',
                    'evidence': dns_provider_info['ns_server']
                })
                dns_provider_list.append(provider_name)
        
        if dns_provider_list:
            result['confidence_factors'].append(f"NS record analysis identified DNS providers: {', '.join(set(dns_provider_list))}")
            result['analysis_methods'].append('NS Record Analysis')
        
        # Add reverse DNS info
        if reverse_dns and reverse_dns.get('provider'):
            result['providers'].append({
                'name': reverse_dns['provider'],
                'role': 'Origin',
                'confidence': 'Low',
                'source': 'Reverse DNS',
                'evidence': reverse_dns['reverse_domain']
            })
            result['confidence_factors'].append(f"Reverse DNS confirms {reverse_dns['provider']}")
            result['analysis_methods'].append('Reverse DNS')
        
        # Organize providers by role
        result.update(self._organize_providers_by_role(result['providers']))
        
        # Store detailed analysis data
        result['DNS_Analysis'] = ns_analysis
        result['TTL_Analysis'] = ttl_analysis
        result['DNS_Chain'] = dns_chain
        result['Reverse_DNS'] = reverse_dns
        
        # Calculate confidence score
        result['Confidence'] = self._calculate_confidence_score(result)
        
        return result
    
    def detect_provider_ultimate_with_virustotal(self, headers: str, ip: str, whois_data: str, domain: str) -> Dict[str, Any]:
        """
        Ultimate provider detection with VirusTotal enhancement (Phase 2B)
        
        Args:
            headers: HTTP headers
            ip: IP address  
            whois_data: WHOIS data
            domain: Domain name
            
        Returns:
            Complete detection results with VirusTotal data
        """
        # Start with enhanced multi-layer detection
        result = self.detect_provider_multi_layer_enhanced(headers, ip, whois_data, domain)
        
        # Enhance with VirusTotal if available
        if self.vt_integration and self.vt_integration.is_enabled:
            try:
                result = self.vt_integration.enhance_existing_detection(result, domain)
                result['analysis_methods'].append('VirusTotal API')
            except Exception as e:
                self.logger.error(f"VirusTotal enhancement failed: {e}")
                result['confidence_factors'].append(f"VirusTotal enhancement failed: {str(e)}")
                result['virustotal_enhanced'] = False
        else:
            result['virustotal_enhanced'] = False
        
        return result
    
    def detect_provider_ultimate(self, headers: str, ip: str, whois_data: str) -> List[Dict[str, str]]:
        """
        Legacy method for backward compatibility with original API
        
        Args:
            headers: HTTP headers
            ip: IP address
            whois_data: WHOIS data
            
        Returns:
            List of providers (legacy format)
        """
        # Use enhanced detection but return in legacy format
        providers = []
        
        # Header analysis
        header_providers = self.analyze_headers_comprehensive(headers)
        providers.extend(header_providers)
        
        # IP range analysis
        ip_provider = self.ip_manager.get_provider_by_ip(ip)
        if ip_provider:
            providers.append({
                'name': ip_provider,
                'role': 'Origin',
                'confidence': 'High',
                'source': 'IP Range Analysis'
            })
        
        # WHOIS analysis
        whois_providers = self.analyze_whois_enhanced(whois_data)
        providers.extend(whois_providers)
        
        return providers

    @property
    def vt_integrator(self):
        """Legacy property for backward compatibility"""
        return self.vt_integration
    
    def _organize_providers_by_role(self, providers: List[Dict[str, str]]) -> Dict[str, Any]:
        """Organize providers by their roles"""
        organized = {
            'Primary_Provider': None,
            'Origin_Provider': None,
            'CDN_Providers': [],
            'WAF_Providers': [],
            'LB_Providers': [],
            'DNS_Providers': []
        }
        
        for provider in providers:
            name = provider['name']
            role = provider['role']
            
            if role == 'Origin' and not organized['Origin_Provider']:
                organized['Origin_Provider'] = name
            elif role == 'CDN' and name not in organized['CDN_Providers']:
                organized['CDN_Providers'].append(name)
            elif role in ['WAF', 'Security'] and name not in organized['WAF_Providers']:
                organized['WAF_Providers'].append(name)
            elif role == 'Load Balancer' and name not in organized['LB_Providers']:
                organized['LB_Providers'].append(name)
            elif role == 'DNS' and name not in organized['DNS_Providers']:
                organized['DNS_Providers'].append(name)
        
        # Determine primary provider (prefer Origin, then first CDN)
        if organized['Origin_Provider']:
            organized['Primary_Provider'] = organized['Origin_Provider']
        elif organized['CDN_Providers']:
            organized['Primary_Provider'] = organized['CDN_Providers'][0]
        elif organized['DNS_Providers']:
            organized['Primary_Provider'] = organized['DNS_Providers'][0]
        
        return organized
    
    def _calculate_confidence_score(self, result: Dict[str, Any]) -> str:
        """Calculate overall confidence score"""
        score = 0
        
        # Points for different analysis methods
        method_points = {
            'HTTP Headers': 25,
            'IP Range Analysis': 30,
            'WHOIS Analysis': 20,
            'DNS Chain Analysis': 15,
            'NS Record Analysis': 20,
            'Reverse DNS': 10,
            'VirusTotal API': 25
        }
        
        for method in result.get('analysis_methods', []):
            score += method_points.get(method, 0)
        
        # Bonus for multiple confirming sources
        if len(result.get('analysis_methods', [])) >= 3:
            score += 15
        
        # Penalty for failed methods
        if any('failed' in factor.lower() for factor in result.get('confidence_factors', [])):
            score -= 10
        
        # Convert to descriptive confidence
        if score >= 80:
            return 'Very High'
        elif score >= 60:
            return 'High'
        elif score >= 40:
            return 'Medium'
        elif score >= 20:
            return 'Low'
        else:
            return 'Very Low'
    
    def process_single_url(self, url: str) -> Dict[str, Any]:
        """
        Process a single URL with complete analysis
        
        Args:
            url: URL to analyze
            
        Returns:
            Complete analysis results
        """
        self.logger.info(f"🔍 Processing URL: {url}")
        
        # Extract domain for DNS analysis
        parsed = urlparse(url)
        domain = parsed.hostname or parsed.netloc
        
        # Step 1: Get headers
        headers = self.get_headers(url)
        
        # Step 2: Get IP
        ip = self.get_ip(url)
        
        # Step 3: Get WHOIS
        whois_data = self.get_whois(ip)
        
        # Step 4: Ultimate detection with all enhancements
        result = self.detect_provider_ultimate_with_virustotal(headers, ip, whois_data, domain)
        
        self.logger.info(f"✅ Analysis complete for {url}")
        return result


# Global detector instance
_global_detector: Optional[ProviderDetector] = None


def get_provider_detector(vt_api_key: Optional[str] = None) -> ProviderDetector:
    """Get global provider detector instance"""
    global _global_detector
    if _global_detector is None:
        _global_detector = ProviderDetector(vt_api_key)
    return _global_detector


# Example usage and testing
if __name__ == "__main__":
    # Test provider detector
    detector = ProviderDetector()
    
    test_urls = [
        "https://github.com",
        "https://cloudflare.com", 
        "https://google.com"
    ]
    
    print("🔍 Testing Provider Detector:")
    for url in test_urls:
        print(f"\n📋 Analyzing {url}:")
        
        result = detector.process_single_url(url)
        
        print(f"  Primary Provider: {result.get('Primary_Provider', 'Unknown')}")
        print(f"  Confidence: {result.get('Confidence', 'Unknown')}")
        print(f"  Analysis Methods: {len(result.get('analysis_methods', []))}")
        print(f"  Providers Found: {len(result.get('providers', []))}")
        
        if result.get('virustotal_enhanced'):
            print("  ✅ Enhanced with VirusTotal")
        else:
            print("  ⚠️ VirusTotal not available")
    
    print("\n✅ Provider detector testing completed!")
