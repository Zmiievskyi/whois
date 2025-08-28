#!/usr/bin/env python3
"""
Comprehensive Analysis Integration
Full DNS records, subdomain enumeration, raw headers, and enhanced data collection
"""

import dns.resolver
import dns.rdatatype
import dns.exception
import socket
import ssl
import requests
import json
import logging
import time
import concurrent.futures
from typing import Dict, List, Optional, Any, Set, Tuple
from urllib.parse import urlparse
from .base import HTTPIntegration

logger = logging.getLogger(__name__)

class ComprehensiveAnalysisIntegration(HTTPIntegration):
    """
    Comprehensive analysis for complete infrastructure visibility
    
    Features:
    - Full DNS record collection (A, AAAA, CNAME, NS, MX, TXT, SOA, PTR, CAA, SRV)
    - Subdomain enumeration using multiple techniques
    - Raw HTTP headers and response analysis
    - Origin server detection behind CDN
    - Advanced SSL/TLS analysis
    - Infrastructure mapping
    """
    
    def __init__(self, cache_ttl: int = 3600):
        """
        Initialize comprehensive analysis integration
        
        Args:
            cache_ttl: Cache TTL in seconds (default 1 hour)
        """
        super().__init__(
            service_name="comprehensive_analysis",
            base_url="https://api.comprehensive.local"  # Placeholder
        )
        
        self.cache_ttl = cache_ttl
        
        # DNS record types to query
        self.dns_record_types = [
            'A', 'AAAA', 'CNAME', 'NS', 'MX', 'TXT', 'SOA', 'PTR',
            'CAA', 'SRV', 'HINFO', 'NAPTR'
        ]
        
        # Common subdomain prefixes for enumeration
        self.subdomain_wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'dev', 'staging', 'test',
            'admin', 'api', 'blog', 'shop', 'forum', 'support', 'mobile', 'm', 'beta',
            'alpha', 'app', 'cdn', 'assets', 'static', 'media', 'images', 'img', 'css',
            'js', 'ajax', 'xml', 'json', 'secure', 'ssl', 'vpn', 'remote', 'cloud',
            'portal', 'login', 'auth', 'dashboard', 'panel', 'control', 'manage', 'origin',
            'direct', 'backend', 'server', 'lb', 'loadbalancer', 'db', 'database', 'cache'
        ]
        
        # HTTP headers for realistic requests
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0'
        }
        
        logger.info("🔍 Comprehensive Analysis integration initialized")
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers (not needed for this integration)"""
        return {}
    
    def analyze_domain_comprehensive(self, domain: str) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of a domain
        
        Args:
            domain: Domain to analyze
            
        Returns:
            Complete analysis results
        """
        # Temporarily disable caching to avoid cache type errors
        # cache_key = f"comprehensive:{domain}"
        # cached_result = self.cache.get('enhanced_dns', cache_key)
        # if cached_result:
        #     logger.debug(f"Using cached comprehensive analysis for {domain}")
        #     return cached_result
        
        logger.info(f"🔍 Starting comprehensive analysis for {domain}")
        
        results = {
            'domain': domain,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
            'dns_records': {},
            'subdomains': {},
            'http_analysis': {},
            'origin_detection': {},
            'infrastructure_mapping': {},
            'ssl_analysis': {},
            'performance_metrics': {}
        }
        
        # Parallel execution for efficiency
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                'dns': executor.submit(self._collect_all_dns_records, domain),
                'subdomains': executor.submit(self._enumerate_subdomains, domain),
                'http': executor.submit(self._analyze_http_comprehensive, domain),
                'origin': executor.submit(self._detect_origin_servers, domain)
            }
            
            # Collect results
            for key, future in futures.items():
                try:
                    if key == 'dns':
                        results['dns_records'] = future.result(timeout=30)
                    elif key == 'subdomains':
                        results['subdomains'] = future.result(timeout=60)
                    elif key == 'http':
                        results['http_analysis'] = future.result(timeout=30)
                    elif key == 'origin':
                        results['origin_detection'] = future.result(timeout=30)
                except Exception as e:
                    logger.error(f"Error in {key} analysis for {domain}: {e}")
                    if key == 'dns':
                        results['dns_records'] = {'error': str(e)}
                    elif key == 'subdomains':
                        results['subdomains'] = {'error': str(e)}
                    elif key == 'http':
                        results['http_analysis'] = {'error': str(e)}
                    elif key == 'origin':
                        results['origin_detection'] = {'error': str(e)}
        
        # Infrastructure mapping based on collected data
        results['infrastructure_mapping'] = self._map_infrastructure(results)
        
        # Cache results (temporarily disabled)
        # self.cache.set('enhanced_dns', cache_key, results, self.cache_ttl)
        
        logger.info(f"✅ Comprehensive analysis completed for {domain}")
        return results
    
    def _collect_all_dns_records(self, domain: str) -> Dict[str, Any]:
        """
        Collect all DNS record types for the domain
        
        Args:
            domain: Domain to query
            
        Returns:
            Dict with all DNS records
        """
        dns_data = {
            'domain': domain,
            'records': {},
            'nameservers': [],
            'resolver_info': {},
            'errors': []
        }
        
        # Configure resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10
        
        # Collect nameserver information
        try:
            ns_answers = resolver.resolve(domain, 'NS')
            dns_data['nameservers'] = [str(ns).rstrip('.') for ns in ns_answers]
            dns_data['resolver_info']['authoritative_ns'] = dns_data['nameservers']
        except Exception as e:
            dns_data['errors'].append(f"NS query failed: {e}")
        
        # Query each record type
        for record_type in self.dns_record_types:
            try:
                answers = resolver.resolve(domain, record_type)
                records = []
                
                for rdata in answers:
                    record_data = {
                        'value': str(rdata),
                        'ttl': answers.ttl,
                        'type': record_type
                    }
                    
                    # Add type-specific parsing
                    if record_type == 'MX':
                        record_data.update({
                            'priority': rdata.preference,
                            'exchange': str(rdata.exchange).rstrip('.')
                        })
                    elif record_type == 'SOA':
                        record_data.update({
                            'mname': str(rdata.mname).rstrip('.'),
                            'rname': str(rdata.rname).rstrip('.'),
                            'serial': rdata.serial,
                            'refresh': rdata.refresh,
                            'retry': rdata.retry,
                            'expire': rdata.expire,
                            'minimum': rdata.minimum
                        })
                    elif record_type == 'SRV':
                        record_data.update({
                            'priority': rdata.priority,
                            'weight': rdata.weight,
                            'port': rdata.port,
                            'target': str(rdata.target).rstrip('.')
                        })
                    elif record_type == 'TXT':
                        # Handle TXT records properly
                        txt_string = ' '.join([part.decode() if isinstance(part, bytes) else str(part) for part in rdata.strings])
                        record_data['value'] = txt_string
                        
                        # Parse common TXT record types
                        if txt_string.startswith('v=spf1'):
                            record_data['spf_record'] = True
                        elif txt_string.startswith('v=DMARC1'):
                            record_data['dmarc_record'] = True
                        elif 'google-site-verification' in txt_string:
                            record_data['google_verification'] = True
                    elif record_type == 'CAA':
                        record_data.update({
                            'flags': rdata.flags,
                            'tag': rdata.tag.decode() if isinstance(rdata.tag, bytes) else str(rdata.tag),
                            'value': rdata.value.decode() if isinstance(rdata.value, bytes) else str(rdata.value)
                        })
                    
                    records.append(record_data)
                
                dns_data['records'][record_type] = records
                
            except dns.resolver.NoAnswer:
                dns_data['records'][record_type] = []
            except dns.resolver.NXDOMAIN:
                dns_data['errors'].append(f"Domain {domain} does not exist")
                break
            except Exception as e:
                dns_data['errors'].append(f"{record_type} query failed: {e}")
        
        return dns_data
    
    def _enumerate_subdomains(self, domain: str) -> Dict[str, Any]:
        """
        Enumerate subdomains using multiple techniques
        
        Args:
            domain: Domain to enumerate subdomains for
            
        Returns:
            Dict with discovered subdomains
        """
        subdomain_data = {
            'domain': domain,
            'discovered_subdomains': {},
            'enumeration_methods': [],
            'total_found': 0,
            'errors': []
        }
        
        discovered = set()
        
        # Method 1: Dictionary-based enumeration
        logger.debug(f"Starting dictionary enumeration for {domain}")
        dictionary_found = self._dictionary_subdomain_enum(domain)
        discovered.update(dictionary_found)
        if dictionary_found:
            subdomain_data['enumeration_methods'].append('dictionary')
        
        # Method 2: Certificate Transparency logs (simplified)
        try:
            ct_found = self._certificate_transparency_enum(domain)
            discovered.update(ct_found)
            if ct_found:
                subdomain_data['enumeration_methods'].append('certificate_transparency')
        except Exception as e:
            subdomain_data['errors'].append(f"CT enumeration failed: {e}")
        
        # Analyze discovered subdomains
        for subdomain in discovered:
            try:
                analysis = self._analyze_subdomain(subdomain)
                subdomain_data['discovered_subdomains'][subdomain] = analysis
            except Exception as e:
                subdomain_data['discovered_subdomains'][subdomain] = {'error': str(e)}
        
        subdomain_data['total_found'] = len(discovered)
        return subdomain_data
    
    def _dictionary_subdomain_enum(self, domain: str, max_workers: int = 20) -> Set[str]:
        """Dictionary-based subdomain enumeration"""
        discovered = set()
        
        def check_subdomain(prefix):
            subdomain = f"{prefix}.{domain}"
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2
                resolver.resolve(subdomain, 'A')
                return subdomain
            except:
                return None
        
        # Use threading for faster enumeration
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(check_subdomain, prefix) for prefix in self.subdomain_wordlist[:50]]  # Limit to avoid overwhelming
            
            for future in concurrent.futures.as_completed(futures, timeout=30):
                try:
                    result = future.result()
                    if result:
                        discovered.add(result)
                except:
                    pass
        
        return discovered
    
    def _certificate_transparency_enum(self, domain: str) -> Set[str]:
        """Certificate Transparency log enumeration (simplified)"""
        discovered = set()
        
        try:
            # Simple CT log query using crt.sh
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data[:20]:  # Limit results
                    common_name = entry.get('common_name', '')
                    if common_name and domain in common_name:
                        discovered.add(common_name)
                    
                    # Also check SANs if available
                    name_value = entry.get('name_value', '')
                    if name_value:
                        for name in name_value.split('\n'):
                            name = name.strip()
                            if name and domain in name and not name.startswith('*'):
                                discovered.add(name)
        except Exception as e:
            logger.debug(f"CT enumeration failed for {domain}: {e}")
        
        return discovered
    
    def _analyze_subdomain(self, subdomain: str) -> Dict[str, Any]:
        """Analyze individual subdomain"""
        analysis = {
            'subdomain': subdomain,
            'ip_addresses': [],
            'cname_records': [],
            'http_status': None,
            'server_info': {},
            'ssl_info': {}
        }
        
        try:
            # DNS resolution
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            
            # Get A records
            try:
                a_answers = resolver.resolve(subdomain, 'A')
                analysis['ip_addresses'] = [str(ip) for ip in a_answers]
            except:
                pass
            
            # Get CNAME records
            try:
                cname_answers = resolver.resolve(subdomain, 'CNAME')
                analysis['cname_records'] = [str(cname).rstrip('.') for cname in cname_answers]
            except:
                pass
            
            # Quick HTTP check
            if analysis['ip_addresses']:
                try:
                    response = requests.head(f"https://{subdomain}", timeout=5, verify=False)
                    analysis['http_status'] = response.status_code
                    analysis['server_info'] = dict(response.headers)
                except:
                    try:
                        response = requests.head(f"http://{subdomain}", timeout=5)
                        analysis['http_status'] = response.status_code
                        analysis['server_info'] = dict(response.headers)
                    except:
                        pass
        
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_http_comprehensive(self, domain: str) -> Dict[str, Any]:
        """
        Comprehensive HTTP analysis including raw headers
        
        Args:
            domain: Domain to analyze
            
        Returns:
            Dict with HTTP analysis results
        """
        http_data = {
            'domain': domain,
            'protocols': {},
            'raw_headers': {},
            'response_analysis': {},
            'security_headers': {},
            'performance_metrics': {},
            'cdn_detection': {},
            'errors': []
        }
        
        protocols = ['https', 'http']
        
        for protocol in protocols:
            url = f"{protocol}://{domain}"
            protocol_data = {
                'url': url,
                'accessible': False,
                'status_code': None,
                'headers': {},
                'raw_response': None,
                'redirect_chain': [],
                'timing': {},
                'ssl_info': {}
            }
            
            try:
                start_time = time.time()
                
                # Make request with detailed tracking
                session = requests.Session()
                response = session.get(
                    url,
                    headers=self.headers,
                    timeout=15,
                    allow_redirects=True,
                    verify=False if protocol == 'https' else True,
                    stream=False
                )
                
                end_time = time.time()
                
                protocol_data.update({
                    'accessible': True,
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'raw_response': response.text[:1000] if response.text else None,  # First 1KB
                    'redirect_chain': [r.url for r in response.history] + [response.url],
                    'timing': {
                        'total_time': end_time - start_time,
                        'url_final': response.url
                    }
                })
                
                # Extract raw headers for detailed analysis
                raw_headers_formatted = '\n'.join([f"{k}: {v}" for k, v in response.headers.items()])
                
                protocol_data['raw_headers'] = {
                    'formatted': raw_headers_formatted,
                    'count': len(response.headers)
                }
                
                # Security headers analysis
                security_headers = self._analyze_security_headers(response.headers)
                protocol_data['security_headers'] = security_headers
                
                # CDN detection from headers
                cdn_indicators = self._detect_cdn_from_headers(response.headers)
                protocol_data['cdn_detection'] = cdn_indicators
                
                # SSL analysis for HTTPS
                if protocol == 'https' and response.url.startswith('https'):
                    ssl_info = self._analyze_ssl_certificate(domain)
                    protocol_data['ssl_info'] = ssl_info
                
            except Exception as e:
                protocol_data['error'] = str(e)
                http_data['errors'].append(f"{protocol.upper()} analysis failed: {e}")
            
            http_data['protocols'][protocol] = protocol_data
        
        return http_data
    
    def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze security headers"""
        security_analysis = {
            'headers_present': [],
            'headers_missing': [],
            'security_score': 0,
            'recommendations': []
        }
        
        security_headers_check = {
            'Strict-Transport-Security': 'HSTS protection',
            'Content-Security-Policy': 'CSP protection',
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME type sniffing protection',
            'X-XSS-Protection': 'XSS protection',
            'Referrer-Policy': 'Referrer policy',
            'Permissions-Policy': 'Feature policy'
        }
        
        for header, description in security_headers_check.items():
            if any(h.lower() == header.lower() for h in headers.keys()):
                security_analysis['headers_present'].append({
                    'header': header,
                    'description': description,
                    'value': headers.get(header, '')
                })
                security_analysis['security_score'] += 10
            else:
                security_analysis['headers_missing'].append({
                    'header': header,
                    'description': description,
                    'recommendation': f"Add {header} header"
                })
        
        return security_analysis
    
    def _detect_cdn_from_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Detect CDN from HTTP headers"""
        cdn_indicators = {
            'detected_cdns': [],
            'header_indicators': [],
            'confidence': 0
        }
        
        cdn_patterns = {
            'Cloudflare': ['cloudflare', 'cf-ray', 'cf-cache-status'],
            'AWS CloudFront': ['cloudfront', 'x-amz-cf-', 'x-cache'],
            'Fastly': ['fastly', 'x-served-by'],
            'Akamai': ['akamai', 'akamai-', 'x-cache-key'],
            'MaxCDN': ['maxcdn', 'netdna'],
            'KeyCDN': ['keycdn'],
            'BunnyCDN': ['bunnycdn'],
            'jsDelivr': ['jsdelivr']
        }
        
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        for cdn, patterns in cdn_patterns.items():
            for pattern in patterns:
                for header_name, header_value in headers_lower.items():
                    if pattern in header_name or pattern in header_value:
                        if cdn not in cdn_indicators['detected_cdns']:
                            cdn_indicators['detected_cdns'].append(cdn)
                            cdn_indicators['header_indicators'].append({
                                'cdn': cdn,
                                'header': header_name,
                                'pattern': pattern,
                                'value': header_value
                            })
                            cdn_indicators['confidence'] += 20
        
        return cdn_indicators
    
    def _analyze_ssl_certificate(self, domain: str) -> Dict[str, Any]:
        """Analyze SSL certificate"""
        ssl_info = {
            'certificate_available': False,
            'issuer': None,
            'subject': None,
            'san_list': [],
            'expires': None,
            'protocol_versions': [],
            'cipher_suites': []
        }
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info.update({
                        'certificate_available': True,
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'san_list': cert.get('subjectAltName', []),
                        'expires': cert.get('notAfter'),
                        'protocol_version': ssock.version(),
                        'cipher': ssock.cipher()
                    })
        except Exception as e:
            ssl_info['error'] = str(e)
        
        return ssl_info
    
    def _detect_origin_servers(self, domain: str) -> Dict[str, Any]:
        """
        Attempt to detect origin servers behind CDN
        
        Args:
            domain: Domain to analyze
            
        Returns:
            Dict with origin server detection results
        """
        origin_data = {
            'domain': domain,
            'detection_methods': [],
            'potential_origins': [],
            'bypassed_cdn': False,
            'origin_ips': [],
            'errors': []
        }
        
        # Method 1: Check for origin IP in DNS history/subdomains
        try:
            origin_candidates = self._find_origin_candidates(domain)
            if origin_candidates:
                origin_data['potential_origins'].extend(origin_candidates)
                origin_data['detection_methods'].append('dns_analysis')
        except Exception as e:
            origin_data['errors'].append(f"DNS analysis failed: {e}")
        
        # Method 2: Common origin subdomain patterns
        try:
            origin_subdomains = self._check_origin_subdomains(domain)
            if origin_subdomains:
                origin_data['potential_origins'].extend(origin_subdomains)
                origin_data['detection_methods'].append('subdomain_analysis')
        except Exception as e:
            origin_data['errors'].append(f"Subdomain analysis failed: {e}")
        
        # Method 3: Header analysis for origin hints
        try:
            header_origins = self._analyze_headers_for_origin(domain)
            if header_origins:
                origin_data['potential_origins'].extend(header_origins)
                origin_data['detection_methods'].append('header_analysis')
        except Exception as e:
            origin_data['errors'].append(f"Header analysis failed: {e}")
        
        return origin_data
    
    def _find_origin_candidates(self, domain: str) -> List[Dict[str, Any]]:
        """Find potential origin server IPs"""
        candidates = []
        
        # Check A records for non-CDN IPs
        try:
            resolver = dns.resolver.Resolver()
            a_answers = resolver.resolve(domain, 'A')
            
            for ip in a_answers:
                ip_str = str(ip)
                # Simple heuristic: check if IP is not in common CDN ranges
                if not self._is_known_cdn_ip(ip_str):
                    candidates.append({
                        'ip': ip_str,
                        'type': 'direct_dns',
                        'confidence': 'medium'
                    })
        except:
            pass
        
        return candidates
    
    def _check_origin_subdomains(self, domain: str) -> List[Dict[str, Any]]:
        """Check common origin server subdomain patterns"""
        origin_subdomains = []
        origin_patterns = ['origin', 'direct', 'server', 'main', 'primary', 'backend']
        
        for pattern in origin_patterns:
            subdomain = f"{pattern}.{domain}"
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 3
                a_answers = resolver.resolve(subdomain, 'A')
                
                for ip in a_answers:
                    origin_subdomains.append({
                        'subdomain': subdomain,
                        'ip': str(ip),
                        'type': 'origin_subdomain',
                        'confidence': 'high'
                    })
            except:
                continue
        
        return origin_subdomains
    
    def _analyze_headers_for_origin(self, domain: str) -> List[Dict[str, Any]]:
        """Analyze headers for origin server hints"""
        origin_hints = []
        
        try:
            response = requests.get(f"https://{domain}", headers=self.headers, timeout=10, verify=False)
            
            # Check for common origin-revealing headers
            origin_headers = ['X-Origin-Server', 'X-Real-IP', 'X-Forwarded-For', 'X-Backend-Server']
            
            for header in origin_headers:
                if header in response.headers:
                    origin_hints.append({
                        'header': header,
                        'value': response.headers[header],
                        'type': 'header_hint',
                        'confidence': 'low'
                    })
        except:
            pass
        
        return origin_hints
    
    def _is_known_cdn_ip(self, ip: str) -> bool:
        """Check if IP belongs to known CDN ranges (simplified)"""
        # This is a simplified check - in reality, you'd want comprehensive IP ranges
        cdn_prefixes = [
            '104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.',  # Cloudflare
            '13.32.', '13.33.', '13.34.', '13.35.',  # AWS CloudFront
            '151.101.',  # Fastly
        ]
        
        return any(ip.startswith(prefix) for prefix in cdn_prefixes)
    
    def _map_infrastructure(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map the complete infrastructure based on all collected data
        
        Args:
            analysis_results: Complete analysis results
            
        Returns:
            Dict with infrastructure mapping
        """
        infrastructure = {
            'providers': {
                'dns': [],
                'cdn': [],
                'hosting': [],
                'ssl': []
            },
            'architecture': {
                'uses_cdn': False,
                'cdn_providers': [],
                'origin_accessible': False,
                'ssl_termination': 'unknown'
            },
            'security_posture': {
                'score': 0,
                'strengths': [],
                'weaknesses': []
            }
        }
        
        # Analyze DNS providers
        dns_records = analysis_results.get('dns_records', {})
        if 'nameservers' in dns_records:
            for ns in dns_records['nameservers']:
                provider = self._identify_provider_from_nameserver(ns)
                if provider:
                    infrastructure['providers']['dns'].append(provider)
        
        # Analyze CDN usage
        http_analysis = analysis_results.get('http_analysis', {})
        for protocol, data in http_analysis.get('protocols', {}).items():
            cdn_detection = data.get('cdn_detection', {})
            if cdn_detection.get('detected_cdns'):
                infrastructure['architecture']['uses_cdn'] = True
                infrastructure['architecture']['cdn_providers'].extend(cdn_detection['detected_cdns'])
                infrastructure['providers']['cdn'].extend(cdn_detection['detected_cdns'])
        
        # Security analysis
        for protocol, data in http_analysis.get('protocols', {}).items():
            security_headers = data.get('security_headers', {})
            if security_headers:
                infrastructure['security_posture']['score'] += security_headers.get('security_score', 0)
        
        return infrastructure
    
    def _identify_provider_from_nameserver(self, nameserver: str) -> Optional[str]:
        """Identify provider from nameserver domain"""
        ns_lower = nameserver.lower()
        
        providers = {
            'Cloudflare': ['cloudflare.com'],
            'AWS Route 53': ['awsdns', 'amazonaws.com'],
            'Google Cloud DNS': ['googledomains.com', 'google.com'],
            'Microsoft DNS': ['microsoft.com', 'azure.com'],
            'GoDaddy': ['godaddy.com', 'secureserver.net'],
            'Namecheap': ['namecheap.com', 'registrar-servers.com']
        }
        
        for provider, patterns in providers.items():
            if any(pattern in ns_lower for pattern in patterns):
                return provider
        
        return None

# Global instance
_comprehensive_analysis: Optional[ComprehensiveAnalysisIntegration] = None

def get_comprehensive_analysis() -> ComprehensiveAnalysisIntegration:
    """Get global comprehensive analysis instance"""
    global _comprehensive_analysis
    if _comprehensive_analysis is None:
        _comprehensive_analysis = ComprehensiveAnalysisIntegration()
    return _comprehensive_analysis
