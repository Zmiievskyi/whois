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
import subprocess
import shutil
from pathlib import Path
import concurrent.futures
from typing import Dict, List, Optional, Any, Set, Tuple
from urllib.parse import urlparse
from .base import HTTPIntegration
from ..config.settings import get_settings

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
        self.settings = get_settings()
        
        # DNS record types to query
        self.dns_record_types = [
            'A', 'AAAA', 'CNAME', 'NS', 'MX', 'TXT', 'SOA', 'PTR',
            'CAA', 'SRV', 'HINFO', 'NAPTR'
        ]
        self.subdomain_wordlist = self._load_subdomain_wordlist()
        self.dictionary_limit = max(0, self.settings.subdomain_dictionary_limit)
        self.analysis_limit = max(10, self.settings.subdomain_analysis_limit)
        self.max_concurrency = max(5, self.settings.subdomain_max_concurrency)
        self.enable_ct_enumeration = self.settings.enable_ct_enumeration
        self.ct_page_limit = max(1, self.settings.ct_log_page_limit)
        self.enable_passive_dns = self.settings.enable_passive_dns_enumeration
        self.enable_subfinder = self.settings.enable_subfinder_enumeration
        self.subfinder_timeout = max(30, self.settings.subfinder_timeout)
        self.subfinder_path = self.settings.subfinder_binary_path
        self.enable_detailed_analysis = self.settings.enable_subdomain_detailed_analysis
        
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
    
    def _load_subdomain_wordlist(self) -> List[str]:
        """
        Load subdomain wordlist from configured path or default dataset
        """
        candidates: List[str] = []
        
        # Helper to read wordlist file
        def _read_wordlist(path: Path) -> List[str]:
            try:
                if path.exists() and path.is_file():
                    return [
                        line.strip()
                        for line in path.read_text(encoding="utf-8").splitlines()
                        if line.strip() and not line.startswith("#")
                    ]
            except Exception as exc:
                logger.warning(f"Failed to read subdomain wordlist {path}: {exc}")
            return []
        
        # 1. User-specified path
        if self.settings.subdomain_wordlist_path:
            custom_path = Path(self.settings.subdomain_wordlist_path).expanduser()
            candidates = _read_wordlist(custom_path)
            if candidates:
                logger.info(f"Loaded {len(candidates)} subdomain prefixes from {custom_path}")
        
        # 2. Project default dataset
        if not candidates:
            default_path = Path(__file__).resolve().parent.parent / "data" / "common_subdomains.txt"
            candidates = _read_wordlist(default_path)
            if candidates:
                logger.info(f"Loaded {len(candidates)} subdomain prefixes from bundled dataset")
        
        # 3. Fallback minimal list
        if not candidates:
            candidates = [
                'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 'dev', 'staging',
                'test', 'admin', 'api', 'blog', 'shop', 'support', 'm', 'beta', 'app', 'cdn',
                'assets', 'static', 'media', 'images', 'img', 'portal', 'login', 'auth',
                'dashboard', 'panel', 'control', 'manage', 'origin', 'direct', 'server',
                'db', 'cache'
            ]
            logger.info("Using fallback subdomain prefix list (minimal set)")
        
        # Deduplicate while preserving order
        seen = set()
        deduped: List[str] = []
        for item in candidates:
            if item not in seen:
                deduped.append(item)
                seen.add(item)
        
        return deduped
    
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
                        results['subdomains'] = future.result(timeout=180)  # Increased to 3 minutes for subdomain enumeration
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
            'method_summary': [],
            'total_found': 0,
            'errors': []
        }
        
        discovered = set()
        method_summary = []

        # Method 1: Dictionary-based enumeration (disabled by default for performance)
        # Only run if domain resolves to avoid DNS timeout issues
        try:
            import socket
            socket.gethostbyname(domain)
            domain_resolves = True
        except:
            domain_resolves = False

        if domain_resolves and self.dictionary_limit > 0:
            logger.debug(f"Starting dictionary enumeration for {domain}")
            dictionary_found = self._dictionary_subdomain_enum(domain)
            discovered.update(dictionary_found)
            if dictionary_found:
                subdomain_data['enumeration_methods'].append('dictionary')
                method_summary.append({'method': 'dictionary', 'count': len(dictionary_found)})
        else:
            logger.debug(f"Skipping dictionary enumeration for {domain} (domain does not resolve or limit=0)")
        
        # Method 2: Passive DNS sources
        passive_found = self._passive_dns_enum(domain)
        discovered.update(passive_found)
        if passive_found:
            subdomain_data['enumeration_methods'].append('passive_dns')
            method_summary.append({'method': 'passive_dns', 'count': len(passive_found)})
        
        # Method 3: Certificate Transparency logs
        if self.enable_ct_enumeration:
            try:
                ct_found = self._certificate_transparency_enum(domain)
                discovered.update(ct_found)
                if ct_found:
                    subdomain_data['enumeration_methods'].append('certificate_transparency')
                    method_summary.append({'method': 'certificate_transparency', 'count': len(ct_found)})
            except Exception as e:
                subdomain_data['errors'].append(f"CT enumeration failed: {e}")
        
        # Method 4: External tools (subfinder)
        subfinder_found = self._subfinder_enum(domain)
        discovered.update(subfinder_found)
        if subfinder_found:
            subdomain_data['enumeration_methods'].append('subfinder')
            method_summary.append({'method': 'subfinder', 'count': len(subfinder_found)})
        
        # Normalize and sort results
        normalized = {
            sub.lower().strip('.')
            for sub in discovered
            if sub and sub != domain and sub.endswith(domain)
        }

        subdomain_data['total_found'] = len(normalized)
        subdomain_data['method_summary'] = method_summary

        # Save full list of all subdomain names (for JSON/CSV export)
        subdomain_data['all_subdomains'] = sorted(list(normalized))

        if not normalized:
            return subdomain_data

        # Detailed analysis (DNS + HTTP check for each subdomain)
        if self.enable_detailed_analysis and len(normalized) > 0:
            analysis_candidates = sorted(normalized)
            if len(analysis_candidates) > self.analysis_limit:
                subdomain_data['analysis_truncated'] = len(analysis_candidates) - self.analysis_limit
                analysis_candidates = analysis_candidates[:self.analysis_limit]

            logger.info(f"Running detailed analysis for {len(analysis_candidates)} subdomains (this may take a while)")

            # Analyze discovered subdomains
            for subdomain in analysis_candidates:
                # Skip wildcard artifacts
                if subdomain.startswith("*."):
                    continue
                try:
                    analysis = self._analyze_subdomain(subdomain)
                    subdomain_data['discovered_subdomains'][subdomain] = analysis
                except Exception as e:
                    subdomain_data['discovered_subdomains'][subdomain] = {'error': str(e)}
        else:
            logger.info(f"Detailed subdomain analysis disabled (found {len(normalized)} subdomains). Enable with ENABLE_SUBDOMAIN_DETAILED_ANALYSIS=true")
            subdomain_data['discovered_subdomains'] = {}

        subdomain_data['total_found'] = len(normalized)
        return subdomain_data
    
    def _dictionary_subdomain_enum(self, domain: str) -> Set[str]:
        """Dictionary-based subdomain enumeration"""
        if not self.subdomain_wordlist:
            return set()
        
        prefixes = self.subdomain_wordlist
        if self.dictionary_limit:
            prefixes = prefixes[: self.dictionary_limit]
        
        prefixes = [prefix.strip() for prefix in prefixes if prefix and prefix.strip()]
        if not prefixes:
            return set()
        
        discovered: Set[str] = set()
        max_workers = min(max(len(prefixes), 1), self.max_concurrency)
        
        def check_subdomain(prefix: str) -> Optional[str]:
            subdomain = f"{prefix}.{domain}".lower()
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2
                resolver.lifetime = 4
                
                try:
                    resolver.resolve(subdomain, 'A')
                    return subdomain
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    # Try CNAME as fallback
                    resolver.resolve(subdomain, 'CNAME')
                    return subdomain
            except (dns.exception.DNSException, socket.gaierror, TimeoutError):
                return None
            except Exception:
                return None
        
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                for result in executor.map(check_subdomain, prefixes, chunksize=5):
                    if result:
                        discovered.add(result)
        except Exception as exc:
            logger.debug(f"Dictionary enumeration error for {domain}: {exc}")
        
        return discovered
    
    def _passive_dns_enum(self, domain: str) -> Set[str]:
        """Passive DNS based enumeration using free community sources"""
        if not self.enable_passive_dns:
            return set()
        
        discovered: Set[str] = set()
        
        # Source 1: hackertarget
        try:
            response = requests.get(
                "https://api.hackertarget.com/hostsearch/",
                params={'q': domain},
                timeout=15
            )
            if response.status_code == 200 and 'error' not in response.text.lower():
                for line in response.text.splitlines():
                    parts = line.split(',')
                    if parts:
                        host = parts[0].strip().lower()
                        if host.endswith(domain):
                            discovered.add(host)
            elif response.status_code == 429:
                logger.debug("hackertarget rate limit reached")
        except Exception as exc:
            logger.debug(f"Hackertarget passive DNS failed for {domain}: {exc}")
        
        # Source 2: dns.bufferover.run
        try:
            response = requests.get(
                "https://dns.bufferover.run/dns",
                params={'q': f'.{domain}'},
                timeout=15
            )
            if response.status_code == 200:
                data = response.json()
                for key in ('FDNS_A', 'RDNS'):
                    for entry in data.get(key, []) or []:
                        # Format is "subdomain,IP"
                        host = entry.split(',')[0].strip().lower()
                        if host and host.endswith(domain):
                            discovered.add(host)
        except Exception as exc:
            logger.debug(f"bufferover passive DNS failed for {domain}: {exc}")
        
        return discovered
    
    def _subfinder_enum(self, domain: str) -> Set[str]:
        """Integrate with subfinder if available (optional)"""
        if not self.enable_subfinder:
            return set()
        
        binary = self.subfinder_path or shutil.which("subfinder")
        if not binary:
            logger.debug("Subfinder enumeration requested but binary not found")
            return set()
        
        cmd = [
            binary,
            "-d", domain,
            "-silent",
            "-timeout", str(max(10, int(self.subfinder_timeout / 2))),
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.subfinder_timeout
            )
            if result.returncode not in (0, 1):
                logger.debug(f"Subfinder exited with code {result.returncode}: {result.stderr.strip()}")
                return set()
            
            hosts = {
                line.strip().lower()
                for line in result.stdout.splitlines()
                if line.strip().lower().endswith(domain)
            }
            return hosts
        except FileNotFoundError:
            logger.debug("Subfinder binary not found during execution")
        except subprocess.TimeoutExpired:
            logger.debug("Subfinder execution timed out")
        except Exception as exc:
            logger.debug(f"Subfinder enumeration failed: {exc}")
        
        return set()
    
    def _certificate_transparency_enum(self, domain: str) -> Set[str]:
        """Certificate Transparency log enumeration with pagination"""
        discovered: Set[str] = set()
        page_size = 100
        throttle_seconds = 1.0
        seen_entries: Set[str] = set()
        
        for page in range(self.ct_page_limit):
            offset = page * page_size
            url = f"https://crt.sh/?q=%25.{domain}&output=json&offset={offset}"
            try:
                response = requests.get(url, timeout=15)
            except Exception as exc:
                logger.debug(f"CT query error for {domain} (offset {offset}): {exc}")
                break
            
            if response.status_code != 200:
                logger.debug(f"CT query returned status {response.status_code} for {domain}")
                break
            
            try:
                data = response.json()
            except ValueError:
                # crt.sh may return HTML when throttled
                logger.debug(f"CT query returned non-JSON payload for {domain}")
                break
            
            if not data:
                break
            
            for entry in data:
                entry_id = str(entry.get('id'))
                if entry_id in seen_entries:
                    continue
                seen_entries.add(entry_id)
                
                common_name = entry.get('common_name', '')
                if common_name and domain in common_name and not common_name.startswith('*.'):
                    discovered.add(common_name.strip().lower())
                
                name_value = entry.get('name_value', '')
                if name_value:
                    for name in name_value.split('\n'):
                        clean = name.strip().lower()
                        if clean and domain in clean and not clean.startswith('*.'):
                            discovered.add(clean)
            
            # Respect crt.sh fair use
            time.sleep(throttle_seconds)
        
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
                    response = requests.head(
                        f"https://{subdomain}",
                        timeout=5,
                        verify=False,
                        headers=self.headers
                    )
                    analysis['http_status'] = response.status_code
                    analysis['server_info'] = dict(response.headers)
                except:
                    try:
                        response = requests.head(
                            f"http://{subdomain}",
                            timeout=5,
                            headers=self.headers
                        )
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
