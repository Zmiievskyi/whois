#!/usr/bin/env python3
"""
DNS Analysis for Provider Detection (Phase 2A)
Advanced DNS analysis including NS records, TTL patterns, and reverse DNS
"""
import re
import socket
import dns.resolver
import dns.reversename
import logging
from typing import Dict, List, Optional, Set
from ..config.settings import get_settings
from ..utils.cache import get_multi_cache


class DNSAnalyzer:
    """Advanced DNS analysis for provider detection"""
    
    def __init__(self):
        """Initialize DNS analyzer"""
        self.settings = get_settings()
        self.cache = get_multi_cache()
        self.logger = logging.getLogger(__name__)
        
        # Configure DNS resolver timeout
        try:
            if dns.resolver.default_resolver:
                dns.resolver.default_resolver.timeout = self.settings.dns_timeout
                dns.resolver.default_resolver.lifetime = self.settings.dns_timeout
        except Exception:
            # Fallback - create new resolver if default doesn't work
            pass
    
    def analyze_dns_chain(self, domain: str) -> List[Dict]:
        """
        Analyze complete DNS resolution chain
        
        Args:
            domain: Domain to analyze
            
        Returns:
            List of DNS chain steps with provider information
        """
        cache_key = f"dns_chain:{domain}"
        cached_result = self.cache.get('dns', cache_key)
        if cached_result:
            return cached_result
        
        chain = []
        current_domain = domain
        visited_domains = set()  # Prevent infinite loops
        max_depth = 10  # Safety limit
        
        try:
            for depth in range(max_depth):
                if current_domain in visited_domains:
                    self.logger.warning(f"DNS loop detected for {current_domain}")
                    break
                
                visited_domains.add(current_domain)
                
                # Try to resolve CNAME
                try:
                    cname_answers = dns.resolver.resolve(current_domain, 'CNAME')
                    if cname_answers:
                        cname = str(cname_answers[0]).rstrip('.')
                        provider = self.identify_provider_from_domain(cname)
                        role = self.determine_provider_role(provider, cname)
                        
                        chain.append({
                            'type': 'CNAME',
                            'domain': current_domain,
                            'cname': cname,
                            'provider': provider,
                            'role': role,
                            'step': depth + 1
                        })
                        
                        current_domain = cname
                        continue
                        
                except dns.resolver.NoAnswer:
                    pass
                except dns.resolver.NXDOMAIN:
                    self.logger.warning(f"Domain {current_domain} does not exist")
                    break
                
                # If no CNAME, resolve to IP
                try:
                    a_answers = dns.resolver.resolve(current_domain, 'A')
                    if a_answers:
                        ip = str(a_answers[0])
                        provider = self.identify_provider_from_ip(ip)
                        
                        chain.append({
                            'type': 'A',
                            'domain': current_domain,
                            'ip': ip,
                            'provider': provider,
                            'role': 'Origin',
                            'step': depth + 1
                        })
                        break
                        
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    self.logger.warning(f"No A record found for {current_domain}")
                    break
        
        except Exception as e:
            self.logger.error(f"DNS chain analysis failed for {domain}: {e}")
        
        # Cache result
        self.cache.set('dns', cache_key, chain)
        return chain
    
    def analyze_ns_records(self, domain: str) -> Dict:
        """
        Analyze NS records to identify DNS provider
        
        Args:
            domain: Domain to analyze
            
        Returns:
            Dictionary with DNS provider information
        """
        cache_key = f"ns_records:{domain}"
        cached_result = self.cache.get('dns', cache_key)
        if cached_result:
            return cached_result
        
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            ns_providers = []
            
            for ns in ns_records:
                ns_domain = str(ns).rstrip('.')
                dns_provider = self.identify_dns_provider(ns_domain)
                if dns_provider:
                    ns_providers.append({
                        'ns_server': ns_domain,
                        'provider': dns_provider,
                        'role': 'DNS'
                    })
            
            result = {
                'dns_providers': ns_providers,
                'dns_diversity': len(set(p['provider'] for p in ns_providers)),
                'all_ns_servers': [str(ns).rstrip('.') for ns in ns_records]
            }
            
            # Cache result
            self.cache.set('dns', cache_key, result)
            return result
            
        except Exception as e:
            self.logger.error(f"NS record analysis failed for {domain}: {e}")
            return {'error': str(e), 'dns_providers': [], 'dns_diversity': 0, 'all_ns_servers': []}

    def analyze_ttl_patterns(self, domain: str) -> Dict:
        """
        Analyze TTL values to detect migration patterns
        
        Args:
            domain: Domain to analyze
            
        Returns:
            Dictionary with TTL analysis results
        """
        cache_key = f"ttl_patterns:{domain}"
        cached_result = self.cache.get('dns', cache_key)
        if cached_result:
            return cached_result
        
        ttl_data = {}
        
        for record_type in ['A', 'CNAME', 'NS']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                ttl_value = answers.rrset.ttl
                ttl_data[record_type] = {
                    'ttl': ttl_value,
                    'migration_indicator': self._get_migration_indicator(ttl_value),
                    'description': self.get_ttl_description(ttl_value)
                }
            except Exception as e:
                ttl_data[record_type] = {'error': str(e)}
        
        # Cache result
        self.cache.set('dns', cache_key, ttl_data)
        return ttl_data

    def _get_migration_indicator(self, ttl: int) -> str:
        """Get migration indicator based on TTL value"""
        if ttl < 300:
            return 'high'
        elif ttl < 3600:
            return 'medium'
        else:
            return 'low'

    def get_ttl_description(self, ttl: int) -> str:
        """Get human-readable TTL description"""
        if ttl < 60:
            return f"Very low ({ttl}s) - Active migration possible"
        elif ttl < 300:
            return f"Low ({ttl}s) - Recent changes or testing"
        elif ttl < 3600:
            return f"Medium ({ttl//60}m) - Normal operation"
        elif ttl < 86400:
            return f"High ({ttl//3600}h) - Stable configuration"
        else:
            return f"Very high ({ttl//86400}d) - Long-term stable"

    def reverse_dns_lookup(self, ip: str) -> Optional[Dict]:
        """
        Perform reverse DNS lookup for additional context
        
        Args:
            ip: IP address for reverse lookup
            
        Returns:
            Dictionary with reverse DNS information or None
        """
        if not ip:
            return None
        
        cache_key = f"reverse_dns:{ip}"
        cached_result = self.cache.get('dns', cache_key)
        if cached_result:
            return cached_result
            
        try:
            reverse_domain = dns.reversename.from_address(ip)
            reverse_result = str(dns.resolver.resolve(reverse_domain, 'PTR')[0])
            
            # Extract provider from reverse DNS
            provider = self.identify_provider_from_domain(reverse_result.rstrip('.'))
            
            result = {
                'reverse_domain': reverse_result.rstrip('.'),
                'provider': provider,
                'ip': ip
            }
            
            # Cache result
            self.cache.set('dns', cache_key, result)
            return result
            
        except Exception as e:
            self.logger.debug(f"Reverse DNS lookup failed for {ip}: {e}")
            return None

    def identify_dns_provider(self, ns_domain: str) -> Optional[str]:
        """
        Intelligently identify DNS provider from NS domain patterns with fallback analysis
        
        Args:
            ns_domain: NS domain to analyze
            
        Returns:
            DNS provider name or None
        """
        if not ns_domain:
            return None
            
        ns_lower = ns_domain.lower()
        
        # First try known patterns
        provider = self._check_known_patterns(ns_lower)
        if provider:
            return provider
        
        # If no pattern match, try intelligent analysis
        return self._analyze_unknown_dns_provider(ns_domain)
    
    def _check_known_patterns(self, ns_lower: str) -> Optional[str]:
        """Check against known DNS provider patterns"""
        dns_patterns = {
            'AWS Route53': [
                r'awsdns-.*\.net$', r'awsdns-.*\.org$', r'awsdns-.*\.com$', r'awsdns-.*\.co\.uk$'
            ],
            'Cloudflare': [
                r'.*\.ns\.cloudflare\.com$', r'.*\.cloudflare\.com$'
            ],
            'Google Cloud DNS': [
                r'ns-cloud-.*\.googledomains\.com$', r'.*\.google\.com$'
            ],
            'Azure DNS': [
                r'.*\.ns\.azure-dns\..*$', r'.*\.azure-dns\..*$'
            ],
            'Namecheap': [
                r'dns.*\.registrar-servers\.com$', r'.*\.registrar-servers\.com$'
            ],
            'GoDaddy': [
                r'ns.*\.domaincontrol\.com$', r'.*\.domaincontrol\.com$'
            ],
            'DigitalOcean': [
                r'ns.*\.digitalocean\.com$', r'.*\.digitalocean\.com$'
            ],
            'Gcore': [
                r'.*\.gcorelabs\.net$', r'.*\.g-core\.net$'
            ],
            'OVH': [
                r'.*\.ovh\.net$', r'.*\.ovh\.com$'
            ],
            'Hetzner': [
                r'.*\.hetzner\.com$', r'.*\.hetzner\.de$'
            ],
            'Linode': [
                r'.*\.linode\.com$', r'.*\.members\.linode\.com$'
            ],
            'Vultr': [
                r'.*\.vultr\.com$'
            ]
        }
        
        for provider, patterns in dns_patterns.items():
            for pattern in patterns:
                if re.search(pattern, ns_lower):
                    return provider
        
        return None
    
    def _analyze_unknown_dns_provider(self, ns_domain: str) -> Optional[str]:
        """
        Intelligent analysis for unknown DNS providers using WHOIS and domain analysis
        
        Args:
            ns_domain: NS domain to analyze
            
        Returns:
            DNS provider name or None
        """
        # Check cache first
        cache_key = f"unknown_dns_provider:{ns_domain}"
        cached_result = self.cache.get('dns', cache_key)
        if cached_result:
            self.logger.debug(f"Using cached DNS provider result for {ns_domain}: {cached_result}")
            return cached_result
        
        provider = None
        
        try:
            # Method 1: Extract domain root and analyze
            domain_parts = ns_domain.split('.')
            if len(domain_parts) >= 2:
                root_domain = '.'.join(domain_parts[-2:])  # Get domain.tld
                provider = self._analyze_domain_whois(root_domain)
            
            # Method 2: If no result, try IP-based analysis
            if not provider:
                provider = self._analyze_ns_ip(ns_domain)
            
            # Method 3: Extract company name from domain patterns
            if not provider:
                provider = self._extract_company_from_domain(ns_domain)
            
            # Cache the result (even if None) for 24 hours
            self.cache.set('dns', cache_key, provider, ttl=86400)
            
            if provider:
                self.logger.info(f"🔍 Intelligent DNS analysis: {ns_domain} -> {provider}")
                # Optionally: add to learning dataset
                self._add_to_learning_dataset(ns_domain, provider)
            else:
                self.logger.debug(f"Could not determine provider for unknown NS: {ns_domain}")
                
        except Exception as e:
            self.logger.error(f"Error in intelligent DNS analysis for {ns_domain}: {e}")
        
        return provider
    
    def _analyze_domain_whois(self, domain: str) -> Optional[str]:
        """Analyze domain WHOIS to find DNS provider"""
        try:
            import whois
            whois_data = whois.whois(domain)
            
            # Extract organization/registrant information
            org_fields = ['org', 'organization', 'registrant_organization', 'registrant']
            for field in org_fields:
                if hasattr(whois_data, field):
                    value = getattr(whois_data, field)
                    if value and isinstance(value, str):
                        # Clean and normalize the organization name
                        provider = self._normalize_provider_name(value)
                        if provider:
                            return provider
            
        except Exception as e:
            self.logger.debug(f"WHOIS analysis failed for {domain}: {e}")
        
        return None
    
    def _analyze_ns_ip(self, ns_domain: str) -> Optional[str]:
        """Analyze NS server IP to determine provider"""
        try:
            import socket
            ip = socket.gethostbyname(ns_domain)
            
            # Try to get provider from IP using existing methods
            if hasattr(self, 'ip_manager') and hasattr(self.ip_manager, 'get_provider_by_ip'):
                provider = self.ip_manager.get_provider_by_ip(ip)
                if provider:
                    return provider
            
            # Try reverse DNS lookup
            reverse_info = self.reverse_dns_lookup(ip)
            if reverse_info and reverse_info.get('provider'):
                return reverse_info['provider']
                
        except Exception as e:
            self.logger.debug(f"IP analysis failed for {ns_domain}: {e}")
        
        return None
    
    def _extract_company_from_domain(self, ns_domain: str) -> Optional[str]:
        """Extract company name from domain patterns"""
        domain_lower = ns_domain.lower()
        
        # Common patterns in DNS server names
        company_patterns = {
            'dnsimple': 'DNSimple',
            'easydns': 'EasyDNS', 
            'dns.he.net': 'Hurricane Electric',
            'zoneedit': 'ZoneEdit',
            'everydns': 'EveryDNS',
            'freedns': 'FreeDNS',
            'afraid.org': 'FreeDNS',
            'registrar-servers': 'Namecheap',
            'domaincontrol': 'GoDaddy',
            'parkingcrew': 'ParkingCrew',
            'sedoparking': 'Sedo',
            'idp365': 'Safenames'  # Our arsenal.co.uk case
        }
        
        for pattern, provider in company_patterns.items():
            if pattern in domain_lower:
                return provider
        
        return None
    
    def _normalize_provider_name(self, org_name: str) -> Optional[str]:
        """Normalize organization name to standard provider name"""
        if not org_name:
            return None
        
        org_lower = org_name.lower().strip()
        
        # Mapping of organization names to standardized provider names
        name_mappings = {
            'safenames ltd': 'Safenames',
            'safenames limited': 'Safenames',
            'amazon technologies': 'AWS',
            'amazon.com': 'AWS',
            'cloudflare': 'Cloudflare',
            'google llc': 'Google',
            'google inc': 'Google',
            'microsoft corporation': 'Microsoft',
            'digitalocean': 'DigitalOcean',
            'ovh sas': 'OVH',
            'hetzner online gmbh': 'Hetzner',
            'linode': 'Linode',
            'vultr holdings': 'Vultr'
        }
        
        for pattern, provider in name_mappings.items():
            if pattern in org_lower:
                return provider
        
        # If no mapping, try to extract meaningful name
        # Remove common suffixes
        clean_name = org_lower
        for suffix in [' ltd', ' limited', ' llc', ' inc', ' corporation', ' corp', ' gmbh', ' sas']:
            clean_name = clean_name.replace(suffix, '')
        
        # Capitalize first letter of each word
        if clean_name and len(clean_name) > 2:
            return ' '.join(word.capitalize() for word in clean_name.split())
        
        return None
    
    def _add_to_learning_dataset(self, ns_domain: str, provider: str):
        """Add discovered pattern to learning dataset for future improvements"""
        try:
            # This could be expanded to maintain a learning dataset
            # For now, just log the discovery
            self.logger.info(f"📚 Learning: {ns_domain} -> {provider}")
            
            # Future enhancement: save to a file or database for pattern analysis
            # This could help automatically generate new patterns
            
        except Exception as e:
            self.logger.error(f"Error adding to learning dataset: {e}")

    def identify_provider_from_domain(self, domain: str) -> Optional[str]:
        """
        Identify provider from domain name patterns
        
        Args:
            domain: Domain to analyze
            
        Returns:
            Provider name or None
        """
        if not domain:
            return None
            
        domain_lower = domain.lower()
        
        # Enhanced domain patterns
        domain_patterns = {
            'AWS': [
                'amazonaws.com', 'awsglobalconfig.com', 'awsdns-', 'cloudfront.net',
                'elb.amazonaws.com', 's3.amazonaws.com', 'elasticbeanstalk.com'
            ],
            'Cloudflare': [
                'cloudflare.com', 'cloudflare.net', 'cloudflaressl.com', 'cf-ips'
            ],
            'Google': [
                'google.com', 'googleapis.com', 'googleusercontent.com', 'goog.',
                'googlevideo.com', 'googleusercontent.com', 'appspot.com'
            ],
            'Microsoft': [
                'microsoft.com', 'azure.com', 'outlook.com', 'office.com',
                'sharepoint.com', 'windows.net', 'azurewebsites.net'
            ],
            'Fastly': [
                'fastly.com', 'fastlylb.net', 'fastly-edge.com'
            ],
            'Akamai': [
                'akamai.com', 'akamaitechnologies.com', 'akamaihd.net',
                'akamaistream.net', 'akamaized.net'
            ],
            'GitHub': [
                'github.com', 'githubusercontent.com', 'githubassets.com'
            ],
            'Netlify': [
                'netlify.com', 'netlify.app'
            ],
            'Vercel': [
                'vercel.com', 'vercel.app'
            ]
        }
        
        for provider, patterns in domain_patterns.items():
            for pattern in patterns:
                if pattern in domain_lower:
                    return provider
        
        return None

    def identify_provider_from_ip(self, ip: str) -> Optional[str]:
        """
        Identify provider from IP address (using IP range manager)
        
        Args:
            ip: IP address to analyze
            
        Returns:
            Provider name or None
        """
        # This will be implemented when we have IP range manager integrated
        # For now, return None to avoid circular imports
        return None

    def determine_provider_role(self, provider: Optional[str], domain: str) -> str:
        """
        Determine the role of a provider based on context
        
        Args:
            provider: Provider name
            domain: Domain context
            
        Returns:
            Provider role (CDN, Origin, WAF, etc.)
        """
        if not provider:
            return 'Unknown'
        
        # CDN providers
        cdn_providers = {
            'Cloudflare', 'AWS', 'Fastly', 'Akamai', 'Google', 
            'Microsoft', 'MaxCDN', 'KeyCDN', 'StackPath'
        }
        
        # Check domain patterns for role hints
        domain_lower = domain.lower()
        
        if provider in cdn_providers:
            # Check if it's likely a CDN based on subdomain patterns
            if any(pattern in domain_lower for pattern in ['cdn', 'static', 'assets', 'media']):
                return 'CDN'
            elif 'cloudfront' in domain_lower or 'fastly' in domain_lower:
                return 'CDN'
            else:
                return 'Origin'
        
        # WAF providers (often same as CDN but different context)
        if provider in ['Cloudflare', 'Akamai'] and 'waf' in domain_lower:
            return 'WAF'
        
        # Load balancer patterns
        if 'elb' in domain_lower or 'lb' in domain_lower:
            return 'Load Balancer'
        
        return 'Origin'

    def get_comprehensive_dns_analysis(self, domain: str) -> Dict:
        """
        Get comprehensive DNS analysis combining all methods
        
        Args:
            domain: Domain to analyze
            
        Returns:
            Complete DNS analysis results
        """
        result = {
            'domain': domain,
            'dns_chain': self.analyze_dns_chain(domain),
            'ns_analysis': self.analyze_ns_records(domain),
            'ttl_analysis': self.analyze_ttl_patterns(domain),
            'reverse_dns': None
        }
        
        # Get IP from DNS chain for reverse lookup
        for step in result['dns_chain']:
            if step.get('type') == 'A' and step.get('ip'):
                result['reverse_dns'] = self.reverse_dns_lookup(step['ip'])
                break
        
        return result


# Global DNS analyzer instance
_global_dns_analyzer: Optional[DNSAnalyzer] = None


def get_dns_analyzer() -> DNSAnalyzer:
    """Get global DNS analyzer instance"""
    global _global_dns_analyzer
    if _global_dns_analyzer is None:
        _global_dns_analyzer = DNSAnalyzer()
    return _global_dns_analyzer


# Example usage and testing
if __name__ == "__main__":
    # Test DNS analyzer
    analyzer = DNSAnalyzer()
    
    test_domains = ["github.com", "cloudflare.com", "google.com"]
    
    print("🔍 Testing DNS Analysis:")
    for domain in test_domains:
        print(f"\n📋 Analyzing {domain}:")
        
        # Test NS records
        ns_result = analyzer.analyze_ns_records(domain)
        print(f"  DNS Providers: {len(ns_result.get('dns_providers', []))}")
        
        # Test TTL analysis
        ttl_result = analyzer.analyze_ttl_patterns(domain)
        for record_type, ttl_info in ttl_result.items():
            if 'ttl' in ttl_info:
                print(f"  {record_type} TTL: {ttl_info['description']}")
        
        # Test DNS chain
        chain = analyzer.analyze_dns_chain(domain)
        print(f"  DNS Chain steps: {len(chain)}")
        for step in chain:
            if step['type'] == 'CNAME':
                print(f"    {step['domain']} → {step['cname']} ({step['provider']})")
            else:
                print(f"    {step['domain']} → {step['ip']} ({step['provider']})")
    
    print("\n✅ DNS analysis testing completed!")
