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
        Identify DNS provider from NS domain patterns
        
        Args:
            ns_domain: NS domain to analyze
            
        Returns:
            DNS provider name or None
        """
        if not ns_domain:
            return None
            
        ns_lower = ns_domain.lower()
        
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
