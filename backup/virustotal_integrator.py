#!/usr/bin/env python3
"""
VirusTotal API integration for enhanced provider detection
Phase 2B implementation with rate limiting and caching
"""
import time
import json
import logging
import os
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import vt
from urllib.parse import urlparse

class RateLimiter:
    """Rate limiter for VirusTotal API calls"""
    
    def __init__(self, max_calls: int = 4, time_window: int = 60):
        """
        Initialize rate limiter
        
        Args:
            max_calls: Maximum calls per time window (4 for public API)
            time_window: Time window in seconds (60 for per-minute limit)
        """
        self.max_calls = max_calls
        self.time_window = time_window
        self.calls = []
        
    def wait_if_needed(self):
        """Wait if rate limit would be exceeded"""
        now = time.time()
        
        # Remove calls outside time window
        self.calls = [call_time for call_time in self.calls 
                     if now - call_time < self.time_window]
        
        if len(self.calls) >= self.max_calls:
            sleep_time = self.time_window - (now - self.calls[0]) + 1
            if sleep_time > 0:
                logging.info(f"Rate limit reached, sleeping for {sleep_time:.1f}s")
                time.sleep(sleep_time)
        
        self.calls.append(now)

class VirusTotalCache:
    """Simple in-memory cache for VirusTotal responses"""
    
    def __init__(self, cache_ttl: int = 3600):  # 1 hour cache
        self.cache = {}
        self.cache_ttl = cache_ttl
        
    def get(self, key: str) -> Optional[Dict]:
        """Get cached response if still valid"""
        if key in self.cache:
            cached_data, timestamp = self.cache[key]
            if time.time() - timestamp < self.cache_ttl:
                return cached_data
            else:
                # Remove expired entry
                del self.cache[key]
        return None
        
    def set(self, key: str, data: Dict):
        """Cache response with timestamp"""
        self.cache[key] = (data, time.time())
        
    def clear_expired(self):
        """Remove expired cache entries"""
        now = time.time()
        expired_keys = [
            key for key, (_, timestamp) in self.cache.items()
            if now - timestamp >= self.cache_ttl
        ]
        for key in expired_keys:
            del self.cache[key]

class VirusTotalIntegrator:
    """VirusTotal API integration for enhanced provider detection"""
    
    def __init__(self, api_key: Optional[str] = None, is_premium: bool = False):
        """
        Initialize VirusTotal integrator
        
        Args:
            api_key: VirusTotal API key (can be None for testing)
            is_premium: Whether using premium API features
        """
        self.api_key = api_key or os.getenv('VT_API_KEY')
        self.is_premium = is_premium
        self.enabled = bool(self.api_key)
        
        # Rate limiting (4 req/min for public API)
        self.rate_limiter = RateLimiter(4, 60) if not is_premium else RateLimiter(300, 60)
        
        # Caching
        self.cache = VirusTotalCache()
        
        # Initialize client if API key available
        self.client = None
        if self.enabled:
            try:
                self.client = vt.Client(self.api_key)
                logging.info("VirusTotal client initialized successfully")
            except Exception as e:
                logging.error(f"Failed to initialize VirusTotal client: {e}")
                self.enabled = False
        
        # Provider patterns for domain analysis
        self.provider_domain_patterns = {
            'Cloudflare': [
                r'\.cloudflare\.', r'\.cf-', r'cloudflare-dns', r'1\.1\.1\.1'
            ],
            'AWS': [
                r'\.aws\.', r'\.amazon\.', r'\.awsglobalconfig\.', r'\.awsdns-',
                r'cloudfront', r'elasticloadbalancing', r's3\.amazonaws'
            ],
            'Google': [
                r'\.google\.', r'\.googleapis\.', r'\.googleusercontent\.', 
                r'\.goog$', r'\.googlevideo\.', r'\.googleusercontent\.'
            ],
            'Microsoft': [
                r'\.microsoft\.', r'\.azure\.', r'\.outlook\.', r'\.office\.', 
                r'\.sharepoint\.', r'\.windows\.', r'azurewebsites'
            ],
            'Fastly': [
                r'\.fastly\.', r'\.fastlylb\.', r'\.fastly-edge\.'
            ],
            'Akamai': [
                r'\.akamai\.', r'\.akamaitechnologies\.', r'\.akamaihd\.', 
                r'\.akamaistream\.', r'\.akamaized\.'
            ]
        }
    
    def is_enabled(self) -> bool:
        """Check if VirusTotal integration is enabled"""
        return self.enabled
    
    def analyze_domain_comprehensive(self, domain: str) -> Dict:
        """
        Comprehensive domain analysis using VirusTotal data
        
        Args:
            domain: Domain to analyze
            
        Returns:
            Dictionary with analysis results
        """
        if not self.enabled:
            return {
                'error': 'VirusTotal integration not available',
                'providers': {'origin': None, 'cdn': [], 'waf': [], 'dns_provider': None},
                'confidence_score': 0
            }
        
        # Check cache first
        cache_key = f"domain:{domain}"
        cached_result = self.cache.get(cache_key)
        if cached_result:
            logging.info(f"Using cached VirusTotal data for {domain}")
            return cached_result
        
        try:
            # Rate limiting
            self.rate_limiter.wait_if_needed()
            
            # Get domain report
            domain_data = self.get_domain_report(domain)
            
            # Analyze DNS resolutions  
            resolutions = self.get_domain_resolutions(domain) if self.is_premium else []
            
            # Extract provider information
            result = {
                'domain': domain,
                'providers': self.extract_multi_layer_providers(domain_data, resolutions),
                'dns_chain': self.analyze_vt_dns_chain(domain_data),
                'confidence_score': self.calculate_confidence_score(domain_data, resolutions),
                'last_analysis_stats': self.get_analysis_stats(domain_data),
                'reputation': self.get_reputation_score(domain_data)
            }
            
            # Cache result
            self.cache.set(cache_key, result)
            
            return result
            
        except Exception as e:
            logging.error(f"VirusTotal analysis failed for {domain}: {e}")
            return {
                'error': str(e),
                'providers': {'origin': None, 'cdn': [], 'waf': [], 'dns_provider': None},
                'confidence_score': 0
            }
    
    def get_domain_report(self, domain: str) -> Dict:
        """Get domain report from VirusTotal"""
        try:
            with self.client as client:
                domain_obj = client.get_object(f"/domains/{domain}")
                return domain_obj.to_dict()
        except vt.APIError as e:
            if e.code == "NotFoundError":
                return {}
            raise
    
    def get_domain_resolutions(self, domain: str) -> List[Dict]:
        """Get domain resolutions (Premium feature)"""
        if not self.is_premium:
            return []
            
        try:
            with self.client as client:
                resolutions = []
                for resolution in client.iterator(f"/domains/{domain}/resolutions", limit=10):
                    resolutions.append(resolution.to_dict())
                return resolutions
        except Exception as e:
            logging.warning(f"Failed to get resolutions for {domain}: {e}")
            return []
    
    def analyze_vt_dns_chain(self, domain_data: Dict) -> List[Dict]:
        """Analyze DNS chain from VirusTotal data"""
        dns_chain = []
        
        if not domain_data or 'attributes' not in domain_data:
            return dns_chain
        
        attributes = domain_data['attributes']
        last_dns_records = attributes.get('last_dns_records', [])
        
        for record in last_dns_records:
            record_type = record.get('type', '')
            value = record.get('value', '')
            
            if record_type == 'CNAME':
                provider = self.identify_provider_from_domain(value)
                dns_chain.append({
                    'type': 'CNAME',
                    'domain': domain_data.get('id', ''),
                    'cname': value,
                    'provider': provider,
                    'role': 'CDN' if provider else 'Unknown'
                })
            elif record_type == 'A':
                provider = self.identify_provider_from_ip(value)
                dns_chain.append({
                    'type': 'A',
                    'domain': domain_data.get('id', ''),
                    'ip': value,
                    'provider': provider,
                    'role': 'Origin' if provider else 'Unknown'
                })
        
        return dns_chain
    
    def extract_multi_layer_providers(self, domain_data: Dict, resolutions: List[Dict]) -> Dict:
        """Extract providers from different layers"""
        providers = {
            'origin': None,
            'cdn': [],
            'waf': [],
            'dns_provider': None
        }
        
        if not domain_data or 'attributes' not in domain_data:
            return providers
        
        attributes = domain_data['attributes']
        
        # Analyze current DNS records
        last_dns_records = attributes.get('last_dns_records', [])
        
        for record in last_dns_records:
            record_type = record.get('type', '')
            value = record.get('value', '')
            
            if record_type == 'CNAME':
                provider = self.identify_provider_from_domain(value)
                if provider and self.is_cdn_provider(provider):
                    if provider not in providers['cdn']:
                        providers['cdn'].append(provider)
            elif record_type == 'A':
                provider = self.identify_provider_from_ip(value)
                if provider and not providers['origin']:
                    providers['origin'] = provider
            elif record_type == 'NS':
                dns_provider = self.identify_dns_provider_from_ns(value)
                if dns_provider and not providers['dns_provider']:
                    providers['dns_provider'] = dns_provider
        
        # Analyze historical resolutions (Premium only)
        if self.is_premium and resolutions:
            for resolution in resolutions[:5]:  # Limit to recent 5
                ip_address = resolution.get('attributes', {}).get('ip_address', '')
                if ip_address:
                    historical_provider = self.identify_provider_from_ip(ip_address)
                    if historical_provider and historical_provider != providers['origin']:
                        historical_label = f"Historical: {historical_provider}"
                        if historical_label not in providers['cdn']:
                            providers['cdn'].append(historical_label)
        
        return providers
    
    def identify_provider_from_domain(self, domain: str) -> Optional[str]:
        """Identify provider from domain name"""
        if not domain:
            return None
            
        domain_lower = domain.lower()
        
        for provider, patterns in self.provider_domain_patterns.items():
            for pattern in patterns:
                if pattern in domain_lower:
                    return provider
        
        return None
    
    def identify_provider_from_ip(self, ip: str) -> Optional[str]:
        """Identify provider from IP address (simplified)"""
        # This would typically use IP range analysis
        # For now, return None as we have this logic in main detector
        return None
    
    def identify_dns_provider_from_ns(self, ns_domain: str) -> Optional[str]:
        """Identify DNS provider from NS domain"""
        if not ns_domain:
            return None
            
        ns_lower = ns_domain.lower()
        
        dns_patterns = {
            'AWS Route53': ['awsdns-', '.awsdns-'],
            'Cloudflare': ['.ns.cloudflare.com', '.cloudflare.com'],
            'Google Cloud DNS': ['ns-cloud-', '.google.com'],
            'Azure DNS': ['.azure-dns.', 'azure-dns'],
            'Namecheap': ['registrar-servers.com'],
            'GoDaddy': ['domaincontrol.com']
        }
        
        for provider, patterns in dns_patterns.items():
            for pattern in patterns:
                if pattern in ns_lower:
                    return provider
        
        return None
    
    def is_cdn_provider(self, provider: str) -> bool:
        """Check if provider is typically used as CDN"""
        cdn_providers = {
            'Cloudflare', 'AWS', 'Fastly', 'Akamai', 'Google', 
            'Microsoft', 'MaxCDN', 'KeyCDN', 'StackPath'
        }
        return provider in cdn_providers
    
    def calculate_confidence_score(self, domain_data: Dict, resolutions: List[Dict]) -> int:
        """Calculate confidence score based on available data"""
        score = 0
        
        if not domain_data:
            return score
        
        attributes = domain_data.get('attributes', {})
        
        # DNS records available
        if attributes.get('last_dns_records'):
            score += 30
        
        # Recent analysis available
        if attributes.get('last_analysis_date'):
            score += 20
        
        # Multiple resolution history (Premium)
        if resolutions:
            score += 25
        
        # Domain reputation indicators
        reputation = attributes.get('reputation', 0)
        if reputation >= 0:
            score += 15
        
        # Categories information
        if attributes.get('categories'):
            score += 10
        
        return min(score, 100)
    
    def get_analysis_stats(self, domain_data: Dict) -> Dict:
        """Get analysis statistics from domain data"""
        if not domain_data or 'attributes' not in domain_data:
            return {}
        
        attributes = domain_data['attributes']
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        
        return {
            'harmless': last_analysis_stats.get('harmless', 0),
            'malicious': last_analysis_stats.get('malicious', 0),
            'suspicious': last_analysis_stats.get('suspicious', 0),
            'undetected': last_analysis_stats.get('undetected', 0),
            'timeout': last_analysis_stats.get('timeout', 0)
        }
    
    def get_reputation_score(self, domain_data: Dict) -> int:
        """Get domain reputation score"""
        if not domain_data or 'attributes' not in domain_data:
            return 0
        
        return domain_data['attributes'].get('reputation', 0)
    
    def enhance_existing_detection(self, existing_result: Dict, domain: str) -> Dict:
        """Enhance existing detection results with VirusTotal data"""
        if not self.enabled:
            return existing_result
        
        try:
            # Get VirusTotal analysis
            vt_analysis = self.analyze_domain_comprehensive(domain)
            
            if 'error' in vt_analysis:
                existing_result['confidence_factors'].append(f"VirusTotal: {vt_analysis['error']}")
                return existing_result
            
            # Cross-validate providers
            vt_providers = vt_analysis['providers']
            existing_providers = existing_result.get('providers', [])
            
            # Add VirusTotal confidence factors
            if vt_analysis['confidence_score'] > 70:
                existing_result['confidence_factors'].append(f"VirusTotal validation (confidence: {vt_analysis['confidence_score']}%)")
            
            # Cross-validate origin provider
            if vt_providers['origin']:
                origin_matches = any(
                    p['name'].lower() == vt_providers['origin'].lower() 
                    for p in existing_providers if p['role'] == 'Origin'
                )
                if origin_matches:
                    existing_result['confidence_factors'].append("VirusTotal confirms origin provider")
                else:
                    existing_result['confidence_factors'].append(f"VirusTotal suggests different origin: {vt_providers['origin']}")
            
            # Add CDN information from VirusTotal
            for cdn in vt_providers.get('cdn', []):
                if not any(p['name'] == cdn for p in existing_providers if p['role'] == 'CDN'):
                    existing_result['providers'].append({
                        'name': cdn,
                        'role': 'CDN',
                        'confidence': 'Medium',
                        'source': 'VirusTotal'
                    })
                    existing_result['confidence_factors'].append(f"VirusTotal identified additional CDN: {cdn}")
            
            # Add reputation information
            reputation = vt_analysis.get('reputation', 0)
            if reputation != 0:
                rep_desc = "positive" if reputation > 0 else "negative" 
                existing_result['confidence_factors'].append(f"Domain reputation: {rep_desc} ({reputation})")
            
            # Add analysis stats if available
            stats = vt_analysis.get('last_analysis_stats', {})
            if stats.get('malicious', 0) > 0:
                existing_result['confidence_factors'].append(f"Security warning: {stats['malicious']} engines flagged domain")
            
            # Store VirusTotal data for reference
            existing_result['virustotal_data'] = vt_analysis
            
        except Exception as e:
            logging.error(f"Failed to enhance detection with VirusTotal: {e}")
            existing_result['confidence_factors'].append(f"VirusTotal enhancement failed: {str(e)}")
        
        return existing_result
    
    def __del__(self):
        """Cleanup when object is destroyed"""
        if self.client:
            try:
                self.client.close()
            except:
                pass

# Example usage and testing
def test_virustotal_integration():
    """Test VirusTotal integration with sample domains"""
    # Initialize without API key for testing
    vt_integrator = VirusTotalIntegrator()
    
    if not vt_integrator.is_enabled():
        print("⚠️ VirusTotal integration not enabled (no API key)")
        print("Set VT_API_KEY environment variable to enable")
        return
    
    test_domains = ['github.com', 'cloudflare.com', 'google.com']
    
    for domain in test_domains:
        print(f"\n🔍 Testing {domain} with VirusTotal...")
        result = vt_integrator.analyze_domain_comprehensive(domain)
        
        if 'error' in result:
            print(f"❌ Error: {result['error']}")
        else:
            print(f"✅ Confidence: {result['confidence_score']}%")
            print(f"🏢 Providers: {result['providers']}")
            if result.get('reputation'):
                print(f"🛡️ Reputation: {result['reputation']}")

if __name__ == "__main__":
    test_virustotal_integration()
