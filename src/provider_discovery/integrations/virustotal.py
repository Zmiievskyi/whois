#!/usr/bin/env python3
"""
VirusTotal API integration for enhanced provider detection (Phase 2B)
Enhanced version using new integration framework
"""
import re
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from ..integrations.base import HTTPIntegration
from ..config.settings import get_settings

# Import VirusTotal library with error handling
try:
    import vt
    VT_AVAILABLE = True
except ImportError:
    VT_AVAILABLE = False
    vt = None


class VirusTotalIntegration(HTTPIntegration):
    """VirusTotal API integration for enhanced provider detection"""
    
    def __init__(self, api_key: Optional[str] = None, is_premium: bool = False):
        """
        Initialize VirusTotal integration
        
        Args:
            api_key: VirusTotal API key
            is_premium: Whether using premium API features
        """
        # Use settings for API key if not provided
        settings = get_settings()
        api_key = api_key or settings.vt_api_key
        
        super().__init__(
            service_name="virustotal",
            base_url="https://www.virustotal.com/api/v3",
            api_key=api_key,
            default_headers={
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
        )
        
        self.is_premium = is_premium
        self.client = None
        self.settings = settings
        
        # Configure rate limiting based on API type
        if api_key:
            max_calls = 300 if is_premium else settings.vt_rate_limit_calls
            time_window = settings.vt_rate_limit_window
            self.rate_limiter.add_service(self.service_name, max_calls, time_window)
        
        # Initialize VT client if available
        if VT_AVAILABLE and self.api_key:
            try:
                # Don't store the client - create fresh for each request to avoid async issues
                self.client_available = True
                self.logger.info("✅ VirusTotal API key configured successfully")
            except Exception as e:
                self.logger.error(f"❌ Failed to configure VirusTotal: {e}")
                self.client_available = False
        elif not VT_AVAILABLE:
            self.logger.warning("⚠️ VirusTotal library not available (install vt-py)")
            self.client_available = False
        else:
            self.client_available = False
        
        # Provider patterns for enhanced detection
        self.provider_domain_patterns = {
            'Cloudflare': [
                r'\.cloudflare\.', r'\.cf-', r'cloudflare-dns', r'1\.1\.1\.1',
                r'cloudflaressl', r'cf-ips'
            ],
            'AWS': [
                r'\.aws\.', r'\.amazon\.', r'\.awsglobalconfig\.', r'\.awsdns-',
                r'cloudfront', r'elasticloadbalancing', r's3\.amazonaws',
                r'elb\.amazonaws', r'cloudformation'
            ],
            'Google': [
                r'\.google\.', r'\.googleapis\.', r'\.googleusercontent\.', 
                r'\.goog$', r'\.googlevideo\.', r'\.googleusercontent\.',
                r'appspot\.com', r'blogger\.com'
            ],
            'Microsoft': [
                r'\.microsoft\.', r'\.azure\.', r'\.outlook\.', r'\.office\.', 
                r'\.sharepoint\.', r'\.windows\.', r'azurewebsites',
                r'azurecontainer', r'microsoftonline'
            ],
            'Fastly': [
                r'\.fastly\.', r'\.fastlylb\.', r'\.fastly-edge\.',
                r'fastly\.com'
            ],
            'Akamai': [
                r'\.akamai\.', r'\.akamaitechnologies\.', r'\.akamaihd\.', 
                r'\.akamaistream\.', r'\.akamaized\.', r'edgekey\.net',
                r'edgesuite\.net'
            ],
            'GitHub': [
                r'\.github\.', r'\.githubusercontent\.', r'\.githubassets\.',
                r'github\.io'
            ],
            'Netlify': [
                r'\.netlify\.', r'netlify\.app', r'netlify\.com'
            ],
            'Vercel': [
                r'\.vercel\.', r'vercel\.app', r'vercel\.com'
            ]
        }
        
        # DNS provider patterns
        self.dns_provider_patterns = {
            'AWS Route53': [
                r'awsdns-.*\.net$', r'awsdns-.*\.org$', r'awsdns-.*\.com$', 
                r'awsdns-.*\.co\.uk$'
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
            ]
        }
    
    @property
    def is_enabled(self) -> bool:
        """Check if VirusTotal integration is properly configured"""
        return (
            VT_AVAILABLE and 
            self.api_key is not None and 
            len(self.api_key.strip()) >= 64 and  # VT API keys are typically 64 chars
            self.client_available
        )
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for VirusTotal API"""
        return {"x-apikey": self.api_key}
    
    def _make_api_request(self, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make API request to VirusTotal (using vt-py client)"""
        if not self.client:
            raise Exception("VirusTotal client not initialized")
        
        # This is handled by the vt-py client
        raise NotImplementedError("Use vt-py client methods directly")
    
    def _test_api_connection(self) -> Dict[str, Any]:
        """Test VirusTotal API connection"""
        if not self.is_enabled:
            return {
                'success': False, 
                'error': 'VirusTotal integration not properly configured'
            }
        
        try:
            # Test with a simple domain query
            result = self._get_domain_report("google.com")
            return {
                'success': True,
                'message': 'VirusTotal API connection successful',
                'api_type': 'Premium' if self.is_premium else 'Public'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'VirusTotal API test failed: {str(e)}'
            }
    
    def analyze_domain_comprehensive(self, domain: str) -> Dict[str, Any]:
        """
        Comprehensive domain analysis using VirusTotal data
        
        Args:
            domain: Domain to analyze
            
        Returns:
            Dictionary with analysis results
        """
        if not self.is_enabled:
            return {
                'error': 'VirusTotal integration not available',
                'providers': self._get_empty_providers(),
                'confidence_score': 0,
                'vt_available': False
            }
        
        cache_key = f"domain_analysis:{domain}"
        cache_ttl = self.settings.vt_cache_ttl
        
        # Check cache first
        cached_result = self.cache.get(self.service_name, cache_key)
        if cached_result:
            self.logger.debug(f"Cache hit for {cache_key}")
            return cached_result
        
        # Rate limiting
        self.rate_limiter.wait_if_needed(self.service_name)
        
        # Perform fresh analysis
        result = self._analyze_domain_fresh(domain)
        
        # Cache the result
        self.cache.set(self.service_name, cache_key, result, cache_ttl)
        
        return result
    
    def _analyze_domain_fresh(self, domain: str) -> Dict[str, Any]:
        """Perform fresh domain analysis (called by cached request)"""
        try:
            # Get domain report
            domain_data = self._get_domain_report(domain)
            
            # Get DNS resolutions (Premium only)
            resolutions = self._get_domain_resolutions(domain) if self.is_premium else []
            
            # Extract comprehensive provider information
            providers = self._extract_multi_layer_providers(domain_data, resolutions)
            
            # Analyze DNS chain
            dns_chain = self._analyze_vt_dns_chain(domain_data)
            
            # Calculate confidence score
            confidence_score = self._calculate_confidence_score(domain_data, resolutions)
            
            # Get security analysis
            security_analysis = self._get_security_analysis(domain_data)
            
            result = {
                'domain': domain,
                'providers': providers,
                'dns_chain': dns_chain,
                'confidence_score': confidence_score,
                'security_analysis': security_analysis,
                'reputation': self._get_reputation_score(domain_data),
                'vt_available': True,
                'timestamp': datetime.now().isoformat()
            }
            
            return result
            
        except Exception as e:
            self.logger.error(f"VirusTotal analysis failed for {domain}: {e}")
            return {
                'error': str(e),
                'providers': self._get_empty_providers(),
                'confidence_score': 0,
                'vt_available': True
            }
    
    def _get_domain_report(self, domain: str) -> Dict[str, Any]:
        """Get domain report from VirusTotal"""
        if not self.client_available:
            self.logger.debug("VirusTotal client not available")
            return {}
        
        try:
            # Create fresh client for each request to avoid async context issues
            with vt.Client(self.api_key) as client:
                try:
                    domain_obj = client.get_object(f"/domains/{domain}")
                    return domain_obj.to_dict()
                except vt.APIError as e:
                    if e.code == "NotFoundError":
                        self.logger.debug(f"Domain {domain} not found in VirusTotal")
                        return {}
                    self.logger.warning(f"VirusTotal API error for {domain}: {e}")
                    return {}
        except Exception as e:
            self.logger.debug(f"VirusTotal connection error for {domain}: {str(e)}")
            return {}
    
    def _get_domain_resolutions(self, domain: str) -> List[Dict[str, Any]]:
        """Get domain resolutions (Premium feature)"""
        if not self.is_premium or not self.client_available:
            return []
        
        try:
            # Create fresh client for each request to avoid async context issues
            with vt.Client(self.api_key) as client:
                resolutions = []
                for resolution in client.iterator(f"/domains/{domain}/resolutions", limit=10):
                    resolutions.append(resolution.to_dict())
                return resolutions
        except Exception as e:
            self.logger.debug(f"Failed to get resolutions for {domain}: {e}")
            return []
    
    def _extract_multi_layer_providers(self, domain_data: Dict, resolutions: List[Dict]) -> Dict[str, Any]:
        """Extract providers from different layers of DNS data"""
        providers = self._get_empty_providers()
        
        if not domain_data or 'attributes' not in domain_data:
            return providers
        
        attributes = domain_data['attributes']
        last_dns_records = attributes.get('last_dns_records', [])
        
        # Analyze current DNS records
        for record in last_dns_records:
            record_type = record.get('type', '')
            value = record.get('value', '')
            
            if record_type == 'CNAME':
                provider = self._identify_provider_from_domain(value)
                if provider and self._is_cdn_provider(provider):
                    if provider not in providers['cdn_providers']:
                        providers['cdn_providers'].append(provider)
            elif record_type == 'A':
                # IP analysis would be done by IP Range Manager
                pass
            elif record_type == 'NS':
                dns_provider = self._identify_dns_provider_from_ns(value)
                if dns_provider and dns_provider not in providers['dns_providers']:
                    providers['dns_providers'].append(dns_provider)
        
        # Analyze historical resolutions (Premium only)
        if self.is_premium and resolutions:
            for resolution in resolutions[:5]:  # Recent 5
                ip_address = resolution.get('attributes', {}).get('ip_address', '')
                if ip_address:
                    # This would be enhanced with IP Range Manager integration
                    pass
        
        return providers
    
    def _analyze_vt_dns_chain(self, domain_data: Dict) -> List[Dict[str, Any]]:
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
                provider = self._identify_provider_from_domain(value)
                dns_chain.append({
                    'type': 'CNAME',
                    'domain': domain_data.get('id', ''),
                    'cname': value,
                    'provider': provider,
                    'role': self._determine_provider_role(provider, value),
                    'source': 'VirusTotal'
                })
            elif record_type == 'A':
                dns_chain.append({
                    'type': 'A',
                    'domain': domain_data.get('id', ''),
                    'ip': value,
                    'provider': None,  # Will be filled by IP Range Manager
                    'role': 'Origin',
                    'source': 'VirusTotal'
                })
        
        return dns_chain
    
    def _calculate_confidence_score(self, domain_data: Dict, resolutions: List[Dict]) -> int:
        """Calculate confidence score based on available VirusTotal data"""
        score = 0
        
        if not domain_data:
            return score
        
        attributes = domain_data.get('attributes', {})
        
        # DNS records available (+30)
        if attributes.get('last_dns_records'):
            score += 30
        
        # Recent analysis available (+20)
        if attributes.get('last_analysis_date'):
            score += 20
        
        # Multiple resolution history (+25 for Premium)
        if resolutions:
            score += 25
        
        # Domain reputation indicators (+15)
        reputation = attributes.get('reputation', 0)
        if reputation >= 0:
            score += 15
        
        # Categories information (+10)
        if attributes.get('categories'):
            score += 10
        
        return min(score, 100)
    
    def _get_security_analysis(self, domain_data: Dict) -> Dict[str, Any]:
        """Get security analysis from VirusTotal data"""
        if not domain_data or 'attributes' not in domain_data:
            return {}
        
        attributes = domain_data['attributes']
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        
        return {
            'harmless': last_analysis_stats.get('harmless', 0),
            'malicious': last_analysis_stats.get('malicious', 0),
            'suspicious': last_analysis_stats.get('suspicious', 0),
            'undetected': last_analysis_stats.get('undetected', 0),
            'timeout': last_analysis_stats.get('timeout', 0),
            'last_analysis_date': attributes.get('last_analysis_date'),
            'categories': attributes.get('categories', {})
        }
    
    def _get_reputation_score(self, domain_data: Dict) -> int:
        """Get domain reputation score"""
        if not domain_data or 'attributes' not in domain_data:
            return 0
        
        return domain_data['attributes'].get('reputation', 0)
    
    def _identify_provider_from_domain(self, domain: str) -> Optional[str]:
        """Identify provider from domain name patterns"""
        if not domain:
            return None
        
        domain_lower = domain.lower()
        
        for provider, patterns in self.provider_domain_patterns.items():
            for pattern in patterns:
                if re.search(pattern, domain_lower):
                    return provider
        
        return None
    
    def _identify_dns_provider_from_ns(self, ns_domain: str) -> Optional[str]:
        """Identify DNS provider from NS domain"""
        if not ns_domain:
            return None
        
        ns_lower = ns_domain.lower()
        
        for provider, patterns in self.dns_provider_patterns.items():
            for pattern in patterns:
                if re.search(pattern, ns_lower):
                    return provider
        
        return None
    
    def _is_cdn_provider(self, provider: str) -> bool:
        """Check if provider is typically used as CDN"""
        cdn_providers = {
            'Cloudflare', 'AWS', 'Fastly', 'Akamai', 'Google', 
            'Microsoft', 'MaxCDN', 'KeyCDN', 'StackPath'
        }
        return provider in cdn_providers
    
    def _determine_provider_role(self, provider: Optional[str], domain: str) -> str:
        """Determine the role of a provider based on context"""
        if not provider:
            return 'Unknown'
        
        # CDN providers
        cdn_providers = {
            'Cloudflare', 'AWS', 'Fastly', 'Akamai', 'Google', 
            'Microsoft', 'MaxCDN', 'KeyCDN', 'StackPath'
        }
        
        domain_lower = domain.lower()
        
        if provider in cdn_providers:
            # Check domain patterns for role hints
            if any(pattern in domain_lower for pattern in ['cdn', 'static', 'assets', 'media']):
                return 'CDN'
            elif 'cloudfront' in domain_lower or 'fastly' in domain_lower:
                return 'CDN'
            else:
                return 'Origin'
        
        # WAF providers
        if provider in ['Cloudflare', 'Akamai'] and 'waf' in domain_lower:
            return 'WAF'
        
        # Load balancer patterns
        if 'elb' in domain_lower or 'lb' in domain_lower:
            return 'Load Balancer'
        
        return 'Origin'
    
    def _get_empty_providers(self) -> Dict[str, List]:
        """Get empty providers structure"""
        return {
            'origin_providers': [],
            'cdn_providers': [],
            'waf_providers': [],
            'lb_providers': [],
            'dns_providers': []
        }
    
    def enhance_existing_detection(self, existing_result: Dict, domain: str) -> Dict[str, Any]:
        """
        Enhance existing detection results with VirusTotal data
        
        Args:
            existing_result: Existing detection result to enhance
            domain: Domain being analyzed
            
        Returns:
            Enhanced detection result
        """
        if not self.is_enabled:
            existing_result['virustotal_enhanced'] = False
            return existing_result
        
        try:
            # Get VirusTotal analysis
            vt_analysis = self.analyze_domain_comprehensive(domain)
            
            if 'error' in vt_analysis:
                existing_result['confidence_factors'].append(f"VirusTotal: {vt_analysis['error']}")
                existing_result['virustotal_enhanced'] = False
                return existing_result
            
            # Cross-validate and enhance providers
            self._cross_validate_providers(existing_result, vt_analysis)
            
            # Add reputation and security information
            self._add_security_information(existing_result, vt_analysis)
            
            # Store VirusTotal data for reference
            existing_result['virustotal_data'] = vt_analysis
            existing_result['virustotal_enhanced'] = True
            
            # Update confidence based on VT validation
            if vt_analysis['confidence_score'] > 70:
                existing_result['confidence_factors'].append(
                    f"VirusTotal validation (confidence: {vt_analysis['confidence_score']}%)"
                )
            
        except Exception as e:
            self.logger.error(f"Failed to enhance detection with VirusTotal: {e}")
            existing_result['confidence_factors'].append(f"VirusTotal enhancement failed: {str(e)}")
            existing_result['virustotal_enhanced'] = False
        
        return existing_result
    
    def _cross_validate_providers(self, existing_result: Dict, vt_analysis: Dict):
        """Cross-validate providers between existing detection and VirusTotal"""
        vt_providers = vt_analysis.get('providers', {})
        
        # Add DNS providers from VirusTotal
        for dns_provider in vt_providers.get('dns_providers', []):
            if dns_provider not in existing_result.get('DNS_Providers', []):
                if 'DNS_Providers' not in existing_result:
                    existing_result['DNS_Providers'] = []
                existing_result['DNS_Providers'].append(dns_provider)
                existing_result['confidence_factors'].append(f"VirusTotal identified DNS provider: {dns_provider}")
        
        # Add CDN providers from VirusTotal
        for cdn_provider in vt_providers.get('cdn_providers', []):
            existing_cdns = existing_result.get('CDN_Providers', [])
            if cdn_provider not in existing_cdns:
                if 'CDN_Providers' not in existing_result:
                    existing_result['CDN_Providers'] = []
                existing_result['CDN_Providers'].append(cdn_provider)
                existing_result['confidence_factors'].append(f"VirusTotal identified CDN: {cdn_provider}")
    
    def _add_security_information(self, existing_result: Dict, vt_analysis: Dict):
        """Add security information from VirusTotal"""
        security = vt_analysis.get('security_analysis', {})
        reputation = vt_analysis.get('reputation', 0)
        
        # Add reputation information
        if reputation != 0:
            rep_desc = "positive" if reputation > 0 else "negative"
            existing_result['confidence_factors'].append(f"Domain reputation: {rep_desc} ({reputation})")
        
        # Add security warnings
        if security.get('malicious', 0) > 0:
            existing_result['confidence_factors'].append(
                f"⚠️ Security warning: {security['malicious']} engines flagged domain as malicious"
            )
        
        if security.get('suspicious', 0) > 0:
            existing_result['confidence_factors'].append(
                f"⚠️ Security notice: {security['suspicious']} engines flagged domain as suspicious"
            )
    
    def __del__(self):
        """Cleanup when object is destroyed"""
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass


# Global VirusTotal integration instance
_global_vt_integration: Optional[VirusTotalIntegration] = None


def get_virustotal_integration(api_key: Optional[str] = None) -> VirusTotalIntegration:
    """Get global VirusTotal integration instance"""
    global _global_vt_integration
    if _global_vt_integration is None:
        _global_vt_integration = VirusTotalIntegration(api_key)
    return _global_vt_integration


# Example usage and testing
if __name__ == "__main__":
    # Test VirusTotal integration
    vt_integration = VirusTotalIntegration()
    
    print("🦠 Testing VirusTotal Integration:")
    print(f"Enabled: {vt_integration.is_enabled}")
    print(f"VT Library Available: {VT_AVAILABLE}")
    
    if vt_integration.is_enabled:
        # Test connection
        conn_test = vt_integration.test_connection()
        print(f"Connection Test: {'✅' if conn_test else '❌'}")
        
        # Test domain analysis
        test_domain = "github.com"
        print(f"\n🔍 Testing domain analysis for {test_domain}...")
        result = vt_integration.analyze_domain_comprehensive(test_domain)
        
        if 'error' not in result:
            print(f"✅ Confidence: {result['confidence_score']}%")
            print(f"🔗 DNS Chain steps: {len(result.get('dns_chain', []))}")
            print(f"🛡️ Reputation: {result.get('reputation', 'N/A')}")
        else:
            print(f"❌ Error: {result['error']}")
    else:
        print("⚠️ VirusTotal integration not enabled (no API key)")
        print("Set VT_API_KEY environment variable to enable")
    
    # Show usage stats
    stats = vt_integration.get_usage_stats()
    print(f"\n📊 Usage Stats: {stats['requests_made']} requests, {stats['cache_hits']} cache hits")
    
    print("\n✅ VirusTotal integration testing completed!")
