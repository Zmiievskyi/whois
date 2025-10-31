#!/usr/bin/env python3
"""
SSL/TLS Certificate Analysis Integration
Free SSL certificate intelligence and security analysis
Uses certificate transparency logs and direct SSL inspection
"""

import ssl
import socket
import logging
import requests
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse
from .base import HTTPIntegration

logger = logging.getLogger(__name__)

class SSLAnalysisIntegration(HTTPIntegration):
    """
    SSL/TLS Certificate Analysis using free sources
    
    Data Sources:
    - Direct SSL certificate inspection
    - Certificate Transparency logs (free)
    - SSL Labs API (limited free tier)
    - Censys Certificate Search (free tier)
    """
    
    def __init__(self, cache_ttl: int = 7200):
        """
        Initialize SSL Analysis integration
        
        Args:
            cache_ttl: Cache TTL in seconds (default 2 hours)
        """
        super().__init__(
            service_name="ssl_analysis",
            base_url="https://api.ssllabs.com/api/v3"  # SSL Labs free API
        )
        
        self.cache_ttl = cache_ttl
        self.ct_log_urls = {
            'google_aviator': 'https://ct.googleapis.com/aviator/ct/v1',
            'cloudflare_nimbus': 'https://ct.cloudflare.com/logs/nimbus2024/ct/v1',
            'letsencrypt_oak': 'https://oak.ct.letsencrypt.org/2024h1/ct/v1'
        }
        
        # Setup conservative rate limiting for SSL Labs
        if hasattr(self.rate_limiter, 'add_service'):
            self.rate_limiter.add_service('ssl_labs', 5, 60)  # 5 requests per minute
        
        logger.info("SSL Analysis integration initialized")
    
    @property
    def is_enabled(self) -> bool:
        """SSL analysis is always enabled (uses free methods)"""
        return True
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """No authentication needed for free SSL analysis"""
        return {}
    
    def get_certificate_info(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """
        Get SSL certificate information directly from domain
        
        Args:
            domain: Domain to analyze
            port: SSL port (default 443)
            
        Returns:
            Dict with certificate information
        """
        cache_key = f"cert_info_{domain}_{port}"
        cached_result = self.cache.get('ssl_analysis', cache_key)
        if cached_result:
            return cached_result
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((domain, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cert_der = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    protocol = ssock.version()
            
            # Parse certificate information
            cert_info = self._parse_certificate_info(cert, cert_der)
            cert_info.update({
                'cipher_suite': cipher[0] if cipher else None,
                'protocol_version': protocol,
                'domain': domain,
                'port': port,
                'connection_successful': True
            })
            
            # Cache the result
            self.cache.set('ssl_analysis', cache_key, cert_info, self.cache_ttl)
            
            return cert_info
            
        except Exception as e:
            logger.error(f"Failed to get SSL certificate for {domain}:{port}: {e}")
            error_result = {
                'error': str(e),
                'domain': domain,
                'port': port,
                'connection_successful': False
            }
            return error_result
    
    def _parse_certificate_info(self, cert: Dict, cert_der: bytes) -> Dict[str, Any]:
        """Parse SSL certificate information"""
        try:
            # Basic certificate info
            subject = dict(x[0] for x in cert.get('subject', []))
            issuer = dict(x[0] for x in cert.get('issuer', []))
            
            # Parse dates
            not_before = datetime.strptime(cert.get('notBefore', ''), '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.strptime(cert.get('notAfter', ''), '%b %d %H:%M:%S %Y %Z')
            
            # Calculate days until expiry
            days_until_expiry = (not_after - datetime.now()).days
            
            # Extract Subject Alternative Names
            san_list = []
            for extension in cert.get('subjectAltName', []):
                if extension[0] == 'DNS':
                    san_list.append(extension[1])
            
            # Determine certificate authority and hosting provider
            ca_info = self._analyze_certificate_authority(issuer)
            hosting_hints = self._extract_hosting_hints(subject, san_list)
            
            return {
                'subject_cn': subject.get('commonName', ''),
                'subject_org': subject.get('organizationName', ''),
                'issuer_cn': issuer.get('commonName', ''),
                'issuer_org': issuer.get('organizationName', ''),
                'not_before': not_before.isoformat(),
                'not_after': not_after.isoformat(),
                'days_until_expiry': days_until_expiry,
                'is_expired': days_until_expiry < 0,
                'is_expiring_soon': 0 <= days_until_expiry <= 30,
                'subject_alt_names': san_list,
                'serial_number': cert.get('serialNumber', ''),
                'version': cert.get('version', 0),
                'ca_info': ca_info,
                'hosting_hints': hosting_hints,
                'wildcard_cert': any(san.startswith('*.') for san in san_list),
                'multi_domain_cert': len(san_list) > 1
            }
            
        except Exception as e:
            logger.error(f"Failed to parse certificate: {e}")
            return {'parse_error': str(e)}
    
    def _analyze_certificate_authority(self, issuer: Dict) -> Dict[str, Any]:
        """Analyze certificate authority and extract provider hints"""
        issuer_cn = issuer.get('commonName', '').lower()
        issuer_org = issuer.get('organizationName', '').lower()
        
        ca_mappings = {
            # Let's Encrypt (often indicates modern cloud setups)
            'lets_encrypt': {
                'patterns': ['let\'s encrypt', 'letsencrypt'],
                'type': 'Free CA',
                'provider_hints': ['Self-managed', 'Cloud-native'],
                'automation': 'High'
            },
            
            # Cloud provider CAs
            'aws_ca': {
                'patterns': ['amazon', 'aws'],
                'type': 'Cloud CA',
                'provider_hints': ['AWS'],
                'automation': 'High'
            },
            
            'google_ca': {
                'patterns': ['google trust services', 'gts'],
                'type': 'Cloud CA',
                'provider_hints': ['Google Cloud', 'GCP'],
                'automation': 'High'
            },
            
            'cloudflare_ca': {
                'patterns': ['cloudflare'],
                'type': 'CDN CA',
                'provider_hints': ['Cloudflare'],
                'automation': 'High'
            },
            
            # Traditional CAs
            'digicert': {
                'patterns': ['digicert'],
                'type': 'Commercial CA',
                'provider_hints': ['Enterprise'],
                'automation': 'Medium'
            },
            
            'symantec': {
                'patterns': ['symantec', 'verisign'],
                'type': 'Commercial CA',
                'provider_hints': ['Enterprise', 'Legacy'],
                'automation': 'Low'
            },
            
            'comodo': {
                'patterns': ['comodo', 'sectigo'],
                'type': 'Commercial CA',
                'provider_hints': ['SMB', 'Budget'],
                'automation': 'Medium'
            }
        }
        
        # Find matching CA
        for ca_name, ca_info in ca_mappings.items():
            for pattern in ca_info['patterns']:
                if pattern in issuer_cn or pattern in issuer_org:
                    return {
                        'ca_name': ca_name,
                        'ca_type': ca_info['type'],
                        'provider_hints': ca_info['provider_hints'],
                        'automation_level': ca_info['automation'],
                        'issuer_cn': issuer_cn,
                        'issuer_org': issuer_org
                    }
        
        # Unknown CA
        return {
            'ca_name': 'unknown',
            'ca_type': 'Unknown',
            'provider_hints': [],
            'automation_level': 'Unknown',
            'issuer_cn': issuer_cn,
            'issuer_org': issuer_org
        }
    
    def _extract_hosting_hints(self, subject: Dict, san_list: List[str]) -> Dict[str, Any]:
        """Extract hosting provider hints from certificate subject and SANs"""
        subject_cn = subject.get('commonName', '').lower()
        all_domains = [subject_cn] + [san.lower() for san in san_list]
        
        hosting_patterns = {
            'aws': ['amazonaws.com', 'awsapps.com', 'cloudfront.net'],
            'cloudflare': ['cloudflare.com', 'cloudflaressl.com'],
            'google_cloud': ['googleapis.com', 'googleusercontent.com', 'appspot.com'],
            'azure': ['azurewebsites.net', 'azure.com', 'outlook.com'],
            'akamai': ['akamaihd.net', 'akamai.com'],
            'fastly': ['fastly.com', 'fastlylb.net'],
            'github': ['github.io', 'githubusercontent.com'],
            'netlify': ['netlify.app', 'netlify.com'],
            'vercel': ['vercel.app', 'now.sh']
        }
        
        detected_providers = []
        for provider, patterns in hosting_patterns.items():
            for domain in all_domains:
                for pattern in patterns:
                    if pattern in domain:
                        detected_providers.append(provider)
                        break
        
        return {
            'detected_providers': list(set(detected_providers)),
            'total_domains': len(san_list) + 1,
            'wildcard_domains': [san for san in san_list if san.startswith('*.')],
            'subdomain_patterns': self._analyze_subdomain_patterns(all_domains)
        }
    
    def _analyze_subdomain_patterns(self, domains: List[str]) -> Dict[str, int]:
        """Analyze subdomain patterns to infer infrastructure"""
        patterns = {}
        
        for domain in domains:
            parts = domain.split('.')
            if len(parts) >= 2:
                # API endpoints
                if 'api' in parts[0]:
                    patterns['api_endpoints'] = patterns.get('api_endpoints', 0) + 1
                
                # CDN patterns
                if any(cdn in domain for cdn in ['cdn', 'static', 'assets', 'media']):
                    patterns['cdn_domains'] = patterns.get('cdn_domains', 0) + 1
                
                # Admin/internal
                if any(admin in parts[0] for admin in ['admin', 'internal', 'staging', 'dev']):
                    patterns['internal_domains'] = patterns.get('internal_domains', 0) + 1
                
                # Regional patterns
                if any(region in parts[0] for region in ['us', 'eu', 'asia', 'ap']):
                    patterns['regional_domains'] = patterns.get('regional_domains', 0) + 1
        
        return patterns
    
    def get_ssl_labs_analysis(self, domain: str) -> Dict[str, Any]:
        """
        Get SSL Labs analysis (free tier with rate limits)
        
        Args:
            domain: Domain to analyze
            
        Returns:
            Dict with SSL Labs analysis results
        """
        cache_key = f"ssl_labs_{domain}"
        cached_result = self.cache.get('ssl_analysis', cache_key)
        if cached_result:
            return cached_result
        
        try:
            # Apply rate limiting
            self.rate_limiter.wait_if_needed('ssl_labs')
            
            # Start analysis
            start_url = f"{self.base_url}/analyze"
            params = {
                'host': domain,
                'publish': 'off',
                'startNew': 'on',
                'all': 'done',
                'ignoreMismatch': 'on'
            }
            
            response = requests.get(start_url, params=params, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            
            # SSL Labs returns status, we might need to poll for results
            if result.get('status') == 'READY':
                analysis = self._parse_ssl_labs_result(result)
                self.cache.set('ssl_analysis', cache_key, analysis, self.cache_ttl)
                return analysis
            else:
                # Analysis not ready, return partial info
                return {
                    'status': result.get('status', 'UNKNOWN'),
                    'message': 'SSL Labs analysis in progress',
                    'domain': domain
                }
                
        except Exception as e:
            logger.error(f"SSL Labs analysis failed for {domain}: {e}")
            return {'error': str(e), 'domain': domain}
    
    def _parse_ssl_labs_result(self, result: Dict) -> Dict[str, Any]:
        """Parse SSL Labs analysis result"""
        try:
            endpoints = result.get('endpoints', [])
            if not endpoints:
                return {'error': 'No endpoints found', 'raw_result': result}
            
            # Take first endpoint for analysis
            endpoint = endpoints[0]
            details = endpoint.get('details', {})
            
            return {
                'overall_grade': endpoint.get('grade', 'Unknown'),
                'ip_address': endpoint.get('ipAddress', ''),
                'server_name': endpoint.get('serverName', ''),
                'ssl_version': details.get('protocols', []),
                'cipher_suites': len(details.get('suites', {}).get('list', [])),
                'certificate_grade': details.get('cert', {}).get('issues', 0),
                'has_sni': details.get('sniRequired', False),
                'supports_rc4': details.get('supportsRc4', False),
                'vulnerable_beast': details.get('vulnBeast', False),
                'vulnerable_heartbleed': details.get('heartbleed', False),
                'supports_forward_secrecy': details.get('forwardSecrecy', 0) > 0,
                'analysis_time': result.get('testTime', 0),
                'cache_expiry': result.get('cacheExpiryTime', 0)
            }
            
        except Exception as e:
            logger.error(f"Failed to parse SSL Labs result: {e}")
            return {'parse_error': str(e), 'raw_result': result}
    
    def analyze_domain_ssl(self, domain: str) -> Dict[str, Any]:
        """
        Comprehensive SSL analysis for a domain
        
        Args:
            domain: Domain to analyze
            
        Returns:
            Dict with comprehensive SSL analysis
        """
        cache_key = f"domain_ssl_{domain}"
        cached_result = self.cache.get('ssl_analysis', cache_key)
        if cached_result:
            return cached_result
        
        try:
            # Get direct certificate info
            cert_info = self.get_certificate_info(domain)
            
            # Analyze certificate for provider hints
            provider_analysis = self._analyze_ssl_providers(cert_info)
            
            # Security assessment
            security_assessment = self._assess_ssl_security(cert_info)
            
            # Compile comprehensive analysis
            analysis = {
                'domain': domain,
                'certificate_info': cert_info,
                'provider_analysis': provider_analysis,
                'security_assessment': security_assessment,
                'data_source': 'ssl_analysis'
            }
            
            # Cache the result
            self.cache.set('ssl_analysis', cache_key, analysis, self.cache_ttl)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Failed SSL analysis for {domain}: {e}")
            return {'error': str(e), 'domain': domain}
    
    def _analyze_ssl_providers(self, cert_info: Dict) -> Dict[str, Any]:
        """Analyze providers based on SSL certificate information"""
        if 'error' in cert_info:
            return {'error': cert_info['error']}
        
        ca_info = cert_info.get('ca_info', {})
        hosting_hints = cert_info.get('hosting_hints', {})
        
        # Provider classification based on CA and certificate patterns
        providers = {
            'certificate_authority': ca_info.get('ca_name', 'unknown'),
            'ca_type': ca_info.get('ca_type', 'Unknown'),
            'automation_level': ca_info.get('automation_level', 'Unknown'),
            'detected_hosting_providers': hosting_hints.get('detected_providers', []),
            'infrastructure_hints': []
        }
        
        # Add infrastructure hints based on certificate patterns
        if cert_info.get('wildcard_cert'):
            providers['infrastructure_hints'].append('Wildcard certificate (likely CDN/load balancer)')
        
        if cert_info.get('multi_domain_cert'):
            providers['infrastructure_hints'].append('Multi-domain certificate (shared hosting or CDN)')
        
        if ca_info.get('ca_name') == 'lets_encrypt':
            providers['infrastructure_hints'].append('Let\'s Encrypt (automated, likely cloud-native)')
        
        if hosting_hints.get('subdomain_patterns', {}).get('api_endpoints', 0) > 0:
            providers['infrastructure_hints'].append('API endpoints detected (microservices architecture)')
        
        return providers
    
    def _assess_ssl_security(self, cert_info: Dict) -> Dict[str, Any]:
        """Assess SSL security posture"""
        if 'error' in cert_info:
            return {'error': cert_info['error']}
        
        security_score = 100
        issues = []
        recommendations = []
        
        # Certificate expiry check
        if cert_info.get('is_expired'):
            security_score -= 50
            issues.append('Certificate expired')
        elif cert_info.get('is_expiring_soon'):
            security_score -= 10
            issues.append('Certificate expires within 30 days')
        
        # Protocol version check
        protocol = cert_info.get('protocol_version', '')
        if protocol and 'TLSv1.3' not in protocol:
            if 'TLSv1.2' in protocol:
                security_score -= 5
                recommendations.append('Consider upgrading to TLS 1.3')
            else:
                security_score -= 20
                issues.append(f'Outdated protocol: {protocol}')
        
        # Certificate authority assessment
        ca_info = cert_info.get('ca_info', {})
        if ca_info.get('ca_name') == 'unknown':
            security_score -= 10
            issues.append('Unknown certificate authority')
        
        return {
            'security_score': max(0, security_score),
            'security_grade': self._calculate_security_grade(security_score),
            'issues': issues,
            'recommendations': recommendations,
            'protocol_version': cert_info.get('protocol_version'),
            'cipher_suite': cert_info.get('cipher_suite'),
            'certificate_valid': not cert_info.get('is_expired', True)
        }
    
    def _calculate_security_grade(self, score: int) -> str:
        """Calculate security grade from score"""
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'
    
    def test_connection(self) -> Dict[str, Any]:
        """Test SSL analysis capabilities"""
        try:
            # Test with a known good domain
            test_result = self.get_certificate_info('google.com')
            
            if 'error' in test_result:
                return {
                    'success': False,
                    'error': test_result['error']
                }
            
            return {
                'success': True,
                'message': 'SSL analysis working',
                'test_domain': 'google.com',
                'certificate_authority': test_result.get('ca_info', {}).get('ca_name', 'unknown')
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

# Singleton instance
_ssl_analysis_integration = None

def get_ssl_analysis_integration() -> SSLAnalysisIntegration:
    """Get singleton SSL analysis integration instance"""
    global _ssl_analysis_integration
    if _ssl_analysis_integration is None:
        _ssl_analysis_integration = SSLAnalysisIntegration()
    return _ssl_analysis_integration
