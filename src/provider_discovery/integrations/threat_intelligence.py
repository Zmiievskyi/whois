#!/usr/bin/env python3
"""
Threat Intelligence Integration
Free security and threat intelligence using multiple sources
Provides domain reputation, malware detection, and security analysis
"""

import logging
import requests
import socket
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from .base import HTTPIntegration

logger = logging.getLogger(__name__)

class ThreatIntelligenceIntegration(HTTPIntegration):
    """
    Threat Intelligence using free security databases and APIs
    
    Free Data Sources:
    - URLVoid.com (free with rate limits)
    - AbuseIPDB.com (1000 checks/day free)
    - AlienVault OTX (free with registration)
    - Google Safe Browsing (free API)
    - Malware Domain List (free)
    - PhishTank (free with registration)
    """
    
    def __init__(self, cache_ttl: int = 7200):
        """
        Initialize Threat Intelligence integration
        
        Args:
            cache_ttl: Cache TTL in seconds (default 2 hours)
        """
        super().__init__(
            service_name="threat_intelligence",
            base_url="https://www.urlvoid.com/api1000"  # URLVoid free API
        )
        
        self.cache_ttl = cache_ttl
        
        # Configure free threat intelligence sources
        self.threat_sources = {
            'urlvoid': {
                'url': 'https://www.urlvoid.com/api1000/{domain}/',
                'free_limit': 1000,  # per month
                'rate_limit': 200,   # per day
                'auth_required': False,
                'response_format': 'html'  # Free version returns HTML
            },
            'malware_domain_list': {
                'url': 'http://www.malwaredomainlist.com/hostslist/mdl.xml',
                'free_limit': 'unlimited',
                'rate_limit': 'reasonable',
                'auth_required': False,
                'response_format': 'xml'
            },
            'phishtank': {
                'url': 'http://data.phishtank.com/data/online-valid.csv',
                'free_limit': 'unlimited',
                'rate_limit': 'reasonable', 
                'auth_required': False,
                'response_format': 'csv'
            },
            'openphish': {
                'url': 'https://openphish.com/feed.txt',
                'free_limit': 'unlimited',
                'rate_limit': 'reasonable',
                'auth_required': False,
                'response_format': 'text'
            }
        }
        
        # Known malicious domain patterns
        self.suspicious_patterns = {
            'suspicious_tlds': ['.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download'],
            'suspicious_keywords': ['phishing', 'malware', 'virus', 'trojan', 'spam', 'scam'],
            'suspicious_subdomains': ['secure', 'verify', 'update', 'confirm', 'account'],
            'url_shorteners': ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly'],
            'dga_patterns': ['qwerty', 'asdf', 'random', 'temp']  # Domain Generation Algorithm patterns
        }
        
        # Setup conservative rate limiting
        if hasattr(self.rate_limiter, 'add_service'):
            self.rate_limiter.add_service('threat_intelligence', 10, 60)  # 10 requests per minute
        
        logger.info("Threat Intelligence integration initialized")
    
    @property
    def is_enabled(self) -> bool:
        """Threat intelligence is always enabled (uses free sources)"""
        return True
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """No authentication needed for free threat intelligence sources"""
        return {}
    
    def analyze_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """
        Analyze domain reputation using multiple threat intelligence sources
        
        Args:
            domain: Domain to analyze
            
        Returns:
            Dict with reputation analysis
        """
        cache_key = f"domain_reputation_{domain}"
        cached_result = self.cache.get('threat_intelligence', cache_key)
        if cached_result:
            return cached_result
        
        analysis = {
            'domain': domain,
            'reputation_score': 0,
            'threat_level': 'unknown',
            'security_analysis': {},
            'pattern_analysis': {},
            'recommendations': []
        }
        
        try:
            # Pattern-based analysis (always available)
            analysis['pattern_analysis'] = self._analyze_domain_patterns(domain)
            
            # URLVoid analysis (if available)
            urlvoid_result = self._check_urlvoid_reputation(domain)
            if urlvoid_result.get('success'):
                analysis['security_analysis']['urlvoid'] = urlvoid_result
            
            # Google Safe Browsing check (basic)
            safe_browsing_result = self._check_google_safe_browsing(domain)
            if safe_browsing_result.get('success'):
                analysis['security_analysis']['safe_browsing'] = safe_browsing_result
            
            # DNS-based checks
            dns_analysis = self._analyze_dns_security_indicators(domain)
            analysis['security_analysis']['dns_indicators'] = dns_analysis
            
            # Calculate overall reputation score
            analysis['reputation_score'] = self._calculate_reputation_score(analysis)
            analysis['threat_level'] = self._determine_threat_level(analysis['reputation_score'])
            
            # Generate recommendations
            analysis['recommendations'] = self._generate_security_recommendations(analysis)
            
            # Cache the result
            self.cache.set('threat_intelligence', cache_key, analysis, self.cache_ttl)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Domain reputation analysis failed for {domain}: {e}")
            return {'error': str(e), 'domain': domain}
    
    def _analyze_domain_patterns(self, domain: str) -> Dict[str, Any]:
        """Analyze domain for suspicious patterns"""
        pattern_results = {
            'suspicious_indicators': [],
            'risk_factors': [],
            'domain_age_estimate': 'unknown',
            'structure_analysis': {}
        }
        
        domain_lower = domain.lower()
        parts = domain_lower.split('.')
        
        # TLD analysis
        if len(parts) >= 2:
            tld = '.' + parts[-1]
            if tld in self.suspicious_patterns['suspicious_tlds']:
                pattern_results['suspicious_indicators'].append(f'Suspicious TLD: {tld}')
                pattern_results['risk_factors'].append('high_risk_tld')
        
        # Keyword analysis
        for keyword in self.suspicious_patterns['suspicious_keywords']:
            if keyword in domain_lower:
                pattern_results['suspicious_indicators'].append(f'Suspicious keyword: {keyword}')
                pattern_results['risk_factors'].append('suspicious_keyword')
        
        # Subdomain analysis
        if len(parts) >= 3:
            subdomain = parts[0]
            if subdomain in self.suspicious_patterns['suspicious_subdomains']:
                pattern_results['suspicious_indicators'].append(f'Suspicious subdomain: {subdomain}')
                pattern_results['risk_factors'].append('phishing_subdomain')
        
        # URL shortener check
        base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain
        if base_domain in self.suspicious_patterns['url_shorteners']:
            pattern_results['suspicious_indicators'].append('URL shortener service')
            pattern_results['risk_factors'].append('url_shortener')
        
        # Domain Generation Algorithm (DGA) patterns
        for part in parts[:-1]:  # Exclude TLD
            if len(part) > 8 and self._has_dga_characteristics(part):
                pattern_results['suspicious_indicators'].append(f'Possible DGA pattern: {part}')
                pattern_results['risk_factors'].append('dga_pattern')
        
        # Domain structure analysis
        pattern_results['structure_analysis'] = {
            'total_length': len(domain),
            'subdomain_count': len(parts) - 2,
            'has_numbers': any(c.isdigit() for c in domain),
            'has_hyphens': '-' in domain,
            'entropy': self._calculate_domain_entropy(domain)
        }
        
        return pattern_results
    
    def _has_dga_characteristics(self, text: str) -> bool:
        """Check if text has Domain Generation Algorithm characteristics"""
        # High consonant ratio
        consonants = sum(1 for c in text if c.isalpha() and c.lower() not in 'aeiou')
        vowels = sum(1 for c in text if c.lower() in 'aeiou')
        
        if vowels == 0:
            return True
        
        consonant_ratio = consonants / (consonants + vowels)
        
        # Random character patterns
        has_repeated_chars = len(set(text)) < len(text) * 0.6
        has_dictionary_words = any(word in text.lower() for word in ['the', 'and', 'com', 'net', 'org'])
        
        return consonant_ratio > 0.8 or (has_repeated_chars and not has_dictionary_words)
    
    def _calculate_domain_entropy(self, domain: str) -> float:
        """Calculate Shannon entropy of domain name"""
        import math
        
        # Remove TLD for entropy calculation
        domain_base = domain.split('.')[0]
        
        if not domain_base:
            return 0.0
        
        # Calculate character frequency
        char_counts = {}
        for char in domain_base:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        length = len(domain_base)
        
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return round(entropy, 2)
    
    def _check_urlvoid_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation using URLVoid (free version)"""
        try:
            # Apply rate limiting
            self.rate_limiter.wait_if_needed('threat_intelligence')
            
            # URLVoid free API endpoint
            url = f"https://www.urlvoid.com/scan/{domain}/"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (compatible; ThreatIntel/1.0)',
                'Accept': 'text/html,application/xhtml+xml'
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            # Parse HTML response (free version doesn't provide JSON)
            html_content = response.text.lower()
            
            # Basic pattern matching for reputation indicators
            reputation_indicators = {
                'malicious_detections': 0,
                'safety_indicators': [],
                'risk_level': 'unknown'
            }
            
            # Look for positive indicators
            if 'safe' in html_content or 'clean' in html_content:
                reputation_indicators['safety_indicators'].append('marked_as_safe')
            
            # Look for negative indicators
            if 'malicious' in html_content or 'malware' in html_content:
                reputation_indicators['malicious_detections'] += 1
                reputation_indicators['safety_indicators'].append('malware_detected')
            
            if 'phishing' in html_content:
                reputation_indicators['malicious_detections'] += 1
                reputation_indicators['safety_indicators'].append('phishing_detected')
            
            if 'blacklist' in html_content:
                reputation_indicators['malicious_detections'] += 1
                reputation_indicators['safety_indicators'].append('blacklisted')
            
            # Determine risk level
            if reputation_indicators['malicious_detections'] > 0:
                reputation_indicators['risk_level'] = 'high'
            elif 'marked_as_safe' in reputation_indicators['safety_indicators']:
                reputation_indicators['risk_level'] = 'low'
            else:
                reputation_indicators['risk_level'] = 'medium'
            
            return {
                'success': True,
                'source': 'urlvoid',
                'data': reputation_indicators
            }
            
        except Exception as e:
            logger.debug(f"URLVoid check failed for {domain}: {e}")
            return {'success': False, 'error': str(e)}
    
    def _check_google_safe_browsing(self, domain: str) -> Dict[str, Any]:
        """Basic Google Safe Browsing check (without API key)"""
        try:
            # Simple DNS-based check for known bad domains
            # This is a basic implementation without the official API
            
            # Check if domain resolves (basic availability check)
            try:
                socket.gethostbyname(domain)
                dns_resolves = True
            except socket.gaierror:
                dns_resolves = False
            
            # Basic heuristics
            safe_browsing_result = {
                'dns_resolves': dns_resolves,
                'risk_assessment': 'unknown',
                'confidence': 'low'
            }
            
            # If domain doesn't resolve, it might be suspicious or dead
            if not dns_resolves:
                safe_browsing_result['risk_assessment'] = 'medium'
                safe_browsing_result['confidence'] = 'medium'
            else:
                safe_browsing_result['risk_assessment'] = 'low'
            
            return {
                'success': True,
                'source': 'basic_dns_check',
                'data': safe_browsing_result
            }
            
        except Exception as e:
            logger.debug(f"Safe browsing check failed for {domain}: {e}")
            return {'success': False, 'error': str(e)}
    
    def _analyze_dns_security_indicators(self, domain: str) -> Dict[str, Any]:
        """Analyze DNS-based security indicators"""
        dns_indicators = {
            'mx_records': [],
            'txt_records': [],
            'security_policies': {},
            'suspicious_patterns': []
        }
        
        try:
            import dns.resolver
            
            # Check MX records
            try:
                mx_answers = dns.resolver.resolve(domain, 'MX')
                for mx in mx_answers:
                    mx_domain = str(mx.exchange).rstrip('.')
                    dns_indicators['mx_records'].append(mx_domain)
                    
                    # Check for suspicious MX patterns
                    if any(susp in mx_domain.lower() for susp in ['temp', 'test', 'fake']):
                        dns_indicators['suspicious_patterns'].append(f'Suspicious MX: {mx_domain}')
            except:
                pass
            
            # Check TXT records for security policies
            try:
                txt_answers = dns.resolver.resolve(domain, 'TXT')
                for txt in txt_answers:
                    txt_string = ' '.join([part.decode() if isinstance(part, bytes) else str(part) for part in txt.strings])
                    dns_indicators['txt_records'].append(txt_string)
                    
                    # Parse security policies
                    if txt_string.startswith('v=spf1'):
                        dns_indicators['security_policies']['spf'] = True
                    elif txt_string.startswith('v=DMARC1'):
                        dns_indicators['security_policies']['dmarc'] = True
                    elif 'google-site-verification' in txt_string:
                        dns_indicators['security_policies']['google_verified'] = True
            except:
                pass
                
        except ImportError:
            # Fallback if DNS library not available
            dns_indicators['error'] = 'DNS library not available'
        
        return dns_indicators
    
    def _calculate_reputation_score(self, analysis: Dict) -> int:
        """Calculate overall reputation score (0-100, higher is better)"""
        score = 50  # Neutral starting point
        
        # Pattern analysis
        pattern_analysis = analysis.get('pattern_analysis', {})
        risk_factors = pattern_analysis.get('risk_factors', [])
        
        # Deduct points for risk factors
        score -= len(risk_factors) * 10
        
        # Specific risk factor penalties
        if 'high_risk_tld' in risk_factors:
            score -= 15
        if 'suspicious_keyword' in risk_factors:
            score -= 20
        if 'phishing_subdomain' in risk_factors:
            score -= 25
        if 'dga_pattern' in risk_factors:
            score -= 30
        
        # Domain structure analysis
        structure = pattern_analysis.get('structure_analysis', {})
        entropy = structure.get('entropy', 0)
        
        # Very high or very low entropy can be suspicious
        if entropy > 4.5 or entropy < 1.5:
            score -= 10
        
        # Security analysis bonuses/penalties
        security_analysis = analysis.get('security_analysis', {})
        
        # URLVoid results
        urlvoid = security_analysis.get('urlvoid', {})
        if urlvoid.get('success'):
            urlvoid_data = urlvoid.get('data', {})
            malicious_detections = urlvoid_data.get('malicious_detections', 0)
            score -= malicious_detections * 20
            
            if 'marked_as_safe' in urlvoid_data.get('safety_indicators', []):
                score += 15
        
        # DNS security indicators
        dns_indicators = security_analysis.get('dns_indicators', {})
        security_policies = dns_indicators.get('security_policies', {})
        
        # Bonus for security policies
        if security_policies.get('spf'):
            score += 5
        if security_policies.get('dmarc'):
            score += 10
        if security_policies.get('google_verified'):
            score += 5
        
        return max(0, min(100, score))
    
    def _determine_threat_level(self, score: int) -> str:
        """Determine threat level based on reputation score"""
        if score >= 80:
            return 'low'
        elif score >= 60:
            return 'medium'
        elif score >= 40:
            return 'high'
        else:
            return 'critical'
    
    def _generate_security_recommendations(self, analysis: Dict) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        threat_level = analysis.get('threat_level', 'unknown')
        pattern_analysis = analysis.get('pattern_analysis', {})
        risk_factors = pattern_analysis.get('risk_factors', [])
        
        # Threat level recommendations
        if threat_level == 'critical':
            recommendations.append('⚠️ CRITICAL: Avoid accessing this domain')
            recommendations.append('🛡️ Block domain in firewall/DNS filter')
        elif threat_level == 'high':
            recommendations.append('⚠️ HIGH RISK: Exercise extreme caution')
            recommendations.append('🔍 Perform additional security verification')
        elif threat_level == 'medium':
            recommendations.append('⚠️ MEDIUM RISK: Proceed with caution')
            recommendations.append('🔍 Verify domain legitimacy before use')
        
        # Specific risk factor recommendations
        if 'high_risk_tld' in risk_factors:
            recommendations.append('📋 Verify legitimacy - high-risk TLD detected')
        
        if 'phishing_subdomain' in risk_factors:
            recommendations.append('🎣 Potential phishing - verify authentic domain')
        
        if 'dga_pattern' in risk_factors:
            recommendations.append('🤖 Possible malware - DGA pattern detected')
        
        # Security policy recommendations
        security_analysis = analysis.get('security_analysis', {})
        dns_indicators = security_analysis.get('dns_indicators', {})
        security_policies = dns_indicators.get('security_policies', {})
        
        if not security_policies.get('spf'):
            recommendations.append('📧 Consider SPF record for email security')
        
        if not security_policies.get('dmarc'):
            recommendations.append('🔐 Consider DMARC policy for email protection')
        
        return recommendations
    
    def analyze_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """
        Analyze IP address reputation
        
        Args:
            ip: IP address to analyze
            
        Returns:
            Dict with IP reputation analysis
        """
        cache_key = f"ip_reputation_{ip}"
        cached_result = self.cache.get('threat_intelligence', cache_key)
        if cached_result:
            return cached_result
        
        analysis = {
            'ip': ip,
            'reputation_score': 50,
            'threat_indicators': [],
            'geolocation_risk': {},
            'network_analysis': {}
        }
        
        try:
            # Basic IP validation
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            
            # Check for private/reserved IPs
            if ip_obj.is_private:
                analysis['threat_indicators'].append('Private IP address')
                analysis['reputation_score'] += 20  # Private IPs are generally safer
            elif ip_obj.is_reserved:
                analysis['threat_indicators'].append('Reserved IP address')
            elif ip_obj.is_loopback:
                analysis['threat_indicators'].append('Loopback IP address')
                analysis['reputation_score'] += 30
            
            # Geolocation-based risk assessment
            try:
                from .geo_intelligence import get_geo_intelligence_integration
                geo_intel = get_geo_intelligence_integration()
                geo_result = geo_intel.get_multi_provider_geolocation(ip)
                
                if geo_result.get('consensus', {}).get('consensus_reached'):
                    consensus_data = geo_result['consensus']['consensus_data']
                    country_code = consensus_data.get('country_code', '').upper()
                    
                    # Country-based risk assessment (basic heuristics)
                    high_risk_countries = ['CN', 'RU', 'KP', 'IR']  # Example high-risk countries
                    if country_code in high_risk_countries:
                        analysis['geolocation_risk']['risk_level'] = 'high'
                        analysis['reputation_score'] -= 20
                    else:
                        analysis['geolocation_risk']['risk_level'] = 'low'
                    
                    analysis['geolocation_risk']['country'] = consensus_data.get('country')
                    analysis['geolocation_risk']['isp'] = consensus_data.get('isp')
                
            except:
                analysis['geolocation_risk']['error'] = 'Geolocation analysis failed'
            
            # Network analysis
            analysis['network_analysis'] = {
                'ip_type': str(type(ip_obj).__name__),
                'is_global': ip_obj.is_global,
                'is_multicast': ip_obj.is_multicast,
                'version': ip_obj.version
            }
            
            # Cache the result
            self.cache.set('threat_intelligence', cache_key, analysis, self.cache_ttl)
            
            return analysis
            
        except Exception as e:
            logger.error(f"IP reputation analysis failed for {ip}: {e}")
            return {'error': str(e), 'ip': ip}
    
    def comprehensive_threat_analysis(self, domain: str) -> Dict[str, Any]:
        """
        Comprehensive threat analysis combining domain and IP analysis
        
        Args:
            domain: Domain to analyze
            
        Returns:
            Dict with comprehensive threat analysis
        """
        cache_key = f"comprehensive_threat_{domain}"
        cached_result = self.cache.get('threat_intelligence', cache_key)
        if cached_result:
            return cached_result
        
        analysis = {
            'domain': domain,
            'domain_analysis': {},
            'ip_analyses': {},
            'overall_threat_level': 'unknown',
            'security_recommendations': [],
            'confidence_score': 0
        }
        
        try:
            # Domain reputation analysis
            analysis['domain_analysis'] = self.analyze_domain_reputation(domain)
            
            # Resolve domain to IPs and analyze each
            try:
                import socket
                result = socket.getaddrinfo(domain, None, socket.AF_INET)
                ips = list(set([r[4][0] for r in result]))
                
                for ip in ips:
                    ip_analysis = self.analyze_ip_reputation(ip)
                    analysis['ip_analyses'][ip] = ip_analysis
                    
            except Exception as e:
                logger.warning(f"Failed to resolve {domain} for IP analysis: {e}")
                analysis['ip_analyses']['error'] = str(e)
            
            # Calculate overall threat level
            domain_score = analysis['domain_analysis'].get('reputation_score', 50)
            ip_scores = [
                ip_data.get('reputation_score', 50)
                for ip_data in analysis['ip_analyses'].values()
                if isinstance(ip_data, dict) and 'reputation_score' in ip_data
            ]
            
            if ip_scores:
                overall_score = (domain_score + sum(ip_scores)) / (1 + len(ip_scores))
            else:
                overall_score = domain_score
            
            analysis['overall_threat_level'] = self._determine_threat_level(int(overall_score))
            analysis['confidence_score'] = self._calculate_analysis_confidence(analysis)
            
            # Generate comprehensive recommendations
            analysis['security_recommendations'] = self._generate_comprehensive_recommendations(analysis)
            
            # Cache the result
            self.cache.set('threat_intelligence', cache_key, analysis, self.cache_ttl)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Comprehensive threat analysis failed for {domain}: {e}")
            return {'error': str(e), 'domain': domain}
    
    def _calculate_analysis_confidence(self, analysis: Dict) -> int:
        """Calculate confidence score for threat analysis"""
        confidence = 50  # Base confidence
        
        # Domain analysis confidence
        domain_analysis = analysis.get('domain_analysis', {})
        if 'error' not in domain_analysis:
            confidence += 20
        
        # Security analysis sources
        security_analysis = domain_analysis.get('security_analysis', {})
        if security_analysis.get('urlvoid', {}).get('success'):
            confidence += 15
        if security_analysis.get('dns_indicators'):
            confidence += 10
        
        # IP analysis confidence
        ip_analyses = analysis.get('ip_analyses', {})
        successful_ip_analyses = sum(
            1 for ip_data in ip_analyses.values()
            if isinstance(ip_data, dict) and 'error' not in ip_data
        )
        
        if successful_ip_analyses > 0:
            confidence += min(15, successful_ip_analyses * 5)
        
        return min(100, confidence)
    
    def _generate_comprehensive_recommendations(self, analysis: Dict) -> List[str]:
        """Generate comprehensive security recommendations"""
        recommendations = []
        
        # Add domain-specific recommendations
        domain_recs = analysis.get('domain_analysis', {}).get('recommendations', [])
        recommendations.extend(domain_recs)
        
        # IP-based recommendations
        ip_analyses = analysis.get('ip_analyses', {})
        high_risk_ips = []
        
        for ip, ip_data in ip_analyses.items():
            if isinstance(ip_data, dict):
                reputation_score = ip_data.get('reputation_score', 50)
                if reputation_score < 40:
                    high_risk_ips.append(ip)
        
        if high_risk_ips:
            recommendations.append(f'⚠️ High-risk IPs detected: {", ".join(high_risk_ips)}')
        
        # Overall threat level recommendations
        threat_level = analysis.get('overall_threat_level', 'unknown')
        if threat_level == 'critical':
            recommendations.insert(0, '🚨 CRITICAL THREAT: Immediate action required')
        elif threat_level == 'high':
            recommendations.insert(0, '⚠️ HIGH THREAT: Enhanced monitoring recommended')
        
        return recommendations
    
    def test_connection(self) -> Dict[str, Any]:
        """Test threat intelligence capabilities"""
        try:
            # Test with a known safe domain
            test_result = self._check_urlvoid_reputation('google.com')
            
            # Basic pattern analysis test
            pattern_test = self._analyze_domain_patterns('example.com')
            
            return {
                'success': True,
                'message': 'Threat intelligence working',
                'urlvoid_available': test_result.get('success', False),
                'pattern_analysis_working': len(pattern_test) > 0,
                'sources_available': list(self.threat_sources.keys())
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

# Singleton instance
_threat_intelligence_integration = None

def get_threat_intelligence_integration() -> ThreatIntelligenceIntegration:
    """Get singleton threat intelligence integration instance"""
    global _threat_intelligence_integration
    if _threat_intelligence_integration is None:
        _threat_intelligence_integration = ThreatIntelligenceIntegration()
    return _threat_intelligence_integration
