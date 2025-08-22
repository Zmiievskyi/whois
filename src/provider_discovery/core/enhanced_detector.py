#!/usr/bin/env python3
"""
Enhanced Provider Detection Engine
Integrates all 6 FREE data sources for comprehensive provider detection:
1. SSL Certificate Analysis
2. Enhanced DNS Framework 
3. Geographic Intelligence
4. BGP Analysis (BGPView + Hurricane Electric)
5. Threat Intelligence
6. Original detection methods
"""

import logging
from typing import Dict, List, Optional, Any, Set, Union
from datetime import datetime

# Import original detector
from .detector import ProviderDetector

# Import all new FREE integrations
from ..integrations import (
    SSL_INTEGRATION_AVAILABLE, get_ssl_analysis_integration,
    ENHANCED_DNS_INTEGRATION_AVAILABLE, get_enhanced_dns_integration, 
    GEO_INTEGRATION_AVAILABLE, get_geo_intelligence_integration,
    BGP_INTEGRATION_AVAILABLE, get_bgp_analysis_integration,
    THREAT_INTEGRATION_AVAILABLE, get_threat_intelligence_integration,
    HURRICANE_ELECTRIC_INTEGRATION_AVAILABLE, get_hurricane_electric_integration
)

logger = logging.getLogger(__name__)

class EnhancedProviderDetector(ProviderDetector):
    """
    Enhanced Provider Detection Engine with 6 FREE data sources
    
    Comprehensive multi-layer analysis combining:
    - Original detection methods (headers, IP ranges, DNS, WHOIS)
    - SSL certificate analysis and security scoring
    - Enhanced DNS with DoH and multiple resolvers
    - Geographic intelligence and IP geolocation
    - BGP analysis with dual sources (BGPView + Hurricane Electric)
    - Threat intelligence and security assessment
    """
    
    def __init__(self, vt_api_key: Optional[str] = None):
        """
        Initialize enhanced detector with all FREE integrations
        
        Args:
            vt_api_key: Optional VirusTotal API key
        """
        # Initialize base detector
        super().__init__(vt_api_key)
        
        # Initialize all FREE integrations
        self.ssl_analyzer = None
        self.enhanced_dns = None
        self.geo_intel = None
        self.bgp_analyzer = None
        self.hurricane_electric = None
        self.threat_intel = None
        
        # Initialize available integrations
        self._initialize_free_integrations()
        
        logger.info("🚀 Enhanced Provider Detector initialized with all FREE integrations")
        logger.info(f"✅ Available enhancements: {self._get_available_enhancements()}")
    
    def _initialize_free_integrations(self):
        """Initialize all available FREE integrations"""
        
        # SSL Certificate Analysis
        if SSL_INTEGRATION_AVAILABLE:
            try:
                self.ssl_analyzer = get_ssl_analysis_integration()
                logger.info("✅ SSL Certificate Analysis integration loaded")
            except Exception as e:
                logger.warning(f"⚠️ SSL integration failed: {e}")
        
        # Enhanced DNS
        if ENHANCED_DNS_INTEGRATION_AVAILABLE:
            try:
                self.enhanced_dns = get_enhanced_dns_integration()
                logger.info("✅ Enhanced DNS integration loaded")
            except Exception as e:
                logger.warning(f"⚠️ Enhanced DNS integration failed: {e}")
        
        # Geographic Intelligence
        if GEO_INTEGRATION_AVAILABLE:
            try:
                self.geo_intel = get_geo_intelligence_integration()
                logger.info("✅ Geographic Intelligence integration loaded")
            except Exception as e:
                logger.warning(f"⚠️ Geographic intelligence integration failed: {e}")
        
        # BGP Analysis
        if BGP_INTEGRATION_AVAILABLE:
            try:
                self.bgp_analyzer = get_bgp_analysis_integration()
                logger.info("✅ BGP Analysis integration loaded")
            except Exception as e:
                logger.warning(f"⚠️ BGP integration failed: {e}")
        
        # Hurricane Electric BGP
        if HURRICANE_ELECTRIC_INTEGRATION_AVAILABLE:
            try:
                self.hurricane_electric = get_hurricane_electric_integration()
                logger.info("✅ Hurricane Electric BGP integration loaded")
            except Exception as e:
                logger.warning(f"⚠️ Hurricane Electric integration failed: {e}")
        
        # Threat Intelligence
        if THREAT_INTEGRATION_AVAILABLE:
            try:
                self.threat_intel = get_threat_intelligence_integration()
                logger.info("✅ Threat Intelligence integration loaded")
            except Exception as e:
                logger.warning(f"⚠️ Threat intelligence integration failed: {e}")
    
    def _get_available_enhancements(self) -> List[str]:
        """Get list of available enhancements"""
        enhancements = []
        if self.ssl_analyzer: enhancements.append("SSL Analysis")
        if self.enhanced_dns: enhancements.append("Enhanced DNS")
        if self.geo_intel: enhancements.append("Geographic Intelligence")
        if self.bgp_analyzer: enhancements.append("BGP Analysis")
        if self.hurricane_electric: enhancements.append("Hurricane Electric BGP")
        if self.threat_intel: enhancements.append("Threat Intelligence")
        return enhancements
    
    def detect_provider_comprehensive(self, headers: str, ip: str, whois_data: str, domain: str) -> Dict[str, Any]:
        """
        Comprehensive provider detection using all 6 FREE data sources
        
        Args:
            headers: HTTP headers
            ip: IP address
            whois_data: WHOIS data
            domain: Domain name
            
        Returns:
            Complete detection results with all enhancements
        """
        logger.info(f"🔍 Starting comprehensive analysis for domain: {domain}")
        
        # Start with original enhanced detection
        logger.info(f"📊 Step 1/7: Running base provider detection...")
        result = self.detect_provider_ultimate_with_virustotal(headers, ip, whois_data, domain)
        logger.info(f"✅ Step 1/7: Base detection completed")
        
        # Initialize comprehensive analysis sections
        result['Enhanced_Analysis'] = {
            'ssl_analysis': {},
            'enhanced_dns': {},
            'geographic_intelligence': {},
            'bgp_analysis': {},
            'hurricane_electric_bgp': {},
            'threat_intelligence': {},
            'cross_validation': {},
            'security_assessment': {}
        }
        
        # Enhanced confidence tracking
        result['enhanced_confidence_factors'] = []
        result['security_findings'] = []
        result['geographic_insights'] = []
        result['bgp_insights'] = []
        
        # Layer 1: SSL Certificate Analysis
        if self.ssl_analyzer:
            logger.info(f"📊 Step 2/7: Running SSL certificate analysis...")
            result = self._enhance_with_ssl_analysis(result, domain)
            logger.info(f"✅ Step 2/7: SSL analysis completed")
        
        # Layer 2: Enhanced DNS Analysis
        if self.enhanced_dns:
            logger.info(f"📊 Step 3/7: Running enhanced DNS analysis...")
            result = self._enhance_with_enhanced_dns(result, domain)
            logger.info(f"✅ Step 3/7: DNS analysis completed")
        
        # Layer 3: Geographic Intelligence
        if self.geo_intel and ip and 'failed' not in ip:
            logger.info(f"📊 Step 4/7: Running geographic intelligence analysis...")
            result = self._enhance_with_geographic_intelligence(result, ip)
            logger.info(f"✅ Step 4/7: Geographic analysis completed")
        
        # Layer 4: BGP Analysis (dual sources)
        if ip and 'failed' not in ip:
            logger.info(f"📊 Step 5/7: Running BGP analysis...")
            result = self._enhance_with_bgp_analysis(result, ip)
            logger.info(f"✅ Step 5/7: BGP analysis completed")
        
        # Layer 5: Threat Intelligence Assessment
        if self.threat_intel:
            logger.info(f"📊 Step 6/7: Running threat intelligence analysis...")
            result = self._enhance_with_threat_intelligence(result, domain, ip)
            logger.info(f"✅ Step 6/7: Threat intelligence analysis completed")
        
        # Layer 6: Cross-validation and confidence enhancement
        logger.info(f"📊 Step 7/7: Running cross-validation and final calculations...")
        result = self._perform_cross_validation(result)
        logger.info(f"✅ Step 7/7: Cross-validation completed")
        
        # Organize providers by role and determine primary provider
        if result.get('providers'):
            organized = self._organize_providers_by_role(result['providers'])
            result.update(organized)
        
        # Calculate enhanced confidence score
        result['Enhanced_Confidence'] = self._calculate_enhanced_confidence(result)
        
        # Ensure primary_provider is set for compatibility with app.py
        if 'primary_provider' not in result:
            result['primary_provider'] = result.get('Primary_Provider', 'Unknown')
        
        # Generate comprehensive recommendations
        result['Recommendations'] = self._generate_comprehensive_recommendations(result)
        
        logger.info(f"✅ Comprehensive analysis completed for {domain}")
        return result
    
    def _enhance_with_ssl_analysis(self, result: Dict, domain: str) -> Dict:
        """Enhance detection with SSL certificate analysis"""
        try:
            logger.debug(f"🔒 Analyzing SSL certificates for {domain}")
            ssl_result = self.ssl_analyzer.analyze_domain_ssl(domain)
            
            if 'error' not in ssl_result:
                result['Enhanced_Analysis']['ssl_analysis'] = ssl_result
                
                # Extract provider insights from certificates
                cert_providers = []
                ssl_insights = ssl_result.get('certificate_insights', {})
                
                # Certificate Authority insights
                ca_info = ssl_insights.get('certificate_authority', {})
                if ca_info.get('provider_hints'):
                    for hint in ca_info['provider_hints']:
                        cert_providers.append({
                            'name': hint,
                            'role': 'SSL Certificate Authority',
                            'confidence': 'Medium',
                            'source': 'SSL Certificate',
                            'evidence': f"CA: {ca_info.get('issuer', 'Unknown')}"
                        })
                
                # Add to providers list
                result['providers'].extend(cert_providers)
                
                # Security assessment
                security_score = ssl_result.get('security_assessment', {}).get('overall_grade', 'Unknown')
                if security_score != 'Unknown':
                    result['security_findings'].append(f"SSL Security Grade: {security_score}")
                    result['enhanced_confidence_factors'].append(f"SSL certificate analysis completed (Grade: {security_score})")
                
                # Certificate chain insights
                chain_analysis = ssl_result.get('certificate_chain_analysis', {})
                if chain_analysis.get('provider_indicators'):
                    for indicator in chain_analysis['provider_indicators']:
                        result['enhanced_confidence_factors'].append(f"SSL: {indicator}")
                
                result['analysis_methods'].append('SSL Certificate Analysis')
                
        except Exception as e:
            logger.error(f"SSL analysis failed for {domain}: {e}")
            result['Enhanced_Analysis']['ssl_analysis'] = {'error': str(e)}
        
        return result
    
    def _enhance_with_enhanced_dns(self, result: Dict, domain: str) -> Dict:
        """Enhance detection with advanced DNS analysis"""
        try:
            logger.debug(f"🌐 Enhanced DNS analysis for {domain}")
            
            # Multi-resolver analysis
            resolver_result = self.enhanced_dns.comprehensive_dns_analysis(domain)
            result['Enhanced_Analysis']['enhanced_dns']['multi_resolver'] = resolver_result
            
            # DoH analysis
            doh_result = self.enhanced_dns.dns_over_https_query(domain)
            result['Enhanced_Analysis']['enhanced_dns']['doh_analysis'] = doh_result
            
            # Simple DNS validation (checking if domain resolves)
            try:
                import socket
                resolved_ip = socket.gethostbyname(domain)
                cross_validation = {
                    'domain_resolves': True,
                    'resolved_ip': resolved_ip,
                    'validation_status': 'success'
                }
            except Exception as e:
                cross_validation = {
                    'domain_resolves': False,
                    'error': str(e),
                    'validation_status': 'failed'
                }
            result['Enhanced_Analysis']['enhanced_dns']['cross_validation'] = cross_validation
            
            # Extract provider insights
            if resolver_result.get('consensus_reached'):
                consensus_data = resolver_result.get('consensus_data', {})
                confidence = resolver_result.get('confidence_score', 0)
                
                result['enhanced_confidence_factors'].append(
                    f"DNS consensus reached across {len(resolver_result.get('resolver_results', {}))} resolvers (confidence: {confidence}%)"
                )
                
                # Check for CDN or proxy indicators
                if consensus_data.get('cname_chain'):
                    for cname in consensus_data['cname_chain']:
                        if any(cdn in cname.lower() for cdn in ['cloudflare', 'cloudfront', 'fastly', 'akamai']):
                            result['enhanced_confidence_factors'].append(f"Enhanced DNS: CDN detected in CNAME chain ({cname})")
            
            # DoH-specific insights
            if doh_result.get('success') and not doh_result.get('error'):
                result['enhanced_confidence_factors'].append("DoH (DNS over HTTPS) analysis completed")
                
                doh_ips = doh_result.get('resolved_ips', [])
                original_ips = result.get('ip_addresses', [])
                if doh_ips and doh_ips != original_ips:
                    result['enhanced_confidence_factors'].append(f"DoH resolved different IPs: {doh_ips}")
            
            result['analysis_methods'].append('Enhanced DNS Analysis')
            
        except Exception as e:
            logger.error(f"Enhanced DNS analysis failed for {domain}: {e}")
            result['Enhanced_Analysis']['enhanced_dns'] = {'error': str(e)}
        
        return result
    
    def _enhance_with_geographic_intelligence(self, result: Dict, ip: str) -> Dict:
        """Enhance detection with geographic intelligence"""
        try:
            logger.debug(f"🌍 Geographic intelligence analysis for {ip}")
            
            # Multi-provider geolocation
            geo_result = self.geo_intel.get_multi_provider_geolocation(ip)
            result['Enhanced_Analysis']['geographic_intelligence'] = geo_result
            
            if geo_result.get('consensus', {}).get('consensus_reached'):
                consensus_data = geo_result['consensus']['consensus_data']
                confidence = geo_result['consensus'].get('confidence_score', geo_result.get('confidence_score', 75))
                
                # Geographic insights
                location_info = f"{consensus_data.get('city', 'Unknown')}, {consensus_data.get('country', 'Unknown')}"
                result['geographic_insights'].append(f"Location: {location_info} (confidence: {confidence}%)")
                
                # ISP and organization
                isp = consensus_data.get('isp')
                org = consensus_data.get('organization')
                if isp:
                    result['geographic_insights'].append(f"ISP: {isp}")
                    # Add ISP as potential provider
                    result['providers'].append({
                        'name': isp,
                        'role': 'Origin',
                        'confidence': 'Medium',
                        'source': 'Geographic Intelligence (ISP)',
                        'evidence': f"IP geolocation: {location_info}"
                    })
                if org and org != isp:
                    result['geographic_insights'].append(f"Organization: {org}")
                    # Add organization as potential provider if different from ISP
                    result['providers'].append({
                        'name': org,
                        'role': 'Organization',
                        'confidence': 'Medium',
                        'source': 'Geographic Intelligence (Org)',
                        'evidence': f"IP geolocation: {location_info}"
                    })
                
                # Provider classification
                provider_classification = geo_result.get('provider_classification', {})
                if provider_classification.get('provider_type') and provider_classification.get('provider_type') != 'unknown':
                    provider_type = provider_classification['provider_type']
                    classification_confidence = provider_classification.get('confidence', 0)
                    
                    result['enhanced_confidence_factors'].append(
                        f"Geographic analysis classified as {provider_type} provider (confidence: {classification_confidence}%)"
                    )
                    
                    # Add provider based on geographic classification
                    if provider_classification.get('provider_name'):
                        result['providers'].append({
                            'name': provider_classification['provider_name'],
                            'role': provider_type.title(),
                            'confidence': 'High' if classification_confidence > 80 else 'Medium',
                            'source': 'Geographic Intelligence',
                            'evidence': f"Multi-provider consensus: {location_info}"
                        })
                
                # Infrastructure insights
                infra_analysis = geo_result.get('infrastructure_analysis', {})
                if infra_analysis.get('infrastructure_type'):
                    infra_type = infra_analysis['infrastructure_type']
                    result['geographic_insights'].append(f"Infrastructure: {infra_type}")
                    
                    if infra_analysis.get('cloud_provider_indicators'):
                        for indicator in infra_analysis['cloud_provider_indicators']:
                            result['enhanced_confidence_factors'].append(f"Cloud indicator: {indicator}")
            
            result['analysis_methods'].append('Geographic Intelligence')
            
        except Exception as e:
            logger.error(f"Geographic intelligence failed for {ip}: {e}")
            result['Enhanced_Analysis']['geographic_intelligence'] = {'error': str(e)}
        
        return result
    
    def _enhance_with_bgp_analysis(self, result: Dict, ip: str) -> Dict:
        """Enhance detection with dual BGP analysis (BGPView + Hurricane Electric)"""
        try:
            logger.debug(f"📡 BGP analysis for {ip}")
            
            bgp_insights = []
            
            # BGPView analysis
            if self.bgp_analyzer:
                bgp_result = self.bgp_analyzer.get_ip_asn_info(ip)
                result['Enhanced_Analysis']['bgp_analysis'] = bgp_result
                
                if 'error' not in bgp_result:
                    # ASN information
                    asn_info = bgp_result.get('asn_info', {})
                    if asn_info.get('asn'):
                        asn = asn_info['asn']
                        asn_name = asn_info.get('name', 'Unknown')
                        bgp_insights.append(f"ASN: AS{asn} ({asn_name})")
                        
                        # Add ASN-based provider
                        result['providers'].append({
                            'name': asn_name,
                            'role': 'Network Operator',
                            'confidence': 'High',
                            'source': 'BGP Analysis',
                            'evidence': f"AS{asn}"
                        })
                    
                    # Prefix information
                    prefix_info = bgp_result.get('prefix_info', {})
                    if prefix_info.get('prefix'):
                        bgp_insights.append(f"Prefix: {prefix_info['prefix']}")
                    
                    # Provider analysis from BGP
                    provider_analysis = bgp_result.get('provider_analysis', {})
                    if provider_analysis.get('primary_provider'):
                        primary_provider = provider_analysis['primary_provider']
                        provider_type = primary_provider.get('type', 'Unknown')
                        provider_name = primary_provider.get('name', 'Unknown')
                        if provider_type != 'Unknown':
                            bgp_insights.append(f"BGP Classification: {provider_type} provider ({provider_name})")
            
            # Hurricane Electric analysis
            if self.hurricane_electric:
                he_result = self.hurricane_electric.comprehensive_bgp_analysis(ip)
                result['Enhanced_Analysis']['hurricane_electric_bgp'] = he_result
                
                if 'error' not in he_result:
                    # Enhanced ASN details
                    asn_analysis = he_result.get('asn_analysis', {})
                    if asn_analysis and 'error' not in asn_analysis:
                        asn = asn_analysis.get('asn')
                        name = asn_analysis.get('name')
                        org = asn_analysis.get('organization')
                        
                        if asn and name:
                            bgp_insights.append(f"HE BGP: AS{asn} - {name}")
                            if org and org != name:
                                bgp_insights.append(f"Organization: {org}")
                        
                        # Peering insights
                        peers = len(asn_analysis.get('peers', []))
                        upstreams = len(asn_analysis.get('upstreams', []))
                        prefixes_v4 = len(asn_analysis.get('prefixes_v4', []))
                        
                        if peers > 0:
                            bgp_insights.append(f"BGP Peers: {peers}")
                        if upstreams > 0:
                            bgp_insights.append(f"Upstreams: {upstreams}")
                        if prefixes_v4 > 0:
                            bgp_insights.append(f"IPv4 Prefixes: {prefixes_v4}")
                    
                    # Routing insights
                    routing_insights = he_result.get('routing_insights', {})
                    if routing_insights:
                        peering_diversity = routing_insights.get('peering_diversity', 'unknown')
                        if peering_diversity != 'unknown':
                            bgp_insights.append(f"Peering Diversity: {peering_diversity}")
                    
                    # Provider analysis from HE
                    he_analysis = he_result.get('provider_analysis', {})
                    if he_analysis.get('primary_provider'):
                        he_provider = he_analysis['primary_provider']
                        he_type = he_provider.get('type', 'Unknown')
                        he_confidence = he_provider.get('confidence', 0)
                        he_name = he_provider.get('name', 'Unknown')
                        
                        if he_name:
                            bgp_insights.append(f"HE Classification: {he_name} ({he_type}, {he_confidence}%)")
                            
                            # Add HE provider if high confidence
                            if he_confidence > 70:
                                result['providers'].append({
                                    'name': he_name,
                                    'role': he_type.title(),
                                    'confidence': 'High' if he_confidence > 85 else 'Medium',
                                    'source': 'Hurricane Electric BGP',
                                    'evidence': f"BGP analysis with {he_confidence}% confidence"
                                })
            
            # Add all BGP insights
            result['bgp_insights'] = bgp_insights
            if bgp_insights:
                result['enhanced_confidence_factors'].append(f"BGP analysis completed with {len(bgp_insights)} insights")
            
            result['analysis_methods'].append('Dual BGP Analysis')
            
        except Exception as e:
            logger.error(f"BGP analysis failed for {ip}: {e}")
            result['Enhanced_Analysis']['bgp_analysis'] = {'error': str(e)}
        
        return result
    
    def _enhance_with_threat_intelligence(self, result: Dict, domain: str, ip: str) -> Dict:
        """Enhance detection with threat intelligence and security assessment"""
        try:
            logger.debug(f"🛡️ Threat intelligence analysis for {domain}")
            
            # Comprehensive threat analysis
            threat_result = self.threat_intel.comprehensive_threat_analysis(domain)
            result['Enhanced_Analysis']['threat_intelligence'] = threat_result
            
            if 'error' not in threat_result:
                # Overall threat assessment
                threat_level = threat_result.get('overall_threat_level', 'unknown')
                confidence_score = threat_result.get('confidence_score', 0)
                
                result['security_findings'].append(f"Threat Level: {threat_level} (confidence: {confidence_score}%)")
                
                # Domain reputation
                domain_analysis = threat_result.get('domain_analysis', {})
                if domain_analysis and 'error' not in domain_analysis:
                    reputation_score = domain_analysis.get('reputation_score', 0)
                    result['security_findings'].append(f"Domain Reputation: {reputation_score}/100")
                    
                    # Pattern analysis insights
                    pattern_analysis = domain_analysis.get('pattern_analysis', {})
                    suspicious_indicators = pattern_analysis.get('suspicious_indicators', [])
                    if suspicious_indicators:
                        result['security_findings'].append(f"Suspicious patterns detected: {len(suspicious_indicators)}")
                    
                    # Security policy detection
                    security_analysis = domain_analysis.get('security_analysis', {})
                    dns_indicators = security_analysis.get('dns_indicators', {})
                    security_policies = dns_indicators.get('security_policies', {})
                    
                    policy_count = sum(1 for v in security_policies.values() if v)
                    if policy_count > 0:
                        result['security_findings'].append(f"Security policies detected: {policy_count}")
                        result['enhanced_confidence_factors'].append(f"DNS security policies found: {list(security_policies.keys())}")
                
                # IP reputation (if available)
                ip_analyses = threat_result.get('ip_analyses', {})
                if ip_analyses and ip and 'failed' not in ip:
                    ip_data = ip_analyses.get(ip, {})
                    if ip_data and 'error' not in ip_data:
                        ip_reputation = ip_data.get('reputation_score', 0)
                        result['security_findings'].append(f"IP Reputation: {ip_reputation}/100")
                
                # Security recommendations
                recommendations = threat_result.get('security_recommendations', [])
                if recommendations:
                    result['security_findings'].extend(recommendations[:3])  # Top 3 recommendations
            
            result['analysis_methods'].append('Threat Intelligence')
            
        except Exception as e:
            logger.error(f"Threat intelligence failed for {domain}: {e}")
            result['Enhanced_Analysis']['threat_intelligence'] = {'error': str(e)}
        
        return result
    
    def _perform_cross_validation(self, result: Dict) -> Dict:
        """Perform cross-validation between different data sources"""
        logger.debug("🔄 Performing cross-validation of results")
        
        cross_validation = {
            'provider_consensus': {},
            'confidence_boosters': [],
            'conflicting_data': [],
            'validation_score': 0
        }
        
        # Count provider mentions across sources
        provider_mentions = {}
        for provider in result.get('providers', []):
            name = provider['name'].lower()
            if name not in provider_mentions:
                provider_mentions[name] = []
            provider_mentions[name].append(provider['source'])
        
        # Find consensus providers (mentioned by multiple sources)
        for provider_name, sources in provider_mentions.items():
            if len(sources) > 1:
                cross_validation['provider_consensus'][provider_name] = {
                    'sources': sources,
                    'confidence_boost': len(sources) * 10  # 10% boost per additional source
                }
                cross_validation['confidence_boosters'].append(
                    f"{provider_name.title()} confirmed by {len(sources)} sources: {', '.join(sources)}"
                )
        
        # Validate geographic vs BGP data
        geo_analysis = result['Enhanced_Analysis'].get('geographic_intelligence', {})
        bgp_analysis = result['Enhanced_Analysis'].get('bgp_analysis', {})
        
        if geo_analysis.get('consensus') and bgp_analysis.get('asn_info'):
            geo_org = geo_analysis['consensus']['consensus_data'].get('organization', '').lower()
            bgp_name = bgp_analysis['asn_info'].get('name', '').lower()
            
            if geo_org and bgp_name and geo_org in bgp_name or bgp_name in geo_org:
                cross_validation['confidence_boosters'].append(
                    f"Geographic and BGP data confirm same organization"
                )
        
        # Calculate validation score
        consensus_count = len(cross_validation['provider_consensus'])
        booster_count = len(cross_validation['confidence_boosters'])
        conflict_count = len(cross_validation['conflicting_data'])
        
        validation_score = (consensus_count * 20) + (booster_count * 10) - (conflict_count * 15)
        cross_validation['validation_score'] = max(0, min(100, validation_score))
        
        result['Enhanced_Analysis']['cross_validation'] = cross_validation
        
        if cross_validation['confidence_boosters']:
            result['enhanced_confidence_factors'].extend(cross_validation['confidence_boosters'])
        
        return result
    
    def _calculate_enhanced_confidence(self, result: Dict) -> int:
        """Calculate enhanced confidence score incorporating all data sources"""
        # Start with original confidence
        base_confidence = result.get('Confidence', 50)
        if isinstance(base_confidence, str):
            try:
                base_confidence = int(base_confidence)
            except (ValueError, TypeError):
                base_confidence = 50
        
        # Enhancement factors
        enhancement_bonus = 0
        
        # Successful analysis bonuses
        enhanced_analysis = result['Enhanced_Analysis']
        
        if enhanced_analysis.get('ssl_analysis') and 'error' not in enhanced_analysis['ssl_analysis']:
            enhancement_bonus += 10
        
        if enhanced_analysis.get('enhanced_dns') and 'error' not in enhanced_analysis['enhanced_dns']:
            enhancement_bonus += 8
        
        if enhanced_analysis.get('geographic_intelligence') and 'error' not in enhanced_analysis['geographic_intelligence']:
            enhancement_bonus += 12
        
        if enhanced_analysis.get('bgp_analysis') and 'error' not in enhanced_analysis['bgp_analysis']:
            enhancement_bonus += 15
        
        if enhanced_analysis.get('hurricane_electric_bgp') and 'error' not in enhanced_analysis['hurricane_electric_bgp']:
            enhancement_bonus += 10
        
        if enhanced_analysis.get('threat_intelligence') and 'error' not in enhanced_analysis['threat_intelligence']:
            enhancement_bonus += 8
        
        # Cross-validation bonus
        cross_validation = enhanced_analysis.get('cross_validation', {})
        validation_bonus = cross_validation.get('validation_score', 0) // 10  # Convert to 0-10 range
        
        # Provider consensus bonus
        consensus_providers = len(cross_validation.get('provider_consensus', {}))
        consensus_bonus = min(15, consensus_providers * 5)
        
        # Calculate final confidence
        enhanced_confidence = base_confidence + enhancement_bonus + validation_bonus + consensus_bonus
        
        return min(100, enhanced_confidence)
    
    def _generate_comprehensive_recommendations(self, result: Dict) -> List[str]:
        """Generate comprehensive recommendations based on all analysis"""
        recommendations = []
        
        # Security recommendations
        threat_analysis = result['Enhanced_Analysis'].get('threat_intelligence', {})
        if threat_analysis and 'error' not in threat_analysis:
            threat_level = threat_analysis.get('overall_threat_level', 'unknown')
            
            if threat_level in ['high', 'critical']:
                recommendations.append("⚠️ High security risk detected - review domain carefully")
            elif threat_level == 'medium':
                recommendations.append("⚠️ Medium security risk - proceed with caution")
            else:
                recommendations.append("✅ Low security risk detected")
        
        # SSL recommendations
        ssl_analysis = result['Enhanced_Analysis'].get('ssl_analysis', {})
        if ssl_analysis and 'error' not in ssl_analysis:
            security_assessment = ssl_analysis.get('security_assessment', {})
            overall_grade = security_assessment.get('overall_grade')
            
            if overall_grade in ['D', 'F']:
                recommendations.append("🔒 SSL certificate needs improvement - low security grade")
            elif overall_grade in ['A', 'A+']:
                recommendations.append("🔒 Excellent SSL security configuration")
        
        # BGP routing recommendations
        bgp_analysis = result['Enhanced_Analysis'].get('bgp_analysis', {})
        he_bgp = result['Enhanced_Analysis'].get('hurricane_electric_bgp', {})
        
        if bgp_analysis or he_bgp:
            # Check for routing stability
            if he_bgp.get('routing_insights', {}).get('peering_diversity') == 'low':
                recommendations.append("📡 Consider improving BGP peering diversity for better redundancy")
        
        # Geographic recommendations
        geo_analysis = result['Enhanced_Analysis'].get('geographic_intelligence', {})
        if geo_analysis and 'error' not in geo_analysis:
            provider_classification = geo_analysis.get('provider_classification', {})
            if provider_classification and provider_classification.get('provider_type') == 'cloud':
                recommendations.append("☁️ Cloud provider detected - good for scalability")
        
        # Cross-validation recommendations
        cross_validation = result['Enhanced_Analysis'].get('cross_validation', {})
        if cross_validation.get('validation_score', 0) > 70:
            recommendations.append("✅ High data consistency across multiple sources")
        elif cross_validation.get('validation_score', 0) < 30:
            recommendations.append("⚠️ Conflicting data detected - manual verification recommended")
        
        # Enhanced confidence recommendations
        enhanced_confidence = result.get('Enhanced_Confidence', 0)
        if enhanced_confidence > 85:
            recommendations.append("🎯 High confidence detection - results highly reliable")
        elif enhanced_confidence < 50:
            recommendations.append("⚠️ Low confidence detection - additional verification needed")
        
        return recommendations[:6]  # Limit to top 6 recommendations
    
    def test_all_integrations(self) -> Dict[str, Any]:
        """Test all FREE integrations"""
        test_results = {
            'ssl_analysis': False,
            'enhanced_dns': False,
            'geographic_intelligence': False,
            'bgp_analysis': False,
            'hurricane_electric': False,
            'threat_intelligence': False,
            'total_available': 0,
            'integration_status': {}
        }
        
        # Test each integration
        if self.ssl_analyzer:
            try:
                ssl_test = self.ssl_analyzer.test_connection()
                test_results['ssl_analysis'] = ssl_test.get('success', False)
                test_results['integration_status']['ssl_analysis'] = ssl_test
                if test_results['ssl_analysis']:
                    test_results['total_available'] += 1
            except Exception as e:
                test_results['integration_status']['ssl_analysis'] = {'error': str(e)}
        
        if self.enhanced_dns:
            try:
                dns_test = self.enhanced_dns.test_resolvers()
                test_results['enhanced_dns'] = dns_test.get('success', False)
                test_results['integration_status']['enhanced_dns'] = dns_test
                if test_results['enhanced_dns']:
                    test_results['total_available'] += 1
            except Exception as e:
                test_results['integration_status']['enhanced_dns'] = {'error': str(e)}
        
        if self.geo_intel:
            try:
                geo_test = self.geo_intel.test_all_providers()
                test_results['geographic_intelligence'] = geo_test.get('success', False)
                test_results['integration_status']['geographic_intelligence'] = geo_test
                if test_results['geographic_intelligence']:
                    test_results['total_available'] += 1
            except Exception as e:
                test_results['integration_status']['geographic_intelligence'] = {'error': str(e)}
        
        if self.bgp_analyzer:
            try:
                bgp_test = self.bgp_analyzer.test_connection()
                # Consider BGP as available even if rate limited (since Hurricane Electric fallback exists)
                is_available = bgp_test.get('success', False) or bgp_test.get('rate_limited', False)
                test_results['bgp_analysis'] = is_available
                test_results['integration_status']['bgp_analysis'] = bgp_test
                if is_available:
                    test_results['total_available'] += 1
            except Exception as e:
                test_results['integration_status']['bgp_analysis'] = {'error': str(e)}
        
        if self.hurricane_electric:
            try:
                he_test = self.hurricane_electric.test_connection()
                test_results['hurricane_electric'] = he_test.get('success', False)
                test_results['integration_status']['hurricane_electric'] = he_test
                if test_results['hurricane_electric']:
                    test_results['total_available'] += 1
            except Exception as e:
                test_results['integration_status']['hurricane_electric'] = {'error': str(e)}
        
        if self.threat_intel:
            try:
                threat_test = self.threat_intel.test_connection()
                test_results['threat_intelligence'] = threat_test.get('success', False)
                test_results['integration_status']['threat_intelligence'] = threat_test
                if test_results['threat_intelligence']:
                    test_results['total_available'] += 1
            except Exception as e:
                test_results['integration_status']['threat_intelligence'] = {'error': str(e)}
        
        return test_results

# Singleton instance
_enhanced_detector = None

def get_enhanced_provider_detector(vt_api_key: Optional[str] = None) -> EnhancedProviderDetector:
    """Get singleton enhanced provider detector instance"""
    global _enhanced_detector
    if _enhanced_detector is None:
        _enhanced_detector = EnhancedProviderDetector(vt_api_key)
    return _enhanced_detector
