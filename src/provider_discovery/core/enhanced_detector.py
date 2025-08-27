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
    HURRICANE_ELECTRIC_INTEGRATION_AVAILABLE, get_hurricane_electric_integration,
    ADVANCED_BGP_CLASSIFIER_AVAILABLE, get_advanced_bgp_classifier,
    SHODAN_INTEGRATION_AVAILABLE, get_shodan_integration
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
        self.advanced_bgp_classifier = None
        self.shodan_integration = None
        
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
        
        # Advanced BGP Classifier
        if ADVANCED_BGP_CLASSIFIER_AVAILABLE:
            try:
                self.advanced_bgp_classifier = get_advanced_bgp_classifier()
                logger.info("✅ Advanced BGP Classifier integration loaded")
            except Exception as e:
                logger.warning(f"⚠️ Advanced BGP Classifier integration failed: {e}")
        
        # Shodan Integration (Premium WAF Detection)
        if SHODAN_INTEGRATION_AVAILABLE:
            try:
                self.shodan_integration = get_shodan_integration()
                if self.shodan_integration and self.shodan_integration.is_enabled:
                    logger.info("✅ Shodan Premium WAF integration loaded")
                else:
                    logger.info("⚠️ Shodan integration available but not configured (no API key)")
            except Exception as e:
                logger.warning(f"⚠️ Shodan integration failed: {e}")
    
    def _get_available_enhancements(self) -> List[str]:
        """Get list of available enhancements"""
        enhancements = []
        if self.ssl_analyzer: enhancements.append("SSL Analysis")
        if self.enhanced_dns: enhancements.append("Enhanced DNS")
        if self.geo_intel: enhancements.append("Geographic Intelligence")
        if self.bgp_analyzer: enhancements.append("BGP Analysis")
        if self.hurricane_electric: enhancements.append("Hurricane Electric BGP")
        if self.threat_intel: enhancements.append("Threat Intelligence")
        if self.advanced_bgp_classifier: enhancements.append("Advanced BGP Classifier")
        if self.shodan_integration and self.shodan_integration.is_enabled: 
            enhancements.append("Shodan Premium WAF")
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
        
        # Add analysis timestamp
        from datetime import datetime
        analysis_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Start with original enhanced detection
        logger.info(f"📊 Step 1/8: Running base provider detection...")
        result = self.detect_provider_ultimate_with_virustotal(headers, ip, whois_data, domain)
        
        # Ensure URL field is set
        if not result.get('URL') and domain:
            result['URL'] = domain
            
        logger.info(f"✅ Step 1/9: Base detection completed")
        
        # Initialize step-by-step analysis report
        result['analysis_steps_report'] = {
            'step_1_base_detection': {'status': 'pending', 'findings': [], 'confidence_impact': 0},
            'step_2_ssl_analysis': {'status': 'pending', 'findings': [], 'confidence_impact': 0},
            'step_3_enhanced_dns': {'status': 'pending', 'findings': [], 'confidence_impact': 0},
            'step_4_geographic_intel': {'status': 'pending', 'findings': [], 'confidence_impact': 0},
            'step_5_bgp_analysis': {'status': 'pending', 'findings': [], 'confidence_impact': 0},
            'step_6_advanced_bgp_classification': {'status': 'pending', 'findings': [], 'confidence_impact': 0},
            'step_7_threat_intelligence': {'status': 'pending', 'findings': [], 'confidence_impact': 0},
            'step_8_shodan_waf_analysis': {'status': 'pending', 'findings': [], 'confidence_impact': 0},
            'step_9_cross_validation': {'status': 'pending', 'findings': [], 'confidence_impact': 0}
        }
        
        # Record Step 1 results
        step_1_findings = []
        if result.get('providers'):
            step_1_findings.append(f"Detected {len(result['providers'])} providers")
            if result.get('primary_provider'):
                step_1_findings.append(f"Primary provider: {result['primary_provider']}")
        
        result['analysis_steps_report']['step_1_base_detection'] = {
            'status': 'completed',
            'step_name': 'Base Provider Detection',
            'findings': step_1_findings,
            'confidence_impact': 15,  # Base detection provides foundation
            'methods': ['HTTP Headers', 'IP Ranges', 'WHOIS', 'DNS Resolution']
        }
        
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
        
        # Layer 2: SSL Certificate Analysis
        if self.ssl_analyzer:
            logger.info(f"📊 Step 2/9: Running SSL certificate analysis...")
            result = self._enhance_with_ssl_analysis(result, domain)
            logger.info(f"✅ Step 2/9: SSL analysis completed")
        
        # Layer 3: Enhanced DNS Analysis
        if self.enhanced_dns:
            logger.info(f"📊 Step 3/9: Running enhanced DNS analysis...")
            result = self._enhance_with_enhanced_dns(result, domain)
            logger.info(f"✅ Step 3/9: DNS analysis completed")
        
        # Layer 4: Geographic Intelligence
        if self.geo_intel and ip and 'failed' not in ip:
            logger.info(f"📊 Step 4/9: Running geographic intelligence analysis...")
            result = self._enhance_with_geographic_intelligence(result, ip)
            logger.info(f"✅ Step 4/9: Geographic analysis completed")
        
        # Layer 5: BGP Analysis (dual sources)
        if ip and 'failed' not in ip:
            logger.info(f"📊 Step 5/9: Running BGP analysis...")
            result = self._enhance_with_bgp_analysis(result, ip)
            logger.info(f"✅ Step 5/9: BGP analysis completed")
        
        # Layer 6: Advanced BGP Customer Classification
        if self.advanced_bgp_classifier and ip and 'failed' not in ip:
            logger.info(f"📊 Step 6/9: Running advanced BGP customer classification...")
            result = self._enhance_with_advanced_bgp_classification(result, ip)
            logger.info(f"✅ Step 6/9: Advanced BGP classification completed")
        
        # Layer 7: Threat Intelligence Assessment
        if self.threat_intel:
            logger.info(f"📊 Step 7/9: Running threat intelligence analysis...")
            result = self._enhance_with_threat_intelligence(result, domain, ip)
            logger.info(f"✅ Step 7/9: Threat intelligence analysis completed")
        
        # Layer 8: Shodan Premium WAF Analysis
        if self.shodan_integration and self.shodan_integration.is_enabled:
            logger.info(f"📊 Step 8/9: Running Shodan premium WAF analysis...")
            result = self._enhance_with_shodan_analysis(result, domain, ip)
            logger.info(f"✅ Step 8/9: Shodan WAF analysis completed")
        
        # Layer 9: Cross-validation and confidence enhancement
        logger.info(f"📊 Step 9/9: Running cross-validation and final calculations...")
        result = self._perform_cross_validation(result)
        logger.info(f"✅ Step 9/9: Cross-validation completed")
        
        # Organize providers by role and determine primary provider
        if result.get('providers'):
            organized = self._organize_providers_by_role(result['providers'])
            result.update(organized)
        
        # Calculate enhanced confidence score
        result['Enhanced_Confidence'] = self._calculate_enhanced_confidence(result)
        
        # Ensure primary_provider is set for compatibility with app.py
        if 'primary_provider' not in result:
            result['primary_provider'] = result.get('Primary_Provider', 'Unknown')
        
        # Add timestamp to result
        result['timestamp'] = analysis_timestamp
        
        # Generate comprehensive recommendations
        result['Recommendations'] = self._generate_comprehensive_recommendations(result)
        
        # Record all step results for comprehensive report
        self._record_all_step_results(result)
        
        # Save analysis results to backend
        self._save_analysis_to_backend(result, domain)
        
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
    
    def _enhance_with_advanced_bgp_classification(self, result: Dict, ip: str) -> Dict:
        """Enhance detection with advanced BGP customer classification"""
        try:
            logger.debug(f"🎯 Advanced BGP customer classification for {ip}")
            
            # Get ASN for IP
            asn_info = None
            if self.bgp_analyzer:
                basic_bgp = self.bgp_analyzer.get_ip_asn_info(ip)
                if 'error' not in basic_bgp and 'prefixes' in basic_bgp:
                    for prefix in basic_bgp['prefixes']:
                        if 'asn' in prefix and 'asn' in prefix['asn']:
                            asn_info = prefix['asn']['asn']
                            break
            
            if asn_info:
                # Run comprehensive ASN classification
                classification_result = self.advanced_bgp_classifier.classify_asn_comprehensive(asn_info, ip)
                result['Enhanced_Analysis']['advanced_bgp_classification'] = classification_result
                
                if 'error' not in classification_result:
                    classification = classification_result.get('classification', 'UNKNOWN')
                    confidence = classification_result.get('confidence', 0.0)
                    evidence = classification_result.get('evidence', [])
                    data_sources = classification_result.get('data_sources', [])
                    
                    # Update confidence factors
                    if confidence > 0.8:
                        result['enhanced_confidence_factors'].append(
                            f"Advanced BGP classification: {classification} ({confidence:.1%} confidence)"
                        )
                    
                    # Add customer classification insights
                    classification_insights = []
                    classification_insights.append(f"Customer Type: {classification}")
                    classification_insights.append(f"Classification Confidence: {confidence:.1%}")
                    classification_insights.append(f"Data Sources: {', '.join(data_sources)}")
                    
                    if evidence:
                        top_evidence = evidence[:2]  # Top 2 pieces of evidence
                        classification_insights.append(f"Key Evidence: {', '.join(top_evidence)}")
                    
                    # Store insights
                    result['bgp_customer_insights'] = classification_insights
                    
                    # Adjust provider classification based on customer type
                    if classification in ['END_CUSTOMER', 'ENTERPRISE_CUSTOMER']:
                        # This suggests the IP belongs to an end customer, not hosting provider
                        result['enhanced_confidence_factors'].append(
                            "ASN classified as end customer - not a hosting provider"
                        )
                    elif classification in ['HOSTING_PROVIDER', 'CLOUD_PROVIDER', 'CDN_PROVIDER']:
                        # Confirms this is a service provider
                        result['enhanced_confidence_factors'].append(
                            f"ASN confirmed as {classification.lower().replace('_', ' ')}"
                        )
                        
                        # Add provider role
                        provider_role = 'Hosting Provider'
                        if 'CDN' in classification:
                            provider_role = 'CDN'
                        elif 'CLOUD' in classification:
                            provider_role = 'Cloud Provider'
                        
                        # Update existing providers or add new one
                        updated_existing = False
                        for provider in result.get('providers', []):
                            if provider.get('source') == 'BGP Analysis':
                                provider['role'] = provider_role
                                provider['confidence'] = 'High' if confidence > 0.85 else 'Medium'
                                updated_existing = True
                                break
                        
                        if not updated_existing:
                            result.setdefault('providers', []).append({
                                'name': f"AS{asn_info}",
                                'role': provider_role,
                                'confidence': 'High' if confidence > 0.85 else 'Medium',
                                'source': 'Advanced BGP Classification',
                                'evidence': f"{classification} with {confidence:.1%} confidence"
                            })
                    
                    result['analysis_methods'].append('Advanced BGP Customer Classification')
                    
            else:
                logger.debug("No ASN found for advanced BGP classification")
                result['Enhanced_Analysis']['advanced_bgp_classification'] = {
                    'error': 'No ASN information available'
                }
            
        except Exception as e:
            logger.error(f"Advanced BGP classification failed for {ip}: {e}")
            result['Enhanced_Analysis']['advanced_bgp_classification'] = {'error': str(e)}
        
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
    
    def _enhance_with_shodan_analysis(self, result: Dict, domain: str, ip: str) -> Dict:
        """Enhanced Shodan analysis with comprehensive provider classification and security assessment"""
        try:
            logger.debug(f"🛡️ Enhanced Shodan analysis for {domain}")
            
            # Initialize Shodan analysis section
            shodan_analysis = {}
            
            # WAF Detection (original functionality)
            if domain:
                waf_result = self.shodan_integration.detect_waf(domain)
                shodan_analysis['waf_detection'] = waf_result
                
                if waf_result.get('success') and waf_result.get('waf_detected'):
                    # Add WAF provider to results
                    waf_type = waf_result.get('waf_type', 'Unknown WAF')
                    confidence = waf_result.get('confidence', 0)
                    
                    # Add to providers with WAF role
                    waf_provider = {
                        'name': waf_type,
                        'role': 'WAF',
                        'confidence': 'High' if confidence > 80 else 'Medium' if confidence > 50 else 'Low',
                        'source': 'Shodan Premium WAF',
                        'evidence': f"WAF detected with {confidence}% confidence"
                    }
                    result['providers'].append(waf_provider)
                    
                    # Update security findings
                    result['security_findings'].append(f"WAF Detected: {waf_type} (Shodan confidence: {confidence}%)")
                    
                    # Add to confidence factors
                    result['enhanced_confidence_factors'].append(f"Shodan WAF detection: {waf_type}")
            
            # Enhanced Technology Stack Analysis
            if domain:
                tech_result = self.shodan_integration.get_technology_stack(domain)
                shodan_analysis['technology_stack'] = tech_result
                
                if tech_result.get('success'):
                    # Provider Classification Enhancement
                    provider_classification = tech_result.get('provider_classification', {})
                    
                    # Add cloud providers
                    cloud_providers = provider_classification.get('cloud_providers', [])
                    for cloud in cloud_providers:
                        cloud_provider = {
                            'name': cloud,
                            'role': 'Cloud',
                            'confidence': 'High',
                            'source': 'Shodan Provider Classification',
                            'evidence': 'Detected via Shodan infrastructure analysis'
                        }
                        result['providers'].append(cloud_provider)
                        result['enhanced_confidence_factors'].append(f"Shodan cloud provider: {cloud}")
                    
                    # Add CDN providers
                    cdn_providers = provider_classification.get('cdn_providers', [])
                    for cdn in cdn_providers:
                        cdn_provider = {
                            'name': cdn,
                            'role': 'CDN',
                            'confidence': 'High',
                            'source': 'Shodan CDN Classification',
                            'evidence': 'Detected via Shodan CDN analysis'
                        }
                        result['providers'].append(cdn_provider)
                        result['enhanced_confidence_factors'].append(f"Shodan CDN detection: {cdn}")
                    
                    # Add WAF providers
                    waf_providers = provider_classification.get('waf_providers', [])
                    for waf in waf_providers:
                        waf_provider = {
                            'name': waf,
                            'role': 'WAF',
                            'confidence': 'High',
                            'source': 'Shodan WAF Classification',
                            'evidence': 'Detected via Shodan security analysis'
                        }
                        result['providers'].append(waf_provider)
                        result['enhanced_confidence_factors'].append(f"Shodan WAF provider: {waf}")
                    
                    # Technology analysis
                    technologies = tech_result.get('technologies', [])
                    if technologies:
                        result['security_findings'].append(f"Technologies identified: {len(technologies)} (Shodan Enhanced)")
                    
                    # Security Assessment Integration
                    security_assessment = tech_result.get('security_assessment', {})
                    if security_assessment:
                        security_score = security_assessment.get('security_score', 0)
                        if security_score > 0:
                            result['security_findings'].append(f"Shodan Security Score: {security_score}/100")
                        
                        # Security recommendations
                        recommendations = security_assessment.get('recommendations', [])
                        for rec in recommendations[:2]:  # Add top 2 recommendations
                            result['security_findings'].append(f"Shodan: {rec}")
                        
                        # WAF indicators from security analysis
                        waf_indicators = security_assessment.get('waf_indicators', [])
                        if waf_indicators:
                            result['security_findings'].append(f"WAF indicators detected: {len(waf_indicators)}")
                    
                    # Infrastructure Mapping
                    infrastructure_mapping = tech_result.get('infrastructure_mapping', {})
                    if infrastructure_mapping:
                        # Geographic insights
                        geo_distribution = infrastructure_mapping.get('geographic_distribution', {})
                        if geo_distribution:
                            primary_location = list(geo_distribution.keys())[0] if geo_distribution else 'Unknown'
                            result['geographic_insights'].append(f"Shodan: Primary location - {primary_location}")
                        
                        # ASN analysis
                        asn_analysis = infrastructure_mapping.get('asn_analysis', {})
                        if asn_analysis:
                            result['enhanced_confidence_factors'].append(f"Shodan ASN mapping: {len(asn_analysis)} networks")
                        
                        # Hosting patterns
                        hosting_patterns = infrastructure_mapping.get('hosting_patterns', [])
                        for pattern in hosting_patterns[:3]:  # Add top 3 patterns
                            result['enhanced_confidence_factors'].append(f"Shodan hosting pattern: {pattern}")
                    
                    # Vulnerability Analysis
                    vulnerability_analysis = tech_result.get('vulnerability_analysis', {})
                    if vulnerability_analysis:
                        vulnerabilities_found = vulnerability_analysis.get('vulnerabilities_found', [])
                        risk_score = vulnerability_analysis.get('risk_score', 0)
                        
                        if vulnerabilities_found:
                            result['security_findings'].append(f"Vulnerabilities found: {len(vulnerabilities_found)} (Shodan)")
                        
                        if risk_score > 0:
                            result['security_findings'].append(f"Shodan Risk Score: {risk_score}/100")
                        
                        # Security recommendations from vulnerability analysis
                        vuln_recommendations = vulnerability_analysis.get('security_recommendations', [])
                        for rec in vuln_recommendations[:2]:
                            result['security_findings'].append(f"Vuln: {rec}")
                    
                    # SSL Trust Analysis
                    ssl_trust_analysis = tech_result.get('ssl_trust_analysis', {})
                    if ssl_trust_analysis:
                        trust_score = ssl_trust_analysis.get('trust_score', 0)
                        if trust_score > 0:
                            result['security_findings'].append(f"SSL Trust Score: {trust_score}/100 (Shodan)")
                        
                        certificate_authorities = ssl_trust_analysis.get('certificate_authorities', [])
                        if certificate_authorities:
                            primary_ca = certificate_authorities[0] if certificate_authorities else 'Unknown'
                            result['enhanced_confidence_factors'].append(f"Shodan SSL CA: {primary_ca}")
                    
                    # Data Richness Score
                    data_richness_score = tech_result.get('data_richness_score', 0)
                    total_hosts_analyzed = tech_result.get('total_hosts_analyzed', 0)
                    
                    if data_richness_score > 0:
                        result['enhanced_confidence_factors'].append(f"Shodan data richness: {data_richness_score}/100")
                    
                    if total_hosts_analyzed > 0:
                        result['enhanced_confidence_factors'].append(f"Shodan hosts analyzed: {total_hosts_analyzed}")
            
            # IP Analysis (enhanced)
            if ip and 'failed' not in ip:
                ip_result = self.shodan_integration.search_by_ip(ip)
                shodan_analysis['ip_analysis'] = ip_result
                
                if ip_result.get('success'):
                    host_info = ip_result.get('host_info', {})
                    analysis = ip_result.get('analysis', {})
                    
                    # Provider classification from IP analysis
                    cloud_provider = analysis.get('cloud_provider')
                    if cloud_provider:
                        cloud_provider_entry = {
                            'name': cloud_provider,
                            'role': 'Cloud',
                            'confidence': 'High',
                            'source': 'Shodan IP Analysis',
                            'evidence': f"Detected via Shodan host analysis"
                        }
                        result['providers'].append(cloud_provider_entry)
                        result['enhanced_confidence_factors'].append(f"Shodan IP cloud: {cloud_provider}")
                    
                    # Security analysis from IP
                    security_score = analysis.get('security_score', 0)
                    if security_score > 0:
                        result['security_findings'].append(f"IP Security Score: {security_score}/100 (Shodan)")
                    
                    # Organization info
                    org = host_info.get('org', '')
                    if org and org != 'Unknown':
                        result['enhanced_confidence_factors'].append(f"Shodan organization: {org}")
            
            # Store complete Shodan analysis
            result['Enhanced_Analysis']['shodan_analysis'] = shodan_analysis
            
            # Update analysis methods
            if 'analysis_methods' not in result:
                result['analysis_methods'] = []
            result['analysis_methods'].append('Shodan Enhanced Infrastructure Analysis')
            
            logger.debug(f"✅ Enhanced Shodan analysis completed successfully")
            
        except Exception as e:
            logger.error(f"❌ Enhanced Shodan analysis failed: {e}")
            result['Enhanced_Analysis']['shodan_analysis'] = {'error': str(e)}
        
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
            'shodan_integration': False,
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
        
        if self.shodan_integration:
            try:
                shodan_test = self.shodan_integration.test_connection()
                test_results['shodan_integration'] = shodan_test.get('success', False)
                test_results['integration_status']['shodan_integration'] = shodan_test
                if test_results['shodan_integration']:
                    test_results['total_available'] += 1
            except Exception as e:
                test_results['integration_status']['shodan_integration'] = {'error': str(e)}
        
        return test_results
    
    def _record_all_step_results(self, result: Dict) -> None:
        """Record results for all analysis steps"""
        
        # Initialize analysis_steps_report if not exists
        if 'analysis_steps_report' not in result:
            result['analysis_steps_report'] = {}
        
        # Step 2: SSL Analysis
        if 'ssl_analysis' in result.get('Enhanced_Analysis', {}):
            self._record_step_results(result, 'step_2_ssl_analysis', 'SSL Certificate Analysis', 
                                    'ssl_analysis', ['Certificate Authority Detection', 'Security Grading'])
        
        # Step 3: Enhanced DNS
        if 'enhanced_dns' in result.get('Enhanced_Analysis', {}):
            self._record_step_results(result, 'step_3_enhanced_dns', 'Enhanced DNS Analysis', 
                                    'enhanced_dns', ['Multi-Resolver DNS', 'DoH Validation'])
        
        # Step 4: Geographic Intelligence
        if 'geographic_intelligence' in result.get('Enhanced_Analysis', {}):
            self._record_step_results(result, 'step_4_geographic_intel', 'Geographic Intelligence', 
                                    'geographic_intelligence', ['IP Geolocation', 'Provider Classification'])
        
        # Step 5: BGP Analysis
        if 'bgp_analysis' in result.get('Enhanced_Analysis', {}):
            self._record_step_results(result, 'step_5_bgp_analysis', 'BGP Analysis', 
                                    'bgp_analysis', ['ASN Lookup', 'Routing Analysis'])
        
        # Step 6: Advanced BGP Classification
        if 'advanced_bgp_classification' in result.get('Enhanced_Analysis', {}):
            self._record_step_results(result, 'step_6_advanced_bgp_classification', 'Advanced BGP Classification', 
                                    'advanced_bgp_classification', ['Customer Type Detection', 'ML Enhancement'])
        
        # Step 7: Threat Intelligence
        if 'threat_intelligence' in result.get('Enhanced_Analysis', {}):
            self._record_step_results(result, 'step_7_threat_intelligence', 'Threat Intelligence', 
                                    'threat_intelligence', ['Security Assessment', 'Reputation Analysis'])
        
        # Step 8: Shodan Premium WAF Analysis
        if 'shodan_analysis' in result.get('Enhanced_Analysis', {}):
            self._record_step_results(result, 'step_8_shodan_waf_analysis', 'Shodan Premium WAF Analysis', 
                                    'shodan_analysis', ['WAF Detection', 'Technology Stack Analysis', 'IP Security Analysis'])
        
        # Step 9: Cross-validation (always runs)
        cross_validation_findings = []
        total_confidence = result.get('Enhanced_Confidence', 0)
        if total_confidence:
            cross_validation_findings.append(f"Final Confidence Score: {total_confidence}%")
        
        provider_consensus = len(result.get('providers', []))
        if provider_consensus:
            cross_validation_findings.append(f"Provider Consensus: {provider_consensus} sources")
        
        result['analysis_steps_report']['step_9_cross_validation'] = {
            'status': 'completed',
            'step_name': 'Cross-Validation & Final Analysis',
            'findings': cross_validation_findings,
            'confidence_impact': 10,
            'methods': ['Multi-Source Validation', 'Confidence Scoring', 'Provider Consensus']
        }
    
    def _record_step_results(self, result: Dict, step_key: str, step_name: str, analysis_key: str, methods: List[str]) -> None:
        """Record results for a specific analysis step"""
        
        # Initialize analysis_steps_report if not exists
        if 'analysis_steps_report' not in result:
            result['analysis_steps_report'] = {}
            
        findings = []
        confidence_impact = 0
        status = 'skipped'
        
        # Check if this step was executed
        if analysis_key in result.get('Enhanced_Analysis', {}):
            step_data = result['Enhanced_Analysis'][analysis_key]
            
            if 'error' in step_data:
                status = 'failed'
                findings.append(f"Error: {step_data['error']}")
            else:
                status = 'completed'
                
                # Extract findings based on step type
                if step_key == 'step_2_ssl_analysis':
                    if 'security_assessment' in step_data:
                        grade = step_data['security_assessment'].get('overall_grade', 'Unknown')
                        findings.append(f"SSL Grade: {grade}")
                        confidence_impact = 10 if grade in ['A', 'A+'] else 5
                    if 'certificate_authority' in step_data:
                        findings.append(f"CA: {step_data['certificate_authority']}")
                        
                elif step_key == 'step_3_enhanced_dns':
                    if 'dns_providers' in step_data:
                        dns_providers = step_data['dns_providers']
                        findings.append(f"DNS Providers: {', '.join(dns_providers) if dns_providers else 'None detected'}")
                        confidence_impact = 8
                        
                elif step_key == 'step_4_geographic_intel':
                    if 'location_data' in step_data:
                        location = step_data['location_data']
                        if location.get('country'):
                            findings.append(f"Location: {location.get('country')}")
                            confidence_impact = 5
                    if 'provider_classification' in step_data:
                        provider_type = step_data['provider_classification'].get('provider_type', 'Unknown')
                        findings.append(f"Provider Type: {provider_type}")
                        
                elif step_key == 'step_5_bgp_analysis':
                    if 'asn_info' in step_data:
                        asn_info = step_data['asn_info']
                        if asn_info.get('asn'):
                            findings.append(f"ASN: AS{asn_info['asn']} ({asn_info.get('name', 'Unknown')})")
                            confidence_impact = 12
                            
                elif step_key == 'step_6_advanced_bgp_classification':
                    if 'classification' in step_data:
                        classification = step_data.get('classification', 'Unknown')
                        confidence = step_data.get('confidence', 0)
                        findings.append(f"Customer Type: {classification} ({confidence:.1%} confidence)")
                        confidence_impact = int(confidence * 20)  # Scale confidence to impact
                        
                elif step_key == 'step_7_threat_intelligence':
                    if 'overall_threat_level' in step_data:
                        threat_level = step_data['overall_threat_level']
                        findings.append(f"Threat Level: {threat_level}")
                        confidence_impact = 5 if threat_level == 'low' else 0
                        
                elif step_key == 'step_8_shodan_waf_analysis':
                    confidence_impact = 5  # Base impact
                    
                    # WAF Detection Analysis
                    if 'waf_detection' in step_data:
                        waf_result = step_data['waf_detection']
                        if waf_result.get('success') and waf_result.get('waf_detected'):
                            waf_type = waf_result.get('waf_type', 'Unknown WAF')
                            confidence = waf_result.get('confidence', 0)
                            findings.append(f"WAF Detected: {waf_type} ({confidence}% confidence)")
                            confidence_impact += 15  # High impact for premium WAF detection
                        else:
                            findings.append("No direct WAF detected via Shodan")
                    
                    # Enhanced Technology Stack Analysis
                    if 'technology_stack' in step_data:
                        tech_result = step_data['technology_stack']
                        if tech_result.get('success'):
                            # Provider Classification
                            provider_classification = tech_result.get('provider_classification', {})
                            
                            cloud_providers = provider_classification.get('cloud_providers', [])
                            if cloud_providers:
                                findings.append(f"Cloud Providers: {', '.join(cloud_providers[:3])}")
                                confidence_impact += len(cloud_providers) * 5
                            
                            cdn_providers = provider_classification.get('cdn_providers', [])
                            if cdn_providers:
                                findings.append(f"CDN Providers: {', '.join(cdn_providers[:3])}")
                                confidence_impact += len(cdn_providers) * 8
                            
                            waf_providers = provider_classification.get('waf_providers', [])
                            if waf_providers:
                                findings.append(f"WAF Providers: {', '.join(waf_providers[:3])}")
                                confidence_impact += len(waf_providers) * 12
                            
                            # Technology Analysis
                            technologies = tech_result.get('technologies', [])
                            if technologies:
                                findings.append(f"Technologies identified: {len(technologies)}")
                                confidence_impact += min(len(technologies), 5)
                            
                            # Security Assessment
                            security_assessment = tech_result.get('security_assessment', {})
                            if security_assessment:
                                security_score = security_assessment.get('security_score', 0)
                                if security_score > 0:
                                    findings.append(f"Security Score: {security_score}/100")
                                    confidence_impact += security_score // 20
                                
                                waf_indicators = security_assessment.get('waf_indicators', [])
                                if waf_indicators:
                                    findings.append(f"WAF indicators: {len(waf_indicators)}")
                                    confidence_impact += len(waf_indicators) * 3
                            
                            # Infrastructure Mapping
                            infrastructure_mapping = tech_result.get('infrastructure_mapping', {})
                            if infrastructure_mapping:
                                geo_distribution = infrastructure_mapping.get('geographic_distribution', {})
                                if geo_distribution:
                                    findings.append(f"Geographic distribution: {len(geo_distribution)} locations")
                                
                                asn_analysis = infrastructure_mapping.get('asn_analysis', {})
                                if asn_analysis:
                                    findings.append(f"ASN networks: {len(asn_analysis)}")
                            
                            # Vulnerability Analysis
                            vulnerability_analysis = tech_result.get('vulnerability_analysis', {})
                            if vulnerability_analysis:
                                vulnerabilities_found = vulnerability_analysis.get('vulnerabilities_found', [])
                                risk_score = vulnerability_analysis.get('risk_score', 0)
                                
                                if vulnerabilities_found:
                                    findings.append(f"Vulnerabilities: {len(vulnerabilities_found)} found")
                                    confidence_impact -= len(vulnerabilities_found) * 2  # Penalty
                                elif risk_score == 0:
                                    findings.append("No vulnerabilities detected")
                                    confidence_impact += 3
                            
                            # SSL Trust Analysis
                            ssl_trust_analysis = tech_result.get('ssl_trust_analysis', {})
                            if ssl_trust_analysis:
                                trust_score = ssl_trust_analysis.get('trust_score', 0)
                                if trust_score > 0:
                                    findings.append(f"SSL Trust Score: {trust_score}/100")
                                    confidence_impact += trust_score // 25
                            
                            # Data Richness Score
                            data_richness_score = tech_result.get('data_richness_score', 0)
                            total_hosts_analyzed = tech_result.get('total_hosts_analyzed', 0)
                            
                            if data_richness_score > 70:
                                findings.append(f"High data richness: {data_richness_score}/100")
                                confidence_impact += 5
                            elif data_richness_score > 0:
                                findings.append(f"Data richness: {data_richness_score}/100")
                                confidence_impact += 2
                            
                            if total_hosts_analyzed > 5:
                                findings.append(f"Comprehensive analysis: {total_hosts_analyzed} hosts")
                                confidence_impact += 3
                    
                    # IP Analysis Enhancement
                    if 'ip_analysis' in step_data:
                        ip_result = step_data['ip_analysis']
                        if ip_result.get('success'):
                            analysis = ip_result.get('analysis', {})
                            cloud_provider = analysis.get('cloud_provider')
                            if cloud_provider:
                                findings.append(f"IP Cloud Provider: {cloud_provider}")
                                confidence_impact += 8
                            
                            security_score = analysis.get('security_score', 0)
                            if security_score > 0:
                                findings.append(f"IP Security Score: {security_score}/100")
                    
                    # Cap confidence impact
                    confidence_impact = min(confidence_impact, 25)
        
        # Record the step results
        result['analysis_steps_report'][step_key] = {
            'status': status,
            'step_name': step_name,
            'findings': findings,
            'confidence_impact': confidence_impact,
            'methods': methods
        }
    
    def _save_analysis_to_backend(self, result: Dict, domain: str) -> None:
        """Save complete analysis results to backend results folder"""
        import json
        import os
        from datetime import datetime
        
        try:
            # Create results directory if it doesn't exist
            results_dir = os.path.join(os.getcwd(), 'results')
            os.makedirs(results_dir, exist_ok=True)
            
            # Generate safe filename
            safe_domain = domain.replace('.', '_').replace('/', '_').replace(':', '_')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Prepare comprehensive data for backend storage
            backend_data = {
                "analysis_metadata": {
                    "domain": result.get('URL', domain),
                    "ip_address": result.get('IP_Address'),
                    "analysis_timestamp": result.get('timestamp'),
                    "analysis_version": "Provider Discovery Tool v3.0",
                    "enhanced_confidence": result.get('Enhanced_Confidence'),
                    "total_analysis_steps": len(result.get('analysis_steps_report', {})),
                    "backend_save_timestamp": timestamp
                },
                "detection_results": {
                    "primary_provider": result.get('Primary_Provider'),
                    "cdn_providers": result.get('CDN_Providers'),
                    "dns_providers": result.get('DNS_Providers'), 
                    "hosting_providers": result.get('Hosting_Providers'),
                    "cloud_providers": result.get('Cloud_Providers'),
                    "security_providers": result.get('Security_Providers')
                },
                "step_by_step_analysis": result.get('analysis_steps_report', {}),
                "enhanced_analysis_details": result.get('Enhanced_Analysis', {}),
                "security_findings": result.get('security_findings', []),
                "geographic_insights": result.get('geographic_insights', []),
                "bgp_insights": result.get('bgp_insights', []),
                "recommendations": result.get('Recommendations', []),
                "technical_details": {
                    "confidence_factors": result.get('confidence_factors', []),
                    "enhanced_confidence_factors": result.get('enhanced_confidence_factors', []),
                    "analysis_methods": result.get('analysis_methods', []),
                    "dns_chain": result.get('dns_chain'),
                    "whois_data": result.get('whois_data')
                }
            }
            
            # Save as JSON
            json_filename = f"analysis_{safe_domain}_{timestamp}.json"
            json_filepath = os.path.join(results_dir, json_filename)
            
            with open(json_filepath, 'w', encoding='utf-8') as f:
                json.dump(backend_data, f, indent=2, ensure_ascii=False)
            
            # Also save a simplified summary CSV for easy review
            csv_filename = f"summary_{safe_domain}_{timestamp}.csv"
            csv_filepath = os.path.join(results_dir, csv_filename)
            
            # Create CSV summary
            import csv
            with open(csv_filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Category', 'Key', 'Value'])
                
                # Basic info
                writer.writerow(['Domain', 'URL', result.get('URL', domain)])
                writer.writerow(['Network', 'IP_Address', result.get('IP_Address', 'N/A')])
                
                # Fix confidence display
                confidence_value = result.get('Enhanced_Confidence', 0)
                if isinstance(confidence_value, (int, float)):
                    confidence_display = f"{confidence_value}%"
                else:
                    confidence_display = str(confidence_value)
                writer.writerow(['Confidence', 'Enhanced_Confidence', confidence_display])
                
                writer.writerow(['Analysis', 'Timestamp', result.get('timestamp', 'N/A')])
                
                # Provider results
                provider_categories = {
                    'Primary_Provider': 'Primary Provider',
                    'CDN_Providers': 'CDN Providers',
                    'DNS_Providers': 'DNS Providers',
                    'Hosting_Providers': 'Hosting Providers',
                    'Cloud_Providers': 'Cloud Providers'
                }
                
                for key, category in provider_categories.items():
                    value = result.get(key, 'None')
                    if isinstance(value, list):
                        # Remove duplicates and join
                        unique_values = list(dict.fromkeys([str(v) for v in value if v]))  # Preserve order, remove duplicates and empty values
                        value = ', '.join(unique_values) if unique_values else 'None'
                    elif not value or value == [] or value is None:
                        value = 'None'
                    # Clean value to prevent CSV formatting issues
                    if isinstance(value, str):
                        value = value.replace('\n', ' ').replace('\r', ' ').strip()
                        if not value:  # If after cleaning the string is empty
                            value = 'None'
                    writer.writerow(['Providers', category, value])
                
                # Analysis steps summary
                steps_report = result.get('analysis_steps_report', {})
                for step_key, step_data in steps_report.items():
                    step_name = step_data.get('step_name', step_key)
                    status = step_data.get('status', 'unknown')
                    confidence_impact = step_data.get('confidence_impact', 0)
                    findings_count = len(step_data.get('findings', []))
                    
                    writer.writerow(['Analysis Steps', step_name, f"{status} | +{confidence_impact}% confidence | {findings_count} findings"])
                
                # Enhanced Shodan Analysis Details
                shodan_analysis = result.get('Enhanced_Analysis', {}).get('shodan_analysis', {})
                if shodan_analysis:
                    writer.writerow(['', '', ''])  # Empty row for separation
                    writer.writerow(['=== SHODAN PREMIUM ANALYSIS DETAILS ===', '', ''])
                    
                    # WAF Detection Details
                    waf_detection = shodan_analysis.get('waf_detection', {})
                    if waf_detection:
                        writer.writerow(['Shodan WAF', 'Detection Success', waf_detection.get('success', False)])
                        writer.writerow(['Shodan WAF', 'WAF Detected', waf_detection.get('waf_detected', False)])
                        if waf_detection.get('waf_detected'):
                            writer.writerow(['Shodan WAF', 'WAF Type', waf_detection.get('waf_type', 'Unknown')])
                            writer.writerow(['Shodan WAF', 'Confidence', f"{waf_detection.get('confidence', 0)}%"])
                        
                        waf_indicators = waf_detection.get('waf_indicators', [])
                        if waf_indicators:
                            writer.writerow(['Shodan WAF', 'WAF Indicators', f"{len(waf_indicators)} indicators detected"])
                    
                    # Technology Stack Details
                    tech_stack = shodan_analysis.get('technology_stack', {})
                    if tech_stack and tech_stack.get('success'):
                        
                        # Provider Classification
                        provider_classification = tech_stack.get('provider_classification', {})
                        if provider_classification:
                            cloud_providers = provider_classification.get('cloud_providers', [])
                            if cloud_providers:
                                writer.writerow(['Shodan Providers', 'Cloud Providers', ', '.join(cloud_providers)])
                            
                            cdn_providers = provider_classification.get('cdn_providers', [])
                            if cdn_providers:
                                # Remove duplicates while preserving order
                                unique_cdn = list(dict.fromkeys(cdn_providers))
                                writer.writerow(['Shodan Providers', 'CDN Providers', ', '.join(unique_cdn)])
                            
                            waf_providers = provider_classification.get('waf_providers', [])
                            if waf_providers:
                                writer.writerow(['Shodan Providers', 'WAF Providers', ', '.join(waf_providers)])
                            
                            hosting_providers = provider_classification.get('hosting_providers', [])
                            if hosting_providers:
                                writer.writerow(['Shodan Providers', 'Hosting Providers', ', '.join(hosting_providers)])
                            
                            primary_infra = provider_classification.get('primary_infrastructure', '')
                            if primary_infra and primary_infra != 'unknown':
                                writer.writerow(['Shodan Providers', 'Primary Infrastructure', primary_infra])
                        
                        # Technology Analysis
                        technologies = tech_stack.get('technologies', [])
                        if technologies:
                            writer.writerow(['Shodan Technology', 'Technologies Detected', f"{len(technologies)} technologies"])
                            writer.writerow(['Shodan Technology', 'Technology List', ', '.join(technologies[:10])])  # Limit to first 10
                        
                        web_servers = tech_stack.get('web_servers', {})
                        if web_servers:
                            server_list = [f"{k} (x{v})" for k, v in web_servers.items()]
                            writer.writerow(['Shodan Technology', 'Web Servers', ', '.join(server_list)])
                        
                        frameworks = tech_stack.get('frameworks', {})
                        if frameworks:
                            framework_list = [f"{k} (x{v})" for k, v in frameworks.items()]
                            writer.writerow(['Shodan Technology', 'Frameworks', ', '.join(framework_list)])
                        
                        # Security Assessment
                        security_assessment = tech_stack.get('security_assessment', {})
                        if security_assessment:
                            security_score = security_assessment.get('security_score', 0)
                            writer.writerow(['Shodan Security', 'Security Score', f"{security_score}/100"])
                            
                            waf_indicators = security_assessment.get('waf_indicators', [])
                            if waf_indicators:
                                writer.writerow(['Shodan Security', 'WAF Indicators', f"{len(waf_indicators)} indicators"])
                                # Show first few indicators
                                sample_indicators = waf_indicators[:5]
                                writer.writerow(['Shodan Security', 'Sample WAF Indicators', ', '.join(sample_indicators)])
                            
                            security_headers = security_assessment.get('security_headers', {})
                            writer.writerow(['Shodan Security', 'Security Headers', f"{len(security_headers)} headers detected"])
                            
                            recommendations = security_assessment.get('recommendations', [])
                            if recommendations:
                                writer.writerow(['Shodan Security', 'Security Recommendations', f"{len(recommendations)} recommendations"])
                                # Show first recommendation
                                if recommendations:
                                    writer.writerow(['Shodan Security', 'Primary Recommendation', recommendations[0]])
                        
                        # Infrastructure Mapping
                        infrastructure_mapping = tech_stack.get('infrastructure_mapping', {})
                        if infrastructure_mapping:
                            geo_distribution = infrastructure_mapping.get('geographic_distribution', {})
                            if geo_distribution:
                                writer.writerow(['Shodan Infrastructure', 'Geographic Locations', f"{len(geo_distribution)} locations"])
                                # Show primary location
                                if geo_distribution:
                                    primary_location = list(geo_distribution.keys())[0]
                                    location_count = geo_distribution[primary_location]
                                    writer.writerow(['Shodan Infrastructure', 'Primary Location', f"{primary_location} ({location_count} hosts)"])
                            
                            asn_analysis = infrastructure_mapping.get('asn_analysis', {})
                            if asn_analysis:
                                writer.writerow(['Shodan Infrastructure', 'ASN Networks', f"{len(asn_analysis)} networks"])
                                # Show primary ASN
                                if asn_analysis:
                                    primary_asn = list(asn_analysis.keys())[0]
                                    asn_org = asn_analysis[primary_asn]
                                    writer.writerow(['Shodan Infrastructure', 'Primary ASN', f"{primary_asn} - {asn_org}"])
                            
                            port_services = infrastructure_mapping.get('port_services', {})
                            if port_services:
                                writer.writerow(['Shodan Infrastructure', 'Open Ports', f"{len(port_services)} ports detected"])
                                # Show common ports
                                common_ports = [port for port in port_services.keys() if port in ['80', '443', '22', '25', '53', '993', '995']]
                                if common_ports:
                                    writer.writerow(['Shodan Infrastructure', 'Common Ports', ', '.join(common_ports)])
                            
                            hosting_patterns = infrastructure_mapping.get('hosting_patterns', [])
                            if hosting_patterns:
                                writer.writerow(['Shodan Infrastructure', 'Hosting Patterns', ', '.join(hosting_patterns)])
                        
                        # Vulnerability Analysis
                        vulnerability_analysis = tech_stack.get('vulnerability_analysis', {})
                        if vulnerability_analysis:
                            vulnerabilities_found = vulnerability_analysis.get('vulnerabilities_found', [])
                            risk_score = vulnerability_analysis.get('risk_score', 0)
                            
                            writer.writerow(['Shodan Vulnerabilities', 'Vulnerabilities Found', len(vulnerabilities_found)])
                            writer.writerow(['Shodan Vulnerabilities', 'Risk Score', f"{risk_score}/100"])
                            
                            if vulnerabilities_found:
                                # Show first few vulnerabilities
                                sample_vulns = vulnerabilities_found[:3]
                                writer.writerow(['Shodan Vulnerabilities', 'Sample CVEs', ', '.join(sample_vulns)])
                            
                            severity_breakdown = vulnerability_analysis.get('severity_breakdown', {})
                            if any(severity_breakdown.values()):
                                severity_summary = []
                                for severity, count in severity_breakdown.items():
                                    if count > 0:
                                        severity_summary.append(f"{severity}: {count}")
                                if severity_summary:
                                    writer.writerow(['Shodan Vulnerabilities', 'Severity Breakdown', ', '.join(severity_summary)])
                            
                            vuln_recommendations = vulnerability_analysis.get('security_recommendations', [])
                            if vuln_recommendations:
                                writer.writerow(['Shodan Vulnerabilities', 'Security Recommendations', vuln_recommendations[0] if vuln_recommendations else 'None'])
                        
                        # SSL Trust Analysis
                        ssl_trust_analysis = tech_stack.get('ssl_trust_analysis', {})
                        if ssl_trust_analysis:
                            trust_score = ssl_trust_analysis.get('trust_score', 0)
                            writer.writerow(['Shodan SSL', 'SSL Trust Score', f"{trust_score}/100"])
                            
                            certificate_authorities = ssl_trust_analysis.get('certificate_authorities', [])
                            if certificate_authorities:
                                writer.writerow(['Shodan SSL', 'Certificate Authorities', ', '.join(certificate_authorities)])
                            
                            ssl_configurations = ssl_trust_analysis.get('ssl_configurations', [])
                            if ssl_configurations:
                                writer.writerow(['Shodan SSL', 'SSL Configurations', f"{len(ssl_configurations)} configurations"])
                                # Show primary SSL version
                                if ssl_configurations:
                                    primary_ssl = ssl_configurations[0]
                                    ssl_version = primary_ssl.get('version', 'Unknown')
                                    ssl_bits = primary_ssl.get('bits', 0)
                                    writer.writerow(['Shodan SSL', 'Primary SSL Config', f"{ssl_version} ({ssl_bits} bits)"])
                        
                        # Data Quality Metrics
                        data_richness_score = tech_stack.get('data_richness_score', 0)
                        total_hosts_analyzed = tech_stack.get('total_hosts_analyzed', 0)
                        confidence = tech_stack.get('confidence', 0)
                        
                        writer.writerow(['Shodan Quality', 'Data Richness Score', f"{data_richness_score}/100"])
                        writer.writerow(['Shodan Quality', 'Hosts Analyzed', total_hosts_analyzed])
                        writer.writerow(['Shodan Quality', 'Analysis Confidence', f"{confidence}%"])
            
            # Store file paths in result for WebUI display
            result['backend_files'] = {
                'json_file': json_filepath,
                'csv_file': csv_filepath,
                'json_filename': json_filename,
                'csv_filename': csv_filename
            }
            
            logger.info(f"✅ Analysis results saved to backend: {json_filename}, {csv_filename}")
            
            # Optional: Clean up old files (keep last 50 analyses)
            self._cleanup_old_results(results_dir)
            
        except Exception as e:
            logger.error(f"Failed to save analysis results to backend: {e}")
            result['backend_files'] = None
    
    def _cleanup_old_results(self, results_dir: str, max_files: int = 50) -> None:
        """Clean up old analysis files to prevent storage bloat"""
        import os
        try:
            # Get all analysis JSON files
            analysis_files = [f for f in os.listdir(results_dir) if f.startswith('analysis_') and f.endswith('.json')]
            
            if len(analysis_files) > max_files:
                # Sort by modification time (oldest first)
                analysis_files.sort(key=lambda x: os.path.getmtime(os.path.join(results_dir, x)))
                
                # Remove oldest files
                files_to_remove = analysis_files[:-max_files]  # Keep last max_files
                for filename in files_to_remove:
                    try:
                        json_path = os.path.join(results_dir, filename)
                        csv_path = os.path.join(results_dir, filename.replace('analysis_', 'summary_').replace('.json', '.csv'))
                        
                        # Remove both JSON and CSV files
                        if os.path.exists(json_path):
                            os.remove(json_path)
                        if os.path.exists(csv_path):
                            os.remove(csv_path)
                            
                    except Exception as e:
                        logger.debug(f"Failed to remove old file {filename}: {e}")
                
                logger.info(f"🧹 Cleaned up {len(files_to_remove)} old analysis files")
                
        except Exception as e:
            logger.debug(f"Cleanup failed: {e}")

# Singleton instance
_enhanced_detector = None

def get_enhanced_provider_detector(vt_api_key: Optional[str] = None) -> EnhancedProviderDetector:
    """Get singleton enhanced provider detector instance"""
    global _enhanced_detector
    if _enhanced_detector is None:
        _enhanced_detector = EnhancedProviderDetector(vt_api_key)
    return _enhanced_detector
