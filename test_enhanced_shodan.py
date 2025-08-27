#!/usr/bin/env python3
"""Test enhanced Shodan integration"""

from src.provider_discovery.core.enhanced_detector import get_enhanced_provider_detector

def test_enhanced_shodan():
    print("🚀 TESTING ENHANCED SHODAN INTEGRATION")
    print("=" * 60)
    
    detector = get_enhanced_provider_detector()
    result = detector.detect_provider_comprehensive('', '', '', 'cloudflare.com')
    
    # Step 8 Analysis
    step8 = result.get('analysis_steps_report', {}).get('step_8_shodan_waf_analysis', {})
    print(f"📊 STEP 8 ANALYSIS:")
    print(f"   Status: {step8.get('status', 'missing')}")
    print(f"   Confidence Impact: +{step8.get('confidence_impact', 0)}%")
    print(f"   Total Findings: {len(step8.get('findings', []))}")
    
    print(f"\n🔍 DETAILED FINDINGS:")
    for i, finding in enumerate(step8.get('findings', []), 1):
        print(f"   {i}. {finding}")
    
    # Enhanced Analysis Data
    shodan_analysis = result.get('Enhanced_Analysis', {}).get('shodan_analysis', {})
    if shodan_analysis:
        print(f"\n🛡️ SHODAN ENHANCED DATA:")
        
        tech_stack = shodan_analysis.get('technology_stack', {})
        if tech_stack.get('success'):
            # Provider Classification
            provider_classification = tech_stack.get('provider_classification', {})
            print(f"   Cloud Providers: {provider_classification.get('cloud_providers', [])}")
            print(f"   CDN Providers: {provider_classification.get('cdn_providers', [])}")
            print(f"   WAF Providers: {provider_classification.get('waf_providers', [])}")
            
            # Security Assessment
            security_assessment = tech_stack.get('security_assessment', {})
            print(f"   Security Score: {security_assessment.get('security_score', 0)}/100")
            print(f"   WAF Indicators: {len(security_assessment.get('waf_indicators', []))}")
            
            # Infrastructure Mapping
            infrastructure_mapping = tech_stack.get('infrastructure_mapping', {})
            if infrastructure_mapping:
                geo_dist = infrastructure_mapping.get('geographic_distribution', {})
                print(f"   Geographic Locations: {len(geo_dist)}")
                if geo_dist:
                    top_location = list(geo_dist.keys())[0] if geo_dist else 'Unknown'
                    print(f"   Primary Location: {top_location}")
            
            # Vulnerability Analysis
            vuln_analysis = tech_stack.get('vulnerability_analysis', {})
            if vuln_analysis:
                vulns = vuln_analysis.get('vulnerabilities_found', [])
                risk_score = vuln_analysis.get('risk_score', 0)
                print(f"   Vulnerabilities: {len(vulns)} found")
                print(f"   Risk Score: {risk_score}/100")
            
            # SSL Trust Analysis
            ssl_trust = tech_stack.get('ssl_trust_analysis', {})
            if ssl_trust:
                trust_score = ssl_trust.get('trust_score', 0)
                cas = ssl_trust.get('certificate_authorities', [])
                print(f"   SSL Trust Score: {trust_score}/100")
                print(f"   Certificate Authorities: {len(cas)}")
            
            # Data Quality
            data_richness = tech_stack.get('data_richness_score', 0)
            hosts_analyzed = tech_stack.get('total_hosts_analyzed', 0)
            print(f"   Data Richness: {data_richness}/100")
            print(f"   Hosts Analyzed: {hosts_analyzed}")
    
    # Overall Impact
    print(f"\n📈 OVERALL IMPACT:")
    enhanced_confidence = result.get('Enhanced_Confidence', 0)
    print(f"   Enhanced Confidence: {enhanced_confidence}%")
    
    providers_count = len(result.get('providers', []))
    print(f"   Total Providers Detected: {providers_count}")
    
    security_findings_count = len(result.get('security_findings', []))
    print(f"   Security Findings: {security_findings_count}")
    
    # Shodan-specific findings
    shodan_findings = [f for f in result.get('security_findings', []) if 'Shodan' in f]
    print(f"   Shodan Security Findings: {len(shodan_findings)}")
    for finding in shodan_findings[:5]:  # Show first 5
        print(f"     • {finding}")

if __name__ == "__main__":
    test_enhanced_shodan()
