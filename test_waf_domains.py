#!/usr/bin/env python3
"""Test domains that should have detectable WAF"""

from src.provider_discovery.core.enhanced_detector import get_enhanced_provider_detector

# Test specific domains known to have WAF detection signatures
test_domains = [
    "shopify.com",     # Known to use Cloudflare WAF
    "dropbox.com",     # Uses various security layers
    "slack.com",       # Enterprise security
]

detector = get_enhanced_provider_detector()

for domain in test_domains:
    print(f"\n🔍 TESTING {domain}")
    print("-" * 40)
    
    result = detector.detect_provider_comprehensive('', '', '', domain)
    
    # Show all Shodan findings
    shodan = result.get('Enhanced_Analysis', {}).get('shodan_analysis', {})
    
    # WAF detection
    waf = shodan.get('waf_detection', {})
    if waf.get('waf_detected'):
        print(f"✅ WAF DETECTED: {waf.get('waf_type')} ({waf.get('confidence')}%)")
    else:
        print(f"❌ No WAF detected")
    
    # Technology findings
    tech = shodan.get('technology_stack', {})
    if tech.get('success'):
        technologies = tech.get('technologies', [])
        if technologies:
            print(f"🔧 Technologies: {list(technologies)}")
    
    # Check confidence impact
    steps = result.get('analysis_steps_report', {})
    step_8 = steps.get('step_8_shodan_waf_analysis', {})
    confidence_impact = step_8.get('confidence_impact', 0)
    print(f"📊 Confidence Impact: +{confidence_impact}%")
    
    # Show security findings with Shodan
    security_findings = result.get('security_findings', [])
    shodan_findings = [f for f in security_findings if 'Shodan' in f]
    if shodan_findings:
        print("🔒 Shodan Security Findings:")
        for finding in shodan_findings:
            print(f"   • {finding}")
