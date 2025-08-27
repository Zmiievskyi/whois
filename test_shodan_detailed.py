#!/usr/bin/env python3
"""Test Shodan integration with detailed output"""

from src.provider_discovery.core.enhanced_detector import get_enhanced_provider_detector

def test_shodan_analysis(domain):
    print(f"\n🔍 TESTING SHODAN ANALYSIS FOR {domain.upper()}")
    print("=" * 60)
    
    detector = get_enhanced_provider_detector()
    result = detector.detect_provider_comprehensive('', '', '', domain)
    
    # Extract Shodan analysis
    shodan = result.get('Enhanced_Analysis', {}).get('shodan_analysis', {})
    
    if not shodan:
        print("❌ No Shodan analysis found")
        return
    
    # WAF Detection Results
    print("\n🛡️ WAF DETECTION RESULTS:")
    waf_detection = shodan.get('waf_detection', {})
    if waf_detection.get('success'):
        print(f"   WAF Detected: {waf_detection.get('waf_detected', False)}")
        print(f"   WAF Type: {waf_detection.get('waf_type', 'Unknown')}")
        print(f"   Confidence: {waf_detection.get('confidence', 0)}%")
        print(f"   Security Headers: {len(waf_detection.get('security_headers', []))}")
        if waf_detection.get('waf_indicators'):
            print(f"   WAF Indicators: {waf_detection['waf_indicators']}")
    else:
        print(f"   ❌ WAF detection failed: {waf_detection.get('error', 'Unknown error')}")
    
    # Technology Stack
    print("\n💻 TECHNOLOGY STACK:")
    tech = shodan.get('technology_stack', {})
    if tech.get('success'):
        technologies = tech.get('technologies', [])
        web_servers = tech.get('web_servers', [])
        frameworks = tech.get('frameworks', [])
        cdn_providers = tech.get('cdn_providers', [])
        
        print(f"   Technologies: {len(technologies)} found")
        if technologies:
            print(f"   - Technologies: {list(technologies)[:5]}")  # Show first 5
        if web_servers:
            print(f"   - Web Servers: {list(web_servers)}")
        if frameworks:
            print(f"   - Frameworks: {list(frameworks)}")
        if cdn_providers:
            print(f"   - CDN Providers: {list(cdn_providers)}")
    else:
        print(f"   ❌ Technology analysis failed: {tech.get('error', 'Unknown error')}")
    
    # IP Analysis
    print("\n🌐 IP ANALYSIS:")
    ip_analysis = shodan.get('ip_analysis', {})
    if ip_analysis.get('success'):
        host_info = ip_analysis.get('host_info', {})
        analysis = ip_analysis.get('analysis', {})
        
        print(f"   IP: {ip_analysis.get('ip', 'Unknown')}")
        print(f"   Organization: {host_info.get('org', 'Unknown')}")
        print(f"   ISP: {host_info.get('isp', 'Unknown')}")
        print(f"   Country: {host_info.get('country_name', 'Unknown')}")
        print(f"   Security Score: {analysis.get('security_score', 'N/A')}/100")
        
        cloud_provider = analysis.get('cloud_provider')
        if cloud_provider:
            print(f"   Cloud Provider: {cloud_provider}")
        
        security_headers = analysis.get('security_headers', [])
        if security_headers:
            print(f"   Security Headers: {len(security_headers)} found")
        
        open_ports = analysis.get('open_ports', [])
        if open_ports:
            print(f"   Open Ports: {open_ports}")
    else:
        print(f"   ❌ IP analysis failed: {ip_analysis.get('error', 'Unknown error')}")
    
    # Security Findings
    print("\n🔒 SECURITY FINDINGS FROM SHODAN:")
    security_findings = result.get('security_findings', [])
    shodan_findings = [f for f in security_findings if 'Shodan' in f]
    if shodan_findings:
        for finding in shodan_findings:
            print(f"   • {finding}")
    else:
        print("   No Shodan-specific security findings")
    
    # Step 8 Analysis
    print("\n📊 STEP 8 ANALYSIS STATUS:")
    steps = result.get('analysis_steps_report', {})
    step_8 = steps.get('step_8_shodan_waf_analysis', {})
    if step_8:
        status = step_8.get('status', 'unknown')
        findings = step_8.get('findings', [])
        confidence_impact = step_8.get('confidence_impact', 0)
        
        print(f"   Status: {status}")
        print(f"   Confidence Impact: +{confidence_impact}%")
        print(f"   Findings: {len(findings)}")
        for finding in findings:
            print(f"     • {finding}")
    else:
        print("   No Step 8 data found")

if __name__ == "__main__":
    # Test with domains that should have different WAF setups
    test_domains = [
        "cloudflare.com",  # Should have Cloudflare WAF
        "github.com",      # Should have some WAF
        "nike.com",        # Major brand, likely has WAF
    ]
    
    for domain in test_domains:
        test_shodan_analysis(domain)
        print("\n" + "="*60)
