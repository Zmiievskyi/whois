#!/usr/bin/env python3
"""Debug Step 8 execution"""

from src.provider_discovery.core.enhanced_detector import get_enhanced_provider_detector

detector = get_enhanced_provider_detector()

print("=== STEP 8 DEBUG ===")
domain = "shopify.com"

# Test just the shodan analysis
print(f"Testing Shodan analysis for {domain}...")

# Initialize empty result structure like in the real detector
result = {
    'Enhanced_Analysis': {},
    'providers': [],
    'security_findings': [],
    'enhanced_confidence_factors': [],
    'analysis_methods': []
}

# Test Shodan analysis directly
print("\n1. Testing _enhance_with_shodan_analysis...")
result = detector._enhance_with_shodan_analysis(result, domain, "1.1.1.1")

shodan_analysis = result.get('Enhanced_Analysis', {}).get('shodan_analysis', {})
print(f"Shodan analysis present: {'shodan_analysis' in result.get('Enhanced_Analysis', {})}")
print(f"Shodan WAF detection success: {shodan_analysis.get('waf_detection', {}).get('success')}")
print(f"Shodan tech stack success: {shodan_analysis.get('technology_stack', {}).get('success')}")

# Test recording results
print("\n2. Testing _record_step_results...")
if 'analysis_steps_report' not in result:
    result['analysis_steps_report'] = {}

detector._record_step_results(result, 'step_8_shodan_waf_analysis', 'Shodan Premium WAF Analysis', 
                               'shodan_analysis', ['WAF Detection', 'Technology Stack Analysis'])

step_8_status = result.get('analysis_steps_report', {}).get('step_8_shodan_waf_analysis', {})
print(f"Step 8 recorded: {bool(step_8_status)}")
print(f"Step 8 status: {step_8_status.get('status', 'missing')}")
print(f"Step 8 findings: {step_8_status.get('findings', [])}")
print(f"Step 8 confidence impact: {step_8_status.get('confidence_impact', 0)}")

print("\n3. Full analysis_steps_report:")
for step_key, step_data in result.get('analysis_steps_report', {}).items():
    print(f"  {step_key}: {step_data.get('status', 'unknown')}")
