#!/usr/bin/env python3
"""Debug full analysis flow"""

from src.provider_discovery.core.enhanced_detector import get_enhanced_provider_detector

detector = get_enhanced_provider_detector()

print("=== FULL ANALYSIS DEBUG ===")
domain = "shopify.com"

print(f"Running full analysis for {domain}...")

# Monkey patch to add debug logging
original_enhance_with_shodan = detector._enhance_with_shodan_analysis

def debug_enhance_with_shodan(result, domain, ip):
    print(f"🔥 DEBUG: _enhance_with_shodan_analysis called with domain={domain}, ip={ip}")
    enhanced_result = original_enhance_with_shodan(result, domain, ip)
    shodan_present = 'shodan_analysis' in enhanced_result.get('Enhanced_Analysis', {})
    print(f"🔥 DEBUG: Shodan analysis added: {shodan_present}")
    return enhanced_result

detector._enhance_with_shodan_analysis = debug_enhance_with_shodan

# Run full analysis
result = detector.detect_provider_comprehensive('', '', '', domain)

print("\n=== RESULTS ===")
print(f"Total steps: {len(result.get('analysis_steps_report', {}))}")
print(f"Shodan in Enhanced_Analysis: {'shodan_analysis' in result.get('Enhanced_Analysis', {})}")

steps_report = result.get('analysis_steps_report', {})
for step_key, step_data in steps_report.items():
    status = step_data.get('status', 'unknown')
    findings_count = len(step_data.get('findings', []))
    confidence = step_data.get('confidence_impact', 0)
    print(f"  {step_key}: {status} | +{confidence}% | {findings_count} findings")

# Check if Step 8 specifically was processed
step_8 = steps_report.get('step_8_shodan_waf_analysis', {})
if step_8:
    print(f"\nStep 8 details:")
    print(f"  Status: {step_8.get('status')}")
    print(f"  Findings: {step_8.get('findings', [])}")
    print(f"  Confidence: +{step_8.get('confidence_impact', 0)}%")
else:
    print("\n❌ Step 8 not found in analysis_steps_report!")
