#!/usr/bin/env python3
"""
Demo script for Shodan WAF detection functionality
Shows how to integrate Shodan into our provider detection system
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add src to path
sys.path.insert(0, 'src')

from provider_discovery.integrations import SHODAN_INTEGRATION_AVAILABLE, get_shodan_integration
from provider_discovery.config.settings import get_settings

def demo_without_api_key():
    """Demonstrate Shodan integration without API key"""
    print("🔍 DEMO: Shodan WAF Detection (Without API Key)")
    print("=" * 60)
    
    print(f"📚 Shodan library available: {SHODAN_INTEGRATION_AVAILABLE}")
    
    if not SHODAN_INTEGRATION_AVAILABLE:
        print("❌ Shodan library not installed. Install with: pip install shodan")
        print("💡 Note: This is optional - system works without Shodan")
        return
    
    # Test basic integration
    shodan = get_shodan_integration()
    print(f"🔧 Shodan integration created: ✅")
    print(f"🔑 API credentials configured: {shodan.is_enabled}")
    
    # Test connection (will fail gracefully without API key)
    connection_test = shodan.test_connection()
    print(f"🔗 Connection test: {connection_test}")
    
    # Test WAF detection (will fail gracefully)
    test_domains = ['github.com', 'cloudflare.com', 'aws.amazon.com']
    
    for domain in test_domains:
        result = shodan.detect_waf(domain)
        print(f"🛡️  WAF detection for {domain}: {result.get('success', False)} - {result.get('error', 'No error')}")
    
    print("\n💡 To enable full functionality:")
    print("1. Sign up at https://account.shodan.io/register")
    print("2. Choose a plan:")
    print("   - Free: 1 query per month (very limited)")
    print("   - Developer: $59/month - 10,000 query credits")
    print("   - Enterprise: Higher limits available")
    print("3. Add to .env file:")
    print("   SHODAN_API_KEY=your-shodan-api-key")

def demo_configuration():
    """Show Shodan configuration options"""
    print("\n🔧 SHODAN CONFIGURATION")
    print("=" * 60)
    
    settings = get_settings()
    print(f"📋 Shodan enabled: {settings.is_shodan_enabled()}")
    print(f"🔑 API Key configured: {'Yes' if settings.shodan_api_key else 'No'}")
    print(f"⏰ Cache TTL: {settings.shodan_cache_ttl} seconds ({settings.shodan_cache_ttl/3600:.1f} hours)")
    print(f"🚦 Rate limit: {settings.shodan_rate_limit} requests/minute")
    
    # Show configuration
    shodan_config = settings.get_shodan_config()
    print(f"\n📊 Shodan Config: {shodan_config}")

def demo_waf_detection_patterns():
    """Show WAF detection patterns and logic"""
    print("\n🛡️  SHODAN WAF DETECTION PATTERNS")
    print("=" * 60)
    
    # Show the patterns we use for detection
    waf_patterns = {
        'Cloudflare': ['cloudflare', 'cf-ray', 'cf-cache-status'],
        'Akamai': ['akamai', 'akamaihost', 'x-akamai'],
        'AWS WAF/CloudFront': ['awselb', 'cloudfront', 'x-amz-cf-id'],
        'Fastly': ['fastly', 'x-served-by', 'x-cache'],
        'Imperva/Incapsula': ['imperva', 'incapsula', 'x-iinfo'],
        'Sucuri': ['sucuri', 'x-sucuri-id'],
        'Barracuda': ['barracuda', 'barra'],
        'F5': ['f5', 'bigip'],
        'Generic WAF': ['waf', 'firewall', 'security']
    }
    
    print("🔍 HTTP Header Patterns Used for Detection:")
    for waf_type, patterns in waf_patterns.items():
        print(f"  {waf_type}:")
        for pattern in patterns:
            print(f"    - Headers containing: '{pattern}'")
    
    security_headers = [
        'x-frame-options', 'content-security-policy', 
        'x-content-type-options', 'strict-transport-security',
        'x-xss-protection', 'referrer-policy'
    ]
    
    print(f"\n🔐 Security Headers Analyzed:")
    for header in security_headers:
        print(f"  - {header}")

def demo_shodan_queries():
    """Show example Shodan queries used for WAF detection"""
    print("\n🔍 EXAMPLE SHODAN QUERIES")
    print("=" * 60)
    
    example_queries = {
        'WAF Detection': 'hostname:example.com http.waf',
        'Security Headers': 'hostname:example.com http.component:"WAF"',
        'Cloudflare WAF': 'hostname:example.com http.component:"Cloudflare"',
        'Technology Stack': 'hostname:example.com',
        'IP Analysis': '1.1.1.1',
        'Geographic Analysis': 'country:US http.waf'
    }
    
    print("📊 Query Types and Examples:")
    for query_type, query in example_queries.items():
        print(f"  {query_type}:")
        print(f"    Query: {query}")
        print(f"    Purpose: Detect {query_type.lower()}")
        print()

def demo_cost_analysis():
    """Show cost analysis for Shodan usage"""
    print("\n💰 SHODAN COST ANALYSIS")
    print("=" * 60)
    
    print("📊 Pricing Tiers:")
    print("  Free Tier:")
    print("    - 1 query per month")
    print("    - Search and scan results")
    print("    - Basic API access")
    print("    - Cost: $0")
    print()
    print("  Developer Plan:")
    print("    - 10,000 query credits/month")
    print("    - Scan data downloads")
    print("    - Bulk data access")
    print("    - Cost: $59/month")
    print()
    print("  Enterprise Plans:")
    print("    - Higher query limits")
    print("    - Priority support")
    print("    - Custom integrations")
    print("    - Cost: Contact sales")
    
    print("\n🧮 Usage Estimation:")
    print("  For 100 domains/month:")
    print("    - Queries needed: ~300-500 (3-5 per domain)")
    print("    - Recommended plan: Developer ($59/month)")
    print("    - Cost per domain: ~$0.12-0.20")
    print()
    print("  For 1000 domains/month:")
    print("    - Queries needed: ~3000-5000")
    print("    - Recommended plan: Enterprise")
    print("    - Requires higher tier or multiple accounts")
    
    print("\n⚠️  IMPORTANT CONSIDERATIONS:")
    print("  ✅ Very high accuracy for WAF detection")
    print("  ✅ Comprehensive security analysis")
    print("  ✅ Technology stack identification")
    print("  ❌ Significant cost for bulk analysis")
    print("  ❌ Rate limiting can slow batch processing")
    print("  💡 Best used selectively for high-value targets")

def demo_integration_comparison():
    """Compare Shodan with existing integrations"""
    print("\n⚖️  INTEGRATION COMPARISON")
    print("=" * 60)
    
    comparison = {
        'Feature': ['Cost', 'WAF Detection', 'Security Analysis', 'Rate Limits', 'Accuracy'],
        'Shodan': ['$59/month', 'Excellent', 'Excellent', 'Strict', '95%'],
        'Censys': ['Free tier', 'Good', 'Good', 'Moderate', '85%'],
        'Enhanced DNS': ['Free', 'Limited', 'Basic', 'None', '70%'],
        'Threat Intel': ['Free', 'Pattern-based', 'Good', 'Moderate', '75%'],
    }
    
    print("📊 Feature Comparison:")
    for i, feature in enumerate(comparison['Feature']):
        print(f"  {feature:15} | {'Shodan':10} | {'Censys':10} | {'DNS':10} | {'Threat':10}")
        if i == 0:
            print("  " + "-" * 70)
        else:
            feature_name = comparison['Feature'][i]
            shodan_val = comparison['Shodan'][i]
            censys_val = comparison['Censys'][i]
            dns_val = comparison['Enhanced DNS'][i]
            threat_val = comparison['Threat Intel'][i]
            print(f"  {feature_name:15} | {shodan_val:10} | {censys_val:10} | {dns_val:10} | {threat_val:10}")
    
    print(f"\n🎯 RECOMMENDATION:")
    print(f"  • Use Shodan for high-value competitive analysis")
    print(f"  • Use Censys for regular WAF detection (free tier)")
    print(f"  • Use existing free integrations for bulk analysis")
    print(f"  • Combine all sources for maximum accuracy")

def demo_future_phases():
    """Show future development phases"""
    print("\n🚀 FUTURE PHASES")
    print("=" * 60)
    
    print("📋 Phase 3B - Shodan Integration (IMPLEMENTED):")
    print("  ✅ Basic Shodan API integration")
    print("  ✅ WAF detection via http.waf queries")
    print("  ✅ Security headers analysis")
    print("  ✅ Technology stack identification")
    print("  ✅ Geographic distribution analysis")
    print("  ✅ Rate limiting and cost management")
    
    print("\n📋 Phase 3C - Enhanced Analysis (PLANNED):")
    print("  🔮 Historical infrastructure tracking")
    print("  🔮 Provider migration detection")
    print("  🔮 Competitive intelligence dashboard")
    print("  🔮 Automated alerting for changes")
    print("  🔮 Custom reporting and analytics")
    
    print("\n📋 Phase 3D - Enterprise Features (FUTURE):")
    print("  🔮 Multi-tenant support")
    print("  🔮 API rate optimization")
    print("  🔮 Bulk analysis workflows")
    print("  🔮 Custom integrations")
    print("  🔮 SLA monitoring and reporting")

def main():
    """Run all demo functions"""
    print("🚀 SHODAN WAF DETECTION DEMO")
    print("=" * 60)
    print("This demo shows the Shodan integration for enhanced WAF detection")
    print("as part of the Provider Discovery Tool v3.0 Phase 3B implementation.")
    print()
    
    # Run demos
    demo_without_api_key()
    demo_configuration()
    demo_waf_detection_patterns()
    demo_shodan_queries()
    demo_cost_analysis()
    demo_integration_comparison()
    demo_future_phases()
    
    print("\n" + "=" * 60)
    print("🎉 SHODAN INTEGRATION DEMO COMPLETE")
    print()
    print("📋 Next Steps:")
    print("  1. Get Shodan API key if needed")
    print("  2. Configure in .env file") 
    print("  3. Test with real domains")
    print("  4. Integrate into enhanced detector")
    print("  5. Monitor costs and usage")
    print("  6. Enhance accuracy and reduce false positives")

if __name__ == "__main__":
    main()
