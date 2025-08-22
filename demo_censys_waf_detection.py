#!/usr/bin/env python3
"""
Demo script for Censys WAF detection functionality
Shows how to integrate Censys into our provider detection system
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add src to path
sys.path.insert(0, 'src')

from provider_discovery.integrations import CENSYS_INTEGRATION_AVAILABLE, get_censys_integration
from provider_discovery.config.settings import get_settings

def demo_without_api_keys():
    """Demonstrate Censys integration without API keys"""
    print("🔍 DEMO: Censys WAF Detection (Without API Keys)")
    print("=" * 60)
    
    print(f"📚 Censys library available: {CENSYS_INTEGRATION_AVAILABLE}")
    
    if not CENSYS_INTEGRATION_AVAILABLE:
        print("❌ Censys library not installed. Install with: pip install censys")
        return
    
    # Test basic integration
    censys = get_censys_integration()
    print(f"🔧 Censys integration created: ✅")
    print(f"🔑 API credentials configured: {censys.is_enabled}")
    
    # Test connection
    connection_test = censys.test_connection()
    print(f"🔗 Connection test: {connection_test}")
    
    # Test WAF detection (will fail gracefully)
    test_domains = ['github.com', 'cloudflare.com', 'aws.amazon.com']
    
    for domain in test_domains:
        result = censys.get_waf_summary(domain)
        print(f"🛡️  WAF detection for {domain}: {result}")
    
    print("\n💡 To enable full functionality:")
    print("1. Sign up at https://search.censys.io/register")
    print("2. Get your API credentials from https://search.censys.io/account/api")
    print("3. Add to .env file:")
    print("   CENSYS_API_ID=your-api-id")
    print("   CENSYS_API_SECRET=your-api-secret")

def demo_configuration():
    """Show Censys configuration options"""
    print("\n🔧 CENSYS CONFIGURATION")
    print("=" * 60)
    
    settings = get_settings()
    print(f"📋 Censys enabled: {settings.is_censys_enabled()}")
    print(f"🔑 API ID configured: {'Yes' if settings.censys_api_id else 'No'}")
    print(f"🔐 API Secret configured: {'Yes' if settings.censys_api_secret else 'No'}")
    print(f"⏰ Cache TTL: {settings.censys_cache_ttl} seconds")
    print(f"🚦 Rate limit: {settings.censys_rate_limit} requests/minute")
    
    # Show configuration
    censys_config = settings.get_censys_config()
    print(f"\n📊 Censys Config: {censys_config}")

def demo_waf_detection_patterns():
    """Show WAF detection patterns and logic"""
    print("\n🛡️  WAF DETECTION PATTERNS")
    print("=" * 60)
    
    # Show the patterns we use for detection
    waf_patterns = {
        'Cloudflare': ['cloudflare', 'cf-ray', 'cf-cache-status'],
        'Akamai': ['akamai', 'akamaihost', 'x-akamai'],
        'AWS WAF/CloudFront': ['awselb', 'cloudfront', 'x-amz-cf-id'],
        'Fastly': ['fastly', 'x-served-by', 'x-cache'],
        'Imperva/Incapsula': ['imperva', 'incapsula', 'x-iinfo'],
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

def demo_integration_with_existing_system():
    """Show how Censys integrates with existing provider detection"""
    print("\n🔗 INTEGRATION WITH EXISTING SYSTEM")
    print("=" * 60)
    
    print("📊 Current Detection Stack:")
    print("  Phase 1: ✅ IP Range Analysis (AWS, Cloudflare, etc.)")
    print("  Phase 2A: ✅ DNS Analysis (NS records, TTL, reverse DNS)")
    print("  Phase 2B: ✅ VirusTotal Integration")
    print("  Phase 3B: 🆕 Censys WAF Detection (NEW!)")
    
    print("\n🔄 Detection Flow Enhancement:")
    print("  1. Traditional detection (IP ranges, DNS, WHOIS)")
    print("  2. VirusTotal cross-validation")
    print("  3. 🆕 Censys WAF/CDN analysis")
    print("  4. 🆕 Enhanced confidence scoring")
    print("  5. 🆕 Multi-provider role classification")
    
    print("\n💪 Benefits:")
    print("  ✅ Reduced false positives through cross-validation")
    print("  ✅ WAF vs CDN distinction")
    print("  ✅ Security posture analysis")
    print("  ✅ Geographic distribution insights")
    print("  ✅ Alternative to expensive Shodan")

def demo_future_phases():
    """Show planned future enhancements"""
    print("\n🔮 FUTURE PHASE 3 ENHANCEMENTS")
    print("=" * 60)
    
    print("🚀 Phase 3A: Passive DNS & History Intelligence")
    print("  - SecurityTrails integration for DNS history")
    print("  - Migration detection vs provider switching")
    print("  - Enhanced CNAME chain analysis")
    print("  - Target: <5% false positive rate")
    
    print("\n🌐 Phase 3C: BGP Intelligence & Network Layer")
    print("  - Hurricane Electric BGP toolkit")
    print("  - BGPView API integration")
    print("  - ASN analysis and routing intelligence")
    print("  - Complete L3/L4 layer visibility")
    
    print("\n🏢 Phase 3D: Business Intelligence & Analytics")
    print("  - Infrastructure cost estimation")
    print("  - Competitive intelligence dashboard")
    print("  - Compliance & risk assessment")
    print("  - Market trends analysis")

def main():
    """Main demo function"""
    print("🚀 Censys WAF Detection Integration Demo")
    print("🎯 Alternative to Shodan for Phase 3B Implementation")
    print("=" * 80)
    
    # Demo 1: Basic functionality without API keys
    demo_without_api_keys()
    
    # Demo 2: Configuration
    demo_configuration()
    
    # Demo 3: WAF detection patterns
    demo_waf_detection_patterns()
    
    # Demo 4: Integration with existing system
    demo_integration_with_existing_system()
    
    # Demo 5: Future phases
    demo_future_phases()
    
    print("\n" + "=" * 80)
    print("✅ Demo completed! Ready for Phase 3B implementation.")
    print("📚 Next steps:")
    print("  1. Get Censys API credentials (free tier: 250 queries/month)")
    print("  2. Test WAF detection with real domains")
    print("  3. Integrate with main detector system")
    print("  4. Implement cross-validation logic")
    print("  5. Enhance confidence scoring")

if __name__ == "__main__":
    main()
