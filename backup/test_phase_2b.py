#!/usr/bin/env python3
"""
Test script for Phase 2B VirusTotal Integration
"""
import sys
import os
import time
from ultimate_provider_detector import UltimateProviderDetector

def test_virustotal_integration():
    """Test Phase 2B VirusTotal integration"""
    print("🧪 Testing Phase 2B: VirusTotal Integration")
    print("=" * 60)
    
    # Check for API key
    vt_api_key = os.getenv('VT_API_KEY')
    if not vt_api_key:
        print("⚠️ VirusTotal API key not found in environment")
        print("Set VT_API_KEY environment variable to test integration")
        print("\nExample:")
        print("export VT_API_KEY='your-virustotal-api-key-here'")
        print("python test_phase_2b.py")
        return False
    
    detector = UltimateProviderDetector(vt_api_key=vt_api_key)
    
    # Test domains
    test_domains = [
        "github.com",       # Expected: GitHub + multiple CDNs
        "cloudflare.com",   # Expected: Cloudflare
        "google.com",       # Expected: Google
        "malicious.test",   # Non-existent domain for testing
    ]
    
    for domain in test_domains:
        print(f"\n🔍 Testing: {domain}")
        print("-" * 40)
        
        try:
            # Get basic info
            headers = detector.get_headers(domain)
            ip = detector.get_ip(domain)
            whois_data = detector.get_whois(ip) if ip else ""
            
            # Phase 2B: Ultimate detection with VirusTotal
            start_time = time.time()
            result = detector.detect_provider_ultimate_with_virustotal(headers, ip, whois_data, domain)
            analysis_time = time.time() - start_time
            
            # Display results
            print(f"⏱️  Analysis time: {analysis_time:.2f}s")
            print(f"🌐 IP Address: {ip}")
            print(f"🏢 Primary Provider: {result['primary_provider']}")
            print(f"🦠 VirusTotal Enhanced: {result.get('virustotal_enhanced', False)}")
            
            # Show all providers by role
            providers_by_role = {}
            for provider in result['providers']:
                role = provider['role']
                if role not in providers_by_role:
                    providers_by_role[role] = []
                providers_by_role[role].append({
                    'name': provider['name'],
                    'source': provider.get('source', 'Internal')
                })
            
            for role, providers in providers_by_role.items():
                provider_list = []
                for p in providers:
                    source_indicator = " (VT)" if p['source'] == 'VirusTotal' else ""
                    provider_list.append(f"{p['name']}{source_indicator}")
                print(f"📍 {role}: {', '.join(provider_list)}")
            
            # VirusTotal specific data
            if result.get('virustotal_data'):
                vt_data = result['virustotal_data']
                print(f"🎯 VT Confidence: {vt_data.get('confidence_score', 0)}%")
                
                reputation = vt_data.get('reputation', 0)
                if reputation != 0:
                    rep_indicator = "👍" if reputation > 0 else "👎"
                    print(f"🛡️  Reputation: {reputation} {rep_indicator}")
                
                stats = vt_data.get('last_analysis_stats', {})
                if stats:
                    total_engines = sum(stats.values())
                    if total_engines > 0:
                        print(f"🔍 Security Analysis: {stats.get('harmless', 0)} clean, "
                              f"{stats.get('malicious', 0)} malicious, "
                              f"{stats.get('suspicious', 0)} suspicious")
                        
                        if stats.get('malicious', 0) > 0:
                            print("🚨 WARNING: Domain flagged as malicious by some engines!")
            
            # Confidence factors
            if result.get('confidence_factors'):
                print("📊 Confidence Factors:")
                for factor in result['confidence_factors']:
                    print(f"   • {factor}")
            
        except Exception as e:
            print(f"❌ Error analyzing {domain}: {str(e)}")
    
    print(f"\n📊 Test Summary:")
    vt_status = "Enabled" if detector.vt_integrator and detector.vt_integrator.is_enabled() else "Disabled"
    print(f"   VirusTotal Status: {vt_status}")
    print(f"   AWS ranges loaded: {len(detector.aws_ranges)}")
    print(f"   Cloudflare ranges loaded: {len(detector.cloudflare_ranges)}")
    
    return True

def test_rate_limiting():
    """Test VirusTotal rate limiting"""
    print("\n⏱️  Testing VirusTotal Rate Limiting")
    print("=" * 40)
    
    vt_api_key = os.getenv('VT_API_KEY')
    if not vt_api_key:
        print("⚠️ VirusTotal API key not found - skipping rate limit test")
        return
    
    detector = UltimateProviderDetector(vt_api_key=vt_api_key)
    
    if not (detector.vt_integrator and detector.vt_integrator.is_enabled()):
        print("⚠️ VirusTotal not enabled - skipping rate limit test")
        return
    
    # Test multiple rapid requests (should be rate limited)
    test_domains = ["example.com", "google.com", "github.com", "cloudflare.com", "microsoft.com"]
    
    print(f"Testing {len(test_domains)} requests to verify rate limiting...")
    
    start_time = time.time()
    for i, domain in enumerate(test_domains):
        print(f"Request {i+1}: {domain}")
        try:
            result = detector.vt_integrator.analyze_domain_comprehensive(domain)
            if 'error' not in result:
                print(f"  ✅ Success - Confidence: {result.get('confidence_score', 0)}%")
            else:
                print(f"  ⚠️  Error: {result['error']}")
        except Exception as e:
            print(f"  ❌ Exception: {str(e)}")
    
    total_time = time.time() - start_time
    print(f"\nTotal time for {len(test_domains)} requests: {total_time:.1f}s")
    print(f"Average time per request: {total_time/len(test_domains):.1f}s")
    
    if total_time > 60:  # Should take at least 1 minute for 5 requests due to rate limiting
        print("✅ Rate limiting appears to be working correctly")
    else:
        print("⚠️ Rate limiting may not be working as expected")

def test_without_api_key():
    """Test functionality without VirusTotal API key"""
    print("\n🔧 Testing without VirusTotal API key")
    print("=" * 40)
    
    # Temporarily remove API key
    original_key = os.environ.get('VT_API_KEY')
    if 'VT_API_KEY' in os.environ:
        del os.environ['VT_API_KEY']
    
    try:
        detector = UltimateProviderDetector()
        
        domain = "github.com"
        headers = detector.get_headers(domain)
        ip = detector.get_ip(domain)
        whois_data = detector.get_whois(ip) if ip else ""
        
        # Should still work without VirusTotal
        result = detector.detect_provider_ultimate_with_virustotal(headers, ip, whois_data, domain)
        
        print(f"✅ Analysis completed without VirusTotal")
        print(f"🏢 Primary Provider: {result['primary_provider']}")
        print(f"🦠 VirusTotal Enhanced: {result.get('virustotal_enhanced', False)}")
        
        if not result.get('virustotal_enhanced', True):  # Should be False
            print("✅ Graceful fallback working correctly")
        else:
            print("⚠️ Expected VirusTotal to be disabled")
    
    finally:
        # Restore API key
        if original_key:
            os.environ['VT_API_KEY'] = original_key

if __name__ == "__main__":
    try:
        success = test_virustotal_integration()
        
        if success:
            test_rate_limiting()
        
        test_without_api_key()
        
        print("\n✅ Phase 2B testing completed!")
        
    except KeyboardInterrupt:
        print("\n⚠️ Testing interrupted by user")
    except Exception as e:
        print(f"\n❌ Testing failed: {str(e)}")
        sys.exit(1)
