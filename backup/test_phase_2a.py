#!/usr/bin/env python3
"""
Test script for Phase 2A DNS Analysis features
"""
import sys
import os
import time
from ultimate_provider_detector import UltimateProviderDetector

def test_dns_analysis():
    """Test Phase 2A DNS analysis features"""
    print("🧪 Testing Phase 2A: Advanced DNS Analysis")
    print("=" * 60)
    
    detector = UltimateProviderDetector()
    
    # Test domains with different providers
    test_domains = [
        "github.com",       # GitHub + Fastly CDN
        "cloudflare.com",   # Cloudflare
        "google.com",       # Google
        "microsoft.com",    # Microsoft
        "aws.amazon.com",   # AWS
        "stackoverflow.com" # Fastly CDN
    ]
    
    for domain in test_domains:
        print(f"\n🔍 Analyzing: {domain}")
        print("-" * 40)
        
        try:
            # Get basic info
            headers = detector.get_headers(domain)
            ip = detector.get_ip(domain)
            whois_data = detector.get_whois(ip) if ip else ""
            
            # Phase 2A: Enhanced analysis
            start_time = time.time()
            result = detector.detect_provider_multi_layer_enhanced(headers, ip, whois_data, domain)
            analysis_time = time.time() - start_time
            
            # Display results
            print(f"⏱️  Analysis time: {analysis_time:.2f}s")
            print(f"🌐 IP Address: {ip}")
            print(f"🏢 Primary Provider: {result['primary_provider']}")
            
            # Show all providers by role
            providers_by_role = {}
            for provider in result['providers']:
                role = provider['role']
                if role not in providers_by_role:
                    providers_by_role[role] = []
                providers_by_role[role].append(provider['name'])
            
            for role, providers in providers_by_role.items():
                print(f"📍 {role}: {', '.join(providers)}")
            
            # DNS Analysis
            dns_analysis = result.get('dns_analysis', {})
            if dns_analysis.get('dns_providers'):
                print(f"🔧 DNS Providers:")
                for dns_prov in dns_analysis['dns_providers']:
                    print(f"   • {dns_prov['provider']}: {dns_prov['ns_server']}")
                
                dns_diversity = dns_analysis.get('dns_diversity', 0)
                if dns_diversity > 1:
                    print(f"⚠️  Complex DNS setup - {dns_diversity} different providers")
            
            # TTL Analysis
            ttl_analysis = result.get('ttl_analysis', {})
            if ttl_analysis:
                print("📊 TTL Analysis:")
                for record_type, ttl_info in ttl_analysis.items():
                    if 'ttl' in ttl_info:
                        indicator = ttl_info.get('migration_indicator', 'unknown')
                        emoji = "🚨" if indicator == 'high' else "⚠️" if indicator == 'medium' else "✅"
                        print(f"   {emoji} {record_type}: {ttl_info['description']}")
            
            # Confidence factors
            if result.get('confidence_factors'):
                print("🎯 Confidence Factors:")
                for factor in result['confidence_factors']:
                    print(f"   • {factor}")
            
        except Exception as e:
            print(f"❌ Error analyzing {domain}: {str(e)}")
    
    print(f"\n📊 Test Summary:")
    print(f"   Tested domains: {len(test_domains)}")
    print(f"   AWS ranges loaded: {len(detector.aws_ranges)}")
    print(f"   Cloudflare ranges loaded: {len(detector.cloudflare_ranges)}")

def test_ns_analysis():
    """Test NS record analysis specifically"""
    print("\n🔬 Testing NS Record Analysis")
    print("=" * 40)
    
    detector = UltimateProviderDetector()
    
    test_cases = [
        ("github.com", "Expected: GitHub DNS or third-party"),
        ("cloudflare.com", "Expected: Cloudflare DNS"),
        ("google.com", "Expected: Google Cloud DNS"),
        ("digitalocean.com", "Expected: DigitalOcean DNS")
    ]
    
    for domain, expectation in test_cases:
        try:
            result = detector.analyze_ns_records(domain)
            print(f"\n🌐 {domain} ({expectation})")
            
            if result.get('error'):
                print(f"❌ Error: {result['error']}")
            else:
                print(f"🔧 DNS Providers found: {len(result.get('dns_providers', []))}")
                for dns_prov in result.get('dns_providers', []):
                    print(f"   • {dns_prov['provider']}: {dns_prov['ns_server']}")
                
                if result.get('all_ns_servers'):
                    print(f"📋 All NS servers: {', '.join(result['all_ns_servers'])}")
        
        except Exception as e:
            print(f"❌ Error testing {domain}: {str(e)}")

def test_ttl_analysis():
    """Test TTL analysis specifically"""
    print("\n⏱️  Testing TTL Analysis")
    print("=" * 40)
    
    detector = UltimateProviderDetector()
    
    test_domains = ["github.com", "cloudflare.com", "google.com"]
    
    for domain in test_domains:
        try:
            result = detector.analyze_ttl_patterns(domain)
            print(f"\n🌐 {domain}")
            
            for record_type, ttl_info in result.items():
                if 'error' in ttl_info:
                    print(f"❌ {record_type}: {ttl_info['error']}")
                else:
                    indicator = ttl_info.get('migration_indicator', 'unknown')
                    emoji = "🚨" if indicator == 'high' else "⚠️" if indicator == 'medium' else "✅"
                    print(f"{emoji} {record_type}: {ttl_info['description']}")
        
        except Exception as e:
            print(f"❌ Error testing {domain}: {str(e)}")

if __name__ == "__main__":
    try:
        test_dns_analysis()
        test_ns_analysis() 
        test_ttl_analysis()
        print("\n✅ Phase 2A testing completed!")
        
    except KeyboardInterrupt:
        print("\n⚠️ Testing interrupted by user")
    except Exception as e:
        print(f"\n❌ Testing failed: {str(e)}")
        sys.exit(1)
