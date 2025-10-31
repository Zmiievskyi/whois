#!/usr/bin/env python3
"""
Demo: Multi-Source BGP Strategy
Demonstrates the new intelligent BGP data sourcing with automatic fallback
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from provider_discovery.integrations.bgp_analysis import BGPAnalysisIntegration
from provider_discovery.config.settings import get_settings


def print_section(title: str):
    """Print section header"""
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print('=' * 80)


def print_asn_info(ip: str, info: dict):
    """Pretty print ASN information"""
    print(f"\n📍 IP Address: {ip}")
    print(f"   Data Source: {info.get('data_source', 'unknown').upper()}")

    if 'error' in info:
        print(f"   ❌ Error: {info['error']}")
        return

    print(f"   🏢 ASN: AS{info.get('asn', 0)}")
    print(f"   📛 Organization: {info.get('asn_name', 'Unknown')}")

    if info.get('country_code'):
        print(f"   🌍 Country: {info.get('country_code')}")

    # Bonus data from IPInfo
    if info.get('city'):
        print(f"   🏙️  City: {info.get('city')}, {info.get('region', '')}")

    if info.get('latitude') and info.get('longitude'):
        print(f"   📍 Coordinates: {info.get('latitude')}, {info.get('longitude')}")

    if info.get('hostname'):
        print(f"   🖥️  Hostname: {info.get('hostname')}")

    if info.get('timezone'):
        print(f"   🕐 Timezone: {info.get('timezone')}")

    if info.get('anycast'):
        print(f"   🌐 Anycast: Yes (likely CDN)")


def main():
    """Run multi-source BGP demo"""
    print("\n🚀 Multi-Source BGP Strategy Demo")
    print("Strategy: IPInfo.io → Hurricane Electric → RIPE → Local Classifier")

    # Initialize settings and BGP integration
    settings = get_settings()
    bgp = BGPAnalysisIntegration()

    # Test connection
    print_section("Testing Multi-Source BGP Connection")
    test_result = bgp.test_connection()

    if test_result.get('success'):
        print("✅ Multi-Source BGP is working!")
        print(f"   Primary Source: {test_result.get('data_source', 'unknown')}")
        print(f"   Test IP: {test_result.get('test_ip')}")
        print(f"   Test ASN: AS{test_result.get('test_asn')}")
        print(f"   Test Name: {test_result.get('test_name')}")

        sources_available = test_result.get('sources_available', {})
        print(f"\n   Available Sources:")
        for source, available in sources_available.items():
            status = "✅" if available else "❌"
            print(f"     {status} {source}")
    else:
        print(f"❌ Error: {test_result.get('error')}")
        return

    # Test with various well-known IPs
    print_section("Testing Well-Known IP Addresses")

    test_ips = [
        ("8.8.8.8", "Google Public DNS"),
        ("1.1.1.1", "Cloudflare DNS"),
        ("13.107.21.200", "Microsoft Azure"),
        ("54.239.28.85", "Amazon AWS"),
    ]

    for ip, description in test_ips:
        print(f"\n🔍 Analyzing: {description}")
        info = bgp.get_ip_asn_info(ip)
        print_asn_info(ip, info)

    # Show domain analysis
    print_section("Domain BGP Analysis Example")

    domain = "google.com"
    print(f"\n🌐 Analyzing domain: {domain}")

    analysis = bgp.get_domain_bgp_analysis(domain)

    if 'error' not in analysis:
        print(f"   Resolved IPs: {', '.join(analysis.get('resolved_ips', []))}")
        print(f"   Total ASNs: {analysis.get('total_asns', 0)}")

        primary_asn = analysis.get('primary_asn')
        if primary_asn:
            print(f"\n   Primary ASN:")
            print(f"     ASN: AS{primary_asn.get('asn')}")
            print(f"     Name: {primary_asn.get('name')}")
            print(f"     Country: {primary_asn.get('country')}")
            print(f"     IP Count: {primary_asn.get('ip_count')}")

        geo = analysis.get('geographic_distribution', {})
        if geo:
            print(f"\n   Geographic Distribution:")
            for country, count in geo.get('countries', {}).items():
                print(f"     {country}: {count} IP(s)")
    else:
        print(f"   ❌ Error: {analysis.get('error')}")

    # Summary
    print_section("Summary")
    print("""
✅ Multi-Source BGP Strategy is fully operational!

Key Benefits:
  • Reliable data with automatic fallback
  • Enhanced geolocation data (city, coordinates) from IPInfo.io
  • 50,000 free requests per month with IPInfo token
  • Works even without API token (1000/day limit)
  • Seamless migration from unreliable BGPView

Next Steps:
  1. Get your free IPInfo token: https://ipinfo.io/signup
  2. Add to .env: IPINFO_API_KEY=your_token_here
  3. Enjoy enhanced BGP/ASN intelligence!
    """)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
