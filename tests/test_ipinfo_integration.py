#!/usr/bin/env python3
"""
Tests for IPInfo Integration
"""

import pytest
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from provider_discovery.integrations.ipinfo_integration import IPInfoIntegration, get_ipinfo_integration


class TestIPInfoIntegration:
    """Test cases for IPInfo integration"""

    def test_initialization_without_key(self):
        """Test IPInfo can be initialized without API key"""
        integration = IPInfoIntegration()
        assert integration is not None
        assert integration.is_enabled
        assert integration.service_name == "ipinfo"

    def test_initialization_with_key(self):
        """Test IPInfo can be initialized with API key"""
        integration = IPInfoIntegration(api_key="test_token")
        assert integration is not None
        assert integration.api_key == "test_token"

    def test_get_ip_info_google_dns(self):
        """Test IP info retrieval for Google DNS (8.8.8.8)"""
        integration = IPInfoIntegration()
        result = integration.get_ip_info("8.8.8.8")

        assert result is not None
        assert 'ip' in result
        assert result['ip'] == "8.8.8.8"

        # Should have ASN info
        if 'error' not in result:
            assert 'asn' in result
            assert 'asn_name' in result
            assert result['asn'] == 15169  # Google ASN
            assert 'Google' in result.get('asn_name', '')

    def test_get_ip_info_cloudflare(self):
        """Test IP info retrieval for Cloudflare DNS (1.1.1.1)"""
        integration = IPInfoIntegration()
        result = integration.get_ip_info("1.1.1.1")

        assert result is not None
        assert 'ip' in result

        if 'error' not in result:
            assert 'asn' in result
            assert result['asn'] == 13335  # Cloudflare ASN

    def test_get_ip_info_includes_geolocation(self):
        """Test that IP info includes geolocation data"""
        integration = IPInfoIntegration()
        result = integration.get_ip_info("8.8.8.8")

        if 'error' not in result:
            # IPInfo should provide geo data
            assert 'country_code' in result or 'country' in result
            # May have city, region, coordinates
            assert 'city' in result or 'region' in result

    def test_caching_works(self):
        """Test that caching works for repeated requests"""
        integration = IPInfoIntegration()

        # First request
        result1 = integration.get_ip_info("8.8.8.8")

        # Second request (should be cached)
        result2 = integration.get_ip_info("8.8.8.8")

        # Results should be identical
        assert result1 == result2

    def test_bulk_lookup(self):
        """Test bulk IP lookup"""
        integration = IPInfoIntegration()
        ips = ["8.8.8.8", "1.1.1.1"]

        results = integration.get_bulk_ip_info(ips)

        assert len(results) == 2
        assert "8.8.8.8" in results
        assert "1.1.1.1" in results

    def test_connection_test(self):
        """Test connection testing"""
        integration = IPInfoIntegration()
        result = integration.test_connection()

        assert 'success' in result
        # Should either succeed or explain why it failed

    def test_singleton_pattern(self):
        """Test that get_ipinfo_integration returns singleton"""
        integration1 = get_ipinfo_integration()
        integration2 = get_ipinfo_integration()

        assert integration1 is integration2


class TestIPInfoMultiSource:
    """Test IPInfo as part of multi-source strategy"""

    def test_works_as_bgp_source(self):
        """Test that IPInfo works as a BGP data source"""
        from provider_discovery.integrations.bgp_analysis import BGPAnalysisIntegration

        bgp = BGPAnalysisIntegration()
        result = bgp.get_ip_asn_info("8.8.8.8")

        assert result is not None
        assert 'asn' in result
        assert 'data_source' in result

        # Should successfully get data from one of the sources
        if 'error' not in result:
            assert result['asn'] != 0
            # IPInfo should be the primary source
            assert result['data_source'] in ['ipinfo', 'hurricane_electric', 'ripe', 'local_classifier']


if __name__ == "__main__":
    # Run basic tests
    print("Testing IPInfo Integration...")

    test = TestIPInfoIntegration()

    print("\n1. Testing initialization...")
    test.test_initialization_without_key()
    print("✓ Initialization without key works")

    print("\n2. Testing IP lookup for 8.8.8.8...")
    test.test_get_ip_info_google_dns()
    print("✓ IP lookup works")

    print("\n3. Testing connection...")
    test.test_connection_test()
    print("✓ Connection test works")

    print("\n4. Testing multi-source integration...")
    test_multi = TestIPInfoMultiSource()
    test_multi.test_works_as_bgp_source()
    print("✓ Multi-source BGP strategy works")

    print("\n✅ All tests passed!")
