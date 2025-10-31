#!/usr/bin/env python3
"""
IPInfo.io Integration
Provides IP geolocation, ASN lookup, and network intelligence
Free tier: 50,000 requests/month with token, 1,000/day without token
"""

import logging
import requests
from typing import Dict, List, Optional, Any
from .base import HTTPIntegration

logger = logging.getLogger(__name__)

class IPInfoIntegration(HTTPIntegration):
    """
    IPInfo.io integration for IP intelligence and ASN data

    Features:
    - IP geolocation (city, region, country, coordinates)
    - ASN information (number, name, domain)
    - Network type detection (hosting, business, education)
    - Carrier/mobile detection
    - Privacy detection (VPN, proxy, tor)
    - Company information

    API Documentation: https://ipinfo.io/developers
    """

    def __init__(self, api_key: Optional[str] = None, cache_ttl: int = 7200):
        """
        Initialize IPInfo integration

        Args:
            api_key: IPInfo API token (optional, but recommended for 50k/month limit)
            cache_ttl: Cache TTL in seconds (default 2 hours)
        """
        # Use ipinfo.io directly (not api.ipinfo.io)
        super().__init__(
            service_name="ipinfo",
            base_url="https://ipinfo.io",
            api_key=api_key
        )

        self.cache_ttl = cache_ttl

        # Setup rate limiting
        if hasattr(self.rate_limiter, 'add_service'):
            # Free tier: 50k/month with token ≈ 1666/day ≈ 69/hour ≈ 1/min (conservative)
            # Without token: 1000/day ≈ 41/hour ≈ 0.7/min
            rate_per_min = 60 if self.api_key else 40  # Conservative rates
            self.rate_limiter.add_service('ipinfo', rate_per_min, 60)

        logger.info(f"IPInfo integration initialized (API key: {'provided' if api_key else 'not provided'})")

    @property
    def is_enabled(self) -> bool:
        """IPInfo is always enabled (free tier available)"""
        return True

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for IPInfo API"""
        if self.api_key:
            return {"Authorization": f"Bearer {self.api_key}"}
        return {}

    def _make_ipinfo_request(self, endpoint: str, **kwargs) -> Dict[str, Any]:
        """
        Make API request to IPInfo with caching and rate limit handling

        Args:
            endpoint: API endpoint (e.g., "8.8.8.8", "AS15169")
            **kwargs: Additional request parameters

        Returns:
            API response data
        """
        # Check cache first
        cache_key = f"ipinfo_{hash(endpoint + str(kwargs))}"
        cached_result = self.cache.get('ipinfo', cache_key)
        if cached_result:
            return cached_result

        # Build URL (IPInfo uses simple URL structure: ipinfo.io/IP or ipinfo.io/AS)
        if self.api_key:
            url = f"{self.base_url}/{endpoint}?token={self.api_key}"
        else:
            url = f"{self.base_url}/{endpoint}"

        try:
            # Check rate limit
            if hasattr(self.rate_limiter, 'is_rate_limited') and self.rate_limiter.is_rate_limited('ipinfo'):
                return {'error': 'Rate limited - please try again later', 'rate_limited': True}

            # Apply rate limiting
            self.rate_limiter.wait_if_needed('ipinfo')

            response = requests.get(url, timeout=10, **kwargs)

            # Handle 429 specifically
            if response.status_code == 429:
                logger.debug(f"IPInfo API rate limited (429)")
                error_result = {'error': 'IPInfo API rate limited', 'rate_limited': True}
                # Cache the rate limit error for 5 minutes
                self.cache.set('ipinfo', cache_key, error_result, 300)
                return error_result

            response.raise_for_status()
            result = response.json()

            # Cache successful results
            self.cache.set('ipinfo', cache_key, result, self.cache_ttl)
            return result

        except Exception as e:
            error_str = str(e)
            if '429' not in error_str:
                logger.error(f"IPInfo API request failed for {url}: {e}")
            else:
                logger.debug(f"IPInfo API rate limited: {e}")

            return {'error': error_str, 'rate_limited': '429' in error_str}

    def get_ip_info(self, ip: str) -> Dict[str, Any]:
        """
        Get comprehensive information for an IP address

        Args:
            ip: IP address to lookup

        Returns:
            Dict with IP information including:
            - ip: IP address
            - hostname: Reverse DNS hostname
            - city, region, country: Geographic location
            - loc: Coordinates (lat,long)
            - org: Organization (includes ASN)
            - postal: Postal/ZIP code
            - timezone: Timezone
            - asn: ASN number (parsed from org)
            - asn_name: ASN name (parsed from org)
        """
        cache_key = f"ip_info_{ip}"
        cached_result = self.cache.get('ipinfo', cache_key)
        if cached_result:
            return cached_result

        try:
            result = self._make_ipinfo_request(ip)

            if 'error' in result:
                return result

            # Parse ASN from org field (format: "AS15169 Google LLC")
            org = result.get('org', '')
            asn_number = 0
            asn_name = ''

            if org.startswith('AS'):
                parts = org.split(' ', 1)
                if len(parts) >= 1:
                    try:
                        asn_number = int(parts[0][2:])  # Remove "AS" prefix
                    except ValueError:
                        pass
                if len(parts) >= 2:
                    asn_name = parts[1]

            # Enrich the result with parsed ASN data
            enriched = {
                'ip': result.get('ip', ip),
                'hostname': result.get('hostname', ''),
                'city': result.get('city', ''),
                'region': result.get('region', ''),
                'country': result.get('country', ''),
                'country_code': result.get('country', ''),
                'loc': result.get('loc', ''),
                'org': org,
                'postal': result.get('postal', ''),
                'timezone': result.get('timezone', ''),
                'asn': asn_number,
                'asn_name': asn_name,
                'asn_description': asn_name,  # For compatibility with BGPView format
                'anycast': result.get('anycast', False),
                'data_source': 'ipinfo'
            }

            # Parse coordinates
            if enriched['loc']:
                try:
                    lat, lon = enriched['loc'].split(',')
                    enriched['latitude'] = float(lat)
                    enriched['longitude'] = float(lon)
                except (ValueError, AttributeError):
                    pass

            # Cache the enriched result
            self.cache.set('ipinfo', cache_key, enriched, self.cache_ttl)

            return enriched

        except Exception as e:
            logger.error(f"Failed to get IP info for {ip}: {e}")
            return {'error': str(e), 'ip': ip}

    def get_asn_details(self, asn: int) -> Dict[str, Any]:
        """
        Get detailed information about an ASN

        Args:
            asn: Autonomous System Number

        Returns:
            Dict with ASN details including:
            - asn: ASN number
            - name: Organization name
            - country: Country code
            - allocated: Allocation date
            - registry: RIR (ARIN, RIPE, etc.)
            - domain: Associated domain
            - type: ASN type (hosting, isp, business, education)
        """
        cache_key = f"asn_details_{asn}"
        cached_result = self.cache.get('ipinfo', cache_key)
        if cached_result:
            return cached_result

        try:
            # IPInfo ASN endpoint format: /AS15169
            endpoint = f"AS{asn}"
            result = self._make_ipinfo_request(endpoint)

            if 'error' in result:
                # If ASN endpoint requires token, return basic info
                if 'token' in result.get('error', '').lower():
                    return {
                        'asn': asn,
                        'name': '',
                        'error': 'ASN details require API token',
                        'requires_token': True
                    }
                return result

            # Format ASN details
            asn_details = {
                'asn': asn,
                'name': result.get('name', ''),
                'country': result.get('country', ''),
                'country_code': result.get('country', ''),
                'allocated': result.get('allocated', ''),
                'registry': result.get('registry', ''),
                'domain': result.get('domain', ''),
                'type': result.get('type', ''),
                'num_ips': result.get('num_ips', 0),
                'prefixes': result.get('prefixes', []),
                'prefixes_v6': result.get('prefixes6', []),
                'data_source': 'ipinfo'
            }

            # Cache the result
            self.cache.set('ipinfo', cache_key, asn_details, self.cache_ttl)

            return asn_details

        except Exception as e:
            logger.error(f"Failed to get ASN details for {asn}: {e}")
            return {'error': str(e), 'asn': asn}

    def get_bulk_ip_info(self, ips: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Get information for multiple IPs (batch processing)

        Note: Bulk lookup is only available in paid tiers
        This method makes individual requests for free tier

        Args:
            ips: List of IP addresses

        Returns:
            Dict mapping IP to info
        """
        results = {}

        for ip in ips:
            info = self.get_ip_info(ip)
            results[ip] = info

        return results

    def test_connection(self) -> Dict[str, Any]:
        """Test IPInfo API connection"""
        try:
            # Check rate limit first
            if hasattr(self.rate_limiter, 'is_rate_limited') and self.rate_limiter.is_rate_limited('ipinfo'):
                return {
                    'success': False,
                    'error': 'Rate limited - please wait before testing IPInfo API',
                    'rate_limited': True
                }

            # Test with Google DNS
            result = self.get_ip_info('8.8.8.8')

            if 'error' in result:
                return {
                    'success': False,
                    'error': result['error'],
                    'rate_limited': result.get('rate_limited', False)
                }

            # Success case
            return {
                'success': True,
                'message': 'IPInfo integration working',
                'test_ip': '8.8.8.8',
                'test_asn': result.get('asn'),
                'test_name': result.get('asn_name', 'Unknown'),
                'api_status': 'available',
                'has_token': bool(self.api_key)
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

# Singleton instance
_ipinfo_integration = None

def get_ipinfo_integration() -> IPInfoIntegration:
    """Get singleton IPInfo integration instance"""
    global _ipinfo_integration
    if _ipinfo_integration is None:
        # Try to get API key from settings
        try:
            from ..config.settings import get_settings
            settings = get_settings()
            api_key = getattr(settings, 'ipinfo_api_key', None)
            _ipinfo_integration = IPInfoIntegration(api_key=api_key)
        except Exception:
            # Fallback to no API key
            _ipinfo_integration = IPInfoIntegration()
    return _ipinfo_integration
