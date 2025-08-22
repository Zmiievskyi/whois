#!/usr/bin/env python3
"""
IP Range Management for Provider Detection
Handles loading and querying official IP ranges from various providers
"""
import ipaddress
import requests
import logging
from typing import Set, Optional, Dict, List
from ..config.settings import get_settings


class IPRangeManager:
    """Manages IP ranges for provider detection"""
    
    def __init__(self):
        """Initialize IP range manager"""
        self.aws_ranges: Set[str] = set()
        self.cloudflare_ranges: Set[str] = set()
        self.settings = get_settings()
        self.logger = logging.getLogger(__name__)
        
        # Load ranges on initialization
        self.load_all_ranges()
    
    def load_all_ranges(self):
        """Load IP ranges from all official sources"""
        self.logger.info("Loading official IP ranges...")
        
        try:
            # Load AWS ranges from official JSON
            self.load_aws_ranges()
            self.logger.info(f"✓ Loaded {len(self.aws_ranges)} AWS IP ranges")
        except Exception as e:
            self.logger.error(f"Could not load AWS ranges: {e}")
            self.load_aws_ranges_fallback()
        
        try:
            # Load Cloudflare ranges
            self.load_cloudflare_ranges()
            self.logger.info(f"✓ Loaded {len(self.cloudflare_ranges)} Cloudflare IP ranges")
        except Exception as e:
            self.logger.error(f"Could not load Cloudflare ranges: {e}")
            self.load_cloudflare_ranges_fallback()
    
    def load_aws_ranges(self):
        """Load AWS IP ranges from official JSON"""
        try:
            response = requests.get(
                'https://ip-ranges.amazonaws.com/ip-ranges.json', 
                timeout=self.settings.http_timeout
            )
            response.raise_for_status()
            aws_data = response.json()
            
            # Extract all AWS prefixes
            for prefix in aws_data['prefixes']:
                self.aws_ranges.add(prefix['ip_prefix'])
            
            # Extract IPv6 prefixes (convert to string for consistency)
            for prefix in aws_data['ipv6_prefixes']:
                self.aws_ranges.add(prefix['ipv6_prefix'])
                
        except Exception as e:
            raise Exception(f"Failed to load AWS ranges: {e}")
    
    def load_aws_ranges_fallback(self):
        """Fallback AWS ranges if official source fails"""
        fallback_ranges = [
            # Core AWS ranges
            "52.0.0.0/8", "54.0.0.0/8", "13.0.0.0/8", "35.0.0.0/8",
            "3.0.0.0/8", "18.0.0.0/8", "34.192.0.0/10", "34.208.0.0/12",
            # CloudFront ranges
            "205.251.0.0/16", "204.246.0.0/16", "99.84.0.0/16", "143.204.0.0/16",
            "13.32.0.0/15", "13.35.0.0/16", "144.220.0.0/16", "54.230.0.0/16",
            # Additional AWS ranges
            "52.94.0.0/16", "52.95.0.0/16", "54.239.0.0/16", "107.20.0.0/14",
            "205.251.240.0/22", "205.251.244.0/22", "205.251.248.0/22"
        ]
        self.aws_ranges.update(fallback_ranges)
        self.logger.warning(f"Using AWS fallback ranges: {len(fallback_ranges)} ranges")
    
    def load_cloudflare_ranges(self):
        """Load Cloudflare IP ranges from official source"""
        try:
            # IPv4 ranges
            response_v4 = requests.get(
                'https://www.cloudflare.com/ips-v4', 
                timeout=self.settings.http_timeout
            )
            response_v4.raise_for_status()
            
            for line in response_v4.text.strip().split('\n'):
                if line.strip():
                    self.cloudflare_ranges.add(line.strip())
            
            # IPv6 ranges (for completeness)
            response_v6 = requests.get(
                'https://www.cloudflare.com/ips-v6', 
                timeout=self.settings.http_timeout
            )
            response_v6.raise_for_status()
            
            for line in response_v6.text.strip().split('\n'):
                if line.strip():
                    self.cloudflare_ranges.add(line.strip())
                    
        except Exception as e:
            raise Exception(f"Failed to load Cloudflare ranges: {e}")
    
    def load_cloudflare_ranges_fallback(self):
        """Fallback Cloudflare ranges if official source fails"""
        fallback_ranges = [
            "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
            "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
            "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
            "104.24.0.0/14", "172.64.0.0/13", "104.18.0.0/16", "131.0.72.0/22"
        ]
        self.cloudflare_ranges.update(fallback_ranges)
        self.logger.warning(f"Using Cloudflare fallback ranges: {len(fallback_ranges)} ranges")

    def analyze_ip_ranges_official(self, ip: str) -> Optional[str]:
        """
        Analyze IP against official provider ranges
        
        Args:
            ip: IP address to analyze
            
        Returns:
            Provider name if matched, None otherwise
        """
        if not ip:
            return None
        
        try:
            ip_addr = ipaddress.ip_address(ip)
            
            # Check AWS ranges
            for range_str in self.aws_ranges:
                try:
                    if ip_addr in ipaddress.ip_network(range_str):
                        return "AWS"
                except ValueError:
                    continue
            
            # Check Cloudflare ranges
            for range_str in self.cloudflare_ranges:
                try:
                    if ip_addr in ipaddress.ip_network(range_str):
                        return "Cloudflare"
                except ValueError:
                    continue
            
            # Static ranges for other major providers
            static_ranges = self.get_static_provider_ranges()
            
            for provider, ranges in static_ranges.items():
                for range_str in ranges:
                    try:
                        if ip_addr in ipaddress.ip_network(range_str):
                            return provider
                    except ValueError:
                        continue
            
        except ValueError:
            # Invalid IP address
            return None
        
        return None
    
    def get_static_provider_ranges(self) -> Dict[str, List[str]]:
        """Get static IP ranges for providers without official APIs"""
        return {
            "Google": [
                "8.8.8.0/24", "8.8.4.0/24", "8.34.208.0/20", "8.35.192.0/20",
                "23.236.48.0/20", "23.251.128.0/19", "34.64.0.0/10", "34.128.0.0/10",
                "35.184.0.0/13", "35.192.0.0/14", "35.196.0.0/15", "35.198.0.0/16",
                "35.199.0.0/17", "35.199.128.0/18", "35.200.0.0/13", "35.208.0.0/12",
                "35.224.0.0/12", "35.240.0.0/13", "64.233.160.0/19", "66.102.0.0/20",
                "66.249.80.0/20", "72.14.192.0/18", "74.125.0.0/16", "108.177.8.0/21",
                "142.250.0.0/15", "172.217.0.0/16", "173.194.0.0/16", "209.85.128.0/17",
                "216.58.192.0/19", "216.239.32.0/19"
            ],
            "Microsoft": [
                "13.64.0.0/11", "13.96.0.0/13", "13.104.0.0/14", "20.0.0.0/6",
                "23.96.0.0/13", "40.64.0.0/10", "52.96.0.0/12", "52.112.0.0/14",
                "52.120.0.0/14", "52.124.0.0/16", "65.52.0.0/14", "70.37.0.0/17",
                "94.245.64.0/18", "103.9.8.0/22", "103.25.156.0/22", "104.40.0.0/13",
                "131.253.1.0/24", "134.170.0.0/16", "137.116.0.0/16", "138.91.0.0/16",
                "157.55.0.0/16", "168.61.0.0/16", "168.62.0.0/15", "191.232.0.0/13",
                "199.30.16.0/20", "204.79.180.0/24", "207.46.0.0/16"
            ],
            "DigitalOcean": [
                "104.131.0.0/16", "138.197.0.0/16", "139.59.0.0/16", "142.93.0.0/16",
                "143.110.0.0/16", "157.230.0.0/16", "164.90.0.0/16", "165.22.0.0/16",
                "165.227.0.0/16", "167.71.0.0/16", "167.99.0.0/16", "68.183.0.0/16",
                "188.166.0.0/16", "188.226.0.0/16", "46.101.0.0/16", "159.89.0.0/16",
                "178.62.0.0/16", "128.199.0.0/16", "192.241.0.0/16", "162.243.0.0/16"
            ],
            "Linode": [
                "96.126.96.0/19", "173.255.192.0/18", "45.79.0.0/16", "66.175.208.0/20",
                "74.207.224.0/19", "173.230.128.0/19", "69.164.192.0/19", "50.116.0.0/16",
                "139.162.0.0/16", "172.104.0.0/15", "139.144.0.0/16", "45.33.0.0/16",
                "198.58.96.0/19", "23.239.0.0/16", "72.14.176.0/20", "97.107.128.0/19"
            ],
            "Vultr": [
                "45.32.0.0/16", "45.63.0.0/16", "45.76.0.0/16", "64.176.0.0/16",
                "66.42.0.0/16", "95.179.128.0/17", "104.156.224.0/19", "108.61.0.0/16",
                "140.82.0.0/16", "144.202.0.0/16", "149.28.0.0/16", "207.148.64.0/18",
                "216.128.128.0/17", "217.163.8.0/21"
            ]
        }
    
    def get_provider_by_ip(self, ip: str) -> Optional[str]:
        """
        Get provider for IP address (alias for analyze_ip_ranges_official)
        
        Args:
            ip: IP address to check
            
        Returns:
            Provider name or None
        """
        return self.analyze_ip_ranges_official(ip)
    
    def is_aws_ip(self, ip: str) -> bool:
        """Check if IP belongs to AWS"""
        return self.analyze_ip_ranges_official(ip) == "AWS"
    
    def is_cloudflare_ip(self, ip: str) -> bool:
        """Check if IP belongs to Cloudflare"""
        return self.analyze_ip_ranges_official(ip) == "Cloudflare"
    
    def get_stats(self) -> Dict[str, int]:
        """Get statistics about loaded ranges"""
        return {
            'aws_ranges': len(self.aws_ranges),
            'cloudflare_ranges': len(self.cloudflare_ranges),
            'total_ranges': len(self.aws_ranges) + len(self.cloudflare_ranges)
        }
    
    def reload_ranges(self):
        """Reload all IP ranges from sources"""
        self.aws_ranges.clear()
        self.cloudflare_ranges.clear()
        self.load_all_ranges()


# Global IP range manager instance
_global_ip_manager: Optional[IPRangeManager] = None


def get_ip_range_manager() -> IPRangeManager:
    """Get global IP range manager instance"""
    global _global_ip_manager
    if _global_ip_manager is None:
        _global_ip_manager = IPRangeManager()
    return _global_ip_manager


# Example usage and testing
if __name__ == "__main__":
    # Test IP range manager
    manager = IPRangeManager()
    
    # Test known IPs
    test_ips = [
        ("8.8.8.8", "Google"),
        ("1.1.1.1", "Cloudflare"), 
        ("54.239.25.192", "AWS"),
        ("13.107.42.14", "Microsoft"),
        ("192.168.1.1", None)  # Private IP
    ]
    
    print("🌐 Testing IP Range Detection:")
    for ip, expected in test_ips:
        detected = manager.get_provider_by_ip(ip)
        status = "✅" if detected == expected else "❌"
        print(f"{status} {ip} → {detected} (expected: {expected})")
    
    # Show statistics
    stats = manager.get_stats()
    print(f"\n📊 IP Range Statistics:")
    for key, value in stats.items():
        print(f"   {key}: {value}")
