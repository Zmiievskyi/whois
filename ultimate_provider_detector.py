#!/usr/bin/env python3
"""
Ultimate provider detector with real-time IP range updates
Uses official sources for maximum accuracy and coverage
"""
import csv
import subprocess
import socket
import os
import re
import ipaddress
import requests
import json
from urllib.parse import urlparse
from typing import Dict, List, Optional, Set

class UltimateProviderDetector:
    def __init__(self):
        self.aws_ranges: Set[str] = set()
        self.cloudflare_ranges: Set[str] = set()
        self.ip_cache: Dict[str, Optional[str]] = {}
        self.load_official_ip_ranges()
    
    def load_official_ip_ranges(self):
        """Load IP ranges from official sources"""
        print("Loading official IP ranges...")
        
        try:
            # Load AWS ranges from official JSON
            self.load_aws_ranges()
            print(f"✓ Loaded {len(self.aws_ranges)} AWS IP ranges")
        except Exception as e:
            print(f"⚠️ Could not load AWS ranges: {e}")
            self.load_aws_ranges_fallback()
        
        try:
            # Load Cloudflare ranges
            self.load_cloudflare_ranges()
            print(f"✓ Loaded {len(self.cloudflare_ranges)} Cloudflare IP ranges")
        except Exception as e:
            print(f"⚠️ Could not load Cloudflare ranges: {e}")
            self.load_cloudflare_ranges_fallback()
    
    def load_aws_ranges(self):
        """Load AWS IP ranges from official JSON"""
        try:
            response = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json', timeout=10)
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
    
    def load_cloudflare_ranges(self):
        """Load Cloudflare IP ranges from official source"""
        try:
            # IPv4 ranges
            response_v4 = requests.get('https://www.cloudflare.com/ips-v4', timeout=10)
            response_v4.raise_for_status()
            
            for line in response_v4.text.strip().split('\n'):
                if line.strip():
                    self.cloudflare_ranges.add(line.strip())
            
            # IPv6 ranges (for completeness)
            response_v6 = requests.get('https://www.cloudflare.com/ips-v6', timeout=10)
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

    def get_headers(self, url):
        """Get HTTP headers"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            result = subprocess.run(['curl', '-sI', url], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
            return result.stdout.decode()
        except:
            return ""

    def get_ip(self, url):
        """Get IP address with caching"""
        if url in self.ip_cache:
            return self.ip_cache[url]
        
        try:
            hostname = urlparse(url).hostname or url.replace('https://', '').replace('http://', '').split('/')[0]
            ip = socket.gethostbyname(hostname)
            self.ip_cache[url] = ip
            return ip
        except:
            self.ip_cache[url] = None
            return ""

    def get_whois(self, ip):
        """Get comprehensive WHOIS information"""
        try:
            # First try standard whois
            result = subprocess.run(['whois', ip], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
            whois_data = result.stdout.decode()
            
            # If it's a RIPE reference, get detailed info from RIPE
            if 'whois.ripe.net' in whois_data.lower() and 'refer:' in whois_data.lower():
                try:
                    ripe_result = subprocess.run(['whois', '-h', 'whois.ripe.net', ip], 
                                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
                    ripe_data = ripe_result.stdout.decode()
                    if ripe_data.strip():
                        whois_data += "\n\n# Additional RIPE data:\n" + ripe_data
                except:
                    pass
            
            # If it's an APNIC reference, get detailed info from APNIC  
            elif 'whois.apnic.net' in whois_data.lower() and 'refer:' in whois_data.lower():
                try:
                    apnic_result = subprocess.run(['whois', '-h', 'whois.apnic.net', ip], 
                                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
                    apnic_data = apnic_result.stdout.decode()
                    if apnic_data.strip():
                        whois_data += "\n\n# Additional APNIC data:\n" + apnic_data
                except:
                    pass
            
            return whois_data
        except:
            return ""

    def detect_provider_ultimate(self, headers, ip, whois_data):
        """Ultimate provider detection with maximum accuracy"""
        
        # Step 1: HTTP headers analysis (fastest and most reliable)
        provider_from_headers = self.analyze_headers_comprehensive(headers)
        if provider_from_headers:
            return provider_from_headers
        
        # Step 2: Official IP range analysis (most accurate)
        provider_from_ip = self.analyze_ip_ranges_official(ip)
        if provider_from_ip:
            return provider_from_ip
        
        # Step 3: Enhanced WHOIS analysis (check keywords first)
        provider_from_whois = self.analyze_whois_enhanced(whois_data)
        if provider_from_whois:
            return provider_from_whois
        
        # Step 4: Extract any organization as fallback
        fallback_provider = self.extract_organization_fallback(whois_data)
        if fallback_provider:
            # Double-check if the fallback contains known provider names
            fallback_lower = fallback_provider.lower()
            if any(keyword in fallback_lower for keyword in ['g-core', 'gcore']):
                return 'Gcore'
            return fallback_provider
        
        return "Unknown"

    def analyze_headers_comprehensive(self, headers):
        """Comprehensive HTTP headers analysis"""
        if not headers:
            return None
            
        headers_lower = headers.lower()
        
        # Major CDN providers with extensive patterns
        provider_patterns = {
            "Cloudflare": [
                r'cloudflare', r'cf-ray:', r'cf-cache-status:', r'cf-connecting-ip:',
                r'cf-visitor:', r'cf-request-id:', r'server:\s*cloudflare'
            ],
            "AWS": [
                r'server:\s*awselb', r'x-amz', r'cloudfront', r'aws', 
                r'x-cache:\s*.*cloudfront', r'server:\s*amazons3', r'x-amzn-'
            ],
            "Google": [
                r'server:\s*gws', r'x-goog', r'x-cloud-trace-context:', 
                r'server:\s*gfe', r'alt-svc:.*quic'
            ],
            "Microsoft": [
                r'server:\s*microsoft', r'x-ms-', r'azure', r'x-azure-',
                r'server:\s*iis', r'server:\s*.*azure'
            ],
            "GitHub": [
                r'github', r'x-github', r'server:\s*github'
            ],
            "Fastly": [
                r'x-served-by.*fastly', r'x-cache.*fastly', r'fastly-debug',
                r'x-timer:', r'via.*fastly'
            ],
            "Akamai": [
                r'x-cache.*akamai', r'akamaihd', r'server:\s*akamaighost',
                r'x-akamai-', r'server:\s*apache.*akamai'
            ],
            "Netlify": [
                r'server:\s*netlify', r'x-nf-'
            ],
            "Vercel": [
                r'server:\s*vercel', r'x-vercel'
            ]
        }
        
        for provider, patterns in provider_patterns.items():
            for pattern in patterns:
                if re.search(pattern, headers_lower):
                    return provider
        
        return None

    def analyze_ip_ranges_official(self, ip):
        """Analyze IP against official ranges"""
        if not ip:
            return None
            
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check Cloudflare ranges
            for range_str in self.cloudflare_ranges:
                try:
                    if ip_obj in ipaddress.ip_network(range_str):
                        return "Cloudflare"
                except:
                    continue
            
            # Check AWS ranges  
            for range_str in self.aws_ranges:
                try:
                    if ip_obj in ipaddress.ip_network(range_str):
                        return "AWS"
                except:
                    continue
            
            # Static ranges for other major providers
            other_providers = {
                "Google": [
                    "8.8.8.0/24", "8.8.4.0/24", "74.125.0.0/16", "142.250.0.0/15", 
                    "172.217.0.0/16", "216.58.192.0/19", "64.233.160.0/19", "66.249.80.0/20",
                    "72.14.192.0/18", "209.85.128.0/17", "173.194.0.0/16", "108.177.8.0/21",
                    "142.251.0.0/16", "172.253.0.0/16"
                ],
                "Microsoft": [
                    "13.64.0.0/11", "13.96.0.0/13", "13.104.0.0/14", "20.0.0.0/8",
                    "40.64.0.0/10", "52.96.0.0/12", "13.107.0.0/16", "104.40.0.0/13"
                ],
                "GitHub": [
                    "140.82.112.0/20", "143.55.64.0/20", "185.199.108.0/22",
                    "192.30.252.0/22", "20.26.0.0/16", "20.27.0.0/16"
                ],
                "DigitalOcean": [
                    "104.131.0.0/16", "138.197.0.0/16", "139.59.0.0/16", "142.93.0.0/16",
                    "143.110.0.0/16", "147.182.0.0/16", "157.245.0.0/16", "159.203.0.0/16",
                    "159.223.0.0/16", "161.35.0.0/16", "164.90.0.0/16", "165.22.0.0/16",
                    "167.71.0.0/16", "167.99.0.0/16", "188.166.0.0/16", "188.226.0.0/16"
                ],
                "Linode": [
                    "45.33.0.0/16", "45.56.0.0/16", "45.79.0.0/16", "66.175.208.0/20",
                    "69.164.192.0/18", "74.207.224.0/19", "96.126.96.0/19", "139.144.0.0/16",
                    "172.104.0.0/15", "173.255.192.0/18", "176.58.96.0/19", "178.79.128.0/17"
                ],
                "Vultr": [
                    "45.32.0.0/16", "45.63.0.0/16", "45.76.0.0/16", "45.77.0.0/16",
                    "63.209.32.0/19", "66.42.32.0/19", "95.179.128.0/17", "104.156.224.0/19",
                    "108.61.128.0/17", "149.28.0.0/16", "207.148.64.0/18", "208.167.224.0/19"
                ],
                "OVH": [
                    "137.74.0.0/16", "144.217.0.0/16", "147.135.0.0/16", "151.80.0.0/16",
                    "158.69.0.0/16", "164.132.0.0/16", "176.31.0.0/16", "178.32.0.0/15",
                    "188.165.0.0/16", "193.70.0.0/15"
                ]
            }
            
            for provider, ranges in other_providers.items():
                for range_str in ranges:
                    try:
                        if ip_obj in ipaddress.ip_network(range_str):
                            return provider
                    except:
                        continue
                        
        except:
            pass
        
        return None

    def analyze_whois_enhanced(self, whois_data):
        """Enhanced WHOIS analysis"""
        if not whois_data:
            return None
            
        whois_lower = whois_data.lower()
        
        # Comprehensive provider keywords
        provider_keywords = {
            'cloudflare': 'Cloudflare',
            'amazon': 'AWS',
            'aws': 'AWS',
            'google': 'Google',
            'microsoft': 'Microsoft',
            'github': 'GitHub',
            'akamai': 'Akamai',
            'fastly': 'Fastly',
            'netlify': 'Netlify',
            'vercel': 'Vercel',
            'digitalocean': 'DigitalOcean',
            'linode': 'Linode', 
            'vultr': 'Vultr',
            'ovh': 'OVH',
            'godaddy': 'GoDaddy',
            'bluehost': 'BlueHost',
            'hostgator': 'HostGator',
            'dreamhost': 'DreamHost',
            'siteground': 'SiteGround',
            'namecheap': 'Namecheap',
            'hetzner': 'Hetzner',
            'scaleway': 'Scaleway',
            'rackspace': 'Rackspace',
            'g-core': 'Gcore',
            'gcore': 'Gcore',
            'gcore labs': 'Gcore',
            'g-core labs': 'Gcore'
        }
        
        for keyword, provider in provider_keywords.items():
            if keyword in whois_lower:
                return provider
        
        return None

    def extract_organization_fallback(self, whois_data):
        """Extract any valid organization as fallback"""
        if not whois_data:
            return None
        
        # Enhanced patterns to capture more organization formats
        org_patterns = [
            r"orgname:\s*(.+)",
            r"org-name:\s*(.+)", 
            r"organisation:\s*(.+)",
            r"organization:\s*(.+)",
            r"org:\s*(.+)",
            r"owner:\s*(.+)",
            r"person:\s*(.+)",
            r"descr:\s*(.+)",
            # Additional patterns for different WHOIS formats
            r"address:\s*([^,\n]+(?:\s+[A-Z][a-z]+)*)\s*$",  # Company name in address
            r"netname:\s*([A-Z0-9][A-Z0-9-]*)",  # Network name
            r"route:\s*\d+\.\d+\.\d+\.\d+/\d+\s*\n\s*descr:\s*(.+)",  # Route description
        ]
        
        # Collect all potential organizations
        candidates = []
        
        for pattern in org_patterns:
            matches = re.finditer(pattern, whois_data, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                org = match.group(1).strip()
                
                if self.is_valid_organization(org):
                    cleaned = self.clean_organization_name(org)
                    if cleaned and len(cleaned) > 2:
                        # Check if it's a known provider name
                        org_lower = cleaned.lower()
                        if any(keyword in org_lower for keyword in ['gcore', 'g-core', 'labs']):
                            return 'Gcore'
                        candidates.append((len(cleaned), cleaned))
        
        # Return the best candidate (prefer reasonable length names)
        if candidates:
            # Sort by length preference (not too short, not too long)
            candidates.sort(key=lambda x: abs(x[0] - 15))  # Prefer ~15 char length
            return candidates[0][1]
        
        return None

    def is_valid_organization(self, org):
        """Check if organization name is valid"""
        if len(org) < 3:
            return False
        
        org_lower = org.lower()
        
        invalid_patterns = [
            r'^\s*$', r'^n/a$', r'^not available$', r'^private$', r'^redacted',
            r'^whois privacy', r'^see https?://', r'^\d+$', r'^[a-f0-9]{8,}$',
            r'^abuse', r'^contact', r'^registry', r'^registrar', r'^technical',
            r'^admin', r'^billing', r'^\.+$', r'^-+$'
        ]
        
        for pattern in invalid_patterns:
            if re.match(pattern, org_lower):
                return False
        
        return True

    def clean_organization_name(self, org):
        """Clean organization name"""
        cleaned = re.sub(r',?\s*(inc|llc|ltd|corp|corporation|co|company|gmbh|sa|srl|bv)\.?$', '', org, flags=re.IGNORECASE)
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        cleaned = ' '.join(word.capitalize() for word in cleaned.split())
        
        if len(cleaned) > 35:
            cleaned = cleaned[:35] + "..."
        
        return cleaned

    def process_csv_file(self, input_file, output_file):
        """Process CSV file with ultimate detection"""
        results = []
        
        with open(input_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            header = next(reader)
            
            for row in reader:
                if len(row) >= 2:
                    company, url = row[0], row[1]
                    
                    headers = self.get_headers(url)
                    ip = self.get_ip(url)
                    whois_data = self.get_whois(ip) if ip else ""
                    provider = self.detect_provider_ultimate(headers, ip, whois_data)
                    
                    results.append([company, url, provider, ip or 'N/A'])
                    print(f"✓ {company}: {provider}")
        
        # Save results
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Company', 'URL', 'Provider', 'IP_Address'])
            writer.writerows(results)
        
        print(f"\nResults saved to: {output_file}")

def main():
    """Main function"""
    print("🚀 Ultimate Provider Detector")
    print("Real-time IP ranges from official sources")
    print("=" * 60)
    
    detector = UltimateProviderDetector()
    
    # Test with our data
    test_csv = "/Users/anton/code-dev/provider_discovery/test_data.csv"
    
    if os.path.exists(test_csv):
        print("\nProcessing test data...")
        output_csv = "/Users/anton/code-dev/provider_discovery/ultimate_results.csv"
        detector.process_csv_file(test_csv, output_csv)
        
        print(f"\n📊 Summary:")
        print(f"   AWS ranges loaded: {len(detector.aws_ranges)}")
        print(f"   Cloudflare ranges loaded: {len(detector.cloudflare_ranges)}")
        print(f"   IP cache size: {len(detector.ip_cache)}")

if __name__ == "__main__":
    main()
