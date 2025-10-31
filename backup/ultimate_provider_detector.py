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
import dns.resolver
from urllib.parse import urlparse
from typing import Dict, List, Optional, Set, Tuple

# VirusTotal integration (optional)
try:
    from virustotal_integrator import VirusTotalIntegrator
    VT_AVAILABLE = True
except ImportError:
    VT_AVAILABLE = False
    VirusTotalIntegrator = None

class UltimateProviderDetector:
    def __init__(self, vt_api_key: Optional[str] = None):
        self.aws_ranges: Set[str] = set()
        self.cloudflare_ranges: Set[str] = set()
        self.ip_cache: Dict[str, Optional[str]] = {}
        self.dns_cache: Dict[str, List] = {}
        
        # Initialize VirusTotal integration
        self.vt_integrator = None
        if VT_AVAILABLE and vt_api_key:
            try:
                self.vt_integrator = VirusTotalIntegrator(vt_api_key)
                if self.vt_integrator.is_enabled():
                    print("✅ VirusTotal integration enabled")
                else:
                    print("⚠️ VirusTotal integration failed to initialize")
                    self.vt_integrator = None
            except Exception as e:
                print(f"⚠️ VirusTotal integration error: {e}")
                self.vt_integrator = None
        elif not VT_AVAILABLE:
            print("⚠️ VirusTotal integration not available (install vt-py)")
        
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

    def analyze_dns_chain(self, domain: str) -> List[Dict]:
        """Analyze CNAME chain to identify all providers in the resolution path"""
        if domain in self.dns_cache:
            return self.dns_cache[domain]
        
        chain = []
        current_domain = domain
        visited = set()  # Prevent infinite loops
        
        try:
            while current_domain and current_domain not in visited:
                visited.add(current_domain)
                
                # Try to get CNAME record
                try:
                    answers = dns.resolver.resolve(current_domain, 'CNAME')
                    if answers:
                        cname = str(answers[0]).rstrip('.')
                        provider = self.identify_provider_from_domain(cname)
                        chain.append({
                            'domain': current_domain,
                            'cname': cname,
                            'provider': provider,
                            'role': self.determine_provider_role(provider, cname),
                            'type': 'CNAME'
                        })
                        current_domain = cname
                        continue
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    pass
                
                # If no CNAME, get A record
                try:
                    answers = dns.resolver.resolve(current_domain, 'A')
                    if answers:
                        ip = str(answers[0])
                        provider = self.analyze_ip_ranges_official(ip)
                        if not provider:
                            # Fallback to WHOIS if IP ranges don't match
                            whois_data = self.get_whois(ip)
                            provider = self.analyze_whois_enhanced(whois_data)
                        
                        chain.append({
                            'domain': current_domain,
                            'ip': ip,
                            'provider': provider or 'Unknown',
                            'role': 'Origin',
                            'type': 'A'
                        })
                        break
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    break
                    
        except Exception as e:
            print(f"DNS analysis error for {domain}: {e}")
        
        self.dns_cache[domain] = chain
        return chain

    def identify_provider_from_domain(self, domain: str) -> Optional[str]:
        """Identify provider from domain name patterns"""
        domain_lower = domain.lower()
        
        # Common CDN/Cloud provider domain patterns
        provider_patterns = {
            'Cloudflare': [r'cloudflare\.', r'\.cloudflare\.', r'cf-ipv6\.com$'],
            'AWS': [r'amazonaws\.com$', r'aws\.', r'cloudfront\.net$', r'elb\.amazonaws\.com$'],
            'Google': [r'googleusercontent\.com$', r'ghs\.google\.com$', r'\.goog$'],
            'Microsoft': [r'azure\.', r'azurewebsites\.net$', r'cloudapp\.net$', r'trafficmanager\.net$'],
            'Fastly': [r'fastly\.', r'fastlylb\.net$', r'\.global\.fastly\.net$'],
            'Akamai': [r'akamai\.', r'akamaistream\.net$', r'akamaiedge\.net$'],
            'MaxCDN': [r'maxcdn\.', r'bootstrapcdn\.com$'],
            'Netlify': [r'netlify\.', r'netlifyglobalcdn\.com$'],
            'Vercel': [r'vercel\.', r'now\.sh$', r'vercel\.app$'],
            'GitHub': [r'github\.', r'githubpages\.com$', r'github\.io$']
        }
        
        for provider, patterns in provider_patterns.items():
            for pattern in patterns:
                if re.search(pattern, domain_lower):
                    return provider
        
        return None

    def determine_provider_role(self, provider: Optional[str], domain: str) -> str:
        """Determine the role of the provider based on domain patterns"""
        if not provider:
            return 'Unknown'
        
        domain_lower = domain.lower()
        
        # CDN indicators
        cdn_indicators = [
            'cdn', 'cache', 'edge', 'static', 'assets', 'media',
            'cloudfront', 'fastly', 'akamai', 'maxcdn'
        ]
        
        # WAF indicators  
        waf_indicators = ['waf', 'security', 'protection', 'firewall']
        
        # Load balancer indicators
        lb_indicators = ['lb', 'elb', 'alb', 'loadbalancer', 'balance']
        
        if any(indicator in domain_lower for indicator in waf_indicators):
            return 'WAF'
        elif any(indicator in domain_lower for indicator in cdn_indicators):
            return 'CDN'
        elif any(indicator in domain_lower for indicator in lb_indicators):
            return 'Load Balancer'
        elif provider in ['Cloudflare', 'Fastly', 'Akamai', 'MaxCDN']:
            return 'CDN'
        else:
            return 'Origin'

    def detect_provider_multi_layer(self, headers: str, ip: str, whois_data: str, domain: str) -> Dict:
        """Enhanced provider detection returning multiple providers with roles"""
        result = {
            'providers': [],
            'primary_provider': None,
            'confidence_factors': [],
            'dns_chain': []
        }
        
        # Get DNS chain analysis
        dns_chain = self.analyze_dns_chain(domain)
        result['dns_chain'] = dns_chain
        
        # Collect all providers from DNS chain
        providers_found = {}
        for step in dns_chain:
            if step['provider'] and step['provider'] != 'Unknown':
                role = step['role']
                if role not in providers_found:
                    providers_found[role] = []
                providers_found[role].append(step['provider'])
        
        # Original header analysis
        header_provider = self.analyze_headers_comprehensive(headers)
        if header_provider:
            result['confidence_factors'].append('HTTP headers match')
            if 'CDN' not in providers_found:
                providers_found['CDN'] = []
            if header_provider not in providers_found['CDN']:
                providers_found['CDN'].append(header_provider)
        
        # IP range analysis
        ip_provider = self.analyze_ip_ranges_official(ip)
        if ip_provider:
            result['confidence_factors'].append('Official IP ranges match')
            if 'Origin' not in providers_found:
                providers_found['Origin'] = []
            if ip_provider not in providers_found['Origin']:
                providers_found['Origin'].append(ip_provider)
        
        # WHOIS analysis as fallback
        if not providers_found:
            whois_provider = self.analyze_whois_enhanced(whois_data)
            if whois_provider:
                result['confidence_factors'].append('WHOIS data match')
                providers_found['Origin'] = [whois_provider]
        
        # Format results
        for role, provider_list in providers_found.items():
            for provider in provider_list:
                result['providers'].append({
                    'name': provider,
                    'role': role,
                    'confidence': 'High' if role in ['Origin', 'CDN'] else 'Medium'
                })
        
        # Determine primary provider (prefer Origin, then CDN)
        if 'Origin' in providers_found:
            result['primary_provider'] = providers_found['Origin'][0]
        elif 'CDN' in providers_found:
            result['primary_provider'] = providers_found['CDN'][0]
        elif providers_found:
            result['primary_provider'] = list(providers_found.values())[0][0]
        else:
            result['primary_provider'] = 'Unknown'
        
        return result

    def process_csv_file(self, input_file, output_file):
        """Process CSV file with enhanced multi-layer detection"""
        results = []
        
        with open(input_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            header = next(reader)
            
            for row in reader:
                if len(row) >= 2:
                    company, url = row[0], row[1]
                    domain = urlparse(url).netloc or url.replace('https://', '').replace('http://', '').split('/')[0]
                    
                    headers = self.get_headers(url)
                    ip = self.get_ip(url)
                    whois_data = self.get_whois(ip) if ip else ""
                    
                    # Enhanced multi-layer detection
                    enhanced_result = self.detect_provider_multi_layer(headers, ip, whois_data, domain)
                    
                    # Format providers by role
                    origin_providers = [p['name'] for p in enhanced_result['providers'] if p['role'] == 'Origin']
                    cdn_providers = [p['name'] for p in enhanced_result['providers'] if p['role'] == 'CDN']
                    waf_providers = [p['name'] for p in enhanced_result['providers'] if p['role'] == 'WAF']
                    lb_providers = [p['name'] for p in enhanced_result['providers'] if p['role'] == 'Load Balancer']
                    
                    result_row = [
                        company,
                        url,
                        enhanced_result['primary_provider'],
                        ', '.join(origin_providers) or 'Unknown',
                        ', '.join(cdn_providers) or 'None',
                        ', '.join(waf_providers) or 'None',
                        ', '.join(lb_providers) or 'None',
                        ip or 'N/A',
                        '; '.join(enhanced_result['confidence_factors']) or 'Low'
                    ]
                    
                    results.append(result_row)
                    
                    # Enhanced logging
                    provider_summary = f"{enhanced_result['primary_provider']}"
                    if cdn_providers:
                        provider_summary += f" (CDN: {', '.join(cdn_providers)})"
                    if waf_providers:
                        provider_summary += f" (WAF: {', '.join(waf_providers)})"
                    
                    print(f"✓ {company}: {provider_summary}")
        
        # Save enhanced results
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Company', 'URL', 'Primary_Provider', 'Origin_Provider', 
                'CDN_Providers', 'WAF_Providers', 'LB_Providers', 
                'IP_Address', 'Confidence_Factors'
            ])
            writer.writerows(results)
        
        print(f"\nEnhanced results saved to: {output_file}")
        
        # Summary statistics
        total_sites = len(results)
        multi_provider_sites = len([r for r in results if ',' in r[4] or ',' in r[5] or ',' in r[6]])
        print(f"📊 Analysis Summary:")
        print(f"   Total sites analyzed: {total_sites}")
        print(f"   Multi-provider setups detected: {multi_provider_sites}")
        print(f"   Multi-provider ratio: {(multi_provider_sites/total_sites*100):.1f}%")

    # =================================================================
    # Phase 2A: Advanced DNS Analysis Implementation
    # =================================================================
    
    def analyze_ns_records(self, domain: str) -> Dict:
        """Analyze NS records to identify DNS provider"""
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            ns_providers = []
            
            for ns in ns_records:
                ns_domain = str(ns).rstrip('.')
                dns_provider = self.identify_dns_provider(ns_domain)
                if dns_provider:
                    ns_providers.append({
                        'ns_server': ns_domain,
                        'provider': dns_provider,
                        'role': 'DNS'
                    })
            
            return {
                'dns_providers': ns_providers,
                'dns_diversity': len(set(p['provider'] for p in ns_providers)),
                'all_ns_servers': [str(ns).rstrip('.') for ns in ns_records]
            }
        except Exception as e:
            return {'error': str(e), 'dns_providers': [], 'dns_diversity': 0, 'all_ns_servers': []}

    def analyze_ttl_patterns(self, domain: str) -> Dict:
        """Analyze TTL values to detect migration patterns"""
        ttl_data = {}
        
        for record_type in ['A', 'CNAME', 'NS']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                ttl_value = answers.rrset.ttl
                ttl_data[record_type] = {
                    'ttl': ttl_value,
                    'migration_indicator': 'high' if ttl_value < 300 else 'medium' if ttl_value < 3600 else 'low',
                    'description': self.get_ttl_description(ttl_value)
                }
            except Exception as e:
                ttl_data[record_type] = {'error': str(e)}
        
        return ttl_data

    def get_ttl_description(self, ttl: int) -> str:
        """Get human-readable TTL description"""
        if ttl < 60:
            return f"Very low ({ttl}s) - Active migration possible"
        elif ttl < 300:
            return f"Low ({ttl}s) - Recent changes or testing"
        elif ttl < 3600:
            return f"Medium ({ttl//60}m) - Normal operation"
        elif ttl < 86400:
            return f"High ({ttl//3600}h) - Stable configuration"
        else:
            return f"Very high ({ttl//86400}d) - Long-term stable"

    def reverse_dns_lookup(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup for additional context"""
        if not ip:
            return None
            
        try:
            reverse_domain = dns.reversename.from_address(ip)
            reverse_result = str(dns.resolver.resolve(reverse_domain, 'PTR')[0])
            
            # Extract provider from reverse DNS
            provider = self.identify_provider_from_domain(reverse_result.rstrip('.'))
            return {
                'reverse_domain': reverse_result.rstrip('.'),
                'provider': provider
            }
        except Exception:
            return None

    def identify_dns_provider(self, ns_domain: str) -> Optional[str]:
        """Identify DNS provider from NS domain patterns"""
        if not ns_domain:
            return None
            
        ns_lower = ns_domain.lower()
        
        dns_patterns = {
            'AWS Route53': [
                r'awsdns-.*\.net$', r'awsdns-.*\.org$', r'awsdns-.*\.com$', r'awsdns-.*\.co\.uk$'
            ],
            'Cloudflare': [
                r'.*\.ns\.cloudflare\.com$', r'.*\.cloudflare\.com$'
            ],
            'Google Cloud DNS': [
                r'ns-cloud-.*\.googledomains\.com$', r'.*\.google\.com$'
            ],
            'Azure DNS': [
                r'.*\.ns\.azure-dns\..*$', r'.*\.azure-dns\..*$'
            ],
            'Namecheap': [
                r'dns.*\.registrar-servers\.com$', r'.*\.registrar-servers\.com$'
            ],
            'GoDaddy': [
                r'ns.*\.domaincontrol\.com$', r'.*\.domaincontrol\.com$'
            ],
            'DigitalOcean': [
                r'ns.*\.digitalocean\.com$', r'.*\.digitalocean\.com$'
            ],
            'Gcore': [
                r'.*\.gcorelabs\.net$', r'.*\.g-core\.net$'
            ],
            'OVH': [
                r'.*\.ovh\.net$', r'.*\.ovh\.com$'
            ],
            'Hetzner': [
                r'.*\.hetzner\.com$', r'.*\.hetzner\.de$'
            ]
        }
        
        for provider, patterns in dns_patterns.items():
            for pattern in patterns:
                if re.search(pattern, ns_lower):
                    return provider
        
        return None

    def detect_provider_multi_layer_enhanced(self, headers: str, ip: str, whois_data: str, domain: str) -> Dict:
        """Enhanced multi-layer detection with Phase 2A DNS analysis"""
        result = {
            'providers': [],
            'primary_provider': 'Unknown',
            'confidence_factors': [],
            'dns_chain': [],
            'dns_analysis': {},
            'ttl_analysis': {}
        }
        
        # Original multi-layer detection
        original_result = self.detect_provider_multi_layer(headers, ip, whois_data, domain)
        result.update(original_result)
        
        # Phase 2A: Enhanced DNS Analysis
        try:
            # NS Record Analysis
            ns_analysis = self.analyze_ns_records(domain)
            result['dns_analysis'] = ns_analysis
            
            # Add DNS providers to the providers list
            for dns_provider_info in ns_analysis.get('dns_providers', []):
                dns_provider = {
                    'name': dns_provider_info['provider'],
                    'role': 'DNS',
                    'confidence': 'High',
                    'source': 'NS Record Analysis'
                }
                if dns_provider not in result['providers']:
                    result['providers'].append(dns_provider)
                    result['confidence_factors'].append(f"DNS provider identified: {dns_provider_info['provider']}")
            
            # TTL Analysis
            ttl_analysis = self.analyze_ttl_patterns(domain)
            result['ttl_analysis'] = ttl_analysis
            
            # Add migration indicators to confidence factors
            for record_type, ttl_info in ttl_analysis.items():
                if 'migration_indicator' in ttl_info and ttl_info['migration_indicator'] == 'high':
                    result['confidence_factors'].append(f"Low TTL detected ({record_type}): {ttl_info['description']}")
            
            # Reverse DNS Analysis
            if ip:
                reverse_dns = self.reverse_dns_lookup(ip)
                if reverse_dns and reverse_dns['provider']:
                    result['confidence_factors'].append(f"Reverse DNS confirms: {reverse_dns['provider']}")
                    
                    # Cross-validate with existing providers
                    for provider in result['providers']:
                        if provider['name'].lower() == reverse_dns['provider'].lower():
                            provider['confidence'] = 'Very High'
                            result['confidence_factors'].append('Reverse DNS validation successful')
                            break
            
        except Exception as e:
            result['confidence_factors'].append(f"DNS analysis error: {str(e)}")
        
        return result

    def detect_provider_ultimate_with_virustotal(self, headers: str, ip: str, whois_data: str, domain: str) -> Dict:
        """
        Phase 2B: Ultimate detection with VirusTotal enhancement
        
        Args:
            headers: HTTP headers
            ip: IP address
            whois_data: WHOIS data
            domain: Domain name
            
        Returns:
            Enhanced detection result with VirusTotal data
        """
        # Start with Phase 2A enhanced detection
        result = self.detect_provider_multi_layer_enhanced(headers, ip, whois_data, domain)
        
        # Enhance with VirusTotal if available
        if self.vt_integrator and self.vt_integrator.is_enabled():
            try:
                result = self.vt_integrator.enhance_existing_detection(result, domain)
                result['virustotal_enhanced'] = True
            except Exception as e:
                result['confidence_factors'].append(f"VirusTotal enhancement failed: {str(e)}")
                result['virustotal_enhanced'] = False
        else:
            result['virustotal_enhanced'] = False
            
        return result

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
