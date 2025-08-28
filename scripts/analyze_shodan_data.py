#!/usr/bin/env python3
"""Analyze what data Shodan actually returns to optimize extraction"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from src.provider_discovery.integrations.shodan import get_shodan_integration
import json

def analyze_shodan_raw_data():
    print("🔍 ANALYZING SHODAN RAW DATA")
    print("=" * 60)
    
    shodan = get_shodan_integration()
    if not shodan or not shodan.is_enabled:
        print("❌ Shodan not available")
        return
    
    # Test different types of queries to see what data we get
    test_cases = [
        ("cloudflare.com", "Well-known CDN/WAF provider"),
        ("github.com", "Large tech company"),
        ("nike.com", "E-commerce with likely WAF"),
    ]
    
    for domain, description in test_cases:
        print(f"\n📊 ANALYZING {domain.upper()} ({description})")
        print("-" * 50)
        
        # 1. Search by domain hostname
        print("1. Domain search:")
        try:
            results = shodan.client.search(f'hostname:{domain}', limit=3)
            hosts = results.get('matches', [])
            print(f"   Found {len(hosts)} hosts")
            
            if hosts:
                host = hosts[0]  # Analyze first host
                print(f"   Sample host keys: {list(host.keys())}")
                
                # Check what's in the host data
                interesting_fields = ['org', 'isp', 'asn', 'location', 'hostnames', 'domains', 'tags', 'vulns', 'ssl', 'http', 'product', 'version', 'cpe']
                for field in interesting_fields:
                    if field in host:
                        value = host[field]
                        if field == 'location':
                            print(f"   {field}: {value.get('country_name', 'N/A')}, {value.get('city', 'N/A')}")
                        elif field == 'ssl':
                            cert = value.get('cert', {})
                            print(f"   {field}: {cert.get('subject', {}).get('CN', 'N/A')} (issuer: {cert.get('issuer', {}).get('CN', 'N/A')})")
                        elif field == 'http':
                            print(f"   {field}: status={value.get('status')}, server={value.get('server', 'N/A')}")
                        elif field == 'tags':
                            print(f"   {field}: {value}")
                        elif field == 'vulns':
                            print(f"   {field}: {len(value) if value else 0} vulnerabilities found")
                        elif isinstance(value, (list, dict)):
                            if isinstance(value, list) and value:
                                print(f"   {field}: {value[0] if len(value) == 1 else f'{len(value)} items'}")
                            elif isinstance(value, dict) and value:
                                print(f"   {field}: {list(value.keys()) if len(str(value)) < 100 else 'large dict'}")
                        else:
                            print(f"   {field}: {str(value)[:50]}{'...' if len(str(value)) > 50 else ''}")
        
        except Exception as e:
            print(f"   Error: {e}")
        
        # 2. Try finding more detailed info
        print("\n2. Facet analysis (what technologies are common):")
        try:
            facets = shodan.client.search(f'hostname:{domain}', limit=1, facets=['product', 'port', 'org'])
            for facet_name, facet_data in facets.get('facets', {}).items():
                print(f"   {facet_name}: {facet_data[:3] if facet_data else 'none'}")  # Show top 3
        except Exception as e:
            print(f"   Facet error: {e}")
        
        # 3. Check for specific security features
        print("\n3. Security-specific searches:")
        security_queries = [
            ('ssl', f'hostname:{domain} ssl'),
            ('http.component', f'hostname:{domain} http.component'),
            ('vuln', f'hostname:{domain} vuln'),
            ('port:443', f'hostname:{domain} port:443'),
        ]
        
        for query_name, query in security_queries:
            try:
                results = shodan.client.search(query, limit=1)
                count = results.get('total', 0)
                print(f"   {query_name}: {count} results")
            except Exception as e:
                print(f"   {query_name}: Error - {e}")

def analyze_ip_data():
    print(f"\n🌐 IP-SPECIFIC ANALYSIS")
    print("=" * 60)
    
    shodan = get_shodan_integration()
    
    # Test with well-known IPs
    test_ips = [
        ("1.1.1.1", "Cloudflare DNS"),
        ("8.8.8.8", "Google DNS"),
        ("104.16.132.229", "Cloudflare CDN IP"),
    ]
    
    for ip, description in test_ips:
        print(f"\n📍 ANALYZING {ip} ({description})")
        print("-" * 40)
        
        try:
            host_info = shodan.client.host(ip)
            
            print(f"Organization: {host_info.get('org', 'N/A')}")
            print(f"ISP: {host_info.get('isp', 'N/A')}")
            print(f"Country: {host_info.get('country_name', 'N/A')}")
            print(f"ASN: {host_info.get('asn', 'N/A')}")
            
            # Ports and services
            ports = host_info.get('ports', [])
            print(f"Open ports: {ports[:10]}{'...' if len(ports) > 10 else ''}")
            
            # Tags (these can indicate cloud providers, CDNs, etc.)
            tags = host_info.get('tags', [])
            if tags:
                print(f"Tags: {tags}")
            
            # Vulnerabilities
            vulns = host_info.get('vulns', [])
            if vulns:
                print(f"Vulnerabilities: {len(vulns)} found")
            
            # Services analysis
            data = host_info.get('data', [])
            print(f"Services: {len(data)} found")
            
            for service in data[:2]:  # Show first 2 services
                port = service.get('port')
                product = service.get('product', 'Unknown')
                version = service.get('version', '')
                print(f"  Port {port}: {product} {version}".strip())
                
                # HTTP specific data
                if 'http' in service:
                    http = service['http']
                    server = http.get('server', 'Unknown')
                    title = http.get('title', 'No title')
                    print(f"    HTTP: {server}, Title: {title[:50]}")
                    
                    # Security headers
                    headers = http.get('headers', {})
                    security_headers = {k: v for k, v in headers.items() 
                                      if any(sec in k.lower() for sec in ['security', 'frame', 'xss', 'content-security'])}
                    if security_headers:
                        print(f"    Security headers: {list(security_headers.keys())}")
        
        except Exception as e:
            print(f"Error analyzing {ip}: {e}")

if __name__ == "__main__":
    analyze_shodan_raw_data()
    analyze_ip_data()
    
    print(f"\n💡 POTENTIAL IMPROVEMENTS")
    print("=" * 60)
    print("Based on this analysis, we could extract:")
    print("1. 🏷️  Tags - cloud provider/CDN classification")
    print("2. 🔓 Vulnerabilities - security assessment")
    print("3. 🌐 HTTP Headers - detailed security analysis")
    print("4. 🔌 Port/Service mapping - infrastructure insights")
    print("5. 📜 SSL Certificate chains - trust analysis")
    print("6. 🏢 Organization/ASN data - ownership insights")
    print("7. 📊 Facet analysis - technology trends")
    print("8. 🔍 Historical data - infrastructure changes")
