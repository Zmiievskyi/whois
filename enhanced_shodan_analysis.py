#!/usr/bin/env python3
"""Enhanced Shodan analysis methods to extract more value"""

from typing import Dict, List, Any, Set
import logging

logger = logging.getLogger(__name__)

class EnhancedShodanAnalyzer:
    """Enhanced Shodan analysis with maximum data extraction"""
    
    def __init__(self, shodan_client):
        self.client = shodan_client
    
    def comprehensive_domain_analysis(self, domain: str) -> Dict[str, Any]:
        """
        Extract ALL useful information from Shodan for a domain
        
        Returns comprehensive analysis including:
        - CDN/Cloud provider classification via tags
        - Vulnerability assessment
        - Technology stack with versions
        - Security headers analysis
        - Infrastructure mapping
        - Historical insights
        """
        results = {
            'domain': domain,
            'provider_classification': {},
            'security_assessment': {},
            'technology_analysis': {},
            'infrastructure_mapping': {},
            'cdn_analysis': {},
            'vulnerability_analysis': {},
            'ssl_trust_analysis': {},
            'success': False
        }
        
        try:
            # 1. Main domain search with facets for technology trends
            search_results = self.client.search(
                f'hostname:{domain}', 
                limit=10,  # Get more results for better analysis
                facets=['product', 'port', 'org', 'country']  # Technology trends
            )
            
            hosts = search_results.get('matches', [])
            facets = search_results.get('facets', {})
            
            if not hosts:
                results['error'] = 'No hosts found'
                return results
            
            # 2. PROVIDER CLASSIFICATION via tags and organization
            results['provider_classification'] = self._classify_providers(hosts, facets)
            
            # 3. TECHNOLOGY ANALYSIS (enhanced)
            results['technology_analysis'] = self._analyze_technology_stack_enhanced(hosts)
            
            # 4. SECURITY ASSESSMENT (comprehensive)
            results['security_assessment'] = self._comprehensive_security_analysis(domain, hosts)
            
            # 5. INFRASTRUCTURE MAPPING
            results['infrastructure_mapping'] = self._map_infrastructure(hosts)
            
            # 6. CDN/WAF ANALYSIS (enhanced)
            results['cdn_analysis'] = self._enhanced_cdn_waf_analysis(hosts)
            
            # 7. VULNERABILITY ANALYSIS
            results['vulnerability_analysis'] = self._analyze_vulnerabilities(hosts)
            
            # 8. SSL TRUST ANALYSIS
            results['ssl_trust_analysis'] = self._analyze_ssl_trust_chain(hosts)
            
            results['success'] = True
            results['total_hosts_analyzed'] = len(hosts)
            results['data_richness_score'] = self._calculate_data_richness(results)
            
        except Exception as e:
            results['error'] = str(e)
            logger.error(f"Enhanced Shodan analysis failed for {domain}: {e}")
        
        return results
    
    def _classify_providers(self, hosts: List[Dict], facets: Dict) -> Dict[str, Any]:
        """Enhanced provider classification using tags, org, and facet data"""
        classification = {
            'cloud_providers': set(),
            'cdn_providers': set(),
            'waf_providers': set(),
            'hosting_providers': set(),
            'confidence_indicators': [],
            'primary_infrastructure': 'unknown'
        }
        
        # Known provider patterns
        cloud_providers = {
            'aws': ['amazon', 'aws', 'amazon web services'],
            'gcp': ['google', 'gcp', 'google cloud'],
            'azure': ['microsoft', 'azure'],
            'cloudflare': ['cloudflare'],
            'akamai': ['akamai'],
            'digitalocean': ['digitalocean'],
            'linode': ['linode'],
            'vultr': ['vultr']
        }
        
        cdn_waf_indicators = {
            'cloudflare': ['cloudflare', 'cf-'],
            'akamai': ['akamai', 'akamaihost', 'akamaighost'],
            'fastly': ['fastly'],
            'maxcdn': ['maxcdn'],
            'keycdn': ['keycdn'],
            'imperva': ['imperva', 'incapsula']
        }
        
        # Analyze hosts for provider indicators
        for host in hosts:
            org = (host.get('org') or '').lower()
            isp = (host.get('isp') or '').lower()
            tags = host.get('tags', []) or []
            product = (host.get('product') or '').lower()
            
            # Check for CDN tags (most reliable)
            if 'cdn' in tags:
                classification['confidence_indicators'].append(f"CDN tag found: {host.get('org', 'Unknown')}")
                classification['cdn_providers'].add(host.get('org', 'Unknown'))
            
            # Check for cloud providers
            for provider, patterns in cloud_providers.items():
                if any(pattern in org or pattern in isp for pattern in patterns):
                    classification['cloud_providers'].add(provider.upper())
                    classification['confidence_indicators'].append(f"Cloud provider detected: {provider}")
            
            # Check for CDN/WAF providers
            for provider, patterns in cdn_waf_indicators.items():
                if any(pattern in product or pattern in org or pattern in isp for pattern in patterns):
                    classification['cdn_providers'].add(provider.upper())
                    if provider in ['imperva', 'cloudflare']:
                        classification['waf_providers'].add(provider.upper())
        
        # Use facet data for primary infrastructure determination
        org_facets = facets.get('org', [])
        if org_facets:
            primary_org = org_facets[0].get('value', 'unknown')
            classification['primary_infrastructure'] = primary_org
            classification['confidence_indicators'].append(f"Primary organization: {primary_org}")
        
        # Convert sets to lists for JSON serialization
        for key in ['cloud_providers', 'cdn_providers', 'waf_providers', 'hosting_providers']:
            classification[key] = list(classification[key])
        
        return classification
    
    def _analyze_technology_stack_enhanced(self, hosts: List[Dict]) -> Dict[str, Any]:
        """Enhanced technology stack analysis with versions and confidence"""
        tech_analysis = {
            'web_servers': {},
            'frameworks': {},
            'databases': {},
            'operating_systems': {},
            'security_products': {},
            'development_tools': {},
            'confidence_score': 0
        }
        
        # Enhanced categorization patterns
        categories = {
            'web_servers': ['nginx', 'apache', 'iis', 'lighttpd', 'cloudflare', 'akamaighost'],
            'frameworks': ['django', 'rails', 'express', 'php', 'asp.net', 'spring'],
            'databases': ['mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch'],
            'operating_systems': ['ubuntu', 'centos', 'windows', 'debian', 'amazon linux'],
            'security_products': ['cloudflare', 'imperva', 'sucuri', 'barracuda'],
            'development_tools': ['jenkins', 'gitlab', 'docker', 'kubernetes']
        }
        
        for host in hosts:
            product = (host.get('product') or '').lower()
            version = host.get('version') or ''
            os = (host.get('os') or '').lower()
            
            # Categorize products
            for category, patterns in categories.items():
                for pattern in patterns:
                    if pattern in product:
                        tech_key = f"{product} {version}".strip()
                        if category not in tech_analysis:
                            tech_analysis[category] = {}
                        tech_analysis[category][tech_key] = tech_analysis[category].get(tech_key, 0) + 1
            
            # Operating system detection
            if os:
                tech_analysis['operating_systems'][os] = tech_analysis['operating_systems'].get(os, 0) + 1
        
        # Calculate confidence based on data richness
        total_items = sum(len(v) for v in tech_analysis.values() if isinstance(v, dict))
        tech_analysis['confidence_score'] = min(total_items * 10, 100)
        
        return tech_analysis
    
    def _comprehensive_security_analysis(self, domain: str, hosts: List[Dict]) -> Dict[str, Any]:
        """Comprehensive security analysis including headers, vulnerabilities, and SSL"""
        security = {
            'security_headers': {},
            'ssl_configuration': {},
            'vulnerability_indicators': [],
            'security_score': 0,
            'recommendations': []
        }
        
        security_headers_to_check = [
            'x-frame-options', 'content-security-policy', 'x-content-type-options',
            'strict-transport-security', 'x-xss-protection', 'referrer-policy',
            'permissions-policy', 'expect-ct'
        ]
        
        for host in hosts:
            # HTTP security headers analysis
            http_data = host.get('http', {})
            if http_data:
                headers = http_data.get('headers', {})
                
                for header in security_headers_to_check:
                    if header in headers:
                        security['security_headers'][header] = headers[header]
                
                # Server security analysis
                server = (http_data.get('server') or '').lower()
                if 'cloudflare' in server:
                    security['security_score'] += 20
                    security['recommendations'].append("Cloudflare protection detected")
                
                # Check for security-related response codes
                status = http_data.get('status')
                if status in [403, 406]:  # Common WAF response codes
                    security['vulnerability_indicators'].append(f"WAF-like response: {status}")
            
            # SSL analysis
            ssl_data = host.get('ssl', {})
            if ssl_data:
                cert = ssl_data.get('cert', {})
                security['ssl_configuration'] = {
                    'subject': cert.get('subject', {}),
                    'issuer': cert.get('issuer', {}),
                    'version': ssl_data.get('version'),
                    'cipher': ssl_data.get('cipher', {})
                }
                
                # SSL scoring
                cipher = ssl_data.get('cipher', {})
                if cipher.get('version') == 'TLSv1.3':
                    security['security_score'] += 25
                elif cipher.get('version') == 'TLSv1.2':
                    security['security_score'] += 15
                
                # Certificate authority scoring
                issuer = cert.get('issuer', {}).get('CN') or ''
                if any(ca in issuer.lower() for ca in ['let\'s encrypt', 'digicert', 'sectigo']):
                    security['security_score'] += 10
            
            # Vulnerability indicators
            vulns = host.get('vulns', [])
            if vulns:
                security['vulnerability_indicators'].extend(vulns)
                security['security_score'] -= len(vulns) * 5  # Penalty for vulnerabilities
        
        # Final security score calculation
        header_score = len(security['security_headers']) * 5
        security['security_score'] = max(0, min(100, security['security_score'] + header_score))
        
        return security
    
    def _map_infrastructure(self, hosts: List[Dict]) -> Dict[str, Any]:
        """Map the complete infrastructure landscape"""
        infrastructure = {
            'geographic_distribution': {},
            'port_services': {},
            'asn_analysis': {},
            'hosting_patterns': []
        }
        
        for host in hosts:
            # Geographic analysis
            location = host.get('location', {})
            country = location.get('country_name', 'Unknown')
            city = location.get('city', 'Unknown')
            geo_key = f"{country}, {city}"
            infrastructure['geographic_distribution'][geo_key] = infrastructure['geographic_distribution'].get(geo_key, 0) + 1
            
            # Port and service mapping
            port = host.get('port')
            product = host.get('product', 'Unknown')
            if port:
                if port not in infrastructure['port_services']:
                    infrastructure['port_services'][port] = []
                infrastructure['port_services'][port].append(product)
            
            # ASN analysis
            asn = host.get('asn')
            org = host.get('org', 'Unknown')
            if asn:
                infrastructure['asn_analysis'][asn] = org
            
            # Hosting pattern analysis
            tags = host.get('tags', [])
            if tags:
                infrastructure['hosting_patterns'].extend(tags)
        
        # Remove duplicates from hosting patterns
        infrastructure['hosting_patterns'] = list(set(infrastructure['hosting_patterns']))
        
        return infrastructure
    
    def _enhanced_cdn_waf_analysis(self, hosts: List[Dict]) -> Dict[str, Any]:
        """Enhanced CDN and WAF detection with confidence scoring"""
        cdn_analysis = {
            'cdn_detected': False,
            'waf_detected': False,
            'cdn_providers': [],
            'waf_indicators': [],
            'confidence_score': 0,
            'evidence': []
        }
        
        cdn_indicators = {
            'cloudflare': ['cloudflare', 'cf-ray', 'cf-cache-status'],
            'akamai': ['akamai', 'akamaihost', 'akamaighost', 'x-akamai'],
            'fastly': ['fastly', 'x-served-by', 'x-cache'],
            'maxcdn': ['maxcdn', 'netdna'],
            'keycdn': ['keycdn']
        }
        
        waf_indicators = {
            'cloudflare': ['cloudflare waf', 'cf-ray'],
            'akamai': ['akamai web application firewall', 'akamai kona'],
            'imperva': ['imperva', 'incapsula', 'x-iinfo'],
            'sucuri': ['sucuri', 'x-sucuri-id'],
            'barracuda': ['barracuda', 'barra']
        }
        
        for host in hosts:
            tags = host.get('tags', []) or []
            product = (host.get('product') or '').lower()
            org = (host.get('org') or '').lower()
            
            # CDN detection via tags (most reliable)
            if 'cdn' in tags:
                cdn_analysis['cdn_detected'] = True
                cdn_analysis['confidence_score'] += 30
                cdn_analysis['evidence'].append(f"CDN tag found for {org}")
            
            # Product-based detection
            for provider, indicators in cdn_indicators.items():
                if any(indicator in product or indicator in org for indicator in indicators):
                    cdn_analysis['cdn_detected'] = True
                    cdn_analysis['cdn_providers'].append(provider.upper())
                    cdn_analysis['confidence_score'] += 20
                    cdn_analysis['evidence'].append(f"CDN signature: {provider}")
            
            # WAF detection
            for provider, indicators in waf_indicators.items():
                if any(indicator in product or indicator in org for indicator in indicators):
                    cdn_analysis['waf_detected'] = True
                    cdn_analysis['waf_indicators'].append(provider.upper())
                    cdn_analysis['confidence_score'] += 25
                    cdn_analysis['evidence'].append(f"WAF signature: {provider}")
            
            # HTTP-based WAF detection
            http_data = host.get('http', {})
            if http_data:
                headers = http_data.get('headers', {})
                server = (http_data.get('server') or '').lower()
                
                # Check for WAF response patterns
                status = http_data.get('status')
                if status in [403, 406, 429]:  # Common WAF responses
                    cdn_analysis['waf_indicators'].append("WAF response pattern")
                    cdn_analysis['confidence_score'] += 10
                
                # Security headers that indicate WAF presence
                waf_headers = ['cf-ray', 'x-akamai-transformed', 'x-sucuri-id']
                for header in waf_headers:
                    if header in headers:
                        cdn_analysis['waf_detected'] = True
                        cdn_analysis['confidence_score'] += 15
                        cdn_analysis['evidence'].append(f"WAF header: {header}")
        
        # Remove duplicates
        cdn_analysis['cdn_providers'] = list(set(cdn_analysis['cdn_providers']))
        cdn_analysis['waf_indicators'] = list(set(cdn_analysis['waf_indicators']))
        
        # Cap confidence score
        cdn_analysis['confidence_score'] = min(100, cdn_analysis['confidence_score'])
        
        return cdn_analysis
    
    def _analyze_vulnerabilities(self, hosts: List[Dict]) -> Dict[str, Any]:
        """Analyze security vulnerabilities and risk factors"""
        vuln_analysis = {
            'vulnerabilities_found': [],
            'risk_score': 0,
            'security_recommendations': [],
            'outdated_software': []
        }
        
        for host in hosts:
            # Direct vulnerability data
            vulns = host.get('vulns', [])
            if vulns:
                vuln_analysis['vulnerabilities_found'].extend(vulns)
                vuln_analysis['risk_score'] += len(vulns) * 20
            
            # Outdated software detection
            product = host.get('product') or ''
            version = host.get('version') or ''
            if product and version:
                # This could be enhanced with a CVE database lookup
                software_info = f"{product} {version}"
                vuln_analysis['outdated_software'].append(software_info)
        
        # Generate recommendations
        if vuln_analysis['vulnerabilities_found']:
            vuln_analysis['security_recommendations'].append("Critical: Vulnerabilities detected - immediate patching required")
        
        if vuln_analysis['risk_score'] > 50:
            vuln_analysis['security_recommendations'].append("High risk: Enhanced monitoring recommended")
        
        vuln_analysis['risk_score'] = min(100, vuln_analysis['risk_score'])
        
        return vuln_analysis
    
    def _analyze_ssl_trust_chain(self, hosts: List[Dict]) -> Dict[str, Any]:
        """Analyze SSL certificate trust chain and configuration"""
        ssl_analysis = {
            'certificate_authorities': [],
            'trust_score': 0,
            'ssl_configurations': [],
            'recommendations': []
        }
        
        trusted_cas = [
            'let\'s encrypt', 'digicert', 'sectigo', 'globalsign', 'comodo',
            'godaddy', 'symantec', 'thawte', 'geotrust'
        ]
        
        for host in hosts:
            ssl_data = host.get('ssl', {})
            if ssl_data:
                cert = ssl_data.get('cert', {})
                issuer_cn = (cert.get('issuer', {}).get('CN') or '').lower()
                
                # Certificate authority analysis
                if issuer_cn:
                    ssl_analysis['certificate_authorities'].append(issuer_cn)
                    
                    # Trust scoring
                    if any(ca in issuer_cn for ca in trusted_cas):
                        ssl_analysis['trust_score'] += 20
                    
                    if 'let\'s encrypt' in issuer_cn:
                        ssl_analysis['recommendations'].append("Using Let's Encrypt - ensure auto-renewal is configured")
                
                # SSL configuration analysis
                cipher = ssl_data.get('cipher', {})
                if cipher:
                    version = cipher.get('version', '')
                    ssl_analysis['ssl_configurations'].append({
                        'version': version,
                        'cipher_name': cipher.get('name', ''),
                        'bits': cipher.get('bits', 0)
                    })
                    
                    # Version scoring
                    if version == 'TLSv1.3':
                        ssl_analysis['trust_score'] += 30
                    elif version == 'TLSv1.2':
                        ssl_analysis['trust_score'] += 20
                    else:
                        ssl_analysis['recommendations'].append(f"Outdated TLS version detected: {version}")
        
        ssl_analysis['trust_score'] = min(100, ssl_analysis['trust_score'])
        ssl_analysis['certificate_authorities'] = list(set(ssl_analysis['certificate_authorities']))
        
        return ssl_analysis
    
    def _calculate_data_richness(self, results: Dict[str, Any]) -> int:
        """Calculate how rich/comprehensive the extracted data is"""
        score = 0
        
        # Provider classification richness
        providers = results.get('provider_classification', {})
        score += len(providers.get('cloud_providers', [])) * 10
        score += len(providers.get('cdn_providers', [])) * 15
        score += len(providers.get('waf_providers', [])) * 20
        
        # Technology analysis richness
        tech = results.get('technology_analysis', {})
        score += len(tech.get('web_servers', {})) * 5
        score += len(tech.get('frameworks', {})) * 8
        
        # Security analysis richness
        security = results.get('security_assessment', {})
        score += len(security.get('security_headers', {})) * 3
        score += security.get('security_score', 0) // 5
        
        # Infrastructure mapping richness
        infra = results.get('infrastructure_mapping', {})
        score += len(infra.get('geographic_distribution', {})) * 2
        score += len(infra.get('port_services', {})) * 3
        
        return min(100, score)


# Test the enhanced analyzer
if __name__ == "__main__":
    from src.provider_discovery.integrations.shodan import get_shodan_integration
    import json
    
    shodan = get_shodan_integration()
    if shodan and shodan.is_enabled:
        analyzer = EnhancedShodanAnalyzer(shodan.client)
        
        # Test with a domain
        test_domain = "cloudflare.com"
        print(f"🚀 ENHANCED ANALYSIS FOR {test_domain}")
        print("=" * 60)
        
        results = analyzer.comprehensive_domain_analysis(test_domain)
        
        if results['success']:
            print(f"📊 Data Richness Score: {results['data_richness_score']}/100")
            print(f"📈 Hosts Analyzed: {results['total_hosts_analyzed']}")
            
            # Provider Classification
            providers = results['provider_classification']
            print(f"\n🏢 PROVIDER CLASSIFICATION:")
            print(f"  Cloud: {providers['cloud_providers']}")
            print(f"  CDN: {providers['cdn_providers']}")
            print(f"  WAF: {providers['waf_providers']}")
            print(f"  Primary: {providers['primary_infrastructure']}")
            
            # Enhanced CDN/WAF Analysis
            cdn = results['cdn_analysis']
            print(f"\n🛡️ CDN/WAF ANALYSIS:")
            print(f"  CDN Detected: {cdn['cdn_detected']}")
            print(f"  WAF Detected: {cdn['waf_detected']}")
            print(f"  Confidence: {cdn['confidence_score']}%")
            print(f"  Evidence: {cdn['evidence'][:3]}")  # Show first 3
            
            # Security Assessment
            security = results['security_assessment']
            print(f"\n🔒 SECURITY ASSESSMENT:")
            print(f"  Security Score: {security['security_score']}/100")
            print(f"  Security Headers: {len(security['security_headers'])}")
            print(f"  Vulnerabilities: {len(security['vulnerability_indicators'])}")
            
            # Technology Analysis
            tech = results['technology_analysis']
            print(f"\n💻 TECHNOLOGY ANALYSIS:")
            print(f"  Confidence: {tech['confidence_score']}%")
            for category in ['web_servers', 'security_products']:
                if tech.get(category):
                    print(f"  {category}: {list(tech[category].keys())[:3]}")
            
        else:
            print(f"❌ Analysis failed: {results.get('error')}")
    else:
        print("❌ Shodan not available")
