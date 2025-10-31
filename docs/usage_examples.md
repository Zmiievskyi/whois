# 📚 Usage Examples & Tutorials

## Complete usage examples for Enhanced Provider Detection System with 6 FREE integrations

## 🚀 Quick Start Examples

### Basic Enhanced Detection

```python
from provider_discovery import get_enhanced_provider_detector

# Initialize enhanced detector
detector = get_enhanced_provider_detector()

# Basic analysis
result = detector.detect_provider_comprehensive(
    headers="",
    ip="", 
    whois_data="",
    domain="github.com"
)

print(f"🎯 Enhanced Confidence: {result['Enhanced_Confidence']}%")
print(f"🔬 Analysis Methods: {len(result['analysis_methods'])}")
print(f"🏢 Providers Found: {len(result['providers'])}")
```

### Check System Health

```python
# Test all FREE integrations
test_results = detector.test_all_integrations()

print(f"📊 System Health: {test_results['total_available']}/6 integrations working")

for integration, status in test_results.items():
    if isinstance(status, bool):
        emoji = "✅" if status else "❌"
        print(f"   {emoji} {integration.replace('_', ' ').title()}")
```

## 🔍 Real-World Use Cases

### 1. Security Assessment Workflow

```python
def security_assessment(domain):
    """Complete security assessment of a domain"""
    detector = get_enhanced_provider_detector()
    
    print(f"🔒 Security Assessment for: {domain}")
    print("=" * 50)
    
    # Comprehensive analysis
    result = detector.detect_provider_comprehensive("", "", "", domain)
    
    # Security findings
    security_findings = result.get('security_findings', [])
    if security_findings:
        print("\n🛡️ Security Findings:")
        for finding in security_findings:
            print(f"   {finding}")
    
    # Threat level assessment
    threat_analysis = result['Enhanced_Analysis'].get('threat_intelligence', {})
    if threat_analysis and 'error' not in threat_analysis:
        threat_level = threat_analysis.get('overall_threat_level', 'unknown')
        domain_rep = threat_analysis.get('domain_analysis', {}).get('reputation_score', 0)
        
        print(f"\n⚠️ Threat Assessment:")
        print(f"   Threat Level: {threat_level.upper()}")
        print(f"   Domain Reputation: {domain_rep}/100")
    
    # SSL security
    ssl_analysis = result['Enhanced_Analysis'].get('ssl_analysis', {})
    if ssl_analysis and 'error' not in ssl_analysis:
        ssl_grade = ssl_analysis.get('security_assessment', {}).get('overall_grade', 'Unknown')
        print(f"   SSL Security Grade: {ssl_grade}")
    
    # Recommendations
    recommendations = result.get('Recommendations', [])
    if recommendations:
        print(f"\n💡 Security Recommendations:")
        for rec in recommendations:
            print(f"   {rec}")
    
    return result

# Example usage
security_assessment("github.com")
```

### 2. Infrastructure Analysis

```python
def infrastructure_analysis(domain):
    """Analyze infrastructure setup and provider stack"""
    detector = get_enhanced_provider_detector()
    
    print(f"🏗️ Infrastructure Analysis for: {domain}")
    print("=" * 50)
    
    result = detector.detect_provider_comprehensive("", "", "", domain)
    
    # Provider stack
    providers = result.get('providers', [])
    if providers:
        print(f"\n🏢 Provider Stack ({len(providers)} providers):")
        
        # Group by role
        by_role = {}
        for provider in providers:
            role = provider.get('role', 'Unknown')
            if role not in by_role:
                by_role[role] = []
            by_role[role].append(provider)
        
        for role, role_providers in by_role.items():
            print(f"\n   {role}:")
            for provider in role_providers:
                name = provider['name']
                confidence = provider['confidence']
                source = provider['source']
                print(f"     • {name} ({confidence} confidence via {source})")
    
    # Geographic insights
    geo_insights = result.get('geographic_insights', [])
    if geo_insights:
        print(f"\n🌍 Geographic Intelligence:")
        for insight in geo_insights:
            print(f"   {insight}")
    
    # BGP insights
    bgp_insights = result.get('bgp_insights', [])
    if bgp_insights:
        print(f"\n📡 BGP Routing Intelligence:")
        for insight in bgp_insights:
            print(f"   {insight}")
    
    # Cross-validation
    cross_val = result['Enhanced_Analysis'].get('cross_validation', {})
    if cross_val:
        consensus_providers = cross_val.get('provider_consensus', {})
        if consensus_providers:
            print(f"\n🤝 Cross-Validated Providers:")
            for provider, data in consensus_providers.items():
                sources = data['sources']
                print(f"   • {provider} (confirmed by {len(sources)} sources)")
    
    return result

# Example usage
infrastructure_analysis("cloudflare.com")
```

### 3. Competitive Intelligence

```python
def competitive_analysis(competitor_domains):
    """Analyze competitor infrastructure and technology stack"""
    detector = get_enhanced_provider_detector()
    
    print("🔍 Competitive Infrastructure Analysis")
    print("=" * 50)
    
    analysis_results = {}
    
    for domain in competitor_domains:
        print(f"\n📊 Analyzing: {domain}")
        
        try:
            result = detector.detect_provider_comprehensive("", "", "", domain)
            
            # Extract key insights
            insights = {
                'domain': domain,
                'confidence': result.get('Enhanced_Confidence', 0),
                'providers': [],
                'security_grade': 'Unknown',
                'threat_level': 'unknown',
                'bgp_asn': None,
                'location': 'Unknown'
            }
            
            # Provider stack
            for provider in result.get('providers', []):
                insights['providers'].append({
                    'name': provider['name'],
                    'role': provider['role'],
                    'confidence': provider['confidence']
                })
            
            # Security assessment
            ssl_analysis = result['Enhanced_Analysis'].get('ssl_analysis', {})
            if ssl_analysis and 'error' not in ssl_analysis:
                insights['security_grade'] = ssl_analysis.get('security_assessment', {}).get('overall_grade', 'Unknown')
            
            threat_analysis = result['Enhanced_Analysis'].get('threat_intelligence', {})
            if threat_analysis and 'error' not in threat_analysis:
                insights['threat_level'] = threat_analysis.get('overall_threat_level', 'unknown')
            
            # BGP information
            bgp_analysis = result['Enhanced_Analysis'].get('bgp_analysis', {})
            if bgp_analysis and 'error' not in bgp_analysis:
                asn_info = bgp_analysis.get('asn_info', {})
                insights['bgp_asn'] = asn_info.get('asn')
            
            # Geographic information
            geo_analysis = result['Enhanced_Analysis'].get('geographic_intelligence', {})
            if geo_analysis and 'error' not in geo_analysis:
                consensus = geo_analysis.get('consensus', {})
                if consensus.get('consensus_reached'):
                    location_data = consensus['consensus_data']
                    insights['location'] = f"{location_data.get('city', 'Unknown')}, {location_data.get('country', 'Unknown')}"
            
            analysis_results[domain] = insights
            
            # Display summary
            print(f"   🎯 Confidence: {insights['confidence']}%")
            print(f"   🏢 Primary Providers: {', '.join([p['name'] for p in insights['providers'][:3]])}")
            print(f"   🔒 SSL Grade: {insights['security_grade']}")
            print(f"   🌍 Location: {insights['location']}")
            
        except Exception as e:
            print(f"   ❌ Analysis failed: {e}")
            analysis_results[domain] = {'error': str(e)}
        
        time.sleep(2)  # Rate limiting
    
    # Comparative summary
    print(f"\n📋 Competitive Summary:")
    print("-" * 30)
    
    for domain, data in analysis_results.items():
        if 'error' not in data:
            providers = [p['name'] for p in data['providers']]
            print(f"{domain:20} | {data['confidence']:3}% | {', '.join(providers[:2])}")
    
    return analysis_results

# Example usage
competitors = ["github.com", "gitlab.com", "bitbucket.org"]
competitive_analysis(competitors)
```

### 4. Provider Migration Planning

```python
def migration_analysis(domain):
    """Analyze current setup for migration planning"""
    detector = get_enhanced_provider_detector()
    
    print(f"🚀 Migration Analysis for: {domain}")
    print("=" * 50)
    
    result = detector.detect_provider_comprehensive("", "", "", domain)
    
    # Current infrastructure
    providers = result.get('providers', [])
    
    print(f"\n📊 Current Infrastructure:")
    cdn_providers = [p for p in providers if p['role'] in ['CDN', 'Proxy']]
    hosting_providers = [p for p in providers if p['role'] in ['Origin', 'Hosting']]
    dns_providers = [p for p in providers if p['role'] == 'DNS']
    
    if cdn_providers:
        print(f"   CDN: {', '.join([p['name'] for p in cdn_providers])}")
    if hosting_providers:
        print(f"   Hosting: {', '.join([p['name'] for p in hosting_providers])}")
    if dns_providers:
        print(f"   DNS: {', '.join([p['name'] for p in dns_providers])}")
    
    # Performance characteristics
    geo_insights = result.get('geographic_insights', [])
    if geo_insights:
        print(f"\n🌍 Geographic Distribution:")
        for insight in geo_insights:
            print(f"   {insight}")
    
    # BGP routing analysis
    bgp_insights = result.get('bgp_insights', [])
    if bgp_insights:
        print(f"\n📡 Routing Characteristics:")
        for insight in bgp_insights:
            print(f"   {insight}")
    
    # Security considerations
    security_findings = result.get('security_findings', [])
    if security_findings:
        print(f"\n🔒 Security Considerations:")
        for finding in security_findings:
            print(f"   {finding}")
    
    # Migration recommendations
    recommendations = result.get('Recommendations', [])
    if recommendations:
        print(f"\n💡 Migration Considerations:")
        for rec in recommendations:
            print(f"   {rec}")
    
    # Confidence assessment
    confidence = result.get('Enhanced_Confidence', 0)
    if confidence > 85:
        print(f"\n✅ High confidence analysis - reliable for migration planning")
    elif confidence > 70:
        print(f"\n⚠️ Good confidence - consider additional verification")
    else:
        print(f"\n❌ Low confidence - manual verification strongly recommended")
    
    return result

# Example usage
migration_analysis("mycompany.com")
```

### 5. Batch Domain Analysis

```python
def batch_domain_analysis(domains, output_file="analysis_results.json"):
    """Analyze multiple domains and save results"""
    import json
    import time
    from datetime import datetime
    
    detector = get_enhanced_provider_detector()
    
    print(f"📊 Batch Analysis of {len(domains)} domains")
    print("=" * 50)
    
    results = {
        'analysis_date': datetime.now().isoformat(),
        'total_domains': len(domains),
        'domains': {}
    }
    
    for i, domain in enumerate(domains, 1):
        print(f"\n[{i}/{len(domains)}] Analyzing: {domain}")
        
        try:
            result = detector.detect_provider_comprehensive("", "", "", domain)
            
            # Extract summary data
            summary = {
                'enhanced_confidence': result.get('Enhanced_Confidence', 0),
                'analysis_methods': result.get('analysis_methods', []),
                'providers': [
                    {
                        'name': p['name'],
                        'role': p['role'],
                        'confidence': p['confidence'],
                        'source': p['source']
                    }
                    for p in result.get('providers', [])
                ],
                'security_findings': result.get('security_findings', []),
                'geographic_insights': result.get('geographic_insights', []),
                'bgp_insights': result.get('bgp_insights', []),
                'recommendations': result.get('Recommendations', [])
            }
            
            # Integration status
            enhanced_analysis = result.get('Enhanced_Analysis', {})
            integration_status = {}
            
            for integration, data in enhanced_analysis.items():
                if isinstance(data, dict):
                    integration_status[integration] = 'error' not in data
            
            summary['integration_status'] = integration_status
            summary['working_integrations'] = sum(integration_status.values())
            
            results['domains'][domain] = {
                'status': 'success',
                'summary': summary,
                'full_result': result  # Include full result for detailed analysis
            }
            
            print(f"   ✅ Confidence: {summary['enhanced_confidence']}%")
            print(f"   🔬 Methods: {len(summary['analysis_methods'])}")
            print(f"   🏢 Providers: {len(summary['providers'])}")
            
        except Exception as e:
            print(f"   ❌ Failed: {e}")
            results['domains'][domain] = {
                'status': 'error',
                'error': str(e)
            }
        
        # Rate limiting
        if i < len(domains):
            time.sleep(1)
    
    # Save results
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    # Summary statistics
    successful = sum(1 for d in results['domains'].values() if d['status'] == 'success')
    failed = len(domains) - successful
    
    print(f"\n📈 Batch Analysis Summary:")
    print(f"   ✅ Successful: {successful}/{len(domains)}")
    print(f"   ❌ Failed: {failed}/{len(domains)}")
    print(f"   💾 Results saved to: {output_file}")
    
    return results

# Example usage
domain_list = [
    "github.com", "google.com", "cloudflare.com",
    "amazon.com", "microsoft.com", "fastly.com"
]

batch_results = batch_domain_analysis(domain_list)
```

### 6. Custom Monitoring Dashboard

```python
def create_monitoring_report():
    """Create monitoring report for system health"""
    from datetime import datetime
    
    detector = get_enhanced_provider_detector()
    
    print("📊 Enhanced Provider Detection System - Health Report")
    print("=" * 60)
    print(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Test all integrations
    test_results = detector.test_all_integrations()
    
    print(f"\n🔧 Integration Health Status:")
    print(f"Working Integrations: {test_results['total_available']}/6")
    print()
    
    # Detailed integration status
    integration_names = {
        'ssl_analysis': '🔒 SSL Certificate Analysis',
        'enhanced_dns': '🌐 Enhanced DNS Framework',
        'geographic_intelligence': '🌍 Geographic Intelligence',
        'bgp_analysis': '📡 BGP Analysis (BGPView)',
        'hurricane_electric': '🌐 Hurricane Electric BGP',
        'threat_intelligence': '🛡️ Threat Intelligence'
    }
    
    for integration, name in integration_names.items():
        status = test_results.get(integration, False)
        emoji = "✅" if status else "❌"
        status_text = "WORKING" if status else "FAILED"
        
        print(f"{emoji} {name}: {status_text}")
        
        # Show detailed status if available
        detailed_status = test_results.get('integration_status', {}).get(integration, {})
        if isinstance(detailed_status, dict) and detailed_status:
            if status:
                # Show success details
                if 'message' in detailed_status:
                    print(f"     {detailed_status['message']}")
            else:
                # Show error details
                if 'error' in detailed_status:
                    print(f"     Error: {detailed_status['error']}")
    
    # System performance test
    print(f"\n⚡ Performance Test:")
    start_time = time.time()
    
    try:
        test_result = detector.detect_provider_comprehensive("", "", "", "github.com")
        end_time = time.time()
        analysis_time = end_time - start_time
        
        confidence = test_result.get('Enhanced_Confidence', 0)
        methods_count = len(test_result.get('analysis_methods', []))
        providers_count = len(test_result.get('providers', []))
        
        print(f"   ✅ Test analysis completed in {analysis_time:.2f}s")
        print(f"   📊 Confidence: {confidence}%")
        print(f"   🔬 Methods used: {methods_count}")
        print(f"   🏢 Providers found: {providers_count}")
        
    except Exception as e:
        print(f"   ❌ Performance test failed: {e}")
    
    # Cache statistics
    cache = detector.cache
    print(f"\n💾 Cache Statistics:")
    
    cache_types = [
        'ssl_analysis', 'enhanced_dns', 'geographic_intelligence',
        'bgp_analysis', 'hurricane_electric', 'threat_intelligence'
    ]
    
    for cache_type in cache_types:
        if hasattr(cache, 'get_stats'):
            stats = cache.get_stats(cache_type)
            if stats:
                hit_rate = (stats.get('hits', 0) / max(stats.get('requests', 1), 1)) * 100
                print(f"   {cache_type}: {stats.get('size', 0)} entries, {hit_rate:.1f}% hit rate")
    
    # Recommendations
    print(f"\n💡 System Recommendations:")
    
    if test_results['total_available'] >= 5:
        print("   ✅ System operating at full capacity")
    elif test_results['total_available'] >= 4:
        print("   ⚠️ System operating with minor degradation")
        print("   💡 Consider investigating failed integrations")
    else:
        print("   ❌ System operating with significant degradation")
        print("   🚨 Immediate attention required for failed integrations")
    
    # Rate limiting status
    print(f"\n⏱️ Rate Limiting Status:")
    rate_limiter = detector.rate_limiter
    
    for service in ['ssl_analysis', 'bgp_analysis', 'hurricane_electric', 'threat_intelligence']:
        if hasattr(rate_limiter, 'get_status'):
            status = rate_limiter.get_status(service)
            if status:
                remaining = status.get('remaining_requests', 0)
                window = status.get('time_window', 60)
                print(f"   {service}: {remaining} requests remaining in {window}s window")
    
    return test_results

# Example usage - run this periodically for monitoring
monitoring_report = create_monitoring_report()
```

## 🔧 Advanced Configuration Examples

### Custom Integration Settings

```python
def configure_enhanced_detector():
    """Configure enhanced detector with custom settings"""
    from provider_discovery.config import get_settings
    
    # Get settings instance
    settings = get_settings()
    
    # Configure timeouts
    settings.update({
        'ssl_timeout': 20,          # SSL analysis timeout
        'dns_timeout': 15,          # DNS resolver timeout
        'bgp_timeout': 25,          # BGP analysis timeout
        'geo_timeout': 12,          # Geographic analysis timeout
        'threat_timeout': 18        # Threat intelligence timeout
    })
    
    # Configure cache settings
    settings.update({
        'cache_ttl_ssl': 14400,     # 4 hours for SSL data
        'cache_ttl_dns': 1800,      # 30 minutes for DNS data
        'cache_ttl_geo': 21600,     # 6 hours for geo data
        'cache_ttl_bgp': 7200,      # 2 hours for BGP data
        'cache_ttl_threat': 14400   # 4 hours for threat data
    })
    
    # Configure rate limiting
    settings.update({
        'rate_limit_ssl': 15,       # 15 requests per minute
        'rate_limit_dns': 25,       # 25 requests per minute
        'rate_limit_bgp': 8,        # 8 requests per minute
        'rate_limit_he': 4,         # 4 requests per minute (conservative)
        'rate_limit_threat': 8      # 8 requests per minute
    })
    
    print("⚙️ Enhanced detector configured with custom settings")
    return settings

# Example usage
custom_settings = configure_enhanced_detector()
detector = get_enhanced_provider_detector()
```

### Integration-Specific Examples

```python
# Direct access to individual integrations
detector = get_enhanced_provider_detector()

# SSL-specific analysis
ssl_analyzer = detector.ssl_analyzer
ssl_result = ssl_analyzer.analyze_domain_ssl("example.com")
print(f"SSL Grade: {ssl_result['security_assessment']['overall_grade']}")

# DNS-specific analysis
dns_analyzer = detector.enhanced_dns
dns_result = dns_analyzer.query_multiple_resolvers("example.com")
print(f"DNS Consensus: {dns_result['consensus_reached']}")

# Geographic-specific analysis
geo_analyzer = detector.geo_intel
geo_result = geo_analyzer.analyze_ip_comprehensive("8.8.8.8")
print(f"Location Confidence: {geo_result['consensus']['confidence_score']}%")

# BGP-specific analysis
bgp_analyzer = detector.bgp_analyzer
bgp_result = bgp_analyzer.analyze_ip_bgp("1.1.1.1")
print(f"ASN: AS{bgp_result['asn_info']['asn']}")

# Hurricane Electric BGP
he_analyzer = detector.hurricane_electric
he_result = he_analyzer.get_asn_details(13335)
print(f"HE Peers: {len(he_result['peers'])}")

# Threat intelligence
threat_analyzer = detector.threat_intel
threat_result = threat_analyzer.analyze_domain_reputation("example.com")
print(f"Threat Level: {threat_result['threat_level']}")
```

## 📊 Output Processing Examples

### JSON Export

```python
import json

def export_analysis_to_json(domain, filename=None):
    """Export analysis results to JSON format"""
    detector = get_enhanced_provider_detector()
    
    result = detector.detect_provider_comprehensive("", "", "", domain)
    
    # Create exportable version (remove non-serializable objects)
    exportable_result = {
        'domain': domain,
        'analysis_timestamp': datetime.now().isoformat(),
        'enhanced_confidence': result.get('Enhanced_Confidence', 0),
        'providers': result.get('providers', []),
        'security_findings': result.get('security_findings', []),
        'geographic_insights': result.get('geographic_insights', []),
        'bgp_insights': result.get('bgp_insights', []),
        'recommendations': result.get('Recommendations', []),
        'analysis_methods': result.get('analysis_methods', [])
    }
    
    # Add integration status
    enhanced_analysis = result.get('Enhanced_Analysis', {})
    integration_summary = {}
    
    for integration, data in enhanced_analysis.items():
        if isinstance(data, dict):
            integration_summary[integration] = {
                'status': 'success' if 'error' not in data else 'failed',
                'error': data.get('error') if 'error' in data else None
            }
    
    exportable_result['integration_summary'] = integration_summary
    
    # Save to file
    if not filename:
        filename = f"analysis_{domain.replace('.', '_')}.json"
    
    with open(filename, 'w') as f:
        json.dump(exportable_result, f, indent=2, default=str)
    
    print(f"📄 Analysis exported to: {filename}")
    return exportable_result

# Example usage
export_analysis_to_json("github.com")
```

### CSV Report Generation

```python
import csv

def generate_csv_report(domains, filename="provider_analysis.csv"):
    """Generate CSV report for multiple domains"""
    detector = get_enhanced_provider_detector()
    
    fieldnames = [
        'domain', 'enhanced_confidence', 'analysis_methods_count',
        'providers_count', 'primary_provider', 'cdn_provider',
        'ssl_grade', 'threat_level', 'location', 'asn',
        'working_integrations', 'analysis_date'
    ]
    
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for domain in domains:
            try:
                result = detector.detect_provider_comprehensive("", "", "", domain)
                
                # Extract data
                providers = result.get('providers', [])
                primary_provider = next((p['name'] for p in providers if p['role'] in ['Origin', 'Hosting']), 'Unknown')
                cdn_provider = next((p['name'] for p in providers if p['role'] in ['CDN', 'Proxy']), 'None')
                
                # SSL grade
                ssl_analysis = result['Enhanced_Analysis'].get('ssl_analysis', {})
                ssl_grade = ssl_analysis.get('security_assessment', {}).get('overall_grade', 'Unknown') if 'error' not in ssl_analysis else 'Error'
                
                # Threat level
                threat_analysis = result['Enhanced_Analysis'].get('threat_intelligence', {})
                threat_level = threat_analysis.get('overall_threat_level', 'unknown') if 'error' not in threat_analysis else 'error'
                
                # Location
                geo_analysis = result['Enhanced_Analysis'].get('geographic_intelligence', {})
                location = 'Unknown'
                if geo_analysis and 'error' not in geo_analysis:
                    consensus = geo_analysis.get('consensus', {})
                    if consensus.get('consensus_reached'):
                        location_data = consensus['consensus_data']
                        location = f"{location_data.get('city', 'Unknown')}, {location_data.get('country', 'Unknown')}"
                
                # ASN
                bgp_analysis = result['Enhanced_Analysis'].get('bgp_analysis', {})
                asn = bgp_analysis.get('asn_info', {}).get('asn', 'Unknown') if 'error' not in bgp_analysis else 'Error'
                
                # Working integrations
                enhanced_analysis = result.get('Enhanced_Analysis', {})
                working_integrations = sum(
                    1 for data in enhanced_analysis.values()
                    if isinstance(data, dict) and 'error' not in data
                )
                
                row_data = {
                    'domain': domain,
                    'enhanced_confidence': result.get('Enhanced_Confidence', 0),
                    'analysis_methods_count': len(result.get('analysis_methods', [])),
                    'providers_count': len(providers),
                    'primary_provider': primary_provider,
                    'cdn_provider': cdn_provider,
                    'ssl_grade': ssl_grade,
                    'threat_level': threat_level,
                    'location': location,
                    'asn': asn,
                    'working_integrations': working_integrations,
                    'analysis_date': datetime.now().isoformat()
                }
                
                writer.writerow(row_data)
                print(f"✅ {domain}: {result.get('Enhanced_Confidence', 0)}% confidence")
                
            except Exception as e:
                error_row = {field: 'Error' if field != 'domain' else domain for field in fieldnames}
                error_row['analysis_date'] = datetime.now().isoformat()
                writer.writerow(error_row)
                print(f"❌ {domain}: Analysis failed - {e}")
            
            time.sleep(1)  # Rate limiting
    
    print(f"📊 CSV report generated: {filename}")

# Example usage
domains = ["github.com", "google.com", "cloudflare.com"]
generate_csv_report(domains)
```

These comprehensive usage examples demonstrate how to leverage the Enhanced Provider Detection System with all 6 FREE integrations for various real-world scenarios, from security assessments to competitive intelligence and infrastructure analysis.
