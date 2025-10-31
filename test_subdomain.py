#!/usr/bin/env python3
import sys
sys.path.insert(0, '/app/src')

from provider_discovery.integrations.comprehensive_analysis import ComprehensiveAnalysisIntegration
import time

comp = ComprehensiveAnalysisIntegration()

print('=== Testing subdomain enumeration for prestashop.sh ===')
start = time.time()

result = comp._enumerate_subdomains('prestashop.sh')

elapsed = time.time() - start

print(f'\n✅ Completed in {elapsed:.2f} seconds')
print(f'\nResults:')
print(f'  - Total found: {result.get("total_found")}')
print(f'  - Methods used: {result.get("enumeration_methods")}')
print(f'  - Method summary:')
for m in result.get("method_summary", []):
    print(f'      • {m["method"]}: {m["count"]} subdomains')

print(f'\n📝 First 50 of {len(result.get("all_subdomains", []))} subdomains:')
for i, sub in enumerate(sorted(result.get("all_subdomains", []))[:50], 1):
    print(f'  {i:3d}. {sub}')
