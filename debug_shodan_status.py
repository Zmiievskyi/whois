#!/usr/bin/env python3
"""Debug Shodan integration status"""

from src.provider_discovery.core.enhanced_detector import get_enhanced_provider_detector

detector = get_enhanced_provider_detector()

print("=== SHODAN INTEGRATION DEBUG ===")
print(f"Shodan integration available: {hasattr(detector, 'shodan_integration')}")
print(f"Shodan integration object: {detector.shodan_integration}")

if detector.shodan_integration:
    print(f"Shodan enabled: {detector.shodan_integration.is_enabled}")
    if hasattr(detector.shodan_integration, 'client'):
        print(f"Shodan client: {detector.shodan_integration.client}")
    
    # Test connection
    try:
        test_result = detector.shodan_integration.test_connection()
        print(f"Connection test: {test_result}")
    except Exception as e:
        print(f"Connection test error: {e}")

# Check if condition passes
condition_result = detector.shodan_integration and detector.shodan_integration.is_enabled
print(f"Condition 'shodan_integration and is_enabled': {condition_result}")

# Show available enhancements
enhancements = detector._get_available_enhancements()
print(f"Available enhancements: {enhancements}")
