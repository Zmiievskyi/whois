"""
Provider Discovery Tool - Advanced CDN/hosting provider detection

A comprehensive tool for identifying hosting and CDN infrastructure with:
- Multi-layer detection (DNS, HTTP headers, IP ranges, WHOIS)
- VirusTotal integration for validation
- Advanced DNS analysis
- Security threat detection

Version: 3.0.0 (Enhanced System with 6 FREE Integrations)
"""

__version__ = "3.0.0"
__author__ = "Provider Discovery Team"
__description__ = "Enhanced Provider Detection System with 6 FREE data source integrations"

# Import configuration
from .config.settings import Settings, get_settings

# Try to import main classes (may not be available during refactoring)
try:
    from .core.detector import ProviderDetector
    from .core.enhanced_detector import EnhancedProviderDetector, get_enhanced_provider_detector
    DETECTOR_AVAILABLE = True
    ENHANCED_DETECTOR_AVAILABLE = True
except ImportError:
    DETECTOR_AVAILABLE = False
    ENHANCED_DETECTOR_AVAILABLE = False
    ProviderDetector = None
    EnhancedProviderDetector = None
    get_enhanced_provider_detector = None

# Version info
VERSION_INFO = (3, 0, 0)

__all__ = [
    'ProviderDetector',
    'EnhancedProviderDetector',
    'get_enhanced_provider_detector',
    'Settings', 
    'get_settings',
    '__version__',
    'VERSION_INFO'
]
