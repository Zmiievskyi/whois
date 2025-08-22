"""
Provider Discovery Tool - Advanced CDN/hosting provider detection

A comprehensive tool for identifying hosting and CDN infrastructure with:
- Multi-layer detection (DNS, HTTP headers, IP ranges, WHOIS)
- VirusTotal integration for validation
- Advanced DNS analysis
- Security threat detection

Version: 2.0.0 (Phase 2B Complete)
"""

__version__ = "2.0.0"
__author__ = "Provider Discovery Team"
__description__ = "Advanced CDN/hosting provider detection with multi-layer analysis"

# Import configuration
from .config.settings import Settings, get_settings

# Try to import main classes (may not be available during refactoring)
try:
    from .core.detector import ProviderDetector
    DETECTOR_AVAILABLE = True
except ImportError:
    DETECTOR_AVAILABLE = False
    ProviderDetector = None

# Version info
VERSION_INFO = (2, 0, 0)

__all__ = [
    'ProviderDetector',
    'Settings', 
    'get_settings',
    '__version__',
    'VERSION_INFO'
]
