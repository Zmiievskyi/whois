"""
Integrations package for external API services
"""

from .base import BaseIntegration, APIKeyIntegration, HTTPIntegration

try:
    from .virustotal import VirusTotalIntegration, get_virustotal_integration
    VT_INTEGRATION_AVAILABLE = True
except ImportError:
    VT_INTEGRATION_AVAILABLE = False
    VirusTotalIntegration = None
    get_virustotal_integration = None

__all__ = [
    'BaseIntegration', 
    'APIKeyIntegration', 
    'HTTPIntegration',
    'VirusTotalIntegration',
    'get_virustotal_integration',
    'VT_INTEGRATION_AVAILABLE'
]
