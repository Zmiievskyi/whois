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

try:
    from .censys import CensysIntegration, get_censys_integration
    CENSYS_INTEGRATION_AVAILABLE = True
except ImportError:
    CENSYS_INTEGRATION_AVAILABLE = False
    CensysIntegration = None
    get_censys_integration = None

try:
    from .bgp_analysis import BGPAnalysisIntegration, get_bgp_analysis_integration
    BGP_INTEGRATION_AVAILABLE = True
except ImportError:
    BGP_INTEGRATION_AVAILABLE = False
    BGPAnalysisIntegration = None
    get_bgp_analysis_integration = None

try:
    from .ssl_analysis import SSLAnalysisIntegration, get_ssl_analysis_integration
    SSL_INTEGRATION_AVAILABLE = True
except ImportError:
    SSL_INTEGRATION_AVAILABLE = False
    SSLAnalysisIntegration = None
    get_ssl_analysis_integration = None

try:
    from .enhanced_dns import EnhancedDNSIntegration, get_enhanced_dns_integration
    ENHANCED_DNS_INTEGRATION_AVAILABLE = True
except ImportError:
    ENHANCED_DNS_INTEGRATION_AVAILABLE = False
    EnhancedDNSIntegration = None
    get_enhanced_dns_integration = None

try:
    from .geo_intelligence import GeoIntelligenceIntegration, get_geo_intelligence_integration
    GEO_INTEGRATION_AVAILABLE = True
except ImportError:
    GEO_INTEGRATION_AVAILABLE = False
    GeoIntelligenceIntegration = None
    get_geo_intelligence_integration = None

try:
    from .threat_intelligence import ThreatIntelligenceIntegration, get_threat_intelligence_integration
    THREAT_INTEGRATION_AVAILABLE = True
except ImportError:
    THREAT_INTEGRATION_AVAILABLE = False
    ThreatIntelligenceIntegration = None
    get_threat_intelligence_integration = None

try:
    from .hurricane_electric import HurricaneElectricIntegration, get_hurricane_electric_integration
    HURRICANE_ELECTRIC_INTEGRATION_AVAILABLE = True
except ImportError:
    HURRICANE_ELECTRIC_INTEGRATION_AVAILABLE = False
    HurricaneElectricIntegration = None
    get_hurricane_electric_integration = None

__all__ = [
    'BaseIntegration',
    'APIKeyIntegration',
    'HTTPIntegration',
    'VirusTotalIntegration',
    'get_virustotal_integration',
    'VT_INTEGRATION_AVAILABLE',
    'CensysIntegration',
    'get_censys_integration',
    'CENSYS_INTEGRATION_AVAILABLE',
    'BGPAnalysisIntegration',
    'get_bgp_analysis_integration',
    'BGP_INTEGRATION_AVAILABLE',
    'SSLAnalysisIntegration',
    'get_ssl_analysis_integration',
    'SSL_INTEGRATION_AVAILABLE',
    'EnhancedDNSIntegration',
    'get_enhanced_dns_integration',
    'ENHANCED_DNS_INTEGRATION_AVAILABLE',
    'GeoIntelligenceIntegration',
    'get_geo_intelligence_integration',
    'GEO_INTEGRATION_AVAILABLE',
    'ThreatIntelligenceIntegration',
    'get_threat_intelligence_integration',
    'THREAT_INTEGRATION_AVAILABLE',
    'HurricaneElectricIntegration',
    'get_hurricane_electric_integration',
    'HURRICANE_ELECTRIC_INTEGRATION_AVAILABLE'
]
