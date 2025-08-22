# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Development Commands

### Setup and Running
- **Install dependencies**: `pip install -r requirements.txt`
- **Run web application**: `streamlit run app.py`
- **Install development dependencies**: `pip install -e .[dev]`
- **Install all dependencies**: `pip install -e .[all]`

### Testing
- **Run specific integration test**: `python test_<integration_name>.py` (e.g., `python test_ssl_analysis.py`)
- **Run integrated system test**: `python test_integrated_system.py`
- **Install test dependencies**: `pip install pytest pytest-cov`

### Code Quality
- **Format code**: `black .`
- **Lint code**: `flake8 .`
- **Type checking**: `mypy src/`

### Virtual Environment
The project uses `venv_whois` as the virtual environment name:
```bash
python -m venv venv_whois
source venv_whois/bin/activate  # On Windows: venv_whois\Scripts\activate
```

## High-Level Architecture

### Core System Design
This is an **Enhanced Provider Discovery Tool v3.0** that detects hosting/CDN providers using 6 FREE data source integrations. The architecture follows a modular design:

```
provider_discovery/
├── src/provider_discovery/
│   ├── core/                    # Core detection engines
│   │   ├── detector.py          # Original provider detector
│   │   ├── enhanced_detector.py # Enhanced detector with 6 integrations
│   │   ├── dns_analyzer.py      # DNS resolution logic
│   │   └── ip_ranges.py         # IP range matching
│   ├── integrations/            # 6 FREE data source modules
│   │   ├── ssl_analysis.py      # SSL certificate analysis
│   │   ├── enhanced_dns.py      # Multi-resolver DNS + DoH
│   │   ├── geo_intelligence.py  # Geographic IP intelligence
│   │   ├── bgp_analysis.py      # BGPView API integration
│   │   ├── hurricane_electric.py # Hurricane Electric BGP fallback
│   │   ├── threat_intelligence.py # Security threat assessment
│   │   ├── virustotal.py        # VirusTotal API (optional)
│   │   └── censys.py            # Censys API integration
│   ├── config/                  # Configuration management
│   ├── utils/                   # Utility functions (cache, validators)
│   └── web/                     # Web interface components
└── app.py                       # Main Streamlit web application
```

### Detection Pipeline
The system uses a **multi-layer detection approach**:

1. **Enhanced Provider Detector** (`EnhancedProviderDetector`) orchestrates all 6 integrations
2. Each integration provides **specialized analysis**:
   - SSL Analysis: Certificate authority detection, security scoring
   - Enhanced DNS: Multi-resolver consensus, DoH validation
   - Geographic Intelligence: IP geolocation, cloud provider classification
   - BGP Analysis: ASN data, routing information (with Hurricane Electric fallback)
   - Threat Intelligence: Security assessment, reputation scoring
3. Results are **cross-validated** and confidence scores assigned
4. **Role separation**: Origin/CDN/WAF/Load Balancer/DNS provider identification

### Key Classes
- **`EnhancedProviderDetector`**: Main detection engine combining all 6 integrations
- **`ProviderDetector`**: Original detection engine (headers, IP ranges, WHOIS)
- **Integration classes**: Each integration module has its own class (e.g., `SSLAnalysisIntegration`)

### Data Flow
```
Input Domain → Enhanced Detector → 6 Parallel Integrations → Cross-Validation → Confidence Scoring → Multi-Provider Result
```

### Configuration
- **Settings**: Managed through `src/provider_discovery/config/settings.py`
- **Environment variables**: API keys loaded from `.env` or environment
- **Caching**: IP resolution and DNS queries cached for performance
- **Rate limiting**: Built-in rate limiting for external API calls

### Web Interface
- **Streamlit-based** web application (`app.py`)
- **Two modes**: Single URL analysis and CSV batch processing  
- **Terminal-style UI** with dark theme and monospace fonts
- **Real-time progress tracking** for batch operations
- **Enhanced analytics** with charts and confidence metrics

### Testing Strategy
- **Integration-specific tests**: Individual test files for each integration (`test_<integration>.py`)
- **System integration test**: `test_integrated_system.py` validates the complete pipeline
- **Fallback testing**: Tests verify graceful degradation when services are unavailable

### Key Features
- **6 FREE data sources** - no expensive API keys required for core functionality
- **Fallback systems** - Hurricane Electric provides BGP backup when BGPView is rate-limited
- **Cross-validation** - Multiple sources validate each other for accuracy
- **Security assessment** - Built-in threat intelligence and SSL security grading
- **Multi-provider detection** - Identifies complex setups (Origin + CDN + WAF)
- **High performance** - Parallel processing and intelligent caching