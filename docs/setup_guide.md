# Provider Discovery Tool - Setup Guide

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Virtual environment (recommended)

### Installation

#### 1. Clone and Setup
```bash
cd provider_discovery
python -m venv venv_whois
source venv_whois/bin/activate  # On Windows: venv_whois\Scripts\activate
pip install -r requirements.txt
```

#### 2. Configure Environment
```bash
# Copy example environment file
cp env.example .env

# Edit .env file with your settings
VT_API_KEY=your-virustotal-api-key-here
```

#### 3. Run the Application
```bash
# Launch web interface
python scripts/run_app.py web

# Run tests
python scripts/run_app.py test

# Show configuration
python scripts/run_app.py config
```

## 📁 New Project Structure

```
provider_discovery/
├── .env                          # Environment variables (create from env.example)
├── env.example                   # Example environment file
├── requirements.txt              # Dependencies
├── setup.py                      # Package configuration
├── 
├── src/                          # Source code
│   └── provider_discovery/
│       ├── config/              # Configuration management
│       │   ├── settings.py      # Environment & settings
│       ├── core/                # Core detection logic
│       │   ├── detector.py      # Main detection (TODO)
│       │   ├── ip_ranges.py     # IP range management (TODO)
│       │   └── dns_analyzer.py  # DNS analysis (TODO)
│       ├── integrations/        # External API integrations
│       │   ├── virustotal.py    # VirusTotal integration (TODO)
│       │   └── base.py          # Base integration class (TODO)
│       ├── utils/               # Utilities
│       │   ├── cache.py         # Caching system ✅
│       │   ├── rate_limiter.py  # Rate limiting ✅
│       │   └── validators.py    # Data validation ✅
│       └── web/                 # Web interface
│           └── app.py           # Streamlit app (TODO: migrate)
├── 
├── tests/                       # Test files
├── docs/                        # Documentation
├── scripts/                     # Utility scripts
│   └── run_app.py              # Application launcher ✅
└── 
└── Legacy files (to be migrated):
    ├── app.py                   # Current Streamlit app
    ├── ultimate_provider_detector.py  # Current detector
    ├── virustotal_integrator.py # Current VT integration
    └── test_*.py               # Current tests
```

## 🔧 Configuration

### Environment Variables
The application uses `.env` file or environment variables:

```bash
# VirusTotal Configuration
VT_API_KEY=your-api-key-here
VT_PREMIUM=false
VT_TIMEOUT=30

# Application Settings
APP_DEBUG=false
APP_LOG_LEVEL=INFO
APP_CACHE_SIZE=1000

# Feature Flags
ENABLE_DNS_ANALYSIS=true
ENABLE_VIRUSTOTAL=true
ENABLE_CACHING=true
```

### Testing Configuration
```bash
# Test configuration module
python scripts/run_app.py config

# Test utilities
python -c "
import sys; sys.path.insert(0, 'src')
from provider_discovery.utils.cache import Cache
from provider_discovery.utils.validators import URLValidator
print('✅ All utilities working')
"
```

## 🔄 Migration Status

### ✅ Completed Modules
- **Configuration system** - Environment variable management
- **Caching utilities** - Thread-safe cache with TTL
- **Rate limiting** - Multi-service rate limiter
- **Validation utilities** - URL, IP, CSV validation
- **Project structure** - Modular organization
- **Documentation** - Setup guides and examples

### 🚧 In Progress
- **Code refactoring** - Moving legacy code to new structure
- **Core detector** - Breaking down ultimate_provider_detector.py
- **Integration modules** - Separating VirusTotal and other integrations
- **Web interface** - Migrating Streamlit app to new structure

### 📋 Next Steps
1. Refactor `ultimate_provider_detector.py` into modular components
2. Move VirusTotal integration to `src/provider_discovery/integrations/`
3. Migrate web interface to new structure
4. Update test files for new modules
5. Add CLI interface

## 🧪 Testing

### Test Current Functionality
```bash
# Test legacy app (still works)
streamlit run app.py

# Test Phase 2A features
python test_phase_2a.py

# Test Phase 2B features (requires VT_API_KEY)
python test_phase_2b.py
```

### Test New Modules
```bash
# Test configuration
python scripts/run_app.py config

# Test all utilities
python -c "
import sys; sys.path.insert(0, 'src')
from provider_discovery.config import get_settings
from provider_discovery.utils.cache import Cache
from provider_discovery.utils.rate_limiter import RateLimiter
from provider_discovery.utils.validators import URLValidator
print('All new modules working!')
"
```

## 🎯 Benefits of New Structure

### 1. **Modularity**
- Clear separation of concerns
- Easier testing and maintenance
- Reusable components

### 2. **Configuration Management**
- Centralized settings
- Environment variable support
- Validation and defaults

### 3. **Better Organization**
- Logical folder structure
- Import clarity
- Scalable architecture

### 4. **Enhanced Development**
- Easier to add new integrations
- Better error handling
- Improved logging and debugging

## 🔗 Next Documentation
- [API Reference](api_reference.md) - Module and class documentation
- [VirusTotal Setup](virustotal_setup.md) - VirusTotal integration guide
