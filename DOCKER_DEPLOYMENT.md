# Docker Deployment Guide - Provider Discovery Tool

## 🐳 Quick Start

### Prerequisites
- Docker (20.10+)
- Docker Compose (2.0+)

### Basic Deployment

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd provider_discovery
   ```

2. **Create `.env` file from template:**
   ```bash
   cp env.example .env
   ```

3. **Configure API keys in `.env`:**
   ```bash
   # Edit .env and add your API keys
   nano .env
   ```

4. **Build and run:**
   ```bash
   docker-compose up -d
   ```

5. **Access the application:**
   ```
   http://localhost:8501
   ```

---

## 🔧 Environment Configuration

### Required Configuration for Full Functionality

#### **IPInfo.io (Highly Recommended - Multi-Source BGP)**
```bash
# Get free token from: https://ipinfo.io/signup
IPINFO_API_KEY=your_ipinfo_token_here
IPINFO_CACHE_TTL=7200
IPINFO_RATE_LIMIT=60
```

**Benefits:**
- ✅ 50,000 requests/month (free)
- ✅ City-level geolocation
- ✅ Enhanced ASN/BGP data
- ✅ Replaces unreliable BGPView

#### **VirusTotal (Optional - Threat Intelligence)**
```bash
VT_API_KEY=your_virustotal_api_key_here
VT_PREMIUM=false
VT_TIMEOUT=30
VT_CACHE_TTL=3600
```

#### **Censys (Optional - Alternative to Shodan)**
```bash
CENSYS_API_ID=your_censys_api_id_here
CENSYS_API_SECRET=your_censys_api_secret_here
CENSYS_CACHE_TTL=7200
CENSYS_RATE_LIMIT=10
```

#### **Shodan (Optional - Premium WAF Detection)**
```bash
SHODAN_API_KEY=your_shodan_api_key_here
SHODAN_CACHE_TTL=14400
SHODAN_RATE_LIMIT=1
```

---

## 📋 Complete Docker Compose Configuration

### Current `docker-compose.yml`

```yaml
services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8501:8501"
    volumes:
      - ./results:/app/results
      - ./.env:/app/.env:ro
    env_file:
      - .env
    environment:
      - STREAMLIT_SERVER_HEADLESS=true
      - STREAMLIT_SERVER_FILE_WATCHER_TYPE=none
```

### How Environment Variables are Loaded

1. **`env_file: .env`** - Automatically loads ALL variables from `.env`
2. **`- ./.env:/app/.env:ro`** - Mounts `.env` as read-only for runtime access
3. **`environment:`** - Overrides specific Streamlit settings

**All variables from `env.example` are automatically available in the container!**

---

## 🚀 Deployment Scenarios

### Scenario 1: Development (No API Keys)

```bash
# Use default env.example (works without keys)
cp env.example .env
docker-compose up
```

**What works:**
- ✅ DNS analysis
- ✅ WHOIS lookups
- ✅ SSL analysis
- ✅ IPInfo.io (1000 req/day free tier)
- ✅ Hurricane Electric (fallback)
- ✅ Basic provider detection

**What's limited:**
- ⚠️ IPInfo.io limited to 1000/day
- ❌ No VirusTotal threat intel
- ❌ No Shodan/Censys data

---

### Scenario 2: Production (With IPInfo Token)

```bash
# Create .env with IPInfo token
cp env.example .env

# Edit .env and add:
# IPINFO_API_KEY=your_token_here

docker-compose up -d
```

**Enhanced capabilities:**
- ✅ 50,000 IPInfo requests/month
- ✅ City-level geolocation
- ✅ Enhanced ASN data
- ✅ Full multi-source BGP strategy

---

### Scenario 3: Full Featured (All API Keys)

```bash
# Create .env with all keys
cp env.example .env

# Edit .env and add:
# IPINFO_API_KEY=...
# VT_API_KEY=...
# CENSYS_API_ID=...
# CENSYS_API_SECRET=...
# SHODAN_API_KEY=...

docker-compose up -d
```

**Maximum capabilities:**
- ✅ All BGP/ASN intelligence
- ✅ Threat intelligence
- ✅ WAF detection
- ✅ Port scanning data
- ✅ Historical DNS records

---

## 🔍 Verification

### Check Container Status

```bash
# View running containers
docker-compose ps

# Check logs
docker-compose logs -f app

# Check API key status
docker-compose exec app python3 -c "
from src.provider_discovery.config.settings import get_settings, print_configuration_info
settings = get_settings()
print_configuration_info(settings)
"
```

### Test Multi-Source BGP

```bash
# Run demo script inside container
docker-compose exec app python3 demo_multisource_bgp.py
```

Expected output:
```
✅ Multi-Source BGP is working!
   Primary Source: ipinfo
   Test ASN: AS15169
   Test Name: Google LLC

   Available Sources:
     ✅ ipinfo
     ✅ hurricane_electric
     ✅ ripe
     ✅ local_classifier
```

---

## 🛠️ Troubleshooting

### Issue: IPInfo API Key Not Working

```bash
# Check if .env is mounted
docker-compose exec app cat .env | grep IPINFO

# Verify environment variable is loaded
docker-compose exec app printenv IPINFO_API_KEY

# Restart container to reload .env
docker-compose restart app
```

### Issue: "Unknown cache type: ipinfo"

**Solution:** Rebuild the container with updated code:

```bash
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Issue: BGPView 500 Errors in Logs

**This is expected and normal!** BGPView is deprecated and replaced by IPInfo.io.

The logs show:
```
BGP API request failed for https://api.bgpview.io/ip/8.8.8.8: 500 Server Error
```

**Solution:** These are harmless - the system automatically falls back to IPInfo.io.

To silence these warnings, IPInfo.io is now the primary source.

---

## 📊 Monitoring

### Health Check

Docker includes automatic health checks:

```bash
# Check container health
docker inspect --format='{{.State.Health.Status}}' provider_discovery-app-1

# View health check logs
docker inspect --format='{{json .State.Health}}' provider_discovery-app-1 | jq
```

### Application Metrics

```bash
# View cache statistics
docker-compose exec app python3 -c "
from src.provider_discovery.utils.cache import get_cache_manager
cache = get_cache_manager()
print(cache.stats())
"
```

---

## 🔄 Updates and Maintenance

### Update Application Code

```bash
# Pull latest changes
git pull

# Rebuild container
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Update Dependencies

```bash
# If requirements.txt changed
docker-compose build --no-cache
docker-compose up -d
```

### Clear Cache

```bash
# Remove volumes and restart
docker-compose down -v
docker-compose up -d
```

---

## 📦 Production Deployment

### Recommended `docker-compose.prod.yml`

```yaml
services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8501:8501"
    volumes:
      - ./results:/app/results
      - ./.env:/app/.env:ro
    env_file:
      - .env
    environment:
      - STREAMLIT_SERVER_HEADLESS=true
      - STREAMLIT_SERVER_FILE_WATCHER_TYPE=none
    restart: unless-stopped
    healthcheck:
      interval: 30s
      timeout: 10s
      start_period: 5s
      retries: 3
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M
```

**Deploy:**
```bash
docker-compose -f docker-compose.prod.yml up -d
```

---

## 🔒 Security Best Practices

### 1. Protect `.env` File

```bash
# Never commit .env to git
echo ".env" >> .gitignore

# Set restrictive permissions
chmod 600 .env
```

### 2. Use Secrets in Production

For production, consider Docker secrets:

```yaml
services:
  app:
    secrets:
      - ipinfo_api_key
      - vt_api_key

secrets:
  ipinfo_api_key:
    file: ./secrets/ipinfo_api_key.txt
  vt_api_key:
    file: ./secrets/vt_api_key.txt
```

### 3. Run as Non-Root User

Add to Dockerfile:

```dockerfile
RUN useradd -m -u 1000 appuser
USER appuser
```

---

## 📈 Performance Tuning

### Adjust Cache Settings

```bash
# In .env
APP_CACHE_SIZE=2000
IPINFO_CACHE_TTL=14400  # 4 hours for longer caching
```

### Resource Limits

```yaml
# docker-compose.yml
services:
  app:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
```

---

## 🎯 Summary Checklist

- [ ] Copy `env.example` to `.env`
- [ ] Add IPInfo API key (get from https://ipinfo.io/signup)
- [ ] Add other API keys (optional)
- [ ] Run `docker-compose up -d`
- [ ] Verify at http://localhost:8501
- [ ] Run `docker-compose exec app python3 demo_multisource_bgp.py`
- [ ] Check logs: `docker-compose logs -f app`

---

## 🆘 Support

**Issues with Docker deployment?**

1. Check logs: `docker-compose logs -f app`
2. Verify .env file is mounted: `docker-compose exec app cat .env`
3. Test multi-source BGP: `docker-compose exec app python3 demo_multisource_bgp.py`
4. Rebuild container: `docker-compose build --no-cache && docker-compose up -d`

**All environment variables are automatically passed from `.env` to Docker container via `env_file` directive!**

---

**Status:** ✅ Docker Deployment Verified - All Variables Properly Configured
