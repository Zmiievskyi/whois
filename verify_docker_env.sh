#!/bin/bash
# Verification script for Docker environment variables
# Checks that all required environment variables are properly configured

set -e

echo "🔍 Verifying Docker Environment Configuration..."
echo "=================================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to check if variable is set in .env
check_env_var() {
    local var_name=$1
    local is_required=$2

    if grep -q "^${var_name}=" .env 2>/dev/null; then
        local value=$(grep "^${var_name}=" .env | cut -d'=' -f2)
        local lower_name=$(echo "${var_name}" | tr '[:upper:]' '[:lower:]')
        if [ "$value" != "your-${lower_name}-here" ] && [ "$value" != "your_token_here" ] && [ -n "$value" ]; then
            echo -e "${GREEN}✅ ${var_name}${NC} - Configured"
            return 0
        else
            if [ "$is_required" = "true" ]; then
                echo -e "${RED}❌ ${var_name}${NC} - Not configured (placeholder value)"
                return 1
            else
                echo -e "${YELLOW}⚠️  ${var_name}${NC} - Not configured (optional)"
                return 0
            fi
        fi
    else
        if [ "$is_required" = "true" ]; then
            echo -e "${RED}❌ ${var_name}${NC} - Missing from .env"
            return 1
        else
            echo -e "${YELLOW}⚠️  ${var_name}${NC} - Missing (optional)"
            return 0
        fi
    fi
}

# Check if .env exists
if [ ! -f .env ]; then
    echo -e "${RED}❌ .env file not found!${NC}"
    echo ""
    echo "Please create .env file:"
    echo "  cp env.example .env"
    echo ""
    exit 1
fi

echo "1. Checking .env file..."
echo "-----------------------"
echo ""

# Check IPInfo (recommended)
echo "🌐 IPInfo.io Configuration (Recommended):"
check_env_var "IPINFO_API_KEY" "false"
check_env_var "IPINFO_CACHE_TTL" "false"
check_env_var "IPINFO_RATE_LIMIT" "false"
echo ""

# Check VirusTotal (optional)
echo "🦠 VirusTotal Configuration (Optional):"
check_env_var "VT_API_KEY" "false"
echo ""

# Check Censys (optional)
echo "🔍 Censys Configuration (Optional):"
check_env_var "CENSYS_API_ID" "false"
check_env_var "CENSYS_API_SECRET" "false"
echo ""

# Check Shodan (optional)
echo "🔍 Shodan Configuration (Optional):"
check_env_var "SHODAN_API_KEY" "false"
echo ""

# Check docker-compose.yml
echo "2. Checking docker-compose.yml..."
echo "----------------------------------"
echo ""

if [ ! -f docker-compose.yml ]; then
    echo -e "${RED}❌ docker-compose.yml not found!${NC}"
    exit 1
fi

# Check if env_file is configured
if grep -q "env_file:" docker-compose.yml; then
    echo -e "${GREEN}✅ env_file directive found${NC}"
else
    echo -e "${RED}❌ env_file directive missing${NC}"
    exit 1
fi

# Check if .env is mounted
if grep -q ".env:/app/.env" docker-compose.yml; then
    echo -e "${GREEN}✅ .env volume mount configured${NC}"
else
    echo -e "${YELLOW}⚠️  .env not mounted as volume (variables will still work via env_file)${NC}"
fi

echo ""

# Check Dockerfile
echo "3. Checking Dockerfile..."
echo "-------------------------"
echo ""

if [ ! -f Dockerfile ]; then
    echo -e "${RED}❌ Dockerfile not found!${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Dockerfile exists${NC}"
echo ""

# Test if Docker is running
echo "4. Checking Docker availability..."
echo "----------------------------------"
echo ""

if ! docker info >/dev/null 2>&1; then
    echo -e "${RED}❌ Docker is not running!${NC}"
    echo "Please start Docker daemon."
    exit 1
fi

echo -e "${GREEN}✅ Docker is running${NC}"
echo ""

# Check if container is running
echo "5. Checking container status..."
echo "-------------------------------"
echo ""

if docker-compose ps | grep -q "Up"; then
    echo -e "${GREEN}✅ Container is running${NC}"

    # Test if we can execute commands
    echo ""
    echo "6. Testing environment variables in container..."
    echo "------------------------------------------------"
    echo ""

    # Check IPINFO_API_KEY
    if docker-compose exec -T app printenv IPINFO_API_KEY >/dev/null 2>&1; then
        echo -e "${GREEN}✅ IPINFO_API_KEY is available in container${NC}"
    else
        echo -e "${YELLOW}⚠️  IPINFO_API_KEY not set (will use free tier)${NC}"
    fi

    # Check VT_API_KEY
    if docker-compose exec -T app printenv VT_API_KEY >/dev/null 2>&1; then
        echo -e "${GREEN}✅ VT_API_KEY is available in container${NC}"
    else
        echo -e "${YELLOW}⚠️  VT_API_KEY not set (optional)${NC}"
    fi

    echo ""
    echo "7. Testing multi-source BGP integration..."
    echo "------------------------------------------"
    echo ""

    # Run quick BGP test
    if docker-compose exec -T app python3 -c "
from src.provider_discovery.integrations.bgp_analysis import BGPAnalysisIntegration
bgp = BGPAnalysisIntegration()
result = bgp.test_connection()
if result.get('success'):
    print('✅ Multi-source BGP is working')
    print(f'   Primary source: {result.get(\"data_source\")}')
    print(f'   Sources available: {list(result.get(\"sources_available\", {}).keys())}')
else:
    print('❌ BGP test failed:', result.get('error'))
" 2>/dev/null; then
        echo ""
    else
        echo -e "${RED}❌ BGP test failed${NC}"
    fi

else
    echo -e "${YELLOW}⚠️  Container is not running${NC}"
    echo ""
    echo "To start the container:"
    echo "  docker-compose up -d"
fi

echo ""
echo "=================================================="
echo "✅ Verification Complete!"
echo "=================================================="
echo ""

# Summary and recommendations
echo "📋 Summary:"
echo "-----------"
echo ""

if grep -q "^IPINFO_API_KEY=" .env && [ "$(grep '^IPINFO_API_KEY=' .env | cut -d'=' -f2)" != "your_token_here" ]; then
    echo -e "${GREEN}✅ IPInfo.io token configured${NC} (50k requests/month)"
else
    echo -e "${YELLOW}⚠️  IPInfo.io token not configured${NC}"
    echo ""
    echo "   To get enhanced BGP/ASN data with 50k requests/month:"
    echo "   1. Sign up at: https://ipinfo.io/signup"
    echo "   2. Get your free token"
    echo "   3. Add to .env: IPINFO_API_KEY=your_token_here"
    echo "   4. Restart container: docker-compose restart"
fi

echo ""
echo "📚 Documentation:"
echo "   - Quick start: docker-compose up -d"
echo "   - View logs: docker-compose logs -f app"
echo "   - Test BGP: docker-compose exec app python3 demo_multisource_bgp.py"
echo "   - Full guide: see DOCKER_DEPLOYMENT.md"
echo ""
