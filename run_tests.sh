#!/bin/bash

# Provider Discovery Tool - Test Runner Script
# Run tests with various options

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}Provider Discovery Tool - Test Suite${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Check if pytest is installed
if ! command -v pytest &> /dev/null; then
    echo -e "${RED}Error: pytest not found${NC}"
    echo "Please install test dependencies:"
    echo "  pip install pytest pytest-cov pytest-mock"
    exit 1
fi

# Parse command line arguments
TEST_TYPE="${1:-all}"

case $TEST_TYPE in
    all)
        echo -e "${GREEN}Running all tests with coverage...${NC}"
        pytest -v --cov=src/provider_discovery --cov-report=html --cov-report=term-missing
        ;;
    unit)
        echo -e "${GREEN}Running unit tests only...${NC}"
        pytest -v -m unit
        ;;
    integration)
        echo -e "${GREEN}Running integration tests...${NC}"
        pytest -v -m integration
        ;;
    subdomain)
        echo -e "${GREEN}Running subdomain enumeration tests...${NC}"
        pytest -v -m subdomain
        ;;
    dns)
        echo -e "${GREEN}Running DNS analysis tests...${NC}"
        pytest -v -m dns
        ;;
    fast)
        echo -e "${GREEN}Running fast tests only (excluding slow tests)...${NC}"
        pytest -v -m "not slow"
        ;;
    coverage)
        echo -e "${GREEN}Running tests and generating coverage report...${NC}"
        pytest --cov=src/provider_discovery --cov-report=html --cov-report=term
        echo ""
        echo -e "${BLUE}Coverage report generated in htmlcov/index.html${NC}"
        if command -v open &> /dev/null; then
            echo "Opening coverage report..."
            open htmlcov/index.html
        fi
        ;;
    watch)
        echo -e "${GREEN}Running tests in watch mode...${NC}"
        echo -e "${YELLOW}Note: Install pytest-watch for better experience: pip install pytest-watch${NC}"
        if command -v ptw &> /dev/null; then
            ptw -- -v
        else
            echo "pytest-watch not found, running in loop..."
            while true; do
                clear
                pytest -v
                echo ""
                echo -e "${YELLOW}Waiting for changes... (Ctrl+C to exit)${NC}"
                sleep 5
            done
        fi
        ;;
    *)
        echo -e "${YELLOW}Usage: $0 [all|unit|integration|subdomain|dns|fast|coverage|watch]${NC}"
        echo ""
        echo "Options:"
        echo "  all          - Run all tests with coverage (default)"
        echo "  unit         - Run only unit tests (fast)"
        echo "  integration  - Run only integration tests"
        echo "  subdomain    - Run subdomain enumeration tests"
        echo "  dns          - Run DNS analysis tests"
        echo "  fast         - Run fast tests only (exclude slow)"
        echo "  coverage     - Generate HTML coverage report"
        echo "  watch        - Run tests in watch mode"
        echo ""
        echo "Examples:"
        echo "  $0              # Run all tests"
        echo "  $0 unit         # Run unit tests only"
        echo "  $0 coverage     # Generate coverage report"
        exit 1
        ;;
esac

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ Tests completed successfully!${NC}"
else
    echo -e "${RED}✗ Tests failed with exit code $EXIT_CODE${NC}"
fi

exit $EXIT_CODE
