# 🧪 Testing Quick Start Guide

Quick guide to get started with testing the Provider Discovery Tool.

## 📦 Installation

### 1. Install Test Dependencies

```bash
# Make sure your virtual environment is activated
source venv_whois/bin/activate  # macOS/Linux
# or
venv_whois\Scripts\activate  # Windows

# Install test dependencies
pip install pytest pytest-cov pytest-mock
```

## 🚀 Running Tests

### Quick Start

```bash
# Run all tests (simplest)
pytest

# Run tests with output
pytest -v

# Run tests with coverage
pytest --cov=src/provider_discovery
```

### Using the Test Runner Script

```bash
# Make the script executable (first time only)
chmod +x run_tests.sh

# Run all tests
./run_tests.sh

# Run only fast unit tests
./run_tests.sh unit

# Run subdomain tests
./run_tests.sh subdomain

# Generate coverage report
./run_tests.sh coverage
```

## 📊 Test Categories

### Unit Tests (Fast ⚡)

Test individual components without external dependencies:

```bash
pytest -m unit
```

**What's tested:**
- ✅ Subdomain enumeration (all 4 methods)
- ✅ Dictionary brute force with limits
- ✅ DNS record collection and parsing
- ✅ Wordlist loading
- ✅ Result aggregation
- ✅ Error handling

### Integration Tests (Comprehensive 🔄)

Test full workflows with mocked external APIs:

```bash
pytest -m integration
```

**What's tested:**
- ✅ Full comprehensive analysis workflow
- ✅ Multi-method aggregation
- ✅ HTTP/HTTPS analysis
- ✅ CDN detection
- ✅ Security header analysis
- ✅ Infrastructure mapping

### Specific Categories

```bash
# Subdomain enumeration tests
pytest -m subdomain

# DNS analysis tests
pytest -m dns
```

## 📝 Example Test Run

```bash
$ pytest -v

tests/test_subdomain_enumeration.py::TestSubdomainEnumeration::test_enumerate_subdomains_returns_data_structure PASSED
tests/test_subdomain_enumeration.py::TestSubdomainEnumeration::test_all_subdomains_list_is_complete PASSED
tests/test_subdomain_enumeration.py::TestDictionaryEnumeration::test_dictionary_enum_with_limit PASSED
tests/test_subdomain_enumeration.py::TestDictionaryEnumeration::test_dictionary_enum_with_zero_limit PASSED
tests/test_dns_analysis.py::TestDNSRecordCollection::test_collect_all_dns_records_structure PASSED
tests/test_dns_analysis.py::TestDNSRecordCollection::test_collect_dns_a_records PASSED
tests/integration/test_comprehensive_analysis.py::TestComprehensiveAnalysisIntegration::test_full_comprehensive_analysis PASSED

======================== 65 passed in 2.34s =========================
```

## 🎯 What's Being Tested

### ✅ Subdomain Enumeration
- **Dictionary method**: Wordlist limits (0, 100, 2000, 10000)
- **Passive DNS**: HackerTarget & BufferOver API parsing
- **Certificate Transparency**: crt.sh log parsing
- **Subfinder**: Binary execution and output parsing
- **Result aggregation**: Deduplication across all methods
- **Full list export**: `all_subdomains` field verification

### ✅ DNS Analysis
- **Record types**: A, AAAA, MX, TXT, NS, SOA, CAA, SRV
- **Record parsing**: SPF detection, DMARC, CAA extraction
- **Provider detection**: Cloudflare, AWS, Google DNS identification
- **Error handling**: NXDOMAIN, timeouts, NoAnswer

### ✅ Integration
- **Full workflow**: Domain → DNS → Subdomains → HTTP → Results
- **Analysis limits**: Truncation of detailed analysis
- **Partial failures**: Continue when some methods fail
- **HTTP analysis**: Security headers, CDN detection
- **Infrastructure mapping**: Provider categorization

## 🔍 Coverage Report

Generate and view coverage report:

```bash
pytest --cov=src/provider_discovery --cov-report=html
open htmlcov/index.html  # macOS
```

## 🐛 Debugging Failed Tests

```bash
# Run specific test
pytest tests/test_subdomain_enumeration.py::TestDictionaryEnumeration::test_dictionary_enum_with_limit -v

# Stop at first failure
pytest -x

# Show print statements
pytest -s

# Show full traceback
pytest --tb=long
```

## ✅ Before Committing

Run this checklist before pushing code:

```bash
# 1. Run all tests
pytest

# 2. Check coverage (should be >80%)
pytest --cov=src/provider_discovery --cov-report=term-missing

# 3. Run fast tests to catch obvious issues
pytest -m "not slow" -x
```

## 📚 Key Test Files

```
tests/
├── conftest.py                         # Fixtures & mocks
├── test_subdomain_enumeration.py       # 40+ tests for subdomain discovery
├── test_dns_analysis.py                # 25+ tests for DNS operations
├── integration/
│   └── test_comprehensive_analysis.py  # Full workflow tests
└── README.md                           # Detailed documentation
```

## 💡 Tips

1. **Fast feedback**: Use `-x` to stop at first failure
2. **Focus**: Use `-k "test_dictionary"` to run matching tests
3. **Watch mode**: Use `./run_tests.sh watch` for TDD
4. **Coverage gaps**: Look at `htmlcov/index.html` for untested code

## 🎯 Test Philosophy

Our tests verify:
- ✅ **Updated functionality**: New `all_subdomains` field works correctly
- ✅ **Limits respected**: `SUBDOMAIN_DICTIONARY_LIMIT` and `SUBDOMAIN_ANALYSIS_LIMIT`
- ✅ **Error handling**: DNS failures, API timeouts, missing binaries
- ✅ **Integration**: All 4 methods work together correctly
- ✅ **Edge cases**: Empty results, huge wordlists, partial failures

## 🚨 Common Issues

### Import Errors
```bash
# Make sure you're in project root
cd /path/to/provider_discovery

# Check Python path
python -c "import sys; print(sys.path)"
```

### Pytest Not Found
```bash
# Install in virtual environment
pip install pytest pytest-cov pytest-mock

# Verify installation
pytest --version
```

### Tests Hang
Some integration tests may take a few seconds due to DNS mocking. This is normal.

## 📖 Further Reading

- Full documentation: `tests/README.md`
- Pytest docs: https://docs.pytest.org/
- Coverage docs: https://pytest-cov.readthedocs.io/

---

**Ready to test?** Run: `./run_tests.sh` or `pytest -v`
