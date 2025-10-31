# Provider Discovery Tool - Test Suite

Comprehensive test suite for the Provider Discovery Tool covering unit tests, integration tests, and end-to-end scenarios.

## 📋 Test Structure

```
tests/
├── conftest.py                              # Shared fixtures and configuration
├── test_subdomain_enumeration.py            # Subdomain discovery tests
├── test_dns_analysis.py                     # DNS record collection tests
├── integration/
│   └── test_comprehensive_analysis.py       # Integration tests
└── README.md                                # This file
```

## 🎯 Test Coverage

### Unit Tests (Fast, No External Dependencies)

1. **Subdomain Enumeration** (`test_subdomain_enumeration.py`)
   - Dictionary-based enumeration with wordlist limits
   - Passive DNS enumeration (HackerTarget, BufferOver)
   - Certificate Transparency log parsing
   - Subfinder integration
   - Subdomain analysis and deduplication
   - Full subdomain list export (`all_subdomains` field)

2. **DNS Analysis** (`test_dns_analysis.py`)
   - DNS record collection (A, AAAA, MX, TXT, NS, SOA, CAA, etc.)
   - Nameserver detection and provider identification
   - Record parsing and validation
   - Error handling (NXDOMAIN, timeouts, etc.)

### Integration Tests (May Use Mocked External APIs)

3. **Comprehensive Analysis** (`integration/test_comprehensive_analysis.py`)
   - Full analysis workflow
   - Multi-method subdomain aggregation
   - Analysis limit and truncation
   - HTTP/HTTPS analysis
   - Security header detection
   - CDN detection
   - Origin server detection
   - Infrastructure mapping

## 🚀 Running Tests

### Install Test Dependencies

```bash
pip install pytest pytest-cov pytest-mock
```

### Run All Tests

```bash
# Run all tests with coverage
pytest

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=src/provider_discovery --cov-report=html
```

### Run Specific Test Categories

```bash
# Run only unit tests (fast)
pytest -m unit

# Run only integration tests
pytest -m integration

# Run only subdomain tests
pytest -m subdomain

# Run only DNS tests
pytest -m dns

# Exclude slow tests
pytest -m "not slow"
```

### Run Specific Test Files

```bash
# Run subdomain enumeration tests
pytest tests/test_subdomain_enumeration.py

# Run DNS analysis tests
pytest tests/test_dns_analysis.py

# Run integration tests
pytest tests/integration/
```

### Run Specific Test Classes or Functions

```bash
# Run specific test class
pytest tests/test_subdomain_enumeration.py::TestDictionaryEnumeration

# Run specific test function
pytest tests/test_subdomain_enumeration.py::TestDictionaryEnumeration::test_dictionary_enum_with_limit

# Run tests matching a pattern
pytest -k "test_dictionary"
```

## 📊 Test Markers

Tests are organized with pytest markers:

- `@pytest.mark.unit` - Fast unit tests, no external dependencies
- `@pytest.mark.integration` - Integration tests with mocked APIs
- `@pytest.mark.slow` - Slow-running tests
- `@pytest.mark.dns` - DNS-related tests
- `@pytest.mark.subdomain` - Subdomain enumeration tests
- `@pytest.mark.provider` - Provider detection tests
- `@pytest.mark.api` - Tests requiring API keys
- `@pytest.mark.mock` - Tests using mocked services

## 🔍 Coverage Report

After running tests with coverage:

```bash
# Generate HTML coverage report
pytest --cov=src/provider_discovery --cov-report=html

# Open coverage report
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

## 🛠️ Writing New Tests

### 1. Use Existing Fixtures

```python
def test_my_feature(comprehensive_analysis_instance, sample_domain):
    result = comprehensive_analysis_instance.some_method(sample_domain)
    assert result['key'] == 'expected_value'
```

### 2. Add Appropriate Markers

```python
@pytest.mark.unit
@pytest.mark.subdomain
def test_subdomain_feature():
    # Test implementation
    pass
```

### 3. Mock External Dependencies

```python
from unittest.mock import patch, Mock

@patch('requests.get')
def test_with_mocked_api(mock_get):
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {'data': 'test'}
    # Test implementation
```

### 4. Test Both Success and Failure Cases

```python
def test_handles_success():
    # Test successful scenario
    pass

def test_handles_api_error():
    # Test error handling
    pass

def test_handles_timeout():
    # Test timeout handling
    pass
```

## 🐛 Debugging Tests

### Run Tests in Debug Mode

```bash
# Run with print statements visible
pytest -s

# Run with detailed traceback
pytest --tb=long

# Stop at first failure
pytest -x

# Run last failed tests
pytest --lf
```

### Use pytest's built-in debugger

```python
def test_something():
    result = some_function()
    import pdb; pdb.set_trace()  # Breakpoint
    assert result == expected
```

## 📝 Test Configuration

Configuration is in `pytest.ini`:

```ini
[pytest]
testpaths = tests
python_files = test_*.py *_test.py
addopts = -v --cov=src/provider_discovery --cov-report=term-missing
markers =
    unit: Unit tests (fast, no external dependencies)
    integration: Integration tests (may call external APIs)
    subdomain: Subdomain enumeration tests
    dns: DNS related tests
```

## ✅ CI/CD Integration

### GitHub Actions Example

```yaml
- name: Run tests
  run: |
    pip install pytest pytest-cov
    pytest --cov=src/provider_discovery --cov-report=xml

- name: Upload coverage
  uses: codecov/codecov-action@v3
  with:
    file: ./coverage.xml
```

## 🎯 Test Goals

- **Coverage Target**: >80% code coverage
- **Performance**: Unit tests should run in <10 seconds
- **Reliability**: All tests should pass consistently
- **Maintainability**: Tests should be clear and well-documented

## 🔧 Troubleshooting

### Import Errors

If you get import errors, make sure `src/` is in the Python path:

```python
# In conftest.py (already configured)
import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
```

### DNS Resolution Fails

All DNS operations are mocked in unit tests. If you need real DNS:

```bash
# Run integration tests only
pytest -m integration
```

### Slow Tests

```bash
# Skip slow tests
pytest -m "not slow"

# Show slowest 10 tests
pytest --durations=10
```

## 📚 Resources

- [pytest Documentation](https://docs.pytest.org/)
- [pytest-cov Documentation](https://pytest-cov.readthedocs.io/)
- [unittest.mock Documentation](https://docs.python.org/3/library/unittest.mock.html)

## 🤝 Contributing

When adding new features:

1. Write tests first (TDD approach recommended)
2. Ensure all tests pass: `pytest`
3. Check coverage: `pytest --cov`
4. Add appropriate markers
5. Update this README if adding new test categories
