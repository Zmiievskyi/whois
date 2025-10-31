"""
Pytest configuration and shared fixtures for Provider Discovery Tool tests
"""
import os
import sys
from pathlib import Path
from unittest.mock import Mock, MagicMock
import pytest
import dns.resolver
import dns.rdatatype

# Add src to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from provider_discovery.integrations.comprehensive_analysis import ComprehensiveAnalysisIntegration


# ============================================================================
# Environment Setup
# ============================================================================

@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Setup test environment variables"""
    os.environ.setdefault("APP_DEBUG", "false")
    os.environ.setdefault("APP_LOG_LEVEL", "ERROR")
    os.environ.setdefault("ENABLE_CACHING", "false")
    # Disable external API calls by default
    os.environ.setdefault("ENABLE_VIRUSTOTAL", "false")
    os.environ.setdefault("ENABLE_SHODAN", "false")
    os.environ.setdefault("ENABLE_CT_ENUMERATION", "false")
    os.environ.setdefault("ENABLE_PASSIVE_DNS_ENUMERATION", "false")
    os.environ.setdefault("ENABLE_SUBFINDER_ENUMERATION", "false")


# ============================================================================
# Mock DNS Responses
# ============================================================================

@pytest.fixture
def mock_dns_resolver():
    """Mock DNS resolver for testing"""
    resolver = Mock(spec=dns.resolver.Resolver)
    resolver.timeout = 5
    resolver.lifetime = 10

    # Mock successful A record response
    def resolve_mock(domain, record_type):
        if record_type == 'A':
            response = Mock()
            response.ttl = 300
            response.__iter__ = Mock(return_value=iter([Mock(address='1.2.3.4')]))
            return response
        elif record_type == 'NS':
            response = Mock()
            response.__iter__ = Mock(return_value=iter([Mock(target='ns1.example.com.')]))
            return response
        else:
            raise dns.resolver.NoAnswer()

    resolver.resolve = Mock(side_effect=resolve_mock)
    return resolver


# ============================================================================
# Sample Test Data
# ============================================================================

@pytest.fixture
def sample_domain():
    """Sample domain for testing"""
    return "example.com"


@pytest.fixture
def sample_subdomains():
    """Sample subdomain list for testing"""
    return [
        "www.example.com",
        "api.example.com",
        "mail.example.com",
        "blog.example.com",
        "dev.example.com"
    ]


@pytest.fixture
def sample_wordlist(tmp_path):
    """Create temporary wordlist file for testing"""
    wordlist_file = tmp_path / "test_subdomains.txt"
    wordlist_content = """# Test wordlist
www
api
mail
blog
dev
test
staging
admin
"""
    wordlist_file.write_text(wordlist_content)
    return wordlist_file


@pytest.fixture
def sample_dns_records():
    """Sample DNS records for testing"""
    return {
        'A': [
            {'value': '1.2.3.4', 'ttl': 300, 'type': 'A'},
            {'value': '5.6.7.8', 'ttl': 300, 'type': 'A'}
        ],
        'NS': [
            {'value': 'ns1.example.com.', 'ttl': 86400, 'type': 'NS'},
            {'value': 'ns2.example.com.', 'ttl': 86400, 'type': 'NS'}
        ],
        'MX': [
            {
                'value': 'mail.example.com.',
                'ttl': 3600,
                'type': 'MX',
                'priority': 10,
                'exchange': 'mail.example.com.'
            }
        ],
        'TXT': [
            {
                'value': 'v=spf1 include:_spf.example.com ~all',
                'ttl': 3600,
                'type': 'TXT',
                'spf_record': True
            }
        ]
    }


# ============================================================================
# Comprehensive Analysis Fixtures
# ============================================================================

@pytest.fixture
def comprehensive_analysis_instance():
    """Create ComprehensiveAnalysisIntegration instance for testing"""
    # Override settings to avoid external calls
    instance = ComprehensiveAnalysisIntegration(cache_ttl=0)
    instance.enable_ct_enumeration = False
    instance.enable_passive_dns = False
    instance.enable_subfinder = False
    return instance


# ============================================================================
# Mock External API Responses
# ============================================================================

@pytest.fixture
def mock_crt_sh_response():
    """Mock Certificate Transparency API response"""
    return [
        {
            'id': '1',
            'common_name': 'www.example.com',
            'name_value': 'www.example.com\napi.example.com\nmail.example.com'
        },
        {
            'id': '2',
            'common_name': 'blog.example.com',
            'name_value': 'blog.example.com\ndev.example.com'
        }
    ]


@pytest.fixture
def mock_hackertarget_response():
    """Mock HackerTarget API response"""
    return """www.example.com,1.2.3.4
api.example.com,1.2.3.5
mail.example.com,1.2.3.6
blog.example.com,1.2.3.7"""


@pytest.fixture
def mock_subfinder_output():
    """Mock subfinder command output"""
    return """www.example.com
api.example.com
mail.example.com
blog.example.com
dev.example.com
staging.example.com
admin.example.com"""


# ============================================================================
# HTTP Response Mocks
# ============================================================================

@pytest.fixture
def mock_http_response():
    """Mock HTTP response object"""
    response = Mock()
    response.status_code = 200
    response.headers = {
        'Server': 'nginx/1.21.0',
        'Content-Type': 'text/html',
        'X-Frame-Options': 'SAMEORIGIN',
        'Strict-Transport-Security': 'max-age=31536000'
    }
    response.text = '<html><head><title>Test</title></head><body>Test Page</body></html>'
    response.url = 'https://example.com'
    response.history = []
    return response


# ============================================================================
# Provider Detection Fixtures
# ============================================================================

@pytest.fixture
def cloudflare_headers():
    """Sample Cloudflare headers"""
    return {
        'Server': 'cloudflare',
        'CF-Ray': '1234567890abc-SJC',
        'CF-Cache-Status': 'HIT'
    }


@pytest.fixture
def aws_cloudfront_headers():
    """Sample AWS CloudFront headers"""
    return {
        'Server': 'CloudFront',
        'X-Amz-Cf-Id': 'abcdef123456',
        'X-Cache': 'Hit from cloudfront'
    }


@pytest.fixture
def fastly_headers():
    """Sample Fastly headers"""
    return {
        'Server': 'Fastly',
        'X-Served-By': 'cache-sjc10043-SJC',
        'X-Cache': 'HIT'
    }


# ============================================================================
# Helper Functions
# ============================================================================

def create_mock_dns_answer(records, ttl=300):
    """Helper to create mock DNS answer"""
    answer = Mock()
    answer.ttl = ttl
    answer.__iter__ = Mock(return_value=iter(records))
    return answer


def create_mock_subprocess_result(stdout='', stderr='', returncode=0):
    """Helper to create mock subprocess result"""
    result = Mock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result
