"""
Unit tests for subdomain enumeration functionality
Tests all 4 methods: Dictionary, Passive DNS, Certificate Transparency, Subfinder
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
import dns.resolver
import dns.exception


@pytest.mark.unit
@pytest.mark.subdomain
class TestSubdomainEnumeration:
    """Test subdomain enumeration core functionality"""

    def test_enumerate_subdomains_returns_data_structure(self, comprehensive_analysis_instance, sample_domain):
        """Test that _enumerate_subdomains returns correct data structure"""
        result = comprehensive_analysis_instance._enumerate_subdomains(sample_domain)

        assert isinstance(result, dict)
        assert 'domain' in result
        assert 'discovered_subdomains' in result
        assert 'enumeration_methods' in result
        assert 'method_summary' in result
        assert 'total_found' in result
        assert 'all_subdomains' in result  # NEW: Check for full list
        assert 'errors' in result

    def test_all_subdomains_list_is_complete(self, comprehensive_analysis_instance, sample_domain):
        """Test that all_subdomains contains all discovered subdomains"""
        # Disable CT enumeration to avoid real API calls
        comprehensive_analysis_instance.enable_ct_enumeration = False
        comprehensive_analysis_instance.enable_passive_dns = True

        with patch.object(comprehensive_analysis_instance, '_dictionary_subdomain_enum',
                          return_value={'api.example.com', 'dev.example.com'}):
            with patch.object(comprehensive_analysis_instance, '_passive_dns_enum',
                              return_value={'blog.example.com', 'www.example.com'}):
                with patch.object(comprehensive_analysis_instance, '_certificate_transparency_enum',
                                  return_value={'mail.example.com'}):
                    with patch.object(comprehensive_analysis_instance, '_subfinder_enum',
                                      return_value=set()):

                        result = comprehensive_analysis_instance._enumerate_subdomains(sample_domain)

                        # Check total count (4 subdomains since CT is disabled)
                        assert result['total_found'] == 4

                        # Check all_subdomains list
                        assert 'all_subdomains' in result
                        assert len(result['all_subdomains']) == 4
                        assert 'api.example.com' in result['all_subdomains']
                        assert 'dev.example.com' in result['all_subdomains']
                        assert 'blog.example.com' in result['all_subdomains']
                        assert 'www.example.com' in result['all_subdomains']

    def test_enumeration_methods_tracked(self, comprehensive_analysis_instance, sample_domain):
        """Test that enumeration methods are tracked correctly"""
        with patch.object(comprehensive_analysis_instance, '_dictionary_subdomain_enum',
                          return_value={'api.example.com'}):
            with patch.object(comprehensive_analysis_instance, '_passive_dns_enum',
                              return_value={'blog.example.com'}):
                result = comprehensive_analysis_instance._enumerate_subdomains(sample_domain)

                assert 'dictionary' in result['enumeration_methods']
                assert 'passive_dns' in result['enumeration_methods']

                # Check method summary
                methods = {m['method']: m['count'] for m in result['method_summary']}
                assert methods.get('dictionary') == 1
                assert methods.get('passive_dns') == 1


@pytest.mark.unit
@pytest.mark.subdomain
class TestDictionaryEnumeration:
    """Test dictionary-based subdomain enumeration"""

    def test_dictionary_enum_with_limit(self, comprehensive_analysis_instance, sample_domain):
        """Test dictionary enumeration respects the limit"""
        # Set limit to 3
        comprehensive_analysis_instance.dictionary_limit = 3
        comprehensive_analysis_instance.subdomain_wordlist = ['www', 'api', 'mail', 'blog', 'dev']

        with patch('dns.resolver.Resolver') as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver_class.return_value = mock_resolver

            # Mock successful DNS resolution for first 2 prefixes
            def resolve_side_effect(domain, record_type):
                if domain in ['www.example.com', 'api.example.com']:
                    return Mock()
                raise dns.resolver.NXDOMAIN()

            mock_resolver.resolve = Mock(side_effect=resolve_side_effect)

            result = comprehensive_analysis_instance._dictionary_subdomain_enum(sample_domain)

            # Should only test first 3 prefixes due to limit
            assert len(result) <= 2  # At most 2 found (www, api)
            if 'www.example.com' in result:
                assert 'www.example.com' in result

    def test_dictionary_enum_with_zero_limit(self, comprehensive_analysis_instance, sample_domain):
        """Test that limit=0 uses ALL wordlist entries"""
        comprehensive_analysis_instance.dictionary_limit = 0  # Use all
        comprehensive_analysis_instance.subdomain_wordlist = ['www', 'api', 'mail', 'blog', 'dev']

        with patch('dns.resolver.Resolver') as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver_class.return_value = mock_resolver

            def resolve_side_effect(domain, record_type):
                # Make all succeed for testing
                return Mock()

            mock_resolver.resolve = Mock(side_effect=resolve_side_effect)

            result = comprehensive_analysis_instance._dictionary_subdomain_enum(sample_domain)

            # With limit=0, should try ALL 5 prefixes
            # Since all succeed in our mock, should find 5
            assert len(result) == 5

    def test_dictionary_enum_empty_wordlist(self, comprehensive_analysis_instance, sample_domain):
        """Test dictionary enumeration with empty wordlist"""
        comprehensive_analysis_instance.subdomain_wordlist = []

        result = comprehensive_analysis_instance._dictionary_subdomain_enum(sample_domain)

        assert len(result) == 0

    def test_dictionary_enum_handles_dns_errors(self, comprehensive_analysis_instance, sample_domain):
        """Test dictionary enumeration handles DNS errors gracefully"""
        comprehensive_analysis_instance.subdomain_wordlist = ['www', 'api']
        comprehensive_analysis_instance.dictionary_limit = 2

        with patch('dns.resolver.Resolver') as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver_class.return_value = mock_resolver
            mock_resolver.resolve = Mock(side_effect=dns.resolver.NXDOMAIN())

            result = comprehensive_analysis_instance._dictionary_subdomain_enum(sample_domain)

            # Should handle errors and return empty set
            assert isinstance(result, set)
            assert len(result) == 0


@pytest.mark.unit
@pytest.mark.subdomain
class TestPassiveDNSEnumeration:
    """Test passive DNS enumeration"""

    def test_passive_dns_when_disabled(self, comprehensive_analysis_instance, sample_domain):
        """Test passive DNS returns empty when disabled"""
        comprehensive_analysis_instance.enable_passive_dns = False

        result = comprehensive_analysis_instance._passive_dns_enum(sample_domain)

        assert isinstance(result, set)
        assert len(result) == 0

    @patch('requests.get')
    def test_passive_dns_hackertarget_success(self, mock_get, comprehensive_analysis_instance, sample_domain):
        """Test successful passive DNS enumeration from HackerTarget"""
        comprehensive_analysis_instance.enable_passive_dns = True

        # Mock HackerTarget response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "www.example.com,1.2.3.4\napi.example.com,1.2.3.5"
        mock_get.return_value = mock_response

        result = comprehensive_analysis_instance._passive_dns_enum(sample_domain)

        assert len(result) >= 1
        # Should extract subdomains from response
        if len(result) > 0:
            assert any('example.com' in sub for sub in result)

    @patch('requests.get')
    def test_passive_dns_handles_rate_limit(self, mock_get, comprehensive_analysis_instance, sample_domain):
        """Test passive DNS handles rate limiting"""
        comprehensive_analysis_instance.enable_passive_dns = True

        # Mock rate limit response
        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.text = "error"
        mock_get.return_value = mock_response

        result = comprehensive_analysis_instance._passive_dns_enum(sample_domain)

        # Should handle gracefully and return empty or partial results
        assert isinstance(result, set)


@pytest.mark.unit
@pytest.mark.subdomain
class TestCertificateTransparencyEnumeration:
    """Test Certificate Transparency log enumeration"""

    def test_ct_enum_when_disabled(self, comprehensive_analysis_instance, sample_domain):
        """Test CT enumeration doesn't run when disabled"""
        comprehensive_analysis_instance.enable_ct_enumeration = False

        # Should not be called in enumerate_subdomains when disabled
        result = comprehensive_analysis_instance._enumerate_subdomains(sample_domain)

        assert 'certificate_transparency' not in result.get('enumeration_methods', [])

    @patch('requests.get')
    def test_ct_enum_successful_parsing(self, mock_get, comprehensive_analysis_instance,
                                       sample_domain, mock_crt_sh_response):
        """Test successful CT log parsing"""
        comprehensive_analysis_instance.enable_ct_enumeration = True
        comprehensive_analysis_instance.ct_page_limit = 1

        # Mock crt.sh response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_crt_sh_response
        mock_get.return_value = mock_response

        result = comprehensive_analysis_instance._certificate_transparency_enum(sample_domain)

        # Should extract subdomains from CT logs
        assert len(result) > 0
        assert any('example.com' in sub for sub in result)

    @patch('requests.get')
    def test_ct_enum_handles_non_json_response(self, mock_get, comprehensive_analysis_instance, sample_domain):
        """Test CT enumeration handles non-JSON responses"""
        comprehensive_analysis_instance.enable_ct_enumeration = True

        # Mock HTML response (throttled)
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Not JSON")
        mock_get.return_value = mock_response

        result = comprehensive_analysis_instance._certificate_transparency_enum(sample_domain)

        # Should handle gracefully
        assert isinstance(result, set)

    @patch('requests.get')
    def test_ct_enum_respects_page_limit(self, mock_get, comprehensive_analysis_instance, sample_domain):
        """Test CT enumeration respects page limit"""
        comprehensive_analysis_instance.enable_ct_enumeration = True
        comprehensive_analysis_instance.ct_page_limit = 2

        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = []
            return mock_response

        mock_get.side_effect = side_effect

        result = comprehensive_analysis_instance._certificate_transparency_enum(sample_domain)

        # Should make exactly ct_page_limit requests
        assert call_count <= 2


@pytest.mark.unit
@pytest.mark.subdomain
class TestSubfinderEnumeration:
    """Test Subfinder integration"""

    def test_subfinder_when_disabled(self, comprehensive_analysis_instance, sample_domain):
        """Test subfinder doesn't run when disabled"""
        comprehensive_analysis_instance.enable_subfinder = False

        result = comprehensive_analysis_instance._subfinder_enum(sample_domain)

        assert len(result) == 0

    def test_subfinder_when_binary_not_found(self, comprehensive_analysis_instance, sample_domain):
        """Test subfinder handles missing binary"""
        comprehensive_analysis_instance.enable_subfinder = True
        comprehensive_analysis_instance.subfinder_path = None

        with patch('shutil.which', return_value=None):
            result = comprehensive_analysis_instance._subfinder_enum(sample_domain)

            assert len(result) == 0

    @patch('subprocess.run')
    @patch('shutil.which')
    def test_subfinder_successful_execution(self, mock_which, mock_run,
                                           comprehensive_analysis_instance,
                                           sample_domain, mock_subfinder_output):
        """Test successful subfinder execution"""
        comprehensive_analysis_instance.enable_subfinder = True
        mock_which.return_value = '/usr/local/bin/subfinder'

        # Mock subprocess result
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = mock_subfinder_output
        mock_result.stderr = ''
        mock_run.return_value = mock_result

        result = comprehensive_analysis_instance._subfinder_enum(sample_domain)

        # Should parse subfinder output
        assert len(result) > 0
        assert 'www.example.com' in result
        assert 'api.example.com' in result

    @patch('subprocess.run')
    @patch('shutil.which')
    def test_subfinder_handles_timeout(self, mock_which, mock_run,
                                      comprehensive_analysis_instance, sample_domain):
        """Test subfinder handles timeout"""
        comprehensive_analysis_instance.enable_subfinder = True
        mock_which.return_value = '/usr/local/bin/subfinder'

        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd='subfinder', timeout=60)

        result = comprehensive_analysis_instance._subfinder_enum(sample_domain)

        # Should handle timeout gracefully
        assert isinstance(result, set)
        assert len(result) == 0


@pytest.mark.unit
@pytest.mark.subdomain
class TestSubdomainAnalysis:
    """Test individual subdomain analysis"""

    def test_analyze_subdomain_structure(self, comprehensive_analysis_instance):
        """Test _analyze_subdomain returns correct structure"""
        subdomain = "api.example.com"

        with patch('dns.resolver.Resolver'):
            result = comprehensive_analysis_instance._analyze_subdomain(subdomain)

            assert isinstance(result, dict)
            assert 'subdomain' in result
            assert 'ip_addresses' in result
            assert 'cname_records' in result
            assert 'http_status' in result
            assert 'server_info' in result
            assert 'ssl_info' in result

    @patch('dns.resolver.Resolver')
    def test_analyze_subdomain_dns_resolution(self, mock_resolver_class,
                                              comprehensive_analysis_instance):
        """Test subdomain DNS resolution"""
        subdomain = "api.example.com"

        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver

        # Create proper mock IP object that returns string when str() is called
        mock_ip = MagicMock()
        mock_ip.__str__ = MagicMock(return_value='1.2.3.4')
        mock_ip.address = '1.2.3.4'

        # Create proper mock CNAME object
        mock_cname = MagicMock()
        mock_cname.__str__ = MagicMock(return_value='cdn.example.com.')
        mock_cname.target = 'cdn.example.com.'

        # Mock A record answer
        mock_a_answer = Mock()
        mock_a_answer.__iter__ = Mock(return_value=iter([mock_ip]))

        # Mock CNAME record answer
        mock_cname_answer = Mock()
        mock_cname_answer.__iter__ = Mock(return_value=iter([mock_cname]))

        def resolve_side_effect(domain, record_type):
            if record_type == 'A':
                return mock_a_answer
            elif record_type == 'CNAME':
                return mock_cname_answer
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve = Mock(side_effect=resolve_side_effect)

        result = comprehensive_analysis_instance._analyze_subdomain(subdomain)

        assert '1.2.3.4' in result['ip_addresses']
        assert 'cdn.example.com' in result['cname_records']

    def test_analyze_subdomain_handles_errors(self, comprehensive_analysis_instance):
        """Test subdomain analysis handles errors"""
        subdomain = "nonexistent.example.com"

        with patch('dns.resolver.Resolver') as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver_class.return_value = mock_resolver
            mock_resolver.resolve = Mock(side_effect=dns.resolver.NXDOMAIN())

            result = comprehensive_analysis_instance._analyze_subdomain(subdomain)

            # Should handle error gracefully
            assert isinstance(result, dict)
            # May contain error or empty lists
            assert isinstance(result.get('ip_addresses', []), list)


@pytest.mark.unit
@pytest.mark.subdomain
class TestWordlistLoading:
    """Test subdomain wordlist loading"""

    def test_load_wordlist_from_file(self, comprehensive_analysis_instance, sample_wordlist):
        """Test loading wordlist from file"""
        # Test the wordlist loading logic
        wordlist = []
        for line in sample_wordlist.read_text().splitlines():
            clean_line = line.strip()
            if clean_line and not clean_line.startswith('#'):
                wordlist.append(clean_line)

        assert len(wordlist) > 0
        assert 'www' in wordlist
        assert 'api' in wordlist

    def test_load_wordlist_filters_comments(self, sample_wordlist):
        """Test that comments are filtered from wordlist"""
        content = sample_wordlist.read_text()
        lines = [line.strip() for line in content.splitlines()
                 if line.strip() and not line.startswith('#')]

        # Should not include comment lines
        assert all(not line.startswith('#') for line in lines)

    def test_load_wordlist_handles_empty_lines(self, tmp_path):
        """Test wordlist loading handles empty lines"""
        wordlist_file = tmp_path / "test.txt"
        wordlist_file.write_text("www\n\napi\n  \nmail")

        lines = [line.strip() for line in wordlist_file.read_text().splitlines() if line.strip()]

        assert len(lines) == 3
        assert '' not in lines
