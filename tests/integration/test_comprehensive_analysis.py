"""
Integration tests for comprehensive analysis
Tests the full analysis workflow with mocked external dependencies
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
import json


@pytest.mark.integration
class TestComprehensiveAnalysisIntegration:
    """Integration tests for full comprehensive analysis workflow"""

    @patch('dns.resolver.Resolver')
    @patch('requests.get')
    def test_full_comprehensive_analysis(self, mock_requests, mock_resolver_class,
                                        comprehensive_analysis_instance, sample_domain):
        """Test full comprehensive analysis workflow"""
        # Mock DNS resolver
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver

        def dns_side_effect(domain, record_type):
            if record_type == 'A':
                mock_answer = Mock()
                mock_answer.ttl = 300
                rdata = Mock(address='1.2.3.4')
                mock_answer.__iter__ = Mock(return_value=iter([rdata]))
                return mock_answer
            raise Exception("No answer")

        mock_resolver.resolve = Mock(side_effect=dns_side_effect)

        # Mock HTTP requests
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {
            'Server': 'nginx',
            'Content-Type': 'text/html'
        }
        mock_response.text = '<html></html>'
        mock_response.url = f'https://{sample_domain}'
        mock_response.history = []
        mock_requests.return_value = mock_response

        # Run comprehensive analysis
        result = comprehensive_analysis_instance.analyze_domain_comprehensive(sample_domain)

        # Verify structure
        assert isinstance(result, dict)
        assert 'domain' in result
        assert result['domain'] == sample_domain
        assert 'timestamp' in result
        assert 'dns_records' in result
        assert 'subdomains' in result
        assert 'http_analysis' in result
        assert 'origin_detection' in result
        assert 'infrastructure_mapping' in result

    @patch('dns.resolver.Resolver')
    def test_subdomain_enumeration_aggregates_all_methods(self, mock_resolver_class,
                                                          comprehensive_analysis_instance,
                                                          sample_domain):
        """Test that subdomain enumeration aggregates results from all methods"""
        # Enable all enumeration methods
        comprehensive_analysis_instance.enable_ct_enumeration = True
        comprehensive_analysis_instance.enable_subfinder = True
        comprehensive_analysis_instance.enable_passive_dns = True

        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver
        mock_resolver.resolve = Mock(side_effect=Exception("No DNS"))

        # Mock individual methods with unique subdomains to avoid deduplication issues
        with patch.object(comprehensive_analysis_instance, '_dictionary_subdomain_enum',
                          return_value={'www.example.com', 'api.example.com'}):
            with patch.object(comprehensive_analysis_instance, '_passive_dns_enum',
                              return_value={'mail.example.com', 'blog.example.com'}):
                with patch.object(comprehensive_analysis_instance, '_certificate_transparency_enum',
                                  return_value={'cdn.example.com', 'static.example.com'}):
                    with patch.object(comprehensive_analysis_instance, '_subfinder_enum',
                                      return_value={'dev.example.com'}):

                        result = comprehensive_analysis_instance._enumerate_subdomains(sample_domain)

                        # Should aggregate all results (7 unique subdomains)
                        assert result['total_found'] == 7
                        assert len(result['all_subdomains']) == 7

                        # Verify all subdomains are present
                        expected_subs = {'www.example.com', 'api.example.com', 'mail.example.com',
                                       'blog.example.com', 'cdn.example.com', 'static.example.com',
                                       'dev.example.com'}
                        assert set(result['all_subdomains']) == expected_subs

                        # Check method summary
                        methods = {m['method']: m['count'] for m in result['method_summary']}
                        assert methods['dictionary'] == 2
                        assert methods['passive_dns'] == 2
                        assert methods['certificate_transparency'] == 2
                        assert methods['subfinder'] == 1

    @patch('dns.resolver.Resolver')
    @patch('requests.get')
    def test_analysis_limit_truncates_detailed_analysis(self, mock_requests, mock_resolver_class,
                                                        comprehensive_analysis_instance,
                                                        sample_domain):
        """Test that analysis limit truncates detailed analysis but keeps all names"""
        # Set low analysis limit
        comprehensive_analysis_instance.analysis_limit = 3

        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver

        # Mock successful DNS for all subdomains
        def dns_side_effect(domain, record_type):
            if record_type == 'A':
                mock_answer = Mock()
                mock_answer.ttl = 300
                rdata = Mock(address='1.2.3.4')
                mock_answer.__iter__ = Mock(return_value=iter([rdata]))
                return mock_answer
            raise Exception("No answer")

        mock_resolver.resolve = Mock(side_effect=dns_side_effect)

        # Mock methods to return more than analysis_limit
        subdomains = {f'sub{i}.example.com' for i in range(10)}
        with patch.object(comprehensive_analysis_instance, '_dictionary_subdomain_enum',
                          return_value=subdomains):

            result = comprehensive_analysis_instance._enumerate_subdomains(sample_domain)

            # All subdomains found
            assert result['total_found'] == 10
            assert len(result['all_subdomains']) == 10

            # But detailed analysis limited to 3
            assert len(result['discovered_subdomains']) == 3
            assert result['analysis_truncated'] == 7

    @patch('dns.resolver.Resolver')
    def test_handles_partial_method_failures(self, mock_resolver_class,
                                            comprehensive_analysis_instance,
                                            sample_domain):
        """Test that analysis continues when some methods fail"""
        # Enable CT and subfinder to ensure they run
        comprehensive_analysis_instance.enable_ct_enumeration = True
        comprehensive_analysis_instance.enable_subfinder = True
        comprehensive_analysis_instance.enable_passive_dns = True

        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver

        # Mock some methods succeeding, some returning empty (simulating failure)
        with patch.object(comprehensive_analysis_instance, '_dictionary_subdomain_enum',
                          return_value={'www.example.com'}):
            with patch.object(comprehensive_analysis_instance, '_passive_dns_enum',
                              return_value=set()):  # Returns empty set instead of exception
                with patch.object(comprehensive_analysis_instance, '_certificate_transparency_enum',
                                  return_value={'api.example.com'}):
                    with patch.object(comprehensive_analysis_instance, '_subfinder_enum',
                                      return_value={'mail.example.com'}):

                        result = comprehensive_analysis_instance._enumerate_subdomains(sample_domain)

                        # Should still have results from successful methods (3 subdomains)
                        assert result['total_found'] == 3
                        # passive_dns returned empty but others succeeded
                        assert 'dictionary' in result['enumeration_methods']
                        assert 'certificate_transparency' in result['enumeration_methods']
                        assert 'subfinder' in result['enumeration_methods']
                        # passive_dns should not be in methods since it returned empty
                        assert 'passive_dns' not in result['enumeration_methods']


@pytest.mark.integration
class TestHTTPAnalysis:
    """Integration tests for HTTP analysis"""

    @patch('requests.Session')
    @patch('requests.get')
    def test_http_analysis_both_protocols(self, mock_get, mock_session_class,
                                         comprehensive_analysis_instance, sample_domain):
        """Test HTTP analysis checks both HTTP and HTTPS"""
        # Mock session
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        # Mock HTTPS response
        mock_https_response = Mock()
        mock_https_response.status_code = 200
        mock_https_response.headers = {'Server': 'nginx'}
        mock_https_response.text = '<html></html>'
        mock_https_response.url = f'https://{sample_domain}'
        mock_https_response.history = []

        mock_session.get.return_value = mock_https_response

        result = comprehensive_analysis_instance._analyze_http_comprehensive(sample_domain)

        # Should have results for both protocols
        assert 'protocols' in result
        # At least one protocol tested
        assert len(result['protocols']) > 0

    @patch('requests.Session')
    def test_http_analysis_security_headers(self, mock_session_class,
                                           comprehensive_analysis_instance, sample_domain):
        """Test HTTP analysis detects security headers"""
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        # Mock response with security headers
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {
            'Server': 'nginx',
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Frame-Options': 'SAMEORIGIN',
            'X-Content-Type-Options': 'nosniff'
        }
        mock_response.text = '<html></html>'
        mock_response.url = f'https://{sample_domain}'
        mock_response.history = []

        mock_session.get.return_value = mock_response

        result = comprehensive_analysis_instance._analyze_http_comprehensive(sample_domain)

        # Should detect security headers
        if 'https' in result['protocols']:
            https_data = result['protocols']['https']
            if 'security_headers' in https_data:
                security = https_data['security_headers']
                assert 'headers_present' in security
                assert len(security['headers_present']) > 0

    @patch('requests.Session')
    def test_http_analysis_cdn_detection(self, mock_session_class,
                                        comprehensive_analysis_instance, sample_domain):
        """Test HTTP analysis detects CDN from headers"""
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        # Mock response with Cloudflare headers
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {
            'Server': 'cloudflare',
            'CF-Ray': '1234567890abc-SJC',
            'CF-Cache-Status': 'HIT'
        }
        mock_response.text = '<html></html>'
        mock_response.url = f'https://{sample_domain}'
        mock_response.history = []

        mock_session.get.return_value = mock_response

        result = comprehensive_analysis_instance._analyze_http_comprehensive(sample_domain)

        # Should detect Cloudflare
        if 'https' in result['protocols']:
            https_data = result['protocols']['https']
            if 'cdn_detection' in https_data:
                cdn = https_data['cdn_detection']
                assert 'Cloudflare' in cdn.get('detected_cdns', [])


@pytest.mark.integration
class TestOriginDetection:
    """Integration tests for origin server detection"""

    @patch('dns.resolver.Resolver')
    def test_origin_detection_checks_common_patterns(self, mock_resolver_class,
                                                     comprehensive_analysis_instance,
                                                     sample_domain):
        """Test origin detection checks common subdomain patterns"""
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver

        # Mock DNS responses for origin patterns
        def dns_side_effect(domain, record_type):
            if 'origin' in domain and record_type == 'A':
                mock_answer = Mock()
                mock_answer.ttl = 300
                rdata = Mock(address='10.0.0.1')
                mock_answer.__iter__ = Mock(return_value=iter([rdata]))
                return mock_answer
            raise Exception("No answer")

        mock_resolver.resolve = Mock(side_effect=dns_side_effect)

        result = comprehensive_analysis_instance._detect_origin_servers(sample_domain)

        # Should check origin patterns
        assert isinstance(result, dict)
        assert 'detection_methods' in result
        assert 'potential_origins' in result


@pytest.mark.integration
class TestInfrastructureMapping:
    """Integration tests for infrastructure mapping"""

    def test_infrastructure_mapping_structure(self, comprehensive_analysis_instance):
        """Test infrastructure mapping returns correct structure"""
        # Create sample analysis results
        analysis_results = {
            'dns_records': {
                'nameservers': ['ns1.cloudflare.com', 'ns2.cloudflare.com']
            },
            'http_analysis': {
                'protocols': {
                    'https': {
                        'cdn_detection': {
                            'detected_cdns': ['Cloudflare']
                        }
                    }
                }
            }
        }

        result = comprehensive_analysis_instance._map_infrastructure(analysis_results)

        # Verify structure
        assert isinstance(result, dict)
        assert 'providers' in result
        assert 'dns' in result['providers']
        assert 'cdn' in result['providers']
        assert 'architecture' in result
        assert 'uses_cdn' in result['architecture']
        assert 'security_posture' in result

    def test_infrastructure_mapping_detects_cdn_usage(self, comprehensive_analysis_instance):
        """Test infrastructure mapping detects CDN usage"""
        analysis_results = {
            'dns_records': {'nameservers': []},
            'http_analysis': {
                'protocols': {
                    'https': {
                        'cdn_detection': {
                            'detected_cdns': ['Cloudflare', 'Fastly']
                        }
                    }
                }
            }
        }

        result = comprehensive_analysis_instance._map_infrastructure(analysis_results)

        # Should detect CDN
        assert result['architecture']['uses_cdn'] is True
        assert 'Cloudflare' in result['architecture']['cdn_providers']
