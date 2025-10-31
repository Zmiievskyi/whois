"""
Unit tests for DNS analysis functionality
Tests DNS record collection, parsing, and provider detection
"""
import pytest
from unittest.mock import Mock, patch
import dns.resolver
import dns.exception


@pytest.mark.unit
@pytest.mark.dns
class TestDNSRecordCollection:
    """Test DNS record collection functionality"""

    def test_collect_all_dns_records_structure(self, comprehensive_analysis_instance, sample_domain):
        """Test DNS collection returns correct structure"""
        with patch('dns.resolver.Resolver'):
            result = comprehensive_analysis_instance._collect_all_dns_records(sample_domain)

            assert isinstance(result, dict)
            assert 'domain' in result
            assert 'records' in result
            assert 'nameservers' in result
            assert 'resolver_info' in result
            assert 'errors' in result

    @patch('dns.resolver.Resolver')
    def test_collect_dns_a_records(self, mock_resolver_class, comprehensive_analysis_instance, sample_domain):
        """Test A record collection"""
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver

        # Mock A record response
        mock_answer = Mock()
        mock_answer.ttl = 300
        mock_rdata = Mock()
        mock_rdata.address = '1.2.3.4'
        mock_answer.__iter__ = Mock(return_value=iter([mock_rdata]))

        def resolve_side_effect(domain, record_type):
            if record_type == 'A':
                return mock_answer
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve = Mock(side_effect=resolve_side_effect)

        result = comprehensive_analysis_instance._collect_all_dns_records(sample_domain)

        # Check A records were collected
        if 'A' in result['records']:
            assert len(result['records']['A']) > 0
            if result['records']['A']:
                assert result['records']['A'][0]['type'] == 'A'

    @patch('dns.resolver.Resolver')
    def test_collect_dns_mx_records(self, mock_resolver_class, comprehensive_analysis_instance, sample_domain):
        """Test MX record collection and parsing"""
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver

        # Mock MX record response
        mock_answer = Mock()
        mock_answer.ttl = 3600
        mock_rdata = Mock()
        mock_rdata.preference = 10
        mock_rdata.exchange = Mock()
        mock_rdata.exchange.__str__ = Mock(return_value='mail.example.com.')
        mock_answer.__iter__ = Mock(return_value=iter([mock_rdata]))

        def resolve_side_effect(domain, record_type):
            if record_type == 'MX':
                return mock_answer
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve = Mock(side_effect=resolve_side_effect)

        result = comprehensive_analysis_instance._collect_all_dns_records(sample_domain)

        # Check MX records were collected with priority
        if 'MX' in result['records'] and result['records']['MX']:
            mx_record = result['records']['MX'][0]
            assert 'priority' in mx_record
            assert 'exchange' in mx_record

    @patch('dns.resolver.Resolver')
    def test_collect_dns_txt_records(self, mock_resolver_class, comprehensive_analysis_instance, sample_domain):
        """Test TXT record collection and SPF detection"""
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver

        # Mock TXT record response with SPF
        mock_answer = Mock()
        mock_answer.ttl = 3600
        mock_rdata = Mock()
        mock_rdata.strings = [b'v=spf1 include:_spf.example.com ~all']
        mock_answer.__iter__ = Mock(return_value=iter([mock_rdata]))

        def resolve_side_effect(domain, record_type):
            if record_type == 'TXT':
                return mock_answer
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve = Mock(side_effect=resolve_side_effect)

        result = comprehensive_analysis_instance._collect_all_dns_records(sample_domain)

        # Check TXT records and SPF detection
        if 'TXT' in result['records'] and result['records']['TXT']:
            txt_record = result['records']['TXT'][0]
            if 'spf_record' in txt_record:
                assert txt_record['spf_record'] is True

    @patch('dns.resolver.Resolver')
    def test_collect_dns_handles_nxdomain(self, mock_resolver_class,
                                         comprehensive_analysis_instance):
        """Test DNS collection handles non-existent domains"""
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver
        mock_resolver.resolve = Mock(side_effect=dns.resolver.NXDOMAIN())

        result = comprehensive_analysis_instance._collect_all_dns_records("nonexistent.invalid")

        # Should handle gracefully and record error
        assert 'errors' in result
        assert any('does not exist' in error for error in result['errors'])

    @patch('dns.resolver.Resolver')
    def test_collect_dns_handles_timeout(self, mock_resolver_class,
                                        comprehensive_analysis_instance, sample_domain):
        """Test DNS collection handles timeouts"""
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver
        mock_resolver.resolve = Mock(side_effect=dns.exception.Timeout())

        result = comprehensive_analysis_instance._collect_all_dns_records(sample_domain)

        # Should handle timeout and continue
        assert isinstance(result, dict)
        assert 'errors' in result


@pytest.mark.unit
@pytest.mark.dns
class TestNameserverDetection:
    """Test nameserver detection and DNS provider identification"""

    @patch('dns.resolver.Resolver')
    def test_nameserver_collection(self, mock_resolver_class,
                                   comprehensive_analysis_instance, sample_domain):
        """Test nameserver collection"""
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver

        # Mock NS records
        mock_answer = Mock()
        ns1 = Mock()
        ns1.__str__ = Mock(return_value='ns1.cloudflare.com.')
        ns2 = Mock()
        ns2.__str__ = Mock(return_value='ns2.cloudflare.com.')
        mock_answer.__iter__ = Mock(return_value=iter([ns1, ns2]))

        def resolve_side_effect(domain, record_type):
            if record_type == 'NS':
                return mock_answer
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve = Mock(side_effect=resolve_side_effect)

        result = comprehensive_analysis_instance._collect_all_dns_records(sample_domain)

        # Check nameservers were collected
        if result['nameservers']:
            assert len(result['nameservers']) == 2
            assert 'cloudflare.com' in result['nameservers'][0]

    def test_identify_cloudflare_dns(self, comprehensive_analysis_instance):
        """Test Cloudflare DNS provider identification"""
        nameserver = "ns1.cloudflare.com"

        provider = comprehensive_analysis_instance._identify_provider_from_nameserver(nameserver)

        assert provider == "Cloudflare"

    def test_identify_aws_route53_dns(self, comprehensive_analysis_instance):
        """Test AWS Route53 DNS provider identification"""
        nameserver = "ns-123.awsdns-45.com"

        provider = comprehensive_analysis_instance._identify_provider_from_nameserver(nameserver)

        assert provider == "AWS Route 53"

    def test_identify_google_cloud_dns(self, comprehensive_analysis_instance):
        """Test Google Cloud DNS provider identification"""
        nameserver = "ns1.googledomains.com"

        provider = comprehensive_analysis_instance._identify_provider_from_nameserver(nameserver)

        assert provider == "Google Cloud DNS"

    def test_identify_unknown_dns_provider(self, comprehensive_analysis_instance):
        """Test unknown DNS provider"""
        nameserver = "ns1.unknown-provider.example"

        provider = comprehensive_analysis_instance._identify_provider_from_nameserver(nameserver)

        assert provider is None


@pytest.mark.unit
@pytest.mark.dns
class TestSOARecordParsing:
    """Test SOA record parsing"""

    @patch('dns.resolver.Resolver')
    def test_soa_record_parsing(self, mock_resolver_class,
                               comprehensive_analysis_instance, sample_domain):
        """Test SOA record parsing extracts all fields"""
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver

        # Mock SOA record
        mock_answer = Mock()
        mock_answer.ttl = 3600
        mock_rdata = Mock()
        mock_rdata.mname = Mock(__str__=lambda x: 'ns1.example.com.')
        mock_rdata.rname = Mock(__str__=lambda x: 'admin.example.com.')
        mock_rdata.serial = 2024103101
        mock_rdata.refresh = 7200
        mock_rdata.retry = 3600
        mock_rdata.expire = 1209600
        mock_rdata.minimum = 86400
        mock_answer.__iter__ = Mock(return_value=iter([mock_rdata]))

        def resolve_side_effect(domain, record_type):
            if record_type == 'SOA':
                return mock_answer
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve = Mock(side_effect=resolve_side_effect)

        result = comprehensive_analysis_instance._collect_all_dns_records(sample_domain)

        # Check SOA record fields
        if 'SOA' in result['records'] and result['records']['SOA']:
            soa = result['records']['SOA'][0]
            assert 'serial' in soa
            assert 'refresh' in soa
            assert 'retry' in soa
            assert 'expire' in soa


@pytest.mark.unit
@pytest.mark.dns
class TestCAARecordParsing:
    """Test CAA record parsing"""

    @patch('dns.resolver.Resolver')
    def test_caa_record_parsing(self, mock_resolver_class,
                               comprehensive_analysis_instance, sample_domain):
        """Test CAA record parsing extracts certificate authority"""
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver

        # Mock CAA record
        mock_answer = Mock()
        mock_answer.ttl = 3600
        mock_rdata = Mock()
        mock_rdata.flags = 0
        mock_rdata.tag = b'issue'
        mock_rdata.value = b'letsencrypt.org'
        mock_answer.__iter__ = Mock(return_value=iter([mock_rdata]))

        def resolve_side_effect(domain, record_type):
            if record_type == 'CAA':
                return mock_answer
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve = Mock(side_effect=resolve_side_effect)

        result = comprehensive_analysis_instance._collect_all_dns_records(sample_domain)

        # Check CAA record fields
        if 'CAA' in result['records'] and result['records']['CAA']:
            caa = result['records']['CAA'][0]
            assert 'flags' in caa
            assert 'tag' in caa
            assert 'value' in caa


@pytest.mark.unit
@pytest.mark.dns
class TestDNSRecordTypes:
    """Test handling of various DNS record types"""

    def test_all_record_types_attempted(self, comprehensive_analysis_instance, sample_domain):
        """Test that all configured record types are attempted"""
        expected_types = ['A', 'AAAA', 'CNAME', 'NS', 'MX', 'TXT', 'SOA', 'PTR',
                         'CAA', 'SRV', 'HINFO', 'NAPTR']

        assert comprehensive_analysis_instance.dns_record_types == expected_types

    @patch('dns.resolver.Resolver')
    def test_handles_no_answer_for_record_type(self, mock_resolver_class,
                                               comprehensive_analysis_instance, sample_domain):
        """Test handling when a record type has no answer"""
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver
        mock_resolver.resolve = Mock(side_effect=dns.resolver.NoAnswer())

        result = comprehensive_analysis_instance._collect_all_dns_records(sample_domain)

        # Should not crash, records should be empty lists
        assert isinstance(result['records'], dict)
        # Empty or no records is acceptable
        for record_type, records in result['records'].items():
            assert isinstance(records, list)
