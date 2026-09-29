"""Unit tests for DNS resolver and precedence mapping."""

from unittest.mock import MagicMock

import dns.exception
import dns.resolver

from asm.models import DNSStatus
from asm.resolver import resolve_subdomain, resolve_subdomains_concurrently


def _make_mock_answer(ip_list: list[str]) -> MagicMock:
    """Helper to create a mock dns.resolver.Answer object."""
    mock_answer = MagicMock()
    mock_rdatas = []
    for ip in ip_list:
        rdata = MagicMock()
        rdata.to_text.return_value = ip
        mock_rdatas.append(rdata)
    mock_answer.__iter__.return_value = mock_rdatas
    return mock_answer


class TestSubdomainResolution:
    """Test resolution logic and precedence rules for A and AAAA queries."""

    def test_precedence_resolved_when_either_has_ip(self):
        """Rule 1: Any IP found -> RESOLVED even if other query errors or times out."""
        mock_resolver = MagicMock(spec=dns.resolver.Resolver)

        # A query returns 1.2.3.4, AAAA returns NXDOMAIN
        def mock_resolve(qname, rdtype):
            if rdtype == "A":
                return _make_mock_answer(["1.2.3.4"])
            raise dns.resolver.NXDOMAIN()

        mock_resolver.resolve.side_effect = mock_resolve

        res = resolve_subdomain("api.example.com", resolver=mock_resolver)
        assert res.status == DNSStatus.RESOLVED.value
        assert res.resolved is True
        assert res.ip_addresses == ["1.2.3.4"]

    def test_precedence_resolved_with_both_a_and_aaaa(self):
        """Rule 1: Both A and AAAA return IPs, combined and sorted."""
        mock_resolver = MagicMock(spec=dns.resolver.Resolver)

        def mock_resolve(qname, rdtype):
            if rdtype == "A":
                return _make_mock_answer(["10.0.0.1", "10.0.0.2"])
            return _make_mock_answer(["2001:db8::1"])

        mock_resolver.resolve.side_effect = mock_resolve

        res = resolve_subdomain("web.example.com", resolver=mock_resolver)
        assert res.status == DNSStatus.RESOLVED.value
        assert res.resolved is True
        assert res.ip_addresses == ["10.0.0.1", "10.0.0.2", "2001:db8::1"]

    def test_precedence_nxdomain_over_timeout_and_error(self):
        """Rule 2: If no IP found and either returned NXDOMAIN -> NXDOMAIN."""
        mock_resolver = MagicMock(spec=dns.resolver.Resolver)

        def mock_resolve(qname, rdtype):
            if rdtype == "A":
                raise dns.resolver.NXDOMAIN()
            raise dns.exception.Timeout()

        mock_resolver.resolve.side_effect = mock_resolve

        res = resolve_subdomain("missing.example.com", resolver=mock_resolver)
        assert res.status == DNSStatus.NXDOMAIN.value
        assert res.resolved is False
        assert res.ip_addresses == []

    def test_precedence_timeout_over_error_and_noanswer(self):
        """Rule 3: If no IP and no NXDOMAIN, but either timed out -> TIMEOUT."""
        mock_resolver = MagicMock(spec=dns.resolver.Resolver)

        def mock_resolve(qname, rdtype):
            if rdtype == "A":
                raise dns.exception.Timeout()
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve.side_effect = mock_resolve

        res = resolve_subdomain("slow.example.com", resolver=mock_resolver)
        assert res.status == DNSStatus.TIMEOUT.value
        assert res.resolved is False
        assert res.ip_addresses == []

    def test_precedence_error_mapping(self):
        """Rule 4: If no IP, no NXDOMAIN, no TIMEOUT, but error occurred -> ERROR."""
        mock_resolver = MagicMock(spec=dns.resolver.Resolver)

        # NoNameservers must map to ERROR per specification
        def mock_resolve(qname, rdtype):
            if rdtype == "A":
                raise dns.resolver.NoNameservers()
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve.side_effect = mock_resolve

        res = resolve_subdomain("broken.example.com", resolver=mock_resolver)
        assert res.status == DNSStatus.ERROR.value
        assert res.resolved is False
        assert res.ip_addresses == []

    def test_precedence_no_answer(self):
        """Rule 5: Else -> NO_ANSWER when both queries return NoAnswer."""
        mock_resolver = MagicMock(spec=dns.resolver.Resolver)

        def mock_resolve(qname, rdtype):
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve.side_effect = mock_resolve

        res = resolve_subdomain("txtonly.example.com", resolver=mock_resolver)
        assert res.status == DNSStatus.NO_ANSWER.value
        assert res.resolved is False
        assert res.ip_addresses == []


class TestConcurrentResolution:
    """Test suite for resolve_subdomains_concurrently."""

    def test_concurrent_resolution_returns_sorted(self):
        """Verify concurrent lookups return results sorted alphabetically."""
        mock_resolver = MagicMock(spec=dns.resolver.Resolver)

        def mock_resolve(qname, rdtype):
            if "zebra" in qname and rdtype == "A":
                return _make_mock_answer(["1.1.1.1"])
            if "alpha" in qname and rdtype == "A":
                return _make_mock_answer(["2.2.2.2"])
            raise dns.resolver.NXDOMAIN()

        mock_resolver.resolve.side_effect = mock_resolve

        subdomains = ["zebra.example.com", "beta.example.com", "alpha.example.com"]
        results = resolve_subdomains_concurrently(subdomains, resolver=mock_resolver)

        assert len(results) == 3
        assert [r.subdomain for r in results] == [
            "alpha.example.com",
            "beta.example.com",
            "zebra.example.com",
        ]
        assert results[0].status == DNSStatus.RESOLVED.value
        assert results[1].status == DNSStatus.NXDOMAIN.value
        assert results[2].status == DNSStatus.RESOLVED.value

    def test_empty_subdomains_returns_empty_list(self):
        """Verify empty list of subdomains returns an empty list immediately."""
        assert resolve_subdomains_concurrently([]) == []
