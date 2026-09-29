"""Unit tests for domain validation and normalization."""

import pytest

from asm.validators import DomainValidationError, normalize_domain, validate_domain


class TestNormalization:
    """Test cases for normalize_domain."""

    def test_normalize_with_scheme_port_path(self):
        """Verify URL with scheme, port, and path normalizes correctly."""
        raw = "http://EXAMPLE.COM:8080/path"
        assert normalize_domain(raw) == "example.com"

    def test_normalize_with_https_query_fragment(self):
        """Verify HTTPS URL with query string and fragment normalizes correctly."""
        raw = "https://sub.Example.Com:443/api/v1?token=xyz#overview"
        assert normalize_domain(raw) == "sub.example.com"

    def test_normalize_strips_trailing_dot(self):
        """Verify trailing DNS root dot is removed."""
        assert normalize_domain("example.com.") == "example.com"
        assert normalize_domain("api.example.com.") == "api.example.com"

    def test_normalize_whitespace(self):
        """Verify surrounding whitespace is stripped and characters lowercased."""
        assert normalize_domain("   MyDomain.Org   ") == "mydomain.org"

    def test_normalize_empty_raises_error(self):
        """Verify empty strings raise DomainValidationError."""
        with pytest.raises(DomainValidationError, match="cannot be empty"):
            normalize_domain("")

        with pytest.raises(DomainValidationError, match="cannot be empty"):
            normalize_domain("   ")


class TestValidation:
    """Test cases for validate_domain."""

    @pytest.mark.parametrize(
        "valid_input, expected",
        [
            ("example.com", "example.com"),
            ("sub.example.com", "sub.example.com"),
            ("deep.sub.level.example.co.uk", "deep.sub.level.example.co.uk"),
            ("my-app-01.corp.internal.net", "my-app-01.corp.internal.net"),
            ("http://EXAMPLE.COM:8080/path", "example.com"),
            ("https://admin.portal.org/login", "admin.portal.org"),
        ],
    )
    def test_valid_domains(self, valid_input: str, expected: str):
        """Verify valid domains and URLs pass validation and normalize."""
        assert validate_domain(valid_input) == expected

    @pytest.mark.parametrize(
        "ip_input",
        [
            "127.0.0.1",
            "192.168.1.1",
            "8.8.8.8",
            "10.0.0.1",
            "::1",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "fe80::1",
        ],
    )
    def test_rejects_ip_addresses(self, ip_input: str):
        """Verify IPv4 and IPv6 addresses are rejected."""
        with pytest.raises(DomainValidationError, match="is an IP address"):
            validate_domain(ip_input)

    def test_rejects_single_label_domain(self):
        """Verify single label names without a TLD are rejected."""
        with pytest.raises(DomainValidationError, match="not a fully qualified domain"):
            validate_domain("localhost")

        with pytest.raises(DomainValidationError, match="not a fully qualified domain"):
            validate_domain("internalhost")

    def test_rejects_domain_exceeding_max_length(self):
        """Verify domains longer than 253 characters are rejected."""
        long_domain = (
            "a" * 60 + "." + "b" * 60 + "." + "c" * 60 + "." + "d" * 60 + "." + "e" * 20 + ".com"
        )
        assert len(long_domain) > 253
        with pytest.raises(DomainValidationError, match="exceeds the maximum allowed length"):
            validate_domain(long_domain)

    def test_rejects_label_exceeding_63_chars(self):
        """Verify labels longer than 63 characters are rejected."""
        long_label = "a" * 64 + ".example.com"
        with pytest.raises(DomainValidationError, match="exceeding the 63 character limit"):
            validate_domain(long_label)

    def test_rejects_empty_label_consecutive_dots(self):
        """Verify consecutive dots causing empty labels are rejected."""
        with pytest.raises(DomainValidationError, match="empty label"):
            validate_domain("example..com")

    @pytest.mark.parametrize(
        "invalid_label",
        [
            "-example.com",
            "example-.com",
            "sub.-test.com",
            "sub.test-.com",
        ],
    )
    def test_rejects_hyphens_at_boundaries(self, invalid_label: str):
        """Verify labels starting or ending with a hyphen are rejected."""
        with pytest.raises(DomainValidationError, match="cannot start or end with a hyphen"):
            validate_domain(invalid_label)

    @pytest.mark.parametrize(
        "invalid_chars",
        [
            "exam_ple.com",
            "exam!ple.com",
            "exam$ple.com",
            "exam ple.com",
        ],
    )
    def test_rejects_invalid_characters(self, invalid_chars: str):
        """Verify non-alphanumeric, non-hyphen characters are rejected."""
        with pytest.raises(DomainValidationError, match="invalid characters"):
            validate_domain(invalid_chars)

    def test_rejects_purely_numeric_tld(self):
        """Verify TLDs composed entirely of numbers are rejected."""
        with pytest.raises(DomainValidationError, match="cannot be purely numeric"):
            validate_domain("example.123")
