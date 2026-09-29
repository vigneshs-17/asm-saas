"""Unit tests for shared scanning utilities in asm.scan_common."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from asm.scan_common import (
    ReportValidationError,
    check_host_for_ssrf,
    load_and_validate_report,
    validate_host_and_scope,
)


class TestReportLoading:
    """Test suite for load_and_validate_report."""

    def test_load_valid_report(self, tmp_path: Path):
        """Verify successful parsing and resolved host extraction."""
        report_file = tmp_path / "valid_report.json"
        report_file.write_text(
            json.dumps({
                "domain": "example.com",
                "results": [
                    {"subdomain": "api.example.com", "status": "RESOLVED", "resolved": True},
                    {"subdomain": "dev.example.com", "status": "NXDOMAIN", "resolved": False},
                ],
            }),
            encoding="utf-8",
        )

        data, domain, resolved, skipped = load_and_validate_report(str(report_file))
        assert domain == "example.com"
        assert resolved == ["api.example.com"]
        assert skipped == 1
        assert isinstance(data, dict)

    def test_missing_report_file_raises_error(self):
        """Verify non-existent report file raises ReportValidationError."""
        with pytest.raises(ReportValidationError, match="not found"):
            load_and_validate_report("missing_report_123.json")

    def test_malformed_json_raises_error(self, tmp_path: Path):
        """Verify non-JSON file raises ReportValidationError."""
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{broken-json", encoding="utf-8")

        with pytest.raises(ReportValidationError, match="Failed to parse"):
            load_and_validate_report(str(bad_file))

    def test_missing_domain_field_raises_error(self, tmp_path: Path):
        """Verify report lacking 'domain' field raises ReportValidationError."""
        bad_file = tmp_path / "nodomain.json"
        bad_file.write_text(json.dumps({"results": []}), encoding="utf-8")

        with pytest.raises(ReportValidationError, match="missing a valid 'domain' field"):
            load_and_validate_report(str(bad_file))

    def test_missing_results_list_raises_error(self, tmp_path: Path):
        """Verify report lacking 'results' list raises ReportValidationError."""
        bad_file = tmp_path / "noresults.json"
        bad_file.write_text(json.dumps({"domain": "example.com"}), encoding="utf-8")

        with pytest.raises(ReportValidationError, match="'results' field must be a list"):
            load_and_validate_report(str(bad_file))


class TestSharedSecurityAndScope:
    """Test suite for host validation, scope control, and SSRF checks."""

    def test_validate_host_and_scope_success(self):
        """Verify in-scope subdomain passes validation."""
        host, err = validate_host_and_scope("api.example.com", "example.com")
        assert host == "api.example.com"
        assert err is None

    def test_validate_host_and_scope_out_of_scope(self):
        """Verify out-of-scope domain returns error."""
        host, err = validate_host_and_scope("evil.com", "example.com")
        assert host is None
        assert "out of scope" in (err or "")

    def test_validate_host_and_scope_invalid_syntax(self):
        """Verify malformed host returns domain validation error."""
        host, err = validate_host_and_scope("bad..name", "example.com")
        assert host is None
        assert "Failed domain validation" in (err or "")

    def test_check_host_for_ssrf_safe_and_private(self):
        """Verify check_host_for_ssrf distinguishes safe from private IPs."""
        mock_resolver = MagicMock()

        # Safe public IP
        mock_rdata_safe = MagicMock()
        mock_rdata_safe.to_text.return_value = "93.184.216.34"
        mock_resolver.resolve.return_value = [mock_rdata_safe]
        safe, _ = check_host_for_ssrf("safe.example.com", resolver=mock_resolver)
        assert safe is True

        # Private IP
        mock_rdata_priv = MagicMock()
        mock_rdata_priv.to_text.return_value = "10.0.0.1"
        mock_resolver.resolve.return_value = [mock_rdata_priv]
        safe, reason = check_host_for_ssrf("priv.example.com", resolver=mock_resolver)
        assert safe is False
        assert "non-public/private IP: 10.0.0.1" in (reason or "")
