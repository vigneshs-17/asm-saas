"""Unit tests for crt.sh discovery and parsing module."""

from unittest.mock import MagicMock

import httpx
import pytest

from asm.discovery import (
    CRTSH_BASE_URL,
    USER_AGENT,
    CrtshError,
    fetch_crtsh_data,
    parse_subdomains,
)


class TestSubdomainParsing:
    """Test suite for parse_subdomains using mock and fixture data."""

    def test_parse_subdomains_from_fixture(self, crtsh_sample_data):
        """Verify parsing handles wildcards, newlines, duplicates, emails, and scope."""
        target_domain = "example.com"
        results = parse_subdomains(crtsh_sample_data, target_domain)

        # Expected subdomains:
        # - example.com (from *.example.com and example.com)
        # - api.example.com (from api.example.com)
        # - dev.example.com (from multi-line)
        # - staging.example.com (from multi-line)
        # - corp.example.com (from *.corp.example.com)
        # - vpn.corp.example.com (from vpn.corp.example.com)
        # Excluded:
        # - admin@example.com (email)
        # - support@example.com (email)
        # - unrelated.org, sub.unrelated.org (out of scope)
        expected = [
            "api.example.com",
            "corp.example.com",
            "dev.example.com",
            "example.com",
            "staging.example.com",
            "vpn.corp.example.com",
        ]
        assert results == expected

    def test_parse_subdomains_deduplication_and_sorting(self):
        """Verify identical entries from multiple certs are deduplicated and sorted."""
        raw_entries = [
            {"name_value": "z.example.com\na.example.com"},
            {"name_value": "a.example.com\nm.example.com"},
        ]
        assert parse_subdomains(raw_entries, "example.com") == [
            "a.example.com",
            "m.example.com",
            "z.example.com",
        ]

    def test_parse_subdomains_empty_entries(self):
        """Verify empty records or missing fields are safely ignored."""
        raw_entries = [
            {},
            {"name_value": ""},
            {"name_value": None},
            {"name_value": "\n  \n"},
        ]
        assert parse_subdomains(raw_entries, "example.com") == []


class TestCrtshFetching:
    """Test suite for fetch_crtsh_data and network resilience logic."""

    def test_successful_fetch(self, crtsh_sample_data):
        """Verify successful query with correct parameters and headers."""
        client_mock = MagicMock(spec=httpx.Client)
        response_mock = MagicMock(spec=httpx.Response)
        response_mock.status_code = 200
        response_mock.json.return_value = crtsh_sample_data
        client_mock.get.return_value = response_mock

        data = fetch_crtsh_data("example.com", client=client_mock)

        assert data == crtsh_sample_data
        client_mock.get.assert_called_once_with(
            CRTSH_BASE_URL,
            params={"q": "%.example.com", "output": "json"},
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )

    def test_retry_on_server_502_then_success(self, mock_sleep):
        """Verify 502 Bad Gateway triggers a retry and succeeds on attempt 2."""
        client_mock = MagicMock(spec=httpx.Client)

        resp_502 = MagicMock(spec=httpx.Response)
        resp_502.status_code = 502

        resp_200 = MagicMock(spec=httpx.Response)
        resp_200.status_code = 200
        resp_200.json.return_value = [{"name_value": "sub.example.com"}]

        client_mock.get.side_effect = [resp_502, resp_200]

        data = fetch_crtsh_data("example.com", client=client_mock)
        assert len(data) == 1
        assert client_mock.get.call_count == 2
        mock_sleep.assert_called_once_with(1)

    def test_retry_on_timeout_and_rate_limit(self, mock_sleep):
        """Verify retries on Timeout and HTTP 429 then succeeds on attempt 3."""
        client_mock = MagicMock(spec=httpx.Client)

        timeout_exc = httpx.TimeoutException("Connection timed out")

        resp_429 = MagicMock(spec=httpx.Response)
        resp_429.status_code = 429

        resp_200 = MagicMock(spec=httpx.Response)
        resp_200.status_code = 200
        resp_200.json.return_value = [{"name_value": "app.example.com"}]

        client_mock.get.side_effect = [timeout_exc, resp_429, resp_200]

        data = fetch_crtsh_data("example.com", client=client_mock)
        assert len(data) == 1
        assert client_mock.get.call_count == 3
        # Should have slept with 1s then 2s
        assert mock_sleep.call_count == 2
        mock_sleep.assert_any_call(1)
        mock_sleep.assert_any_call(2)

    def test_retry_on_invalid_json_html_error(self, mock_sleep):
        """Verify retrying when response body is HTML rather than valid JSON."""
        client_mock = MagicMock(spec=httpx.Client)

        resp_bad_json = MagicMock(spec=httpx.Response)
        resp_bad_json.status_code = 200
        resp_bad_json.json.side_effect = ValueError("Invalid JSON")

        resp_200 = MagicMock(spec=httpx.Response)
        resp_200.status_code = 200
        resp_200.json.return_value = []

        client_mock.get.side_effect = [resp_bad_json, resp_200]

        data = fetch_crtsh_data("example.com", client=client_mock)
        assert data == []
        assert client_mock.get.call_count == 2
        mock_sleep.assert_called_once_with(1)

    def test_exhausted_retries_raises_crtsh_error(self, mock_sleep):
        """Verify exhausting all 3 attempts raises CrtshError."""
        client_mock = MagicMock(spec=httpx.Client)
        resp_500 = MagicMock(spec=httpx.Response)
        resp_500.status_code = 500
        client_mock.get.return_value = resp_500

        with pytest.raises(CrtshError, match="Failed to retrieve data from crt.sh"):
            fetch_crtsh_data("example.com", client=client_mock)

        assert client_mock.get.call_count == 3
        assert mock_sleep.call_count == 2

    def test_non_retryable_404_fails_immediately(self, mock_sleep):
        """Verify non-retryable 4xx errors like 404 abort immediately without retrying."""
        client_mock = MagicMock(spec=httpx.Client)
        resp_404 = MagicMock(spec=httpx.Response)
        resp_404.status_code = 404
        resp_404.text = "Not Found"
        client_mock.get.return_value = resp_404

        with pytest.raises(CrtshError, match="client error HTTP 404"):
            fetch_crtsh_data("example.com", client=client_mock)

        assert client_mock.get.call_count == 1
        mock_sleep.assert_not_called()
