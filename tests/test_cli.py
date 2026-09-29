"""Unit tests for the ASM command-line interface."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from asm.cli import main
from asm.discovery import CrtshError
from asm.models import HostProbeResult, HostProbeStatus, SubdomainResult, UrlProbeResult


class TestDiscoverCLIExecution:
    """Test suite for 'asm discover' command dispatch and error handling."""

    def test_discover_success(self, tmp_path: Path, crtsh_sample_data: list[dict], capsys):
        """Verify successful discovery run writes JSON and returns exit code 0."""
        with (
            patch("asm.cli.fetch_crtsh_data", return_value=crtsh_sample_data),
            patch("asm.cli.resolve_subdomains_concurrently") as mock_resolve,
        ):
            mock_resolve.return_value = [
                SubdomainResult(
                    subdomain="api.example.com",
                    ip_addresses=["93.184.216.34"],
                    status="RESOLVED",
                    resolved=True,
                )
            ]

            exit_code = main(["discover", "example.com", "--output", str(tmp_path)])

            assert exit_code == 0
            captured = capsys.readouterr()
            assert "=== Discovery Summary ===" in captured.out
            assert "api.example.com" not in captured.err

            # Check that report JSON file was written
            files = list(tmp_path.glob("example.com_*.json"))
            assert len(files) == 1
            report_file = files[0]

            with report_file.open("r", encoding="utf-8") as f:
                data = json.load(f)

            assert data["domain"] == "example.com"
            assert data["source"] == "crt.sh"
            assert "scan_started_utc" in data
            assert "scan_finished_utc" in data
            assert data["counts"]["total_discovered"] > 0
            assert len(data["results"]) == 1
            assert data["results"][0]["subdomain"] == "api.example.com"

    def test_discover_invalid_domain_exit_code_1(self, capsys):
        """Verify invalid domain exits with code 1 and writes to stderr without traceback."""
        exit_code = main(["discover", "192.168.1.1"])
        assert exit_code == 1

        captured = capsys.readouterr()
        assert "Error:" in captured.err
        assert "Traceback" not in captured.err

    def test_discover_crtsh_error_exit_code_2(self, capsys):
        """Verify crt.sh failure exits with code 2 and writes to stderr without traceback."""
        with patch("asm.cli.fetch_crtsh_data", side_effect=CrtshError("crt.sh timed out")):
            exit_code = main(["discover", "example.com"])
            assert exit_code == 2

            captured = capsys.readouterr()
            assert "Error: crt.sh timed out" in captured.err
            assert "Traceback" not in captured.err

    def test_discover_zero_subdomains_found(self, tmp_path: Path, capsys):
        """Verify handling when crt.sh returns empty results."""
        with (
            patch("asm.cli.fetch_crtsh_data", return_value=[]),
            patch("asm.cli.resolve_subdomains_concurrently") as mock_resolve,
        ):
            exit_code = main(["discover", "empty-target.com", "--output", str(tmp_path)])
            assert exit_code == 0
            mock_resolve.assert_not_called()

            captured = capsys.readouterr()
            assert "0 subdomains found" in captured.out

            files = list(tmp_path.glob("empty-target.com_*.json"))
            assert len(files) == 1
            with files[0].open("r", encoding="utf-8") as f:
                data = json.load(f)
            assert data["counts"]["total_discovered"] == 0
            assert data["results"] == []


class TestProbeCLIExecution:
    """Test suite for 'asm probe' command dispatch and authorization gate."""

    def test_probe_missing_authorized_flag_exits_1(self, tmp_path: Path, capsys):
        """Verify omitting --authorized prints warning with domain and makes 0 requests."""
        report_file = tmp_path / "test_report.json"
        report_file.write_text(
            json.dumps({"domain": "my-target.com", "results": []}),
            encoding="utf-8",
        )

        with patch("asm.cli.probe_hosts_concurrently") as mock_probe:
            exit_code = main(["probe", str(report_file)])
            assert exit_code == 1
            mock_probe.assert_not_called()

        captured = capsys.readouterr()
        expected_msg = (
            "Active probing sends requests to my-target.com. Re-run with --authorized "
            "to confirm you own it or have written permission to test it."
        )
        assert expected_msg in captured.err
        assert "Traceback" not in captured.err

    def test_probe_missing_report_file_exits_1(self, capsys):
        """Verify non-existent report file prints error to stderr and exits 1."""
        exit_code = main(["probe", "non_existent_file.json", "--authorized"])
        assert exit_code == 1

        captured = capsys.readouterr()
        assert "Error: Discovery report file not found" in captured.err
        assert "Traceback" not in captured.err

    def test_probe_invalid_json_report_exits_1(self, tmp_path: Path, capsys):
        """Verify malformed JSON report file prints error to stderr and exits 1."""
        corrupt_file = tmp_path / "corrupt.json"
        corrupt_file.write_text("{not-valid-json", encoding="utf-8")

        exit_code = main(["probe", str(corrupt_file), "--authorized"])
        assert exit_code == 1

        captured = capsys.readouterr()
        assert "Error: Failed to parse discovery report JSON" in captured.err
        assert "Traceback" not in captured.err

    def test_probe_zero_resolved_hosts_writes_report(self, tmp_path: Path, capsys):
        """Verify report with 0 resolved hosts skips probing, writes report, and exits 0."""
        report_file = tmp_path / "unresolved_report.json"
        report_file.write_text(
            json.dumps({
                "domain": "target.org",
                "results": [
                    {"subdomain": "sub.target.org", "status": "NXDOMAIN", "resolved": False}
                ],
            }),
            encoding="utf-8",
        )

        with patch("asm.cli.probe_hosts_concurrently") as mock_probe:
            exit_code = main(["probe", str(report_file), "--authorized", "-o", str(tmp_path)])
            assert exit_code == 0
            mock_probe.assert_not_called()

        captured = capsys.readouterr()
        assert "0 resolved hosts to probe" in captured.out

        probe_files = list(tmp_path.glob("target.org_probe_*.json"))
        assert len(probe_files) == 1
        with probe_files[0].open("r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["counts"]["hosts_probed"] == 0
        assert data["counts"]["skipped_unresolved"] == 1

    def test_probe_success_flow(self, tmp_path: Path, capsys):
        """Verify successful probe run outputs summary, writes report, and exits 0."""
        fixture_path = Path(__file__).parent / "fixtures" / "discovery_report_sample.json"

        mock_results = [
            HostProbeResult(
                subdomain="api.example.com",
                status=HostProbeStatus.PROBED.value,
                https=UrlProbeResult(
                    url="https://api.example.com/",
                    reachable=True,
                    status_code=200,
                    final_url="https://api.example.com/",
                    title="API Gateway",
                    tls_valid=True,
                ),
                live=True,
                preferred_url="https://api.example.com/",
            ),
            HostProbeResult(
                subdomain="www.example.com",
                status=HostProbeStatus.PROBED.value,
                https=UrlProbeResult(
                    url="https://www.example.com/",
                    reachable=True,
                    status_code=200,
                    final_url="https://www.example.com/",
                    title="Main Website",
                    tls_valid=True,
                ),
                live=True,
                preferred_url="https://www.example.com/",
            ),
        ]

        with patch("asm.cli.probe_hosts_concurrently", return_value=mock_results):
            exit_code = main(["probe", str(fixture_path), "--authorized", "-o", str(tmp_path)])
            assert exit_code == 0

        captured = capsys.readouterr()
        assert "=== Probe Summary ===" in captured.out
        assert "=== Live Hosts ===" in captured.out
        assert "https://api.example.com/ [200] API Gateway" in captured.out
        assert "https://www.example.com/ [200] Main Website" in captured.out

        probe_files = list(tmp_path.glob("example.com_probe_*.json"))
        assert len(probe_files) == 1
        with probe_files[0].open("r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["domain"] == "example.com"
        assert data["counts"]["hosts_probed"] == 2
        assert data["counts"]["https_live"] == 2
        assert data["counts"]["skipped_unresolved"] == 2
