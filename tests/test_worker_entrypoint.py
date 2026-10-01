"""Unit tests for the ASM worker CLI entry point."""

from unittest.mock import MagicMock, patch


def test_worker_entrypoint_importable_and_callable() -> None:
    """Verify that worker entry point can be imported without side effects and main is callable."""
    from asm.worker.__main__ import main

    assert callable(main)


def test_worker_main_execution() -> None:
    """Verify that main instantiates ASMWorker and starts worker.run()."""
    from asm.worker.__main__ import main

    with patch("asm.worker.__main__.get_engine") as mock_get_engine, patch(
        "asm.worker.__main__.ASMWorker"
    ) as mock_worker_cls:
        mock_worker_instance = MagicMock()
        mock_worker_cls.return_value = mock_worker_instance

        exit_code = main()

        assert exit_code == 0
        mock_get_engine.assert_called_once()
        mock_worker_cls.assert_called_once_with(engine=mock_get_engine.return_value)
        mock_worker_instance.run.assert_called_once()


def test_direct_scanner_runner_run_discover_delegates_to_v1_discovery() -> None:
    """Verify DirectScannerRunner.run_discover delegates to discover_subdomains with the domain."""
    from asm.models import SubdomainResult
    from asm.worker.runner import DirectScannerRunner

    runner = DirectScannerRunner()
    fake_resolved = [
        SubdomainResult(subdomain="api.example.com", resolved=True, ip_addresses=["1.2.3.4"])
    ]

    with patch(
        "asm.worker.runner.discover_subdomains",
        return_value=(["api.example.com"], "crt.sh", None, False),
    ) as mock_discover, patch(
        "asm.worker.runner.resolve_subdomains_concurrently", return_value=fake_resolved
    ) as mock_resolve:
        report = runner.run_discover("EXAMPLE.COM.")

        # Must call discover_subdomains with the normalized domain
        mock_discover.assert_called_once_with("example.com")
        mock_resolve.assert_called_once_with(["api.example.com"])
        assert report["domain"] == "example.com"
        assert report["source"] == "crt.sh"
        assert report["fallback_reason"] is None
        assert report["truncated"] is False
        assert report["counts"]["total_discovered"] == 1
        assert report["counts"]["resolved"] == 1


def test_sanitize_error_text_strips_control_chars_and_truncates() -> None:
    """Verify sanitize_error_text strips control characters and truncates to 300 chars."""
    from asm.scan_common import sanitize_error_text

    # None and empty handling
    assert sanitize_error_text(None) is None
    assert sanitize_error_text("") == ""

    # HTML error page with newlines, carriage returns, tabs, null bytes, and excess length
    remote_html_error = (
        "crt.sh returned client error HTTP 404:\r\n"
        "<html>\n<head><title>404 Not Found</title></head>\n"
        "<body>\x00\x1b<h1>Not Found</h1>\t<p>"
        + ("A" * 500)
        + "</p></body>\r\n</html>"
    )

    sanitized = sanitize_error_text(remote_html_error)
    assert sanitized is not None
    assert len(sanitized) == 300
    assert "\r" not in sanitized
    assert "\n" not in sanitized
    assert "\t" not in sanitized
    assert "\x00" not in sanitized
    assert "\x1b" not in sanitized
    assert sanitized.startswith(
        "crt.sh returned client error HTTP 404:<html><head><title>404 Not Found"
    )


def test_contract_run_discover() -> None:
    """Contract test: DirectScannerRunner.run_discover autospec call to discover_subdomains."""
    from asm.models import SubdomainResult
    from asm.worker.runner import DirectScannerRunner

    runner = DirectScannerRunner()
    fake_resolved = [
        SubdomainResult(subdomain="api.example.com", resolved=True, ip_addresses=["1.2.3.4"])
    ]

    with patch(
        "asm.worker.runner.discover_subdomains",
        autospec=True,
        return_value=(["api.example.com"], "crt.sh", None, False),
    ) as mock_discover, patch(
        "asm.worker.runner.resolve_subdomains_concurrently",
        autospec=True,
        return_value=fake_resolved,
    ) as mock_resolve:
        report = runner.run_discover("example.com")
        mock_discover.assert_called_once_with("example.com")
        mock_resolve.assert_called_once_with(["api.example.com"])
        assert report["domain"] == "example.com"


def test_contract_run_probe() -> None:
    """Contract test: DirectScannerRunner.run_probe autospec call to probe_hosts_concurrently."""
    from asm.models import HostProbeResult
    from asm.worker.runner import DirectScannerRunner

    runner = DirectScannerRunner()
    mock_res = [HostProbeResult(subdomain="api.example.com", status="probed", live=True)]

    with patch(
        "asm.worker.runner.probe_hosts_concurrently",
        autospec=True,
        return_value=mock_res,
    ) as mock_probe:
        disc_report = {
            "domain": "example.com",
            "counts": {"unresolved": 0},
            "results": [{"subdomain": "api.example.com", "resolved": True}],
        }
        report = runner.run_probe("example.com", disc_report, authorized=True)
        mock_probe.assert_called_once_with(["api.example.com"], "example.com", max_workers=10)
        assert report["domain"] == "example.com"


def test_contract_run_portscan() -> None:
    """Contract test: DirectScannerRunner.run_portscan autospec call to run_port_scan."""
    from asm.models import HostPortScanResult
    from asm.worker.runner import DirectScannerRunner

    runner = DirectScannerRunner()
    mock_res = [
        HostPortScanResult(
            subdomain="api.example.com",
            status="probed",
            open_ports=[],
            closed_ports=[],
            filtered_ports=[],
            risk_flags=[],
        )
    ]

    with patch(
        "asm.worker.runner.run_port_scan",
        autospec=True,
        return_value=mock_res,
    ) as mock_portscan:
        disc_report = {
            "domain": "example.com",
            "counts": {"unresolved": 0},
            "results": [{"subdomain": "api.example.com", "resolved": True}],
        }
        report = runner.run_portscan("example.com", disc_report, authorized=True)
        mock_portscan.assert_called_once_with(["api.example.com"], "example.com")
        assert report["domain"] == "example.com"


def test_contract_run_inspect() -> None:
    """Contract test: DirectScannerRunner.run_inspect autospec call to run_inspection."""
    from asm.models import InspectReport
    from asm.worker.runner import DirectScannerRunner

    runner = DirectScannerRunner()
    mock_res = InspectReport(
        domain="example.com",
        source_report="probe_report",
        inspect_started_utc="2026-09-30T12:00:00Z",
        inspect_finished_utc="2026-09-30T12:00:01Z",
        counts={},
        results=[],
    )

    with patch(
        "asm.worker.runner.run_inspection",
        autospec=True,
        return_value=mock_res,
    ) as mock_inspect:
        probe_report = {
            "domain": "example.com",
            "results": [{"subdomain": "api.example.com", "status": "probed"}],
        }
        report = runner.run_inspect("example.com", probe_report, authorized=True)
        mock_inspect.assert_called_once_with(
            [{"subdomain": "api.example.com", "status": "probed"}],
            "example.com",
            source_report_name="probe_report",
        )
        assert report["domain"] == "example.com"


def test_contract_run_score() -> None:
    """Contract test: DirectScannerRunner.run_score autospec call to score_domain_payloads."""
    from asm.models import ScoreReport
    from asm.worker.runner import DirectScannerRunner

    runner = DirectScannerRunner()
    mock_score_report = ScoreReport(
        domain="example.com",
        generated_utc="2026-09-30T12:00:00Z",
        domain_score=0,
        domain_band="INFO",
        inputs_present=["discover"],
        counts={
            "hosts_evaluated": 1,
            "hosts_critical": 0,
            "hosts_high": 0,
            "hosts_medium": 0,
            "hosts_low": 0,
            "hosts_info": 1,
        },
        hosts=[],
    )

    with patch(
        "asm.worker.runner.score_domain_payloads",
        autospec=True,
        return_value=mock_score_report,
    ) as mock_score:
        disc_rep = {"results": [{"subdomain": "api.example.com"}]}
        report = runner.run_score("example.com", disc_rep, None, None, None)
        mock_score.assert_called_once_with(
            target_domain="example.com",
            disc_results=[{"subdomain": "api.example.com"}],
            probe_results=None,
            portscan_results=None,
            inspect_results=None,
        )
        assert report["domain"] == "example.com"

