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
    """Verify DirectScannerRunner.run_discover delegates to v1 fetch_crtsh_data with the domain."""
    from asm.models import SubdomainResult
    from asm.worker.runner import DirectScannerRunner

    runner = DirectScannerRunner()
    fake_entries = [{"name_value": "api.example.com"}]
    fake_resolved = [
        SubdomainResult(subdomain="api.example.com", resolved=True, ip_addresses=["1.2.3.4"])
    ]

    with patch(
        "asm.worker.runner.fetch_crtsh_data", return_value=fake_entries
    ) as mock_fetch, patch(
        "asm.worker.runner.resolve_subdomains_concurrently", return_value=fake_resolved
    ) as mock_resolve:
        report = runner.run_discover("EXAMPLE.COM.")

        # Must call v1 discovery function with the normalized domain
        mock_fetch.assert_called_once_with("example.com")
        mock_resolve.assert_called_once_with(["api.example.com"])
        assert report["domain"] == "example.com"
        assert report["counts"]["total_discovered"] == 1
        assert report["counts"]["resolved"] == 1


def test_sanitize_error_text_strips_control_chars_and_truncates() -> None:
    """Verify sanitize_error_text strips control characters and truncates to 300 chars."""
    from asm.worker.worker import sanitize_error_text

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

