"""Command-line interface (CLI) for ASM SaaS."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from asm.discovery import CrtshError, fetch_crtsh_data, parse_subdomains
from asm.models import (
    DiscoveryReport,
    HostProbeResult,
    HostProbeStatus,
    ProbeReport,
    SubdomainResult,
)
from asm.prober import probe_hosts_concurrently
from asm.resolver import resolve_subdomains_concurrently
from asm.validators import DomainValidationError, validate_domain

logger = logging.getLogger("asm")


def setup_logging(verbose: bool = False) -> None:
    """Configure standard library logging format and log level."""
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def build_parser() -> argparse.ArgumentParser:
    """Construct the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="asm",
        description="ASM SaaS - Attack Surface Management CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: discover
    discover_parser = subparsers.add_parser(
        "discover",
        help="Passively discover subdomains via Certificate Transparency logs (crt.sh)",
    )
    discover_parser.add_argument(
        "domain",
        help="Target domain to scan (e.g. 'example.com' or 'https://example.com')",
    )
    discover_parser.add_argument(
        "-o",
        "--output",
        dest="output_dir",
        default="output",
        help="Directory to save the JSON discovery report (default: output)",
    )
    discover_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging",
    )

    # Subcommand: probe
    probe_parser = subparsers.add_parser(
        "probe",
        help="Actively probe resolved hosts for live HTTP/HTTPS services",
    )
    probe_parser.add_argument(
        "report_file",
        help="Path to Step 1 discovery report JSON file",
    )
    probe_parser.add_argument(
        "--authorized",
        action="store_true",
        default=False,
        help="Confirm authorization to perform active network requests against target domain",
    )
    probe_parser.add_argument(
        "-o",
        "--output",
        dest="output_dir",
        default="output",
        help="Directory to save the JSON probe report (default: output)",
    )
    probe_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging",
    )

    return parser


def handle_discover(domain_arg: str, output_dir_arg: str) -> int:
    """Execute the subdomain discovery and DNS resolution workflow.

    Args:
        domain_arg: The raw user-supplied target domain.
        output_dir_arg: Directory path to write the JSON report to.

    Returns:
        Exit code: 0 on success, 1 on validation error, 2 on crt.sh failure.
    """
    # 1. Input validation & normalization
    try:
        domain = validate_domain(domain_arg)
    except DomainValidationError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1

    start_mono = time.monotonic()
    scan_start_dt = datetime.now(UTC)
    scan_started_utc = scan_start_dt.isoformat()

    print(f"[*] Discovering subdomains for '{domain}' via crt.sh...")

    # 2. Query Certificate Transparency logs
    try:
        raw_entries = fetch_crtsh_data(domain)
    except CrtshError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 2

    # 3. Parse and sanitize subdomains
    subdomains = parse_subdomains(raw_entries, domain)
    total_found = len(subdomains)

    results: list[SubdomainResult] = []
    if total_found == 0:
        print("[*] 0 subdomains found.")
        resolved_count = 0
        unresolved_count = 0
    else:
        print(f"[*] Found {total_found} unique subdomains. Resolving DNS records...")
        # 4. Resolve DNS records concurrently
        results = resolve_subdomains_concurrently(subdomains)
        resolved_count = sum(1 for r in results if r.resolved)
        unresolved_count = total_found - resolved_count

    scan_finish_dt = datetime.now(UTC)
    scan_finished_utc = scan_finish_dt.isoformat()
    elapsed_seconds = round(time.monotonic() - start_mono, 2)

    # 5. Build report
    counts = {
        "total_discovered": total_found,
        "resolved": resolved_count,
        "unresolved": unresolved_count,
    }
    report = DiscoveryReport(
        domain=domain,
        scan_started_utc=scan_started_utc,
        scan_finished_utc=scan_finished_utc,
        source="crt.sh",
        counts=counts,
        results=results,
    )

    # 6. Save report to JSON file
    output_dir = Path(output_dir_arg)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Format Windows-safe UTC timestamp with no colons (e.g. 20260929T041500Z)
    filename_ts = scan_start_dt.strftime("%Y%m%dT%H%M%SZ")
    report_file = output_dir / f"{domain}_{filename_ts}.json"

    with report_file.open("w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2)

    # 7. Print summary to user
    print("\n=== Discovery Summary ===")
    print(f"Domain:              {domain}")
    print(f"Subdomains Found:    {total_found}")
    print(f"Resolved (Active):   {resolved_count}")
    print(f"Unresolved:          {unresolved_count}")
    print(f"Scan Duration:       {elapsed_seconds}s")
    print(f"Report File:         {report_file}")

    return 0


def handle_probe(report_file_arg: str, authorized: bool, output_dir_arg: str) -> int:
    """Execute the active HTTP/HTTPS host probing workflow.

    Enforces authorization gate, validates discovery report input, performs
    concurrent probing against resolved hosts, and writes a probe report.

    Args:
        report_file_arg: Path to the Step 1 discovery report JSON file.
        authorized: User-supplied boolean confirmation of testing authorization.
        output_dir_arg: Target directory for the probe report.

    Returns:
        Exit code: 0 on success, 1 on authorization or validation error.
    """
    report_path = Path(report_file_arg)

    # 1. Validate file presence
    if not report_path.is_file():
        sys.stderr.write(f"Error: Discovery report file not found: {report_file_arg}\n")
        return 1

    # 2. Parse report JSON
    try:
        with report_path.open("r", encoding="utf-8") as f:
            report_data: dict[str, Any] = json.load(f)
    except Exception as exc:
        sys.stderr.write(f"Error: Failed to parse discovery report JSON: {exc}\n")
        return 1

    domain = report_data.get("domain")
    if not domain or not isinstance(domain, str):
        sys.stderr.write("Error: Discovery report is missing a valid 'domain' field\n")
        return 1

    # 3. Authorization Gate (strictly enforced before any network requests)
    if not authorized:
        sys.stderr.write(
            f"Active probing sends requests to {domain}. Re-run with --authorized "
            "to confirm you own it or have written permission to test it.\n"
        )
        return 1

    # 4. Extract resolved subdomains
    raw_results = report_data.get("results", [])
    if not isinstance(raw_results, list):
        sys.stderr.write("Error: Discovery report 'results' field must be a list\n")
        return 1

    resolved_hosts: list[str] = []
    skipped_unresolved_count = 0

    for item in raw_results:
        if isinstance(item, dict):
            subdomain = item.get("subdomain")
            if not subdomain or not isinstance(subdomain, str):
                continue
            is_resolved = item.get("resolved") is True or item.get("status") == "RESOLVED"
            if is_resolved:
                resolved_hosts.append(subdomain)
            else:
                skipped_unresolved_count += 1

    start_mono = time.monotonic()
    probe_start_dt = datetime.now(UTC)
    probe_started_utc = probe_start_dt.isoformat()

    results: list[HostProbeResult] = []

    # 5. Probing execution
    if not resolved_hosts:
        print("[*] 0 resolved hosts to probe.")
    else:
        print(f"[*] Probing {len(resolved_hosts)} resolved hosts for '{domain}' (HTTPS/HTTP)...")
        results = probe_hosts_concurrently(resolved_hosts, domain, max_workers=10)

    probe_finish_dt = datetime.now(UTC)
    probe_finished_utc = probe_finish_dt.isoformat()
    elapsed_seconds = round(time.monotonic() - start_mono, 2)

    # 6. Statistical counts
    hosts_probed = sum(1 for r in results if r.status == HostProbeStatus.PROBED.value)
    https_live = sum(1 for r in results if r.https is not None and r.https.reachable)
    http_only = sum(
        1
        for r in results
        if (
            r.http is not None
            and r.http.reachable
            and not (r.https is not None and r.https.reachable)
        )
    )
    unreachable = sum(
        1 for r in results if r.status == HostProbeStatus.PROBED.value and not r.live
    )
    tls_invalid = sum(1 for r in results if r.https is not None and r.https.tls_valid is False)
    skipped_untrusted = sum(
        1 for r in results if r.status == HostProbeStatus.SKIPPED_UNTRUSTED.value
    )
    skipped_private_ip = sum(
        1 for r in results if r.status == HostProbeStatus.SKIPPED_PRIVATE_IP.value
    )

    counts = {
        "hosts_probed": hosts_probed,
        "https_live": https_live,
        "http_only": http_only,
        "unreachable": unreachable,
        "tls_invalid": tls_invalid,
        "skipped_untrusted": skipped_untrusted,
        "skipped_private_ip": skipped_private_ip,
        "skipped_unresolved": skipped_unresolved_count,
    }

    report = ProbeReport(
        domain=domain,
        source_report=str(report_path.name),
        probe_started_utc=probe_started_utc,
        probe_finished_utc=probe_finished_utc,
        counts=counts,
        results=results,
    )

    # 7. Save probe report
    output_dir = Path(output_dir_arg)
    output_dir.mkdir(parents=True, exist_ok=True)

    filename_ts = probe_start_dt.strftime("%Y%m%dT%H%M%SZ")
    report_file = output_dir / f"{domain}_probe_{filename_ts}.json"

    with report_file.open("w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2)

    # 8. Print summary
    print("\n=== Probe Summary ===")
    print(f"Domain:              {domain}")
    print(f"Hosts Probed:        {hosts_probed}")
    print(f"HTTPS Live:          {https_live}")
    print(f"HTTP Only:           {http_only}")
    print(f"Unreachable:         {unreachable}")
    print(f"TLS Invalid:         {tls_invalid}")
    print(f"Skipped Untrusted:   {skipped_untrusted}")
    print(f"Skipped Private IP:  {skipped_private_ip}")
    print(f"Skipped Unresolved:  {skipped_unresolved_count}")
    print(f"Scan Duration:       {elapsed_seconds}s")
    print(f"Report File:         {report_file}")

    # Print live hosts list
    live_hosts = [r for r in results if r.live]
    if live_hosts:
        print("\n=== Live Hosts ===")
        for host_res in live_hosts:
            active_url_res = (
                host_res.https
                if (host_res.https and host_res.https.reachable)
                else host_res.http
            )
            if active_url_res is not None:
                url_display = active_url_res.final_url or active_url_res.url
                code_display = active_url_res.status_code or "???"
                title_display = active_url_res.title or ""
                print(f"{url_display} [{code_display}] {title_display}".strip())

    return 0


def main(argv: list[str] | None = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    setup_logging(verbose=getattr(args, "verbose", False))

    if args.command == "discover":
        return handle_discover(args.domain, args.output_dir)
    if args.command == "probe":
        return handle_probe(args.report_file, args.authorized, args.output_dir)

    return 0


if __name__ == "__main__":
    sys.exit(main())
