"""Shared security, validation, and report loading utilities for ASM scans."""

from __future__ import annotations

import ipaddress
import json
import logging
from pathlib import Path
from typing import Any

import dns.resolver

from asm.validators import DomainValidationError, validate_domain

logger = logging.getLogger(__name__)


class ReportValidationError(Exception):
    """Raised when an input discovery report is missing, malformed, or invalid."""


def load_and_validate_report(
    report_path_str: str,
) -> tuple[dict[str, Any], str, list[str], int]:
    """Load and validate a Step 1 discovery report JSON file.

    Treats the input report as untrusted data:
    - Verifies file existence.
    - Validates JSON format.
    - Requires a non-empty 'domain' string.
    - Requires a 'results' list.
    - Extracts hostnames where status == 'RESOLVED' or resolved is True.
    - Counts skipped unresolved hosts.

    Args:
        report_path_str: Path to the discovery report JSON file.

    Returns:
        Tuple of (raw_report_dict, target_domain, resolved_hosts, skipped_unresolved_count).

    Raises:
        ReportValidationError: If the file cannot be found, parsed, or lacks required fields.
    """
    report_path = Path(report_path_str)
    if not report_path.is_file():
        raise ReportValidationError(f"Discovery report file not found: {report_path_str}")

    try:
        with report_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        raise ReportValidationError(f"Failed to parse discovery report JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ReportValidationError("Discovery report JSON root must be an object")

    domain = data.get("domain")
    if not domain or not isinstance(domain, str):
        raise ReportValidationError("Discovery report is missing a valid 'domain' field")

    raw_results = data.get("results")
    if not isinstance(raw_results, list):
        raise ReportValidationError("Discovery report 'results' field must be a list")

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

    return data, domain, resolved_hosts, skipped_unresolved_count


def load_and_validate_generic_report(
    report_path_str: str,
    report_type: str = "report",
    expected_domain: str | None = None,
) -> tuple[dict[str, Any], str, list[dict[str, Any]]]:
    """Load and validate an untrusted scan report JSON file.

    Treats the input report as untrusted data:
    - Verifies file existence.
    - Validates JSON format and root dictionary structure.
    - Requires a non-empty 'domain' string.
    - Asserts domain matches expected_domain if specified.
    - Requires a 'results' list of dictionaries.

    Args:
        report_path_str: Path to the JSON report file.
        report_type: Descriptive name for errors (e.g. 'probe', 'inspect').
        expected_domain: Optional expected domain to check for agreement.

    Returns:
        Tuple of (raw_report_dict, target_domain, results_list).

    Raises:
        ReportValidationError: On missing, malformed, or mismatched domain report.
    """
    report_path = Path(report_path_str)
    type_name = report_type.capitalize()
    if not report_path.is_file():
        raise ReportValidationError(f"{type_name} report file not found: {report_path_str}")

    try:
        with report_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        raise ReportValidationError(f"Failed to parse {report_type} report JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ReportValidationError(f"{type_name} report JSON root must be an object")

    domain = data.get("domain")
    if not domain or not isinstance(domain, str):
        raise ReportValidationError(f"{type_name} report is missing a valid 'domain' field")

    if expected_domain and domain.strip().lower() != expected_domain.strip().lower():
        msg = f"{type_name} report domain '{domain}' does not match expected '{expected_domain}'"
        raise ReportValidationError(msg)

    raw_results = data.get("results")
    if not isinstance(raw_results, list):
        raise ReportValidationError(f"{type_name} report 'results' field must be a list")

    dict_results = [r for r in raw_results if isinstance(r, dict)]
    return data, domain, dict_results


def is_safe_public_ip(ip_str: str) -> bool:
    """Check if an IP address is a safe, globally routable public address.

    First unwraps IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 -> 127.0.0.1),
    then verifies that ip.is_global is True and ip.is_multicast is False.
    This safely filters out:
    - Private networks (RFC 1918)
    - Loopback addresses (127.0.0.0/8, ::1)
    - Link-local addresses (169.254.0.0/16, fe80::/10)
    - Reserved ranges
    - CGNAT addresses (100.64.0.0/10)
    - Unspecified addresses (0.0.0.0, ::)
    - Multicast groups

    Args:
        ip_str: The IP address string to check.

    Returns:
        True if the IP is globally routable and public, False otherwise.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    # Unwrap IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1 -> 127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped

    return bool(ip.is_global and not ip.is_multicast)


def resolve_host_ips(
    hostname: str,
    resolver: dns.resolver.Resolver | None = None,
) -> list[str]:
    """Resolve A and AAAA DNS records for a hostname.

    Args:
        hostname: The hostname to resolve.
        resolver: Optional configured Resolver instance.

    Returns:
        List of resolved IP address strings (may be empty if resolution fails).
    """
    active_resolver = resolver if resolver is not None else dns.resolver.Resolver()
    active_resolver.lifetime = 3.0
    active_resolver.timeout = 3.0

    resolved_ips: list[str] = []
    for rdtype in ("A", "AAAA"):
        try:
            answers = active_resolver.resolve(hostname, rdtype)
            for rdata in answers:
                resolved_ips.append(rdata.to_text())
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass
        except Exception as exc:
            logger.debug("DNS check error for %s (%s): %s", hostname, rdtype, exc)

    return resolved_ips


def check_host_for_ssrf(
    hostname: str,
    resolver: dns.resolver.Resolver | None = None,
) -> tuple[bool, str | None]:
    """Resolve a host and check whether any resolved IP is internal/private.

    Maintains backward compatibility with Step 2 prober logic.

    Note: This pre-probe check prevents the tool from probing internal networks (SSRF).
    Protection against DNS rebinding (where an authoritative DNS server changes the
    IP address to an internal IP between our DNS check and the request) will be handled in v2.

    Args:
        hostname: Subdomain to resolve and inspect.
        resolver: Optional Resolver instance for testing.

    Returns:
        (True, None) if safe, or (False, reason) if any resolved IP is non-public.
    """
    resolved_ips = resolve_host_ips(hostname, resolver=resolver)

    if not resolved_ips:
        # If no IPs resolve during pre-check, allow to proceed to prober/scanner
        return True, None

    for ip in resolved_ips:
        if not is_safe_public_ip(ip):
            return False, f"Host '{hostname}' resolved to non-public/private IP: {ip}"

    return True, None


def validate_host_and_scope(
    hostname: str,
    base_domain: str,
) -> tuple[str | None, str | None]:
    """Validate a hostname's syntax and ensure it belongs to the target domain scope.

    Args:
        hostname: Subdomain string from untrusted report.
        base_domain: Root domain authorized for testing.

    Returns:
        Tuple of (validated_hostname, None) on success, or (None, failure_reason).
    """
    try:
        validated_host = validate_domain(hostname)
    except DomainValidationError as exc:
        return None, f"Failed domain validation: {exc}"

    norm_base = base_domain.lower().rstrip(".")
    if not (validated_host == norm_base or validated_host.endswith(f".{norm_base}")):
        return None, f"Host '{hostname}' is out of scope for root domain '{base_domain}'"

    return validated_host, None
