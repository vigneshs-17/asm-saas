"""Data models for ASM SaaS discovery, probe results, and reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class DNSStatus(StrEnum):
    """Enumeration of possible DNS resolution outcomes for a subdomain."""

    RESOLVED = "RESOLVED"
    NXDOMAIN = "NXDOMAIN"
    NO_ANSWER = "NO_ANSWER"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"


class HostProbeStatus(StrEnum):
    """Enumeration of possible outcomes when evaluating whether to probe a host."""

    PROBED = "PROBED"
    SKIPPED_UNTRUSTED = "SKIPPED_UNTRUSTED"
    SKIPPED_PRIVATE_IP = "SKIPPED_PRIVATE_IP"
    SKIPPED_UNRESOLVED = "SKIPPED_UNRESOLVED"


class ProbeErrorType(StrEnum):
    """Categorization of network or protocol failures encountered during HTTP probing."""

    TIMEOUT = "TIMEOUT"
    CONNECT_ERROR = "CONNECT_ERROR"
    TLS_ERROR = "TLS_ERROR"
    TOO_MANY_REDIRECTS = "TOO_MANY_REDIRECTS"
    OTHER = "OTHER"


@dataclass
class SubdomainResult:
    """Represents a discovered subdomain and its DNS resolution status.

    Attributes:
        subdomain: The fully-qualified subdomain name (e.g. 'api.example.com').
        ip_addresses: List of resolved IPv4 and IPv6 addresses.
        status: DNS resolution status (from DNSStatus).
        resolved: True if at least one IP address was resolved, False otherwise.
    """

    subdomain: str
    ip_addresses: list[str] = field(default_factory=list)
    status: str = DNSStatus.NO_ANSWER.value
    resolved: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert the SubdomainResult to a dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class DiscoveryReport:
    """Top-level report containing the results of a passive discovery scan.

    Attributes:
        domain: The root domain investigated.
        scan_started_utc: ISO 8601 UTC timestamp when scan started.
        scan_finished_utc: ISO 8601 UTC timestamp when scan completed.
        source: The passive intelligence source used (defaults to 'crt.sh').
        counts: Summary counts of discovered, resolved, and unresolved domains.
        results: Detailed list of SubdomainResult objects.
    """

    domain: str
    scan_started_utc: str
    scan_finished_utc: str
    source: str = "crt.sh"
    counts: dict[str, int] = field(default_factory=dict)
    results: list[SubdomainResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert the full report to a dictionary suitable for JSON export."""
        return {
            "domain": self.domain,
            "scan_started_utc": self.scan_started_utc,
            "scan_finished_utc": self.scan_finished_utc,
            "source": self.source,
            "counts": self.counts,
            "results": [result.to_dict() for result in self.results],
        }


@dataclass
class RedirectHop:
    """Records an individual redirect step encountered during URL probing."""

    url: str
    status_code: int
    out_of_scope: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert redirect hop to dictionary."""
        return asdict(self)


@dataclass
class UrlProbeResult:
    """Outcome of probing a single URL (HTTPS or HTTP) for a host.

    Attributes:
        url: The initial URL targeted (e.g. 'https://api.example.com/').
        reachable: True if an HTTP response was received (even error/redirect).
        status_code: HTTP status code returned (e.g. 200, 301, 404, 500).
        final_url: The URL reached after following in-scope redirects.
        redirect_chain: Sequence of followed redirect hops.
        title: Extracted HTML <title> tag text (if Content-Type is text/html).
        server: Value of the 'Server' response header.
        x_powered_by: Value of the 'X-Powered-By' response header.
        content_type: Value of the 'Content-Type' response header.
        response_time_ms: Round-trip time in milliseconds.
        error_type: Categorized failure reason (from ProbeErrorType).
        error_message: Detailed error message or reason.
        tls_valid: Certificate validity (True=valid, False=cert verification error, None=HTTP).
    """

    url: str
    reachable: bool = False
    status_code: int | None = None
    final_url: str | None = None
    redirect_chain: list[RedirectHop] = field(default_factory=list)
    title: str | None = None
    server: str | None = None
    x_powered_by: str | None = None
    content_type: str | None = None
    response_time_ms: float | None = None
    error_type: str | None = None
    error_message: str | None = None
    tls_valid: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert URL probe result to dictionary."""
        return {
            "url": self.url,
            "reachable": self.reachable,
            "status_code": self.status_code,
            "final_url": self.final_url,
            "redirect_chain": [hop.to_dict() for hop in self.redirect_chain],
            "title": self.title,
            "server": self.server,
            "x_powered_by": self.x_powered_by,
            "content_type": self.content_type,
            "response_time_ms": self.response_time_ms,
            "error_type": self.error_type,
            "error_message": self.error_message,
            "tls_valid": self.tls_valid,
        }


@dataclass
class HostProbeResult:
    """Outcome of probing both HTTPS and HTTP endpoints for a single hostname.

    Attributes:
        subdomain: Hostname probed (e.g. 'admin.example.com').
        status: Host status (PROBED, SKIPPED_UNTRUSTED, SKIPPED_PRIVATE_IP, etc.).
        skip_reason: Explanation if the host was skipped.
        https: Probe result for the HTTPS endpoint.
        http: Probe result for the HTTP endpoint.
        live: True if either HTTPS or HTTP endpoint responded.
        preferred_url: The primary URL to access the service (HTTPS if live, else HTTP).
    """

    subdomain: str
    status: str = HostProbeStatus.PROBED.value
    skip_reason: str | None = None
    https: UrlProbeResult | None = None
    http: UrlProbeResult | None = None
    live: bool = False
    preferred_url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert host probe result to dictionary."""
        return {
            "subdomain": self.subdomain,
            "status": self.status,
            "skip_reason": self.skip_reason,
            "https": self.https.to_dict() if self.https is not None else None,
            "http": self.http.to_dict() if self.http is not None else None,
            "live": self.live,
            "preferred_url": self.preferred_url,
        }


@dataclass
class ProbeReport:
    """Top-level report containing the results of an active HTTP/HTTPS probe scan.

    Attributes:
        domain: Root domain probed.
        source_report: Path or filename of the Step 1 discovery report used as input.
        probe_started_utc: ISO 8601 UTC timestamp when scan started.
        probe_finished_utc: ISO 8601 UTC timestamp when scan finished.
        counts: Statistical counts of probed, live, and skipped hosts.
        results: Detailed list of HostProbeResult objects.
    """

    domain: str
    source_report: str
    probe_started_utc: str
    probe_finished_utc: str
    counts: dict[str, int] = field(default_factory=dict)
    results: list[HostProbeResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert probe report to dictionary for JSON export."""
        return {
            "domain": self.domain,
            "source_report": self.source_report,
            "probe_started_utc": self.probe_started_utc,
            "probe_finished_utc": self.probe_finished_utc,
            "counts": self.counts,
            "results": [result.to_dict() for result in self.results],
        }
