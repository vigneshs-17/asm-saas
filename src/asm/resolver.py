"""DNS resolution module using dnspython and concurrent thread pooling."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.resolver

from asm.models import DNSStatus, SubdomainResult

logger = logging.getLogger(__name__)

DEFAULT_DNS_TIMEOUT = 5.0
DEFAULT_MAX_WORKERS = 20


def _query_record_type(
    resolver: dns.resolver.Resolver,
    hostname: str,
    record_type: str,
) -> tuple[list[str], DNSStatus]:
    """Query a single DNS record type (e.g. 'A' or 'AAAA') for a hostname.

    Args:
        resolver: Configured dnspython Resolver instance.
        hostname: The hostname to resolve.
        record_type: Record type string ('A' or 'AAAA').

    Returns:
        A tuple of (list of IP address strings, status enum).
    """
    try:
        answers = resolver.resolve(hostname, record_type)
        ips = [rdata.to_text() for rdata in answers]
        if ips:
            return ips, DNSStatus.RESOLVED
        return [], DNSStatus.NO_ANSWER
    except dns.resolver.NXDOMAIN:
        return [], DNSStatus.NXDOMAIN
    except dns.resolver.NoAnswer:
        return [], DNSStatus.NO_ANSWER
    except dns.resolver.NoNameservers:
        # Per project requirements: NoNameservers maps to ERROR
        return [], DNSStatus.ERROR
    except dns.exception.Timeout:
        return [], DNSStatus.TIMEOUT
    except Exception as exc:
        logger.debug("Unexpected error resolving %s for %s: %s", record_type, hostname, exc)
        return [], DNSStatus.ERROR


def resolve_subdomain(
    hostname: str,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    resolver: dns.resolver.Resolver | None = None,
) -> SubdomainResult:
    """Resolve A and AAAA DNS records for a single subdomain.

    Combines A and AAAA results using the following precedence:
    1. Any IP found from either query -> RESOLVED
    2. Else if either returned NXDOMAIN -> NXDOMAIN
    3. Else if either timed out -> TIMEOUT
    4. Else if either had an unexpected error -> ERROR
    5. Else -> NO_ANSWER

    Args:
        hostname: The subdomain name to resolve.
        timeout: Query lifetime and timeout in seconds.
        resolver: Optional Resolver instance (useful for mocking/testing).

    Returns:
        SubdomainResult containing status, resolved flag, and sorted unique IPs.
    """
    if resolver is None:
        active_resolver = dns.resolver.Resolver()
        active_resolver.lifetime = timeout
        active_resolver.timeout = timeout
    else:
        active_resolver = resolver

    # Query IPv4 (A) and IPv6 (AAAA) records
    a_ips, a_status = _query_record_type(active_resolver, hostname, "A")
    aaaa_ips, aaaa_status = _query_record_type(active_resolver, hostname, "AAAA")

    # Deduplicate and sort all discovered IP addresses
    combined_ips = sorted(set(a_ips + aaaa_ips))
    statuses = [a_status, aaaa_status]

    # Apply precedence rules
    if combined_ips:
        final_status = DNSStatus.RESOLVED
        is_resolved = True
    elif DNSStatus.NXDOMAIN in statuses:
        final_status = DNSStatus.NXDOMAIN
        is_resolved = False
    elif DNSStatus.TIMEOUT in statuses:
        final_status = DNSStatus.TIMEOUT
        is_resolved = False
    elif DNSStatus.ERROR in statuses:
        final_status = DNSStatus.ERROR
        is_resolved = False
    else:
        final_status = DNSStatus.NO_ANSWER
        is_resolved = False

    return SubdomainResult(
        subdomain=hostname,
        ip_addresses=combined_ips,
        status=final_status.value,
        resolved=is_resolved,
    )


def resolve_subdomains_concurrently(
    subdomains: list[str],
    max_workers: int = DEFAULT_MAX_WORKERS,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    resolver: dns.resolver.Resolver | None = None,
) -> list[SubdomainResult]:
    """Concurrently resolve a list of subdomains using a ThreadPoolExecutor.

    Args:
        subdomains: List of hostname strings to resolve.
        max_workers: Maximum number of worker threads (default: 20).
        timeout: Query timeout in seconds.
        resolver: Optional Resolver instance to reuse or mock.

    Returns:
        List of SubdomainResult objects sorted alphabetically by subdomain.
    """
    if not subdomains:
        return []

    results: list[SubdomainResult] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all resolution tasks
        future_to_subdomain = {
            executor.submit(resolve_subdomain, host, timeout, resolver): host
            for host in subdomains
        }

        for future in future_to_subdomain:
            subdomain = future_to_subdomain[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as exc:
                logger.error("Thread execution failed for subdomain '%s': %s", subdomain, exc)
                results.append(
                    SubdomainResult(
                        subdomain=subdomain,
                        ip_addresses=[],
                        status=DNSStatus.ERROR.value,
                        resolved=False,
                    )
                )

    # Return results sorted alphabetically by subdomain name
    results.sort(key=lambda r: r.subdomain)
    return results
