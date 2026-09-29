"""Certificate Transparency log discovery via crt.sh.

Queries crt.sh to passively discover subdomains that have had TLS/SSL
certificates issued for a target domain.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

CRTSH_BASE_URL = "https://crt.sh"
USER_AGENT = "asm-saas/0.1 (student project)"
REQUEST_TIMEOUT = 30.0
MAX_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = [1, 2]  # Wait 1s after attempt 1, 2s after attempt 2


class CrtshError(Exception):
    """Raised when querying crt.sh fails after exhausting all retries."""


def _is_valid_discovered_name(candidate: str) -> bool:
    """Check if a discovered name is a syntactically valid hostname.

    Filters out certificate common names that are emails, IP addresses,
    or contain invalid DNS characters.

    Args:
        candidate: The sanitized hostname candidate.

    Returns:
        True if candidate is a valid DNS hostname, False otherwise.
    """
    if not candidate or len(candidate) > 253 or "@" in candidate:
        return False

    # Disallow whitespace or invalid characters
    label_pattern = re.compile(r"^[a-z0-9-]+$")
    labels = candidate.split(".")
    if len(labels) < 2:
        return False

    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not label_pattern.match(label):
            return False

    return True


def fetch_crtsh_data(domain: str, client: httpx.Client | None = None) -> list[dict[str, Any]]:
    """Query crt.sh for certificate logs associated with the given domain.

    Includes retry logic with backoff for transient issues:
    - Retries on network timeouts, connection errors, HTTP 5xx, HTTP 429,
      and invalid JSON responses.
    - Fails immediately on other HTTP 4xx client errors.
    - Maximum 3 attempts with 1s and 2s delays between attempts.

    Args:
        domain: The target domain to query (e.g. 'example.com').
        client: Optional httpx.Client instance (useful for unit testing/mocking).

    Returns:
        A list of dictionary records returned by crt.sh.

    Raises:
        CrtshError: If all retry attempts fail or a non-retryable 4xx is returned.
    """
    params = {
        "q": f"%.{domain}",
        "output": "json",
    }
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }

    # Use provided client or create a short-lived local client
    owns_client = client is None
    active_client = client if client is not None else httpx.Client(timeout=REQUEST_TIMEOUT)

    last_error: str = "Unknown error"

    try:
        for attempt in range(1, MAX_ATTEMPTS + 1):
            logger.debug(
                "Querying crt.sh for domain '%s' (Attempt %d/%d)",
                domain,
                attempt,
                MAX_ATTEMPTS,
            )
            try:
                response = active_client.get(CRTSH_BASE_URL, params=params, headers=headers)

                # Handle 4xx Client Errors
                if 400 <= response.status_code < 500:
                    if response.status_code == 429:
                        # Rate limited: retryable
                        last_error = "Rate limited (HTTP 429) by crt.sh"
                        logger.warning(
                            "crt.sh returned HTTP 429 Too Many Requests on attempt %d/%d",
                            attempt,
                            MAX_ATTEMPTS,
                        )
                    else:
                        # Non-retryable 4xx error (e.g. 400 Bad Request, 404 Not Found)
                        truncated_text = response.text[:200]
                        raise CrtshError(
                            f"crt.sh returned client error HTTP {response.status_code}: "
                            f"{truncated_text}"
                        )
                # Handle 5xx Server Errors (retryable)
                elif response.status_code >= 500:
                    last_error = f"Server error HTTP {response.status_code} from crt.sh"
                    logger.warning(
                        "crt.sh returned HTTP %d on attempt %d/%d",
                        response.status_code,
                        attempt,
                        MAX_ATTEMPTS,
                    )
                else:
                    # Successful HTTP status code; attempt JSON decoding
                    try:
                        data = response.json()
                        if isinstance(data, list):
                            return data
                        # crt.sh occasionally returns JSON error payloads or unexpected types
                        last_error = (
                            f"Unexpected JSON structure from crt.sh: "
                            f"expected list, got {type(data).__name__}"
                        )
                        logger.warning(
                            "crt.sh returned unexpected JSON structure on attempt %d/%d",
                            attempt,
                            MAX_ATTEMPTS,
                        )
                    except (json.JSONDecodeError, ValueError) as exc:
                        last_error = f"Failed to parse JSON response: {exc}"
                        logger.warning(
                            "crt.sh returned non-JSON response on attempt %d/%d: %s",
                            attempt,
                            MAX_ATTEMPTS,
                            exc,
                        )

            except httpx.TimeoutException as exc:
                last_error = f"Connection timed out: {exc}"
                logger.warning(
                    "Timeout querying crt.sh on attempt %d/%d: %s",
                    attempt,
                    MAX_ATTEMPTS,
                    exc,
                )
            except httpx.NetworkError as exc:
                last_error = f"Network connection error: {exc}"
                logger.warning(
                    "Network error querying crt.sh on attempt %d/%d: %s",
                    attempt,
                    MAX_ATTEMPTS,
                    exc,
                )

            # If there are attempts remaining, pause before the next attempt
            if attempt < MAX_ATTEMPTS:
                wait_time = RETRY_BACKOFF_SECONDS[attempt - 1]
                logger.debug("Waiting %ds before retry...", wait_time)
                time.sleep(wait_time)

    finally:
        if owns_client:
            active_client.close()

    # All retries exhausted
    raise CrtshError(
        f"Failed to retrieve data from crt.sh after {MAX_ATTEMPTS} attempts. "
        f"Last error: {last_error}"
    )


def parse_subdomains(crtsh_entries: list[dict[str, Any]], target_domain: str) -> list[str]:
    """Parse and clean subdomains from raw crt.sh records.

    Rules applied:
    - Splits multi-line 'name_value' fields.
    - Converts all names to lowercase.
    - Strips leading wildcard prefixes (e.g. '*.' or '*').
    - Discards invalid hostnames (emails, IP addresses, invalid characters).
    - Discards out-of-scope hostnames (must equal target_domain or end with '.<target_domain>').
    - Deduplicates and returns an alphabetically sorted list.

    Args:
        crtsh_entries: List of records returned from crt.sh JSON output.
        target_domain: The domain being searched (e.g. 'example.com').

    Returns:
        Sorted list of unique discovered subdomains.
    """
    normalized_target = target_domain.lower().strip(".")
    scope_suffix = f".{normalized_target}"
    unique_subdomains: set[str] = set()

    for entry in crtsh_entries:
        name_value = entry.get("name_value")
        if not name_value or not isinstance(name_value, str):
            continue

        for line in name_value.splitlines():
            cleaned = line.strip().lower()

            # Remove leading wildcard syntax (e.g. '*.sub.example.com' -> 'sub.example.com')
            if cleaned.startswith("*."):
                cleaned = cleaned[2:]
            elif cleaned.startswith("*"):
                cleaned = cleaned[1:]

            cleaned = cleaned.strip(".")

            # Validate syntax and filter out invalid names (e.g. emails)
            if not _is_valid_discovered_name(cleaned):
                continue

            # Scope check: must be target_domain or end with .target_domain
            if cleaned == normalized_target or cleaned.endswith(scope_suffix):
                unique_subdomains.add(cleaned)

    return sorted(unique_subdomains)
