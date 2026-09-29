"""TLS certificate inspection and validation for ASM SaaS.

Extracts certificate details, verifies trust, evaluates expiry and hostname
matching, and flags certificate anomalies (expired, expiring soon, self-signed,
hostname mismatch, deprecated TLS versions).
"""

from __future__ import annotations

import datetime
import logging
import socket
import ssl
from typing import Any

from asm.models import CertInfo

logger = logging.getLogger(__name__)

DEPRECATED_TLS_VERSIONS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}


def matches_hostname(
    hostname: str,
    san_dns_list: list[str],
    common_name: str | None,
) -> bool:
    """Check if hostname matches any SAN DNS entry or common name (RFC 6125).

    Evaluates exact matches and single-level wildcard domains (*.example.com).
    Wildcards only match a single DNS label.

    Args:
        hostname: The hostname being checked.
        san_dns_list: List of DNS names from Subject Alternative Names.
        common_name: Common Name (CN) from Subject.

    Returns:
        True if the hostname matches, False otherwise.
    """
    # Prefer SAN if present; fallback to CN if no SANs exist
    names_to_check = san_dns_list if san_dns_list else ([common_name] if common_name else [])
    clean_host = hostname.lower().strip(".")

    for pattern in names_to_check:
        clean_pattern = pattern.lower().strip(".")
        if clean_pattern.startswith("*."):
            # Single-level wildcard match (e.g. *.example.com matches sub.example.com)
            wildcard_suffix = clean_pattern[2:]
            if clean_host.endswith("." + wildcard_suffix):
                prefix = clean_host[: -(len(wildcard_suffix) + 1)]
                # Wildcard cannot span multiple dots (e.g. a.b.example.com does not match
                # *.example.com)
                if "." not in prefix and prefix:
                    return True
        elif clean_host == clean_pattern:
            return True

    return False


def format_rdn_tuple(rdn_tuple: tuple[Any, ...]) -> str:
    """Format an OpenSSL RDN tuple into a readable distinguished name string.

    Example input: ((('countryName', 'US'),), (('commonName', 'example.com'),))
    Example output: 'C=US, CN=example.com'

    Args:
        rdn_tuple: Nested tuple of attributes from ssl.getpeercert().

    Returns:
        Formatted comma-separated string.
    """
    if not rdn_tuple:
        return ""

    short_names = {
        "commonName": "CN",
        "organizationName": "O",
        "organizationalUnitName": "OU",
        "countryName": "C",
        "stateOrProvinceName": "ST",
        "localityName": "L",
    }

    parts: list[str] = []
    for rdn in rdn_tuple:
        for attr, val in rdn:
            key = short_names.get(attr, attr)
            parts.append(f"{key}={val}")

    return ", ".join(parts)


def extract_cn(rdn_tuple: tuple[Any, ...]) -> str | None:
    """Extract commonName value from an OpenSSL RDN tuple.

    Args:
        rdn_tuple: Nested tuple of attributes from ssl.getpeercert().

    Returns:
        Common Name string if found, None otherwise.
    """
    if not rdn_tuple:
        return None

    for rdn in rdn_tuple:
        for attr, val in rdn:
            if attr == "commonName":
                return str(val)

    return None


def parse_cert_dict(
    cert_dict: dict[str, Any],
    hostname: str,
    tls_version: str | None,
    is_trusted: bool,
    verify_error: str | None,
    source: str = "from_response",
    now_utc: datetime.datetime | None = None,
) -> CertInfo:
    """Parse a certificate dictionary from getpeercert() into a CertInfo model.

    Args:
        cert_dict: Parsed certificate dictionary from ssl.getpeercert().
        hostname: Hostname that was scanned.
        tls_version: Negotiated TLS protocol version (e.g. 'TLSv1.3').
        is_trusted: Whether the certificate verified against the system CA store.
        verify_error: Verification error message if verification failed.
        source: Method used ('from_response' or 'from_socket').
        now_utc: Optional current UTC datetime for testing.

    Returns:
        Populated CertInfo dataclass with flags.
    """
    if now_utc is None:
        now_utc = datetime.datetime.now(datetime.UTC)

    # 1. Subject CN and SANs
    subject_tuple = cert_dict.get("subject", ())
    issuer_tuple = cert_dict.get("issuer", ())
    subject_cn = extract_cn(subject_tuple)
    issuer_str = format_rdn_tuple(issuer_tuple)

    sans: list[str] = []
    for typ, val in cert_dict.get("subjectAltName", ()):
        if typ.lower() == "dns":
            sans.append(val)

    # 2. Validity period
    not_before_str = cert_dict.get("notBefore", "")
    not_after_str = cert_dict.get("notAfter", "")

    not_before_iso = ""
    not_after_iso = ""
    days_until_expiry = 0.0
    expired = False
    not_yet_valid = False

    if not_before_str:
        try:
            nb_secs = ssl.cert_time_to_seconds(not_before_str)
            nb_dt = datetime.datetime.fromtimestamp(nb_secs, tz=datetime.UTC)
            not_before_iso = nb_dt.isoformat()
            if now_utc < nb_dt:
                not_yet_valid = True
        except Exception:
            pass

    if not_after_str:
        try:
            na_secs = ssl.cert_time_to_seconds(not_after_str)
            na_dt = datetime.datetime.fromtimestamp(na_secs, tz=datetime.UTC)
            not_after_iso = na_dt.isoformat()
            diff_secs = (na_dt - now_utc).total_seconds()
            days_until_expiry = round(diff_secs / 86400, 1)
            if now_utc > na_dt or diff_secs < 0:
                expired = True
        except Exception:
            pass

    # 3. Serial number & flags
    serial_hex = cert_dict.get("serialNumber")
    if serial_hex and not isinstance(serial_hex, str):
        serial_hex = str(serial_hex)

    # Hostname matching (RFC 6125)
    hostname_matches = matches_hostname(hostname, sans, subject_cn)
    hostname_mismatch = not hostname_matches

    # Issuer equals subject (indicates a likely self-signed certificate, not definitive proof
    # of untrust)
    issuer_equals_subject = bool(subject_tuple and subject_tuple == issuer_tuple)

    # Expiring soon: between 0 and 30 days remaining
    expiring_soon = not expired and (0.0 <= days_until_expiry <= 30.0)

    # Deprecated TLS version negotiated
    deprecated_tls = bool(tls_version and tls_version in DEPRECATED_TLS_VERSIONS)

    return CertInfo(
        subject_cn=subject_cn,
        sans=sans,
        issuer=issuer_str,
        not_before=not_before_iso,
        not_after=not_after_iso,
        days_until_expiry=days_until_expiry,
        serial_hex=serial_hex,
        tls_version=tls_version,
        hostname_matches=hostname_matches,
        is_trusted=is_trusted,
        verify_error=verify_error,
        source=source,
        expired=expired,
        not_yet_valid=not_yet_valid,
        issuer_equals_subject=issuer_equals_subject,
        hostname_mismatch=hostname_mismatch,
        expiring_soon=expiring_soon,
        deprecated_tls=deprecated_tls,
    )


def connect_and_inspect_cert_socket(
    hostname: str,
    port: int = 443,
    timeout: float = 5.0,
    now_utc: datetime.datetime | None = None,
) -> CertInfo | None:
    """Connect to a host via direct ssl+socket to retrieve and evaluate its certificate.

    Follows a two-pass strategy using only public standard library APIs:
    - Pass 1 (Verified): Uses ssl.create_default_context(). If successful, reads
      the parsed peer certificate dictionary and records is_trusted=True.
    - Pass 2 (Unverified fallback): If verification fails, connects using a context
      with verify_mode=ssl.CERT_NONE and check_hostname=False. Records is_trusted=False
      and captures the verify error message.

    Args:
        hostname: Target domain or subdomain.
        port: TCP port (default 443).
        timeout: Socket connect timeout in seconds.
        now_utc: Optional current UTC datetime for testing.

    Returns:
        Populated CertInfo, or None if the host is genuinely unreachable.
    """
    # Pass 1: Verified connection
    try:
        ctx_verified = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx_verified.wrap_socket(sock, server_hostname=hostname) as sslsock:
                cert_dict = sslsock.getpeercert()
                tls_version = sslsock.version()
                if cert_dict:
                    return parse_cert_dict(
                        cert_dict=cert_dict,
                        hostname=hostname,
                        tls_version=tls_version,
                        is_trusted=True,
                        verify_error=None,
                        source="from_socket",
                        now_utc=now_utc,
                    )
    except (ssl.SSLCertVerificationError, ssl.SSLError) as exc:
        # TLS verification failed (e.g. self-signed, expired, invalid CA chain)
        verify_error = str(exc)
        logger.debug(
            "TLS verification failed for %s: %s; trying unverified fallback", hostname, exc
        )

        # Pass 2: Unverified connection using public standard library API
        # verify_mode=ssl.CERT_NONE allows us to complete the handshake and inspect TLS version
        try:
            ctx_unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_unverified.check_hostname = False
            ctx_unverified.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx_unverified.wrap_socket(sock, server_hostname=hostname) as sslsock:
                    tls_version = sslsock.version()
                    cert_dict = sslsock.getpeercert()

                    if cert_dict:
                        return parse_cert_dict(
                            cert_dict=cert_dict,
                            hostname=hostname,
                            tls_version=tls_version,
                            is_trusted=False,
                            verify_error=verify_error,
                            source="from_socket",
                            now_utc=now_utc,
                        )

                    # In standard OpenSSL/CPython, getpeercert() returns {} when CERT_NONE is set.
                    # We infer key security flags directly from the verified failure message.
                    err_lower = verify_error.lower()
                    expired = "expired" in err_lower
                    self_signed = "self signed" in err_lower or "self-signed" in err_lower
                    hostname_mismatch = "hostname" in err_lower or "match" in err_lower

                    deprecated_tls = bool(
                        tls_version and tls_version in DEPRECATED_TLS_VERSIONS
                    )

                    return CertInfo(
                        subject_cn=None,
                        sans=[],
                        issuer="",
                        not_before="",
                        not_after="",
                        days_until_expiry=0.0,
                        serial_hex=None,
                        tls_version=tls_version,
                        hostname_matches=not hostname_mismatch,
                        is_trusted=False,
                        verify_error=verify_error,
                        source="from_socket",
                        expired=expired,
                        not_yet_valid=False,
                        issuer_equals_subject=self_signed,
                        hostname_mismatch=hostname_mismatch,
                        expiring_soon=False,
                        deprecated_tls=deprecated_tls,
                    )
        except Exception as unverified_exc:
            logger.debug("Unverified socket fallback failed for %s: %s", hostname, unverified_exc)
            return None

    except (OSError, TimeoutError) as net_err:
        # Port 443 is genuinely unreachable, refused, or timed out
        logger.debug("Port 443 unreachable on %s: %s", hostname, net_err)
        return None

    return None
