"""Real network integration tests for TLS inspection.

Skipped by default in CI and standard test runs via `-m 'not integration'`.
Run explicitly with:
    pytest -m integration
"""

from __future__ import annotations

import pytest

from asm.headers_inspect import inspect_single_host


@pytest.mark.integration
def test_real_expired_badssl_com_has_expired_cert() -> None:
    """Scan expired.badssl.com over live network to verify expired cert detection."""
    target = "expired.badssl.com"
    res = inspect_single_host(target, "badssl.com")

    assert res.cert is not None, "Expected cert to be inspected on expired.badssl.com"
    assert res.cert.is_trusted is False, "Expected expired cert to fail verification"
    assert res.cert.expired is True, "Expected expired flag to be True on expired.badssl.com"
