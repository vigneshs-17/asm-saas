"""Real network integration tests for port scanning.

Skipped by default in CI and standard test runs via `-m 'not integration'`.
Run explicitly with:
    pytest -m integration
"""

from __future__ import annotations

import asyncio

import pytest

from asm.models import HostProbeStatus
from asm.portscan import scan_host_ports


@pytest.mark.integration
def test_real_scanme_nmap_org_has_open_and_filtered_ports() -> None:
    """Scan scanme.nmap.org over live network to verify port classification.

    Confirms:
    1. At least one port in the fixed list is OPEN.
    2. At least one port in the fixed list is FILTERED.
    """

    async def _run_test() -> None:
        target = "scanme.nmap.org"
        host_sem = asyncio.Semaphore(1)
        host_result = await scan_host_ports(
            hostname=target,
            base_domain=target,
            host_semaphore=host_sem,
        )

        assert host_result.status == HostProbeStatus.PROBED.value
        # Assert at least one port is OPEN and at least one is FILTERED
        assert len(host_result.open_ports) > 0, (
            "Expected at least one port in fixed list to be OPEN on scanme.nmap.org"
        )
        assert len(host_result.filtered_ports) > 0, (
            "Expected at least one port in fixed list to be FILTERED on scanme.nmap.org"
        )

    asyncio.run(_run_test())
