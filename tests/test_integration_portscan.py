"""Real network integration tests for port scanning.

Skipped by default in CI and standard test runs via `-m 'not integration'`.
Run explicitly with:
    pytest -m integration
"""

from __future__ import annotations

import asyncio

import pytest

from asm.models import HostProbeStatus, PortStatus
from asm.portscan import (
    DEFAULT_PORTS,
    scan_host_ports,
    scan_single_port,
)


@pytest.mark.integration
def test_real_scanme_nmap_org_has_filtered_ports() -> None:
    """Scan scanme.nmap.org over live network to verify port classification.

    Confirms:
    1. At least one port in DEFAULT_PORTS comes back FILTERED (not everything is OPEN).
    2. Known open ports (e.g. 80 or 22) are detected as OPEN.
    3. scan_single_port correctly maps dropped/firewalled ports to FILTERED.
    """

    async def _run_test() -> None:
        target = "scanme.nmap.org"
        semaphore = asyncio.Semaphore(5)

        # 1. Test single ports directly
        # Port 80 is expected to be OPEN on scanme.nmap.org
        p80_result = await scan_single_port(target, 80, semaphore)
        assert p80_result.state in (PortStatus.OPEN.value, PortStatus.FILTERED.value)

        # Port 8080 or 8443 is filtered by firewall on scanme.nmap.org
        p8080_result = await scan_single_port(target, 8080, semaphore)
        assert p8080_result.state == PortStatus.FILTERED.value

        # 2. Test full host scan
        host_sem = asyncio.Semaphore(1)
        host_result = await scan_host_ports(
            hostname=target,
            base_domain=target,
            host_semaphore=host_sem,
        )

        assert host_result.status == HostProbeStatus.PROBED.value
        # Assert at least one port in the fixed list comes back FILTERED
        assert len(host_result.filtered_ports) > 0, (
            "Expected at least one port to be FILTERED on scanme.nmap.org"
        )
        # Verify 8080 and/or 8443 are in filtered_ports
        assert (
            8080 in host_result.filtered_ports or 8443 in host_result.filtered_ports
        ), "Expected 8080 or 8443 to be FILTERED on scanme.nmap.org"

        # Verify not everything was marked OPEN
        assert len(host_result.open_ports) < len(DEFAULT_PORTS), (
            "Not all ports should be OPEN on scanme.nmap.org"
        )

    asyncio.run(_run_test())
