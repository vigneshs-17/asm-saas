"""Concurrency and race-condition tests using multi-threaded separate database connections."""

import concurrent.futures
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from asm.api.main import app
from asm.db.models import Domain, Organization, ScanRun, ScanStage
from asm.worker.worker import ASMWorker

pytestmark = pytest.mark.db


def test_concurrent_workers_skip_locked(clean_db, db_engine):
    """Verify that multiple concurrent workers claiming with SKIP LOCKED never double-claim."""
    # 1. Setup: 2 domains, each with 1 queued scan run
    with Session(db_engine) as session:
        org = Organization(name="Concurrency Test Org")
        session.add(org)
        session.flush()

        domain1 = Domain(org_id=org.id, name="skip-locked-1.com", authorized=True)
        domain2 = Domain(org_id=org.id, name="skip-locked-2.com", authorized=True)
        session.add_all([domain1, domain2])
        session.commit()

        run1 = ScanRun(domain_id=domain1.id, status="queued")
        run2 = ScanRun(domain_id=domain2.id, status="queued")
        session.add_all([run1, run2])
        session.flush()

        for r in (run1, run2):
            for stage_name in ("discover", "probe", "portscan", "inspect", "score"):
                session.add(ScanStage(scan_run_id=r.id, stage=stage_name, status="pending"))
        session.commit()
        run1_id = run1.id
        run2_id = run2.id

    # 2. Launch 3 concurrent workers in separate threads with independent sessions/connections
    results: list[Any] = []

    def _worker_claim(worker_num: int):
        worker = ASMWorker(engine=db_engine, worker_id=f"worker-{worker_num}")
        return worker.claim_next_job()

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = [executor.submit(_worker_claim, i) for i in range(3)]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    # Exactly 2 claims should succeed with distinct run IDs; 1 should return None
    claimed_jobs = [r for r in results if r is not None]
    assert len(claimed_jobs) == 2

    claimed_run_ids = {r[0] for r in claimed_jobs}
    assert claimed_run_ids == {run1_id, run2_id}

    none_jobs = [r for r in results if r is None]
    assert len(none_jobs) == 1


def test_concurrent_posts_single_active_scan(
    lifecycle_client: TestClient, db_engine, lifecycle_org: Organization
):
    """Verify that concurrent POSTs for the same domain result in 1 active run and 409 conflict."""
    # 1. Create domain
    with Session(db_engine) as session:
        domain = Domain(
            org_id=lifecycle_org.id,
            name="active-scan-race.com",
            authorized=True,
        )
        session.add(domain)
        session.commit()
        domain_id = domain.id

    # 2. Send 2 concurrent POSTs across separate threads
    def _send_post():
        with TestClient(app) as test_client:
            return test_client.post(f"/orgs/{lifecycle_org.id}/domains/{domain_id}/scans")

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(_send_post)
        f2 = executor.submit(_send_post)
        r1 = f1.result()
        r2 = f2.result()

    statuses = sorted([r1.status_code, r2.status_code])
    assert statuses == [202, 409]

    # Verify 409 payload contains active_scan_id
    conflict_resp = r1 if r1.status_code == 409 else r2
    conflict_json = conflict_resp.json()
    assert "active_scan_id" in conflict_json
    assert conflict_json["active_scan_id"] > 0


def test_idempotent_post_while_running(
    lifecycle_client: TestClient, db_engine, lifecycle_org: Organization
):
    """Verify that an Idempotency-Key matching an active run returns 200 with that run, not 409."""
    # 1. Create domain
    with Session(db_engine) as session:
        domain = Domain(
            org_id=lifecycle_org.id,
            name="idemp-running.com",
            authorized=True,
        )
        session.add(domain)
        session.commit()
        domain_id = domain.id

    client = lifecycle_client

    # 2. First POST with Idempotency-Key
    resp1 = client.post(
        f"/orgs/{lifecycle_org.id}/domains/{domain_id}/scans",
        headers={"Idempotency-Key": "unique-token-999"},
    )
    assert resp1.status_code == 202
    scan_id = resp1.json()["id"]

    # 3. Simulate worker claiming the job -> moves to 'running'
    with Session(db_engine) as session:
        run = session.get(ScanRun, scan_id)
        run.status = "running"
        session.commit()

    # 4. Duplicate POST with same Idempotency-Key while scan is running
    resp2 = client.post(
        f"/orgs/{lifecycle_org.id}/domains/{domain_id}/scans",
        headers={"Idempotency-Key": "unique-token-999"},
    )
    assert resp2.status_code == 200
    assert resp2.json()["id"] == scan_id
    assert resp2.json()["status"] == "running"
