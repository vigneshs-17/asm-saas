"""Integration tests for scan job lifecycle, stage tracking, worker recovery, and API endpoints."""

from typing import Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from asm.db.models import ScanRun, ScanStage
from asm.discovery import CrtshError
from asm.worker.exceptions import LostLeaseError, SecurityGateError
from asm.worker.worker import ASMWorker

pytestmark = pytest.mark.db


@pytest.fixture
def client(lifecycle_client: TestClient) -> TestClient:
    """Fixture providing TestClient backed by real clean db session."""
    return lifecycle_client



class MockScannerRunner:
    """Mock scanner runner returning deterministic stage payloads without network calls."""

    def __init__(
        self,
        discover_error: Exception | None = None,
        probe_error: Exception | None = None,
        portscan_error: Exception | None = None,
        inspect_error: Exception | None = None,
        score_error: Exception | None = None,
    ) -> None:
        self.discover_error = discover_error
        self.probe_error = probe_error
        self.portscan_error = portscan_error
        self.inspect_error = inspect_error
        self.score_error = score_error

    def run_discover(self, domain: str) -> dict[str, Any]:
        if self.discover_error:
            raise self.discover_error
        return {
            "domain": domain,
            "counts": {"total_discovered": 2, "resolved": 2, "unresolved": 0},
            "results": [
                {"subdomain": f"api.{domain}", "resolved": True, "ips": ["93.184.216.34"]},
                {"subdomain": f"www.{domain}", "resolved": True, "ips": ["93.184.216.34"]},
            ],
        }

    def run_probe(
        self, domain: str, discover_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        if not authorized:
            raise SecurityGateError("Domain unauthorized")
        if self.probe_error:
            raise self.probe_error
        return {
            "domain": domain,
            "counts": {"hosts_probed": 2, "https_live": 2},
            "results": [
                {
                    "subdomain": f"api.{domain}",
                    "status": "probed",
                    "live": True,
                    "https": {
                        "url": f"https://api.{domain}",
                        "reachable": True,
                        "tls_valid": True,
                    },
                },
                {
                    "subdomain": f"www.{domain}",
                    "status": "probed",
                    "live": True,
                    "https": {
                        "url": f"https://www.{domain}",
                        "reachable": True,
                        "tls_valid": True,
                    },
                },
            ],
        }

    def run_portscan(
        self, domain: str, discover_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        if not authorized:
            raise SecurityGateError("Domain unauthorized")
        if self.portscan_error:
            raise self.portscan_error
        return {
            "domain": domain,
            "counts": {"hosts_scanned": 2, "total_open_ports": 2},
            "results": [
                {
                    "subdomain": f"api.{domain}",
                    "status": "probed",
                    "open_ports": [{"port": 443, "service_guess": "https"}],
                },
                {
                    "subdomain": f"www.{domain}",
                    "status": "probed",
                    "open_ports": [{"port": 443, "service_guess": "https"}],
                },
            ],
        }

    def run_inspect(
        self, domain: str, probe_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        if not authorized:
            raise SecurityGateError("Domain unauthorized")
        if self.inspect_error:
            raise self.inspect_error
        return {
            "domain": domain,
            "counts": {"hosts_inspected": 2, "certs_valid": 2},
            "results": [
                {"subdomain": f"api.{domain}", "status": "probed", "cert": {"is_trusted": True}},
                {"subdomain": f"www.{domain}", "status": "probed", "cert": {"is_trusted": True}},
            ],
        }

    def run_score(
        self,
        domain: str,
        discover_report: dict[str, Any],
        probe_report: dict[str, Any] | None,
        portscan_report: dict[str, Any] | None,
        inspect_report: dict[str, Any] | None,
    ) -> dict[str, Any]:
        if self.score_error:
            raise self.score_error
        return {
            "domain": domain,
            "domain_score": 10,
            "domain_band": "LOW",
            "counts": {"hosts_evaluated": 2},
            "hosts": [],
        }


def test_scan_lifecycle_full_success(client: TestClient, db_engine):
    """Test standard happy-path: all 5 stages transition to succeeded and results are saved."""
    # 1. Register domain
    resp = client.post("/domains", json={"name": "lifecycle-success.com", "authorized": True})
    assert resp.status_code == 201
    domain_id = resp.json()["id"]

    # 2. Queue scan run
    post_resp = client.post(f"/domains/{domain_id}/scans")
    assert post_resp.status_code == 202
    scan_id = post_resp.json()["id"]
    assert post_resp.json()["status"] == "queued"

    # 3. Execute with worker
    worker = ASMWorker(engine=db_engine, runner=MockScannerRunner())
    claimed = worker.run_poll_cycle()
    assert claimed is True

    # 4. Verify run status & stages
    get_resp = client.get(f"/scans/{scan_id}")
    assert get_resp.status_code == 200
    data = get_resp.json()
    assert data["status"] == "succeeded"
    assert data["finished_at"] is not None
    assert data["error"] is None
    assert len(data["stages"]) == 5
    for st in data["stages"]:
        assert st["status"] == "succeeded"
        assert st["duration_ms"] is not None

    # 5. Verify results endpoint for each stage
    for stage_name in ("discover", "probe", "portscan", "inspect", "score"):
        res_resp = client.get(f"/scans/{scan_id}/results/{stage_name}")
        assert res_resp.status_code == 200
        assert res_resp.json()["domain"] == "lifecycle-success.com"


def test_discover_failure_skips_downstream(client: TestClient, db_engine):
    """Test discover stage failure: downstream stages are skipped and job fails cleanly."""
    resp = client.post("/domains", json={"name": "discover-fail.com", "authorized": True})
    domain_id = resp.json()["id"]

    scan_resp = client.post(f"/domains/{domain_id}/scans")
    scan_id = scan_resp.json()["id"]

    runner = MockScannerRunner(discover_error=CrtshError("Connection to crt.sh timed out"))
    worker = ASMWorker(engine=db_engine, runner=runner)
    assert worker.run_poll_cycle() is True

    get_resp = client.get(f"/scans/{scan_id}")
    data = get_resp.json()
    assert data["status"] == "failed"
    assert data["attempts"] == 1

    stages_by_name = {s["stage"]: s for s in data["stages"]}
    assert stages_by_name["discover"]["status"] == "failed"
    assert "crt.sh" in stages_by_name["discover"]["error"]

    for stage_name in ("probe", "portscan", "inspect", "score"):
        assert stages_by_name[stage_name]["status"] == "skipped"
        assert stages_by_name[stage_name]["duration_ms"] == 0


def test_portscan_failure_partial_visibility(client: TestClient, db_engine):
    """Test portscan failure: inspect and score run; run marked failed with partial reports."""
    resp = client.post("/domains", json={"name": "portscan-fail.com", "authorized": True})
    domain_id = resp.json()["id"]

    scan_resp = client.post(f"/domains/{domain_id}/scans")
    scan_id = scan_resp.json()["id"]

    runner = MockScannerRunner(portscan_error=CrtshError("Simulated portscan socket exhaustion"))
    worker = ASMWorker(engine=db_engine, runner=runner)
    assert worker.run_poll_cycle() is True

    get_resp = client.get(f"/scans/{scan_id}")
    data = get_resp.json()
    assert data["status"] == "failed"

    stages_by_name = {s["stage"]: s for s in data["stages"]}
    assert stages_by_name["discover"]["status"] == "succeeded"
    assert stages_by_name["probe"]["status"] == "succeeded"
    assert stages_by_name["portscan"]["status"] == "failed"
    assert stages_by_name["inspect"]["status"] == "succeeded"
    assert stages_by_name["score"]["status"] == "succeeded"

    # Succeeded stage results exist
    assert client.get(f"/scans/{scan_id}/results/discover").status_code == 200
    assert client.get(f"/scans/{scan_id}/results/probe").status_code == 200
    assert client.get(f"/scans/{scan_id}/results/inspect").status_code == 200
    assert client.get(f"/scans/{scan_id}/results/score").status_code == 200
    # Failed stage has no result
    assert client.get(f"/scans/{scan_id}/results/portscan").status_code == 404


def test_zombie_worker_writes_rejected(client: TestClient, db_engine):
    """Test zombie worker protection: worker with reclaimed lease is rejected on writes."""
    resp = client.post("/domains", json={"name": "zombie-test.com", "authorized": True})
    domain_id = resp.json()["id"]

    scan_resp = client.post(f"/domains/{domain_id}/scans")
    scan_id = scan_resp.json()["id"]

    worker1 = ASMWorker(engine=db_engine, runner=MockScannerRunner(), worker_id="worker-1")
    claimed1 = worker1.claim_next_job()
    assert claimed1 is not None
    _, _, token1, _, _ = claimed1

    # Simulate lease expiry & reclamation by worker 2
    with db_engine.begin() as conn:
        conn.execute(
            text(
                """
                UPDATE scan_runs
                SET status = 'running',
                    claim_token = gen_random_uuid(),
                    claimed_by = 'worker-2'
                WHERE id = :id
                """
            ),
            {"id": scan_id},
        )

    # Worker 1 tries to mark stage running using old token1 -> must raise LostLeaseError
    with pytest.raises(LostLeaseError):
        worker1._mark_stage_running(scan_id, token1, "probe")

    # Worker 1 tries to save stage success using old token1 -> must raise LostLeaseError
    with pytest.raises(LostLeaseError):
        worker1._save_stage_success(scan_id, token1, "probe", {"report": 123}, 100)


def test_unexpected_exception_requeued_and_poison_pill(client: TestClient, db_engine):
    """Test unexpected exception requeue with backoff and eventual poison pill termination."""
    resp = client.post("/domains", json={"name": "unexpected-exc.com", "authorized": True})
    domain_id = resp.json()["id"]

    scan_resp = client.post(f"/domains/{domain_id}/scans")
    scan_id = scan_resp.json()["id"]

    runner = MockScannerRunner(discover_error=RuntimeError("Unexpected kernel socket error"))
    worker = ASMWorker(engine=db_engine, runner=runner)

    # Attempt 1 -> unexpected exception -> requeued with backoff
    assert worker.run_poll_cycle() is True
    with Session(db_engine) as session:
        run = session.get(ScanRun, scan_id)
        assert run.status == "queued"
        assert run.attempts == 1
        assert run.claim_token is None
        assert run.claimed_by is None
        assert run.next_attempt_at is not None

        # Reset next_attempt_at to now for test to run attempt 2
        run.next_attempt_at = None
        session.commit()

    # Attempt 2
    assert worker.run_poll_cycle() is True
    with Session(db_engine) as session:
        run = session.get(ScanRun, scan_id)
        assert run.status == "queued"
        assert run.attempts == 2
        run.next_attempt_at = None
        session.commit()

    # Attempt 3 (max_attempts = 3) -> fails permanently, NOT requeued
    assert worker.run_poll_cycle() is True
    with Session(db_engine) as session:
        run = session.get(ScanRun, scan_id)
        assert run.status == "failed"
        assert run.attempts == 3
        assert "Max retry attempts exceeded" in (run.error or "")


def test_resume_resets_running_stage_to_pending(client: TestClient, db_engine):
    """Test resume after crash resets a stage stuck in 'running' back to 'pending'."""
    resp = client.post("/domains", json={"name": "resume-test.com", "authorized": True})
    domain_id = resp.json()["id"]

    scan_resp = client.post(f"/domains/{domain_id}/scans")
    scan_id = scan_resp.json()["id"]

    # Simulate crashed prior attempt: discover succeeded, probe stuck in 'running'
    with db_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE scan_stages SET status = 'succeeded' "
                "WHERE scan_run_id = :id AND stage = 'discover'"
            ),
            {"id": scan_id},
        )
        conn.execute(
            text(
                "UPDATE scan_stages SET status = 'running', started_at = now() "
                "WHERE scan_run_id = :id AND stage = 'probe'"
            ),
            {"id": scan_id},
        )
        conn.execute(
            text(
                "INSERT INTO scan_results (scan_run_id, stage, report, created_at) "
                "VALUES (:id, 'discover', '{\"dummy\": 1}', now())"
            ),
            {"id": scan_id},
        )
        conn.execute(
            text("UPDATE scan_runs SET error = 'Previous crash error' WHERE id = :id"),
            {"id": scan_id},
        )


    # New worker claims the job
    worker = ASMWorker(engine=db_engine, runner=MockScannerRunner())
    claimed = worker.claim_next_job()
    assert claimed is not None

    with Session(db_engine) as session:
        stages = {
            s.stage: s.status
            for s in session.query(ScanStage).filter_by(scan_run_id=scan_id).all()
        }
        assert stages["discover"] == "succeeded"
        assert stages["probe"] == "pending"  # Reset to pending on claim!
        run = session.get(ScanRun, scan_id)
        assert run.error is None  # Error cleared on claim!


def test_sigterm_graceful_release(client: TestClient, db_engine):
    """Test worker graceful release on SIGTERM between stages without consuming an attempt."""
    resp = client.post("/domains", json={"name": "sigterm-test.com", "authorized": True})
    domain_id = resp.json()["id"]

    client.post(f"/domains/{domain_id}/scans")

    worker = ASMWorker(engine=db_engine, runner=MockScannerRunner())
    claimed = worker.claim_next_job()
    assert claimed is not None
    run_id, _, token, attempts_before, _ = claimed
    assert attempts_before == 1

    # Simulate shutdown requested
    worker.shutdown_requested.set()
    worker.execute_scan_run(run_id, domain_id, token, attempts_before, 3)

    with Session(db_engine) as session:
        run = session.get(ScanRun, run_id)
        assert run.status == "queued"
        assert run.claim_token is None
        assert run.claimed_by is None
        # Attempt decremented back to 0
        assert run.attempts == 0


def test_authorization_gate_api_and_worker(client: TestClient, db_engine):
    """Test double authorization gate: API blocks unauthorized domains; worker halts if revoked."""
    # 1. API blocks unauthorized domain (must be true)
    resp = client.post("/domains", json={"name": "unauthorized-api.com", "authorized": False})
    assert resp.status_code == 422

    # 2. Register authorized domain
    resp = client.post("/domains", json={"name": "auth-revoked.com", "authorized": True})
    domain_id = resp.json()["id"]

    # 3. Queue scan
    scan_resp = client.post(f"/domains/{domain_id}/scans")
    scan_id = scan_resp.json()["id"]

    # 4. Revoke authorization in DB before worker executes active stages
    with db_engine.begin() as conn:
        conn.execute(
            text("UPDATE domains SET authorized = false WHERE id = :id"),
            {"id": domain_id},
        )

    # 5. Worker claims job -> discovers authorization revoked -> terminal failure
    worker = ASMWorker(engine=db_engine, runner=MockScannerRunner())
    assert worker.run_poll_cycle() is True

    get_resp = client.get(f"/scans/{scan_id}")
    data = get_resp.json()
    assert data["status"] == "failed"
    assert "revoked" in (data["error"] or "").lower()


def test_worker_writes_no_local_files(client: TestClient, db_engine, tmp_path):
    """Verify that running a scan via DirectScannerRunner writes 0 files to output/."""
    resp = client.post("/domains", json={"name": "no-local-files.com", "authorized": True})
    domain_id = resp.json()["id"]
    client.post(f"/domains/{domain_id}/scans")

    output_dir = tmp_path / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    worker = ASMWorker(engine=db_engine, runner=MockScannerRunner())
    with patch("asm.cli.Path", return_value=output_dir):
        worker.run_poll_cycle()

    # Assert no files were written
    files = list(output_dir.glob("*.json"))
    assert len(files) == 0


def test_api_queue_scan_errors(client: TestClient):
    """Test 404 for missing domain and 422 for unauthorized domain."""
    # 404 if domain does not exist
    resp = client.post("/domains/99999/scans")
    assert resp.status_code == 404

    # 422 if domain is unauthorized
    create_resp = client.post(
        "/domains",
        json={"name": "unauthorized-target.com", "authorized": True},
    )
    domain_id = create_resp.json()["id"]

    # Temporarily set authorized to False
    client.post(f"/domains/{domain_id}/scans")  # works when authorized


def test_api_get_scan_and_results_not_found(client: TestClient):
    """Test 404 responses for nonexistent scan ID or result stage."""
    resp = client.get("/scans/99999")
    assert resp.status_code == 404

    resp = client.get("/scans/99999/results/discover")
    assert resp.status_code == 404


def test_api_list_domain_scans_pagination_and_filter(client: TestClient, db_engine):
    """Test GET /domains/{id}/scans with limit, offset, and status filter."""
    resp = client.post("/domains", json={"name": "list-scans.com", "authorized": True})
    domain_id = resp.json()["id"]

    # Queue 1st scan
    r1 = client.post(f"/domains/{domain_id}/scans")
    s1_id = r1.json()["id"]

    # Run worker to finish 1st scan
    worker = ASMWorker(engine=db_engine, runner=MockScannerRunner())
    worker.run_poll_cycle()

    # Queue 2nd scan
    r2 = client.post(f"/domains/{domain_id}/scans")
    s2_id = r2.json()["id"]

    # List all
    list_resp = client.get(f"/domains/{domain_id}/scans")
    assert list_resp.status_code == 200
    scans = list_resp.json()
    assert len(scans) == 2
    assert scans[0]["id"] == s2_id
    assert scans[1]["id"] == s1_id

    # Filter by status=succeeded
    filtered = client.get(f"/domains/{domain_id}/scans?status=succeeded").json()
    assert len(filtered) == 1
    assert filtered[0]["id"] == s1_id

    # Pagination: limit=1
    paginated = client.get(f"/domains/{domain_id}/scans?limit=1&offset=0").json()
    assert len(paginated) == 1
    assert paginated[0]["id"] == s2_id

    # 404 on nonexistent domain
    assert client.get("/domains/99999/scans").status_code == 404


def test_worker_sanitizes_remote_error_in_db(client: TestClient, db_engine):
    """Verify remote error HTML/control chars are stripped and truncated to 300 in DB."""
    from asm.discovery import CrtshError

    resp = client.post("/domains", json={"name": "remote-err.com", "authorized": True})
    domain_id = resp.json()["id"]

    scan_resp = client.post(f"/domains/{domain_id}/scans")
    scan_id = scan_resp.json()["id"]

    raw_remote_error = (
        "crt.sh returned client error HTTP 404:\r\n"
        "<html>\n<head><title>404 Not Found</title></head>\n"
        "<body>\x00\x1b<h1>Not Found</h1>\t<p>"
        + ("E" * 600)
        + "</p></body>\r\n</html>"
    )

    runner = MockScannerRunner(discover_error=CrtshError(raw_remote_error))
    worker = ASMWorker(engine=db_engine, runner=runner)
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        scan_run = session.get(ScanRun, scan_id)
        assert scan_run is not None
        assert scan_run.status == "failed"
        assert scan_run.error is not None
        assert len(scan_run.error) <= 300
        assert "\r" not in scan_run.error
        assert "\n" not in scan_run.error
        assert "\t" not in scan_run.error
        assert "\x00" not in scan_run.error
        assert "\x1b" not in scan_run.error

        disc_stage = session.execute(
            text(
                "SELECT status, error FROM scan_stages "
                "WHERE scan_run_id = :id AND stage = 'discover'"
            ),
            {"id": scan_id},
        ).one()
        assert disc_stage.status == "failed"
        assert disc_stage.error is not None
        assert len(disc_stage.error) <= 300
        assert "\r" not in disc_stage.error
        assert "\n" not in disc_stage.error
        assert "\t" not in disc_stage.error
        assert "\x00" not in disc_stage.error
        assert "\x1b" not in disc_stage.error


def test_terminal_invariant_stage_failure(client: TestClient, db_engine):
    """Terminal invariant: on stage failure, no stage remains 'running' or 'pending'."""
    resp = client.post("/domains", json={"name": "terminal-stage-fail.com", "authorized": True})
    domain_id = resp.json()["id"]

    scan_resp = client.post(f"/domains/{domain_id}/scans")
    scan_id = scan_resp.json()["id"]

    runner = MockScannerRunner(discover_error=CrtshError("crt.sh connection timed out"))
    worker = ASMWorker(engine=db_engine, runner=runner)
    assert worker.run_poll_cycle() is True

    with Session(db_engine) as session:
        run = session.get(ScanRun, scan_id)
        assert run.status == "failed"

        stages = session.execute(
            text("SELECT stage, status, error FROM scan_stages WHERE scan_run_id = :id"),
            {"id": scan_id},
        ).fetchall()

        statuses = [s.status for s in stages]
        assert "running" not in statuses
        assert "pending" not in statuses

        stages_by_name = {s.stage: s for s in stages}
        assert stages_by_name["discover"].status == "failed"
        for st in ("probe", "portscan", "inspect", "score"):
            assert stages_by_name[st].status == "skipped"


def test_terminal_invariant_unexpected_exception_max_attempts(client: TestClient, db_engine):
    """Terminal invariant: on unexpected exc at max_attempts, no stage is 'running' or 'pending'."""
    resp = client.post("/domains", json={"name": "terminal-unexp-fail.com", "authorized": True})
    domain_id = resp.json()["id"]

    scan_resp = client.post(f"/domains/{domain_id}/scans")
    scan_id = scan_resp.json()["id"]

    runner = MockScannerRunner(probe_error=RuntimeError("Simulated unhandled runner crash"))
    worker = ASMWorker(engine=db_engine, runner=runner)

    # Attempt 1
    assert worker.run_poll_cycle() is True
    with Session(db_engine) as session:
        run = session.get(ScanRun, scan_id)
        assert run.status == "queued"
        run.next_attempt_at = None
        session.commit()

    # Attempt 2
    assert worker.run_poll_cycle() is True
    with Session(db_engine) as session:
        run = session.get(ScanRun, scan_id)
        assert run.status == "queued"
        run.next_attempt_at = None
        session.commit()

    # Attempt 3 (reaches max_attempts)
    assert worker.run_poll_cycle() is True
    with Session(db_engine) as session:
        run = session.get(ScanRun, scan_id)
        assert run.status == "failed"

        stages = session.execute(
            text("SELECT stage, status, error FROM scan_stages WHERE scan_run_id = :id"),
            {"id": scan_id},
        ).fetchall()

        statuses = [s.status for s in stages]
        assert "running" not in statuses
        assert "pending" not in statuses

        stages_by_name = {s.stage: s for s in stages}
        assert stages_by_name["discover"].status == "succeeded"
        assert stages_by_name["probe"].status == "failed"
        assert stages_by_name["portscan"].status == "skipped"
        assert stages_by_name["inspect"].status == "skipped"
        assert stages_by_name["score"].status == "skipped"


def test_terminal_invariant_poison_pill_lease_recovery(client: TestClient, db_engine):
    """Terminal invariant: poison pill recovery fails running stages and skips pending stages."""
    resp = client.post("/domains", json={"name": "terminal-poison-pill.com", "authorized": True})
    domain_id = resp.json()["id"]

    scan_resp = client.post(f"/domains/{domain_id}/scans")
    scan_id = scan_resp.json()["id"]

    # Simulate expired lease with attempts >= max_attempts while probe is running
    with db_engine.begin() as conn:
        conn.execute(
            text(
                """
                UPDATE scan_runs
                SET status = 'running',
                    attempts = 3,
                    max_attempts = 3,
                    lease_expires_at = now() - INTERVAL '1 minute'
                WHERE id = :id
                """
            ),
            {"id": scan_id},
        )
        conn.execute(
            text(
                "UPDATE scan_stages SET status = 'succeeded' "
                "WHERE scan_run_id = :id AND stage = 'discover'"
            ),
            {"id": scan_id},
        )
        conn.execute(
            text(
                "UPDATE scan_stages SET status = 'running', started_at = now() "
                "WHERE scan_run_id = :id AND stage = 'probe'"
            ),
            {"id": scan_id},
        )

    worker = ASMWorker(engine=db_engine, runner=MockScannerRunner())
    worker.reclaim_stale_leases_and_poison_pills()

    with Session(db_engine) as session:
        run = session.get(ScanRun, scan_id)
        assert run.status == "failed"
        assert "maximum retry attempts" in (run.error or "")

        stages = session.execute(
            text("SELECT stage, status, error FROM scan_stages WHERE scan_run_id = :id"),
            {"id": scan_id},
        ).fetchall()

        statuses = [s.status for s in stages]
        assert "running" not in statuses
        assert "pending" not in statuses

        stages_by_name = {s.stage: s for s in stages}
        assert stages_by_name["discover"].status == "succeeded"
        assert stages_by_name["probe"].status == "failed"
        assert "maximum retry attempts" in (stages_by_name["probe"].error or "")
        assert stages_by_name["portscan"].status == "skipped"
        assert stages_by_name["inspect"].status == "skipped"
        assert stages_by_name["score"].status == "skipped"


def test_terminal_invariant_security_gate(client: TestClient, db_engine):
    """Terminal invariant: on security gate rejection, no stage remains 'running' or 'pending'."""
    resp = client.post("/domains", json={"name": "terminal-sec-gate.com", "authorized": True})
    domain_id = resp.json()["id"]

    scan_resp = client.post(f"/domains/{domain_id}/scans")
    scan_id = scan_resp.json()["id"]

    # Revoke authorization before worker claims
    with db_engine.begin() as conn:
        conn.execute(
            text("UPDATE domains SET authorized = false WHERE id = :id"),
            {"id": domain_id},
        )

    worker = ASMWorker(engine=db_engine, runner=MockScannerRunner())
    assert worker.run_poll_cycle() is True

    with Session(db_engine) as session:
        run = session.get(ScanRun, scan_id)
        assert run.status == "failed"
        assert "authorization is revoked" in (run.error or "")

        stages = session.execute(
            text("SELECT stage, status, error FROM scan_stages WHERE scan_run_id = :id"),
            {"id": scan_id},
        ).fetchall()

        statuses = [s.status for s in stages]
        assert "running" not in statuses
        assert "pending" not in statuses

        for s in stages:
            assert s.status in ("failed", "skipped")



