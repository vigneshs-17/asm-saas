from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from asm.api.main import app
from asm.db.models import Domain, ScanChange, ScanRun
from asm.db.session import get_db

pytestmark = pytest.mark.db


def test_health_endpoint_healthy(client: TestClient) -> None:
    """GET /health returns 200 and healthy database status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["database"] == "connected"


def test_health_endpoint_db_failure(client: TestClient) -> None:
    """GET /health returns 503 and clean JSON error without stack traces when DB is unreachable."""
    def _failing_db():
        failing_session = MagicMock()
        failing_session.execute.side_effect = RuntimeError("Connection refused")
        yield failing_session

    app.dependency_overrides[get_db] = _failing_db
    try:
        response = client.get("/health")
        assert response.status_code == 503
        data = response.json()
        assert data["detail"]["status"] == "error"
        assert data["detail"]["database"] == "disconnected"
        assert "traceback" not in response.text
    finally:
        app.dependency_overrides.clear()


def test_create_domain_success(client: TestClient) -> None:
    """POST /domains registers a valid domain with explicit authorization."""
    payload = {
        "name": "example.com",
        "authorized": True,
        "authorization_note": "Explicit written permission from target owner",
    }
    response = client.post("/domains", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "example.com"
    assert data["authorized"] is True
    assert data["authorization_note"] == "Explicit written permission from target owner"
    assert "id" in data
    assert "created_at" in data


def test_create_domain_normalizes_input(client: TestClient) -> None:
    """POST /domains normalizes messy input (strips scheme, port, path, casing)."""
    payload = {
        "name": "https://DEV.EXAMPLE.COM:8443/api/v1",
        "authorized": True,
    }
    response = client.post("/domains", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "dev.example.com"


def test_create_domain_unauthorized_rejected(client: TestClient) -> None:
    """POST /domains rejects requests with authorized=False with HTTP 422."""
    payload = {
        "name": "unauthorized.com",
        "authorized": False,
    }
    response = client.post("/domains", json=payload)
    assert response.status_code == 422
    assert "authorized" in response.text.lower()


def test_create_domain_invalid_syntax_rejected(client: TestClient) -> None:
    """POST /domains rejects IP addresses and invalid RFC domain labels with HTTP 422."""
    # Test IP address rejection
    ip_res = client.post("/domains", json={"name": "192.168.1.1", "authorized": True})
    assert ip_res.status_code == 422
    assert "invalid domain" in ip_res.text.lower()

    # Test invalid hyphen placement
    hyphen_res = client.post("/domains", json={"name": "-invalid-.com", "authorized": True})
    assert hyphen_res.status_code == 422
    assert "invalid domain" in hyphen_res.text.lower()


def test_create_domain_duplicate_conflict(client: TestClient) -> None:
    """POST /domains returns HTTP 409 Conflict when attempting to register a duplicate domain."""
    payload = {"name": "unique.com", "authorized": True}
    first_res = client.post("/domains", json=payload)
    assert first_res.status_code == 201

    # Attempt duplicate registration
    dup_res = client.post("/domains", json=payload)
    assert dup_res.status_code == 409
    assert "already exists" in dup_res.text


def test_list_domains(client: TestClient) -> None:
    """GET /domains returns all registered domains in ascending ID order."""
    client.post("/domains", json={"name": "alpha.com", "authorized": True})
    client.post("/domains", json={"name": "beta.com", "authorized": True})

    response = client.get("/domains")
    assert response.status_code == 200
    data = response.json()
    names = [d["name"] for d in data]
    assert "alpha.com" in names
    assert "beta.com" in names


def test_get_domain_by_id_success(client: TestClient) -> None:
    """GET /domains/{id} returns domain details for an existing ID."""
    create_res = client.post("/domains", json={"name": "lookup.com", "authorized": True})
    domain_id = create_res.json()["id"]

    get_res = client.get(f"/domains/{domain_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == domain_id
    assert get_res.json()["name"] == "lookup.com"


def test_get_domain_by_id_not_found(client: TestClient) -> None:
    """GET /domains/{id} returns 404 for a non-existent ID."""
    response = client.get("/domains/999999")
    assert response.status_code == 404
    assert "not found" in response.text.lower()


def test_test_safety_check_rejects_non_test_database() -> None:
    """Safety check fails if TEST_DATABASE_URL does not end with '_test'."""
    from tests.conftest import validate_test_database_url

    with pytest.raises(pytest.fail.Exception, match="Safety check failed"):
        validate_test_database_url("postgresql+psycopg://user:pass@localhost:5432/asm_prod")


def test_get_domain_changes_not_found(client: TestClient) -> None:
    """GET /domains/{id}/changes returns 404 for unknown domain."""
    response = client.get("/domains/999999/changes")
    assert response.status_code == 404
    assert "not found" in response.text.lower()


def test_get_scan_changes_not_found(client: TestClient) -> None:
    """GET /scans/{id}/changes returns 404 for unknown scan."""
    response = client.get("/scans/999999/changes")
    assert response.status_code == 404
    assert "not found" in response.text.lower()


def test_get_domain_changes_success_and_filters(
    client: TestClient, db_session: Session
) -> None:
    """GET /domains/{id}/changes returns newest-first changes with filtering and pagination."""
    domain = Domain(name="api-changes.com", authorized=True)
    db_session.add(domain)
    db_session.flush()

    run1 = ScanRun(domain_id=domain.id, status="succeeded")
    run2 = ScanRun(domain_id=domain.id, status="succeeded")
    db_session.add_all([run1, run2])
    db_session.flush()

    t_now = datetime.now(UTC)
    t_earlier = t_now - timedelta(hours=1)

    c1 = ScanChange(
        domain_id=domain.id,
        scan_run_id=run2.id,
        baseline_scan_run_id=run1.id,
        change_type="PORT_NEWLY_OPEN",
        category="exposure",
        severity="CRITICAL",
        asset="api-changes.com",
        detail="3306",
        evidence="portscan",
        observed_at=t_earlier,
    )
    c2 = ScanChange(
        domain_id=domain.id,
        scan_run_id=run2.id,
        baseline_scan_run_id=run1.id,
        change_type="SECURITY_HEADER_REMOVED",
        category="exposure",
        severity="LOW",
        asset="api-changes.com",
        detail="Strict-Transport-Security",
        evidence="inspect",
        observed_at=t_now,
    )
    db_session.add_all([c1, c2])
    db_session.flush()

    # 1. Fetch all changes (newest first)
    res = client.get(f"/domains/{domain.id}/changes")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 2
    assert data[0]["change_type"] == "SECURITY_HEADER_REMOVED"
    assert data[1]["change_type"] == "PORT_NEWLY_OPEN"

    # 2. Filter by severity
    res_crit = client.get(f"/domains/{domain.id}/changes?severity=CRITICAL")
    assert res_crit.status_code == 200
    crit_data = res_crit.json()
    assert len(crit_data) == 1
    assert crit_data[0]["detail"] == "3306"

    # 3. Filter by since
    since_iso = (t_now - timedelta(minutes=30)).isoformat()
    res_since = client.get(f"/domains/{domain.id}/changes?since={since_iso}")
    assert res_since.status_code == 200
    since_data = res_since.json()
    assert len(since_data) == 1
    assert since_data[0]["change_type"] == "SECURITY_HEADER_REMOVED"

    # 4. Pagination
    res_pag = client.get(f"/domains/{domain.id}/changes?limit=1&offset=1")
    assert res_pag.status_code == 200
    pag_data = res_pag.json()
    assert len(pag_data) == 1
    assert pag_data[0]["change_type"] == "PORT_NEWLY_OPEN"


def test_get_scan_changes_success(client: TestClient, db_session: Session) -> None:
    """GET /scans/{id}/changes returns changes for a specific scan run."""
    domain = Domain(name="scan-changes.com", authorized=True)
    db_session.add(domain)
    db_session.flush()

    run1 = ScanRun(domain_id=domain.id, status="succeeded")
    run2 = ScanRun(domain_id=domain.id, status="succeeded")
    db_session.add_all([run1, run2])
    db_session.flush()

    c1 = ScanChange(
        domain_id=domain.id,
        scan_run_id=run2.id,
        baseline_scan_run_id=run1.id,
        change_type="PORT_NEWLY_OPEN",
        category="exposure",
        severity="HIGH",
        asset="scan-changes.com",
        detail="3389",
        evidence="portscan",
        observed_at=datetime.now(UTC),
    )
    db_session.add(c1)
    db_session.flush()

    res = client.get(f"/scans/{run2.id}/changes")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 1
    assert data[0]["change_type"] == "PORT_NEWLY_OPEN"
    assert data[0]["detail"] == "3389"
    assert data[0]["scan_run_id"] == run2.id


def test_changes_endpoints_not_found_and_validation(
    client: TestClient, db_session: Session
) -> None:
    """GET /domains/{id}/changes and /scans/{id}/changes return 404 on unknown IDs
    and 422 on invalid since.
    """
    # 404 for unknown domain
    res_domain = client.get("/domains/999999/changes")
    assert res_domain.status_code == 404
    assert "Domain with ID 999999 not found" in res_domain.json()["detail"]

    # 404 for unknown scan
    res_scan = client.get("/scans/999999/changes")
    assert res_scan.status_code == 404
    assert "Scan run with ID 999999 not found" in res_scan.json()["detail"]

    # 422 for invalid since datetime
    domain = Domain(name="validation-test.com", authorized=True)
    db_session.add(domain)
    db_session.flush()

    res_invalid_since = client.get(f"/domains/{domain.id}/changes?since=not-a-datetime")
    assert res_invalid_since.status_code == 422
    assert "Invalid ISO-8601" in res_invalid_since.json()["detail"]



