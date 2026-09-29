"""API endpoint and database integration tests for ASM SaaS."""

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from asm.api.main import app
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

