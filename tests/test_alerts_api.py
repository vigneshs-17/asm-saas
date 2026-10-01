"""API integration tests for domain alerts configuration and notification history."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from asm.api.main import app
from asm.db.models import AlertNotification, Domain


@pytest.fixture
def client(db_engine):
    """FastAPI TestClient configured with test database."""
    from asm.db.session import get_db

    session_factory = sessionmaker(bind=db_engine)

    def override_get_db():
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.mark.db
def test_alerts_endpoints_404_on_unknown_domain(
    client: TestClient, db_engine, clean_db: None
) -> None:
    """Alerts endpoints must return 404 for non-existent domains."""
    res = client.put(
        "/domains/99999/alerts",
        json={
            "alerts_enabled": True,
            "alert_emails": ["ops@example.com"],
            "alert_min_severity": "HIGH",
        },
    )
    assert res.status_code == 404

    res = client.get("/domains/99999/alert-notifications")
    assert res.status_code == 404


@pytest.mark.db
def test_alerts_endpoint_422_on_unauthorized_domain(
    client: TestClient, db_engine, clean_db: None
) -> None:
    """Configuring alerts on an unauthorized domain must return 422."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        domain = Domain(name="unauth-alerts.com", authorized=False)
        session.add(domain)
        session.commit()
        domain_id = domain.id

    res = client.put(
        f"/domains/{domain_id}/alerts",
        json={
            "alerts_enabled": True,
            "alert_emails": ["ops@example.com"],
            "alert_min_severity": "HIGH",
        },
    )
    assert res.status_code == 422
    assert "not authorized" in res.json()["detail"].lower()


@pytest.mark.db
def test_alerts_configure_and_disable(client: TestClient, db_engine, clean_db: None) -> None:
    """Configuring alerts, updating min severity, and disabling with empty list succeeds."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        domain = Domain(name="auth-alerts.com", authorized=True)
        session.add(domain)
        session.commit()
        domain_id = domain.id

    # 1. Enable alerts with 2 emails and HIGH threshold
    res = client.put(
        f"/domains/{domain_id}/alerts",
        json={
            "alerts_enabled": True,
            "alert_emails": ["sec@example.com", "ops@example.com"],
            "alert_min_severity": "HIGH",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["alerts_enabled"] is True
    assert data["alert_emails"] == ["sec@example.com", "ops@example.com"]
    assert data["alert_min_severity"] == "HIGH"

    # 2. Disable alerts with empty email list
    res = client.put(
        f"/domains/{domain_id}/alerts",
        json={
            "alerts_enabled": False,
            "alert_emails": [],
            "alert_min_severity": "MEDIUM",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["alerts_enabled"] is False
    assert data["alert_emails"] == []


@pytest.mark.db
def test_list_alert_notifications_paginated_and_body(
    client: TestClient, db_engine, clean_db: None
) -> None:
    """Listing alert notifications returns entries newest first with full body."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        from asm.db.scans import enqueue_scan

        domain = Domain(name="history-alerts.com", authorized=True)
        session.add(domain)
        session.flush()

        scan = enqueue_scan(session, domain.id, trigger="manual")
        session.flush()

        n1 = AlertNotification(
            domain_id=domain.id,
            scan_run_id=scan.id,
            recipient="one@example.com",
            subject="Subject 1",
            body="Full Body 1 text",
            status="sent",
        )
        n2 = AlertNotification(
            domain_id=domain.id,
            scan_run_id=scan.id,
            recipient="two@example.com",
            subject="Subject 2",
            body="Full Body 2 text",
            status="pending",
        )
        session.add_all([n1, n2])
        session.commit()
        domain_id = domain.id

    res = client.get(f"/domains/{domain_id}/alert-notifications")
    assert res.status_code == 200
    notifications = res.json()
    assert len(notifications) == 2
    # Verify full body is included in response
    assert notifications[0]["body"] in ("Full Body 1 text", "Full Body 2 text")
    assert notifications[1]["body"] in ("Full Body 1 text", "Full Body 2 text")

    # Filter by status
    res = client.get(f"/domains/{domain_id}/alert-notifications?status=pending")
    assert res.status_code == 200
    pending = res.json()
    assert len(pending) == 1
    assert pending[0]["recipient"] == "two@example.com"
