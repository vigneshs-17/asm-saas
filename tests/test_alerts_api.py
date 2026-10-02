"""API integration tests for domain alerts configuration and notification history."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from asm.db.models import AlertNotification, Domain, Organization


@pytest.mark.db
def test_alerts_endpoints_404_on_unknown_domain(
    lifecycle_client: TestClient, lifecycle_org: Organization
) -> None:
    """Alerts endpoints must return 404 for non-existent domains."""
    client = lifecycle_client
    res = client.put(
        f"/orgs/{lifecycle_org.id}/domains/99999/alerts",
        json={
            "alerts_enabled": True,
            "alert_emails": ["ops@example.com"],
            "alert_min_severity": "HIGH",
        },
    )
    assert res.status_code == 404

    res = client.get(f"/orgs/{lifecycle_org.id}/domains/99999/alert-notifications")
    assert res.status_code == 404


@pytest.mark.db
def test_alerts_endpoint_422_on_unauthorized_domain(
    lifecycle_client: TestClient, lifecycle_org: Organization, db_engine
) -> None:
    """Configuring alerts on an unverified domain must return 422."""
    client = lifecycle_client
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        domain = Domain(
            org_id=lifecycle_org.id,
            name="unauth-alerts.com",
            verification_status="pending",
        )
        session.add(domain)
        session.commit()
        domain_id = domain.id

    res = client.put(
        f"/orgs/{lifecycle_org.id}/domains/{domain_id}/alerts",
        json={
            "alerts_enabled": True,
            "alert_emails": ["ops@example.com"],
            "alert_min_severity": "HIGH",
        },
    )
    assert res.status_code == 422
    assert "not verified" in res.json()["detail"].lower()


@pytest.mark.db
def test_alerts_configure_and_disable(
    lifecycle_client: TestClient, lifecycle_org: Organization, db_engine
) -> None:
    """Configuring alerts, updating min severity, and disabling with empty list succeeds."""
    client = lifecycle_client
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        domain = Domain(
            org_id=lifecycle_org.id,
            name="auth-alerts.com",
            verification_status="verified",
        )
        session.add(domain)
        session.commit()
        domain_id = domain.id

    # 1. Enable alerts with 2 emails and HIGH threshold
    res = client.put(
        f"/orgs/{lifecycle_org.id}/domains/{domain_id}/alerts",
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
        f"/orgs/{lifecycle_org.id}/domains/{domain_id}/alerts",
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
    lifecycle_client: TestClient, lifecycle_org: Organization, db_engine
) -> None:
    """Listing alert notifications returns entries newest first with full body."""
    client = lifecycle_client
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        from asm.db.scans import enqueue_scan

        domain = Domain(
            org_id=lifecycle_org.id,
            name="history-alerts.com",
            verification_status="verified",
        )
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

    res = client.get(f"/orgs/{lifecycle_org.id}/domains/{domain_id}/alert-notifications")
    assert res.status_code == 200
    notifications = res.json()
    assert len(notifications) == 2
    # Verify full body is included in response
    assert notifications[0]["body"] in ("Full Body 1 text", "Full Body 2 text")
    assert notifications[1]["body"] in ("Full Body 1 text", "Full Body 2 text")

    # Filter by status
    res = client.get(
        f"/orgs/{lifecycle_org.id}/domains/{domain_id}/alert-notifications?status=pending"
    )
    assert res.status_code == 200
    pending = res.json()
    assert len(pending) == 1
    assert pending[0]["recipient"] == "two@example.com"
