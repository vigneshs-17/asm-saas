"""API tests for domain scan scheduling (PUT /domains/{id}/schedule)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from asm.db.models import Domain, ScanRun


@pytest.mark.db
def test_schedule_endpoint_not_found(client: TestClient) -> None:
    """PUT /domains/{id}/schedule returns 404 for non-existent domain ID."""
    res = client.put("/domains/999999/schedule", json={"interval_hours": 24})
    assert res.status_code == 404
    assert "Domain with ID 999999 not found" in res.json()["detail"]


@pytest.mark.db
def test_schedule_interval_bounds_validation(client: TestClient, db_session: Session) -> None:
    """Interval outside 6..720 is rejected with 422 Unprocessable Entity."""
    domain = Domain(name="sched-bounds.com", authorized=True)
    db_session.add(domain)
    db_session.flush()

    # < 6 rejected
    res_low = client.put(f"/domains/{domain.id}/schedule", json={"interval_hours": 5})
    assert res_low.status_code == 422

    # > 720 rejected
    res_high = client.put(f"/domains/{domain.id}/schedule", json={"interval_hours": 721})
    assert res_high.status_code == 422

    # Lower bound (6) accepted
    res_min = client.put(f"/domains/{domain.id}/schedule", json={"interval_hours": 6})
    assert res_min.status_code == 200
    assert res_min.json()["scan_interval_hours"] == 6

    # Upper bound (720) accepted
    res_max = client.put(f"/domains/{domain.id}/schedule", json={"interval_hours": 720})
    assert res_max.status_code == 200
    assert res_max.json()["scan_interval_hours"] == 720


@pytest.mark.db
def test_schedule_unauthorized_domain_rejected(client: TestClient, db_session: Session) -> None:
    """Enabling a schedule on an unauthorized domain returns 422 matching POST /scans."""
    domain = Domain(name="sched-unauth.com", authorized=False)
    db_session.add(domain)
    db_session.flush()

    res = client.put(f"/domains/{domain.id}/schedule", json={"interval_hours": 24})
    assert res.status_code == 422
    assert "not authorized for scanning" in res.json()["detail"]


@pytest.mark.db
def test_schedule_enable_from_null_sets_next_scan_at_now(
    client: TestClient, db_session: Session
) -> None:
    """Enabling schedule from null sets next_scan_at to current database time."""
    domain = Domain(name="sched-enable.com", authorized=True, scan_interval_hours=None)
    db_session.add(domain)
    db_session.flush()

    t_before = datetime.now(UTC) - timedelta(seconds=2)
    res = client.put(f"/domains/{domain.id}/schedule", json={"interval_hours": 24})
    t_after = datetime.now(UTC) + timedelta(seconds=2)

    assert res.status_code == 200
    data = res.json()
    assert data["scan_interval_hours"] == 24
    assert data["next_scan_at"] is not None

    next_dt = datetime.fromisoformat(data["next_scan_at"]).replace(tzinfo=UTC)
    assert t_before <= next_dt <= t_after


@pytest.mark.db
def test_schedule_change_existing_interval_advances_next_scan_at(
    client: TestClient, db_session: Session
) -> None:
    """Changing an existing interval sets next_scan_at = now() + new interval,
    not triggering an immediate scan.
    """
    domain = Domain(
        name="sched-change.com",
        authorized=True,
        scan_interval_hours=12,
        next_scan_at=datetime.now(UTC),
    )
    db_session.add(domain)
    db_session.flush()

    t_before = datetime.now(UTC) + timedelta(hours=48) - timedelta(seconds=5)
    res = client.put(f"/domains/{domain.id}/schedule", json={"interval_hours": 48})
    t_after = datetime.now(UTC) + timedelta(hours=48) + timedelta(seconds=5)

    assert res.status_code == 200
    data = res.json()
    assert data["scan_interval_hours"] == 48
    assert data["next_scan_at"] is not None

    next_dt = datetime.fromisoformat(data["next_scan_at"]).replace(tzinfo=UTC)
    # Proves interval change does NOT trigger an immediate scan
    assert t_before <= next_dt <= t_after


@pytest.mark.db
def test_schedule_disable_with_null(client: TestClient, db_session: Session) -> None:
    """Setting interval_hours: null disables schedule, clearing scan_interval_hours
    and next_scan_at.
    """
    domain = Domain(
        name="sched-disable.com",
        authorized=True,
        scan_interval_hours=24,
        next_scan_at=datetime.now(UTC),
    )
    db_session.add(domain)
    db_session.flush()

    res = client.put(f"/domains/{domain.id}/schedule", json={"interval_hours": None})
    assert res.status_code == 200
    data = res.json()
    assert data["scan_interval_hours"] is None
    assert data["next_scan_at"] is None

    # Verify GET /domains/{id} reflects the null schedule
    res_get = client.get(f"/domains/{domain.id}")
    assert res_get.status_code == 200
    assert res_get.json()["scan_interval_hours"] is None
    assert res_get.json()["next_scan_at"] is None


@pytest.mark.db
def test_shared_enqueue_used_by_post_scan_sets_manual_trigger(
    client: TestClient, db_session: Session
) -> None:
    """POST /domains/{id}/scans uses shared enqueue_scan and sets trigger to 'manual'."""
    domain = Domain(name="post-manual-trigger.com", authorized=True)
    db_session.add(domain)
    db_session.flush()

    res = client.post(f"/domains/{domain.id}/scans")
    assert res.status_code == 202
    data = res.json()
    assert data["trigger"] == "manual"

    # Verify persisted in database
    run = db_session.get(ScanRun, data["id"])
    assert run is not None
    assert run.trigger == "manual"
