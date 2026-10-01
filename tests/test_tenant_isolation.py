"""Comprehensive test suite for tenant isolation, IDOR prevention, role matrix, and admin move."""

import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from asm.admin import move_domain
from asm.api.deps import get_current_user
from asm.api.main import app
from asm.db.models import (
    AlertNotification,
    Domain,
    Membership,
    Organization,
    ScanChange,
    ScanResult,
    User,
)
from asm.db.scans import enqueue_scan
from asm.db.session import get_db

pytestmark = pytest.mark.db


def make_authenticated_client(db_session: Session, user: User) -> TestClient:
    """Create a TestClient authenticated as the specified real user."""
    def _override_db():
        yield db_session

    def _override_user():
        return user

    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[get_current_user] = _override_user
    return TestClient(app)


@pytest.fixture
def two_tenants(db_session: Session):
    """Fixture providing two completely independent organizations with users, domains, scans."""
    # User A (Owner of Org A)
    user_a = User(id=uuid.uuid4(), email="owner_a@tenant-a.com")
    # User B (Owner of Org B)
    user_b = User(id=uuid.uuid4(), email="owner_b@tenant-b.com")
    # Viewer B (Viewer of Org B only)
    viewer_b = User(id=uuid.uuid4(), email="viewer_b@tenant-b.com")
    db_session.add_all([user_a, user_b, viewer_b])
    db_session.flush()

    org_a = Organization(name="Organization Alpha")
    org_b = Organization(name="Organization Beta")
    db_session.add_all([org_a, org_b])
    db_session.flush()

    mem_a = Membership(org_id=org_a.id, user_id=user_a.id, role="owner")
    mem_b = Membership(org_id=org_b.id, user_id=user_b.id, role="owner")
    mem_b_viewer = Membership(org_id=org_b.id, user_id=viewer_b.id, role="viewer")
    db_session.add_all([mem_a, mem_b, mem_b_viewer])
    db_session.flush()

    # Domain A and Scan A for Org A
    dom_a = Domain(
        org_id=org_a.id,
        name="alpha-target.com",
        authorized=True,
        authorization_note="Alpha scope",
        scan_interval_hours=24,
        next_scan_at=datetime.now(UTC),
        alerts_enabled=True,
        alert_emails=["security@tenant-a.com"],
        alert_min_severity="MEDIUM",
    )
    # Domain B and Scan B for Org B
    dom_b = Domain(
        org_id=org_b.id,
        name="beta-target.com",
        authorized=True,
        authorization_note="Beta scope",
        scan_interval_hours=12,
        next_scan_at=datetime.now(UTC),
        alerts_enabled=True,
        alert_emails=["security@tenant-b.com"],
        alert_min_severity="HIGH",
    )
    db_session.add_all([dom_a, dom_b])
    db_session.flush()

    scan_a = enqueue_scan(db_session, dom_a.id, trigger="manual")
    scan_b = enqueue_scan(db_session, dom_b.id, trigger="manual")
    db_session.flush()

    # Results for Stage
    res_a = ScanResult(
        scan_run_id=scan_a.id,
        stage="discover",
        report={"domain": dom_a.name, "secret": "alpha_internal_subdomains"},
    )
    res_b = ScanResult(
        scan_run_id=scan_b.id,
        stage="discover",
        report={"domain": dom_b.name, "secret": "beta_internal_subdomains"},
    )
    db_session.add_all([res_a, res_b])

    # Scan Changes
    change_a = ScanChange(
        domain_id=dom_a.id,
        scan_run_id=scan_a.id,
        baseline_scan_run_id=scan_a.id,
        change_type="NEW_SUBDOMAIN",
        category="dns",
        severity="LOW",
        asset="secret.alpha-target.com",
        detail="Found secret subdomain",
        evidence="crt.sh",
        observed_at=datetime.now(UTC),
    )
    change_b = ScanChange(
        domain_id=dom_b.id,
        scan_run_id=scan_b.id,
        baseline_scan_run_id=scan_b.id,
        change_type="NEW_SUBDOMAIN",
        category="dns",
        severity="LOW",
        asset="secret.beta-target.com",
        detail="Found secret subdomain",
        evidence="crt.sh",
        observed_at=datetime.now(UTC),
    )
    db_session.add_all([change_a, change_b])

    # Alert notifications
    notif_a = AlertNotification(
        domain_id=dom_a.id,
        scan_run_id=scan_a.id,
        recipient="security@tenant-a.com",
        subject="Alert Alpha",
        body="Secret details Alpha",
        status="sent",
    )
    notif_b = AlertNotification(
        domain_id=dom_b.id,
        scan_run_id=scan_b.id,
        recipient="security@tenant-b.com",
        subject="Alert Beta",
        body="Secret details Beta",
        status="sent",
    )
    db_session.add_all([notif_a, notif_b])
    db_session.commit()

    return {
        "user_a": user_a,
        "user_b": user_b,
        "viewer_b": viewer_b,
        "org_a": org_a,
        "org_b": org_b,
        "dom_a": dom_a,
        "dom_b": dom_b,
        "scan_a": scan_a,
        "scan_b": scan_b,
        "change_a": change_a,
        "change_b": change_b,
        "notif_a": notif_a,
        "notif_b": notif_b,
    }


def test_idor_matrix_vector_1_cross_tenant_paths(two_tenants, db_session: Session):
    """Vector 1: User of Org B attempting to access Org A's path directly receives 404."""
    ctx = two_tenants
    client_b = make_authenticated_client(db_session, ctx["user_b"])
    org_a_id = ctx["org_a"].id
    dom_a_id = ctx["dom_a"].id
    scan_a_id = ctx["scan_a"].id

    try:
        # 1. POST /orgs/{org_a}/domains -> 404
        r = client_b.post(
            f"/orgs/{org_a_id}/domains", json={"name": "hacked.com", "authorized": True}
        )
        assert r.status_code == 404

        # 2. GET /orgs/{org_a}/domains -> 404
        assert client_b.get(f"/orgs/{org_a_id}/domains").status_code == 404

        # 3. GET /orgs/{org_a}/domains/{dom_a} -> 404
        assert client_b.get(f"/orgs/{org_a_id}/domains/{dom_a_id}").status_code == 404

        # 4. PUT /orgs/{org_a}/domains/{dom_a}/schedule -> 404
        assert client_b.put(
            f"/orgs/{org_a_id}/domains/{dom_a_id}/schedule", json={"interval_hours": 48}
        ).status_code == 404

        # 5. PUT /orgs/{org_a}/domains/{dom_a}/alerts -> 404
        assert client_b.put(
            f"/orgs/{org_a_id}/domains/{dom_a_id}/alerts", json={"alerts_enabled": False}
        ).status_code == 404

        # 6. GET /orgs/{org_a}/domains/{dom_a}/alert-notifications -> 404
        assert client_b.get(
            f"/orgs/{org_a_id}/domains/{dom_a_id}/alert-notifications"
        ).status_code == 404

        # 7. GET /orgs/{org_a}/domains/{dom_a}/changes -> 404
        assert client_b.get(f"/orgs/{org_a_id}/domains/{dom_a_id}/changes").status_code == 404

        # 8. POST /orgs/{org_a}/domains/{dom_a}/scans -> 404
        assert client_b.post(f"/orgs/{org_a_id}/domains/{dom_a_id}/scans").status_code == 404

        # 9. GET /orgs/{org_a}/domains/{dom_a}/scans -> 404
        assert client_b.get(f"/orgs/{org_a_id}/domains/{dom_a_id}/scans").status_code == 404

        # 10. GET /orgs/{org_a}/scans -> 404
        assert client_b.get(f"/orgs/{org_a_id}/scans").status_code == 404

        # 11. GET /orgs/{org_a}/scans/{scan_a} -> 404
        assert client_b.get(f"/orgs/{org_a_id}/scans/{scan_a_id}").status_code == 404

        # 12. GET /orgs/{org_a}/scans/{scan_a}/changes -> 404
        assert client_b.get(f"/orgs/{org_a_id}/scans/{scan_a_id}/changes").status_code == 404

        # 13. GET /orgs/{org_a}/scans/{scan_a}/results/discover -> 404
        assert client_b.get(
            f"/orgs/{org_a_id}/scans/{scan_a_id}/results/discover"
        ).status_code == 404
    finally:
        app.dependency_overrides.clear()


def test_idor_matrix_vector_2_id_swapping(two_tenants, db_session: Session):
    """Vector 2: User B requests via Org B path, but substitutes Org A resource IDs -> 404."""
    ctx = two_tenants
    client_b = make_authenticated_client(db_session, ctx["user_b"])
    org_b_id = ctx["org_b"].id
    dom_a_id = ctx["dom_a"].id
    scan_a_id = ctx["scan_a"].id

    try:
        # 1. GET /orgs/{org_b}/domains/{dom_a} -> 404 (Domain does not belong to Org B)
        r1 = client_b.get(f"/orgs/{org_b_id}/domains/{dom_a_id}")
        assert r1.status_code == 404
        assert f"Domain with ID {dom_a_id} not found" in r1.json()["detail"]

        # 2. PUT /orgs/{org_b}/domains/{dom_a}/schedule -> 404
        r2 = client_b.put(
            f"/orgs/{org_b_id}/domains/{dom_a_id}/schedule", json={"interval_hours": 48}
        )
        assert r2.status_code == 404

        # 3. PUT /orgs/{org_b}/domains/{dom_a}/alerts -> 404
        r3 = client_b.put(
            f"/orgs/{org_b_id}/domains/{dom_a_id}/alerts", json={"alerts_enabled": False}
        )
        assert r3.status_code == 404

        # 4. GET /orgs/{org_b}/domains/{dom_a}/alert-notifications -> 404
        r4 = client_b.get(f"/orgs/{org_b_id}/domains/{dom_a_id}/alert-notifications")
        assert r4.status_code == 404

        # 5. GET /orgs/{org_b}/domains/{dom_a}/changes -> 404
        r5 = client_b.get(f"/orgs/{org_b_id}/domains/{dom_a_id}/changes")
        assert r5.status_code == 404

        # 6. POST /orgs/{org_b}/domains/{dom_a}/scans -> 404
        r6 = client_b.post(f"/orgs/{org_b_id}/domains/{dom_a_id}/scans")
        assert r6.status_code == 404

        # 7. GET /orgs/{org_b}/domains/{dom_a}/scans -> 404
        r7 = client_b.get(f"/orgs/{org_b_id}/domains/{dom_a_id}/scans")
        assert r7.status_code == 404

        # 8. GET /orgs/{org_b}/scans/{scan_a} -> 404
        r8 = client_b.get(f"/orgs/{org_b_id}/scans/{scan_a_id}")
        assert r8.status_code == 404
        assert f"Scan run with ID {scan_a_id} not found" in r8.json()["detail"]

        # 9. GET /orgs/{org_b}/scans/{scan_a}/changes -> 404
        r9 = client_b.get(f"/orgs/{org_b_id}/scans/{scan_a_id}/changes")
        assert r9.status_code == 404

        # 10. GET /orgs/{org_b}/scans/{scan_a}/results/discover -> 404
        r10 = client_b.get(f"/orgs/{org_b_id}/scans/{scan_a_id}/results/discover")
        assert r10.status_code == 404
    finally:
        app.dependency_overrides.clear()


def test_list_isolation_between_tenants(two_tenants, db_session: Session):
    """Every list endpoint filters by org in SQL; Org B lists never leak Org A data."""
    ctx = two_tenants
    client_b = make_authenticated_client(db_session, ctx["user_b"])
    org_b_id = ctx["org_b"].id
    dom_b_id = ctx["dom_b"].id

    try:
        # 1. GET /orgs/{org_b}/domains
        res_doms = client_b.get(f"/orgs/{org_b_id}/domains")
        assert res_doms.status_code == 200
        dom_ids = [d["id"] for d in res_doms.json()]
        assert ctx["dom_b"].id in dom_ids
        assert ctx["dom_a"].id not in dom_ids

        # 2. GET /orgs/{org_b}/scans (org-wide scans)
        res_org_scans = client_b.get(f"/orgs/{org_b_id}/scans")
        assert res_org_scans.status_code == 200
        scan_ids = [s["id"] for s in res_org_scans.json()]
        assert ctx["scan_b"].id in scan_ids
        assert ctx["scan_a"].id not in scan_ids

        # 3. GET /orgs/{org_b}/domains/{dom_b}/scans (domain scans)
        res_dom_scans = client_b.get(f"/orgs/{org_b_id}/domains/{dom_b_id}/scans")
        assert res_dom_scans.status_code == 200
        dom_scan_ids = [s["id"] for s in res_dom_scans.json()]
        assert ctx["scan_b"].id in dom_scan_ids
        assert ctx["scan_a"].id not in dom_scan_ids

        # 4. GET /orgs/{org_b}/domains/{dom_b}/changes (domain changes)
        res_changes = client_b.get(f"/orgs/{org_b_id}/domains/{dom_b_id}/changes")
        assert res_changes.status_code == 200
        assets = [c["asset"] for c in res_changes.json()]
        assert "secret.beta-target.com" in assets
        assert "secret.alpha-target.com" not in assets

        # 5. GET /orgs/{org_b}/domains/{dom_b}/alert-notifications
        res_notifs = client_b.get(f"/orgs/{org_b_id}/domains/{dom_b_id}/alert-notifications")
        assert res_notifs.status_code == 200
        recipients = [n["recipient"] for n in res_notifs.json()]
        assert "security@tenant-b.com" in recipients
        assert "security@tenant-a.com" not in recipients
    finally:
        app.dependency_overrides.clear()


def test_role_matrix_viewer_forbidden_on_writes(two_tenants, db_session: Session):
    """Viewer gets HTTP 403 Forbidden on every write endpoint; allowed on read endpoints."""
    ctx = two_tenants
    viewer_client = make_authenticated_client(db_session, ctx["viewer_b"])
    org_b_id = ctx["org_b"].id
    dom_b_id = ctx["dom_b"].id

    try:
        # Write endpoints return 403
        # 1. POST domains
        r1 = viewer_client.post(
            f"/orgs/{org_b_id}/domains", json={"name": "test.com", "authorized": True}
        )
        assert r1.status_code == 403

        # 2. PUT schedule
        r2 = viewer_client.put(
            f"/orgs/{org_b_id}/domains/{dom_b_id}/schedule", json={"interval_hours": 24}
        )
        assert r2.status_code == 403

        # 3. PUT alerts
        r3 = viewer_client.put(
            f"/orgs/{org_b_id}/domains/{dom_b_id}/alerts", json={"alerts_enabled": False}
        )
        assert r3.status_code == 403

        # 4. POST scans
        r4 = viewer_client.post(f"/orgs/{org_b_id}/domains/{dom_b_id}/scans")
        assert r4.status_code == 403

        # 5. POST members
        r5 = viewer_client.post(
            f"/orgs/{org_b_id}/members", json={"email": "x@x.com", "role": "viewer"}
        )
        assert r5.status_code == 403

        # 6. PATCH member role
        r6 = viewer_client.patch(
            f"/orgs/{org_b_id}/members/{ctx['viewer_b'].id}", json={"role": "admin"}
        )
        assert r6.status_code == 403

        # Read endpoints return 200
        assert viewer_client.get(f"/orgs/{org_b_id}/domains").status_code == 200
        assert viewer_client.get(f"/orgs/{org_b_id}/domains/{dom_b_id}").status_code == 200
        assert viewer_client.get(f"/orgs/{org_b_id}/scans").status_code == 200
        assert viewer_client.get(f"/orgs/{org_b_id}/domains/{dom_b_id}/scans").status_code == 200
        assert viewer_client.get(f"/orgs/{org_b_id}/members").status_code == 200
    finally:
        app.dependency_overrides.clear()


def test_per_org_domain_uniqueness(two_tenants, db_session: Session):
    """The same domain name can exist across multiple orgs, but duplicates in one org give 409."""
    ctx = two_tenants
    org_a_id = ctx["org_a"].id
    org_b_id = ctx["org_b"].id
    shared_name = "common-target.com"

    def _get_db():
        yield db_session

    app.dependency_overrides[get_db] = _get_db
    client = TestClient(app)

    try:
        # 1. Org A creates shared_name -> 201
        app.dependency_overrides[get_current_user] = lambda: ctx["user_a"]
        res_a1 = client.post(
            f"/orgs/{org_a_id}/domains", json={"name": shared_name, "authorized": True}
        )
        assert res_a1.status_code == 201
        dom_a_new_id = res_a1.json()["id"]

        # 2. Org B creates identical shared_name -> 201 (Per-org uniqueness allows it!)
        app.dependency_overrides[get_current_user] = lambda: ctx["user_b"]
        res_b1 = client.post(
            f"/orgs/{org_b_id}/domains", json={"name": shared_name, "authorized": True}
        )
        assert res_b1.status_code == 201
        dom_b_new_id = res_b1.json()["id"]
        assert dom_a_new_id != dom_b_new_id

        # 3. Org A tries to create shared_name again -> 409 Conflict
        app.dependency_overrides[get_current_user] = lambda: ctx["user_a"]
        res_a2 = client.post(
            f"/orgs/{org_a_id}/domains", json={"name": shared_name, "authorized": True}
        )
        assert res_a2.status_code == 409
        assert f"Domain '{shared_name}' already exists" in res_a2.json()["detail"]

        # 4. Org B tries to create shared_name again -> 409 Conflict
        app.dependency_overrides[get_current_user] = lambda: ctx["user_b"]
        res_b2 = client.post(
            f"/orgs/{org_b_id}/domains", json={"name": shared_name, "authorized": True}
        )
        assert res_b2.status_code == 409
    finally:
        app.dependency_overrides.clear()


def test_legacy_quarantine_isolation_and_move_domain(db_session: Session):
    """Quarantined domains are completely invisible to users until moved by admin command."""
    # Create quarantine org (system_kind = 'legacy_quarantine') with 0 members
    quarantine_org = Organization(name="Legacy Quarantine", system_kind="legacy_quarantine")
    customer_org = Organization(name="Customer Org")
    customer_user = User(id=uuid.uuid4(), email="customer@corp.com")
    db_session.add_all([quarantine_org, customer_org, customer_user])
    db_session.flush()

    customer_mem = Membership(org_id=customer_org.id, user_id=customer_user.id, role="owner")
    db_session.add(customer_mem)
    db_session.flush()

    # Quarantined domain
    legacy_dom = Domain(
        org_id=quarantine_org.id,
        name="legacy-unassigned.com",
        authorized=True,
    )
    db_session.add(legacy_dom)
    db_session.commit()

    # 1. Customer user cannot access quarantine org via API -> 404
    customer_client = make_authenticated_client(db_session, customer_user)
    try:
        res = customer_client.get(f"/orgs/{quarantine_org.id}/domains")
        assert res.status_code == 404

        res2 = customer_client.get(f"/orgs/{quarantine_org.id}/domains/{legacy_dom.id}")
        assert res2.status_code == 404
    finally:
        app.dependency_overrides.clear()

    # 2. Admin move-domain command moves legacy_dom to customer_org
    exit_code = move_domain(db_session, domain_id=legacy_dom.id, target_org_id=customer_org.id)
    assert exit_code == 0

    # 3. Domain is now owned by customer_org and visible via API
    db_session.refresh(legacy_dom)
    assert legacy_dom.org_id == customer_org.id

    customer_client = make_authenticated_client(db_session, customer_user)
    try:
        res3 = customer_client.get(f"/orgs/{customer_org.id}/domains/{legacy_dom.id}")
        assert res3.status_code == 200
        assert res3.json()["name"] == "legacy-unassigned.com"
    finally:
        app.dependency_overrides.clear()


def test_move_domain_refuses_non_quarantine_source(db_session: Session):
    """move-domain strictly refuses moving domains whose current org is not legacy_quarantine."""
    org_1 = Organization(name="Customer 1")
    org_2 = Organization(name="Customer 2")
    db_session.add_all([org_1, org_2])
    db_session.flush()

    dom = Domain(org_id=org_1.id, name="customer1-domain.com", authorized=True)
    db_session.add(dom)
    db_session.commit()

    # Attempting to move a domain from Customer 1 to Customer 2 must fail with exit code 1
    exit_code = move_domain(db_session, domain_id=dom.id, target_org_id=org_2.id)
    assert exit_code == 1

    # Verify domain was NOT moved
    db_session.refresh(dom)
    assert dom.org_id == org_1.id


def test_move_domain_failure_modes(db_session: Session):
    """move-domain rejects non-existent domain, non-existent target org, and name conflicts."""
    quarantine_org = Organization(name="Legacy Quarantine", system_kind="legacy_quarantine")
    target_org = Organization(name="Target Org")
    db_session.add_all([quarantine_org, target_org])
    db_session.flush()

    dom = Domain(org_id=quarantine_org.id, name="collide.com", authorized=True)
    # Existing domain with same name in target org
    existing_target_dom = Domain(org_id=target_org.id, name="collide.com", authorized=True)
    db_session.add_all([dom, existing_target_dom])
    db_session.commit()

    # 1. Non-existent domain
    assert move_domain(db_session, domain_id=999999, target_org_id=target_org.id) == 1

    # 2. Non-existent target org
    assert move_domain(db_session, domain_id=dom.id, target_org_id=999999) == 1

    # 3. Name collision in target org
    assert move_domain(db_session, domain_id=dom.id, target_org_id=target_org.id) == 1


def test_customer_org_named_legacy_untouched(db_session: Session):
    """Customer org named 'Legacy' (system_kind is None) is untouched by quarantine cleanup."""
    customer_org = Organization(name="Legacy", system_kind=None)
    db_session.add(customer_org)
    db_session.commit()

    # Verify that downgrade deletion query would NOT delete this organization
    delete_quarantine_stmt = text(
        "DELETE FROM organizations WHERE system_kind = 'legacy_quarantine'"
    )
    db_session.execute(delete_quarantine_stmt)
    db_session.commit()

    # Organization named "Legacy" still exists!
    found = db_session.get(Organization, customer_org.id)
    assert found is not None
    assert found.name == "Legacy"
    assert found.system_kind is None
