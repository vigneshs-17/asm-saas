"""Tests for Phase v3.4a dashboard shell, UI fragments, security headers, and static assets."""

import importlib.resources
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from asm.api.deps import get_current_user, reset_auth_dependencies
from asm.api.main import app
from asm.auth.config import get_auth_settings
from asm.config import Settings
from asm.db.models import (
    Domain,
    Membership,
    Organization,
    ScanChange,
    ScanResult,
    ScanRun,
    ScanStage,
    User,
)


def test_app_shell_serves_html_and_no_inline_scripts():
    """GET /app serves HTML with data- attributes, no inline scripts, and no inline styles."""
    with patch.dict(
        os.environ,
        {
            "SUPABASE_URL": "https://testproj.supabase.co",
            "SUPABASE_PUBLISHABLE_KEY": "anon_key_test_12345",
        },
    ):
        reset_auth_dependencies()
        with TestClient(app) as client:
            resp = client.get("/app")
            assert resp.status_code == 200
            assert "text/html" in resp.headers["content-type"]
            html = resp.text

            # Passes config via data- attributes on body
            assert 'data-supabase-url="https://testproj.supabase.co"' in html
            assert 'data-supabase-key="anon_key_test_12345"' in html

            # Assert htmx-config meta tag is present with includeIndicatorStyles false
            assert '<meta name="htmx-config"' in html
            assert '"includeIndicatorStyles": false' in html

            # Assert zero inline scripts (all <script> must have src and empty body)
            script_pattern = r"<script(.*?)>(.*?)</script>"
            script_tags = re.findall(script_pattern, html, re.DOTALL | re.IGNORECASE)
            for attrs, body in script_tags:
                assert "src=" in attrs, f"Inline script found without src: {attrs}"
                assert body.strip() == "", f"Inline script content found: {body}"

            # Assert zero inline style attributes
            style_attrs = re.findall(r'style=["\'](.*?)["\']', html, re.IGNORECASE)
            assert len(style_attrs) == 0, f"Inline style attribute found: {style_attrs}"


def test_csp_and_security_headers_present():
    """Strict CSP and security headers must be present on /app, /ui/*, and /static/*."""
    with patch.dict(
        os.environ,
        {
            "SUPABASE_URL": "https://testproj.supabase.co",
            "SUPABASE_PUBLISHABLE_KEY": "anon_key_test_12345",
        },
    ):
        reset_auth_dependencies()
        with TestClient(app) as client:
            resp = client.get("/app")
            assert resp.status_code == 200

            # Headers present
            assert resp.headers.get("X-Content-Type-Options") == "nosniff"
            assert resp.headers.get("Referrer-Policy") == "no-referrer"

            csp = resp.headers.get("Content-Security-Policy", "")
            assert "default-src 'self'" in csp
            assert "script-src 'self'" in csp
            assert "style-src 'self'" in csp
            assert "font-src 'self'" in csp
            assert "img-src 'self' data:" in csp
            assert "connect-src 'self' https://testproj.supabase.co" in csp
            assert "frame-ancestors 'none'" in csp
            assert "base-uri 'self'" in csp
            assert "form-action 'self'" in csp

            # Check static file security headers
            resp_static = client.get("/static/css/app.css")
            assert resp_static.status_code == 200
            assert resp_static.headers.get("X-Content-Type-Options") == "nosniff"
            assert resp_static.headers.get("Referrer-Policy") == "no-referrer"
            assert "default-src 'self'" in resp_static.headers.get("Content-Security-Policy", "")


def test_secret_key_fails_startup():
    """Startup fails fast if SUPABASE_PUBLISHABLE_KEY starts with 'sb_secret_'."""
    # 1. Settings validation failure
    with pytest.raises((ValueError, RuntimeError), match="CRITICAL SECURITY MISCONFIGURATION"):
        Settings(
            database_url="postgresql+psycopg://test:test@localhost:5432/asm_test",
            supabase_publishable_key="sb_secret_super_secret_service_key",
        )

    # 2. AuthSettings / get_auth_settings failure
    with patch.dict(
        os.environ,
        {"SUPABASE_PUBLISHABLE_KEY": "sb_secret_bad_key"},
    ):
        with pytest.raises(RuntimeError, match="CRITICAL SECURITY MISCONFIGURATION"):
            get_auth_settings()


def test_static_files_served_correctly():
    """Vendored libraries, styles, and self-hosted fonts are served with 200."""
    with TestClient(app) as client:
        # HTMX
        resp_htmx = client.get("/static/vendor/htmx.min.js")
        assert resp_htmx.status_code == 200
        assert len(resp_htmx.content) > 10000

        # Supabase JS
        resp_supa = client.get("/static/vendor/supabase.min.js")
        assert resp_supa.status_code == 200
        assert len(resp_supa.content) > 10000

        # Stylesheet (verifies palette concept comment exists)
        resp_css = client.get("/static/css/app.css")
        assert resp_css.status_code == 200
        assert "A crisp radar-inspired visual hierarchy" in resp_css.text

        # IBM Plex Fonts
        resp_font = client.get("/static/fonts/IBMPlexSans-Regular.woff2")
        assert resp_font.status_code == 200
        assert len(resp_font.content) > 10000


def test_app_js_contains_no_inner_html():
    """Static client script app.js must never contain the word innerHTML."""
    root = Path(__file__).resolve().parent.parent
    app_js_path = root / "src" / "asm" / "static" / "js" / "app.js"
    assert app_js_path.is_file(), "src/asm/static/js/app.js missing!"
    content = app_js_path.read_text(encoding="utf-8")
    assert "innerHTML" not in content, "Found forbidden property 'innerHTML' in app.js"


def test_templates_package_data_exists():
    """Verify templates, static assets, and font files are accessible via package data.

    Docker in-image check.
    """
    expected_files = [
        ("templates", "app.html"),
        ("templates", "partials", "scans_list.html"),
        ("templates", "partials", "scan_detail.html"),
        ("static", "js", "app.js"),
        ("static", "vendor", "htmx.min.js"),
        ("static", "vendor", "supabase.min.js"),
        ("static", "css", "app.css"),
        ("static", "fonts", "IBMPlexSans-Regular.woff2"),
        ("static", "fonts", "IBMPlexSans-SemiBold.woff2"),
        ("static", "fonts", "IBMPlexMono-Regular.woff2"),
    ]
    pkg_files = importlib.resources.files("asm")
    for parts in expected_files:
        res = pkg_files.joinpath(*parts)
        assert res.is_file(), f"{'/'.join(parts)} is not a valid package data file!"


def _score_card_value(html: str, label: str) -> int | None:
    """Return the number shown on the Fix-first summary card with the given label."""
    match = re.search(
        r'<div class="score-card-value">\s*(\d+)\s*</div>\s*'
        rf'<div class="score-card-label">{re.escape(label)}</div>',
        html,
    )
    return int(match.group(1)) if match else None


def test_templates_have_no_csp_blocked_inline_code():
    """Every template must be CSP-clean: style-src/script-src 'self' block inline code.

    Inline style attributes, <style> blocks, inline event handlers, and inline scripts
    are silently blocked by the browser, so they must never appear in a template.
    """
    root = Path(__file__).resolve().parent.parent
    templates_dir = root / "src" / "asm" / "templates"
    template_files = sorted(templates_dir.rglob("*.html"))
    assert template_files, "No templates found"

    forbidden = {
        "inline style attribute": re.compile(r"\sstyle\s*=", re.IGNORECASE),
        "<style> block": re.compile(r"<style\b", re.IGNORECASE),
        "inline event handler": re.compile(r"\son[a-z]+\s*=", re.IGNORECASE),
        "htmx inline handler (hx-on)": re.compile(r"\bhx-on[:-]", re.IGNORECASE),
        "inline <script> without src": re.compile(
            r"<script\b(?![^>]*\bsrc\s*=)[^>]*>", re.IGNORECASE
        ),
    }
    problems = []
    for path in template_files:
        text = path.read_text(encoding="utf-8")
        for name, pattern in forbidden.items():
            for match in pattern.finditer(text):
                line_no = text.count("\n", 0, match.start()) + 1
                problems.append(f"{path.relative_to(root)}:{line_no}: {name}")
    assert not problems, "CSP-blocked inline code found:\n" + "\n".join(problems)


def test_ui_unauthenticated_returns_401():
    """Calling /ui/* endpoints without an Authorization header returns 401."""
    # Ensure no dependency overrides
    app.dependency_overrides.pop(get_current_user, None)
    with patch.dict(os.environ, {"SUPABASE_URL": "https://testproj.supabase.co"}):
        reset_auth_dependencies()
        with TestClient(app) as client:
            resp1 = client.get("/ui/empty-org")
            assert resp1.status_code == 401

            resp2 = client.get("/ui/orgs/1/domains")
            assert resp2.status_code == 401

            resp3 = client.get("/ui/orgs/1/domains/1")
            assert resp3.status_code == 401

            resp4 = client.get("/ui/orgs/1/domains/1/scans")
            assert resp4.status_code == 401

            resp5 = client.get("/ui/orgs/1/scans/1")
            assert resp5.status_code == 401


# ==============================================================================
# Database Integration Tests (marked @pytest.mark.db)
# ==============================================================================


@pytest.mark.db
def test_ui_cache_control_no_store(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Every /ui/* HTML fragment response must include Cache-Control: no-store."""
    resp = client.get(f"/ui/orgs/{test_org.id}/domains")
    assert resp.status_code == 200
    assert resp.headers.get("Cache-Control") == "no-store"


@pytest.mark.db
def test_viewer_vs_admin_rendering(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Viewers do not see write forms or action buttons; admins see full controls."""
    # Create test domain
    domain = Domain(
        org_id=test_org.id,
        name="rbac-test.example.com",
        verification_status="pending",
        verification_token="tok-rbac-test",
        verification_method="dns_txt",
    )
    db_session.add(domain)
    db_session.flush()

    # 1. Admin context (client fixture user is owner of test_org)
    resp_admin_list = client.get(f"/ui/orgs/{test_org.id}/domains")
    assert resp_admin_list.status_code == 200
    assert 'id="add-domain-form"' in resp_admin_list.text

    resp_admin_detail = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}")
    assert resp_admin_detail.status_code == 200
    assert 'id="btn-check-verification"' in resp_admin_detail.text
    assert 'id="btn-rotate-token"' in resp_admin_detail.text
    admin_result_tag = re.search(
        r'<div[^>]*id="verification-check-result"[^>]*>', resp_admin_detail.text
    )
    assert admin_result_tag is not None
    assert "hidden" not in admin_result_tag.group(0)

    # 2. Viewer context
    viewer_user_id = UUID("00000000-0000-0000-0000-000000000002")
    viewer_user = db_session.get(User, viewer_user_id)
    if not viewer_user:
        viewer_user = User(id=viewer_user_id, email="viewer@example.com")
        db_session.add(viewer_user)
        db_session.flush()

    # Downgrade or create membership as viewer
    membership = (
        db_session.query(Membership)
        .filter_by(org_id=test_org.id, user_id=viewer_user_id)
        .first()
    )
    if not membership:
        membership = Membership(org_id=test_org.id, user_id=viewer_user_id, role="viewer")
        db_session.add(membership)
    else:
        membership.role = "viewer"
    db_session.flush()

    # Override get_current_user to return viewer
    def _override_viewer():
        return viewer_user

    app.dependency_overrides[get_current_user] = _override_viewer
    try:
        resp_viewer_list = client.get(f"/ui/orgs/{test_org.id}/domains")
        assert resp_viewer_list.status_code == 200
        assert 'id="add-domain-form"' not in resp_viewer_list.text

        resp_viewer_detail = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}")
        assert resp_viewer_detail.status_code == 200
        assert 'id="btn-check-verification"' not in resp_viewer_detail.text
        assert 'id="btn-rotate-token"' not in resp_viewer_detail.text
        viewer_result_tag = re.search(
            r'<div[^>]*id="verification-check-result"[^>]*>', resp_viewer_detail.text
        )
        assert viewer_result_tag is not None
        assert "hidden" not in viewer_result_tag.group(0)
    finally:
        # Restore fixture user
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.db
def test_cross_tenant_404_on_ui_routes(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Accessing UI endpoints for a foreign tenant returns 404 (anti-enumeration)."""
    # Create foreign organization without membership for test user
    foreign_org = Organization(name="Foreign Organization")
    db_session.add(foreign_org)
    db_session.flush()

    foreign_domain = Domain(
        org_id=foreign_org.id,
        name="foreign-asset.corp",
        verification_status="pending",
        verification_token="foreign-tok",
        verification_method="dns_txt",
    )
    db_session.add(foreign_domain)
    db_session.flush()

    # 1. Accessing foreign org's domain list returns 404
    resp_list = client.get(f"/ui/orgs/{foreign_org.id}/domains")
    assert resp_list.status_code == 404

    # 2. Accessing foreign domain under foreign org returns 404
    resp_detail_foreign_org = client.get(f"/ui/orgs/{foreign_org.id}/domains/{foreign_domain.id}")
    assert resp_detail_foreign_org.status_code == 404

    # 3. Accessing foreign domain under user's own org returns 404 (parameter swapping)
    resp_detail_own_org = client.get(f"/ui/orgs/{test_org.id}/domains/{foreign_domain.id}")
    assert resp_detail_own_org.status_code == 404


@pytest.mark.db
def test_xss_escaping_in_rendered_templates(client: TestClient, db_session: Session):
    """Domain and organization names containing <script> tags are strictly HTML-escaped."""
    xss_org = Organization(name='Acme <script>alert("org-xss")</script>')
    db_session.add(xss_org)
    db_session.flush()

    test_user_id = UUID("00000000-0000-0000-0000-000000000001")
    membership = Membership(org_id=xss_org.id, user_id=test_user_id, role="owner")
    db_session.add(membership)
    db_session.flush()

    xss_domain = Domain(
        org_id=xss_org.id,
        name="test-xss.example.com",
        verification_status="pending",
        verification_token="tok",
        verification_method="dns_txt",
    )
    db_session.add(xss_domain)
    db_session.flush()

    resp = client.get(f"/ui/orgs/{xss_org.id}/domains")
    assert resp.status_code == 200
    assert "<script>" not in resp.text
    assert "&lt;script&gt;" in resp.text


@pytest.mark.db
def test_cross_tenant_404_on_scans_routes(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Accessing domain scans list or scan detail for a foreign tenant returns 404."""
    # 1. Setup foreign org, domain, and scan
    foreign_org = Organization(name="Foreign Org 2")
    db_session.add(foreign_org)
    db_session.flush()

    foreign_domain = Domain(
        org_id=foreign_org.id,
        name="foreign2.example.com",
        verification_status="verified",
        verification_token="tok2",
        verification_method="dns_txt",
    )
    db_session.add(foreign_domain)
    db_session.flush()

    foreign_scan = ScanRun(
        domain_id=foreign_domain.id,
        status="succeeded",
        trigger="manual",
    )
    db_session.add(foreign_scan)
    db_session.flush()

    # 2. Setup user's own domain and scan
    own_domain = Domain(
        org_id=test_org.id,
        name="own.example.com",
        verification_status="verified",
        verification_token="tok-own",
        verification_method="dns_txt",
    )
    db_session.add(own_domain)
    db_session.flush()

    own_scan = ScanRun(
        domain_id=own_domain.id,
        status="succeeded",
        trigger="manual",
    )
    db_session.add(own_scan)
    db_session.flush()

    # Access foreign scans list under foreign org -> 404
    resp1 = client.get(f"/ui/orgs/{foreign_org.id}/domains/{foreign_domain.id}/scans")
    assert resp1.status_code == 404

    # Access foreign domain under own org (parameter swapping) -> 404
    resp2 = client.get(f"/ui/orgs/{test_org.id}/domains/{foreign_domain.id}/scans")
    assert resp2.status_code == 404

    # Access foreign scan under foreign org -> 404
    resp3 = client.get(f"/ui/orgs/{foreign_org.id}/scans/{foreign_scan.id}")
    assert resp3.status_code == 404

    # Access foreign scan under own org (parameter swapping) -> 404
    resp4 = client.get(f"/ui/orgs/{test_org.id}/scans/{foreign_scan.id}")
    assert resp4.status_code == 404

    # Access own scan under foreign org -> 404
    resp5 = client.get(f"/ui/orgs/{foreign_org.id}/scans/{own_scan.id}")
    assert resp5.status_code == 404


@pytest.mark.db
def test_scans_list_viewer_vs_admin_and_verification_status(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Scans list respects roles and unverified domain disabled state with visible reason."""
    domain = Domain(
        org_id=test_org.id,
        name="unverified-scan.example.com",
        verification_status="pending",
        verification_token="tok-scan",
        verification_method="dns_txt",
    )
    db_session.add(domain)
    db_session.flush()

    scan = ScanRun(
        domain_id=domain.id,
        status="queued",
        trigger="manual",
        change_detection={"status": "baseline"},
    )
    db_session.add(scan)
    db_session.flush()

    # 1. As Owner: Run scan button is rendered but disabled because domain is unverified
    resp_owner = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}/scans")
    assert resp_owner.status_code == 200
    assert 'id="btn-run-scan"' in resp_owner.text
    assert "disabled" in resp_owner.text
    assert "Domain ownership verification required to run scans." in resp_owner.text
    # Sentence-case headers
    assert "Scan ID" in resp_owner.text
    assert "Trigger" in resp_owner.text
    assert "Status" in resp_owner.text
    assert "Started at" in resp_owner.text
    assert "Duration" in resp_owner.text
    assert "Changes" in resp_owner.text
    assert "Actions" in resp_owner.text
    assert "Baseline scan" in resp_owner.text
    assert f"#{scan.id}" in resp_owner.text

    # 2. Mark domain verified -> Run scan button becomes enabled
    domain.verification_status = "verified"
    db_session.flush()

    resp_verified = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}/scans")
    assert resp_verified.status_code == 200
    assert 'id="btn-run-scan"' in resp_verified.text
    assert (
        'disabled title="Domain ownership verification required to run scans"'
        not in resp_verified.text
    )

    # 3. As Viewer: Run scan button is not rendered at all
    viewer_user = User(
        id=UUID("00000000-0000-0000-0000-000000000099"),
        email="viewer-scan@example.com",
    )
    db_session.add(viewer_user)
    db_session.flush()
    db_session.add(Membership(org_id=test_org.id, user_id=viewer_user.id, role="viewer"))
    db_session.flush()

    def _override_viewer():
        return viewer_user

    app.dependency_overrides[get_current_user] = _override_viewer
    try:
        resp_viewer = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}/scans")
        assert resp_viewer.status_code == 200
        assert 'id="btn-run-scan"' not in resp_viewer.text
        # But table and view scan buttons are visible
        assert 'btn-view-scan' in resp_viewer.text
    finally:
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.db
def test_scan_detail_polling_and_stale_cap(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Polling trigger is present only for active scans < 15m; stale banner shows at >= 15m."""
    domain = Domain(
        org_id=test_org.id,
        name="polling-test.example.com",
        verification_status="verified",
        verification_token="tok-poll",
        verification_method="dns_txt",
    )
    db_session.add(domain)
    db_session.flush()

    now = datetime.now(UTC)

    # 1. Active scan created 3 minutes ago -> should poll, no stale banner
    scan_active_fresh = ScanRun(
        domain_id=domain.id,
        status="running",
        trigger="manual",
        created_at=now - timedelta(minutes=3),
    )
    db_session.add(scan_active_fresh)
    db_session.flush()

    resp_fresh = client.get(f"/ui/orgs/{test_org.id}/scans/{scan_active_fresh.id}")
    assert resp_fresh.status_code == 200
    assert f'hx-get="/ui/orgs/{test_org.id}/scans/{scan_active_fresh.id}"' in resp_fresh.text
    assert 'hx-trigger="every 3s"' in resp_fresh.text
    assert 'hx-target="this"' in resp_fresh.text
    assert 'hx-swap="outerHTML"' in resp_fresh.text
    assert "Still running after 15 minutes" not in resp_fresh.text

    # 2. Active scan created 16 minutes ago -> no polling, stale banner present.
    # Separate domain: uq_scan_runs_active_domain allows one active scan per domain.
    stale_domain = Domain(
        org_id=test_org.id,
        name="polling-stale.example.com",
        verification_status="verified",
        verification_token="tok-poll-stale",
        verification_method="dns_txt",
    )
    db_session.add(stale_domain)
    db_session.flush()

    scan_active_stale = ScanRun(
        domain_id=stale_domain.id,
        status="running",
        trigger="manual",
        created_at=now - timedelta(minutes=16),
    )
    db_session.add(scan_active_stale)
    db_session.flush()

    resp_stale = client.get(f"/ui/orgs/{test_org.id}/scans/{scan_active_stale.id}")
    assert resp_stale.status_code == 200
    assert 'hx-trigger="every 3s"' not in resp_stale.text
    # No hx-get at all: without hx-trigger htmx would fall back to re-fetching on click
    assert "hx-get=" not in resp_stale.text
    assert "Still running after 15 minutes. Automatic updates have stopped." in resp_stale.text
    assert 'id="btn-refresh-scan"' in resp_stale.text

    # 3. Finished scan -> no polling, no stale banner
    scan_finished = ScanRun(
        domain_id=domain.id,
        status="succeeded",
        trigger="manual",
        created_at=now - timedelta(minutes=5),
        started_at=now - timedelta(minutes=5),
        finished_at=now - timedelta(minutes=4),
    )
    db_session.add(scan_finished)
    db_session.flush()

    resp_finished = client.get(f"/ui/orgs/{test_org.id}/scans/{scan_finished.id}")
    assert resp_finished.status_code == 200
    assert 'hx-trigger="every 3s"' not in resp_finished.text
    assert "hx-get=" not in resp_finished.text
    assert "Still running after 15 minutes" not in resp_finished.text


@pytest.mark.db
def test_scan_detail_fix_first_and_stored_xss_safety(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Score findings are sorted, summarized, and strictly HTML-escaped against stored XSS."""
    domain = Domain(
        org_id=test_org.id,
        name="xss-scan.example.com",
        verification_status="verified",
        verification_token="tok-xss",
        verification_method="dns_txt",
    )
    db_session.add(domain)
    db_session.flush()

    scan = ScanRun(
        domain_id=domain.id,
        status="succeeded",
        trigger="manual",
    )
    db_session.add(scan)
    db_session.flush()

    # Add pipeline stage
    stage = ScanStage(
        scan_run_id=scan.id,
        stage="score",
        status="succeeded",
        duration_ms=45,
    )
    db_session.add(stage)

    # Score report with malicious payload in title, evidence, and why_it_matters
    malicious_report = {
        "domain_score": 120,
        "domain_band": "CRITICAL",
        # Real scoring.py key names
        "counts": {"findings_critical": 1, "findings_high": 1},
        "hosts": [
            {
                "subdomain": "vuln.example.com",
                "findings": [
                    {
                        "id": "F_CRIT_XSS",
                        "title": "Critical <script>alert('title-xss')</script>",
                        "tier": "CRITICAL",
                        "points": 100,
                        "host": "vuln.example.com",
                        "port": 443,
                        "evidence": '<img src=x onerror="alert(document.cookie)">',
                        "why_it_matters": (
                            'Exploitable via <iframe src="javascript:alert(1)"></iframe>'
                        ),
                    },
                    {
                        "id": "F_HIGH_SAFE",
                        "title": "High Severity Exposure",
                        "tier": "HIGH",
                        "points": 20,
                        "host": "vuln.example.com",
                        "port": 80,
                        "evidence": "banner=nginx/1.18",
                        "why_it_matters": "Outdated web server",
                    },
                ],
            }
        ],
    }
    db_session.add(
        ScanResult(
            scan_run_id=scan.id,
            stage="score",
            report=malicious_report,
        )
    )
    db_session.flush()

    resp = client.get(f"/ui/orgs/{test_org.id}/scans/{scan.id}")
    assert resp.status_code == 200

    # Ensure raw dangerous markup is never present
    assert "<script>" not in resp.text
    assert "&lt;script&gt;" in resp.text
    assert "<img src=x" not in resp.text
    assert "&lt;img src=x" in resp.text
    assert "<iframe" not in resp.text
    # Exact escaped forms prove escaping happened (Jinja renders " as &#34;)
    assert "&lt;iframe src=&#34;javascript:alert(1)&#34;&gt;" in resp.text
    assert "&lt;img src=x onerror=&#34;alert(document.cookie)&#34;&gt;" in resp.text

    # Findings summary and details are rendered
    assert _score_card_value(resp.text, "Domain score") == 120
    assert 'class="tier-badge tier-critical">Critical</span>' in resp.text
    assert "vuln.example.com:443" in resp.text
    assert "Tier" in resp.text
    assert "Finding" in resp.text
    assert "Host / Port" in resp.text
    assert "Points" in resp.text
    assert "Evidence" in resp.text

    # Summary cards count the findings actually present
    assert _score_card_value(resp.text, "Critical") == 1
    assert _score_card_value(resp.text, "High") == 1
    assert _score_card_value(resp.text, "Medium") == 0


@pytest.mark.db
def test_scan_detail_overflow_findings_50_cap(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Findings exceeding 50 are capped and the overflow count is displayed."""
    domain = Domain(
        org_id=test_org.id,
        name="cap-test.example.com",
        verification_status="verified",
        verification_token="tok-cap",
        verification_method="dns_txt",
    )
    db_session.add(domain)
    db_session.flush()

    scan = ScanRun(domain_id=domain.id, status="succeeded", trigger="manual")
    db_session.add(scan)
    db_session.flush()

    findings_60 = [
        {
            "id": f"FINDING_{i:02d}",
            "title": f"Finding Number {i}",
            "tier": "LOW",
            "points": 5,
            # Zero-padded so host order matches index order (host00 < host01 < ... < host59)
            "host": f"host{i:02d}.example.com",
            "port": 80,
            "evidence": f"proof_{i}",
            "why_it_matters": "Risk explanation",
        }
        for i in range(60)
    ]
    db_session.add(
        ScanResult(
            scan_run_id=scan.id,
            stage="score",
            report={
                "domain_score": 300,
                "domain_band": "LOW",
                "counts": {"findings_low": 60},
                "hosts": [{"subdomain": "root.example.com", "findings": findings_60}],
            },
        )
    )
    db_session.flush()

    resp = client.get(f"/ui/orgs/{test_org.id}/scans/{scan.id}")
    assert resp.status_code == 200
    assert "... and 10 more findings." in resp.text
    # Check that 50th finding is present, but 51st (index 50) is excluded from table
    assert "Finding Number 0" in resp.text
    assert "Finding Number 49" in resp.text
    assert "Finding Number 50" not in resp.text
    # The Low card counts all 60 findings, not just the 50 rendered rows
    assert _score_card_value(resp.text, "Low") == 60


@pytest.mark.db
def test_scans_list_change_summary_uses_real_worker_shape(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Scans list summarizes change_detection exactly as the worker writes it (no "total")."""
    domain = Domain(
        org_id=test_org.id,
        name="change-summary.example.com",
        verification_status="verified",
        verification_token="tok-summary",
        verification_method="dns_txt",
    )
    db_session.add(domain)
    db_session.flush()

    def _computed(**tier_counts: int) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        counts.update(tier_counts)
        return {
            "status": "computed",
            "baseline_scan_run_id": None,
            "removal_detection": "performed",
            "skip_reason": None,
            "error": None,
            "counts": counts,
        }

    now = datetime.now(UTC)
    db_session.add_all(
        [
            ScanRun(
                domain_id=domain.id,
                status="succeeded",
                trigger="manual",
                created_at=now - timedelta(hours=2),
                change_detection=_computed(),
            ),
            ScanRun(
                domain_id=domain.id,
                status="succeeded",
                trigger="manual",
                created_at=now - timedelta(hours=1),
                change_detection=_computed(critical=1, info=2),
            ),
        ]
    )
    db_session.flush()

    resp = client.get(f"/ui/orgs/{test_org.id}/domains/{domain.id}/scans")
    assert resp.status_code == 200
    assert "1 critical, 2 info" in resp.text
    assert "No changes" in resp.text


@pytest.mark.db
def test_scan_detail_failed_state_no_results(
    client: TestClient, db_session: Session, test_org: Organization
):
    """Failed scan renders error message and 'No findings reported' without crashing."""
    domain = Domain(
        org_id=test_org.id,
        name="failed-scan.example.com",
        verification_status="verified",
        verification_token="tok-fail",
        verification_method="dns_txt",
    )
    db_session.add(domain)
    db_session.flush()

    scan = ScanRun(
        domain_id=domain.id,
        status="failed",
        trigger="manual",
        error="Connection reset by peer during inspect stage <b onmouseover=alert(1)>",
    )
    db_session.add(scan)
    db_session.flush()

    resp = client.get(f"/ui/orgs/{test_org.id}/scans/{scan.id}")
    assert resp.status_code == 200
    assert "Scan failed:" in resp.text
    assert "Connection reset by peer during inspect stage" in resp.text
    assert "<b onmouseover" not in resp.text
    assert "&lt;b onmouseover=alert(1)&gt;" in resp.text
    assert "No findings reported for this scan run." in resp.text


@pytest.mark.db
def test_scan_detail_changes_detected_and_empty(
    client: TestClient, db_session: Session, test_org: Organization
):
    """ScanChanges are rendered when present, or 'No changes detected' when none."""
    domain = Domain(
        org_id=test_org.id,
        name="changes-test.example.com",
        verification_status="verified",
        verification_token="tok-changes",
        verification_method="dns_txt",
    )
    db_session.add(domain)
    db_session.flush()

    # 1. Scan with changes
    scan_with_changes = ScanRun(domain_id=domain.id, status="succeeded", trigger="manual")
    db_session.add(scan_with_changes)
    db_session.flush()

    # Shape as written by changes.py: uppercase severity, real category names.
    # asset/detail come from attacker-influenced data (CT log names, banners).
    change = ScanChange(
        domain_id=domain.id,
        scan_run_id=scan_with_changes.id,
        baseline_scan_run_id=scan_with_changes.id,
        change_type="port_opened",
        category="exposure",
        severity="HIGH",
        asset="<script>alert('asset')</script>.example.com:8443",
        detail="<img src=x onerror=alert(1)>",
        evidence="portscan",
        observed_at=datetime.now(UTC),
    )
    db_session.add(change)
    db_session.add(
        ScanStage(
            scan_run_id=scan_with_changes.id,
            stage="probe",
            status="failed",
            error="<script>alert('stage')</script>",
        )
    )
    db_session.flush()

    resp1 = client.get(f"/ui/orgs/{test_org.id}/scans/{scan_with_changes.id}")
    assert resp1.status_code == 200
    assert "port_opened" in resp1.text
    assert 'class="tier-badge tier-high">High</span>' in resp1.text
    # Exact cell markup: the bare word "portscan" also appears in the pipeline stage cards
    assert "<td><code>portscan</code></td>" in resp1.text
    # Stored XSS: every attacker-influenced field is escaped, never raw
    assert "<script>" not in resp1.text
    assert "<img src=x" not in resp1.text
    assert "&lt;script&gt;alert(&#39;asset&#39;)&lt;/script&gt;.example.com:8443" in resp1.text
    assert "&lt;img src=x onerror=alert(1)&gt;" in resp1.text
    assert "&lt;script&gt;alert(&#39;stage&#39;)&lt;/script&gt;" in resp1.text

    # 2. Scan without changes
    scan_no_changes = ScanRun(domain_id=domain.id, status="succeeded", trigger="manual")
    db_session.add(scan_no_changes)
    db_session.flush()

    resp2 = client.get(f"/ui/orgs/{test_org.id}/scans/{scan_no_changes.id}")
    assert resp2.status_code == 200
    assert "No changes detected in this scan." in resp2.text
