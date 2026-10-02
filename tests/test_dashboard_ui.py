"""Tests for Phase v3.4a dashboard shell, UI fragments, security headers, and static assets."""

import importlib.resources
import os
import re
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
from asm.db.models import Domain, Membership, Organization, User


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
