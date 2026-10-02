"""Server-rendered UI routes for ASM SaaS dashboard (v3.4a)."""

import logging
from pathlib import Path
from typing import Annotated
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Response
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select

from asm.api.deps import (
    CurrentUser,
    DbSession,
    get_current_auth_settings,
    get_domain_for_org,
    require_org_role,
)
from asm.auth.config import AuthSettings
from asm.db.models import Domain, Membership, Organization

logger = logging.getLogger(__name__)

# Template environment with strict HTML auto-escaping
TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates_env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=select_autoescape(["html", "xml"]),
)

ui_router = APIRouter(tags=["Dashboard UI"])


def build_csp_header(supabase_url: str) -> str:
    """Build Content-Security-Policy header scoped to application and Supabase origin."""
    connect_src = "'self'"
    if supabase_url and supabase_url.strip():
        parsed = urlparse(supabase_url.strip())
        if parsed.scheme and parsed.netloc:
            connect_src = f"'self' {parsed.scheme}://{parsed.netloc}"
        else:
            connect_src = f"'self' {supabase_url.strip()}"

    return (
        f"default-src 'self'; "
        f"script-src 'self'; "
        f"style-src 'self'; "
        f"font-src 'self'; "
        f"img-src 'self' data:; "
        f"connect-src {connect_src}; "
        f"frame-ancestors 'none'; "
        f"base-uri 'self'; "
        f"form-action 'self'"
    )


def apply_security_headers(
    response: Response,
    auth_settings: AuthSettings,
    is_fragment: bool = False,
) -> None:
    """Apply strict CSP and security headers to all HTML responses."""
    response.headers["Content-Security-Policy"] = build_csp_header(auth_settings.supabase_url)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    if is_fragment:
        response.headers["Cache-Control"] = "no-store"


@ui_router.get(
    "/app",
    response_class=HTMLResponse,
    summary="Dashboard Application Shell",
)
def get_app_shell(
    response: Response,
    auth_settings: Annotated[AuthSettings, Depends(get_current_auth_settings)],
) -> str:
    """Serve the public dashboard application shell with configuration in data attributes."""
    apply_security_headers(response, auth_settings, is_fragment=False)
    template = templates_env.get_template("app.html")
    return template.render(
        supabase_url=auth_settings.supabase_url,
        supabase_publishable_key=auth_settings.supabase_publishable_key,
    )


@ui_router.get(
    "/ui/empty-org",
    response_class=HTMLResponse,
    summary="Empty organization creation view",
)
def get_empty_org(
    response: Response,
    current_user: CurrentUser,
    auth_settings: Annotated[AuthSettings, Depends(get_current_auth_settings)],
) -> str:
    """Render organization creation view for users with no organizations."""
    apply_security_headers(response, auth_settings, is_fragment=True)
    template = templates_env.get_template("partials/empty_org.html")
    return template.render()


@ui_router.get(
    "/ui/orgs/{org_id}/domains",
    response_class=HTMLResponse,
    summary="Domains list partial for an organization",
)
def get_org_domains_ui(
    org_id: int,
    response: Response,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
    auth_settings: Annotated[AuthSettings, Depends(get_current_auth_settings)],
    db: DbSession,
) -> str:
    """Render the domain list HTML fragment for the selected organization."""
    apply_security_headers(response, auth_settings, is_fragment=True)
    org, membership = auth_context

    stmt = select(Domain).where(Domain.org_id == org_id).order_by(Domain.name.asc())
    domains = list(db.scalars(stmt).all())

    template = templates_env.get_template("partials/domains_list.html")
    return template.render(
        org=org,
        domains=domains,
        user_role=membership.role,
    )


@ui_router.get(
    "/ui/orgs/{org_id}/domains/{domain_id}",
    response_class=HTMLResponse,
    summary="Domain detail partial",
)
def get_domain_detail_ui(
    org_id: int,
    domain_id: int,
    response: Response,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
    auth_settings: Annotated[AuthSettings, Depends(get_current_auth_settings)],
    db: DbSession,
) -> str:
    """Render the domain detail HTML fragment with verification records and actions."""
    apply_security_headers(response, auth_settings, is_fragment=True)
    org, membership = auth_context

    domain = get_domain_for_org(db, org_id, domain_id)

    template = templates_env.get_template("partials/domain_detail.html")
    return template.render(
        org=org,
        domain=domain,
        user_role=membership.role,
    )
