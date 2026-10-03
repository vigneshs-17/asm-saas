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
    get_scan_for_org,
    require_org_role,
)
from asm.auth.config import AuthSettings
from asm.db.models import (
    Domain,
    Membership,
    Organization,
    ScanChange,
    ScanResult,
    ScanRun,
    ScanStage,
)
from asm.ui_views import (
    STATUS_DISPLAY_NAMES,
    check_polling_status,
    extract_fix_first_findings,
    format_change_summary,
    format_duration,
)

logger = logging.getLogger(__name__)

# Template environment with strict HTML auto-escaping
TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates_env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=select_autoescape(["html", "xml"]),
)

ui_router = APIRouter(tags=["Dashboard UI"])

# The scans list shows only the most recent runs; there is no pagination yet.
SCANS_LIST_LIMIT = 20


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


@ui_router.get(
    "/ui/orgs/{org_id}/domains/{domain_id}/scans",
    response_class=HTMLResponse,
    summary="Domain scans list partial",
)
def get_org_domain_scans_ui(
    org_id: int,
    domain_id: int,
    response: Response,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
    auth_settings: Annotated[AuthSettings, Depends(get_current_auth_settings)],
    db: DbSession,
) -> str:
    """Render the domain scans list HTML fragment."""
    apply_security_headers(response, auth_settings, is_fragment=True)
    org, membership = auth_context

    domain = get_domain_for_org(db, org_id, domain_id)

    # Scans list: do NOT load ScanResult reports for list rows.
    # Show a per-row summary from scan_runs.change_detection,
    # plus status, trigger, started, and duration.
    stmt = (
        select(ScanRun)
        .where(ScanRun.domain_id == domain.id)
        .order_by(ScanRun.created_at.desc(), ScanRun.id.desc())
        .limit(SCANS_LIST_LIMIT)
    )
    scans = list(db.scalars(stmt).all())

    scans_data = [
        {
            "scan": s,
            "status_display": STATUS_DISPLAY_NAMES.get(s.status, s.status.capitalize()),
            "duration": format_duration(s.started_at, s.finished_at),
            "changes_summary": format_change_summary(s.change_detection),
        }
        for s in scans
    ]

    template = templates_env.get_template("partials/scans_list.html")
    return template.render(
        org=org,
        domain=domain,
        user_role=membership.role,
        scans_data=scans_data,
        scans_limit=SCANS_LIST_LIMIT,
        is_limited=len(scans) == SCANS_LIST_LIMIT,
    )


@ui_router.get(
    "/ui/orgs/{org_id}/scans/{scan_id}",
    response_class=HTMLResponse,
    summary="Scan detail partial",
)
def get_org_scan_detail_ui(
    org_id: int,
    scan_id: int,
    response: Response,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
    auth_settings: Annotated[AuthSettings, Depends(get_current_auth_settings)],
    db: DbSession,
) -> str:
    """Render the scan run detail HTML fragment."""
    apply_security_headers(response, auth_settings, is_fragment=True)
    org, membership = auth_context

    # Chokepoint: get_scan_for_org returns 404 if not found or cross-tenant.
    scan_run = get_scan_for_org(db, org_id, scan_id)

    # Security rule: Load the score ScanResult and the ScanChange rows ONLY via the scan object
    # returned by get_scan_for_org (filter by scan_run.id). Never use any other id from request.
    score_stmt = select(ScanResult).where(
        ScanResult.scan_run_id == scan_run.id,
        ScanResult.stage == "score",
    )
    score_result = db.scalars(score_stmt).first()
    score_report = score_result.report if score_result else None
    fix_first = extract_fix_first_findings(score_report)

    changes_stmt = (
        select(ScanChange)
        .where(ScanChange.scan_run_id == scan_run.id)
        .order_by(ScanChange.id.asc())
    )
    scan_changes = list(db.scalars(changes_stmt).all())

    stages_stmt = (
        select(ScanStage)
        .where(ScanStage.scan_run_id == scan_run.id)
        .order_by(ScanStage.id.asc())
    )
    stages = list(db.scalars(stages_stmt).all())
    stage_map = {s.stage: s for s in stages}
    pipeline_stages = []
    for st_name in ["discover", "probe", "portscan", "inspect", "score"]:
        st_obj = stage_map.get(st_name)
        if st_obj:
            dur_str = f"{st_obj.duration_ms}ms" if st_obj.duration_ms is not None else "--"
            pipeline_stages.append({
                "name": st_name,
                "status": st_obj.status,
                "status_display": st_obj.status.capitalize(),
                "duration": dur_str,
                "error": st_obj.error,
            })
        else:
            pipeline_stages.append({
                "name": st_name,
                "status": "pending",
                "status_display": "Pending",
                "duration": "--",
                "error": None,
            })

    should_poll, is_stale_active = check_polling_status(
        scan_run.status,
        scan_run.created_at,
    )
    duration = format_duration(scan_run.started_at, scan_run.finished_at)
    status_display = STATUS_DISPLAY_NAMES.get(scan_run.status, scan_run.status.capitalize())

    template = templates_env.get_template("partials/scan_detail.html")
    return template.render(
        org=org,
        domain=scan_run.domain,
        scan_run=scan_run,
        status_display=status_display,
        duration=duration,
        pipeline_stages=pipeline_stages,
        fix_first=fix_first,
        scan_changes=scan_changes,
        should_poll=should_poll,
        is_stale_active=is_stale_active,
        user_role=membership.role,
    )
