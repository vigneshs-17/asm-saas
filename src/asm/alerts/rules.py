"""Pure trigger rules for attack surface change alerts."""

from __future__ import annotations

from typing import Any

from asm.scoring import TIER_RANK


def should_trigger_alerts(
    alerts_enabled: bool,
    alert_emails: list[str] | None,
    authorized: bool,
    alert_min_severity: str,
    change_summary: dict[str, Any] | None,
    changes: list[dict[str, Any]] | None,
) -> tuple[bool, list[dict[str, Any]]]:
    """Pure decision function: determine whether alert notifications should be queued.

    Rules:
    1. Domain must have alerts_enabled == True and 1..5 alert_emails configured.
    2. Domain must be authorized.
    3. change_summary['status'] must be strictly 'computed'.
       - Never triggers on 'baseline' (first scan).
       - Never triggers on 'failed' (detection error).
       - Never triggers on 'skipped'.
    4. There must be >= 1 change with category == 'exposure' and
       severity >= domain.alert_min_severity.
       - Summary changes (category == 'summary') NEVER trigger alerts.
       - Remediation changes (category == 'remediation') NEVER trigger alerts.

    Returns:
        (should_alert, triggering_exposure_changes)
    """
    if not alerts_enabled or not alert_emails or not authorized:
        return False, []

    if not change_summary or change_summary.get("status") != "computed":
        return False, []

    if not changes:
        return False, []

    min_rank = TIER_RANK.get(alert_min_severity, TIER_RANK["MEDIUM"])

    triggering = [
        ch
        for ch in changes
        if ch.get("category") == "exposure"
        and TIER_RANK.get(ch.get("severity", "INFO"), 0) >= min_rank
    ]

    if not triggering:
        return False, []

    # Sort triggering changes: highest severity first, then asset asc, then change_type asc
    triggering.sort(
        key=lambda ch: (
            -TIER_RANK.get(ch.get("severity", "INFO"), 0),
            ch.get("asset", ""),
            ch.get("change_type", ""),
        )
    )

    return True, triggering
