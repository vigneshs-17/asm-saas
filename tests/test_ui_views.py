"""Unit tests for ui_views presentation logic and extract_fix_first_findings."""

from datetime import UTC, datetime, timedelta

from asm.models import Finding, HostScore, ScoreReport
from asm.ui_views import (
    check_polling_status,
    extract_fix_first_findings,
    format_change_summary,
    format_duration,
)

ZERO_TIER_COUNTS = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}


def _worker_change_detection(**tier_counts: int) -> dict:
    """Return change_detection in the exact shape the worker writes (worker.py).

    The worker stores counts for critical/high/medium/low/info and no "total" key.
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    counts.update(tier_counts)
    return {
        "status": "computed",
        "baseline_scan_run_id": 1,
        "removal_detection": "performed",
        "skip_reason": None,
        "error": None,
        "counts": counts,
    }


def test_extract_fix_first_findings_none_or_malformed():
    """Passing None, non-dict, or empty dict returns safe empty result."""
    for bad_input in (None, "string", 123, [], {}):
        res = extract_fix_first_findings(bad_input)
        assert res.findings == []
        assert res.total == 0
        assert res.more_count == 0
        assert res.domain_score == 0
        assert res.domain_band in ("UNKNOWN", "")
        assert res.counts == ZERO_TIER_COUNTS


def test_extract_fix_first_findings_sorting_order():
    """Findings are sorted by tier (CRITICAL>HIGH>MEDIUM>LOW>INFO), points desc, host, port."""
    score_report = {
        "domain_score": 140,
        "domain_band": "HIGH",
        # Real scoring.py key names; the extractor must not depend on them.
        "counts": {"findings_critical": 1, "findings_high": 3, "findings_low": 1},
        "hosts": [
            {
                "subdomain": "zeta.example.com",
                "findings": [
                    {
                        "id": "F_LOW",
                        "title": "Low Finding",
                        "tier": "LOW",
                        "points": 5,
                        "port": 80,
                    },
                    {
                        "id": "F_HIGH_2",
                        "title": "High Finding 20 pts",
                        "tier": "HIGH",
                        "points": 20,
                        "port": 443,
                    },
                ],
            },
            {
                "subdomain": "alpha.example.com",
                "findings": [
                    {
                        "id": "F_CRIT",
                        "title": "Critical Finding",
                        "tier": "CRITICAL",
                        "points": 50,
                        "port": None,
                    },
                    {
                        "id": "F_HIGH_1",
                        "title": "High Finding 30 pts",
                        "tier": "HIGH",
                        "points": 30,
                        "port": 8080,
                    },
                    {
                        "id": "F_HIGH_SAME_PTS_B",
                        "title": "High Beta",
                        "tier": "HIGH",
                        "points": 20,
                        "host": "beta.example.com",
                        "port": 80,
                    },
                ],
            },
        ],
    }

    res = extract_fix_first_findings(score_report)
    assert res.total == 5
    assert res.more_count == 0
    assert res.domain_score == 140
    assert res.domain_band == "HIGH"
    assert res.domain_band_display == "High"
    assert res.counts == {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 0, "LOW": 1, "INFO": 0}

    ids = [f.id for f in res.findings]
    # 1. Critical first: F_CRIT
    # 2. High 30 pts: F_HIGH_1
    # 3. High 20 pts beta.example.com (beta < zeta): F_HIGH_SAME_PTS_B
    # 4. High 20 pts zeta.example.com: F_HIGH_2
    # 5. Low 5 pts: F_LOW
    assert ids == [
        "F_CRIT",
        "F_HIGH_1",
        "F_HIGH_SAME_PTS_B",
        "F_HIGH_2",
        "F_LOW",
    ]
    # Sentence-case display labels
    assert res.findings[0].tier_display == "Critical"
    assert res.findings[1].tier_display == "High"
    assert res.findings[4].tier_display == "Low"


def test_extract_fix_first_findings_port_sorting_tiebreaker():
    """When tier, points, and host are equal, None port precedes numeric ports."""
    report = {
        "hosts": [
            {
                "subdomain": "api.example.com",
                "findings": [
                    {"id": "P_443", "tier": "HIGH", "points": 10, "port": 443},
                    {"id": "P_NONE", "tier": "HIGH", "points": 10, "port": None},
                    {"id": "P_80", "tier": "HIGH", "points": 10, "port": 80},
                ],
            }
        ]
    }
    res = extract_fix_first_findings(report)
    assert [f.id for f in res.findings] == ["P_NONE", "P_80", "P_443"]


def test_extract_fix_first_findings_capping_at_50():
    """A report with 60 findings caps findings at 50 and reports 10 more."""
    findings_list = [
        {
            "id": f"FINDING_{i:02d}",
            "title": f"Finding {i}",
            "tier": "MEDIUM",
            "points": 60 - i,
            "host": f"host{i}.example.com",
            "evidence": f"proof_{i}",
        }
        for i in range(60)
    ]
    report = {
        "domain_score": 1000,
        "domain_band": "MEDIUM",
        "hosts": [{"subdomain": "root.example.com", "findings": findings_list}],
    }

    res = extract_fix_first_findings(report)
    assert len(res.findings) == 50
    assert res.total == 60
    assert res.more_count == 10
    # First finding has highest points (60)
    assert res.findings[0].id == "FINDING_00"
    # 50th finding is FINDING_49
    assert res.findings[49].id == "FINDING_49"
    # Counts cover ALL findings, not only the 50 rendered
    assert res.counts["MEDIUM"] == 60


def test_format_duration():
    """Verify duration formatting across lifecycle states."""
    now = datetime(2026, 10, 2, 10, 0, 0, tzinfo=UTC)
    assert format_duration(None, None) == "--"
    assert format_duration(now, None) == "In progress"
    assert format_duration(now, now + timedelta(seconds=42)) == "42s"
    assert format_duration(now, now + timedelta(seconds=125)) == "2m 5s"


def test_format_change_summary():
    """Verify change detection summary strings against the worker's real shape."""
    assert format_change_summary(None) == "--"
    assert format_change_summary({}) == "--"
    assert format_change_summary({"status": "baseline"}) == "Baseline scan"
    assert format_change_summary({"status": "failed"}) == "Detection error"
    assert format_change_summary(_worker_change_detection()) == "No changes"
    assert format_change_summary(_worker_change_detection(critical=1, info=2)) == (
        "1 critical, 2 info"
    )
    assert format_change_summary(_worker_change_detection(high=2, medium=1, low=4)) == (
        "2 high, 1 medium, 4 low"
    )


def test_format_change_summary_ignores_malformed_counts():
    """Non-integer, boolean, or negative tier values are ignored, never crash."""
    malformed = _worker_change_detection()
    malformed["counts"].update({"critical": "3", "high": True, "medium": -1, "low": 2})
    assert format_change_summary(malformed) == "2 low"
    assert format_change_summary({"status": "computed", "counts": "bad"}) == "Changes detected"


def test_extract_fix_first_findings_real_score_report_shape():
    """Contract test: input built by the real ScoreReport producer, not a hand-written dict."""
    report = ScoreReport(
        domain="example.com",
        generated_utc="2026-10-02T00:00:00Z",
        inputs_present=["discover", "probe", "portscan", "inspect"],
        domain_score=31,
        domain_band="CRITICAL",
        counts={"findings_critical": 1, "findings_high": 2, "findings_info": 1},
        hosts=[
            HostScore(
                subdomain="db.example.com",
                score=17,
                band="CRITICAL",
                findings=[
                    Finding(
                        id="PORT_EXPOSED_DB",
                        title="Database port exposed",
                        tier="CRITICAL",
                        points=10,
                        source="portscan",
                        host="db.example.com",
                        port=5432,
                        evidence="tcp/5432 open",
                        why_it_matters="Databases should not be internet-facing.",
                    ),
                    Finding(
                        id="TLS_EXPIRED",
                        title="Expired certificate",
                        tier="HIGH",
                        points=7,
                        source="inspect",
                        host="db.example.com",
                        port=443,
                    ),
                ],
            ),
            HostScore(
                subdomain="www.example.com",
                score=14,
                band="HIGH",
                findings=[
                    Finding(
                        id="HSTS_MISSING",
                        title="HSTS missing",
                        tier="HIGH",
                        points=7,
                        source="inspect",
                        host="www.example.com",
                        port=443,
                    ),
                    Finding(
                        id="INFO_SERVER_HEADER",
                        title="Server header present",
                        tier="INFO",
                        points=0,
                        source="probe",
                        host="www.example.com",
                    ),
                ],
            ),
        ],
    ).to_dict()

    res = extract_fix_first_findings(report)
    assert res.total == 4
    assert res.counts == {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 0, "INFO": 1}
    assert res.domain_band == "CRITICAL"
    assert [f.id for f in res.findings] == [
        "PORT_EXPOSED_DB",
        "TLS_EXPIRED",
        "HSTS_MISSING",
        "INFO_SERVER_HEADER",
    ]
    assert res.findings[0].port == 5432
    assert res.findings[0].evidence == "tcp/5432 open"


def test_check_polling_status():
    """Verify polling decision based on status and 15-minute age cap."""
    now = datetime(2026, 10, 2, 10, 20, 0, tzinfo=UTC)

    # Finished scans never poll
    assert check_polling_status("succeeded", now - timedelta(minutes=5), now=now) == (False, False)
    assert check_polling_status("failed", now - timedelta(minutes=5), now=now) == (False, False)

    # Active scan < 15 minutes polls
    assert check_polling_status("running", now - timedelta(minutes=5), now=now) == (True, False)
    assert check_polling_status("queued", now - timedelta(minutes=14, seconds=50), now=now) == (
        True,
        False,
    )

    # Active scan >= 15 minutes stops polling and reports stale active
    assert check_polling_status("running", now - timedelta(minutes=15, seconds=1), now=now) == (
        False,
        True,
    )
    assert check_polling_status("queued", now - timedelta(minutes=30), now=now) == (False, True)
