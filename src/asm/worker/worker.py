"""Asynchronous background worker executing scan runs from PostgreSQL."""

from __future__ import annotations

import json
import logging
import os
import signal
import socket
import threading
import time
import uuid
from typing import Any

from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from asm.db.models import Domain, ScanResult
from asm.scan_common import sanitize_error_text
from asm.worker.exceptions import (
    EXPECTED_SCANNER_ERRORS,
    LostLeaseError,
    SecurityGateError,
)
from asm.worker.runner import DirectScannerRunner, IScannerRunner

logger = logging.getLogger("asm.worker")

ALL_STAGES = ("discover", "probe", "portscan", "inspect", "score")


class HeartbeatThread(threading.Thread):
    """Background thread renewing worker lease at fixed intervals using its own DB session."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        scan_run_id: int,
        claim_token: uuid.UUID,
        lease_duration: int,
        heartbeat_interval: float,
        lost_lease_event: threading.Event,
    ) -> None:
        super().__init__(daemon=True, name=f"Heartbeat-{scan_run_id}")
        self.session_factory = session_factory
        self.scan_run_id = scan_run_id
        self.claim_token = claim_token
        self.lease_duration = lease_duration
        self.heartbeat_interval = heartbeat_interval
        self.lost_lease_event = lost_lease_event
        self.stop_requested = threading.Event()

    def run(self) -> None:
        logger.debug("Heartbeat thread started for scan_run_id=%d", self.scan_run_id)
        while not self.stop_requested.wait(self.heartbeat_interval):
            try:
                with self.session_factory() as session:
                    res = session.execute(
                        text(
                            """
                            UPDATE scan_runs
                            SET lease_expires_at = now()
                                + CAST(:lease_duration || ' seconds' AS INTERVAL)
                            WHERE id = :id AND status = 'running' AND claim_token = :token
                            """
                        ),
                        {
                            "id": self.scan_run_id,
                            "lease_duration": self.lease_duration,
                            "token": self.claim_token,
                        },
                    )
                    session.commit()
                    if res.rowcount == 0:
                        logger.warning(
                            "Heartbeat found 0 rows updated for scan_run_id=%d (lease lost)",
                            self.scan_run_id,
                        )
                        self.lost_lease_event.set()
                        break
            except Exception as exc:
                logger.warning(
                    "Error executing heartbeat for scan_run_id=%d: %s",
                    self.scan_run_id,
                    exc,
                )

    def stop(self) -> None:
        self.stop_requested.set()


class ASMWorker:
    """Production-grade scan runner claiming jobs from PostgreSQL via SKIP LOCKED."""

    def __init__(
        self,
        engine: Engine | None = None,
        runner: IScannerRunner | None = None,
        worker_id: str | None = None,
        poll_interval: float = 3.0,
        lease_duration: int = 60,
        heartbeat_interval: float = 15.0,
    ) -> None:
        if engine is None:
            from asm.db.session import get_engine

            self.engine = get_engine()
        else:
            self.engine = engine
        self.session_factory = sessionmaker(bind=self.engine)
        self.runner = runner or DirectScannerRunner()
        self.poll_interval = poll_interval
        self.lease_duration = lease_duration
        self.heartbeat_interval = heartbeat_interval
        self.worker_id = worker_id or (
            f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        )
        self.shutdown_requested = threading.Event()

    def install_signal_handlers(self) -> None:
        """Register signal handlers to initiate graceful shutdown on SIGTERM / SIGINT."""

        def _handle_signal(signum: int, frame: Any) -> None:
            logger.info("Signal %d received: initiating graceful worker shutdown", signum)
            self.shutdown_requested.set()

        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

    def run(self) -> None:
        """Main worker execution loop."""
        logger.info(
            "Starting ASM worker %s (poll_interval=%.1fs)",
            self.worker_id,
            self.poll_interval,
        )
        self.install_signal_handlers()

        while not self.shutdown_requested.is_set():
            try:
                self.run_poll_cycle()
            except Exception:
                logger.exception("Unexpected error in worker poll cycle")

            self.shutdown_requested.wait(self.poll_interval)

        logger.info("Worker %s shut down gracefully.", self.worker_id)

    def run_poll_cycle(self) -> bool:
        """Execute one complete polling cycle: recovery, poison pills, and claiming."""
        self.reclaim_stale_leases_and_poison_pills()

        if self.shutdown_requested.is_set():
            return False

        claimed = self.claim_next_job()
        if claimed is None:
            return False

        scan_run_id, domain_id, claim_token, attempts, max_attempts = claimed
        logger.info(
            "Claimed scan_run_id=%d domain_id=%d attempt=%d/%d token=%s",
            scan_run_id,
            domain_id,
            attempts,
            max_attempts,
            claim_token,
        )

        self.execute_scan_run(scan_run_id, domain_id, claim_token, attempts, max_attempts)
        return True

    def reclaim_stale_leases_and_poison_pills(self) -> None:
        """Run SQL lease recovery and poison pill termination."""
        with self.session_factory() as session:
            # Poison pill termination: attempts >= max_attempts with expired lease
            poisoned_runs = session.execute(
                text(
                    """
                    UPDATE scan_runs
                    SET status = 'failed',
                        finished_at = now(),
                        claimed_by = NULL,
                        claim_token = NULL,
                        lease_expires_at = NULL,
                        error = 'Execution aborted: maximum retry attempts ('
                                || max_attempts
                                || ') exceeded without completion (lease expired).'
                    WHERE status = 'running'
                      AND lease_expires_at < now()
                      AND attempts >= max_attempts
                    RETURNING id, error
                    """
                )
            ).fetchall()

            for p_run in poisoned_runs:
                session.execute(
                    text(
                        """
                        UPDATE scan_stages
                        SET status = 'failed',
                            finished_at = now(),
                            error = :error
                        WHERE scan_run_id = :id AND status = 'running'
                        """
                    ),
                    {"id": p_run.id, "error": p_run.error},
                )
                session.execute(
                    text(
                        """
                        UPDATE scan_stages
                        SET status = 'skipped',
                            started_at = coalesce(started_at, now()),
                            finished_at = now(),
                            duration_ms = 0,
                            error = 'Skipped: maximum retry attempts exceeded (lease expired)'
                        WHERE scan_run_id = :id AND status = 'pending'
                        """
                    ),
                    {"id": p_run.id},
                )

            # Stale lease recovery: attempts < max_attempts with expired lease
            # Backoff is computed dynamically per-row in SQL from its own attempts count:
            # base 10s, doubling, capped at 120s, plus random jitter up to 5s.
            session.execute(
                text(
                    """
                    UPDATE scan_runs
                    SET status = 'queued',
                        claimed_by = NULL,
                        claimed_at = NULL,
                        claim_token = NULL,
                        lease_expires_at = NULL,
                        next_attempt_at = now() + (
                            LEAST(120.0, 10.0 * POWER(2.0, GREATEST(0, attempts - 1)))
                            + (random() * 5.0)
                        ) * INTERVAL '1 second',
                        error = 'Lease expired (worker unresponsive). Re-queued for retry.'
                    WHERE status = 'running'
                      AND lease_expires_at < now()
                      AND attempts < max_attempts
                    """
                )
            )
            session.commit()

    def claim_next_job(self) -> tuple[int, int, uuid.UUID, int, int] | None:
        """Atomically claim the oldest eligible queued scan run."""
        new_token = uuid.uuid4()
        with self.session_factory() as session:
            result = session.execute(
                text(
                    """
                    WITH next_run AS (
                        SELECT id, error
                        FROM scan_runs
                        WHERE status = 'queued'
                          AND (next_attempt_at IS NULL OR next_attempt_at <= now())
                          AND attempts < max_attempts
                        ORDER BY created_at ASC
                        FOR UPDATE SKIP LOCKED
                        LIMIT 1
                    )
                    UPDATE scan_runs
                    SET status = 'running',
                        started_at = COALESCE(scan_runs.started_at, now()),
                        claimed_by = :worker_id,
                        claim_token = :claim_token,
                        claimed_at = now(),
                        lease_expires_at = now()
                            + CAST(:lease_duration || ' seconds' AS INTERVAL),
                        attempts = attempts + 1,
                        error = NULL
                    FROM next_run
                    WHERE scan_runs.id = next_run.id
                    RETURNING
                        scan_runs.id,
                        scan_runs.domain_id,
                        scan_runs.attempts,
                        scan_runs.max_attempts,
                        next_run.error;
                    """
                ),
                {
                    "worker_id": self.worker_id,
                    "claim_token": new_token,
                    "lease_duration": self.lease_duration,
                },
            )
            row = result.fetchone()
            if not row:
                session.commit()
                return None

            run_id, domain_id, attempts, max_attempts, previous_error = row
            if previous_error:
                logger.info(
                    "Resuming scan_run_id=%d; previous error: %s",
                    run_id,
                    previous_error,
                )

            # Reset any stage stuck in 'running' back to 'pending'
            session.execute(
                text(
                    """
                    UPDATE scan_stages
                    SET status = 'pending',
                        started_at = NULL,
                        finished_at = NULL,
                        duration_ms = NULL,
                        error = NULL
                    WHERE scan_run_id = :run_id
                      AND status = 'running'
                    """
                ),
                {"run_id": run_id},
            )
            session.commit()
            return run_id, domain_id, new_token, attempts, max_attempts

    def _verify_fence(self, session: Session, scan_run_id: int, claim_token: uuid.UUID) -> None:
        """Verify worker lease ownership via FOR SHARE lock."""
        res = session.execute(
            text(
                """
                SELECT 1 FROM scan_runs
                WHERE id = :id AND status = 'running' AND claim_token = :token
                FOR SHARE
                """
            ),
            {"id": scan_run_id, "token": claim_token},
        ).fetchone()
        if not res:
            raise LostLeaseError(
                f"Worker {self.worker_id} lost lease for scan_run_id={scan_run_id}"
            )

    def execute_scan_run(
        self,
        scan_run_id: int,
        domain_id: int,
        claim_token: uuid.UUID,
        attempts: int,
        max_attempts: int,
    ) -> None:
        """Execute the 5-stage pipeline with fenced writes, heartbeat, and signal checks."""
        lost_lease_event = threading.Event()
        heartbeat = HeartbeatThread(
            session_factory=self.session_factory,
            scan_run_id=scan_run_id,
            claim_token=claim_token,
            lease_duration=self.lease_duration,
            heartbeat_interval=self.heartbeat_interval,
            lost_lease_event=lost_lease_event,
        )
        heartbeat.start()

        reports: dict[str, dict[str, Any]] = {}
        stage_failed_flag = False
        terminal_security_error: str | None = None

        try:
            # 1. Fetch domain record and load existing succeeded stage reports
            with self.session_factory() as session:
                self._verify_fence(session, scan_run_id, claim_token)
                domain = session.get(Domain, domain_id)
                if not domain:
                    raise SecurityGateError(f"Domain ID {domain_id} does not exist.")
                if not domain.authorized:
                    raise SecurityGateError(
                        f"Target domain '{domain.name}' authorization is revoked."
                    )
                domain_name = domain.name

                # Load existing succeeded reports for resume capability
                existing_results = (
                    session.query(ScanResult).filter_by(scan_run_id=scan_run_id).all()
                )
                for r in existing_results:
                    reports[r.stage] = r.report

            # Pipeline execution: discover -> probe -> portscan -> inspect -> score
            stages = ["discover", "probe", "portscan", "inspect", "score"]

            for stage in stages:
                if lost_lease_event.is_set():
                    raise LostLeaseError(f"Lease lost detected during stage {stage}")

                # Check SIGTERM signal between stages
                if self.shutdown_requested.is_set():
                    logger.info(
                        "Graceful shutdown requested between stages; releasing job %d",
                        scan_run_id,
                    )
                    self._graceful_release(scan_run_id, claim_token)
                    return

                # Check if this stage already succeeded in a prior attempt
                if stage in reports:
                    logger.info(
                        "Stage '%s' already succeeded for scan_run_id=%d; skipping",
                        stage,
                        scan_run_id,
                    )
                    continue

                # Stage dependency evaluation
                should_skip = False
                skip_reason = None

                if stage in ("probe", "portscan", "score") and "discover" not in reports:
                    should_skip = True
                    skip_reason = "Discover stage did not succeed"
                elif stage == "inspect" and "probe" not in reports:
                    should_skip = True
                    skip_reason = "Probe stage did not succeed"

                if should_skip:
                    self._mark_stage_skipped(scan_run_id, claim_token, stage, skip_reason)
                    continue

                # Worker-side authorization gate check before active network stages
                if stage in ("probe", "portscan", "inspect"):
                    with self.session_factory() as session:
                        fresh_domain = session.get(Domain, domain_id)
                        if not fresh_domain or not fresh_domain.authorized:
                            raise SecurityGateError(
                                f"Active scanning authorization revoked for '{domain_name}'"
                            )

                # Mark stage 'running' in short transaction
                self._mark_stage_running(scan_run_id, claim_token, stage)

                # Execute stage logic outside database transaction
                stage_start_mono = time.monotonic()
                try:
                    report = self._run_stage_runner(stage, domain_name, reports)
                    duration_ms = int((time.monotonic() - stage_start_mono) * 1000)

                    # Save stage result & mark stage succeeded in ONE transaction
                    self._save_stage_success(scan_run_id, claim_token, stage, report, duration_ms)
                    reports[stage] = report
                except EXPECTED_SCANNER_ERRORS as exc:
                    duration_ms = int((time.monotonic() - stage_start_mono) * 1000)
                    err_msg = str(exc)
                    logger.warning(
                        "Expected error in stage '%s' for run %d: %s",
                        stage,
                        scan_run_id,
                        err_msg,
                    )
                    self._mark_stage_failed(scan_run_id, claim_token, stage, err_msg, duration_ms)
                    stage_failed_flag = True

                    if isinstance(exc, SecurityGateError):
                        terminal_security_error = err_msg
                        for rem in stages[stages.index(stage) + 1 :]:
                            self._mark_stage_skipped(
                                scan_run_id,
                                claim_token,
                                rem,
                                "Skipped: authorization revoked",
                            )
                        break

                    if stage == "discover":
                        # Discover failure prevents all subsequent stages
                        for rem in ("probe", "portscan", "inspect", "score"):
                            self._mark_stage_skipped(
                                scan_run_id,
                                claim_token,
                                rem,
                                "Skipped due to discover failure",
                            )
                        break

            # Mark final run status
            if terminal_security_error:
                self._mark_run_final(scan_run_id, claim_token, "failed", terminal_security_error)
            elif stage_failed_flag or len(reports) < len(stages):
                # Any stage failure means run failed (partial success visible in scan_results)
                self._mark_run_final(
                    scan_run_id,
                    claim_token,
                    "failed",
                    "One or more scan stages failed or were skipped",
                )
            else:
                summary, changes, baseline_id = self._perform_change_detection(
                    scan_run_id, domain_id, reports
                )
                self._mark_run_final(
                    scan_run_id,
                    claim_token,
                    "succeeded",
                    None,
                    change_detection=summary,
                    changes=changes,
                    domain_id=domain_id,
                    baseline_scan_run_id=baseline_id,
                )

        except SecurityGateError as exc:
            logger.warning(
                "Terminal SecurityGateError for scan_run_id=%d: %s; failing permanently",
                scan_run_id,
                exc,
            )
            for st in ("discover", "probe", "portscan", "inspect", "score"):
                try:
                    self._mark_stage_skipped(
                        scan_run_id, claim_token, st, "Skipped: authorization revoked"
                    )
                except Exception:
                    pass
            self._mark_run_final(scan_run_id, claim_token, "failed", str(exc))

        except LostLeaseError as exc:
            logger.warning(
                "Worker lost lease for scan_run_id=%d: %s; discarding in-memory work",
                scan_run_id,
                exc,
            )
            return

        except Exception as exc:
            logger.exception("Unexpected exception executing scan_run_id=%d", scan_run_id)
            if not lost_lease_event.is_set():
                self._handle_unexpected_worker_exception(
                    scan_run_id, claim_token, str(exc), attempts, max_attempts
                )

        finally:
            heartbeat.stop()

    def _run_stage_runner(
        self, stage: str, domain: str, reports: dict[str, dict[str, Any]]
    ) -> dict[str, Any]:
        """Dispatch stage execution to the configured IScannerRunner."""
        if stage == "discover":
            return self.runner.run_discover(domain)
        elif stage == "probe":
            return self.runner.run_probe(domain, reports["discover"], authorized=True)
        elif stage == "portscan":
            return self.runner.run_portscan(domain, reports["discover"], authorized=True)
        elif stage == "inspect":
            return self.runner.run_inspect(domain, reports["probe"], authorized=True)
        elif stage == "score":
            return self.runner.run_score(
                domain,
                discover_report=reports["discover"],
                probe_report=reports.get("probe"),
                portscan_report=reports.get("portscan"),
                inspect_report=reports.get("inspect"),
            )
        else:
            raise ValueError(f"Unknown scan stage: {stage}")

    def _mark_stage_running(self, scan_run_id: int, claim_token: uuid.UUID, stage: str) -> None:
        """Mark stage status as 'running' in a short transaction with fence check."""
        with self.session_factory() as session:
            self._verify_fence(session, scan_run_id, claim_token)
            res = session.execute(
                text(
                    """
                    UPDATE scan_stages
                    SET status = 'running',
                        started_at = now()
                    WHERE scan_run_id = :id AND stage = :stage
                    """
                ),
                {"id": scan_run_id, "stage": stage},
            )
            if res.rowcount == 0:
                raise LostLeaseError(f"Failed to set stage {stage} to running: 0 rows affected")
            session.commit()

    def _save_stage_success(
        self,
        scan_run_id: int,
        claim_token: uuid.UUID,
        stage: str,
        report: dict[str, Any],
        duration_ms: int,
    ) -> None:
        """Store artifact report in scan_results and mark stage succeeded in ONE transaction."""
        import json

        report_json = json.dumps(report)
        with self.session_factory() as session:
            self._verify_fence(session, scan_run_id, claim_token)

            # Insert report into scan_results
            res_results = session.execute(
                text(
                    """
                    INSERT INTO scan_results (scan_run_id, stage, report, created_at)
                    SELECT :id, :stage, CAST(:report_json AS jsonb), now()
                    WHERE EXISTS (
                        SELECT 1 FROM scan_runs
                        WHERE id = :id AND status = 'running' AND claim_token = :token
                    )
                    """
                ),
                {
                    "id": scan_run_id,
                    "stage": stage,
                    "report_json": report_json,
                    "token": claim_token,
                },
            )
            if res_results.rowcount == 0:
                raise LostLeaseError(
                    f"Failed to insert scan_result for stage {stage}: 0 rows affected"
                )

            # Update stage status to succeeded
            res_stages = session.execute(
                text(
                    """
                    UPDATE scan_stages
                    SET status = 'succeeded',
                        finished_at = now(),
                        duration_ms = :duration_ms,
                        error = NULL
                    WHERE scan_run_id = :id AND stage = :stage
                    """
                ),
                {"id": scan_run_id, "stage": stage, "duration_ms": duration_ms},
            )
            if res_stages.rowcount == 0:
                raise LostLeaseError(
                    f"Failed to update scan_stage {stage} to succeeded: 0 rows affected"
                )

            session.commit()

    def _mark_stage_failed(
        self,
        scan_run_id: int,
        claim_token: uuid.UUID,
        stage: str,
        error_msg: str,
        duration_ms: int,
    ) -> None:
        """Mark stage as 'failed' in a short transaction."""
        sanitized_error = sanitize_error_text(error_msg)
        with self.session_factory() as session:
            self._verify_fence(session, scan_run_id, claim_token)
            res = session.execute(
                text(
                    """
                    UPDATE scan_stages
                    SET status = 'failed',
                        finished_at = now(),
                        duration_ms = :duration_ms,
                        error = :error
                    WHERE scan_run_id = :id AND stage = :stage
                    """
                ),
                {
                    "id": scan_run_id,
                    "stage": stage,
                    "duration_ms": duration_ms,
                    "error": sanitized_error,
                },
            )
            if res.rowcount == 0:
                raise LostLeaseError(f"Failed to mark stage {stage} failed: 0 rows affected")
            session.commit()

    def _mark_stage_skipped(
        self, scan_run_id: int, claim_token: uuid.UUID, stage: str, reason: str | None
    ) -> None:
        """Mark stage as 'skipped' in a short transaction."""
        sanitized_reason = sanitize_error_text(reason)
        with self.session_factory() as session:
            self._verify_fence(session, scan_run_id, claim_token)
            res = session.execute(
                text(
                    """
                    UPDATE scan_stages
                    SET status = 'skipped',
                        started_at = now(),
                        finished_at = now(),
                        duration_ms = 0,
                        error = :reason
                    WHERE scan_run_id = :id AND stage = :stage
                    """
                ),
                {"id": scan_run_id, "stage": stage, "reason": sanitized_reason},
            )
            if res.rowcount == 0:
                raise LostLeaseError(f"Failed to mark stage {stage} skipped: 0 rows affected")
            session.commit()

    def _perform_change_detection(
        self,
        scan_run_id: int,
        domain_id: int,
        new_reports: dict[str, dict[str, Any]],
    ) -> tuple[dict[str, Any], list[dict[str, Any]], int | None]:
        """Perform in-memory change detection against the most recent earlier succeeded scan."""
        from asm.changes import detect_changes, evaluate_removal_eligibility

        with self.session_factory() as session:
            baseline_row = session.execute(
                text(
                    """
                    SELECT id FROM scan_runs
                    WHERE domain_id = :domain_id AND status = 'succeeded' AND id < :current_id
                    ORDER BY id DESC LIMIT 1
                    """
                ),
                {"domain_id": domain_id, "current_id": scan_run_id},
            ).fetchone()

            if not baseline_row:
                summary = {
                    "status": "baseline",
                    "baseline_scan_run_id": None,
                    "removal_detection": "skipped",
                    "skip_reason": "No previous succeeded scan (first scan is baseline)",
                    "error": None,
                    "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                }
                return summary, [], None

            baseline_id = baseline_row[0]
            results = session.execute(
                text(
                    """
                    SELECT stage, report FROM scan_results
                    WHERE scan_run_id = :baseline_id
                    """
                ),
                {"baseline_id": baseline_id},
            ).fetchall()
            baseline_reports = {r[0]: r[1] for r in results}

        base_disc = baseline_reports.get("discover") or {}
        new_disc = new_reports.get("discover") or {}
        allow_removal, skip_reason = evaluate_removal_eligibility(base_disc, new_disc)

        try:
            changes = detect_changes(baseline_reports, new_reports, allow_removal=allow_removal)
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for ch in changes:
                sev = ch.get("severity", "INFO").lower()
                if sev in counts:
                    counts[sev] += 1

            summary = {
                "status": "computed",
                "baseline_scan_run_id": baseline_id,
                "removal_detection": "performed" if allow_removal else "skipped",
                "skip_reason": skip_reason,
                "error": None,
                "counts": counts,
            }
            return summary, changes, baseline_id

        except Exception as exc:
            logger.exception(
                "Change detection failed for scan_run_id=%d against baseline_id=%d",
                scan_run_id,
                baseline_id,
            )
            summary = {
                "status": "failed",
                "baseline_scan_run_id": baseline_id,
                "removal_detection": "skipped",
                "skip_reason": None,
                "error": sanitize_error_text(str(exc)),
                "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            }
            return summary, [], baseline_id

    def _mark_run_final(
        self,
        scan_run_id: int,
        claim_token: uuid.UUID,
        status: str,
        error_msg: str | None,
        change_detection: dict[str, Any] | None = None,
        changes: list[dict[str, Any]] | None = None,
        domain_id: int | None = None,
        baseline_scan_run_id: int | None = None,
    ) -> None:
        """Set terminal status for scan_run and clear claim tokens."""
        sanitized_error = sanitize_error_text(error_msg)
        change_detection_json = (
            json.dumps(change_detection) if change_detection is not None else None
        )
        with self.session_factory() as session:
            self._verify_fence(session, scan_run_id, claim_token)

            # Insert detected changes in the fenced transaction
            if changes and baseline_scan_run_id and domain_id:
                for ch in changes:
                    session.execute(
                        text(
                            """
                            INSERT INTO scan_changes (
                                domain_id,
                                scan_run_id,
                                baseline_scan_run_id,
                                change_type,
                                category,
                                severity,
                                asset,
                                detail,
                                evidence,
                                previous_state,
                                new_state,
                                observed_at,
                                created_at
                            ) VALUES (
                                :domain_id,
                                :scan_run_id,
                                :baseline_scan_run_id,
                                :change_type,
                                :category,
                                :severity,
                                :asset,
                                :detail,
                                :evidence,
                                CAST(:previous_state AS jsonb),
                                CAST(:new_state AS jsonb),
                                :observed_at,
                                now()
                            )
                            """
                        ),
                        {
                            "domain_id": domain_id,
                            "scan_run_id": scan_run_id,
                            "baseline_scan_run_id": baseline_scan_run_id,
                            "change_type": ch["change_type"],
                            "category": ch["category"],
                            "severity": ch["severity"],
                            "asset": ch["asset"],
                            "detail": ch["detail"],
                            "evidence": ch["evidence"],
                            "previous_state": (
                                json.dumps(ch["previous_state"])
                                if ch.get("previous_state") is not None
                                else None
                            ),
                            "new_state": (
                                json.dumps(ch["new_state"])
                                if ch.get("new_state") is not None
                                else None
                            ),
                            "observed_at": ch["observed_at"],
                        },
                    )

            res = session.execute(
                text(
                    """
                    UPDATE scan_runs
                    SET status = :status,
                        finished_at = now(),
                        claimed_by = NULL,
                        claim_token = NULL,
                        lease_expires_at = NULL,
                        error = :error,
                        change_detection = CAST(:change_detection AS jsonb)
                    WHERE id = :id AND status = 'running' AND claim_token = :token
                    """
                ),
                {
                    "id": scan_run_id,
                    "status": status,
                    "error": sanitized_error,
                    "token": claim_token,
                    "change_detection": change_detection_json,
                },
            )
            if res.rowcount == 0:
                raise LostLeaseError(f"Failed to set final status for scan_run_id={scan_run_id}")

            # Terminal-state invariant:
            # any stage still 'running' -> 'failed' with the run's error
            session.execute(
                text(
                    """
                    UPDATE scan_stages
                    SET status = 'failed',
                        finished_at = now(),
                        error = :error
                    WHERE scan_run_id = :id AND status = 'running'
                    """
                ),
                {"id": scan_run_id, "error": sanitized_error or "Scan run terminated"},
            )
            # any 'pending' stage -> 'skipped' with a reason
            skip_reason = sanitized_error or (
                "Scan run succeeded" if status == "succeeded" else "Skipped: scan run terminated"
            )
            session.execute(
                text(
                    """
                    UPDATE scan_stages
                    SET status = 'skipped',
                        started_at = coalesce(started_at, now()),
                        finished_at = now(),
                        duration_ms = 0,
                        error = :reason
                    WHERE scan_run_id = :id AND status = 'pending'
                    """
                ),
                {"id": scan_run_id, "reason": skip_reason},
            )
            session.commit()

    def _handle_unexpected_worker_exception(
        self,
        scan_run_id: int,
        claim_token: uuid.UUID,
        error_msg: str,
        attempts: int,
        max_attempts: int,
    ) -> None:
        """Requeue or fail run on unexpected error using DB clock and retry budget."""
        try:
            with self.session_factory() as session:
                self._verify_fence(session, scan_run_id, claim_token)
                if attempts < max_attempts:
                    sanitized_error = sanitize_error_text(
                        f"Unexpected worker error: {error_msg}"
                    )
                    # Requeue with SQL exponential backoff + jitter
                    session.execute(
                        text(
                            """
                            UPDATE scan_runs
                            SET status = 'queued',
                                claimed_by = NULL,
                                claim_token = NULL,
                                lease_expires_at = NULL,
                                next_attempt_at = now() + (
                                    LEAST(120.0, 10.0 * POWER(2.0, GREATEST(0, attempts - 1)))
                                    + (random() * 5.0)
                                ) * INTERVAL '1 second',
                                error = :error
                            WHERE id = :id AND status = 'running' AND claim_token = :token
                            """
                        ),
                        {
                            "id": scan_run_id,
                            "token": claim_token,
                            "error": sanitized_error,
                        },
                    )
                else:
                    # Attempts reached max_attempts; mark failed permanently
                    sanitized_error = sanitize_error_text(
                        f"Max retry attempts exceeded: {error_msg}"
                    )
                    res = session.execute(
                        text(
                            """
                            UPDATE scan_runs
                            SET status = 'failed',
                                finished_at = now(),
                                claimed_by = NULL,
                                claim_token = NULL,
                                lease_expires_at = NULL,
                                error = :error
                            WHERE id = :id AND status = 'running' AND claim_token = :token
                            """
                        ),
                        {
                            "id": scan_run_id,
                            "token": claim_token,
                            "error": sanitized_error,
                        },
                    )
                    if res.rowcount > 0:
                        # Terminal-state invariant:
                        # any stage still 'running' -> 'failed' with the run's error
                        session.execute(
                            text(
                                """
                                UPDATE scan_stages
                                SET status = 'failed',
                                    finished_at = now(),
                                    error = :error
                                WHERE scan_run_id = :id AND status = 'running'
                                """
                            ),
                            {"id": scan_run_id, "error": sanitized_error},
                        )
                        # any 'pending' stage -> 'skipped' with a reason
                        session.execute(
                            text(
                                """
                                UPDATE scan_stages
                                SET status = 'skipped',
                                    started_at = coalesce(started_at, now()),
                                    finished_at = now(),
                                    duration_ms = 0,
                                    error = 'Skipped: maximum retry attempts exceeded'
                                WHERE scan_run_id = :id AND status = 'pending'
                                """
                            ),
                            {"id": scan_run_id},
                        )
                session.commit()
        except Exception as exc:
            logger.error("Failed to update status on unexpected exception: %s", exc)

    def _graceful_release(self, scan_run_id: int, claim_token: uuid.UUID) -> None:
        """Release claimed run gracefully on SIGTERM without consuming an attempt."""
        try:
            with self.session_factory() as session:
                self._verify_fence(session, scan_run_id, claim_token)
                session.execute(
                    text(
                        """
                        UPDATE scan_runs
                        SET status = 'queued',
                            claimed_by = NULL,
                            claimed_at = NULL,
                            claim_token = NULL,
                            lease_expires_at = NULL,
                            attempts = GREATEST(attempts - 1, 0)
                        WHERE id = :id AND status = 'running' AND claim_token = :token
                        """
                    ),
                    {"id": scan_run_id, "token": claim_token},
                )
                session.commit()
                logger.info("Successfully released scan_run_id=%d gracefully", scan_run_id)
        except Exception as exc:
            logger.error("Failed graceful release for scan_run_id=%d: %s", scan_run_id, exc)
