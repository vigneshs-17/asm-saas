"""Database integration tests for worker scan scheduling and concurrency."""

from __future__ import annotations

import concurrent.futures
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from asm.db.models import Domain, ScanRun, ScanStage
from asm.db.scans import enqueue_scan
from asm.worker.worker import ASMWorker


@pytest.mark.db
def test_scheduler_enqueues_due_domain_with_scheduled_trigger(
    db_engine, clean_db: None
) -> None:
    """Worker scheduler selects due domains, creates queued scan with trigger='scheduled',
    and advances next_scan_at.
    """
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        t_due = datetime.now(UTC) - timedelta(minutes=5)
        domain = Domain(
            name="due-domain.com",
            authorized=True,
            scan_interval_hours=24,
            next_scan_at=t_due,
        )
        session.add(domain)
        session.commit()
        domain_id = domain.id

    worker = ASMWorker(engine=db_engine, poll_interval=1.0)
    processed = worker.schedule_due_scans(batch_limit=10)
    assert processed == 1

    with session_factory() as session:
        # Verify scan run created with scheduled trigger
        run = session.scalar(select(ScanRun).where(ScanRun.domain_id == domain_id))
        assert run is not None
        assert run.status == "queued"
        assert run.trigger == "scheduled"

        # Verify all 5 stages created
        stages = session.scalars(
            select(ScanStage).where(ScanStage.scan_run_id == run.id)
        ).all()
        assert len(stages) == 5
        assert {s.stage for s in stages} == {
            "discover",
            "probe",
            "portscan",
            "inspect",
            "score",
        }

        # Verify next_scan_at is pushed 24 hours into the future
        updated_domain = session.get(Domain, domain_id)
        assert updated_domain is not None
        assert updated_domain.next_scan_at is not None
        min_future = datetime.now(UTC) + timedelta(hours=23, minutes=59)
        max_future = datetime.now(UTC) + timedelta(hours=24, minutes=6)
        assert min_future <= updated_domain.next_scan_at <= max_future


@pytest.mark.db
def test_scheduler_concurrent_workers_produce_exactly_one_scan(
    db_engine, clean_db: None
) -> None:
    """Multiple concurrent workers running schedule_due_scans produce exactly
    one scan for a due domain.
    """
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        domain = Domain(
            name="concurrent-sched.com",
            authorized=True,
            scan_interval_hours=12,
            next_scan_at=datetime.now(UTC) - timedelta(minutes=10),
        )
        session.add(domain)
        session.commit()
        domain_id = domain.id

    worker1 = ASMWorker(engine=db_engine, worker_id="worker-1", poll_interval=1.0)
    worker2 = ASMWorker(engine=db_engine, worker_id="worker-2", poll_interval=1.0)

    # Run schedule_due_scans simultaneously across threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(worker1.schedule_due_scans, 10)
        f2 = executor.submit(worker2.schedule_due_scans, 10)
        res1 = f1.result()
        res2 = f2.result()

    # Total domains processed across workers must be 1 (one locked and scheduled, one skipped)
    assert res1 + res2 == 1

    with session_factory() as session:
        runs = session.scalars(select(ScanRun).where(ScanRun.domain_id == domain_id)).all()
        assert len(runs) == 1
        assert runs[0].trigger == "scheduled"


@pytest.mark.db
def test_scheduler_active_scan_skips_duplicate_and_advances_schedule(
    db_engine, clean_db: None
) -> None:
    """If a domain already has an active scan, the scheduler creates no duplicate
    and advances next_scan_at.
    """
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        t_due = datetime.now(UTC) - timedelta(minutes=10)
        domain = Domain(
            name="active-scan-sched.com",
            authorized=True,
            scan_interval_hours=24,
            next_scan_at=t_due,
        )
        session.add(domain)
        session.flush()

        # Existing active scan
        active_run = ScanRun(domain_id=domain.id, status="running", trigger="manual")
        session.add(active_run)
        session.commit()
        domain_id = domain.id
        active_run_id = active_run.id

    worker = ASMWorker(engine=db_engine, poll_interval=1.0)
    processed = worker.schedule_due_scans(batch_limit=10)
    assert processed == 1

    with session_factory() as session:
        # Still exactly one scan run (no duplicate created)
        all_runs = session.scalars(select(ScanRun).where(ScanRun.domain_id == domain_id)).all()
        assert len(all_runs) == 1
        assert all_runs[0].id == active_run_id

        # Schedule was still advanced into future
        updated_domain = session.get(Domain, domain_id)
        assert updated_domain is not None
        assert updated_domain.next_scan_at > datetime.now(UTC)


@pytest.mark.db
def test_scheduler_skips_unauthorized_and_null_interval_domains(
    db_engine, clean_db: None
) -> None:
    """Unauthorized domains or domains with null intervals are never scheduled."""
    session_factory = sessionmaker(bind=db_engine)
    t_past = datetime.now(UTC) - timedelta(hours=1)
    with session_factory() as session:
        # 1. Unauthorized domain with interval and past next_scan_at
        d_unauth = Domain(
            name="unauth-due.com",
            authorized=False,
            scan_interval_hours=24,
            next_scan_at=t_past,
        )
        # 2. Authorized domain with null interval and past next_scan_at
        d_null = Domain(
            name="null-interval.com",
            authorized=True,
            scan_interval_hours=None,
            next_scan_at=t_past,
        )
        session.add_all([d_unauth, d_null])
        session.commit()

    worker = ASMWorker(engine=db_engine, poll_interval=1.0)
    processed = worker.schedule_due_scans(batch_limit=10)
    assert processed == 0

    with session_factory() as session:
        runs = session.scalars(select(ScanRun)).all()
        assert len(runs) == 0


@pytest.mark.db
def test_scheduler_no_backfill_after_downtime(db_engine, clean_db: None) -> None:
    """After 10 missed intervals during downtime, domain gets exactly ONE catch-up scan, not 10."""
    session_factory = sessionmaker(bind=db_engine)
    t_10_days_ago = datetime.now(UTC) - timedelta(days=10)
    with session_factory() as session:
        domain = Domain(
            name="downtime-domain.com",
            authorized=True,
            scan_interval_hours=24,
            next_scan_at=t_10_days_ago,
        )
        session.add(domain)
        session.commit()
        domain_id = domain.id

    worker = ASMWorker(engine=db_engine, poll_interval=1.0)
    processed = worker.schedule_due_scans(batch_limit=10)
    assert processed == 1

    # Second scheduler invocation finds no more due scans
    processed_again = worker.schedule_due_scans(batch_limit=10)
    assert processed_again == 0

    with session_factory() as session:
        runs = session.scalars(select(ScanRun).where(ScanRun.domain_id == domain_id)).all()
        assert len(runs) == 1
        assert runs[0].trigger == "scheduled"

        updated_domain = session.get(Domain, domain_id)
        assert updated_domain is not None
        # next_scan_at is now 24h into the future, NOT t_10_days_ago + 24h
        assert updated_domain.next_scan_at > datetime.now(UTC) + timedelta(hours=23)


@pytest.mark.db
def test_scheduler_reraises_non_active_scan_integrity_error(
    db_engine, clean_db: None
) -> None:
    """Scheduler re-raises IntegrityError when the violation is NOT uq_scan_runs_active_domain."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        domain = Domain(
            name="foreign-key-err.com",
            authorized=True,
            scan_interval_hours=24,
            next_scan_at=datetime.now(UTC) - timedelta(minutes=5),
        )
        session.add(domain)
        session.commit()

    worker = ASMWorker(engine=db_engine, poll_interval=1.0)

    # Mock enqueue_scan to raise an IntegrityError for a different constraint
    # (e.g. check constraint)
    fake_orig = MagicMock()
    fake_orig.diag.constraint_name = "ck_other_constraint"
    non_active_error = IntegrityError("statement", {}, fake_orig)

    with patch("asm.worker.worker.enqueue_scan", side_effect=non_active_error):
        with pytest.raises(IntegrityError):
            worker.schedule_due_scans(batch_limit=10)


@pytest.mark.db
def test_scheduler_exception_does_not_stop_job_claiming(
    db_engine, clean_db: None
) -> None:
    """An unexpected exception during schedule_due_scans does not stop job claiming."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        domain = Domain(name="claim-resilient.com", authorized=True)
        session.add(domain)
        session.flush()

        queued_run = enqueue_scan(session, domain.id, trigger="manual")
        session.commit()
        queued_id = queued_run.id

    worker = ASMWorker(engine=db_engine, poll_interval=1.0)

    # Mock schedule_due_scans to raise RuntimeError
    with patch.object(worker, "schedule_due_scans", side_effect=RuntimeError("Scheduler exploded")):
        with patch.object(worker, "execute_scan_run", return_value=True) as mock_exec:
            claimed = worker.run_poll_cycle()
            assert claimed is True
            mock_exec.assert_called_once()
            args = mock_exec.call_args[0]
            assert args[0] == queued_id
