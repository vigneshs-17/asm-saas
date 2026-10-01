# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-10-01

### Added

#### API & Database Persistence (v2.1)
- **FastAPI REST Service**: Endpoints for target domain management (`POST /domains`, `GET /domains`), scan initiation (`POST /domains/{id}/scans`), status/progress tracking (`GET /scans/{id}`), and artifact retrieval (`GET /scans/{id}/results/{stage}`).
- **PostgreSQL Storage & Migrations**: SQLAlchemy ORM models (`Domain`, `ScanRun`, `ScanStage`, `ScanResult`, `ScanChange`, `AlertNotification`) with automated Alembic migrations and drift checks.
- **Safety & Authorization Gates**: Preserved non-negotiable security controls requiring explicit target authorization (`authorized: true`) and strict domain normalization before scanning.

#### Asynchronous Scan Worker & Job Queue (v2.2)
- **Database-Backed Job Queue**: Asynchronous worker claiming jobs via PostgreSQL `FOR UPDATE SKIP LOCKED` without external message broker dependencies.
- **Fenced Execution**: Cryptographic `claim_token` UUID validation per stage to prevent zombie worker overwrites.
- **Crash Recovery & Heartbeats**: Lease-based worker recovery with exponential backoff and randomized SQL jitter.
- **Terminal State Invariants**: Atomic guarantee that cancelling or failing a scan transitions any remaining stages cleanly to `failed` or `skipped`.
- **Containerized Architecture**: Multi-stage, non-root Docker Compose setup for API, worker, and database services.

#### Certificate Transparency Fallback (v2.2.1)
- **SSLMate Cert Spotter Integration**: Automated fallback from `crt.sh` to the Cert Spotter API upon primary aggregator failures or timeouts.
- **Bounded Pagination & Rate Limiting**: Pagination capped at 10 pages / 5,000 entries with HTTP 429 `Retry-After` backoff handling.
- **Structured Discovery Metadata**: Reports record discovery `source` (`crt.sh` vs `certspotter`), sanitized `fallback_reason`, and `truncated` status.
- **Unified Error Hierarchy**: `DiscoveryError` base class with `CrtshError`, `CertSpotterError`, and `AllSourcesFailedError`.

#### Attack Surface Change Detection (v2.3)
- **Finding-Based Differential Engine**: Pure function (`detect_changes`) comparing reports between consecutive succeeded scans against `scoring.py` finding evaluators.
- **Definitive Severity Mapping**: Additions inherit finding severities (`CRITICAL` to `LOW`); reductions are classified as `INFO` only when verified on active hosts.
- **"Unknown is Not Absent" Invariant**: DNS timeouts, unreachable hosts, and filtered ports are treated as indeterminate and never produce false removal changes.
- **Source & Truncation Guards**: Subdomain removals are evaluated only when baseline and new scans share discovery sources and neither was truncated.
- **Changes Query API**: Endpoints for querying historical changes (`GET /domains/{id}/changes` and `GET /scans/{id}/changes`) with filtering and pagination.

#### Scheduled Scans Engine (v2.4a)
- **Database-Backed Polling**: Background worker claims due scheduled scans (`schedule_due_scans`) each cycle via `FOR UPDATE SKIP LOCKED`.
- **Per-Domain Cadence**: Configurable scan intervals (6 to 720 hours) with randomized jitter to disperse network and database load.
- **Shared Enqueue Pipeline**: Unified `enqueue_scan()` used by both manual API triggers and the automated scheduler with trigger provenance.
- **No-Backfill Guarantee**: System downtime results in a single catch-up scan with schedule advanced from current time.
- **Active Scan Suppression**: PostgreSQL partial unique index prevents concurrent active scans for the same domain.
- **Schedule Management API**: `PUT /domains/{id}/schedule` endpoint to configure, update, or disable automated scanning.

#### Transactional Outbox Email Alerts (v2.4b)
- **Transactional Outbox Pattern**: Atomic insertion of `alert_notifications` within the same transaction that commits detected changes and marks a scan succeeded, eliminating dual-write risks.
- **In-Memory Fault Isolation**: Alert formatting runs prior to transaction; formatting errors are captured in `change_detection["alert_error"]` without failing the scan run.
- **Worker Outbox Delivery**: Dedicated polling (`deliver_pending_alerts`) using `FOR UPDATE SKIP LOCKED`, holding the row lock during SMTP transmission with a 10s socket timeout to eliminate duplicate sends.
- **CRLF Injection Defense & Sanitization**: Headers sanitized of `\r` and `\n`; email addresses validated via Pydantic `EmailStr`; plain-text digests with finding truncation.
- **Exponential Backoff**: Failed delivery attempts retried via SQL `next_attempt_at = now() + make_interval(secs => :s)` up to 5 attempts.
- **Alert Settings & History API**: `PUT /domains/{id}/alerts` for threshold configuration and `GET /domains/{id}/alert-notifications` for delivery audit logs.
- **Local Mailpit Environment**: Added Mailpit mock SMTP service under Docker Compose `dev` profile for local testing.

---

## [1.0.0] - 2026-09-29

### Added

#### 5-Stage Reconnaissance Scanner Core (CLI)
- **Phase 1: Passive Subdomain Discovery (`asm discover`)**:
  - Certificate Transparency queries against `crt.sh` with backoff and retry.
  - Multi-threaded DNS resolution using `dnspython` for `A` and `AAAA` records.
  - Wildcard stripping, domain normalization, and scope enforcement.
- **Phase 2: Active Host Probing (`asm probe`)**:
  - Mandatory `--authorized` confirmation gate.
  - SSRF protections blocking private, loopback, link-local, and reserved IP ranges.
  - Dual-stack HTTP/HTTPS web availability probing with in-scope redirect following (max 5) and 64 KB response streaming cap.
- **Phase 3: TCP Port Scanning (`asm portscan`)**:
  - Asynchronous TCP connect scan over 16 common service ports (`21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443`).
  - Polite pacing and concurrency limits (max 10 ports per host, max 5 hosts concurrently).
  - Passive and polite banner grabbing with 256-character truncation.
- **Phase 4: TLS & Header Inspection (`asm inspect`)**:
  - TLS certificate validation (expiration, hostname mismatch, self-signed/untrusted, deprecated protocols).
  - Security header evaluation (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, info disclosure).
- **Phase 5: Heuristic Risk Scoring (`asm score`)**:
  - Evidence-based risk scoring algorithm (0-100 score, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` risk bands).
  - Transparent score contributors and actionable mitigation recommendations.
- **CLI Interface**: Single unified command-line entry point with JSON report export.
