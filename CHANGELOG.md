# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### User Authentication & Organizations (v3.1a)
- **Supabase JWT Authentication**: Dependency-injected token verification (`verify_access_token`, `JWKSManager`) validating RS256/ES256 signatures against Supabase JWKS endpoints with cache TTL, min refresh interval, and fail-closed security.
- **Just-In-Time (JIT) User Provisioning**: Automatic upsertion of authenticated users into the `users` table upon verified token presentation.
- **Organization & Role-Based Access Control**: Multi-tenant organizations with membership roles (`owner`, `admin`, `viewer`) and role hierarchies (`ROLE_RANKS`).
- **Organization Management Endpoints**: Endpoints for organization creation (`POST /orgs`), listing (`GET /orgs`), and member management (`POST /orgs/{id}/members`, `PATCH /orgs/{id}/members/{user_id}`, `DELETE /orgs/{id}/members/{user_id}`).
- **Last-Owner Invariant**: Enforced constraint preventing demotion or removal of an organization's final owner.

#### Tenant Isolation (v3.1b)
- **Multi-Tenant Scoping**: All domains and scans partitioned by organization ID (`org_id`); API routes scoped under `/orgs/{org_id}/...`.
- **Anti-Enumeration Security Invariant**: Non-members attempting to access an organization's resources receive HTTP 404 (Not Found), never HTTP 403 (Forbidden), preventing organization ID enumeration.
- **Database-Level Isolation**: `domains.org_id` foreign key with per-organization uniqueness `(org_id, name)`; scans, results and alerts are scoped through their domain. Every tenant query filters by `id` and `org_id` in SQL.
- **Legacy Quarantine Migration (0007)**: Creates a quarantine organization identified by `system_kind = 'legacy_quarantine'` (never by name) and assigns existing domains to it.
- **Operator Move-Domain CLI**: Administrative command `asm admin move-domain --domain-id <id> --target-org-id <id>` for moving quarantined domains to target organizations.

#### Domain Ownership Verification via DNS TXT (v3.2)
- **Proof of DNS Control**: Replaced client-asserted `authorized: true` with proof of DNS control using high-entropy secret tokens (`secrets.token_urlsafe(32)`) published as DNS TXT records at `_asm-verify.<domain>`.
- **DNS TXT Check Engine**: Resolver logic with `dnspython` joining multi-string RFC 1035 TXT chunks and matching `asm-verify=<token>`.
- **Failure Taxonomy**: Tri-state check logic: `MATCH` (verified), `ABSENT` (definite negative: NXDOMAIN or missing/mismatched record), `UNKNOWN` (indeterminate: timeout, SERVFAIL, network error; never counts as a miss).
- **Verification State Machine**: State tracking (`pending`, `verified`, `lapsed`) with centralized transition function `apply_check_outcome()`.
- **Continuous Re-Verification**: Daily worker re-checks with randomized jitter; 2-miss threshold with 1-hour fast retries before transitioning to `lapsed`.
- **Scan Gating**: Endpoints and worker refuse scans for unverified domains (`HTTP 422 Unprocessable Content`). Worker verifies domain ownership before every active stage (`discover`, `probe`, `portscan`, `inspect`, `score`), halting mid-scan if lapsed or revoked.
- **Rate-Limited Verification API**: `GET /verification` for instructions, `POST /verification/check` with a 30-second database row-locked cooldown, and `POST /verification/rotate` to reset token and status.
- **Outbox Lapse Alerts**: Atomic emission of transactional outbox email notifications (`"Domain verification lapsed: monitoring paused"`) upon domain lapse or operator override expiration.
- **Operator Break-Glass Overrides**: Administrative CLI `asm admin verify-domain --domain-id <id> --reason "<text>" [--expires-in-days <1..90>]` and `asm admin revoke-verification --domain-id <id> --reason "<text>"` with mandatory justifications and bounded expiration.

### Changed
- **BREAKING (API)**: Removed `authorized` and `authorization_note` fields from `DomainCreate` request schema and database models. Client can no longer assert authorization.
- **BREAKING (Database)**: Migration `0008_domain_verification` resets all existing domains to `verification_status = 'pending'`, pausing automated scheduled scans until DNS verification is completed.
- **Alert Trigger Rules**: `should_trigger_alerts` requires explicit `verified: bool` argument; removed deprecated `authorized` parameter.

## [2.0.0] - 2026-10-01

### Added

#### API & Database Persistence (v2.1)
- **FastAPI REST Service**: Endpoints for target domain management (`POST /domains`, `GET /domains`), scan initiation (`POST /domains/{id}/scans`), status/progress tracking (`GET /scans/{id}`), and artifact retrieval (`GET /scans/{id}/results/{stage}`).
- **PostgreSQL Storage & Migrations**: SQLAlchemy ORM models (`Domain`, `ScanRun`, `ScanStage`, `ScanResult`, `ScanChange`, `AlertNotification`) with automated Alembic migrations and drift checks.
- **Safety & Authorization Gates**: Preserved non-negotiable security controls requiring explicit target authorization (`authorized: true`) and strict domain normalization before scanning.

#### Asynchronous Scan Worker & Job Queue (v2.2)
- **Database-Backed Job Queue**: Asynchronous worker claiming jobs via PostgreSQL `FOR UPDATE SKIP LOCKED` without external message broker dependencies.
- **Fenced Execution**: Fencing token (`claim_token` UUID) validation per stage to prevent zombie worker overwrites.
- **Crash Recovery & Heartbeats**: Lease-based worker recovery with exponential backoff and randomized SQL jitter.
- **Terminal State Invariants**: Atomic guarantee that failing a scan transitions any remaining stages cleanly to `failed` or `skipped`.
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
- **Worker Outbox Delivery**: Dedicated polling (`deliver_pending_alerts`) using `FOR UPDATE SKIP LOCKED`, holding the row lock during SMTP transmission with a 10s socket timeout to prevent concurrent duplicate sends; delivery is at-least-once.
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
  - HTTPS first, then HTTP, on ports 80/443 web availability probing with in-scope redirect following (max 5) and 64 KB response streaming cap.
- **Phase 3: TCP Port Scanning (`asm portscan`)**:
  - Asynchronous TCP connect scan over 16 common service ports (`21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443`).
  - Polite pacing and concurrency limits (max 10 ports per host, max 5 hosts concurrently).
  - Passive and polite banner grabbing with 256-character truncation.
- **Phase 4: TLS & Header Inspection (`asm inspect`)**:
  - TLS certificate validation (expiration, hostname mismatch, self-signed/untrusted, deprecated protocols).
  - Security header evaluation across six monitored headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`) and information-disclosure headers (`Server`, `X-Powered-By`, `X-AspNet-Version`).
- **Phase 5: Heuristic Risk Scoring (`asm score`)**:
  - Severity-tier triage (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`); host band = worst finding, points only as a tiebreaker; explicitly not CVSS; every finding carries host, port, source and evidence.
- **CLI Interface**: Single unified command-line entry point with JSON report export.
