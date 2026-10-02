# Status

## Test Suite
- Test counts: see the CI run on the latest commit

## Done
- v1 CLI: 5-stage reconnaissance scanner core (`discover`, `probe`, `portscan`, `inspect`, `score`).
- v2.0.0 Service: FastAPI REST API, PostgreSQL persistence, PostgreSQL-backed background job queue (FOR UPDATE SKIP LOCKED), CT Cert Spotter fallback.
- v2.3 Change Detection: Finding-based differential engine with severity-aware transitions.
- v2.4 Scheduling & Alerts: Periodic scheduler (`FOR UPDATE SKIP LOCKED`) and transactional outbox email alerts.
- v3.1a User Auth & Organizations: Supabase JWT auth, JIT user provisioning, organizations RBAC (`owner`, `admin`, `viewer`).
- v3.1b Tenant Isolation: Foreign keys, strict organization-scoped queries, anti-enumeration (404 on cross-tenant), legacy quarantine migration.
- v3.2 Domain Verification: Proof of DNS control via DNS TXT (`_asm-verify.<domain>`), continuous re-verification, scan gating, break-glass operator overrides with expiry.
- v3.3 Audit Log: Append-only audit_events table, trigger against app tampering, 15 structured actions, and organization audit API.

## In Progress
- None.

## Next
- v3.4: Dashboard.

## Known Limitations
- DNS lookup during manual check runs while holding the domain database row lock (bounded about 5s).
- Integration test suite requires PostgreSQL (SQLite is unsupported for DB tests).
- The table owner can disable the audit_events append-only trigger; no retention/purge; denied requests not logged.
