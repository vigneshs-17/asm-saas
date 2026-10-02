# Engineering Log

## Entries

### Entry A: Operator-Verified Domain Transition on DNS Match
- **What happened:** Code review identified that an operator-verified domain could match a DNS TXT check and remain verified indefinitely without undergoing continuous background re-verification.
- **Root cause:** Verification state transition logic was duplicated across API endpoints and worker routines, leading to inconsistent state assignment (`verification_method`, `next_reverification_at`, `verification_expires_at`).
- **Fix:** Consolidated all verification state transitions into a single authoritative pure function: `apply_check_outcome(domain, outcome, now) -> bool` in `src/asm/verification.py`.
- **How to prevent it:** Maintain a single state transition function for all verification outcomes and enforce full broken-path integration tests covering state transitions end-to-end.

### Entry B: Fail-Open Default in Alert Trigger Rules
- **What happened:** `should_trigger_alerts` had a fail-open default argument `verified=True`.
- **Root cause:** Parameter defaulted to `True` during helper refactoring, allowing unverified domains to trigger alerts if callers omitted the argument.
- **Fix:** Removed default values and made `verified: bool` a required argument without default; removed deprecated `authorized` parameter.
- **How to prevent it:** Security gates must never use permissive or fail-open default arguments; required arguments ensure explicit verification checks.

### Entry C: Database Integration Tests Hung on Unreachable PostgreSQL
- **What happened:** On 2026-10-02, database integration tests hung indefinitely instead of failing fast when the test PostgreSQL service was unreachable (most likely Docker Desktop was not yet running; root cause not confirmed).
- **Root cause:** Database connection pool lacked an explicit client-side connection timeout, so a connection attempt could wait without a bound.
- **Fix:** Configured `connect_args={"connect_timeout": 5}` on the test SQLAlchemy engine in `tests/conftest.py`.
- **How to prevent it:** Explicitly configure bounded connect timeouts on database drivers in both test and application harnesses.

### Entry D: DNS Lookup Under Row Lock
- **What happened:** Known trade-off: DNS lookup runs while holding the domain database row lock (`SELECT ... FOR UPDATE`) during manual verification checks.
- **Root cause:** Atomic enforcement of the 30-second verification cooldown across distributed API processes required acquiring the row lock before updating `last_checked_at` and resolving DNS.
- **Fix:** Not fixed; trade-off accepted for current scale. DNS lookup timeout is short and bounded (about 5s), and cooldown prevents concurrent requests on the same domain. Revisit if measured contention occurs.
- **How to prevent it:** If database lock contention is measured under load, decouple cooldown checks and DNS resolution into a two-phase check.

### Entry E: Metadata Checker Exception on Pattern Match Risked Aborting Business Transactions
- **What happened:** The initial v3.3 plan proposed rejecting audit events if metadata contained values matching email or IP patterns, which would raise an exception inside the caller's database transaction.
- **Root cause:** Raising exceptions on pattern matching within audit metadata validation risked aborting critical business operations (e.g. background verification lapses or domain creation with unconventional names).
- **Fix:** Switched to strict per-action allowlists of allowed keys and types; free-text inputs (`org.created` name, operator override reason) are truncated to 500 characters and emails/IP addresses are masked as `[redacted]` instead of rejecting or raising errors.
- **How to prevent it:** Never fail an operational or background transaction due to secondary audit trail formatting; sanitize and mask rather than reject.

### Entry F: Model `index=True` on `AuditEvent.org_id` Caused Schema Drift Against Migration 0009
- **What happened:** `src/asm/db/models.py` had `index=True` on `AuditEvent.org_id`, but migration 0009 only created composite indexes `ix_audit_events_org_id_id` and `ix_audit_events_org_target`. `alembic check` would report schema drift.
- **Root cause:** Declaring `index=True` on a single column in SQLAlchemy creates an implicit single-column index (`ix_audit_events_org_id`) in model metadata that was never defined in the Alembic migration script.
- **Fix:** Removed `index=True` from `AuditEvent.org_id` in `src/asm/db/models.py`. The composite index `(org_id, id)` already covers queries filtering by `org_id`.
- **How to prevent it:** Always run `alembic check` to detect discrepancies between SQLAlchemy model definitions and migration scripts; avoid redundant single-column indexes when a composite index with that column as the leading prefix exists.

### Entry G: Missing Behavioural Tests for 7 of 15 Audit Actions
- **What happened:** Code review found that while route tables and schema maps listed all 15 audit actions, 7 actions lacked behavioural tests verifying that calling the API endpoint actually wrote an audit event to the database.
- **Root cause:** Initial tests asserted the existence of route-to-action mappings rather than exercising the actual HTTP endpoints against the database.
- **Fix:** Added dedicated DB integration tests for all untested actions (`membership.added`, `membership.role_changed`, `membership.removed`, `domain.alerts_changed`, `verification.checked`, `verification.rotated`, `scan.queued`), verifying exact action, actor type, actor user ID, target, and metadata. Added a test confirming idempotent replay of `POST /scans` writes no duplicate `scan.queued` event.
- **How to prevent it:** Test end-to-end event generation through API calls rather than asserting on static lookup tables.

### Entry H: Progress Line Mismatch from Retyped Builder Output
- **What happened:** Discrepancies between builder output text and test progress summaries previously occurred when test outputs or progress counts were manually retyped.
- **Root cause:** Manual retyping and copy-pasting across conversation turns led to drift and unverified claims.
- **Fix / Prevention:** The repo owner runs tests directly in his terminal before every commit, avoiding synthetic or misaligned test count reporting.

---

## Architectural Decisions

### 1. DNS TXT at Dedicated `_asm-verify` Label
- **Decision:** Verification tokens are published as a DNS TXT record at `_asm-verify.<domain>` with value `asm-verify=<token>`.
- **Rejected alternatives:** Zone apex (`@`) TXT record. (Recorded in `docs/LEARNING_NOTES.md`: rejected due to apex congestion with SPF, DMARC, and third-party SaaS verification tokens, risking DNS UDP response sizes exceeding 512 bytes / EDNS limits, and preventing sub-zone delegation).

### 2. Two Definite Misses Before Lapse
- **Decision:** A domain transitions from `verified` to `lapsed` only after 2 consecutive definite misses (`ABSENT`), with a 1-hour fast retry scheduled after the first miss.
- **Rejected alternatives:** not recorded.

### 3. UNKNOWN Never Counts Toward Lapses
- **Decision:** Transient network failures, resolver timeouts, and `SERVFAIL` yield `UNKNOWN` and never increment `consecutive_misses` or cause status lapses.
- **Rejected alternatives:** not recorded.

### 4. Operator Override Expiring After 1-90 Days
- **Decision:** Operator break-glass overrides require a non-empty reason and mandatory expiration between 1 and 90 days (default 30 days).
- **Rejected alternatives:** not recorded.

### 5. Database Trigger vs Code-Only Convention for Append-Only
- **Decision:** Enforced append-only audit log integrity via a PostgreSQL trigger (`trg_audit_events_append_only`) that raises an exception on `UPDATE` or `DELETE`.
- **Rejected alternatives:** Code-only repository convention (e.g. omitting update/delete methods in ORM). Rejected because code-only enforcement offers no protection against direct SQL execution, database migrations, or developer mistakes; anyone with DB access could quietly alter history. Note: It is append-only against the application; the table owner can disable the trigger.

### 6. Two `domain.moved` Events (Source and Target Organizations)
- **Decision:** When a domain is transferred between organizations via operator command (`asm admin move-domain`), two distinct audit events are recorded in the same transaction: one under the source organization (`target_type="domain"`, `metadata={"to_org_id": ...}`) and one under the target organization (`target_type="domain"`, `metadata={"from_org_id": ...}`).
- **Rejected alternatives:** Single event under the source organization or target organization only. Rejected because tenant audit queries are strictly filtered by `org_id`; a single event would leave one organization with an incomplete audit trail for asset transfers.

### 7. Plain Composite Indexes: `(org_id, id)` and `(org_id, target_type, target_id)`
- **Decision:** Created composite B-tree indexes `ix_audit_events_org_id_id` on `(org_id, id)` and `ix_audit_events_org_target` on `(org_id, target_type, target_id)`. PostgreSQL scans this index backwards for ORDER BY id DESC, so no DESC index is needed.
- **Rejected alternatives:** Standalone single-column indexes on `org_id`, `target_id`, or `created_at`. Rejected because tenant queries always require `org_id` filtering first; composite indexes with `org_id` as the leading column provide optimal index-only/index-scan performance and support cursor pagination (`WHERE org_id = :org_id AND id < :before_id ORDER BY id DESC`).

---

## Known Limitations

- **Append-only scope:** The `audit_events` table is append-only against the application; the table owner can disable the trigger.
- **Retention & Purge:** No retention or purge policy is currently implemented; audit logs grow indefinitely until partitioned or archived.
- **Unrecorded Events:** Denied requests (e.g. HTTP 401/403 authorization failures), IP addresses, user agents, and user login events are not recorded in the audit log.

---

## Metrics

- tests collected 339 -> 375, db tests 91 -> 112.
- v3.3 audit logging added 15 tracked actions, migration 0009, and append-only trigger protection.
