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

### Entry I: Plan Used Unscoped Write Paths for Domain Verification Endpoints
- **What happened:** The initial v3.4a implementation plan proposed writing to `/domains/{domain_id}/verification/check` and `/domains/{domain_id}/verification/rotate`.
- **Root cause:** Author referenced pre-v3.1b unscoped endpoints from memory instead of verifying the current tenant-isolated route signatures introduced in v3.1b.
- **Fix:** Caught in design review. Updated client fetch calls and plan to use the exact tenant-isolated write paths: `/orgs/{org_id}/domains/{domain_id}/verification/check` and `/orgs/{org_id}/domains/{domain_id}/verification/rotate`.
- **How to prevent it:** Always inspect the actual OpenAPI route table or router definitions before specifying client API URLs.

### Entry J: Synchronous `htmx:configRequest` vs Asynchronous `supabase.auth.getSession()`
- **What happened:** Attempting to inject the Bearer auth token into HTMX requests dynamically using `supabase.auth.getSession()` failed because HTMX's `htmx:configRequest` event is strictly synchronous.
- **Root cause:** Awaiting a promise inside `htmx:configRequest` does not pause the dispatch; the request was dispatched immediately without the `Authorization` header.
- **Fix:** Stored the current JWT access token in a module-level variable updated synchronously by Supabase's `onAuthStateChange` listener. The `htmx:configRequest` listener reads this variable synchronously.
- **How to prevent it:** Never attempt asynchronous fetching inside synchronous lifecycle hooks; maintain in-memory state driven by event listeners.

### Entry K: Invisible Check Result Due to HTMX Settle Reapplying Classes
- **What happened:** After clicking "Check now", the verification outcome was briefly rendered into `#verification-check-result` but immediately disappeared, leaving the container hidden. Found by reproducing in headless Chrome.
- **Root cause:** HTMX's settle phase runs ~20ms after swapping the HTML partial and reapplies the attributes from the response template. Because the template had `class="hidden"`, HTMX reapplied `class="hidden"` after `app.js` had removed it.
- **Fix:** Removed `class="hidden"` from the `#verification-check-result` template element in `templates/partials/domain_detail.html` (using `aria-live="polite"` instead), refreshed domain detail first, and populated the container after the swap finished.
- **How to prevent it:** Do not use CSS hiding classes on dynamically populated target containers within HTMX swapped fragments; rely on empty content and `aria-live="polite"` for live regions.

### Entry L: CSP Blocked HTMX Injected Indicator Inline Style
- **What happened:** HTMX automatically injected an inline `<style>` tag for `.htmx-indicator` into the document `<head>`, violating the strict `style-src 'self'` Content Security Policy.
- **Root cause:** HTMX injects default indicator styles unless explicitly disabled via configuration.
- **Fix:** Added `<meta name="htmx-config" content='{"includeIndicatorStyles": false, "allowEval": false, "allowScriptTags": false}'>` in `<head>` before the HTMX script tag in `base.html`, and set `window.htmx.config.allowEval = false` and `window.htmx.config.allowScriptTags = false` in `app.js`.
- **How to prevent it:** Check third-party script defaults against strict CSP directives; configure library behavior via meta tags before script execution.

### Entry M: Untested XSS Test Failed on Jinja Quote Escaping
- **What happened:** An XSS escaping test was written expecting `&lt;script&gt;alert("org-xss")&lt;/script&gt;`, but Jinja autoescape also escapes double quotes (`"` becomes `&#34;`), causing an assertion error. The test had been committed without being run locally.
- **Root cause:** The builder assumed Jinja only escapes angle brackets and failed to run the newly created test before reporting completion.
- **Fix:** Updated test assertions to check `assert "<script>" not in resp.text` and `assert "&lt;script&gt;" in resp.text`. Prevention: the builder runs every test it writes; the owner re-runs.
- **How to prevent it:** The builder must run every test it writes; the repo owner re-runs before every commit.

### Entry N: UI Reset on Supabase Token Refresh
- **What happened:** Whenever Supabase automatically refreshed the user's session token (`TOKEN_REFRESHED`), the auth state listener re-executed the entire initial sign-in logic, causing jarring UI reloads and disrupting active user interactions.
- **Root cause:** The `onAuthStateChange` callback treated all session events identically, calling `onUserAuthenticated()` on both `SIGNED_IN` and `TOKEN_REFRESHED`.
- **Fix:** Handled `TOKEN_REFRESHED` by only updating `currentAccessToken` in module memory and returning early without touching the DOM. Guarded `onUserAuthenticated()` with an `isAuthenticated` flag so it runs only once per sign-in.
- **How to prevent it:** Distinguish between token lifecycle events (`TOKEN_REFRESHED`) and user session state changes (`SIGNED_IN`, `SIGNED_OUT`).

### Entry O: Fix-First Count Cards Always Showed 0 on Real Scans
- **What happened:** In real scans, the summary cards for Critical, High, Medium, and Low findings displayed 0 even when findings of those tiers existed.
- **Root cause:** Test fixtures were built using invented dictionary keys (e.g., `{"CRITICAL": 1, "HIGH": 2}`), whereas the real producer `ScoreReport.to_dict()` in `scoring.py` serializes keys as `findings_critical`, `findings_high`, `hosts_high`, etc.
- **Fix:** Per-tier counts are now computed directly from all parsed findings in memory before applying the 50-row cap (`counts = dict.fromkeys(TIER_ORDER, 0)`), ignoring the producer's internal report counts mapping.
- **How to prevent it:** Build test fixtures from the real producer (`ScoreReport(...).to_dict()`) rather than handwriting mock dictionary payloads.

### Entry P: Scans List Showed "No Changes" for Scans with Real Changes
- **What happened:** The domain scans list showed "No changes" for completed scans that actually had detected attack surface changes.
- **Root cause:** The initial UI parser expected a `"total"` key inside `scan_runs.change_detection["counts"]`. The worker (`worker.py`) writes counts as a dictionary of five individual tiers (`{"critical": ..., "high": ..., "medium": ..., "low": ..., "info": ...}`) without any `"total"` key.
- **Fix:** Updated `format_change_summary` to sum the counts across all five tiers (`critical`, `high`, `medium`, `low`, `info`). If the sum is zero, it renders "No changes"; otherwise, it lists non-zero tiers (e.g. `1 critical, 2 info`).
- **How to prevent it:** Use contract test fixtures derived directly from worker output rather than synthetic test dictionaries.

### Entry Q: Finished Scans Re-Fetched on Every Click
- **What happened:** Clicking anywhere inside a completed or failed scan detail panel triggered an unwanted HTTP GET request back to the server.
- **Root cause:** `hx-get` was placed unconditionally on the `<section id="scan-detail-container">` container. When the scan finished, `hx-trigger="every 3s"` was omitted, causing HTMX to fall back to its default element trigger (`click`).
- **Fix:** Emitted all HTMX polling attributes (`hx-get`, `hx-target="this"`, `hx-swap="outerHTML"`, `hx-trigger="every 3s"`) together inside `{% if should_poll %}`. Finished scans omit `hx-get` entirely.
- **How to prevent it:** In HTMX templates, never emit `hx-get` without an explicit trigger if the element is not intended to be clickable.

### Entry R: CSP Blocked Inline Style Attributes
- **What happened:** The strict Content Security Policy (`style-src 'self'`) blocked 8 inline `style="..."` attributes in the dashboard partials.
- **Root cause:** Quick inline styling was added during development without considering that `style-src 'self'` forbids inline styles.
- **Fix:** Replaced all inline style attributes with semantic CSS classes in `src/asm/static/css/app.css` (`.section-header`, `.section-header-first`, `.stage-card-error`, `.finding-why`, `.findings-more`, `.run-scan-hint`, `.scan-meta`). Added `test_templates_have_no_csp_blocked_inline_code` to catch inline styles during test runs.
- **How to prevent it:** Enforce CSP compliance in automated test suites with a template AST or regex guard test.

### Entry S: Two Broken Test Cases in v3.4b Suite
- **What happened:** Two newly added tests failed during implementation: one failed on database uniqueness constraint, and one failed on ordering assertion.
- **Root cause:**
  1. Setting up two running scans for the same domain violated the partial unique index `uq_scan_runs_active_domain` (which permits at most one queued or running scan per domain).
  2. Capping test generated hostnames like `host1.example.com`, `host2.example.com` ... `host10.example.com`; alphabetical string sorting placed `host10` before `host2`, breaking the expected index sequence.
- **Fix:**
  1. Used a separate domain fixture for the stale active scan test case.
  2. Zero-padded test hostnames (`host00`, `host01`, ..., `host59`) so alphabetical ordering matches integer index ordering.
- **How to prevent it:** Respect domain database constraints in test setup; use zero-padding when string ordering must align with numeric sequence.

### Entry T: 401 Token Refresh Nested Duplicate Polling Containers
- **What happened:** Code review (not a user report) found that if an access token expired during background polling, the 401 refresh-and-retry would re-render the scan detail container nested inside the existing one.
- **Root cause:** The scan detail poller uses `hx-target="this"` and `hx-swap="outerHTML"`. The generic 401 retry handler in `app.js` executed `window.htmx.ajax()` with default swap behavior (`innerHTML`), inserting the outer container inside itself.
- **Fix:** Updated `app.js` 401 response error handler to inspect the source element's `hx-swap` attribute (`evt.detail.elt.getAttribute('hx-swap')`) and preserve it on retry (`retryContext.swap = swapStyle`).
- **How to prevent it:** When replaying requests in HTMX error handlers, preserve the original request's swap and target context.

### Entry U: WCAG AA Color Contrast Failure on Tungsten Warning Text
- **What happened:** Accessibility check revealed that `--color-tungsten-warning: #c25700` on `--color-tungsten-bg: #fff8f0` yielded a contrast ratio of 4.28:1, failing WCAG AA requirements ($\ge 4.5:1$).
- **Root cause:** The color was selected visually without calculating the WCAG 2.x relative-luminance contrast ratio against the light background.
- **Fix:** Introduced `--color-tungsten-text: #a84b00`, which achieves 5.43:1 contrast against `#fff8f0` (exceeding WCAG AA 4.5:1), retaining `#c25700` for borders and non-text accents only.
- **How to prevent it:** Calculate and verify relative-luminance contrast ratios for all foreground text tokens against their respective backgrounds during design token creation.

### Entry V: Builder's Implementation Report Described Pre-Fix Code and Claimed Full Pass Without Output
- **What happened:** An earlier implementation report described outdated banner text, unconditional `hx-get`, and stale contrast numbers (6.81/6.25), claiming full-suite pass without pasting raw execution output.
- **Root cause:** The builder summarized initial planning intentions and pre-fix code from memory instead of inspecting the final modified files on disk and pasting verified terminal output.
- **Fix:** Verified on disk: Signal Crimson `#a81a2e` has 7.36:1 contrast on `#ffffff` and 6.77:1 on `#fdf3f4`; Tungsten text `#a84b00` has 5.43:1 on `#fff8f0`. All documentation is strictly sourced from disk.
- **How to prevent it:** Documentation must be written from code on disk; reports must include verbatim, raw command output.

### Entry W: Owner Full Test Run Encountered 139 Setup ERRORs
- **What happened:** The owner's first full run failed at import (ModuleNotFoundError: sqlalchemy); the second run produced 139 ERRORs.
- **Root cause:**
  1. On the first run, pytest was invoked with the host Python instead of the virtual environment (`.venv`), missing installed dependencies (`ModuleNotFoundError: sqlalchemy`).
  2. On the second run, the throwaway PostgreSQL test container (`asm-test-db`) had stopped, causing connection timeouts on port `5433`. Note that in pytest, `ERROR` denotes test fixture or setup failure, whereas `FAILED` denotes test assertion failure.
- **Fix:** Activated `.venv`, ensured `TEST_DATABASE_URL` was exported, and started `asm-test-db` container (`docker start asm-test-db`). All 430 tests then passed cleanly.
- **How to prevent it:** Always run tests using `.venv\Scripts\pytest`, verify that `TEST_DATABASE_URL` is set, and confirm the test database container is running with `docker ps` before running integration tests.

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

### 8. Option A (FastAPI + Jinja2 + HTMX) over Next.js
- **Decision:** Built the v3.4a dashboard as a server-rendered application using FastAPI, Jinja2 templates, and HTMX, with client-side Supabase JS.
- **Rejected alternatives:** Next.js / React SPA. Rejected because a separate Node.js/TypeScript frontend introduces a second programming language, a second package manager (npm), a complex build step, and a second deployment target, increasing operational complexity and attack surface for a lean security tool.

### 9. Bearer Header vs Cookie Session
- **Decision:** Authenticated browser requests to both the JSON API and HTMX `/ui/*` endpoints using `Authorization: Bearer <token>` in the header, passed synchronously.
- **Rejected alternatives:** Session cookies (`Set-Cookie`). Rejected because cookies require CSRF protection tokens, cookie parsing middleware, and dual-auth paths for API and browser clients. Bearer tokens in headers are inherently immune to CSRF. The trade-off is readability via XSS, which is mitigated by strict CSP (`default-src 'self'`, no inline scripts or styles), Jinja autoescaping, and `textContent`-only rendering.

### 10. HTMX 2.x over HTMX 4.0
- **Decision:** Vendored stable HTMX 2.0.11.
- **Rejected alternatives:** HTMX 4.0 pre-release / majors. Rejected due to breaking API changes, unstable ecosystem support, and lack of proven production hardening.

### 11. sessionStorage over localStorage
- **Decision:** Configured Supabase Auth client to persist session tokens in `sessionStorage`.
- **Rejected alternatives:** `localStorage`. Rejected because `localStorage` persists indefinitely across browser restarts and all tabs, whereas `sessionStorage` is isolated to the tab and cleared upon window close, reducing the window of token exposure.

### 12. HTMX Polling with 15-Minute Cap and Self-Swapping Container
- **Decision:** Implemented live scan status updates using HTMX polling (`hx-trigger="every 3s"`, `hx-target="this"`, `hx-swap="outerHTML"`) capped at 15 minutes from scan creation. When 15 minutes elapse, polling ceases and renders a stale warning banner with a manual Refresh button.
- **Rejected alternatives:** WebSockets or Server-Sent Events (SSE). Rejected because WebSockets/SSE introduce persistent connection state, require custom connection management and reconnect logic, complicate load balancing, and demand a dedicated asynchronous notification channel.

### 13. Counts Derived from Findings Rather Than Trusting Stored Report Counts
- **Decision:** Derived summary count cards (Critical, High, Medium, Low) by counting parsed finding objects directly in presentation logic before applying the 50-item display cap.
- **Rejected alternatives:** Reading `report["counts"]` directly. Rejected because `scoring.py` serializes internal keys (`findings_critical`, `hosts_high`) that do not match UI tier keys, and relying on pre-computed counts can cause discrepancies with the findings table when filtering or formatting.

### 14. Attacker-Influenced Evidence Rendered as Escaped Text, Never Links
- **Decision:** Rendered finding evidence, why-it-matters strings, and change assets strictly as HTML-escaped text inside `<code>` and standard elements, never converting URLs or endpoints into active clickable links (`<a href>`).
- **Rejected alternatives:** Automatically hyperlinking evidence strings (e.g. rendering discovered URLs or endpoints as clickable links). Rejected because evidence strings are attacker-influenced (drawn from certificate transparency logs, web banners, and HTTP responses); rendering active links creates stored XSS vectors (e.g. `javascript:...` URIs or data URIs) and phishing risks.

---

## Known Limitations

- **Append-only scope:** The `audit_events` table is append-only against the application; the table owner can disable the trigger.
- **Retention & Purge:** No retention or purge policy is currently implemented; audit logs grow indefinitely until partitioned or archived.
- **Unrecorded Events:** Denied requests (e.g. HTTP 401/403 authorization failures), IP addresses, user agents, and user login events are not recorded in the audit log.
- **Scans List Pagination:** The scans list displays the latest 20 scans only; pagination for older scan history is not yet implemented.
- **15-Minute Polling Cap from `created_at`:** The polling cap calculates elapsed time from scan `created_at`. Scans that spend extended time queued before worker claim will stop auto-polling earlier in their active execution, requiring manual Refresh.
- **UTC Label Without Conversion:** Timestamps are printed with a literal "UTC" suffix but are not explicitly converted to UTC first; they are only correct while the database session time zone is UTC.
- **Untested 401 Retry Swap Path:** The preserved `hx-swap` on 401 token refresh has been verified in code and unit logic, but has not yet been exercised via an end-to-end browser test.

---

## Metrics

- tests collected 339 -> 375, db tests 91 -> 112.
- v3.4b: tests passed 412 -> 430 (2 deselected in both runs; owner-verified).
- v3.4b: 141 tests marked db (pytest -m db --collect-only).
- v3.3 audit logging added 15 tracked actions, migration 0009, and append-only trigger protection.
- v3.4a added dashboard shell, Supabase auth, domains list, and DNS TXT verification.
- v3.4b added scans list, scan detail with 5 stages, Fix first prioritization, and attack surface changes.
