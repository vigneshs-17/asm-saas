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

---

## Metrics

- tests collected 339 -> 375, db tests 91 -> 112.
