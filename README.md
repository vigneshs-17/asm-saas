![CI](https://github.com/vigneshs-17/asm-saas/actions/workflows/ci.yml/badge.svg)

# ASM SaaS - Attack Surface Management CLI

A lightweight, modular, and defensible Attack Surface Management (ASM) reconnaissance tool designed for cybersecurity engineers and students.

---

## Project Status

- **v1 CLI**: Done. 5-stage scanner (`discover`, `probe`, `portscan`, `inspect`, `score`).
- **v2.0.0 Service**: Done. API + database, job queue with crash recovery, Cert Spotter fallback, change detection, scheduled scans, and email alerts. See [CHANGELOG.md](CHANGELOG.md).
- **Next: v3**: Accounts, organisations, and tenant isolation.

---

## What It Does

`asm` operates in structured reconnaissance phases:

### Phase 1: Passive Subdomain Discovery (`asm discover`)
1. **Input Normalization & Validation**: Sanitizes target inputs (e.g. `http://EXAMPLE.COM:8080/path` -> `example.com`), verifies RFC compliance, and strictly rejects IP addresses and malformed domains.
2. **Certificate Transparency (CT) Discovery & Fallback**:
   - Queries `crt.sh` via its JSON API with resilient retry logic, backoff, and timeouts.
   - If `crt.sh` fails after its retry budget (e.g. 502, 404, or timeout), discovery automatically falls back to the **SSLMate Cert Spotter API** (`https://api.certspotter.com/v1/issuances`).
   - Supports optional `CERTSPOTTER_API_KEY` for higher rate limits (works without key within daily quotas).
   - Enforces bounded pagination (max 10 pages, 5,000 entries) and rate limit handling (`Retry-After <= 10s`).
   - Reports record discovery `source` (`"crt.sh"` or `"certspotter"`), sanitized `fallback_reason`, and `truncated` status.
3. **Data Hygiene & Deduplication**: Cleans wildcards (`*.example.com`), separates multi-line entries, discards out-of-scope hostnames and email addresses, and removes duplicates.
4. **Concurrent DNS Resolution**: Uses `dnspython` across a worker thread pool (max 20 workers) to resolve `A` (IPv4) and `AAAA` (IPv6) records for each discovered host.
5. **Deterministic Precedence Mapping**: Categorizes host statuses (`RESOLVED`, `NXDOMAIN`, `TIMEOUT`, `ERROR`, `NO_ANSWER`).
6. **Structured Reporting**: Exports results to a JSON file named `<domain>_<timestamp_utc>.json`.

### Phase 2: Active Host Probing (`asm probe`)
1. **Mandatory Authorization Gate**: Requires explicit `--authorized` confirmation before dispatching any network packets.
2. **Untrusted Input Defense**: Re-validates every host from the input report against RFC standards and scope boundaries.
3. **SSRF Pre-Check**: Resolves hosts and blocks loopback, private, link-local, reserved, CGNAT (`100.64.0.0/10`), `0.0.0.0`, and IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`) before issuing HTTP requests.
4. **Dual-Stack Default Port Probing**: Tests `https://<host>/` first (port 443), then `http://<host>/` (port 80).
5. **Strict Redirect Scope Enforcement**: Follows up to 5 in-scope redirects manually. Rejects external domains, non-default ports (e.g. 8080), or non-HTTP protocols.
6. **Defensive Streaming Body Cap**: Reads at most 64 KB of the response body to extract HTML `<title>` tags without downloading large files.
7. **End-to-End Deadline**: Enforces a strict 10.0-second total deadline per URL.
8. **TLS Certificate Fallback**: Flags invalid certificates (`tls_valid = False`), then retries once with `verify=False` solely to test service availability.

### Phase 3: Lightweight TCP Port Scanning (`asm portscan`)
1. **Mandatory Authorization Gate**: Requires `--authorized` confirmation before opening any socket connections.
2. **Fixed Default Port List Only**: Scans exactly 16 high-value common ports (no arbitrary ranges or intrusive full scans):
   - Ports: `21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443`
3. **Asynchronous TCP Connect Scan**: Built with standard library `asyncio` (`open_connection`). No raw sockets, no SYN packets, and no kernel-level driver requirements.
4. **Strict State Classification**:
   - `OPEN`: Connection established.
   - `CLOSED`: Connection refused (`RST` received; host is up, port closed).
   - `FILTERED`: Connection timed out or dropped (firewall block).
5. **Non-Intrusive Banner Grabbing**:
   - For SSH (`port 22`): Listens passively (SSH servers speak first).
   - For `21, 25, 110, 143`: Sends a single `\r\n` CRLF prompt to trigger service greeting.
   - For all other ports: Listens passively for up to 2 seconds without sending payloads.
   - Sanitizes and truncates banners to at most 256 printable characters.
6. **Exposure Risk Flags**:
   - Database exposure (`3306`, `5432`, `6379`)
   - Remote access (`3389` RDP, `23` Telnet)
   - Windows file sharing (`445` SMB)
   - Legacy plaintext protocols (`21`, `23`, `25`, `110`, `143`)
7. **Politeness & Rate Limiting**: Capped at max 10 concurrent ports per host and max 5 hosts in parallel, with polite pacing delays between connections.

---

## Architecture

`asm` operates as a staged pipeline (`discover` -> `probe` -> `portscan` -> `inspect` -> `score`), where each stage reads the previous stage's JSON report, and active stages require `--authorized`.

---

## Installation & Setup

### 1. Prerequisites
- Python 3.11 or higher
- PowerShell, Bash, or Command Prompt

### 2. Create and Activate a Virtual Environment
```bash
# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Package with Development Tools
```bash
pip install -e ".[dev]"
```

---

## Run with Docker

Alternatively, run `asm` inside a containerized environment without installing Python or local dependencies.

### 1. Build the Docker Image
```bash
docker build -t asm-saas .
```

### 2. Run Commands Mounting the Local Output Directory
To persist generated reports to your host's `output/` directory, bind mount it to `/app/output`:

**Windows (PowerShell):**
```powershell
docker run --rm -v "${PWD}/output:/app/output" asm-saas discover example.com
```

**Linux / macOS:**
```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/output:/app/output" asm-saas discover example.com
```
> [!NOTE]
> On Linux and macOS, `--user "$(id -u):$(id -g)"` is required because the container runs as a non-root user (UID 10001) while mounted host directories retain host ownership, ensuring reports written to the host have correct write permissions.

> [!IMPORTANT]
> Active reconnaissance commands (`probe`, `portscan`, `inspect`) still require the mandatory `--authorized` flag inside the container:
> ```bash
> docker run --rm -v "${PWD}/output:/app/output" asm-saas probe output/<report>.json --authorized
> ```

---

## Run the API (v2, local only)

In v2, ASM SaaS expands into a modular reconnaissance service featuring a FastAPI REST API backed by PostgreSQL and SQLAlchemy 2.0.

### 1. Environment Configuration
Create a local `.env` configuration file from the template:
```bash
cp .env.example .env
```
Ensure `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, and `DATABASE_URL` are defined in `.env`.
Optionally set `CERTSPOTTER_API_KEY` for Cert Spotter fallback (free tier works without a key within daily limits).

### 2. Start the Stack with Docker Compose
```bash
docker compose up --build
```
On startup:
1. `db`: Initializes the pinned `postgres:18.6-alpine` database service and waits until healthy.
2. `migrate`: Executes `alembic upgrade head` in a one-shot container to establish all tables (`domains`, `scan_runs`, `scan_results`).
3. `api`: Starts `uvicorn` serving the FastAPI application once migrations succeed.

> [!WARNING]
> **No Authentication / Localhost Only:**
> The API currently has no authentication layer. In `docker-compose.yml`, port 8000 is bound **strictly to loopback `127.0.0.1:8000`** (not `0.0.0.0`) to prevent unauthorized network access.

### 3. Verify Health
```bash
curl -i http://127.0.0.1:8000/health
```
Response:
```json
{"status":"ok","database":"connected"}
```

### 4. Register Monitored Domains
Register a target domain (requires `"authorized": true` in the request body):
```bash
curl -i -X POST http://127.0.0.1:8000/domains \
  -H "Content-Type: application/json" \
  -d '{
    "name": "example.com",
    "authorized": true,
    "authorization_note": "Target owner written authorization"
  }'
```
Response:
```json
{
  "id": 1,
  "name": "example.com",
  "authorized": true,
  "authorization_note": "Target owner written authorization",
  "created_at": "2026-09-29T18:00:00Z"
}
```

List registered domains:
```bash
curl -i http://127.0.0.1:8000/domains
```

### 5. Asynchronous Scan Jobs & Worker (v2.2)

In v2.2, long-running scans run asynchronously via background workers claiming jobs from PostgreSQL using `FOR UPDATE SKIP LOCKED`.

#### Start the Worker Service
```bash
docker compose up -d worker
```
Or run the worker process locally:
```bash
python -m asm.worker
```

#### Queue a Scan
Queue a multi-stage scan for an authorized domain (returns `202 Accepted` immediately):
```bash
curl -i -X POST http://127.0.0.1:8000/domains/1/scans \
  -H "Idempotency-Key: optional-uuid-token"
```

#### Check Scan Status and Stage Progress
Retrieve real-time execution status and duration for all 5 pipeline stages:
```bash
curl -i http://127.0.0.1:8000/scans/1
```

#### Fetch Stage Artifact Reports
Retrieve the raw JSON report produced by any completed stage (`discover`, `probe`, `portscan`, `inspect`, `score`):
```bash
curl -i http://127.0.0.1:8000/scans/1/results/score
```

#### List Domain Historical Scans
```bash
curl -i "http://127.0.0.1:8000/domains/1/scans?status=succeeded&limit=10"
```

#### List Attack Surface Changes for a Domain
Query historical attack surface changes detected for a domain, ordered newest-first:
```bash
# All changes (default limit: 50, offset: 0)
curl -i http://127.0.0.1:8000/domains/1/changes

# Filtered by severity, category, change_type, or timestamp
curl -i "http://127.0.0.1:8000/domains/1/changes?severity=CRITICAL"
curl -i "http://127.0.0.1:8000/domains/1/changes?category=exposure&since=2026-10-01T00:00:00Z"
curl -i "http://127.0.0.1:8000/domains/1/changes?change_type=PORT_NEWLY_OPEN&limit=10"
```

#### List Attack Surface Changes for a Specific Scan Run
Retrieve only the changes detected in a single scan run (404 if scan not found):
```bash
curl -i http://127.0.0.1:8000/scans/2/changes
```

#### Configure Recurring Scan Schedule for a Domain
Enable, update, or disable automated recurring scanning for an authorized domain (allowed range: 6 to 720 hours):
```bash
# Enable 24-hour recurring scans (enabling from null sets next_scan_at to now, eligible immediately)
curl -i -X PUT http://127.0.0.1:8000/domains/1/schedule \
  -H "Content-Type: application/json" \
  -d '{"interval_hours": 24}'

# Update existing interval to 48 hours (sets next_scan_at = now + 48h, does not trigger immediate scan)
curl -i -X PUT http://127.0.0.1:8000/domains/1/schedule \
  -H "Content-Type: application/json" \
  -d '{"interval_hours": 48}'

# Disable recurring scans (reverts domain to manual scans only)
curl -i -X PUT http://127.0.0.1:8000/domains/1/schedule \
  -H "Content-Type: application/json" \
  -d '{"interval_hours": null}'
```

#### Configure Domain Email Alerts
Configure automated plain-text email alerts for detected attack surface exposures (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`):
```bash
# Enable email alerts (1 to 5 recipient emails, default threshold: MEDIUM)
curl -i -X PUT http://127.0.0.1:8000/domains/1/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "alerts_enabled": true,
    "alert_emails": ["security@example.com", "ops@example.com"],
    "alert_min_severity": "HIGH"
  }'

# Disable email alerts
curl -i -X PUT http://127.0.0.1:8000/domains/1/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "alerts_enabled": false,
    "alert_emails": []
  }'
```

#### List Alert Notifications for a Domain
Query the history and delivery status of outbox alert notifications:
```bash
# List all notifications (newest first, includes plain-text email body)
curl -i http://127.0.0.1:8000/domains/1/alert-notifications

# Filter by delivery status (pending / sent / failed)
curl -i "http://127.0.0.1:8000/domains/1/alert-notifications?status=pending&limit=10"
```


### 6. Local Database Testing Setup & Migrations

#### How the Test Suite Creates the Database Schema
The pytest integration test suite (`pytest -m db`) creates its database schema programmatically via SQLAlchemy:
- When running tests, the session-scoped fixture `db_engine` in `tests/conftest.py` connects to `TEST_DATABASE_URL` (after validating that the database name ends with `_test` for safety).
- It executes `Base.metadata.create_all(bind=engine)`, ensuring all tables, columns, indexes, and constraints defined across `src/asm/db/models.py` exist before tests execute.
- Per-test isolation is maintained via savepoint transactions (`join_transaction_mode="create_savepoint"`), rolling back all changes after each test.

#### Migration Testing in CI (`db-test` Job)
To verify that Alembic migration scripts remain in 100% synchronization with SQLAlchemy ORM models, the CI `db-test` workflow executes a strict 4-step verification sequence against PostgreSQL:
```bash
# 1. Apply all migrations up to head
alembic upgrade head

# 2. Check for schema drift between models.py and migrations (fails if diff exists)
alembic check

# 3. Verify reversible downgrade functionality
alembic downgrade -1

# 4. Re-apply to head for test execution
alembic upgrade head
```

#### Running Database Tests Locally
To run the database integration test suite locally against a dedicated throwaway PostgreSQL 18 container:

1. Start a throwaway PostgreSQL container named `asm-test-db` on port `5433`:
   ```bash
   docker run -d --name asm-test-db -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=asm_test -p 127.0.0.1:5433:5432 postgres:18.6-alpine
   ```

2. Run the Alembic migration verification cycle:
   ```bash
   # Windows (PowerShell)
   $env:DATABASE_URL = "postgresql+psycopg://postgres:postgres@127.0.0.1:5433/asm_test"
   alembic upgrade head
   alembic check
   alembic downgrade -1
   alembic upgrade head

   # Linux / macOS
   export DATABASE_URL="postgresql+psycopg://postgres:postgres@127.0.0.1:5433/asm_test"
   alembic upgrade head
   alembic check
   alembic downgrade -1
   alembic upgrade head
   ```

3. Set `TEST_DATABASE_URL` (safety check: the database name must end with `_test`) and run tests:
   ```bash
   # Windows (PowerShell)
   $env:TEST_DATABASE_URL = "postgresql+psycopg://postgres:postgres@127.0.0.1:5433/asm_test"
   pytest -m db

   # Linux / macOS
   TEST_DATABASE_URL="postgresql+psycopg://postgres:postgres@127.0.0.1:5433/asm_test" pytest -m db
   ```




## Usage

### 1. Discover Subdomains (Passive)
```bash
asm discover example.com
```

Options:
- `-o`, `--output DIR`: Directory to save the discovery report (default: `output`).
- `-v`, `--verbose`: Enable debug logging.

---

### 2. Probe Live Hosts (Active)
```bash
asm probe output/example.com_20260929T041500Z.json --authorized
```

---

### 3. Scan Common TCP Ports (Active)
```bash
asm portscan output/example.com_20260929T041500Z.json --authorized
```

Options:
- `--authorized`: Confirm authorization to perform active network connections (required).
- `-o`, `--output DIR`: Directory to save the port scan report (default: `output`).
- `-v`, `--verbose`: Enable verbose debug logging.

Sample Port Scan Output:
```text
[*] Scanning common ports on 2 resolved hosts for 'example.com'...

=== Port Scan Summary ===
Domain:              example.com
Hosts Scanned:       2
Hosts Skipped:       0
Total Open Ports:    8
Skipped Untrusted:   0
Skipped Private IP:  0
Skipped Unresolved:  4
Scan Duration:       6.16s
Report File:         output\example.com_portscan_20260929T045524Z.json

=== Open Ports & Risk Flags ===
[+] example.com
    - 80/http (guess by port)
    - 443/https (guess by port)
    - 8080/http-alt (guess by port)
    - 8443/https-alt (guess by port)
[+] www.example.com
    - 80/http (guess by port)
    - 443/https (guess by port)
    - 8080/http-alt (guess by port)
    - 8443/https-alt (guess by port)
```

### 4. Inspect TLS Certificates and Security Headers (Active)
```bash
asm inspect output/example.com_probe_20260929T041500Z.json --authorized
```

Options:
- `--authorized`: Confirm authorization to perform active inspection against target domain (required).
- `-o`, `--output DIR`: Directory to save the inspection report (default: `output`).
- `-v`, `--verbose`: Enable verbose debug logging.

Security & Inspection Flags Explained:
- **`expired`**: Certificate validity period ended (`now > not_after`). Browsers will display an invalid certificate warning and block connections.
- **`not_yet_valid`**: Certificate start date is in the future (`now < not_before`).
- **`issuer_equals_subject`**: Certificate subject matches issuer. Indicates a likely self-signed certificate, not definitive proof of untrust.
- **`hostname_mismatch`**: Hostname does not match the Subject Alternative Names (SANs) or Common Name (CN) per RFC 6125.
- **`expiring_soon`**: Certificate expires within 30 days. Needs rotation to prevent service disruption.
- **`deprecated_tls`**: Server negotiated insecure, deprecated TLS protocol versions (`TLSv1.0` or `TLSv1.1`).
- **`hsts_weak`**: `Strict-Transport-Security` is present but `max-age` is under 180 days (15,552,000s), leaving clients vulnerable to downgrade attacks.
- **`server_disclosed` / `x_powered_by_disclosed`**: Response headers leak web server or framework versions (e.g. `Server: cloudflare`, `X-Powered-By: PHP/7.4.3`), assisting attackers in reconnaissance.

Sample Inspection Output:
```text
[*] Inspecting TLS and security headers for live HTTPS hosts of 'example.com'...

=== Inspection Summary ===
Domain:              example.com
Hosts Inspected:     2
Valid Certificates:  2
Expired Certs:       0
Expiring Soon (<=30d): 1
Missing HSTS:        2
Skipped Not HTTPS:   0
Skipped Untrusted:   0
Skipped Private IP:  0
Report File:         output\example.com_inspect_20260929T060910Z.json

=== Host Findings ===
[+] example.com
    - Cert: VALID (expires in 27 days, TLSv1.3) [from_socket]
    - Missing Headers: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
    ! Disclosed: Server: cloudflare
[+] www.example.com
    - Cert: VALID (expires in 27 days, TLSv1.3) [from_socket]
    - Missing Headers: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
    ! Disclosed: Server: cloudflare
```

### 5. Risk Scoring & Combined Report (Passive / Local Aggregation)
```bash
asm score --discover output/example.com_20260929T042333Z.json \
          --probe output/example.com_probe_20260929T043830Z.json \
          --portscan output/example.com_portscan_20260929T045524Z.json \
          --inspect output/example.com_inspect_20260929T060910Z.json
```

Options:
- `--discover FILE`: Path to Step 1 discovery report JSON file (**required**).
- `--probe FILE`: Path to Step 2 probe report JSON file (optional).
- `--portscan FILE`: Path to Step 3 portscan report JSON file (optional).
- `--inspect FILE`: Path to Step 4 inspect report JSON file (optional).
- `-o`, `--output DIR`: Directory to save the final score report (default: `output`).
- `-v`, `--verbose`: Enable verbose debug logging.

Sample Score Output:
```text
Domain Severity Band: HIGH
Total Domain Risk Score: 46 pts
Hosts: 4 total (0 Critical, 2 High, 2 Medium, 0 Low, 0 Info)
  [HIGH] expired.badssl.com  - Expired TLS Certificate (7 pts)
  [HIGH] wrong.host.badssl.com - Untrusted Certificate Authority (7 pts)
  [MEDIUM] self-signed.badssl.com - Self-Signed Certificate (4 pts)
  [MEDIUM] badssl.com - Certificate Expiring Soon (4 pts)
```

> [!NOTE]
> **Heuristic Triage Model (Not CVSS):**
> This scoring model is a heuristic severity model designed for defensive prioritization and attack surface triage. It is **NOT CVSS** and **NOT a guarantee of exploitability**. Scoring evaluates observable internet-facing posture flaws (e.g., exposed databases, expired TLS certificates, missing security headers) to guide remediation, but does not model internal compensating controls, defense-in-depth, or active exploitation.

#### Severity Tiers & Point Values:
- **CRITICAL** (10 pts): Confirmed reachable database services responding with active banners on the public internet.
- **HIGH** (7 pts): Exposed sensitive administrative services (RDP, SMB, Telnet), exposed DB ports without banner, expired/invalid certificates, or untrusted public CAs.
- **MEDIUM** (4 pts): Cleartext protocols (FTP, SMTP, POP3, IMAP), self-signed certificates, certificate hostname mismatches, certificates expiring soon ($\le 30$d), deprecated TLS 1.0/1.1 protocols, or HTTP-only services.
- **LOW** (1 pt): Missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options), weak HSTS max-age duration, or technology disclosure headers.
- **INFO** (0 pts): Domain attack surface context observations ($\ge 10$ live assets).

#### Host and Domain Band Computation:
1. **Host Severity Band**:
   Derived directly from the host's **worst finding tier**:
   - Any `CRITICAL` finding $\rightarrow$ Host band **CRITICAL**
   - Else any `HIGH` finding $\rightarrow$ Host band **HIGH**
   - Else any `MEDIUM` finding $\rightarrow$ Host band **MEDIUM**
   - Else any `LOW` finding $\rightarrow$ Host band **LOW**
   - Else $\rightarrow$ Host band **INFO** (clean host)
   The numerical point sum serves as a secondary sort key within each band.
2. **Domain Severity Band**:
   Derived from the aggregate host bands:
   - Any `CRITICAL` host $\rightarrow$ Domain band **CRITICAL**
   - Else any `HIGH` host $\rightarrow$ Domain band **HIGH** (flagged as an escalation note if $\ge 3$ high hosts exist)
   - Else any `MEDIUM` host $\rightarrow$ Domain band **MEDIUM**
   - Else any `LOW` host $\rightarrow$ Domain band **LOW**
   
---

## Change Detection Engine (v2.3)

`asm` features an automated attack surface differential engine that compares consecutive successful scans of the same domain to detect newly exposed services, resolved issues, and configuration drift.

### Core Principles & Architecture
1. **Pure Function Engine (`detect_changes`)**:
   Core diffing logic resides in `src/asm/changes.py` as a pure function `detect_changes(baseline_reports, new_reports) -> list[dict]`. It requires no network or database connections and is tested with static JSON fixtures.
2. **Strictly Earlier Baseline Selection**:
   The baseline is selected as the most recent earlier scan for the same domain with `status = 'succeeded'` using `id < :current_id ORDER BY id DESC LIMIT 1`. Failed scans are never used as baselines, and the initial scan of a domain produces zero changes.
3. **Finding-Based Diffing (Single Source of Truth for Severity)**:
   Rather than comparing raw report fields, portscan and inspect changes are derived by diffing findings produced by `src/asm/scoring.py` finding evaluators.
   - **Exposure Additions**: Take the exact severity tier (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) of the finding they introduce.
   - **Exposure Reductions**: Are assigned `INFO` severity. A baseline finding is considered resolved only if the host was successfully evaluated in the new scan (`status == "PROBED"`).
4. **"Unknown" is Not "Absent"**:
   Reconnaissance failures or non-definitive states never generate removal changes:
   - A DNS `TIMEOUT` or `ERROR` does not emit `STOPPED_RESOLVING` (only a definite `RESOLVED` $\rightarrow$ `NXDOMAIN` transition does).
   - An unreachable host or `FILTERED` port does not emit `PORT_NO_LONGER_OPEN` (only `OPEN` $\rightarrow$ `CLOSED` does).
   - A probe timeout does not emit `HTTPS_LOST` (only non-timeout connection/TLS errors do).
5. **Source Awareness & Truncation Safety**:
   Subdomain removals (`REMOVED_SUBDOMAIN`) are evaluated **only** when both baseline and new scans used the same Certificate Transparency source (e.g. `crt.sh` vs `certspotter`) and neither report was truncated (`truncated: false`). If sources differ or either was truncated, removal detection is safely skipped with a descriptive `skip_reason`.
6. **Atomic & Resilient Finalization**:
   Change detection runs in memory prior to the final worker transaction. If detection encounters an unexpected error, the scan run still marks `succeeded`, recording the error in `scan_runs.change_detection`. Changes and the final status update are inserted atomically in the same database transaction with a unique constraint preventing duplicate change entries: `(scan_run_id, change_type, asset, detail)`.

---

## Scheduled Scans Engine (v2.4a)

`asm` supports opt-in recurring scans per domain, allowing continuous automated monitoring without requiring external task schedulers (such as Celery Beat or cron daemons).

### Key Architectural Invariants
1. **Database-Backed Worker Scheduling**:
   The worker polling loop executes `schedule_due_scans()` at the start of each cycle before claiming queued jobs. It selects due domains (`authorized = true AND scan_interval_hours IS NOT NULL AND next_scan_at <= now()`) using `FOR UPDATE SKIP LOCKED`. This allows multiple workers to run concurrently without coordination or duplicated scan jobs.
2. **One Short Transaction Per Domain**:
   Each due domain is locked, evaluated, and updated within its own dedicated short transaction, minimizing lock contention and preventing failures in one domain from affecting others.
3. **Shared Enqueue Function**:
   Both `POST /domains/{id}/scans` and the worker scheduler call the shared `enqueue_scan()` function to insert the `scan_run` and its 5 `pending` stage tracking rows.
4. **Active Scan Duplicate Suppression**:
   If an active scan (`status IN ('queued', 'running')`) already exists for a domain, the database constraint `uq_scan_runs_active_domain` blocks insertion. The scheduler safely absorbs this constraint violation and advances `next_scan_at` without creating a duplicate job.
5. **No Backfill Guarantee**:
   Following server or worker downtime, `next_scan_at` is always calculated from the current database clock (`now() + interval + jitter`), never from missed historical timestamps. A domain receives exactly **one** catch-up scan rather than multiple stacked scans.
6. **Desynchronization Jitter**:
   A small random jitter (0 to 300 seconds) is added to `next_scan_at` to disperse execution times across the hour and prevent thundering herds on shared network and database infrastructure.
7. **Explicit Trigger Provenance**:
   Every `scan_run` records its origin in the `trigger` column: `"manual"` for user-initiated scans via the API, and `"scheduled"` for automated recurring scans.

---

## Email Alerts & Outbox Engine (v2.4b)

`asm` features an automated email alerting pipeline that dispatches security digests when a scan uncovers new attack surface exposures matching or exceeding a domain's severity threshold.

### Key Architectural Invariants
1. **Transactional Outbox Pattern**:
   Alert notifications are never sent directly within scan execution. Instead, pending notification rows (`alert_notifications` table) are inserted within the **exact same fenced transaction** that records the detected changes and marks the `scan_run` as `succeeded`. This eliminates the dual-write problem: either both the changes and the notification records persist, or neither does.
2. **In-Memory Fault Isolation**:
   Alert digest formatting and recipient resolution run in memory before the final transaction. If formatting raises an unexpected error, the error is sanitized and recorded under `scan_runs.change_detection["alert_error"]`, no alert rows are inserted, and the scan still completes successfully. Alert formatting failures never cause scan failures.
3. **Dedicated Outbox Delivery Polling**:
   At the end of each poll cycle, the worker calls `deliver_pending_alerts()`, claiming due notifications (`status = 'pending' AND next_attempt_at <= now()`) in batches using `SELECT ... FOR UPDATE SKIP LOCKED`.
4. **Row Lock During SMTP Send**:
   The delivery transaction **holds the row lock during the SMTP transmission** (bounded by a strict 10-second socket timeout). This strictly prevents concurrent workers from double-sending the same notification without needing distributed locks or multi-phase commits. Upon success, `status = 'sent'` and `sent_at = now()` are committed, releasing the lock.
5. **Database-Calculated Exponential Backoff**:
   If delivery fails (e.g. SMTP server unreachable or handshake error), the worker records `last_error` and calculates the next retry using native PostgreSQL intervals:
   `next_attempt_at = now() + make_interval(secs => :s)`.
   Retries follow exponential delays (30s, 60s, 120s, 240s) up to 5 attempts before marking `status = 'failed'`.
6. **Injection-Safe Plain-Text Digest**:
   Alert emails are sent as clean, readable plain-text (no HTML) with strict CR/LF sanitization on all headers and subject lines to prevent email header injection attacks. Untrusted report strings are sanitized and truncated.
7. **Local Testing with Mailpit**:
   Delivery is disabled by default when `SMTP_HOST` is empty (`alert_notifications` stay pending). For local development and testing, run Mailpit via the Docker Compose `dev` profile:
   ```bash
   # Start Mailpit (SMTP on 1025, Web UI on http://127.0.0.1:8025)
   docker compose --profile dev up -d mailpit

   # Configure worker environment in .env
   SMTP_HOST=localhost
   SMTP_PORT=1025
   SMTP_FROM=asm-alerts@example.com
   ```
   Open `http://127.0.0.1:8025` in your browser to inspect delivered alert digests in real-time.

---

## Running Tests and Linting


To run the unit test suite (100% mocked, zero network calls, integration tests deselected):
```bash
pytest
```

To run real network integration tests explicitly (scans `scanme.nmap.org` and `expired.badssl.com`):
```bash
pytest -m integration
```

To run the linter:
```bash
ruff check .
```

---

## Legal and Ethical Use

> [!CAUTION]
> **Authorization & Policy Requirements:** Only scan targets that you own or have explicit written permission to test.
>
> 1. **Active Port Scanning Policy Violations**: Port scanning generates detectable TCP connection sequences. Even against authorized targets or bug bounty scopes, port scanning may violate:
>    - **Network Service Provider (ISP) Acceptable Use Policies (AUP)**: Many residential and commercial ISPs prohibit unsolicited port scanning.
>    - **University, Campus, and Enterprise Network Policies**: Performing port scans from campus or corporate networks without clearance can result in immediate MAC/port disconnection or disciplinary action.
> 2. **Statutory Legal Frameworks**:
>    - **United States**: Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030)
>    - **United Kingdom**: Computer Misuse Act 1990
>    - **India**: Information Technology Act, 2000 (Section 43: unauthorized access and data downloading; Section 66: computer-related offenses / hacking)
>
> Always respect rate limits, adhere strictly to authorized testing scopes, and never attempt to bypass defensive controls.
