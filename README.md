# ASM SaaS - Attack Surface Management CLI

A lightweight, modular, and defensible Attack Surface Management (ASM) reconnaissance tool designed for cybersecurity engineers and students.

---

## What It Does

`asm` operates in structured reconnaissance phases:

### Phase 1: Passive Subdomain Discovery (`asm discover`)
1. **Input Normalization & Validation**: Sanitizes target inputs (e.g. `http://EXAMPLE.COM:8080/path` -> `example.com`), verifies RFC compliance, and strictly rejects IP addresses and malformed domains.
2. **Certificate Transparency (CT) Discovery**: Queries `crt.sh` via its JSON API with resilient retry logic, backoff, and timeouts to enumerate public subdomains.
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

## Usage

### 1. Discover Subdomains (Passive)
```bash
asm discover example.com
```

Options:
- `-o`, `--output DIR`: Directory to save the discovery report (default: `output`).
- `-v`, `--verbose`: Enable debug logging.

Sample Discovery Output:
```text
[*] Discovering subdomains for 'example.com' via crt.sh...
[*] Found 6 unique subdomains. Resolving DNS records...

=== Discovery Summary ===
Domain:              example.com
Subdomains Found:    6
Resolved (Active):   4
Unresolved:          2
Scan Duration:       0.85s
Report File:         output\example.com_20260929T041500Z.json
```

---

### 2. Probe Live Hosts (Active)
```bash
asm probe output/example.com_20260929T041500Z.json --authorized
```

> [!IMPORTANT]
> **The `--authorized` Flag:**
> Active probing sends HTTP/HTTPS GET requests directly to the target servers. To prevent accidental or unauthorized scanning, `asm probe` requires the `--authorized` flag.
> If run without `--authorized`, the CLI will read the local report only to display the target domain, will make **zero network requests**, and will exit with code 1:
> ```text
> Active probing sends requests to example.com. Re-run with --authorized to confirm you own it or have written permission to test it.
> ```

Options:
- `--authorized`: Confirm ownership or written authorization (required).
- `-o`, `--output DIR`: Directory to save the probe report (default: `output`).
- `-v`, `--verbose`: Enable debug logging.

Sample Probe Output:
```text
[*] Probing 4 resolved hosts for 'example.com' (HTTPS/HTTP)...

=== Probe Summary ===
Domain:              example.com
Hosts Probed:        4
HTTPS Live:          3
HTTP Only:           1
Unreachable:         0
TLS Invalid:         0
Skipped Untrusted:   0
Skipped Private IP:  0
Skipped Unresolved:  2
Scan Duration:       1.42s
Report File:         output\example.com_probe_20260929T041600Z.json

=== Live Hosts ===
https://example.com/ [200] Example Domain
https://api.example.com/ [200] API Gateway
https://www.example.com/ [200] Example Domain
http://legacy.example.com/ [200] Legacy Portal
```

---

## Running Tests and Linting

To run the unit test suite (100% mocked, zero network calls):
```bash
pytest
```

To run the linter:
```bash
ruff check .
```

---

## Legal and Ethical Use

> [!CAUTION]
> **Authorization Requirement:** Only scan targets that you own or have explicit written permission to test.
>
> 1. **Passive Reconnaissance (`asm discover`)**: Interacts with third-party Certificate Transparency logs and recursive DNS. However, continuous or high-volume enumeration without authorization can violate terms of service or trigger defensive blocks.
> 2. **Active Probing (`asm probe`)**: Connects directly to target ports 80 and 443. Conducting unauthorized active scanning may violate:
>    - **United States**: Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030)
>    - **United Kingdom**: Computer Misuse Act 1990
>    - **India**: Information Technology Act, 2000 (Section 43 for unauthorized access and Section 66 for computer-related offenses)
>    - Applicable local cybercrime and unauthorized access legislation worldwide.
>
> Always respect rate limits, adhere strictly to authorized testing scopes, and never attempt to bypass defensive controls.
