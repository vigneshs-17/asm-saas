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
Expiring Soon (<=30d): 0
Missing HSTS:        2
Skipped Not HTTPS:   0
Skipped Untrusted:   0
Skipped Private IP:  0
Report File:         output\example.com_inspect_20260929T060910Z.json

=== Host Findings ===
[+] example.com
    - Cert: VALID (expires in 87 days, TLSv1.3) [from_socket]
    - Missing Headers: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
    ! Disclosed: Server: cloudflare
[+] www.example.com
    - Cert: VALID (expires in 87 days, TLSv1.3) [from_socket]
    - Missing Headers: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
    ! Disclosed: Server: cloudflare
```

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
