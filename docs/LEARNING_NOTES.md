# ASM SaaS - Learning Notes

These notes explain the architecture, design choices, and cybersecurity principles behind the implementation of **ASM SaaS**.

---

# Part 1: v1 Step 1 — Project Setup + Passive Subdomain Discovery

## 1. Plain-English Code Walkthrough

### `pyproject.toml`
- **What it is:** The modern, declarative packaging configuration file for Python (PEP 517 / PEP 621).
- **Why it exists:** Replaces legacy `setup.py` scripts. It defines package metadata, build requirements (`setuptools`), core runtime dependencies (`httpx`, `dnspython`), development tools (`pytest`, `ruff`), and the CLI console script `asm` mapping directly to `asm.cli:main`.
- **Key aspects:** Allows installing the package in editable mode (`pip install -e ".[dev]"`), making the `asm` command immediately available in the active environment.

### `.gitignore`
- **What it is:** Git configuration that specifies intentionally untracked files.
- **Why it exists:** Prevents polluting the repository with virtual environments (`.venv/`), bytecode caches (`__pycache__/`, `.pytest_cache/`, `.ruff_cache/`), sensitive files (`.env`), and scan output artifacts (`output/`).

### `src/asm/validators.py`
- **What it is:** Domain normalization and RFC compliance validation engine.
- **Why it exists:** User input is untrusted and messy. A user might supply `http://EXAMPLE.COM:8080/path/to/page` when scanning a domain. Feeding raw paths or ports into DNS resolvers or Certificate Transparency APIs breaks queries or introduces command injection vulnerabilities.
- **Key Functions:**
  - `normalize_domain(raw_input: str) -> str`: Uses `urllib.parse.urlsplit` to safely strip schemes (`http://`, `https://`), userinfo, ports (`:8080`), URL paths (`/path`), query arguments, fragments, and trailing DNS root dots (`.`), while converting everything to lowercase. Detects IP addresses early so they are preserved for explicit rejection.
  - `validate_domain(raw_input: str) -> str`: Enforces DNS rules from RFC 1035/1123. Rejects IP addresses (via Python's `ipaddress` module), checks that total length is $\le 253$ characters, ensures labels are $1-63$ characters without hyphen prefixes/suffixes, verifies valid characters (`[a-z0-9-]`), and blocks numeric-only TLDs. Raises custom `DomainValidationError`.

### `src/asm/models.py` (Discovery Components)
- **What it is:** Strongly-typed data structures representing domain discovery states and scan artifacts.
- **Why it exists:** Using typed dataclasses instead of arbitrary dictionary keys prevents typos, enforces data schemas, and provides structured serialization.
- **Key Structures:**
  - `DNSStatus` (`StrEnum`): Canonical set of DNS resolution states: `RESOLVED`, `NXDOMAIN`, `NO_ANSWER`, `TIMEOUT`, `ERROR`.
  - `SubdomainResult` (`dataclass`): Represents a single host, its resolved IPv4/IPv6 addresses, resolution status, and a boolean `resolved` flag.
  - `DiscoveryReport` (`dataclass`): Represents the full output artifact, tracking the root domain, ISO 8601 UTC timestamps for audit trails, discovery source, statistical counts, and list of `SubdomainResult` entries.

### `src/asm/discovery.py`
- **What it is:** HTTP client for Certificate Transparency (CT) log querying via `crt.sh`.
- **Why it exists:** Queries the `crt.sh` public database to identify all TLS/SSL certificates ever issued for a domain and its subdomains.
- **Key Functions:**
  - `fetch_crtsh_data(domain: str, client: httpx.Client | None = None) -> list[dict]`: Queries `https://crt.sh` with parameters `q=%.<domain>&output=json` passed securely via `httpx` query params (preventing URL manipulation). Includes a student project User-Agent header, a 30s timeout, and exponential backoff retry logic (up to 3 attempts with 1s and 2s waits) for timeouts, connection drops, HTTP 429, HTTP 5xx, or malformed JSON responses. Non-retryable 4xx errors fail immediately. Raises `CrtshError` upon exhaustion.
  - `parse_subdomains(crtsh_entries: list[dict], target_domain: str) -> list[str]`: Inspects `name_value` fields from certificates. Handles multi-line strings, strips wildcard prefixes (`*.`), rejects email addresses and invalid hostnames, verifies the subdomain strictly belongs to `target_domain`, deduplicates, and sorts the list alphabetically.

### `src/asm/resolver.py`
- **What it is:** Multi-threaded DNS resolution engine utilizing `dnspython`.
- **Why it exists:** Having a list of subdomains from CT logs only tells you a certificate once existed; it does not indicate whether the host currently exists or is active. Resolving DNS records verifies live infrastructure.
- **Key Functions:**
  - `_query_record_type(resolver, hostname, record_type) -> tuple[list[str], DNSStatus]`: Performs an `A` (IPv4) or `AAAA` (IPv6) query with a 5.0s timeout. Catches `dns.resolver.NXDOMAIN`, `dns.resolver.NoAnswer`, `dns.resolver.NoNameservers` (mapped to `ERROR`), and `dns.exception.Timeout`.
  - `resolve_subdomain(hostname: str, ...) -> SubdomainResult`: Queries both `A` and `AAAA` records and combines them according to explicit precedence:
    1. Any IP found $\to$ `RESOLVED`
    2. Else if either returned `NXDOMAIN` $\to$ `NXDOMAIN`
    3. Else if either timed out $\to$ `TIMEOUT`
    4. Else if either had an unexpected error $\to$ `ERROR`
    5. Else $\to$ `NO_ANSWER`
  - `resolve_subdomains_concurrently(subdomains, max_workers=20) -> list[SubdomainResult]`: Distributes domain resolution over a thread pool of up to 20 workers, speeding up lookups by a factor of 10–20x without overloading local network sockets.

---

## 2. Five Step 1 Interview Questions & Answers

### Question 1: What is Certificate Transparency (CT), and why is it so valuable for Attack Surface Management?
**Answer:**
Certificate Transparency (RFC 6962) is an open framework designed to monitor and audit TLS/SSL certificates issued by Certificate Authorities (CAs). Whenever a CA issues a certificate for a domain, it submits the certificate to append-only, cryptographically verifiable public logs.

For Attack Surface Management (ASM) and passive reconnaissance, CT logs are an invaluable intelligence source because:
1. **Comprehensive Historical Record:** Any public or internal subdomain that ever obtained a public SSL/TLS certificate (e.g., `dev.example.com`, `vpn-test.internal.example.com`, `staging-api.example.com`) is permanently logged.
2. **Completely Passive:** Querying CT logs queries third-party log databases rather than the target organization's infrastructure. The target cannot observe or detect this reconnaissance activity.
3. **Discovery of "Shadow IT":** Developers and business units frequently spin up temporary subdomains and obtain free certificates. Even if unlinked on the main corporate website, CT logs reveal them immediately.

---

### Question 2: What is the fundamental difference between passive and active reconnaissance, and where does DNS resolution sit?
**Answer:**
- **Passive Reconnaissance:** Gathering intelligence about a target from publicly available third-party sources (e.g., Certificate Transparency logs, WHOIS databases, search engines, Shodan caches) without ever sending network packets to the target's servers.
- **Active Reconnaissance:** Directly sending packets to the target's infrastructure (e.g., port scanning with SYN packets, sending HTTP requests, vulnerability probing). Active scanning creates log entries on the target's firewalls, IDS/IPS, and web servers, and carries legal and operational risks if done without authorization.

**Where does DNS resolution sit?**
Standard recursive DNS resolution is generally considered **semi-passive or near-passive**. When querying a public DNS resolver (like `1.1.1.1` or `8.8.8.8`), your machine speaks to the caching resolver. If the record is cached, the target's authoritative nameservers are never contacted. If the record is not cached, the recursive resolver queries the target's authoritative nameserver on your behalf. However, because you are not connecting to the host's web ports or services, it does not constitute active host probing.

---

### Question 3: In DNS analysis, what is the practical security difference between `NXDOMAIN` and `NO_ANSWER`?
**Answer:**
- **`NXDOMAIN` (Non-Existent Domain):** The authoritative nameserver explicitly confirmed that the domain name itself does not exist in the DNS zone.
  - *Security Implication (Subdomain Takeover):* If a CT log reveals a subdomain that once pointed to a cloud provider (e.g. an AWS S3 bucket, Azure Traffic Manager, or GitHub Pages via a CNAME record) and that domain now yields `NXDOMAIN`, an attacker might register the unclaimed cloud resource or name to hijack the subdomain.
- **`NO_ANSWER` (NODATA):** The domain name exists in the DNS zone, but there are no records matching the requested type (e.g., no `A` or `AAAA` record exists, but an `MX`, `TXT`, or `CNAME` record might).
  - *Security Implication:* The host is registered and actively managed in the zone file, but might be reserved for email routing or identity verification rather than hosting an IPv4/IPv6 web service.

---

### Question 4: Why use a `ThreadPoolExecutor` for DNS resolution instead of standard sequential loops or asynchronous event loops like `asyncio`?
**Answer:**
1. **Network I/O Latency:** Sequential DNS lookups over hundreds of subdomains would incur cumulative network latency. Using concurrent threads drops total scan duration to approximately 1–2 seconds.
2. **Thread Pooling vs. Process Spawning:** Threads share the same memory space and have minimal OS creation overhead compared to processes (`multiprocessing`), which is ideal for lightweight, I/O-bound network calls.
3. **`dnspython` Synchronous Nature:** Standard `dnspython` is synchronous and blocking. Running blocking socket calls inside a Python `ThreadPoolExecutor` (with a sensible limit like 20 workers) provides high throughput without requiring complex asynchronous event loop plumbing.
4. **Controlled Concurrency:** Capping workers at 20 avoids flooding local DNS resolvers or triggering upstream rate-limiting/firewall drops.

---

### Question 5: Why must target domains be strictly normalized and validated before any reconnaissance, and what security risks are mitigated?
**Answer:**
Allowing raw, unsanitized user input into security tools introduces critical reliability and security flaws:
1. **SSRF and Unexpected Target Scoping:** If a user supplies an internal IP (e.g., `127.0.0.1`), querying external APIs or logging pipelines could lead to unintended target scanning.
2. **Command / Query Injection:** While our implementation uses parameterized requests, passing raw strings into external commands or unparameterized queries could lead to command injection.
3. **Denial of Service & Protocol Errors:** RFC 1035 limits domain names to 253 characters and labels to 63 characters. Passing invalid strings causes socket exceptions, broken HTTP query parameters, or unexpected application crashes.
4. **Data Consistency:** Normalizing `http://EXAMPLE.COM:8080/path` to `example.com` ensures that caching, report filenames, and deduplication keys remain deterministic and uniform across scans.

---

# Part 2: v1 Step 2 — Live Host Probing (HTTP/HTTPS)

## 1. Plain-English Code Walkthrough

### `src/asm/models.py` (Probe Extensions)
- **What it is:** Added dataclasses and enumerations for active probing results and reports.
- **Key Structures:**
  - `HostProbeStatus` (`StrEnum`): Host lifecycle states: `PROBED`, `SKIPPED_UNTRUSTED`, `SKIPPED_PRIVATE_IP`, `SKIPPED_UNRESOLVED`.
  - `ProbeErrorType` (`StrEnum`): Standardized error categories: `TIMEOUT`, `CONNECT_ERROR`, `TLS_ERROR`, `TOO_MANY_REDIRECTS`, `OTHER`.
  - `RedirectHop` (`dataclass`): Tracks each redirect URL, status code, and whether it was marked `out_of_scope`.
  - `UrlProbeResult` (`dataclass`): Captures reachability, HTTP status code, final URL, redirect chain, HTML `<title>`, response headers (`Server`, `X-Powered-By`, `Content-Type`), round-trip time in milliseconds, error classification, and certificate validity (`tls_valid`).
  - `HostProbeResult` (`dataclass`): Aggregates HTTPS and HTTP results for a subdomain, sets overall `live` status, and designates the `preferred_url`.
  - `ProbeReport` (`dataclass`): Root export artifact linking the original discovery report, UTC timestamps, counts (`hosts_probed`, `https_live`, `http_only`, `unreachable`, `tls_invalid`, `skipped_untrusted`, `skipped_private_ip`, `skipped_unresolved`), and detailed host results.

### `src/asm/prober.py`
- **What it is:** Active HTTP/HTTPS network prober with defensive controls.
- **Key Functions & Safety Mechanisms:**
  - `is_safe_public_ip(ip_str: str) -> bool`: Unwraps IPv4-mapped IPv6 addresses (e.g. `::ffff:127.0.0.1` -> `127.0.0.1`), then asserts `ip.is_global and not ip.is_multicast`. This blocks private RFC 1918 networks, loopback (`127.0.0.1`, `::1`), link-local (`169.254.0.0/16`), CGNAT (`100.64.0.0/10`), `0.0.0.0`, and multicast ranges.
  - `check_host_for_ssrf(hostname: str) -> tuple[bool, str | None]`: Resolves the host before any HTTP call. If any resolved IP is non-global/private, the host is skipped with `SKIPPED_PRIVATE_IP`. *(Documented: prevents internal network probing/SSRF; DNS rebinding protection will be added in v2).*
  - `is_redirect_in_scope(target_url: str, base_domain: str) -> bool`: Enforces that redirects must use `http` (port 80) or `https` (port 443), must match the target root domain or a subdomain, and cannot point to raw IP addresses or non-default ports like 8080.
  - `extract_title(html_bytes: bytes, content_type: str | None) -> str | None`: Parses the `<title>` tag only when `Content-Type` is `text/html`. Uses charset from headers (fallback `utf-8`), replaces invalid bytes, collapses internal whitespace, and caps length at 200 characters.
  - `_stream_and_read_body(response, deadline) -> bytes`: Streams the response body and caps reading at 64 KB (`65,536 bytes`), raising `DeadlineExceeded` if the clock passes the 10.0s URL deadline.
  - `is_tls_cert_verification_error(exc) -> bool`: Walks `__cause__` and `__context__` to detect real `ssl.SSLCertVerificationError` wrapped in `httpx.ConnectError`.
  - **Per-Client `verify=False` Retry**: When certificate verification fails, `tls_valid = False` is recorded, and a dedicated, isolated `httpx.Client(verify=False)` is used for one retry solely to test whether an HTTP service is responding behind the invalid certificate.
  - `probe_host(hostname, base_domain)`: Validates host syntax and scope, executes the SSRF pre-check, and uses an independent `httpx.Client` per thread to test HTTPS then HTTP.

### `src/asm/cli.py` (`handle_probe`)
- **What it is:** Added `asm probe <report_file> --authorized [-o DIR]` CLI command.
- **Key Workflow:**
  - **Authorization Gate**: Without `--authorized`, reads only the local report file to extract the domain, prints the mandatory warning message to stderr, and exits with code 1 without sending any network packets.
  - Validates report structure, filters for `RESOLVED` hosts, and tracks skipped unresolved hosts.
  - Concurrently probes hosts, writes a Windows-safe JSON report (`<domain>_probe_YYYYMMDDTHHMMSSZ.json`), and displays summary counts and live hosts.

---

## 2. Five Step 2 Cybersecurity Interview Questions & Answers

### Question 1: Why does active reconnaissance require explicit authorization, and what legal frameworks govern unauthorized probing?
**Answer:**
Unlike passive reconnaissance (which queries third-party logs like crt.sh or public DNS caches), active probing sends TCP connections and HTTP/HTTPS requests directly to the target organization's servers and firewalls.

Without explicit written authorization, active scanning can trigger security alerts, cause unintended service disruption, and violate computer crime laws:
1. **United States — Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030):** Prohibits intentionally accessing a protected computer without authorization or exceeding authorized access.
2. **United Kingdom — Computer Misuse Act 1990 (Section 1):** Criminalizes causing a computer to perform any function with intent to secure unauthorized access to programs or data.
3. **India — Information Technology Act, 2000:**
   - **Section 43 (Penalty and Compensation for damage to computer system):** Imposes civil liability and heavy financial penalties for accessing, securing access to, or downloading data from a computer system without permission of the owner.
   - **Section 66 (Computer Related Offenses):** Criminalizes fraudulent or dishonest acts under Section 43 (often termed hacking), punishable with imprisonment up to three years or fines up to ₹500,000 INR.

The `--authorized` flag serves as a deliberate safety gate ensuring the operator affirmatively asserts legal permission before any packets leave their system.

---

### Question 2: What is Server-Side Request Forgery (SSRF), and why must a reconnaissance tool strictly validate redirect targets?
**Answer:**
SSRF occurs when an attacker can coerce an application or scanner into making unintended HTTP requests to an arbitrary destination.

In active reconnaissance tools that automatically follow HTTP redirects:
- If a target subdomain (`sub.example.com`) redirects to an internal endpoint (e.g. `http://169.254.169.254/latest/meta-data/` on AWS/GCP, or `http://localhost:6379` for Redis), an unconstrained prober would follow the redirect, fetch sensitive cloud metadata or internal service banners, and potentially expose them in reports.
- Furthermore, an attacker-controlled server could redirect the tool to external targets or non-default internal ports (`http://sub.example.com:8080/`), turning the scanner into an unwitting proxy or denial-of-service tool.

**How we mitigate this:**
1. We follow redirects **manually** rather than automatically.
2. We validate that every redirect target strictly matches the root domain or authorized subdomains.
3. We enforce that redirects only use HTTP (port 80) or HTTPS (port 443).
4. If a redirect points out-of-scope or to an IP address, we record the hop with `out_of_scope = True`, mark the host as reachable, and stop following immediately.

---

### Question 3: Why should an attack surface management tool distinguish between TLS validity and service reachability?
**Answer:**
In production environments, subdomains frequently host services with expired certificates, self-signed certificates, or certificates with name mismatches (e.g., development, staging, or internal microservices exposed to the internet).

If a security scanner aborts immediately upon encountering a certificate error:
1. It completely misses the service running behind that port, leaving shadow IT and unpatched web applications invisible to defenders.
2. It fails to report the certificate issue itself, which is a major security flaw (rendering communications vulnerable to Man-in-the-Middle attacks).

**Our dual approach:**
We first attempt a strict TLS handshake (`verify=True`). If verification fails (detecting `ssl.SSLCertVerificationError`), we explicitly record `tls_valid = False` to document the certificate vulnerability. We then instantiate a separate client with `verify=False` solely to test if an HTTP service responds, allowing us to capture the page title, web server banner, and status code for comprehensive asset visibility.

---

### Question 4: Why enforce a 64 KB response streaming cap and an overall 10-second URL deadline during reconnaissance?
**Answer:**
Reconnaissance tools must be defensive and resilient against defensive countermeasures and resource exhaustion attacks:
1. **Decompression & Download Bombs:** Web servers can return multi-gigabyte ISOs, video files, or compressed "zip/gzip bombs" (e.g., small downloaded streams that expand to gigabytes or never terminate). Downloading full bodies would saturate the scanner's bandwidth and exhaust system memory.
2. **Reconnaissance Goal:** For asset discovery and service identification, only the HTTP headers, status code, and HTML `<title>` tag are necessary. The `<title>` almost always resides within the initial few kilobytes of the HTML `<head>` section. Reading at most 64 KB guarantees we capture the title while bounding memory consumption.
3. **Slowloris & Tarpit Defense:** A defensive host or misconfigured server might drip bytes at a rate of 1 byte per second to keep scanner threads tied up indefinitely. Enforcing a hard 10.0-second end-to-end deadline per URL (using high-resolution monotonic clocks) guarantees threads terminate promptly.

---

### Question 5: What is the purpose of pre-probe IP resolution and IPv4-mapped IPv6 unwrapping, and what is DNS Rebinding?
**Answer:**
**Pre-Probe IP Resolution & IPv4-Mapped IPv6:**
Before sending any HTTP packets to a resolved host, `asm probe` resolves the host's IP addresses and inspects them using Python's `ipaddress` module.
- Many systems support dual-stack IPv4-mapped IPv6 addresses (format `::ffff:127.0.0.1` or `::ffff:10.0.0.1`). If evaluated solely as IPv6 without unwrapping, some naive filters misidentify them as public IPv6 addresses. We unwrap `ip.ipv4_mapped` first, and ensure `ip.is_global and not ip.is_multicast`. This blocks RFC 1918, CGNAT (`100.64.0.0/10`), link-local, loopback, and broadcast ranges from being probed.

**What is DNS Rebinding?**
DNS Rebinding is an attack where an attacker controls an authoritative nameserver for a domain. When our tool resolves the domain during the pre-check, the nameserver returns a legitimate public IP address (passing the SSRF filter). However, when the HTTP client subsequently resolves the host to establish a socket connection milliseconds later, the nameserver returns an internal IP address (such as `127.0.0.1` or `169.254.169.254`).

*Future Mitigation (v2):* Connecting directly to the pre-verified IP address via an explicit IP socket while passing the hostname in the `Host` header and TLS SNI extension completely prevents DNS rebinding.

---

# Part 3: v1 Step 3 — Lightweight TCP Port Scanning

## 1. Plain-English Code Walkthrough

### `src/asm/scan_common.py`
- **What it is:** Centralized security module containing shared input validation, report loading, and SSRF defense primitives.
- **Why it exists:** Both `prober.py` (HTTP probing) and `portscan.py` (TCP scanning) require identical security checks: treating the input report as untrusted data, re-validating domain syntax/scope, unwrapping IPv4-mapped IPv6 addresses, and blocking internal network ranges. Centralizing this prevents "security drift" between modules.
- **Key Functions:**
  - `load_and_validate_report(report_path)`: Opens JSON report, verifies `domain` and `results`, filters hosts with `status == "RESOLVED"`, and counts skipped unresolved hosts. Raises `ReportValidationError`.
  - `is_safe_public_ip(ip_str)`: Unwraps `ip.ipv4_mapped` and asserts `ip.is_global and not ip.is_multicast`.
  - `check_host_for_ssrf(hostname)`: Resolves host records and blocks private/loopback/CGNAT addresses.
  - `validate_host_and_scope(hostname, base_domain)`: Ensures the hostname passes strict RFC 1035 syntax validation and belongs to the authorized domain scope.

### `src/asm/portscan.py`
- **What it is:** Asynchronous TCP connect port scanner and banner grabber built with Python's standard library `asyncio`.
- **Key Functions & Safety Controls:**
  - `DEFAULT_PORTS`: Fixed list of 16 common ports (`21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443`). Never scans any port outside this set.
  - `compute_risk_flags(port)`: Flags high-risk exposures: `DATABASE_EXPOSURE` (3306, 5432, 6379), `RDP_EXPOSURE` (3389), `SMB_EXPOSURE` (445), `TELNET_INSECURE_REMOTE_ACCESS` (23), and `PLAINTEXT_PROTOCOL` (strictly limited to 21, 23, 25, 110, 143; never flags 80, 8080, 443, 8443, or 22).
  - `grab_banner(reader, writer, port)`: Safely captures service greetings with a 2s timeout and 256-byte limit. For SSH (`port 22`), it listens passively without sending bytes (avoiding handshake breakage). For ports 21, 25, 110, 143, it sends a single `\r\n` CRLF prompt. For all other ports, it listens passively.
  - `sanitize_banner(raw_bytes)`: Strips non-printable ASCII control characters, collapses whitespace, and truncates to 256 characters.
  - `scan_single_port(host, port, port_semaphore)`: Executes `asyncio.wait_for(asyncio.open_connection(host, port), timeout=3.0)`.
    - **Strict Connection Validation:** A port is classified as `OPEN` *only* if `asyncio.open_connection` succeeds with valid reader/writer streams, `writer.is_closing()` is False, socket fileno != -1, and `reader.at_eof()` is False (not closed prematurely).
    - **Error Mapping:** `TimeoutError` strictly maps to `FILTERED`. `ConnectionRefusedError` (and Windows `WSAECONNREFUSED` / 10061) strictly maps to `CLOSED`. `OSError` (network unreachable / host down) and any unexpected exceptions strictly map to `FILTERED` (never `OPEN` on error).
  - `scan_host_ports(hostname, base_domain, ...)`: Validates host scope, performs DNS resolution at scan time (marking `SKIPPED_UNRESOLVED` if DNS fails so one bad host never aborts the scan), runs the SSRF check, and scans ports concurrently.
  - Concurrency limiting: Max 10 ports in parallel per host (`port_semaphore`), max 5 hosts in parallel (`host_semaphore`), with a polite delay between connections.

### `tests/test_integration_portscan.py`
- **What it is:** Real-network integration test against `scanme.nmap.org`.
- **Safety & Isolation:** Decorated with `@pytest.mark.integration` and deselected by default in CI and standard test runs via `addopts = "-v --strict-markers -m 'not integration'"` in `pyproject.toml`.
- **Purpose:** Verifies live socket classification: confirms that dropped/firewalled ports (such as 8080 and 8443 on `scanme.nmap.org`) return `FILTERED`, while actual listening ports return `OPEN`.

### `src/asm/models.py` (Port Scan Extensions)
- Added `PortStatus` (`StrEnum`: `OPEN`, `CLOSED`, `FILTERED`).
- Added `PortResult` (`dataclass`): Port number, state, guessed service, banner, risk flags, and response time.
- Added `HostPortScanResult` (`dataclass`): Per-host breakdown of open, closed, and filtered ports with host-level risk tags.
- Added `PortScanReport` (`dataclass`): Top-level export schema for port scan reports.

### `src/asm/cli.py` (`handle_portscan` and Quiet Logging)
- Added `asm portscan <report.json> --authorized [-o DIR] [-v]`.
- Enforces the `--authorized` gate before connecting to any sockets.
- **Logging Fix**: Silences third-party and standard library debug logs (`httpx`, `httpcore`, `asyncio`) unless `-v` is explicitly passed, keeping default output clean.

---

## 2. Five Step 3 Cybersecurity Interview Questions & Answers

### Question 1: What is the technical and practical difference between a TCP Connect scan and a SYN "Stealth" scan?
**Answer:**
- **TCP Connect Scan (`-sT` in Nmap / `asyncio.open_connection` in Python):**
  - Uses the operating system's standard network API (`connect()` system call) to complete the full three-way TCP handshake (`SYN -> SYN-ACK -> ACK`). Once connected, the application closes the socket (`FIN` or `RST`).
  - *Advantages:* Runs entirely in user-space with standard unprivileged user accounts; requires no raw socket privileges or special kernel drivers (e.g. WinPcap/Npcap on Windows); cross-platform and reliable.
  - *Disadvantages:* Slower than SYN scanning; readily logged by application-layer server logs as established connections.
- **TCP SYN "Stealth" Scan (`-sS` in Nmap):**
  - Sends a raw `SYN` packet. If the target responds with `SYN-ACK` (port open), the scanner immediately sends a `RST` packet to tear down the connection before the three-way handshake completes.
  - *Advantages:* Faster; historically bypassed basic application-layer logging (though modern stateful firewalls and IDS/IPS detect SYN scans easily).
  - *Disadvantages:* Requires raw socket creation (`SOCK_RAW`), which mandates Administrator/root privileges and custom packet crafting.

---

### Question 2: In TCP port scanning, what is the operational distinction between `CLOSED` and `FILTERED`?
**Answer:**
- **`CLOSED`:**
  - The target host is online and received the TCP `SYN` packet, but no service is listening on that port. The target's operating system kernel immediately generates an active TCP `RST` (Reset) packet (or `RST-ACK`) and sends it back to the scanner.
  - *Security Insight:* Proves that the host is alive, responsive, and routing traffic, and that there is no intermediate firewall silently discarding packets on that port.
- **`FILTERED`:**
  - The scanner sent a TCP `SYN` packet, but received no response within the timeout window (or received an ICMP Type 3 "Destination Unreachable / Communication Administratively Prohibited" error).
  - *Security Insight:* Indicates that a stateful firewall, packet filter, or cloud security group (e.g. AWS Security Group or iptables) is silently dropping packets before they reach the target operating system.

---

### Question 3: Why should an Attack Surface Management (ASM) tool scan a fixed list of common ports rather than the full 1–65,535 range?
**Answer:**
1. **Pareto Principle (80/20 Rule):** Over 95% of exposed enterprise assets, misconfigurations, and external attack vectors reside on a small cluster of well-known ports (HTTP/HTTPS, SSH, RDP, SMB, standard databases). A curated 16-port scan detects the vast majority of critical vulnerabilities.
2. **Speed & Efficiency:** Scanning 65,535 ports per host across hundreds of subdomains would take hours or days per scan and consume massive network bandwidth. A 16-port scan takes under 5 seconds per host.
3. **IDS/IPS & Abuse Evasion:** Sweeping full port ranges triggers threshold-based Intrusion Detection/Prevention Systems (IDS/IPS), causes defensive firewalls to blacklist the scanner's IP, and generates automated abuse complaints from ISPs and hosting providers.
4. **Targeted Risk Identification:** Scanning ports like 3389 (RDP) or 445 (SMB) immediately identifies critical exposures without generating unnecessary network noise.

---

### Question 4: What are the operational risks of banner grabbing, and why must protocols like SSH (port 22) be treated differently from SMTP or FTP?
**Answer:**
- **Crash Risks on Fragile Services:** Sending random binary payloads, generic HTTP requests, or malformed data to proprietary or legacy network daemons (e.g. SCADA/ICS devices, medical equipment, or older print servers) can trigger buffer overflows, unhandled socket exceptions, or denial-of-service crashes.
- **Protocol Etiquette (SSH vs. Prompt Protocols):**
  - **SSH (Port 22):** The SSH protocol specification (RFC 4253) states that upon TCP connection, the **server speaks first** by sending its protocol identification string (e.g., `SSH-2.0-OpenSSH_8.9p1`). If a scanner immediately sends bytes before reading the server's identification, the SSH daemon considers it a protocol violation and closes the connection.
  - **Banner Protocols (FTP 21, SMTP 25, POP3 110, IMAP 143):** These protocols often wait for a client prompt or greeting. Sending a single `\r\n` CRLF cleanly prompts the server to return its standard welcome banner without sending dangerous fuzzing payloads.

---

### Question 5: Why is centralizing shared security controls (SSRF guards and domain validation) into `scan_common.py` an essential software architecture pattern?
**Answer:**
1. **Prevention of Security Drift:** In multi-stage security tools (Discovery -> HTTP Probing -> Port Scanning -> Vulnerability Assessment), each stage performs network I/O. If validation logic is duplicated across separate files, improvements or bug fixes made in one scanner (e.g. discovering a bypass in IPv4-mapped IPv6 address parsing) might not be applied to other stages, leaving gaps.
2. **Consistent Policy Enforcement:** Centralizing functions like `load_and_validate_report`, `is_safe_public_ip`, and `validate_host_and_scope` ensures that all active modules adhere strictly to the exact same authorization boundaries, private IP filters, and error handling rules.
3. **Testability & Auditability:** Having a single, dedicated module with unit tests proves that core security boundaries are tested and verified independently of protocol-specific networking logic.

---

# Part 4: TLS Certificate Inspection & HTTP Security Headers

## 1. Plain-English Architecture Walkthrough

### `src/asm/tls_inspect.py`
- **What it is:** Pure standard library TLS certificate inspector and evaluator.
- **Two-Pass Public API Verification Strategy:**
  - **Pass 1 (Verified):** Uses `ssl.create_default_context()` to connect to `host:443`. If the certificate chain validates successfully against the operating system's trusted root CA store, `is_trusted = True` and the parsed certificate dictionary is read via `sslsock.getpeercert()`.
  - **Pass 2 (Unverified Fallback):** If verification fails (e.g. expired, self-signed, invalid CA chain), an unverified context is created using public standard library API (`ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE`). This allows the TLS handshake to complete, records `is_trusted = False`, captures the exact verification error (`verify_error`), and extracts negotiated TLS protocol version and key flags.
- **Key Functions & Logic:**
  - `matches_hostname(hostname, sans, common_name)`: Implements RFC 6125 wildcard matching. Prioritizes Subject Alternative Names (SANs) over Common Name (CN). Ensures single-level wildcards (`*.example.com`) only match single subdomains (`api.example.com`) and never multi-level domains (`a.b.example.com`) or the apex domain (`example.com`).
  - `parse_cert_dict(cert_dict, ...)`: Converts `getpeercert()` output into `CertInfo`. Parses validity dates into ISO 8601 UTC via `ssl.cert_time_to_seconds`, calculates exact `days_until_expiry`, and evaluates security flags.
  - Flags: `expired` (now past notAfter), `not_yet_valid` (now before notBefore), `issuer_equals_subject` (likely self-signed), `hostname_mismatch`, `expiring_soon` (30 days or fewer remaining), and `deprecated_tls` (TLS 1.0 or 1.1).

### Note on Weak Signature Algorithm Detection
- **Why `weak_sig` is omitted in v1:** Python's standard library `ssl.getpeercert()` decodes X.509 certificates using OpenSSL's internal C routines but intentionally omits the certificate signature algorithm OID from its returned dictionary. Hand-parsing binary DER/ASN.1 structures in the standard library without external libraries is fragile and error-prone across different X.509 extensions.
- **Production Standard:** In enterprise Attack Surface Management tools, comprehensive certificate parsing (including signature algorithms like MD5/SHA-1 and full certificate chains) is performed using the dedicated `cryptography` library (`cryptography.x509`).

### `src/asm/headers_inspect.py`
- **What it is:** HTTP security header evaluator and single-connection TLS coordinator.
- **Single-Connection Preference:**
  - Performs an HTTPS GET to `https://<host>/` using `httpx.Client(verify=True)`.
  - Evaluates HTTP response headers directly.
  - Reuses the active TLS connection by reading `response.extensions.get("network_stream").get_extra_info("ssl_object")` to extract certificate data in the exact same TCP round-trip.
  - **Robust Fallback:** If the stream is closed, `ssl_object` is None, or `getpeercert()` returns an empty dictionary, the coordinator falls back to a direct `ssl+socket` connection to `host:443`, recording whether the cert was obtained `from_response` or `from_socket`.
- **Security Header Analysis:**
  - Monitored Headers: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`.
  - HSTS Parsing: Extracts `max-age` in seconds. Flags `hsts_weak = True` if `max-age < 15552000` (180 days).
  - Information Disclosure: Checks for `Server`, `X-Powered-By`, and `X-AspNet-Version` headers that leak server software and backend runtime versions to attackers.

### `src/asm/models.py` (Inspection Extensions)
- Added `CertInfo` (`dataclass`): Certificate metadata and boolean flags.
- Added `HeaderInfo` (`dataclass`): Present/missing headers, HSTS max-age, and disclosure flags.
- Added `HostInspectResult` (`dataclass`): Combined per-host inspection result.
- Added `InspectReport` (`dataclass`): Top-level export schema for inspect reports.

### `src/asm/cli.py` (`handle_inspect`)
- Added `asm inspect <probe_report.json> --authorized [-o DIR] [-v]`.
- Enforces the `--authorized` gate before initiating any network inspection.
- Filters probe results to inspect only hosts that were verified reachable over HTTPS in Step 2 (`SKIPPED_NOT_HTTPS`).
- Displays a clean CLI summary and exports the JSON report.

---

## 2. Five Step 4 Cybersecurity Interview Questions & Answers

### Question 1: What does a TLS certificate actually prove, and what do certificate expiry, self-signing, and hostname mismatch indicate for an organization's attack surface?
**Answer:**
- **What a TLS Certificate Proves:** A TLS certificate cryptographically binds a public key to an identity (a domain name). When signed by a trusted Certificate Authority (CA) in the client's trust store, it proves two things: (1) **Authentication** (the client is speaking to the legitimate owner of the domain) and (2) **Confidentiality/Integrity** (enables symmetric session key exchange so network traffic cannot be eavesdropped on or tampered with).
- **Attack Surface Implications:**
  - **Expired Certificate:** Indicates poor asset management, broken automated certificate lifecycle management (e.g. Certbot/ACME failure), and immediately causes browser security warnings that destroy user trust or break API integrations.
  - **Self-Signed Certificate (`issuer_equals_subject`):** Means no trusted third-party CA validated domain ownership. Attackers on the local network (or via ARP/DNS poisoning) can easily generate their own self-signed certificates and execute Man-in-the-Middle (MitM) attacks.
  - **Hostname Mismatch:** Indicates that the domain serving traffic does not match the names in the certificate's SAN or CN. This commonly happens when a staging site points to production CDN infrastructure, when a virtual host is misconfigured, or after an incomplete domain migration.

---

### Question 2: What is HTTP Strict Transport Security (HSTS), and why does a weak `max-age` value (e.g. less than 180 days) undermine its security guarantee?
**Answer:**
- **What HSTS Does:** HSTS (`Strict-Transport-Security`) is a response header that instructs web browsers to **never** load the site over plain HTTP and to automatically convert all insecure `http://` links to `https://` before sending any request. It also prevents users from clicking through SSL certificate warnings.
- **Why `max-age` Matters:**
  - When a user types `example.com` into their browser, the initial request is sent over unencrypted HTTP port 80. An attacker on the local network (e.g. public Wi-Fi) can intercept this initial request using an SSL-stripping tool (like `sslstrip`) before the server can redirect to HTTPS.
  - HSTS caches the requirement to use HTTPS in the user's browser for the duration of `max-age` seconds.
  - A short `max-age` (e.g. a few hours or days) expires quickly. If a user does not visit the site frequently, their cached HSTS rule expires, reopening the window for SSL-stripping and downgrade attacks. The security community (and Chromium HSTS Preload list) mandates a minimum `max-age` of at least 180 days (15,552,000 seconds), with 1–2 years recommended.

---

### Question 3: What is the primary security objective of Content Security Policy (CSP), and what types of attacks does it mitigate?
**Answer:**
- **Primary Objective:** CSP is an HTTP response header (`Content-Security-Policy`) that allows site administrators to declare an approved allowlist of sources from which the browser is permitted to load and execute dynamic resources (JavaScript, CSS, images, iframes, fonts, media).
- **Attacks Mitigated:**
  - **Cross-Site Scripting (XSS):** By restricting script execution to approved domains and disallowing inline scripts (`'unsafe-inline'`) or `eval()` (`'unsafe-eval'`), CSP prevents injected malicious scripts from executing even if an attacker successfully injects code into an HTML page.
  - **Clickjacking / UI Redressing:** Using the `frame-ancestors` directive (which supersedes `X-Frame-Options`), CSP dictates which parent domains are allowed to embed the current page inside an `<iframe>`, preventing attackers from tricking users into clicking invisible buttons.
  - **Data Exfiltration:** CSP restricts where forms can be submitted (`form-action`) and where background network requests can be sent (`connect-src`), preventing malicious scripts from beaconing stolen session tokens or credentials to external attacker-controlled servers.

---

### Question 4: How do information-disclosure headers (such as `Server`, `X-Powered-By`, `X-AspNet-Version`) assist an attacker during the reconnaissance phase?
**Answer:**
- **Technology Stack Fingerprinting:** Headers like `Server: Apache/2.4.49`, `X-Powered-By: PHP/7.4.3`, or `X-AspNet-Version: 4.0.30319` explicitly tell an attacker the exact web server software, programming language runtime, and web framework versions powering the application.
- **Accelerating Exploit Discovery:** Rather than sending noisy, generalized probe payloads that might trigger a Web Application Firewall (WAF), an attacker can immediately cross-reference the leaked version numbers against public vulnerability databases (CVEs) and exploit repositories (e.g. finding that Apache 2.4.49 is vulnerable to path traversal CVE-2021-41773).
- **Remediation:** Production servers should suppress, strip, or minimize these headers (e.g. `ServerTokens Prod` in Apache, `server_tokens off` in Nginx, or removing `X-Powered-By` in Express/PHP) to enforce defense-in-depth and make reconnaissance more costly for adversaries.

---

### Question 5: Why is the single-connection preference with a two-pass fallback pattern an ideal design for Attack Surface Management tools?
**Answer:**
1. **Network Efficiency & Politeness:** Opening new TCP connections and performing cryptographic TLS handshakes consumes network bandwidth and CPU cycles on both the scanner and the target server. By reading the active TLS peer certificate directly from the underlying transport stream of the HTTP response (`network_stream`), the tool collects both HTTP headers and TLS certificates in a single round-trip.
2. **Graceful Degradation:** Production networks are messy. If a certificate is invalid (expired or self-signed), a strict client like `httpx` will abort the connection immediately during TLS verification. By catching this verification failure and executing a targeted unverified fallback (`verify_mode = ssl.CERT_NONE`), the scanner avoids crashing, records the exact cause of untrust, and still inspects the host's headers and protocol version.
3. **Audit Trail & Transparency:** Tracking the source of inspection (`from_response` vs. `from_socket`) ensures the resulting ASM report clearly indicates whether the host allowed a standard verified session or required low-level socket fallback.
