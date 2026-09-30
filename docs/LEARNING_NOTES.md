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

---

# Part 5: v1 Step 5 — Risk Scoring & Combined Report

## 1. Plain-English Code Walkthrough

### `src/asm/scoring.py`
- **What it is:** The defensive risk scoring and multi-stage report aggregation engine.
- **Why it exists:** Previous steps generated isolated reports for subdomains, HTTP probing, open ports, and TLS/header issues. This module combines these disjoint observations into a unified, actionable risk assessment per host and across the entire domain without generating any network packets.
- **Key Architecture & Design Decisions:**
  - **Single Central Table (`FINDING_DEFINITIONS`):** All 21 finding types are declared in one table at the top of the module with static IDs, titles, severity tiers, points, and human-readable security impact strings (`why_it_matters`). This makes the scoring rules easily auditable, consistent, and defensible.
  - **Host Band Derived from Worst Finding Tier (Rule 1):** Rather than arbitrary point bucket math where multiple trivial issues could artificially create a "critical" host, a host's severity band is determined strictly by its **worst finding tier**:
    - Any `CRITICAL` finding $\rightarrow$ `CRITICAL`
    - Else any `HIGH` finding $\rightarrow$ `HIGH`
    - Else any `MEDIUM` finding $\rightarrow$ `MEDIUM`
    - Else any `LOW` finding $\rightarrow$ `LOW`
    - Else $\rightarrow$ `INFO` (clean host)
    The point sum is preserved and used as a secondary tiebreaker for sorting within each band.
  - **Service Confirmation Distinguishes CRITICAL vs. HIGH (Rule 2):** An exposed database port (3306, 5432, 6379) that returned an active service banner is designated `CRITICAL` (`PORT_CONFIRMED_DB`, 10 pts) because it confirms an active, reachable database engine on the internet. An open DB port without a banner remains `HIGH` (`PORT_EXPOSED_DB`, 7 pts).
  - **Honest Split on Untrusted Certificates (Rule 3):** An expired or not-yet-valid certificate is classified as `HIGH` (definitive failure of trust and browser availability). In contrast, a self-signed certificate (`issuer_equals_subject`) on an unexpired certificate is classified as `MEDIUM` (`TLS_SELF_SIGNED`, 4 pts), explicitly documenting that it may be intentional for internal or development assets.
  - **Domain Band Derivation (Rule 4):**
    - Any `CRITICAL` host $\rightarrow$ Domain `CRITICAL`
    - Else any `HIGH` host $\rightarrow$ Domain `HIGH` (with an escalation note flagged if $\ge 3$ high hosts exist)
    - Else any `MEDIUM` host $\rightarrow$ Domain `MEDIUM`
    - Else any `LOW` host $\rightarrow$ Domain `LOW`
    - Else $\rightarrow$ Domain `INFO`
  - **Stage Evaluators:** Dedicated functions (`evaluate_probe_findings`, `evaluate_portscan_findings`, `evaluate_inspect_findings`) convert raw report data into typed `Finding` objects with concrete proof strings.

### `src/asm/models.py` (Scoring Models)
- Added `SeverityTier` (`StrEnum`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- Added `Finding` (`dataclass`): Represents a single security issue with `id`, `title`, `tier`, `points`, `source`, `host`, `port`, `evidence`, and `why_it_matters`.
- Added `HostScore` (`dataclass`): Aggregated risk score, worst-tier severity band, and itemized findings for a host.
- Added `ScoreReport` (`dataclass`): Domain-wide aggregation report with timestamp, inputs used, domain band, total score, summary counts, and host list.

### `src/asm/scan_common.py` (`load_and_validate_generic_report`)
- Added generic report loader treating all input files as untrusted. Verifies JSON structure, validates the `domain` field, asserts all input reports belong to the exact same domain, and ensures the `results` list exists. Raises `ReportValidationError` on any failure.

### `src/asm/cli.py` (`handle_score`)
- Added `asm score --discover <f> [--probe <f>] [--portscan <f>] [--inspect <f>] [-o DIR] [-v]`.
- Does not require `--authorized` because it performs zero network activity.
- Generates `output/<domain>_score_<UTC>.json` and formats a human-readable CLI summary sorted worst-first.

---

## 2. Five Step 5 Cybersecurity Interview Questions & Answers

### Question 1: Why should an Attack Surface Management tool use categorical severity tiers (CRITICAL, HIGH, MEDIUM, LOW) instead of an arbitrary 0–10 score?
**Answer:**
- **Actionability Over False Precision:** Arbitrary floating-point numbers (e.g. "Risk Score: 7.42") convey a false sense of mathematical precision. Security teams cannot realistically differentiate the urgency of a 7.2 vs. a 7.4. Categorical tiers map directly to operational triage workflows and Service Level Agreements (SLAs) (e.g. CRITICAL = 24-hour remediation, HIGH = 7-day remediation, MEDIUM = 30 days).
- **Preventing "Point Inflation":** Point-only scoring algorithms suffer from distortion where dozens of minor informational findings (like missing headers) can sum up to a high number, artificially labeling a low-risk blog as more dangerous than a server exposing an unauthenticated database. Determining the host band by its **worst finding tier** ensures that critical risks are never masked or artificially created.

---

### Question 2: Why must risk scoring be strictly driven by observable evidence, and what is the danger of a finding without evidence?
**Answer:**
- **Defensibility & Credibility:** In security operations, developer pushback against vulnerability scanners is common. A finding that states *"Host has insecure database"* without evidence will be contested or ignored. A finding with concrete evidence (*"Port 3306 (mysql) is OPEN with confirmed service banner: '5.7.34-log MySQL Community Server'"*) is irrefutable.
- **Root Cause & Remediation:** Concrete evidence provides engineers with the exact diagnostic data required to fix the issue (e.g. the specific port, the exact missing header name, or the certificate expiry date).
- **Audit Compliance:** External compliance frameworks (SOC 2, ISO 27001, PCI-DSS) require evidence-based verification for every identified finding to support formal remediation tracking.

---

### Question 3: How do you justify classifying a confirmed exposed database port with an active banner as CRITICAL, while an open database port without a banner is classified as HIGH?
**Answer:**
- **Confirmed Reachability vs. Firewall Artifacts:** An open TCP port without a banner confirms that a three-way TCP handshake succeeded, but does not prove what software is running behind it. It could be a honeypot, an intermediate firewall performing full proxying, or a load balancer. It remains a `HIGH` risk because sensitive ports should never be accessible from the public internet.
- **Immediate Weaponization Potential (CRITICAL):** When a database port returns an active protocol greeting banner (e.g. MySQL packet handshake or PostgreSQL error response), it conclusively proves that an active database daemon is directly accepting untrusted packets from the public internet. This exposes the organization to immediate remote authentication attacks, zero-day CVE exploitation, and severe data breach risks.

---

### Question 4: In attack surface management, what are false positives vs. false negatives, and how does this heuristic triage model balance them?
**Answer:**
- **Definitions:**
  - **False Positive:** Flagging an issue that does not actually pose risk (e.g. marking a self-signed certificate on an internal staging server as a critical vulnerability). Excessive false positives cause "alert fatigue" and lead engineers to distrust the scanner.
  - **False Negative:** Failing to detect an actual security flaw (e.g. missing an open database or an expired certificate). False negatives create a false sense of security and leave real vulnerabilities exposed.
- **How This Model Balances Them:**
  - Avoids false positives by honestly splitting findings (e.g. self-signed certificates are `MEDIUM`, acknowledging that dev environments intentionally use them; plaintext HTTP is only flagged if port 80 is live while port 443 is unreachable).
  - Avoids false negatives by performing multi-stage correlation (linking port scan results, probe HTTP statuses, and TLS handshake findings across all discovered host assets).

---

### Question 5: What are the fundamental limitations of static heuristic scoring models, and why is this model explicitly NOT CVSS?
**Answer:**
- **What CVSS Is:** The Common Vulnerability Scoring System (CVSS) is an industry standard for rating specific, identified software vulnerabilities (CVEs) based on standardized metrics: Attack Vector (AV), Attack Complexity (AC), Privileges Required (PR), User Interaction (UI), Scope (S), and Impact (Confidentiality, Integrity, Availability).
- **Why This Model is NOT CVSS:**
  - Our ASM scanner evaluates external **configuration posture** and **exposure surface** (e.g. missing defensive headers, open ports, certificate lifespan), not confirmed exploitable software vulnerabilities in a CVE database.
  - Calling heuristic ASM scoring "CVSS" is dishonest and misleading to customers and auditors.
- **Fundamental Limitations of Heuristic Models:**
  1. **No Context on Compensating Controls:** The scanner cannot see internal network segmentation, Web Application Firewall (WAF) rate limiting, or VPN authentication layers behind the host.
  2. **No Business Context:** A missing header on a marketing landing page that serves static brochures carries far less business impact than the same missing header on a banking portal, but static heuristics score them identically.

---

# Part 6: CLI Containerization & Container Security

## 1. Technical Explanations & Architecture

### Multi-Stage Builds: Reducing Final Image Size and Attack Surface
- **How It Works:** A multi-stage Dockerfile uses multiple `FROM` instructions. The first stage (`builder`) mounts the build context, installs packaging tools (`wheel`, `setuptools`, `pip`), and builds a self-contained Python wheel (`.whl`). The second stage (`runtime`) starts from a fresh base image and copies *only* the compiled wheel artifact from the builder stage, installing it without build tools or source repositories.
- **Image Size Optimization:** Build tooling, compiler caches, git metadata, and intermediate wheel build directories never make it into the runtime image. This reduces the image footprint from several hundred megabytes down to minimal runtime requirements.
- **Attack Surface Reduction:** If an attacker compromises an application running in a container, their post-exploitation capabilities depend on the tools available in that environment. By omitting compilers (`gcc`, `clang`), package build tools, and development libraries from the final runtime image, attackers are deprived of the toolchain required to compile local exploits or privilege escalation binaries.

### Non-Root Execution: A Foundational Container Security Control
- **The Containerization Paradigm:** By default, containers execute as `root` (UID 0). While Linux namespaces (PID, Mount, Net) isolate the container from the host, the kernel itself is shared. If a containerized process running as UID 0 achieves a container breakout (e.g. via a Linux kernel vulnerability or a misconfigured volume mount), the compromised process immediately has root privileges on the host operating system.
- **Least Privilege Implementation:** In our Dockerfile, a dedicated system group and user `asm` (`UID:GID 10001`) are created without administrative privileges. The application runs under this unprivileged user (`USER asm`), and `/app/output` is explicitly provisioned with `chown -R asm:asm`. Even if an attacker finds an arbitrary file write or remote code execution flaw in the scanner, they cannot modify system binaries, install packages, or escalate to root.
- **Linux Host Bind-Mount Permissions:** When bind-mounting a host folder (`-v "$(pwd)/output:/app/output"`) on Linux, the kernel enforces the host filesystem's UID/GID permissions. Passing `--user "$(id -u):$(id -g)"` dynamically aligns the container's execution identity with the host user who invoked Docker, allowing reports to be written without requiring root privileges or world-writable (`chmod 777`) host permissions.

### `.dockerignore`: Preventing Secret Leakage and Cache Invalidation
- **Build Context Overhead:** When `docker build` runs, the Docker CLI sends the entire directory contents (the build context) to the Docker daemon. Without a `.dockerignore`, gigabytes of virtual environments (`.venv/`), git history (`.git/`), and local reports (`output/`) are transferred across the socket, dramatically slowing build times.
- **Preventing Secret Leakage:** Development environments often contain `.env` files with API keys or credentials, local database caches, and test artifacts. If these are copied into the image during `COPY . .`, secrets become baked into container layers permanently—discoverable via `docker history` or container inspection even if deleted in a later command.
- **Cache Poisoning & Determinism:** Local bytecode (`__pycache__/`, `*.pyc`), test caches (`.pytest_cache/`), and linter caches (`.ruff_cache/`) can introduce non-deterministic state or cause layer cache invalidation on unrelated code edits. Excluding these ensures reproducible, hermetic container builds.

### Base Image Tag Pinning
- **Floating Tags vs. Immutable Tags:** Using floating tags like `python:3.12` or `python:3.12-slim` is an operational hazard. An upstream update can silently pull new patch versions, updated Debian packages, or breaking system library changes during a build.
- **Explicit Specification:** Pinned to `python:3.12.14-slim-trixie` across both builder and runtime stages. This guarantees reproducible builds across development, CI, and production environments, while locking the underlying Debian distribution (Debian 13 Trixie) to ensure predictable package and OpenSSL behavior.

### Container Vulnerability Scan
- **Vulnerability Findings (Docker Scout):** A vulnerability scan using Docker Scout on the previously pinned base `python:3.12.9-slim-bookworm` found **5 Critical / 51 High**, all originating from the base image.
- **Remediation via Patch Update:** Updating to `python:3.12.14-slim-trixie` reduced it to **0 Critical / 1 High**.
- **Lesson:** Pinning gives reproducibility but pins go stale, so pair pinning with automated updates (Dependabot).
- **Slim vs. Full Distro Images:** The full non-slim image had ~26 High vs 1 for slim: smaller images mean smaller attack surface.


---

## 2. Three Container Security Interview Questions & Answers

### Question 1: What is container breakout / privilege escalation, and how does running as a non-root user mitigate this risk?
**Answer:**
- **Container Breakout Defined:** A container breakout occurs when a process running inside a container circumvents the Linux isolation boundaries (namespaces, cgroups, seccomp, AppArmor) to interact directly with the host operating system or other containers.
- **The Threat of Root in Containers:** Because the container shares the host operating system's kernel, UID 0 inside a container maps to UID 0 on the host kernel unless user namespaces (`userns-remap`) are explicitly enabled. If an attacker discovers a kernel exploit (such as a dirty COW variant) or exploits a misconfigured volume mount (e.g. docker socket `/var/run/docker.sock` or host `/etc`), having root privileges inside the container allows immediate root takeover of the entire underlying host machine.
- **Non-Root Mitigation:** Running as a dedicated unprivileged user (`UID 10001`) enforces the principle of least privilege. Even if an attacker executes arbitrary code within the application process, they lack permissions to access host devices, modify protected container files, or trigger privileged kernel system calls, dramatically reducing the blast radius of any exploit.

---

### Question 2: How do multi-stage Docker builds enhance both supply chain security and operational performance?
**Answer:**
- **Supply Chain & Vulnerability Surface:**
  - Modern software builds require heavy toolchains: C/C++ compilers, header files (`python3-dev`), build utilities (`make`, `cmake`), and package managers. Each toolchain component introduces CVEs and dependencies that Vulnerability Scanners (Trivy, Grype, Snyk) will flag.
  - Multi-stage builds completely segregate the **build environment** from the **shipping artifact**. The build tools exist only in intermediate build stages that are discarded. The final production image contains only the bare runtime interpreter and the compiled wheel, reducing the number of installed packages and associated Common Vulnerabilities and Exposures (CVEs) by up to 70–80%.
- **Operational Performance:**
  - Smaller images (e.g. 50–150 MB vs 1+ GB) lead to faster network transfers across container registries and CI/CD pipelines, quicker node pulling during auto-scaling events, and lower cloud storage costs.
  - Intermediate layers in the build stage are cached independently, accelerating iterative developer builds when only application source code changes.

---

### Question 3: What is the Docker build context, and why is an unconfigured `.dockerignore` file considered a critical security vulnerability?
**Answer:**
- **Build Context Mechanism:** When `docker build` is executed, the Docker client tarballs everything in the target directory (unless excluded) and transmits it to the Docker daemon prior to evaluating the Dockerfile instructions.
- **Security Vulnerabilities of Missing `.dockerignore`:**
  1. **Accidental Credential Exposure:** Development files like `.env`, private keys (`id_rsa`), configuration secrets, or cloud credentials (`aws_credentials`) located in the project folder are sent to the daemon. If a naive `COPY . /app` instruction exists in the Dockerfile, those secrets are copied into the image layer history. Even if removed in a subsequent `RUN rm .env` step, image layers are immutable; any user with image pull access can extract the secret from the underlying layer blob.
  2. **VCS Metadata Leakage:** Omitting `.git` in `.dockerignore` causes the entire Git commit history to be bundled into the image. Attackers who obtain the container image can run `git log`, inspect deleted commits, inspect commit messages, and extract historical credentials previously committed and rolled back.
  3. **Performance Degradation & Cache Invalidation:** Sending gigabytes of node modules, virtual environments, or output reports bloats build times and continuously invalidates Docker's build layer cache, resulting in unnecessarily slow CI/CD pipelines.

---

# Part 7: v2 Step 1 — Service Foundation: Compose, Database, Migrations & Domains API

## 1. Plain-English Code Walkthrough & Architecture

### `src/asm/config.py` (Pydantic Settings)
- **What it is:** A centralized configuration module powered by `pydantic-settings`.
- **Why it exists:** Modern applications must separate configuration from code (12-Factor App methodology). Hardcoding database URIs or credentials in source code creates severe security vulnerabilities.
- **Key Design Decision (No Default Credentials):** `DATABASE_URL` is marked as required with no default value. If the application or CLI starts without `DATABASE_URL` configured in the environment or `.env`, it fails immediately at startup with an informative error rather than silently attempting to connect with an insecure fallback like `postgres:postgres`.

### `src/asm/db/models.py` (SQLAlchemy 2.0 ORM)
- **What it is:** Declarative database models defining the relational persistence layer for attack surface reconnaissance.
- **Key Entities:**
  - `Domain`: Represents a target domain registered for reconnaissance. Includes `name` (unique, indexed, normalized), `authorized` (boolean), `authorization_note` (optional string), and `created_at` (UTC timestamp).
  - **Fail-Safe Default:** `authorized` defaults to `False` in the database schema. Even if a record were inserted bypassing API validation, it remains unauthorized by default.
  - `ScanRun`: Represents an instance of a scheduled or manual scan pipeline run for a domain. Tracks `domain_id` (foreign key with `ON DELETE CASCADE`), `status` (`queued`, `running`, `succeeded`, `failed`), `created_at`, `started_at`, `finished_at`, and `error` detail.
  - `ScanResult`: Stores individual stage reports produced during a scan run (`discover`, `probe`, `portscan`, `inspect`, `score`). Uses PostgreSQL's native binary JSON format (`JSONB`) to store polymorphic scan outputs efficiently while enabling indexing and queryability.

### `src/asm/db/session.py` (Database Engine & Session Dependency)
- **What it is:** Session management module providing database connection pools and FastAPI request-scoped sessions.
- **Key Functions:**
  - `get_engine()`: Creates a cached SQLAlchemy engine with connection pool pre-ping enabled (`pool_pre_ping=True`) to automatically discard stale or terminated connections.
  - `get_db()`: Generator function designed for FastAPI dependency injection (`Depends(get_db)`). Yields a fresh database session per request and guarantees `session.close()` in a `finally` block, preventing database connection leaks.

### `alembic.ini` & `migrations/` (Alembic Schema Evolution)
- **What it is:** Database migration framework tailored for SQLAlchemy models.
- **Key Design Decision (Decoupled Connection String):** `alembic.ini` contains no database URL or credentials. Instead, `migrations/env.py` dynamically resolves `DATABASE_URL` at runtime from `asm.config.get_settings()`, ensuring migrations adapt automatically to local development, Docker Compose, and CI environments without credential duplication.
- **Container Integration:** `alembic.ini` and `migrations/` are copied into the Docker runtime image, allowing a lightweight one-shot `migrate` container in Docker Compose to execute `alembic upgrade head` before the API server boots.

### Docker Compose Architecture & PostgreSQL 18 Volume Path
- **Postgres 18 Volume Mount Finding:** In PostgreSQL 18, the official image documentation and container configuration declare the persistent volume at `/var/lib/postgresql` with internal cluster directory `PGDATA=/var/lib/postgresql/18/docker` (verified via `docker inspect postgres:18.6-alpine --format '{{json .Config.Volumes}}'`). Older PostgreSQL versions (<18) used `/var/lib/postgresql/data`. Mounting to `/var/lib/postgresql` ensures full cluster persistence across container rebuilds.
- **Service Dependency Sequencing:** In `docker-compose.yml`, the `db` service runs with a healthcheck (`pg_isready -U $${POSTGRES_USER} -d $${POSTGRES_DB}`). The one-shot `migrate` service depends on `db: condition: service_healthy`. The `api` service depends on `migrate: condition: service_completed_successfully`. A single `docker compose up` automatically brings up the database, applies all migrations, and launches the API.
- **Loopback Port Binding (`127.0.0.1:8000`):** The API currently has no authentication mechanism. Publishing the port on `0.0.0.0` would expose the reconnaissance API to all devices on the local network. Binding strictly to `127.0.0.1:8000` ensures only local loopback processes can communicate with the service.

### `src/asm/api/` (FastAPI REST Service)
- **`schemas.py`**: Pydantic models for request validation (`DomainCreate`) and response serialization (`DomainRead`, `HealthResponse`).
- **`routes.py`**:
  - `GET /health`: Runs `SELECT 1` on the active database session. Returns 200 OK with `{"status": "ok", "database": "connected"}` if reachable, or 503 Service Unavailable if disconnected.
  - `POST /domains`: Enforces the authorization gate (rejects with 422 if `authorized` is not True), verifies domain RFC syntax via `validate_domain()`, normalizes via `normalize_domain()`, and rejects duplicates with HTTP 409 Conflict.
  - `GET /domains` & `GET /domains/{id}`: Returns all domains or single domain details (404 if missing).
- **`main.py`**: Global error handling ensures unexpected internal errors return clean JSON without exposing Python stack traces or internal filenames to clients.

---

## 2. Five v2 Step 1 Interview Questions & Answers

### Question 1: What are the security, maintenance, and performance trade-offs of using an ORM (like SQLAlchemy 2.0) versus Raw SQL queries?
**Answer:**
- **Security (SQL Injection Mitigation):** ORMs automatically parameterize queries by default, separating SQL command syntax from user-supplied data and effectively eliminating SQL injection vulnerabilities. With raw SQL, developers must manually ensure every query uses bound parameters rather than string concatenation or f-strings.
- **Type Safety & Refactoring:** SQLAlchemy 2.0's typed ORM (`Mapped[T]`, `mapped_column()`, `select()`) integrates with static analysis tools (`mypy`, IDE language servers). Renaming a column or changing a data type immediately surfaces compiler/linter warnings across the entire codebase, whereas raw SQL strings fail silently until executed at runtime.
- **Database Portability & Dialect Abstraction:** The ORM abstracts vendor-specific SQL quirks (e.g. differences in date/time math, autoincrement keywords, or boolean representations between SQLite, PostgreSQL, and MySQL).
- **Trade-offs:** High-throughput analytical queries or complex recursive CTEs (Common Table Expressions) can sometimes be slower or more cumbersome to express through ORM abstractions than raw SQL. In high-performance data warehousing or large batch scans, hybrid approaches (using SQLAlchemy's Core `select()` or typed raw SQL with explicit parameter bindings) provide the best of both worlds.

---

### Question 2: Why are automated database migrations (Alembic) essential for team collaboration and production deployment pipelines?
**Answer:**
- **Deterministic Schema Synchronization:** In a team setting, each developer's local database and the shared staging/production databases must evolve in lockstep. Without migrations, developers resort to running ad-hoc `ALTER TABLE` statements manually, leading to "schema drift" where environments diverge and software breaks unpredictably during deployment.
- **Version Control for DDL:** Migration scripts are committed to git alongside the application code that depends on them. This ensures that any git branch or historical release can reproduce the exact schema state it requires (`alembic upgrade head` or `alembic downgrade -1`).
- **Zero-Downtime Deployment Support:** Automated migrations allow operations teams to execute forward-compatible migrations (e.g. adding nullable columns or creating indexes concurrently) in automated CI/CD pipelines before deploying new container code, preventing service interruptions.

---

### Question 3: Why is binding an unauthenticated web service to `127.0.0.1` rather than `0.0.0.0` a critical defense-in-depth measure?
**Answer:**
- **Network Interface Exposure:**
  - `0.0.0.0` (INADDR_ANY) binds the server socket to **all** network interfaces on the host, including physical Ethernet, Wi-Fi adapters, VPN interfaces, and virtual bridges.
  - `127.0.0.1` (loopback) binds exclusively to the local host interface. Packets directed to `127.0.0.1` can only originate from processes running on the exact same operating system kernel; the network stack drops external packets arriving on physical interfaces destined for loopback addresses.
- **Security Implications:** When an API does not yet possess an authentication and authorization layer (e.g. API keys, JWTs, mTLS), binding to `0.0.0.0` allows anyone on the local Wi-Fi, campus network, or corporate subnet to submit requests, register targets, or inspect reconnaissance data. Binding strictly to `127.0.0.1` prevents unauthorized network access by default.

---

### Question 4: How does 12-Factor environment-based configuration improve both operational security and deployment flexibility?
**Answer:**
- **Separation of Config from Code (Factor III):** The Twelve-Factor App methodology mandates that anything that varies between deployments (database credentials, API keys, service endpoints) must be stored in the environment, not in code or version control.
- **Secret Leakage Prevention:** Committing credentials or connection strings to Git risks exposure in repositories, CI logs, or public mirrors. Environment-based config allows sensitive secrets to be injected dynamically at runtime via Docker secrets, Kubernetes secrets, or `.env` files that remain strictly `.gitignore`d.
- **Write-Once, Deploy-Anywhere (Portability):** A single, immutable container image artifact can be built once and deployed across development, automated testing, staging, and production environments without rebuilding or modifying code—only the environment variables passed to the container change.

---

### Question 5: Why is a database-backed background job queue necessary for long-running scanner tasks instead of executing them synchronously inside HTTP request handlers?
**Answer:**
- **HTTP Timeout & Thread Starvation:** Attack surface reconnaissance operations (DNS resolution across hundreds of subdomains, TCP port scans, TLS handshakes, HTTP probing) take anywhere from 10 seconds to several minutes to complete. If executed synchronously inside an HTTP request handler:
  1. Reverse proxies (Nginx, Cloudflare, AWS ALB) and client browsers will timeout after 30–60 seconds, severing the HTTP connection.
  2. Web server worker threads (uvicorn/gunicorn) remain blocked waiting for network I/O, rapidly exhausting the server's connection pool and causing denial of service for other users.
- **Resilience & State Recovery:** A database-backed job queue records each scan run with a state lifecycle (`queued` $\to$ `running` $\to$ `succeeded` / `failed`). If the application container crashes, restarts, or scales, uncompleted jobs remain safely persisted in the database and can be retried or resumed without losing scan context or customer requests.

---

# Part 5: v2.2 — Scan Jobs with a Robust Job Lifecycle

## 1. Plain-English Code Walkthrough

### `src/asm/db/models.py` (Lifecycle & Stage Tracking Extensions)
- **`ScanRun` Extensions:** Added distributed leasing and lifecycle fields:
  - `claim_token` (`UUID`): A unique fencing token generated on every claim to prevent zombie workers from corrupting state.
  - `claimed_by` and `claimed_at`: Identifies the active worker node (`hostname:pid:uuid`).
  - `lease_expires_at`: Heartbeat expiration timestamp (calculated with DB clock `now()`).
  - `attempts` and `max_attempts`: Retry budget counter (defaults to 3).
  - `next_attempt_at`: Exponential backoff schedule for retries.
  - `idempotency_key`: Deduplication token scoped to the domain.
  - Partial Unique Indexes:
    - `uq_scan_runs_active_domain`: Guarantees at most one active (`queued` or `running`) scan per domain.
    - `uq_scan_runs_domain_idempotency`: Prevents duplicate runs for identical idempotency keys.
    - `ix_scan_runs_claimable`: Indexes eligible queued jobs for fast `SKIP LOCKED` querying.
- **`ScanStage` (`scan_stages` table):** Records per-stage progress (`discover`, `probe`, `portscan`, `inspect`, `score`), status (`pending`, `running`, `succeeded`, `failed`, `skipped`), timestamps, duration in milliseconds, and error messages.
- **`ScanResult` Constraint:** Added unique constraint `(scan_run_id, stage)` to guarantee idempotent artifact writes.

### `migrations/versions/0002_scan_jobs_lifecycle.py`
- Alembic migration script supporting bidirectional `upgrade()` and `downgrade()` for all new columns, tables, and partial indexes.

### `src/asm/worker/exceptions.py`
- **`SecurityGateError`:** Raised when domain authorization is missing or revoked. This is a terminal error; the run fails permanently and is never retried.
- **`LostLeaseError`:** Raised when a worker detects its lease was reclaimed by another worker or a write returned 0 affected rows.
- **`EXPECTED_SCANNER_ERRORS`:** Explicit tuple `(CrtshError, DomainValidationError, ReportValidationError, SecurityGateError)`. Known scanner exceptions fail only that stage; anything else is an unexpected worker exception that triggers retry backoff.

### `src/asm/worker/runner.py`
- **`IScannerRunner` Protocol:** Defines injectable runner methods for all 5 pipeline stages.
- **`DirectScannerRunner`:** Production implementation invoking scanner core functions (`discovery`, `prober`, `portscan`, `headers_inspect`, `scoring`) directly in Python without shelling out to CLI or writing files to disk.

### `src/asm/worker/worker.py`
- **`ASMWorker`:** The background daemon engine claiming and executing scan runs:
  - Claims jobs atomically with `FOR UPDATE SKIP LOCKED`.
  - Runs periodic stale lease recovery and poison pill termination at the start of every poll cycle.
  - Dedicated `HeartbeatThread` runs in its own thread with an independent database session, renewing `lease_expires_at` every 15s.
  - Fenced writes: Every database write begins with `SELECT 1 FROM scan_runs WHERE id = :id AND status = 'running' AND claim_token = :token FOR SHARE` and verifies affected rowcounts.
  - Resets stuck `running` stages back to `pending` on resume and logs previous crash errors.
  - Catches `SIGTERM` signals between stages and performs graceful job release without penalizing retry attempts.

### `src/asm/api/routes.py` & `src/asm/api/schemas.py`
- **`POST /domains/{id}/scans`:** Order enforced: (a) 404 if no domain, (b) 422 if unauthorized, (c) 200 with existing run if idempotency key matches, (d) 202 on insert, or 409 with `active_scan_id` if blocked by active scan constraint.
- **`GET /scans/{scan_id}`:** Returns `ScanRunDetail` with per-stage progress.
- **`GET /domains/{id}/scans`:** Historical scan run listing with status filtering and pagination.
- **`GET /scans/{scan_id}/results/{stage}`:** Returns raw JSON stage artifact report.

---

## 2. Five v2.2 Interview Questions & Answers

### Question 1: How does PostgreSQL `FOR UPDATE SKIP LOCKED` work, and why is it superior to naive queue polling or premature Celery/Redis adoption?
**Answer:**
- **Mechanism:** When a worker executes `SELECT id FROM scan_runs WHERE status = 'queued' ORDER BY created_at ASC FOR UPDATE SKIP LOCKED LIMIT 1`, PostgreSQL inspects the candidate rows. If another concurrent worker already holds a row lock on the oldest record, Postgres skips that locked row immediately without blocking and locks the next available unlocked row.
- **Elimination of Lock Contention:** Standard `FOR UPDATE` causes all concurrent workers to block and serialize behind the first worker, creating lock wait queues and potential deadlocks. `SKIP LOCKED` gives each worker a distinct job immediately.
- **Architectural Superiority for Single-Node / Early SaaS:**
  1. **Transactional Integrity:** Enqueuing, job state transitions, and result persistence happen in the same ACID database. There is zero risk of dual-write discrepancies (e.g. state committed to Postgres but Redis job lost on broker crash).
  2. **No Extra Infrastructure:** Adding Redis, Celery, or RabbitMQ introduces extra network hops, connection management, serialization overhead, and another failure domain to monitor and secure. PostgreSQL handles thousands of jobs per second with `SKIP LOCKED` before dedicated queues are needed.

---

### Question 2: What is the "Zombie Worker" problem, and how do fencing tokens (`claim_token`) prevent database corruption?
**Answer:**
- **The Zombie Worker Scenario:** Suppose Worker A claims a job with a 60-second lease. Due to a prolonged garbage-collection pause, heavy CPU thrashing, or a transient network partition, Worker A becomes unresponsive. Its lease expires. The recovery loop detects the expired lease and re-queues the run. Worker B claims the run and begins executing Stage 2. Suddenly, Worker A wakes back up ("zombie") and attempts to write its delayed Stage 1 results, potentially overwriting Worker B's fresh data.
- **Fencing Token Solution:**
  1. On every claim, a fresh `claim_token` (UUID) is generated and saved on `scan_runs`.
  2. Every write transaction (stage start, result write, status update) must begin with:
     ```sql
     SELECT 1 FROM scan_runs
     WHERE id = :id AND status = 'running' AND claim_token = :token
     FOR SHARE;
     ```
  3. Because Worker B received a new `claim_token`, Worker A's fencing check returns 0 rows. Worker A detects it has lost the lease, raises `LostLeaseError`, and immediately aborts execution without modifying the database.

---

### Question 3: Why use a partial unique index (`WHERE status IN ('queued', 'running')`) rather than an application-level check-then-insert query?
**Answer:**
- **Check-then-Insert Race Condition:** In an application-level check (`if existing_scan: return 409; else: insert()`), two concurrent HTTP requests arriving at the exact same millisecond can both query the database simultaneously, both find no active scan, and both proceed to insert a new scan run.
- **Database-Level Partial Unique Index:**
  ```sql
  CREATE UNIQUE INDEX uq_scan_runs_active_domain ON scan_runs (domain_id)
  WHERE status IN ('queued', 'running');
  ```
  PostgreSQL enforces uniqueness at the storage engine level. When two concurrent transactions attempt to insert active runs for the same `domain_id`, PostgreSQL forces one to succeed and instantly aborts the other with a `UniqueViolation` error. The API catches this error and returns `409 Conflict` containing the active scan ID, eliminating race conditions entirely.

---

### Question 4: Why must network I/O never be performed inside an open database transaction, and why are fenced writes structured as short transactions?
**Answer:**
- **Connection Pool Exhaustion:** Database connection pools are finite (typically 10–50 connections). If a worker begins a transaction (`session.begin()`) and then executes an HTTP probe or port scan taking 10 to 30 seconds, that database connection remains idle and held for the entire duration of the network call. Under slight load, all database connections become exhausted, starving API requests and health checks.
- **Row Lock Accumulation:** Open transactions hold locks on affected rows. If locks remain open during slow network calls, other workers or API queries trying to read or update those records block indefinitely.
- **Short Transactions Pattern:**
  1. The worker opens a short transaction ($\approx 1\text{ms}$), checks the fence token via `FOR SHARE`, updates the stage status to `running`, and immediately commits and releases the DB connection.
  2. Network reconnaissance executes outside the database transaction.
  3. Once finished, another short transaction ($\approx 2\text{ms}$) opens, verifies the fence token, inserts the artifact into `scan_results`, marks the stage as `succeeded`, and immediately commits.

---

### Question 5: How does dynamic exponential backoff with jitter in SQL prevent the "thundering herd" problem during worker crash recovery?
**Answer:**
- **The Problem:** If a worker node crashes or network partition occurs while 20 scan jobs are running, their leases will all expire around the same time. If a recovery query resets all 20 jobs to `'queued'` simultaneously with zero delay, all available workers will pounce on those 20 jobs at the exact same moment. If the failure was caused by target rate-limiting (e.g. crt.sh returning HTTP 429), slamming the target immediately will cause all 20 retried jobs to fail again.
- **The Solution (Exponential Backoff with Jitter in SQL):**
  ```sql
  next_attempt_at = now() + (
      LEAST(120.0, 10.0 * POWER(2.0, GREATEST(0, attempts - 1)))
      + (random() * 5.0)
  ) * INTERVAL '1 second'
  ```
  1. **Exponential Scaling:** Each failed attempt doubles the delay ($10\text{s} \to 20\text{s} \to 40\text{s}$, capped at 120s), giving remote servers and network partitions time to recover.
  2. **Random Jitter ($0\text{s} \text{ to } 5\text{s}$):** Introduces randomization so that the 20 recovered jobs become eligible for claiming at staggered, smoothed intervals rather than all at once, preventing thundering-herd stampedes.




