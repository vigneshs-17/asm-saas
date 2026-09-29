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
