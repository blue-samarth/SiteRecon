# SiteRecon

A modular, **passive**, evidence-driven website reconnaissance CLI. Give it a domain and it collects public DNS, DNSSEC, network, HTTP, TLS, registration, public-resource and Certificate Transparency information. It can also crawl in-scope pages. It profiles technologies, cookies and third-party services, turns everything into normalized observations, interprets them in a separate analysis step, and writes JSON, Markdown and HTML reports. Scans are stored, so you can compare a target over time.

> **Authorized use only.** Scan only domains you own or are permitted to assess. SiteRecon makes ordinary DNS, HTTP and TLS requests and only sends GETs. It does no exploitation, brute-forcing, directory guessing, port scanning, fuzzing or form submission, and it never executes downloaded content.

## Install

```bash
uv sync
```

## Usage

```bash
uv run siterecon example.com                        # or: uv run python recon.py example.com
uv run siterecon scan https://example.com/any/path  # URLs are normalized to a hostname
uv run siterecon scan example.com --modules dns,http,tls
uv run siterecon scan example.com --crawl --depth 2 --max-pages 50
uv run siterecon scan example.com --format json --output reports/

uv run siterecon history example.com                # list stored scans
uv run siterecon compare <previous-scan-id> <current-scan-id>
uv run siterecon compare --target example.com       # the two latest scans
```

A bare domain is treated as `scan`, so the v0.1 form `python recon.py example.com` still works.

### `scan` options

| Option | Description | Default |
|---|---|---|
| `--format`, `-f` | `json`, `markdown`, `html`, `both` (json + markdown), `all` | `all` |
| `--output`, `-o` | Report directory | `reports/` |
| `--modules`, `-m` | Comma-separated subset of `dns, dnssec, network, http, tls, whois, resources, crawler, html, javascript, technology, cookies, subdomains, third_party` | all |
| `--timeout` / `--retries` | Per-request timeout (s) / retries for transient failures | `10` / `2` |
| `--concurrency` | Maximum concurrent requests | `10` |
| `--subdomains/--no-subdomains` | Certificate Transparency discovery | on |
| `--probe-subdomains` | Also check HTTPS and TLS on discovered names that resolve to public addresses | off |
| `--max-subdomains` | Max discovered names to verify | `100` |
| `--whois/--no-whois` | Domain registration lookup | on |
| `--crawl` | Crawl in-scope pages (seeded with the start page and sitemap URLs) | off |
| `--depth` / `--max-pages` | Crawl depth / page limit | `1` / `25` |
| `--crawl-delay` | Delay between crawl requests in seconds (robots.txt `Crawl-delay` can raise it, up to 5 s) | `0.25` |
| `--ignore-robots` | Crawl paths disallowed by robots.txt (only with explicit authorization) | off |
| `--max-assets` | Maximum JS/CSS assets to download and analyze (2 MB each, 20 MB total) | `30` |
| `--asset-host` | External host allowed for asset downloads, e.g. your own CDN (repeatable) | none |
| `--history/--no-history` | Store the scan and compare it with the previous one | on |
| `--allow-private-networks` | Allow private/loopback destinations (authorized internal assessments only) | off |
| `--verbose`, `-v` | Detailed logs | off |

Exit codes: `0` success (including partial results), `1` every module that ran failed, `2` invalid input.

## Output

```text
reports/<hostname>/
├── report.json / report.md / report.html   # includes the JS/CSS asset section (endpoints, public config, redacted secrets)
├── changes.json / changes.md        # differences from the previous scan (when one exists)
├── raw/<module>.json                # one file per module result
├── history/<scan_id>.json           # every stored scan
└── comparisons/<prev>__<curr>/      # output of `siterecon compare`
reports/.cache/ct/                   # cached CT provider results
```

Every module reports a `status`: `success`, `partial` (some checks failed), `failed` (the module raised) or `skipped` (not selected, disabled, or a prerequisite is missing; the `note` says which). One module failing never stops the scan. Errors are listed in `errors`, so missing data is never mistaken for a negative result.

## What is collected

| Module | Collects |
|---|---|
| `dns` | A, AAAA, MX, NS, TXT, SOA, CAA, CNAME, `www` CNAME, DMARC, with TTL, timing and status per query. SPF is parsed, including parse errors, and evaluated with RFC 7208 lookup counting through `include`/`redirect` (10 lookups, 2 void). DMARC: `p`, `sp`, `pct`, `adkim`, `aspf`, `fo`, `rua`, `ruf`. DKIM: 43 common selectors, with key type and size and revoked keys; every selector checked is listed. CAA: the effective policy is found by climbing parent names (RFC 8659). |
| `dnssec` | DS, DNSKEY and the resolver's AD flag together, never one record alone. Status is `signed_validated`, `signed_unvalidated`, `unsigned`, `island`, `broken` or `unknown`. |
| `network` | Per unique IP: PTR, ASN (Team Cymru DNS), RDAP allocation |
| `http` | `http://`, `https://`, `https://www.`: redirect chain, headers, security headers (HSTS, CSP, XCTO, XFO, Referrer-Policy, Permissions-Policy, COOP, CORP, COEP), Cache-Control, CORS headers. `Set-Cookie` values are redacted. |
| `tls` | Version, cipher, chain verification, SAN hostname match, validity, key and signature, over non-blocking asyncio connections |
| `whois` | RDAP (IANA bootstrap) with an async port-43 WHOIS fallback. Registrar, dates, status, nameservers, DNSSEC; registrant contacts are never kept. |
| `resources` | `robots.txt`, sitemaps (from robots.txt or `/sitemap.xml`, including indexes and gzip), `security.txt` (RFC 9116, `.well-known` then legacy path), web manifest, favicon (SHA-256), `humans.txt`. Each is fetched independently, and HTML fallback pages count as soft 404s rather than resources. |
| `crawler` | Breadth-first crawl of in-scope pages within depth, page and delay limits, following robots.txt `Allow`/`Disallow` (`*`, `$`). Per page: status, title, query parameter names, security headers, resources. Every page and discovered URL keeps its source page. Forms are recorded (method, action, input names) but never submitted. |
| `javascript` | In-scope JS/CSS bundles referenced by the landing page and crawled pages, plus hosts explicitly allowed with `--asset-host`. Bundles are downloaded with size caps and **scanned as text, never executed**. Records: library markers and versions; the **service hostnames** and **API endpoints** each bundle references (query values redacted); **public client-configuration** blocks such as Firebase and Supabase (identifier fields shown, key/token fields redacted); **Subresource Integrity verification** against the downloaded bytes; **public source maps**, including the list of original source files they expose (paths only — `sourcesContent` is discarded); and values matching **private-credential patterns** (AWS/Stripe/GitHub keys, private-key blocks, service-role JWTs, …). Feeds technology detection and the third-party inventory. |
| `html` | Landing-page metadata, resources, external domains, JSON-LD, verification tokens. Commented-out URLs are listed separately. |
| `technology` | 87 signatures matched against headers, cookie names, generator, HTML, resource URLs, referenced domains, CSP and DNS CNAMEs. Each detection is graded *confirmed* (strong evidence or two independent sources), *probable* (one medium signal) or *possible* (only weak signals such as a DNS hint, CSP allow-listing or being implied by another technology). Versions are reported only when a signature captures one. |
| `cookies` | Secure, HttpOnly, SameSite, Domain, Path, Expires, Max-Age and `__Host-`/`__Secure-` prefix validity for every cookie set by the fetched and crawled pages. **Values are never stored**; only their length is. |
| `subdomains` | CT names from **crt.sh and Cert Spotter**, merged and deduplicated, with the source(s) of each name. A provider that fails falls back to fresh cached results (`cache:<provider>`), and when providers fail the module reports `partial` instead of failing. Names are scope-filtered and checked in DNS (optionally HTTPS and TLS), then marked `historical`, `resolving`, `reachable` or `unverified`. |
| `third_party` | External services from page and crawl resources, CSP, off-scope redirects, MX/NS/SPF/TXT records and certificate issuers |

### Observations, findings and history

- **Observations** (`report.observations`): every module's data is normalized into stable records of `{id, module, target, type, key, value, source, timestamp, confidence, status}`. Volatile values such as timings and TTLs are left out, so comparisons stay meaningful.
- **Findings**: the analysis engine (no network I/O) produces findings with severity, confidence, evidence, a **recommendation**, **limitations** and **`evidence_refs`** (the IDs of the supporting observations). Missing configuration is informational. Severity rises only for demonstrated problems, such as an expired certificate, a DS record without a DNSKEY, or a password form served over HTTP.
- **History**: each scan gets a `scan_id` and is stored. The next scan of the same target is compared with it, and each difference is classified as `added`, `removed`, `modified`, `unchanged` or `unknown`. A difference is only called added or removed when the relevant module fully succeeded in both scans. Otherwise it's `unknown`, so data missing from a failed module never looks like a removal.

Infrastructure indicators are not treated as proof of where an application is hosted. ASN and RDAP describe who the address space is allocated to, and DNS CNAMEs and HTTP headers describe the delivery provider; the origin may be elsewhere.

## Architecture

```text
recon.py → recon/cli.py (scan / history / compare, TerminalSummary)
             └── ScanOrchestrator ── modules/    Collector subclasses (collect evidence only)
                                  ├─ analysis/   ObservationBuilder, AnalysisEngine, FindingCollector,
                                  │              InfrastructureInference, ScanComparator, signatures (no I/O)
                                  └─ ScanHistory ── storage/   ScanStore, JsonScanStore
             reporting/  JsonReportWriter, MarkdownReportWriter, HtmlReportWriter, ComparisonReportWriter
             models/     Pydantic schemas;  utils/  Scope, SafeHttpClient, DnsClient, validators, redaction
```

Pipeline order:

1. DNS.
2. Network, HTTP, TLS, DNSSEC, registration and subdomains, concurrently with bounded concurrency.
3. HTML, then public resources, then the crawler, then JS/CSS asset analysis.
4. Technology, cookies and third parties (derived from the data already collected).
5. Observations, then the analysis engine.
6. History, then the reports.

```python
import asyncio
from pathlib import Path
from recon.config import Config
from recon.orchestrator import ScanHistory, ScanOrchestrator
from recon.reporting import JsonReportWriter
from recon.storage import JsonScanStore

report = asyncio.run(ScanOrchestrator(Config(target_input="example.com", hostname="example.com", crawl=True)).run())
ScanHistory(JsonScanStore(Path("reports"))).record(report)      # sets report.comparison if a previous scan exists
JsonReportWriter(report).write(Path("reports/example.com"))
```

## HTML report

`report.html` is a single self-contained file. It shows every section, plus collapsible raw JSON per module, a severity filter for findings, and light and dark themes. Every value is HTML-escaped. A Content-Security-Policy blocks scripts and external resources, and discovered URLs appear as text, so opening the report never contacts the scanned site.

## Safety controls

- **Scope**: the target and its subdomains. Each redirect hop is re-validated, and off-scope redirects are recorded but not followed. Third-party hosts are never actively probed. CT, RDAP, WHOIS and IANA services are reached through clients that are allow-listed to those hosts.
- **SSRF**: before each connection, every resolved address must be globally routable. This blocks loopback, RFC 1918, CGNAT, link-local / `169.254.169.254`, ULA and multicast. TLS and WHOIS connect to the address that passed the check. Known limitation: for HTTP, the address check and httpx resolve the hostname separately, so a DNS-rebinding race is theoretically possible.
- **Resource limits**: timeouts, bounded concurrency, crawl depth, page and delay limits, and response-size caps (5 MB pages, 25 MB CT, 256 KB WHOIS). Gzip sitemaps are capped at 10 MB decompressed. Only transient failures are retried, with backoff.
- **Data handling**: downloaded content is never executed. Cookie values are never stored. Sensitive-looking URL query values and userinfo are redacted. Registrant contacts are not collected. Scan IDs and hostnames are validated before they're used in file paths.

## Active testing (`siterecon active`)

A separate, opt-in command for **authorized** active testing, gated behind an operator-authored
authorization file (never a flag). It runs five checks — Supabase row-level-security probing, function-URL reachability, client-IP-header
trust testing, email-endpoint rate-limit probing, and per-version TLS enumeration — each only when enabled
and configured, under a central request budget and rate limit, with a full audit log. The passive `scan`
command is unaffected and never triggers active testing. See **[docs/active.md](docs/active.md)** for the
authorization file format, each check's behavior and budget, and the safety rails. A template lives at
`examples/authorization.example.yaml`.

```bash
siterecon active example.com --authorization auth.yaml --dry-run   # resolve the plan, send nothing
siterecon active example.com --authorization auth.yaml             # run enabled checks
```

## Secret and credential handling

The `javascript` module exists to help an operator **find and remediate** exposed secrets — not to harvest them. Its controls:

- **Raw secret values are never stored.** A suspected private credential is kept only as its type, location, an optional context key, a short prefix hint and a SHA-256 fingerprint (via `redact_secret`). The raw value appears in no report, observation, log or history file. Tests assert this for JSON, Markdown and HTML output.
- **Discovered credentials are never used.** Nothing is sent to the services the keys belong to.
- **Public identifiers are not flagged as secrets.** Stripe publishable keys (`pk_live_`), analytics IDs (`G-`, `GTM-`, `UA-`), Firebase `apiKey` and **Supabase anon JWTs** are classified as public. A Supabase **`service_role`** JWT in client code *is* flagged (high), because it bypasses row-level security.
- **Public client configuration is inventoried, not exposed.** Firebase/Supabase config blocks are shown with their identifier fields (projectId, URL) and their key/token fields redacted.
- **Endpoint paths are an inventory, not a route map of keys.** Query values are redacted and documentation/namespace URLs are filtered out.

Detection is heuristic, so every credential finding is marked as needing manual confirmation, and external assets are downloaded only from the target's own hosts plus any you allow with `--asset-host`.

- **Subresource Integrity** is hash-verified (SHA-256/384/512) against the bytes actually served, for every asset the scan downloaded. A mismatch is reported as a medium finding. For off-scope third-party assets that are not downloaded, only the presence of the attribute is reported.
- **Registrable domains are exact**, not approximated: SiteRecon bundles a Public Suffix List snapshot (`recon/data/public_suffix_list.dat`) and implements the publicsuffix.org matching algorithm, including wildcard and exception rules. ICANN rules are used by default so the result is the name actually registered with a registry (what RDAP/WHOIS expect); the private section can be enabled for grouping delegated namespaces like `github.io`. Refresh the snapshot with `curl -o recon/data/public_suffix_list.dat https://publicsuffix.org/list/public_suffix_list.dat`.

## Tests

```bash
uv run pytest
```

There are 258 tests (including the active command, its authorization gate, the five checks, and budget/rate enforcement). DNS and HTTP are mocked (a fake resolver and `respx`). TLS and WHOIS run against local servers. The tests cover parsers, provider failures, caching, scope and redirect enforcement, robots rules, oversized responses, partial module failures, history comparison and report escaping.
