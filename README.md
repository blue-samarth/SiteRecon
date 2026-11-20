# SiteRecon

A modular, **passive**, evidence-driven website reconnaissance CLI. Give it a domain and it collects public DNS, DNSSEC, network, HTTP, TLS, registration, public-resource and Certificate Transparency information. It can also crawl in-scope pages, query passive-DNS datasets and web archives, and confirm generated hostnames in DNS. It profiles technologies (540+ signatures), cookies, third-party services and the managed-cloud endpoints an application points at, audits on-page SEO across the pages it fetched, turns everything into normalized observations, interprets them in a separate analysis step, and writes JSON, Markdown and HTML reports. Scans are stored, so you can compare a target over time.

> **Authorized use only.** Scan only domains you own or are permitted to assess. SiteRecon makes ordinary DNS, HTTP and TLS requests and only sends GETs. It does no exploitation, directory guessing, port scanning, fuzzing or form submission, and it never executes downloaded content. Opt-in passive sources and web archives are queried *about* the target, never against it, and each one discloses the domain you are assessing to that provider — see **[docs/passive-discovery.md](docs/passive-discovery.md)**. `--permute-subdomains` is the one feature that generates names rather than reading them: it issues A/AAAA lookups only, is hard-capped, and reports a generated name solely when it resolves.

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
uv run siterecon scan example.com --subdomain-source keyless      # passive-DNS / URL-index sources
uv run siterecon scan example.com --permute-subdomains            # DNS-confirm generated names
uv run siterecon scan example.com --historical                    # archived URLs, params, old stack
uv run siterecon scan example.com --seo                           # on-page SEO audit, graded A-F
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
| `--modules`, `-m` | Comma-separated subset of `dns, dnssec, network, http, tls, whois, resources, crawler, html, javascript, technology, cookies, subdomains, third_party, render, vulnscan, historical, seo` | all |
| `--timeout` / `--retries` | Per-request timeout (s) / retries for transient failures | `10` / `2` |
| `--concurrency` | Maximum concurrent requests | `10` |
| `--subdomains/--no-subdomains` | Certificate Transparency discovery | on |
| `--probe-subdomains` | Also check HTTPS and TLS on discovered names that resolve to public addresses | off |
| `--max-subdomains` | Max discovered names to verify | `100` |
| `--subdomain-source` | Additional passive source: `otx`, `urlscan`, `commoncrawl`, `wayback`, `rapiddns`, `hackertarget`, `anubis`, `bufferover`, or `all` / `keyless` (repeatable). Each one discloses the target domain to that provider | none (CT only) |
| `--permute-subdomains` | Generate candidate hostnames from the discovered names and keep the ones that resolve (**DNS lookups only**, hard-capped, nothing is fetched) | off |
| `--max-permutations` | Cap on generated candidates resolved | `200` |
| `--historical` | Collect archived URLs (Wayback, Common Crawl, urlscan.io, OTX) and extract the historical endpoint, parameter and legacy-technology surface | off |
| `--historical-source` | Restrict `--historical` to these archives (repeatable) | all |
| `--max-historical-urls` | Per-source cap on archived URLs requested | `1000` |
| `--seo` | On-page SEO audit of the pages this scan fetches: indexability, metadata, content, internal links, sitemap coverage and delivery, scored A–F per area. Derived from pages already retrieved (no extra requests of its own), but **turns the crawler on**, since a site-wide audit needs more than one page | off |
| `--whois/--no-whois` | Domain registration lookup | on |
| `--crawl/--no-crawl` | Crawl in-scope pages (seeded with the start page and sitemap URLs). Off by default, except with `--seo`; `--no-crawl` overrides that | off |
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
reports/.cache/passive/              # cached passive-source results
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
| `technology` | **541 signatures** matched against headers, cookie names, generator, HTML, resource URLs, referenced domains, CSP and DNS CNAMEs — frontend and backend frameworks, languages, web/application servers, CMS and headless CMS, ecommerce, CDN and edge, analytics, monitoring/APM, marketing, support, payments, authentication, consent, search, media, UI libraries, icons and managed-cloud services. Each detection is graded *confirmed* (a high-strength signal, or two independent **non-weak** sources), *probable* (one medium signal, or several weak ones agreeing) or *possible* (only weak signals — CSP allow-listing, a DNS hint, or an implication). Weak signals never corroborate into *confirmed*: being permitted or delivered is not evidence of use. Versions are reported only when something **states** one — a banner, a generator tag, a versioned asset path, or an asset `?ver=` query (which recovers a CMS version the banner no longer discloses) — never inferred from a hash or a date. |
| `cookies` | Secure, HttpOnly, SameSite, Domain, Path, Expires, Max-Age and `__Host-`/`__Secure-` prefix validity for every cookie set by the fetched and crawled pages. **Values are never stored**; only their length is. |
| `subdomains` | CT names from **crt.sh and Cert Spotter**, plus (opt-in, `--subdomain-source`) **AlienVault OTX, urlscan.io, Common Crawl, Wayback, RapidDNS, HackerTarget, Anubis-DB and BufferOver**, merged and deduplicated with the source(s) of each name and a per-source outcome row. A source that fails falls back to fresh cached results (`cache:<source>`); one that needs an absent API key is `skipped` with the reason; incomplete coverage is reported as a finding rather than presented as a complete list. With `--permute-subdomains`, candidate names built from the discovered labels plus a small fixed wordlist are **resolved in DNS only** and kept only when they resolve. Names are scope-filtered and checked in DNS (optionally HTTPS and TLS), then marked `historical`, `resolving`, `reachable` or `unverified`. |
| `historical` | Opt-in (`--historical`). Archived URLs from **Wayback, Common Crawl, urlscan.io and OTX**, merged and scope-filtered, mined for the historical **endpoint surface**, **query parameters** (names only — values are redacted; classified as credential / redirect / file / identifier), **technology hints** from paths and extensions, **sensitive-looking paths** and extension counts, each with its own first/last-seen window. Hints are annotated with whether the current scan still detects them, never merged into the current technology inventory. |
| `seo` | Opt-in (`--seo`). Re-reads the pages the `http` and `crawler` modules already fetched and records the on-page SEO facts of each: indexability (robots meta, `X-Robots-Tag`, robots.txt, canonical self/off-site), titles and descriptions with their lengths, viewport, `lang` and `hreflang`, heading outline and skipped levels, word count, images with no `alt` attribute, internal/external/nofollow links, and JSON-LD / microdata types. Across pages it computes duplicate titles, descriptions and H1s (indexable pages only), the internal-link graph and its orphans, broken internal URLs, internal redirects, sitemap-vs-robots-vs-crawl coverage, apex/`www` canonicalization and the delivery summary (compression, HTTP version, response-time distribution, HTML weight). **Sends no requests and queries no search engine**: it reports what the site *declares* about indexing, never what is indexed, and its timings are server response times, not Core Web Vitals. |
| `third_party` | External services from page and crawl resources, CSP, off-scope redirects, MX/NS/SPF/TXT records and certificate issuers. Also builds the **managed-cloud inventory**: object-storage buckets, serverless functions, managed databases, edge workers and hosting targets the client references (S3, Azure Blob, GCS, Firebase, Supabase, R2, Workers, Lambda URLs, API Gateway, Atlas, …), with the resource identifier, region and how it was referenced. References only — nothing is requested. |

### Observations, findings and history

- **Observations** (`report.observations`): every module's data is normalized into stable records of `{id, module, target, type, key, value, source, timestamp, confidence, status}`. Volatile values such as timings and TTLs are left out, so comparisons stay meaningful.
- **Findings**: the analysis engine (no network I/O) produces findings with severity, confidence, evidence, a **recommendation**, **limitations** and **`evidence_refs`** (the IDs of the supporting observations). Missing configuration is informational. Severity rises only for demonstrated problems, such as an expired certificate, a DS record without a DNSKEY, or a password form served over HTTP.
- **History**: each scan gets a `scan_id` and is stored. The next scan of the same target is compared with it, and each difference is classified as `added`, `removed`, `modified`, `unchanged` or `unknown`. A difference is only called added or removed when the relevant module fully succeeded in both scans. Otherwise it's `unknown`, so data missing from a failed module never looks like a removal.

Infrastructure indicators are not treated as proof of where an application is hosted. ASN and RDAP describe who the address space is allocated to, and DNS CNAMEs and HTTP headers describe the delivery provider; the origin may be elsewhere.

The same rule governs the newer passive surface. A **referenced** cloud resource is not an exposed one: a bucket URL in a bundle proves the application points at that bucket, not that it is listable, and every cloud finding carries that limitation and points at `siterecon active` for confirmation. An **archived** URL is evidence of the past, not of what is reachable now, and its technology hints describe the stack that served it at the time — which is why they are reported separately from the current technology inventory rather than merged into it. A name from a **passive dataset** is a lead that SiteRecon then verifies in DNS itself. Discovery is never presented as exhaustive: when a source fails, is served from cache or is skipped, that is reported as a finding instead of being silently absorbed into a shorter list.

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
2. Network, HTTP, TLS, DNSSEC, registration, subdomains (CT + passive sources + optional permutation) and historical URLs, concurrently with bounded concurrency.
3. HTML, then public resources, then the crawler, then JS/CSS asset analysis.
4. Technology, cookies, third parties, the managed-cloud inventory and the SEO audit (all derived from the data already collected). Historical technology hints are then annotated with whether the current scan still detects them.
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

- **Scope**: the target and its subdomains. Each redirect hop is re-validated, and off-scope redirects are recorded but not followed. Third-party hosts are never actively probed. CT, RDAP, WHOIS, IANA, passive-discovery and archive services are each reached through a separate client allow-listed to exactly that provider's hostnames, never the target's scope and never private networks. Names and URLs outside the target's scope are dropped before anything is cached, and the dropped count is reported.
- **SSRF**: before each connection, every resolved address must be globally routable. This blocks loopback, RFC 1918, CGNAT, link-local / `169.254.169.254`, ULA and multicast. TLS and WHOIS connect to the address that passed the check. Known limitation: for HTTP, the address check and httpx resolve the hostname separately, so a DNS-rebinding race is theoretically possible.
- **Resource limits**: timeouts, bounded concurrency, crawl depth, page and delay limits, and response-size caps (5 MB pages, 25 MB CT, 256 KB WHOIS). Gzip sitemaps are capped at 10 MB decompressed. Only transient failures are retried, with backoff.
- **Data handling**: downloaded content is never executed. Cookie values are never stored. Sensitive-looking URL query values and userinfo are redacted — including in **archived** URLs, where a real token can sit in the query string, so only parameter names are kept. Registrant contacts are not collected. Provider API keys are read from the environment, sent only to the issuing provider, and never logged or written to a report. Scan IDs and hostnames are validated before they're used in file paths.

## Passive data enrichment

Four capabilities widen what a passive scan sees without making it less passive: additional **passive
subdomain sources**, **controlled permutation**, **historical URLs** from web archives, and the
**managed-cloud inventory**. Three of the four are opt-in because each one discloses the target domain to
another provider; the cloud inventory is derived from evidence already collected and needs no extra traffic.

```bash
siterecon scan example.com --subdomain-source keyless           # every source needing no API key
siterecon scan example.com --subdomain-source otx --subdomain-source urlscan
siterecon scan example.com --permute-subdomains --max-permutations 300
siterecon scan example.com --historical --max-historical-urls 5000
```

`siterecon active --bypass-sec` turns all of them on for its preliminary scan, with widened caps, since
that mode is a local run on property you own.

See **[docs/passive-discovery.md](docs/passive-discovery.md)** for every source, what each kind of hit is
worth, the permutation limits, what the archives are mined for, the cloud resource classes and their
severities, and how all of it reaches observations, findings and the scan diff.

## SEO audit (`--seo`)

`--seo` adds a 39-check on-page audit over the pages the scan already fetched, scored A–F per area
(indexability, metadata, content, crawlability, delivery) and overall. It sends no requests of its own and
asks no search engine anything, so it reports what the site **declares** about indexing — robots meta,
`X-Robots-Tag`, robots.txt, `rel=canonical` — never what is actually indexed, and its timings are server
response times rather than Core Web Vitals.

```bash
siterecon scan example.com --seo                              # audits the site (turns the crawler on)
siterecon scan example.com --seo --depth 3 --max-pages 100    # wider coverage
siterecon scan example.com --seo --no-crawl                   # landing page only
```

Three properties keep the number honest. A check with no evidence to evaluate is **`not_checked`** — it
produces no finding, deducts nothing, and its area is left out of the average rather than credited as
perfect, so a one-page audit cannot read as a clean one. Deductions are **proportional**: one bad page in
forty costs a fortieth of the check's weight, a site-wide template bug costs all of it. And the audit's
own coverage is reported as a finding (`seo.coverage_single_page`, `seo.coverage_truncated`) whenever it
saw one page or stopped at the crawl limit.

SEO findings never move the **security** grade, and security findings never move the SEO grade: the two
are scored from separate tables, because a missing meta description is not a weaker security posture.

See **[docs/seo.md](docs/seo.md)** for the full check table with weights and thresholds, the scoring
formula, which checks skip the landing page and why, what reaches the scan-to-scan diff, and how to add a
check.

## Active testing (`siterecon active`)

A separate, opt-in command for **authorized** active testing, gated behind an operator-authored
authorization file (never a flag). Its `--bypass-sec` mode additionally runs the preliminary passive scan
with every opt-in discovery capability enabled. It runs five checks — Supabase row-level-security probing, function-URL reachability, client-IP-header
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

## Documentation

| Document | Covers |
|---|---|
| [docs/passive-discovery.md](docs/passive-discovery.md) | Passive subdomain sources, controlled permutation, historical URLs, managed-cloud inventory |
| [docs/seo.md](docs/seo.md) | The `--seo` audit: coverage model, all 39 checks and their thresholds, scoring, what it cannot answer |
| [docs/observations.md](docs/observations.md) | The observation model, provenance, finding lifecycle, regression detection |
| [docs/active.md](docs/active.md) | The `active` command: authorization file, each check, safety rails |
| [docs/intelligence.md](docs/intelligence.md) | External-intelligence providers (Wayback summary, Shodan InternetDB) |
| [docs/hosting-location.md](docs/hosting-location.md) | Hosting-location estimation and the optional offline geo database |

## Tests

```bash
uv run pytest
```

There are 671 tests. DNS and HTTP are mocked (a fake resolver and `respx`); TLS and WHOIS run against local servers; **no test contacts a real third-party service**. They cover parsers, provider failures, caching, scope and redirect enforcement, robots rules, oversized responses, partial module failures, history comparison and report escaping, plus the active command, its authorization gate, the five checks and budget/rate enforcement.

For the SEO audit specifically: per-page extraction (canonical self/off-site, robots directives, heading
skips, word counts that ignore scripts and styles, `alt=""` as valid markup, JSON-LD in `<body>` and in
`@graph`); the site-wide aggregates (duplicate groups over indexable pages only, the inbound-link graph,
broken links, redirects, sitemap coverage, apex/`www` split); that missing evidence is `not_checked`
rather than a pass and that its area is excluded from the average; that deductions are proportional to the
share of pages affected; that the landing page is never reported twice for the same problem; that a clean
site fails no check and grades A+; that every check in the table has a recommendation; that SEO findings
leave the security grade untouched; that `--seo` turns the crawler on and `--no-crawl` overrides it; and
that volatile measurements stay out of the scan-to-scan diff.

For the passive-enrichment surface specifically: every passive source's parsing and failure mode, credential gating, cache fallback and scope filtering; that permutation stays capped, in-scope, DNS-only and discards names that do not resolve; archive merging, query-value redaction and parameter/technology/sensitive-path extraction; cloud signature matching for both bucket addressing styles and same-host role separation; that no cloud or historical finding claims an exposure it did not test; that the expanded signature set produces no detections on a plain page and that weak signals never corroborate into *confirmed*; and that all of the new data reaches the scan-to-scan diff, where a skipped module still yields `unknown` rather than `removed`.
