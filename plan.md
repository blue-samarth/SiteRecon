# siterecon — Plan & Roadmap

SiteRecon is growing from a passive website-reconnaissance CLI into an external
attack-surface intelligence platform. This file holds the overall roadmap
(below) and the original **Phase 3** active-module design (the rest of the
document, kept as the design-of-record for that phase).

## Roadmap & current status

Phases 1–5 reflect work that has shipped; the status column is reconstructed
from the actual codebase and git history, not a separate tracker. Phase 6 is
the next, not-yet-started frontier.

| Phase | Theme | Key capabilities | Status |
|------|-------|------------------|--------|
| **1** | Passive recon & reporting | 14 passive modules (DNS, network, HTTP, TLS, WHOIS, HTML, tech, subdomains, third-party, JS, crawler, resources, DNSSEC, email); JSON / Markdown / HTML writers; SSRF-guarded client | ✅ shipped |
| **2** | Observation & provenance model | `Observation`/`Finding` with provenance, freshness and lifecycle state; scan history + `ScanComparator`; schema versioning | ✅ shipped (schema **2.2**) |
| **3** | Active-testing framework & core checks | Authorization gate (scope, window, rate/budget), `ActiveContext`, check registry; `backend_read_access` (ex-`supabase_rls`), `function_url_reachability`, `client_ip_header_trust`, `email_endpoint_rate_limit`, `tls_protocol_enum` | ✅ shipped (PR #1) |
| **4** | External intelligence | Keyless providers (Wayback, Shodan InternetDB); hosting/geolocation inference; provider-aware freshness | ✅ shipped |
| **5** | Active network recon, auto-discovery & regression | `port_scan`, `traceroute`; `--bypass-sec` + auto-discovery of effective authorization; cross-scan `FindingDelta` and `regression.*` findings; cross-module correlation; confidence calibration; CI gates (`--fail-on`, `--fail-on-new`) | ✅ shipped (PR #2) **← current** |
| **5.5** | Passive data enrichment | Passive subdomain sources (OTX, urlscan, Common Crawl, Wayback, RapidDNS, HackerTarget, Anubis, BufferOver) with per-source outcomes and caching; controlled DNS-confirmed permutation; historical-URL module (archived endpoints, parameters, legacy-stack hints); 541 technology signatures with weak-source-aware grading and `?ver=` version recovery; managed-cloud inventory and findings | ✅ shipped (schema **2.4**) |
| **5.6** | On-page SEO audit | `seo` module deriving per-page SEO facts from pages already fetched (indexability, metadata, heading outline, word count, alt coverage, link graph, structured data); site-wide aggregates (duplicate titles/descriptions/H1s, orphans, broken internal links, redirects, sitemap-vs-robots-vs-crawl coverage, apex/www canonicalization, delivery); a 39-entry declarative check table driving both findings and a separate A–F SEO grade with `not_checked` states and proportional deductions | ✅ shipped (schema **2.5**) |
| **6** | Dynamic rendering & deep testing | Headless-browser rendering (Playwright) to capture runtime DOM/endpoints and close the SPA gap; authenticated/session testing; business-logic probing | ⛔ not started |

**Where we are:** Phase 5 is complete (merged as PR #2), followed by a code-review
pass (regression-handler fixes, finding-state re-derivation,
port-scan/traceroute/intel-budget hardening, ruff/mypy config) and then the
passive data-enrichment work in the table above (see
`docs/passive-discovery.md`, and **Follow-up for later phases** at the end of
this file). Phase 5.6 added the on-page SEO audit behind `--seo` (see
`docs/seo.md`): a second, deliberately separate graded dimension alongside the
security grade, derived from the pages a scan already fetched.
The Phase 6 frontier (Playwright-based dynamic rendering, authenticated and
business-logic testing) is designed-but-deferred; see **Deferred beyond v0.3.0**
at the end of this file. Today, JavaScript is analysed statically (parsed, never
executed), and `CollectionMethod.BROWSER_RENDER` is a reserved provenance value
with no collector behind it yet.

> The sections below are the original Phase 3 design for the `active` command.
> They are kept as the design-of-record; some names have since changed in the
> shipped code (`supabase_rls` → `backend_read_access`, the registry is no longer
> empty, network checks and `--bypass-sec` were added in Phase 5). See
> `docs/active.md` for the current, authoritative behaviour.

# siterecon v0.3.0 — Active Module Plan

This release adds the `active` command, its authorization gate, data models,
check registry, orchestrator, reporting, **and** the first set of concrete
checks (Supabase RLS probe, Lambda/function-URL reachability, rate-limit
probing on email-sending endpoints, TLS protocol/cipher enumeration). There
is no v0.3.1 scaffolding-only release; everything below ships together.

## Design goals

1. **Passive stays passive.** The existing `scan` command and its 14 modules
   never send anything beyond GET/HEAD/DNS/TLS-handshake probes. `active` is
   a separate command (`siterecon active <domain>`) that only runs when
   explicitly invoked.
2. **Authorization is a hard gate, not a flag.** `--allow-private-networks`
   today is just a flag; active testing needs more friction than that,
   because the blast radius is bigger (state-changing requests, rate-limit
   triggering, auth probing).
3. **Separate scope.** Active checks often need to reach hosts outside the
   primary domain (Supabase project ref, Lambda function URLs, etc.)
   discovered during a passive scan. That scope must be explicit and
   reviewable, never auto-expanded from recon findings without the operator
   confirming each host.
4. **Same reporting shape.** Active results should flow through the same
   `ModuleResult` / `Finding` / report-writer pipeline so HTML/Markdown/JSON
   output stays consistent, just with a new top-level section.

## New components

### 1. Authorization file (`recon/active/authorization.py`)

A signed-looking, operator-authored YAML/JSON file required to run `active`:

```yaml
target: example.io
authorized_by: "<name/role>"
authorized_on: "2026-11-08"
scope:
  hosts:
    - exampleref1234567890.supabase.co
    - example.lambda-url.ap-south-1.on.aws
  exclude_hosts: []        # explicit carve-outs even if discovered
checks_enabled: []         # populated in a later release; empty by default in v0.3.0
rate_limit_rps: 1.0
window:
  start: "2026-11-10T00:00:00Z"
  end: "2026-11-10T06:00:00Z"
```

- `ActiveScope` model mirrors `Scope` but is never inferred from a passive
  scan automatically — the operator must copy hosts in by hand.
- `--authorization <file>` is a required CLI argument for `active`; there is
  no default path, no env var fallback.
- The file's `window` is validated against wall-clock time at startup; if
  outside the window, the command refuses to run and exits non-zero (this is
  a per-engagement control, not a permanent credential).
- Parsing/validation lives in `recon/active/authorization.py`; failures
  produce a clear, specific error (missing field, expired window, empty
  scope) rather than a generic exception.

### 2. CLI command (`recon/cli.py`)

```
siterecon active <domain> --authorization auth.yaml [--output ...] [--format ...] [--dry-run]
```

- `--dry-run` loads the authorization, resolves the module/check registry
  (empty for now), and prints what *would* run — no network calls. This is
  the main deliverable of v0.3.0: the plumbing works and is auditable before
  any check logic exists.
- Without `--dry-run`, with zero checks registered, the command should run
  end-to-end and produce an empty-but-valid `ActiveReport` (next section),
  proving the pipeline before checks land in v0.3.1+.

### 3. Data models (`recon/active/models.py`)

Parallel to `recon/models/report.py` but separate, so a passive `ReconReport`
is never silently extended with active fields:

```python
class ActiveCheckResult(BaseModel):
    check_id: str
    status: ModuleStatus          # reuse existing enum
    target: str
    findings: list[Finding]       # reuse existing Finding model
    requests_made: int
    started_at: datetime
    finished_at: datetime
    errors: list[CollectionError]

class ActiveReport(BaseModel):
    schema_version: str = "0.1"
    scan_id: str
    authorization: AuthorizationSummary   # who/when/scope, never the raw file contents verbatim if it has secrets
    target: TargetInfo
    checks: list[ActiveCheckResult] = []
    started_at: datetime
    finished_at: datetime
    duration_ms: float
```

Reusing `Finding` and `ModuleStatus` means the existing
`MarkdownReportWriter`/`HtmlReportWriter` patterns extend naturally rather
than needing a parallel renderer from scratch.

### 4. Check registry (`recon/active/registry.py`)

An extensible registry, populated with the four checks below so later
releases can add more without touching the CLI or orchestrator:

```python
class ActiveCheck(ABC):
    check_id: ClassVar[str]
    description: ClassVar[str]
    requires_hosts: ClassVar[tuple[str, ...]]  # which authorization.scope.hosts entries this check needs

    @abstractmethod
    async def run(self, ctx: ActiveContext) -> ActiveCheckResult: ...

REGISTRY: dict[str, type[ActiveCheck]] = {
    "supabase_rls": SupabaseRlsCheck,
    "function_url_reachability": FunctionUrlReachabilityCheck,
    "email_endpoint_rate_limit": EmailEndpointRateLimitCheck,
    "tls_protocol_enum": TlsProtocolEnumCheck,
}
```

`ActiveContext` carries the authorization, a rate-limited `SafeHttpClient`
bound to the authorization's scope (not the passive target scope), and a
shared request counter/budget so the engagement-level rate limit
(`rate_limit_rps`) is enforced centrally rather than per-check. Only checks
named in the authorization's `checks_enabled` list actually run; being in
`REGISTRY` makes a check available, not active.

#### 4a. `SupabaseRlsCheck`

- Targets the `supabase.co` host(s) named in `scope.hosts`.
- Uses only the public anon key the passive scan already extracted (never a
  service-role key) to issue one read-only `select` per discovered table
  name (table names come from the passive scan's client-config/endpoint
  inventory, passed in explicitly, not re-discovered here).
- A table that returns rows with the anon key is flagged `high`
  (`active.supabase_rls_open`); a table that returns a permission error is
  evidence RLS is enforced and produces no finding.
- Hard cap: one request per known table, no pagination, no writes.

#### 4b. `FunctionUrlReachabilityCheck`

- Targets each Lambda Function URL / Supabase edge function in
  `scope.hosts`.
- Sends a single unauthenticated `OPTIONS` or minimal `GET`/`POST` (per
  endpoint, from the passive scan's inventory) and records whether it
  returns 2xx/3xx (reachable without auth) vs. 401/403 (auth required) vs.
  connection failure.
- No payload designed to trigger side effects (e.g. never a real order or
  email send) — reachability and auth posture only. `active.endpoint_open`
  finding (`high`) when an endpoint accepts the request without
  authentication and its name suggests a state-changing action (order,
  coupon, broadcast).

#### 4c. `EmailEndpointRateLimitCheck`

- Only runs against endpoints the authorization explicitly lists as
  email/notification-sending (operator must opt each one in by name in
  `checks_enabled` or a dedicated `email_endpoints` list — never inferred).
- Sends a small, fixed burst (default 5, configurable, hard-capped at 10) at
  the authorization's `rate_limit_rps` and observes whether responses start
  being throttled (429/503) or keep succeeding.
- Never sends real-looking content; uses a clearly test-marked payload where
  the endpoint's schema allows one, and skips the check entirely if it
  cannot avoid sending to a real address.
- Finding `active.no_rate_limit` (`medium`) when the full burst succeeds
  with no throttling signal.

#### 4d. `TlsProtocolEnumCheck`

- Targets hosts in `scope.hosts` the operator has confirmed they control
  (the authorization format requires a `tls_authorized: true` flag per host
  for this check, separate from general scope membership).
- Attempts handshakes offering TLS 1.0, 1.1, 1.2 and 1.3 individually (reusing
  `CertificateParser`/handshake logic from the passive `tls` module) and
  records which versions and cipher suites the server accepts.
- Finding `active.legacy_tls_accepted` (`medium`) when TLS 1.0/1.1 or a weak
  cipher is still negotiable.

### 5. Orchestrator (`recon/active/orchestrator.py`)

Mirrors `ScanOrchestrator` structurally:

- Loads authorization → builds `ActiveScope` → builds a rate-limited client.
- Iterates `REGISTRY`, running each check named in the authorization's
  `checks_enabled`, isolating exceptions into `FAILED` results exactly like
  the passive orchestrator does. A check named in `checks_enabled` but
  missing its required hosts in `scope.hosts` is `SKIPPED` with a clear
  reason, never silently omitted.
- Enforces the request budget (per-check and per-run) centrally, so even if
  a check has a bug, the orchestrator — not the check — is the backstop.
- Writes `requests_made` per check so a post-hoc audit can see exactly how
  much traffic was generated.

### 6. Reporting

- New `ActiveReportWriter` (or extend the existing writers to accept
  `ActiveReport` as an alternate top-level type) with its own section:
  Authorization Summary, Checks Run, Findings, Request Budget/Audit Log.
- Keep it visually distinct from the passive report (e.g., a banner noting
  "active testing — results may have affected the target") so nobody
  mistakes it for passive recon.

### 7. Safety rails carried over from day one

- Same `Scope`/`is_public_ip` SSRF guards, reused for the active HTTP
  client.
- Hard cap on `requests_made` per check and per run (config value, defaults
  conservative, e.g. 100 total) — enforced even with zero checks
  implemented, so the budget logic itself is tested before anything spends
  it.
- No credentials or secrets ever logged; if an authorization file or future
  check needs an API key, it's redacted the same way `SecretScanner`
  redacts things today.
- `active` never runs inside `scan`; the two commands cannot be chained
  implicitly.

## File/module layout

```
recon/active/
  __init__.py
  authorization.py     # AuthorizationFile, ActiveScope, load/validate
  models.py             # ActiveCheckResult, ActiveReport, AuthorizationSummary
  registry.py           # ActiveCheck base class, REGISTRY dict (empty)
  context.py            # ActiveContext (client, budget, authorization)
  orchestrator.py        # ActiveOrchestrator.run()
recon/reporting/
  active_markdown.py    # or extend existing writers
  active_html.py
tests/
  test_active_authorization.py   # window validation, scope parsing, malformed file handling
  test_active_orchestrator.py    # empty registry → valid empty report; rate-limit/budget enforcement
  test_active_cli.py             # --dry-run output, missing/expired authorization exits non-zero
```

## v0.3.0 acceptance criteria

1. `siterecon active example.io --authorization auth.yaml --dry-run` runs
   with no network I/O and prints the resolved scope, window validity, and
   which of the four registered checks `checks_enabled` would run (and
   which it would skip for missing scope hosts).
2. `siterecon active example.io --authorization auth.yaml` with
   `checks_enabled: []` produces a valid `ActiveReport` with zero checks
   run, in JSON/Markdown/HTML, through the same output-directory convention
   as `scan` — proving the harness works independent of any check logic.
3. Each of the four checks (`supabase_rls`, `function_url_reachability`,
   `email_endpoint_rate_limit`, `tls_protocol_enum`) has its own unit tests
   with a mocked/local server — no test depends on example.io or any other
   live third-party target.
4. Expired or malformed authorization files are rejected with a specific,
   actionable error and exit code 2 — no partial run.
5. The authorization's scope is independent of and never inferred from any
   stored passive `ReconReport`; table names and endpoint lists the checks
   need are passed into the authorization file explicitly by the operator.
6. Rate limiting and request-budget enforcement are unit-tested against the
   real checks (e.g., `EmailEndpointRateLimitCheck` capped at its configured
   burst size; `SupabaseRlsCheck` capped at one request per listed table).
7. `email_endpoint_rate_limit` and `tls_protocol_enum` each require their
   own explicit per-host/per-endpoint opt-in beyond general scope
   membership, and the collector/orchestrator reject running them without
   it.
8. Documentation (README or `docs/active.md`) describes each check's
   behavior, request budget, and exactly what evidence it produces, so an
   operator can review before enabling it.

## Deferred beyond v0.3.0

Everything that needs more design before it can ship safely as an automated
check. The first item is the core of **Phase 6**; the rest are the deeper,
target-specific testing that phase would also open up:

- **Dynamic/headless rendering (Playwright) — Phase 6.** Execute the page in a
  real browser to capture the runtime DOM and the requests the app actually
  makes, then feed those into the same endpoint/asset extraction the static
  path uses. This closes the SPA/runtime-endpoint gap (e.g. a Supabase
  `backend_read_access` probe skipped today because table names only appear
  after JS runs). Needs: a `playwright` dependency, a render collector, the
  `browser_render` provenance wired through, and request-budget/SSRF handling
  for browser-initiated traffic.
- Business-logic probing (coupon abuse, payment/order tampering,
  free-tier bypass) — needs per-application modeling, not a generic check.
- Authenticated/session testing (login, password reset, authorization
  bypass between users) — needs test accounts and is inherently
  target-specific.
- Resume/file-upload fuzzing (type validation, malware, stored-content
  rendering) — needs a sandboxed analysis pipeline beyond this tool's scope.

---

# Passive data enrichment — what shipped, and what it leaves open

Shipped (schema **2.4**, documented in `docs/passive-discovery.md`):

- **Passive subdomain sources.** Eight sources behind `--subdomain-source` (OTX, urlscan.io, Common Crawl,
  Wayback, RapidDNS, HackerTarget, Anubis-DB, and key-gated BufferOver), each with its own allow-listed
  client, per-source outcome row, cache fallback and `SourceKind` so a hit's evidential weight is explicit.
  Off by default: every source discloses the target domain to another provider.
- **Controlled permutation.** `--permute-subdomains` generates candidates from observed labels plus a small
  fixed wordlist, scope-checks every one, resolves A/AAAA only, hard-caps the count, and keeps a name only
  when it resolves. Produces `subdomains.unlisted_host` for resolving names absent from every public dataset.
- **Historical URLs.** A new `historical` module (`--historical`) over Wayback, Common Crawl, urlscan.io and
  OTX, extracting the archived endpoint surface, query-parameter classes (values redacted), technology
  hints with first/last-seen windows, and sensitive-looking paths.
- **Technology detection.** 87 → 541 signatures across 45 categories; grading now refuses to let two weak
  signals (CSP allow-listing, a CNAME hint, an implication) corroborate into *confirmed*; version recovery
  added for asset `?ver=` queries, including CMS platform versions the generator tag no longer discloses.
  WAF signatures roughly tripled (AWS WAF, Cloud Armor, FortiWeb, NetScaler, Radware, Reblaze, DDoS-Guard,
  Qrator, Wallarm, SafeLine, Alibaba, Tencent, and more), each still distinguishing "proxy present" from
  "WAF rules enabled".
- **Managed-cloud inventory.** `recon/analysis/cloud_signatures.py` classifies ~90 patterns into object
  storage, serverless functions, managed databases, edge workers, hosting, auth, search and container
  registries, recovering the resource identifier and region from either addressing style and separating
  same-host roles by path. Findings are scoped to what a *reference* justifies, and point at the active
  checks for confirmation.

# On-page SEO audit — what shipped

`--seo` adds an eighteenth module, `seo`, and a second graded dimension. It is **derived**: it re-reads the
response bodies the `http` and `crawler` modules retained, sends no requests of its own, contacts no third
party and queries no search engine. Because a site-wide audit needs more than one page to compare, `--seo`
turns the crawler on (announced on stdout, overridable with `--no-crawl`).

The design decision worth recording is that **every judgement lives in one declarative table**
(`recon/analysis/seo_checks.py`, 39 `SeoCheckSpec` entries). The same entry produces the finding
(`seo.<id>`, with its recommendation from the central table) and the score deduction, so the two can never
disagree, and a new check is one table entry plus one recommendation.

Three rules keep the score from overstating what was observed:

1. **`not_checked` is not a pass.** A check whose inputs are missing produces no finding, deducts nothing,
   and its area is excluded from the overall average rather than credited as 100. A landing-page-only run
   therefore cannot grade as a clean site; its report lists each skipped check and why.
2. **Deductions are proportional.** `weight × (failing pages / evaluated pages)`, so one odd page and a
   site-wide template bug are not the same cost.
3. **The audit's own coverage is a finding.** `seo.coverage_single_page` and `seo.coverage_truncated` state
   when the numbers describe one page or a truncated crawl.

The SEO grade is deliberately separate from the security grade, and `recon/analysis/grading.py` now excludes
the `seo` and `social` categories from the security score entirely. Before this change those findings fell
through to the security grade's "exposure" area, so a missing canonical deducted from a *security* number —
which is fixed here as part of the work.

Two bugs in the new code were found by its own tests and are worth remembering, since both are easy to
reintroduce: extracting `script` elements to exclude them from a word count destroyed any JSON-LD living in
`<body>` before the structured-data inventory could read it (text nodes are now filtered, not removed); and
building a sitemap audit even when the `resources` module had not run reported "no robots.txt" for a file
that was never fetched (the audit is now `None`, so the check reports `not_checked`).

## Follow-up for later phases

Deliberately not attempted here, in rough priority order:

1. **Active confirmation of the cloud inventory.** The passive layer now produces a precise list of buckets,
   function endpoints and backend endpoints, each with its identifier. The existing `backend_read_access`
   and `function_url_reachability` checks could consume that inventory directly (via
   `recon/active/inventory.py`) instead of the operator copying hosts into the authorization file by hand —
   with the same per-host opt-in, since auto-expanding active scope from recon findings is explicitly
   against the Phase 3 design.
2. **Reachability triage for archived endpoints.** `historical.endpoints` lists paths that were once
   fetchable. Confirming which still respond is a bounded GET per path against the target — passive by
   SiteRecon's own definition, but it multiplies request volume, so it needs its own flag, cap and
   robots handling before it ships.
3. **Key-gated discovery sources.** SecurityTrails, Censys, VirusTotal, Chaos, Netlas, FOFA, Shodan DNS and
   Facebook CT all fit the existing `PassiveSource` interface (`key_env` / `key_header` are already in the
   base class) and would lift coverage substantially. Each needs a credential story — environment variable
   today, which does not scale to a dozen providers; a keyfile with per-source entries would.
4. **Wordlist-based permutation.** The current wordlist is intentionally ~130 words. A larger list (or an
   alterations file in the style of altdns) would find more, but changes the traffic profile enough that it
   belongs behind its own flag with its own rate limiting, and arguably in the `active` command.
5. **Signature-set maintenance.** 541 hand-curated signatures will drift. Options: import and transform
   Wappalyzer's dataset at build time (licence review needed), or add a test that samples a corpus of real
   pages and reports signatures that never fire. The `SIGNATURES_VERSION` field already records which set
   produced a scan's detections, so a drift report is straightforward to add.
6. **Historical URL volume.** Archived URLs are summarized into observations rather than recorded
   individually, because a per-URL diff would bury real changes. If per-URL history is ever wanted, it
   needs its own storage shape (an append-only URL ledger per target) rather than the observation table.
7. **SEO over the rendered DOM.** Word counts, headings and metadata come from the HTML as served, so a
   client-rendered page legitimately looks thin. `RenderData` already holds post-JavaScript pages from
   `--render`; feeding those bodies to `PageSeoParser` (and labelling each page record with which view it
   came from) would close the SPA gap for the audit the same way Phase 6 closes it for technology detection.
8. **Real performance signals.** The delivery area scores server response time, compression, HTTP version
   and markup weight — all honest, none of them user-perceived. Core Web Vitals need a real browser, so
   they belong with the Phase 6 render work, not here, and must stay labelled as lab measurements.
9. **Internal-link graph beyond the crawl.** Orphan detection is bounded by what was crawled, so a page
   linked only from an uncrawled page is indistinguishable from a real orphan. Storing the link graph in
   history and accumulating it across scans would sharpen this without more traffic per scan.
10. **Cloud resource ownership.** The inventory cannot tell a bucket the target owns from a third party's
   bucket it merely links to. RDAP/ASN correlation or an operator-supplied owned-resource list would
   sharpen the distinction, which matters before any of this drives an active check.
