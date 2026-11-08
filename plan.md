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
target: jobbie.io
authorized_by: "<name/role>"
authorized_on: "2026-11-08"
scope:
  hosts:
    - muvsftgwvzuttktqtkmc.supabase.co
    - 2u2hesxu3gufz6wdvpvnixefle0uxcon.lambda-url.ap-south-1.on.aws
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

1. `siterecon active jobbie.io --authorization auth.yaml --dry-run` runs
   with no network I/O and prints the resolved scope, window validity, and
   which of the four registered checks `checks_enabled` would run (and
   which it would skip for missing scope hosts).
2. `siterecon active jobbie.io --authorization auth.yaml` with
   `checks_enabled: []` produces a valid `ActiveReport` with zero checks
   run, in JSON/Markdown/HTML, through the same output-directory convention
   as `scan` — proving the harness works independent of any check logic.
3. Each of the four checks (`supabase_rls`, `function_url_reachability`,
   `email_endpoint_rate_limit`, `tls_protocol_enum`) has its own unit tests
   with a mocked/local server — no test depends on jobbie.io or any other
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
check:

- Business-logic probing (coupon abuse, payment/order tampering,
  free-tier bypass) — needs per-application modeling, not a generic check.
- Authenticated/session testing (login, password reset, authorization
  bypass between users) — needs test accounts and is inherently
  target-specific.
- Resume/file-upload fuzzing (type validation, malware, stored-content
  rendering) — needs a sandboxed analysis pipeline beyond this tool's scope.