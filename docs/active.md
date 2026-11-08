# Active testing (`siterecon active`)

The `scan` command is strictly passive: GET/HEAD, DNS, and TLS handshakes only. The `active`
command is separate and sends more than that — row-level-security probes, reachability requests,
a small rate-limit burst, per-version TLS handshakes — so it is gated behind an operator-authored
**authorization file**. There is no flag or environment variable that bypasses it, and `active`
never runs as part of `scan`.

> **Only run this against systems you are authorized to test.** Active checks send requests to the
> target and can affect it. Every active report leads with an "ACTIVE TESTING" banner.

## Usage

```bash
# See exactly what would run — no requests are made:
siterecon active jobbie.io --authorization auth.yaml --dry-run

# Run the enabled checks and write reports to reports/<host>/active/:
siterecon active jobbie.io --authorization auth.yaml --format all
```

**A real run executes in two steps.** First it runs a passive scan (`scan` with crawling) and writes
those reports to `reports/<host>/`. It then distills what the scan discovered — sitemap URLs, crawled
pages, bundle-referenced endpoints and hosts — into `reports/<host>/active/inventory.json`. The active
step **reads that file back** before it proceeds: the inventory is the explicit handoff artifact between
the two phases, so it can be inspected, and so `--no-passive` can reuse the inventory from a previous
run instead of rebuilding it. Loading the inventory lets the command flag any authorized endpoint the
passive recon did not discover (so "testing a path the scan never saw" is visible, not silent); the
active checks still only ever touch operator-listed endpoints — the inventory is never used to invent
targets.

Both phases drive a **live progress bar** (one step per passive module, one per active check, with the
current item beside the bar) so the terminal is never blank. Pass `--no-passive` to skip the passive
scan; the command then loads `inventory.json` if a prior run left one, and warns if none is present.

The command refuses to run (exit code 2) if:

- the authorization file is missing, malformed, or missing a required field;
- the command's target does not match the file's `target`;
- the current time is outside the file's `window` (a real run; `--dry-run` only warns);
- the Supabase key provided is private — a `service_role` JWT or a new-format secret key (`sb_secret_…`) —
  rather than the public anon/publishable key. The JWT signature is not verified (that needs the project
  secret); this is a structural guard, so a key that is neither form is accepted as the expected anon key.

## Authorization file

YAML or JSON. The scope is authored by hand and is **never** inferred from a passive scan — table
names, function URLs and email endpoints are all copied in explicitly by the operator.

```yaml
target: jobbie.io
authorized_by: "Jane Operator / AppSec"
authorized_on: "2026-11-08"
window:                                 # wall-clock window; checked at startup
  start: "2026-11-10T00:00:00Z"
  end: "2026-11-10T06:00:00Z"
rate_limit_rps: 1.0                     # engagement-wide rate; must be finite, 0.1..10.0, else rejected
max_requests: 50                        # total request budget; must be 1..1000, else rejected
max_requests_per_check: 50              # must be 1..1000, else rejected
scope:
  hosts:                                # exact hosts only; subdomains are NOT implicitly included
    - muvsftgwvzuttktqtkmc.supabase.co
    - abc.lambda-url.ap-south-1.on.aws
  exclude_hosts: []                     # explicit carve-outs, even if listed above
  tls_authorized_hosts:                 # extra per-host opt-in required for tls_protocol_enum
    - muvsftgwvzuttktqtkmc.supabase.co
checks_enabled:                         # a check runs only if it is named here AND its config is present
  - supabase_rls
  - tls_protocol_enum
supabase:
  host: muvsftgwvzuttktqtkmc.supabase.co
  anon_key: "eyJ...anon..."             # PUBLIC anon key only; a service_role key is rejected
  tables: [profiles, items]             # one request per table, no pagination
function_urls:
  - url: "https://abc.lambda-url.ap-south-1.on.aws/order"
    method: OPTIONS                     # default; a single, side-effect-free request
    state_changing: true                # your label; drives finding severity, never behavior
email_endpoints:
  - url: "https://jobbie.io/api/notify"
    method: POST
    burst: 5                            # hard-capped at 10
    test_payload: '{"siterecon_test": true}'
    confirmed_no_real_delivery: true    # REQUIRED; the check is skipped without it
ip_trust_endpoints:
  - url: "https://jobbie.io/admin"
    method: GET
    access_control: true                # label: gates access/rate on client IP (raises severity)
```

> **Note on "IP spoofing".** `client_ip_header_trust` does not forge source IP addresses at the packet
> level. Packet-level source-IP spoofing cannot complete a TCP/TLS/HTTP exchange (the response never
> returns to you); its only working uses are UDP reflection/amplification (DoS) and attribution hiding,
> neither of which this tool does. What attackers realistically exploit for IP-based bypass is an
> application trusting client-supplied IP *headers* — which is exactly what this check measures.

Being present in `REGISTRY` makes a check *available*; being in `checks_enabled` with its required
config makes it *run*. Anything else is reported as `skipped` with a clear reason — never silently
omitted.

## The checks

| Check | What it sends | Request budget | Finding(s) |
|---|---|---|---|
| `supabase_rls` | One read-only `GET /rest/v1/<table>?select=*&limit=1` per listed table, using **only** the public anon key. No writes, no pagination. | 1 per table | `active.supabase_rls_open` (high) when a table returns rows with the anon key — RLS is not restricting anonymous reads. A permission error produces **no** finding (RLS is working). |
| `function_url_reachability` | One request per listed function URL with the configured method. GET/OPTIONS send no body; POST/PUT/PATCH send only an empty `{}` — never a payload that could create state. | 1 per URL | `active.endpoint_open` (high) when a URL you labeled `state_changing` answers an unauthenticated request; `active.endpoint_reachable` (info) otherwise. 401/403 → no finding. |
| `email_endpoint_rate_limit` | A small, test-marked burst (`burst`, ≤10) paced at the engagement rate, **only** to endpoints with `confirmed_no_real_delivery: true`. Sends an `X-SiteRecon-Test` header and a test payload; skips any endpoint not confirmed safe. | ≤`burst` per endpoint | `active.no_rate_limit` (medium) when the whole burst is accepted with no 429/503. |
| `tls_protocol_enum` | A handshake at each of TLS 1.0/1.1/1.2/1.3 against hosts carrying the per-host `tls_authorized` opt-in. No application data is sent. The evidence lists **every version offered and its outcome** (accepted / offered-rejected / not-attempted), and each handshake appears in the audit log. | 1 per version per host | `active.legacy_tls_accepted` (medium) when TLS 1.0/1.1 is negotiable; `active.tls_versions` (info) otherwise. |
| `client_ip_header_trust` | A baseline request plus two copies with client-IP headers (`X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`, `Forwarded`, …) set to test values (`127.0.0.1`, `10.0.0.1`). **No packets are forged** — these are ordinary request headers. Endpoints are operator-listed in `ip_trust_endpoints` (never guessed). | 3 per endpoint | `active.access_control_open` (high) when an endpoint labeled `access_control` already answers the plain baseline without auth; `active.client_ip_header_bypass` (high) when the status flips a decision with the headers (e.g. 403→200, 429→200); `active.client_ip_header_trusted` (low) when it merely varies. |

### Safety rails

- **Central budget and rate limit.** Every request (and every TLS handshake) is reserved through a
  shared context that enforces `max_requests`, `max_requests_per_check` and `rate_limit_rps`. A check
  cannot exceed them even if it has a bug — the orchestrator is the backstop.
- **Scope is exact.** The active HTTP client is bound to the authorization's `scope.hosts` as exact
  hostnames, reusing the same SSRF guards as passive scanning (no private/loopback/metadata
  addresses). Out-of-scope requests are blocked and logged.
- **No secrets stored or used.** The anon key is redacted (type + fingerprint) wherever it appears.
  A `service_role` key is rejected outright. No discovered credential is ever used against a service.
- **No side-effect payloads.** Reachability probes send empty bodies; the rate-limit check refuses
  any endpoint the operator has not confirmed cannot deliver to a real recipient.
- **Full audit log.** Every request **and every TLS handshake** is recorded (method, query-redacted
  URL/host, status, note) with a per-check and total count, so the log row count always equals the
  reported requests — a reviewer can see exactly how much traffic the run generated.
- **Every finding carries a recommendation.** Active `active.*` findings pull their recommendation and
  limitations from the same `RECOMMENDATIONS`/`LIMITATIONS` tables (`recon/analysis/findings.py`) the
  passive report uses.

## Output

```text
reports/<host>/active/
├── inventory.json   # passive→active handoff: sitemap URLs, pages, endpoints, hosts the scan found
├── active.json      # full ActiveReport: authorization summary, checks, findings, request log
├── active.md
└── active.html      # self-contained, CSP-locked, with the ACTIVE TESTING banner
```

Exit codes: `0` success, `1` every enabled check failed, `2` invalid input / target mismatch /
invalid or expired authorization.

## Not included in v0.3.0

Business-logic probing (coupon/payment/free-tier abuse), authenticated/session testing, and
file-upload fuzzing are deferred — each needs per-application modeling or a sandbox beyond a generic,
automatically-run check.
