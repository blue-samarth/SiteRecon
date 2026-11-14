# Active testing (`siterecon active`)

The `scan` command is strictly passive: GET/HEAD, DNS, and TLS handshakes only. The `active`
command is separate and sends more than that — backend read-access probes, reachability requests,
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
- any backend credential provided is private rather than a public/client-side key — a Supabase
  `service_role` JWT or new-format secret key (`sb_secret_…`), a Firebase/Google service-account JSON or
  private key block, or any value matching a known private-credential pattern (the same `SecretScanner`
  used by the passive scan). JWT signatures are not verified (that needs the project secret); this is a
  structural guard, so a value that matches no private shape is accepted as the expected public credential.

## Authorization file

YAML or JSON. The scope is authored by hand and is **never** inferred from a passive scan — table
names, function URLs and email endpoints are all copied in explicitly by the operator.

### Automated discover-and-test (CI)

For a pipeline you want the whole discover→test loop automated with **no per-run human step**. Commit an
authorization with an `auto_discover` block — a *standing* assertion that you own certain registrable
domains — reviewed once in a PR (that is the one-time human gate), then run it on every pipeline execution:

```yaml
target: clusterheart.com
authorized_by: "CI"
authorized_on: "2026-11-11"
window: { start: "2026-11-01T00:00:00Z", end: "2027-11-01T00:00:00Z" }   # standing window
auto_discover:
  authorized_domains: [clusterheart.com]     # the ownership boundary
```

```bash
siterecon active clusterheart.com --authorization auth.ci.yaml --format json --fail-on high
```

Each run passively discovers first-party assets under the authorized domains, synthesizes the targets, and
runs the **safe** checks (`tls_protocol_enum`, `function_url_reachability`, `external_intelligence`)
automatically — picking up new in-scope endpoints as they appear. `--fail-on <severity>` exits **code 3**
when any finding is at least that severe, so the build fails on regressions.

Two lines are deliberate and load-bearing:

- **Only first-party hosts are tested.** A discovered host is probed only if its registrable domain is in
  `authorized_domains`; third-party hosts found in your site (analytics, CDNs, someone else's API or
  Supabase project) are **reported but never tested**. This is the boundary that makes automation safe to
  ship — you test your assets, not whatever you happen to find.
- **Email bursting is never auto-enabled** (it can reach a real recipient), and backend reads are not yet
  auto-run (they need a credential). Those stay explicit, per-endpoint opt-ins.

The scaffold below (`scaffold-auth`) is the interactive cousin: it writes a draft for a human to edit,
whereas `auto_discover` runs the same discovery non-interactively within a committed boundary.

#### A complete local run (`--bypass-sec`)

The CI default is the safe set (no credentials needed). For a **local** complete run of your own system,
add `--bypass-sec` to an `auto_discover` run:

```bash
siterecon active clusterheart.com --authorization auth.ci.yaml --bypass-sec --format all
```

It runs the **complete** check set except email — `tls_protocol_enum`, `function_url_reachability`,
`client_ip_header_trust`, `external_intelligence`, **and `backend_read_access`** — against your first-party
hosts **and the backends your own site embeds**. To test the backend it keeps the public Supabase/Firebase
key the passive scan found (normally redacted) and uses the table names it saw in `/rest/v1/<table>`
references. Two things it still will not do: actively probe **unrelated** third-party hosts (Stripe,
analytics, someone else's API — reported, never tested), or **burst email** endpoints. It requires an
`auto_discover` block (for the ownership boundary) and is meant for local testing, not CI.

### Scaffolding a draft (optional)

Typing candidates in by hand is tedious, so SiteRecon can pre-fill a **draft** from a passive scan:

```bash
siterecon scaffold-auth jobbie.io          # writes reports/jobbie.io/active/authorization.draft.yaml
```

The draft lists the backends and endpoints the passive scan discovered, but **enables nothing**
(`checks_enabled` is empty) and leaves the judgements the tool cannot make — whether you own a host,
whether an endpoint is `state_changing`, whether an email endpoint is safe to burst
(`confirmed_no_real_delivery`), and the public credential value — **blank on purpose**. It is inert until
you review it, confirm you are authorized for every host (discovery is not ownership), fill the blanks and
add the checks you want to `checks_enabled`. In other words: the tool proposes, the human approves. This is
why the authorization is required and never auto-populated-and-run.

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
  - backend_read_access
  - tls_protocol_enum
backends:                               # "can a public, client-side credential read data it shouldn't?"
  - kind: supabase                      # each backend has its own `kind` and resource shape
    host: muvsftgwvzuttktqtkmc.supabase.co
    credential: "eyJ...anon..."         # PUBLIC anon key only; a service_role/secret key is rejected
    resources: [profiles, items]        # table names; one request per resource, no pagination
  - kind: rest_generic                  # your own API with a key shipped to the client (the common case)
    base_url: "https://muvsftgwvzuttktqtkmc.supabase.co"
    credential_header: "X-Api-Key"
    credential: "pk_live_public..."
    resources:
      - path: "/v1/users?limit=1"
        success_if: {status: 200, body_contains: "email"}   # you define open vs denied (no universal rule)
        denied_if: {status: [401, 403]}
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
external_intelligence:                  # only needed to restrict providers; the checks_enabled entry is enough
  providers: [wayback, shodan_internetdb]
```

Add `external_intelligence` to `checks_enabled` to run the third-party intelligence phase (see
[intelligence.md](intelligence.md)); the `external_intelligence:` section is optional and only narrows
which providers run.

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
| `backend_read_access` | One read-only probe per operator-listed backend **resource**, using **only** a public/client-side credential. No writes, no pagination. Each backend `kind` has its own probe and its own "open"/"denied" rule (see below). | 1 per resource | `active.backend_read_access_open` (high) when a resource returns data to the public credential — backend authorization (RLS / rules / role permissions) is not restricting anonymous reads. A denial produces **no** finding. |
| `function_url_reachability` | One request per listed function URL with the configured method. GET/OPTIONS send no body; POST/PUT/PATCH send only an empty `{}` — never a payload that could create state. | 1 per URL | `active.endpoint_open` (high) when a URL you labeled `state_changing` answers an unauthenticated request; `active.endpoint_reachable` (info) otherwise. 401/403 → no finding. |
| `email_endpoint_rate_limit` | A small, test-marked burst (`burst`, ≤10) paced at the engagement rate, **only** to endpoints with `confirmed_no_real_delivery: true`. Sends an `X-SiteRecon-Test` header and a test payload; skips any endpoint not confirmed safe. | ≤`burst` per endpoint | `active.no_rate_limit` (medium) when the whole burst is accepted with no 429/503. |
| `tls_protocol_enum` | A handshake at each of TLS 1.0/1.1/1.2/1.3 against hosts carrying the per-host `tls_authorized` opt-in. No application data is sent. The evidence lists **every version offered and its outcome** (accepted / offered-rejected / not-attempted), and each handshake appears in the audit log. | 1 per version per host | `active.legacy_tls_accepted` (medium) when TLS 1.0/1.1 is negotiable; `active.tls_versions` (info) otherwise. |
| `external_intelligence` | Queries keyless third-party providers (Wayback Machine, Shodan InternetDB) **about** the target — its domain and resolved IPs — never the target itself. Discloses the target to those providers. See [intelligence.md](intelligence.md). | ≤1 per Wayback domain + 1 per IP (Shodan) | `intel.archived_history`/`intel.archived_sensitive_path` (info/low) from the web archive; `intel.exposed_ports` (info) and `intel.indexed_vulnerability` (low, candidates) from Shodan's index. |
| `client_ip_header_trust` | A baseline request plus two copies with client-IP headers (`X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`, `Forwarded`, …) set to test values (`127.0.0.1`, `10.0.0.1`). **No packets are forged** — these are ordinary request headers. Endpoints are operator-listed in `ip_trust_endpoints` (never guessed). | 3 per endpoint | `active.access_control_open` (high) when an endpoint labeled `access_control` already answers the plain baseline without auth; `active.client_ip_header_bypass` (high) when the status flips a decision with the headers (e.g. 403→200, 429→200); `active.client_ip_header_trusted` (low) when it merely varies. |

### Backend adapters (`backend_read_access`)

The underlying question — *does a public, client-side credential let you read data it shouldn't* — is not
Supabase-specific. Supabase row-level security is one instance; the same shape covers Firebase rules, a
Hasura anonymous-role query, a PocketBase collection, a bare REST API with a client-shipped key, or an
open GraphQL endpoint. Each operator-listed backend names a `kind`, and each `kind` owns its request shape
and its own definition of "open" vs "denied":

| `kind` | Probe | "Open" signal | "Denied" signal |
|---|---|---|---|
| `supabase` | `GET /rest/v1/<table>?select=*&limit=1`, `apikey` header | 200 + JSON array (**even empty** — an empty array means the anon select was authorized, not denied) | 401/403 |
| `firebase` | Firestore REST `…/documents/<collection>`, or Realtime DB `/<path>.json`, no auth (or public API key) | 200 + data (`null` for an empty-but-readable RTDB path still counts) | `PERMISSION_DENIED`, or 401/403 |
| `hasura` | `POST /v1/graphql`, `x-hasura-role: anonymous`, minimal `{ <type>(limit: 1) { __typename } }` | 200 + `data.<type>` present, no `errors` | `errors` array (permission / field-not-found) |
| `pocketbase` | `GET /api/collections/<name>/records?perPage=1` | 200 + `items` array | 400/401/403 |
| `rest_generic` | operator's `path` + the public key `credential_header`/`credential_param` | operator's `success_if` (`status` / `body_contains`) | operator's `denied_if` |
| `graphql_generic` | `POST <url>` with the operator's minimal query | 200 + `data` non-null, no `errors` | `errors`, or 401/403 |

The `rest_generic` and `graphql_generic` adapters are what make this backend-agnostic: most sites are not
on a named BaaS — they call their own API with a key that shipped to the client. There is no universal
convention for those, so the operator states, per resource, what open and denied look like (`denied_if` is
checked first, so an ambiguous response is never a false "open"). A credential that looks server-side — a
Supabase `service_role`/`sb_secret_`, a service-account JSON, or any `SecretScanner` private pattern — is
refused per backend before any request is sent.

> **Backward compatibility.** The old top-level `supabase:` block and the `supabase_rls` check id still
> work: on load, `supabase:` is folded into a `backends:` entry of `kind: supabase` and `supabase_rls` is
> migrated to `backend_read_access`. New authorization files should use `backends:` directly.

### Safety rails

- **Central budget and rate limit.** Every request (and every TLS handshake) is reserved through a
  shared context that enforces `max_requests`, `max_requests_per_check` and `rate_limit_rps`. A check
  cannot exceed them even if it has a bug — the orchestrator is the backstop.
- **Scope is exact.** The active HTTP client is bound to the authorization's `scope.hosts` as exact
  hostnames, reusing the same SSRF guards as passive scanning (no private/loopback/metadata
  addresses). Out-of-scope requests are blocked and logged.
- **No secrets stored or used.** Every backend credential is redacted (type + fingerprint) wherever it
  appears. A private/server-side credential (Supabase `service_role`/`sb_secret_`, a service-account JSON,
  any known secret pattern) is rejected outright. No discovered credential is ever used against a service;
  only the public, client-side credential the operator supplies by hand is sent.
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
