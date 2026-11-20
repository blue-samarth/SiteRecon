# Passive data enrichment

Four capabilities widen what a passive scan can see without changing what "passive" means. None of them
sends anything to the target beyond the DNS, HTTP and TLS requests SiteRecon already made:

| Capability | What it adds | Default |
|---|---|---|
| [Passive subdomain sources](#passive-subdomain-sources) | Names from passive-DNS datasets and URL indexes, alongside Certificate Transparency | off (`--subdomain-source`) |
| [Controlled permutation](#controlled-permutation) | Candidate names built from the labels already found, kept only when they resolve | off (`--permute-subdomains`) |
| [Historical URLs](#historical-urls) | The endpoint, parameter and legacy-stack surface the site used to expose | off (`--historical`) |
| [Managed-cloud inventory](#managed-cloud-inventory) | Buckets, functions, databases and edge workers the client points at | on (derived, no extra traffic) |

Three rules apply to all of them, and the findings are written to respect them:

1. **The target is not probed any harder.** Passive sources and archives are queried *about* the target.
   Permutation issues DNS lookups only. The cloud inventory is derived from evidence already collected.
2. **Third-party disclosure is opt-in.** Every source you enable learns which domain you are assessing.
   That is why nothing beyond Certificate Transparency is on by default.
3. **A reference is never an exposure.** A bucket in a bundle, a path in an archive and a name in a dataset
   are leads. Where confirming one would need a request to the target, the finding says so and points at
   `siterecon active`.

## Turning all of it on at once

`siterecon active <domain> --authorization auth.yaml --bypass-sec` enables every opt-in passive capability
for its preliminary scan — all subdomain sources, permutation, archives, plus deep crawl, rendering,
subdomain probing and the OSV lookup — with the caps widened (500 names verified, 1000 candidates, 5000
archived URLs per archive). That mode is a local run on property you own, so it accepts the third-party
disclosure these sources imply and prints a line saying so. For a plain `scan`, each capability stays an
explicit flag. See [active.md](active.md#a-complete-local-run---bypass-sec).

---

## Passive subdomain sources

Certificate Transparency (crt.sh, Cert Spotter) is always queried. These additional sources are available:

| Source | `--subdomain-source` | Kind | Needs a key |
|---|---|---|---|
| AlienVault OTX | `otx` | passive DNS | no |
| urlscan.io | `urlscan` | URL index | no |
| Common Crawl | `commoncrawl` | URL index | no |
| Wayback Machine | `wayback` | URL index | no |
| RapidDNS | `rapiddns` | scrape | no |
| HackerTarget | `hackertarget` | passive DNS | no |
| Anubis-DB | `anubis` | passive DNS | no |
| BufferOver | `bufferover` | passive DNS | yes — `$SITERECON_BUFFEROVER_KEY` |

```bash
siterecon scan example.com --subdomain-source otx --subdomain-source urlscan
siterecon scan example.com --subdomain-source keyless   # every source needing no API key
siterecon scan example.com --subdomain-source all       # keyed sources skip themselves if unconfigured
```

What the `kind` is for: it records how much a hit is worth. A passive-DNS dataset observed the name
resolving at some point; a URL index merely holds a URL on that host; a scrape parsed an HTML listing page,
so a layout change degrades it to "no results" rather than wrong ones. Whatever the source, SiteRecon
verifies the name itself in DNS and reports what *it* observed — the source decides what to check, never
what to conclude.

Each source gets its own row in the report with `status` (`live`, `cached`, `failed`, `skipped`), how many
entries it returned, and how many in-scope names it contributed. A source that fails falls back to cached
results within `--ct-cache-ttl-hours`, and those names are labelled `cache:<source>` so a stale answer is
never presented as a live one. A source needing a key it does not have is `skipped` with the reason.

When any source fails, is cached or is skipped, the scan emits `subdomains.discovery_incomplete`
(informational). Saying "these N names exist" without saying "and one source never answered" would
overstate coverage.

**Safety.** Each source is reached through its own HTTP client allow-listed to exactly that provider's
hostnames, never the target's scope and never private networks. Names outside the target's scope are
dropped before anything is cached, and the dropped count is reported. Credentials are read from the
environment, sent only to the provider that issued them, and never logged or written to a report.

## Controlled permutation

`--permute-subdomains` builds candidate hostnames from the labels discovery already found and keeps only
the ones that resolve. It is the one path that generates names rather than reading them, so it is
deliberately small:

- candidates come from the **observed** structure — a fixed ~130-word environment/function list applied to
  the target apex and to each discovered sub-zone, plus affix mutations of labels that were actually seen
  (`api` → `api-dev`, `dev-api`, `api2`);
- the wordlist is fixed and not extended at run time — this is not a brute-force list;
- every candidate is scope-checked before it is resolved, and names over 253 characters are discarded;
- the total is hard-capped by `--max-permutations` (default 200), and the report states whether the cap
  truncated the candidate set;
- **only A/AAAA lookups are issued.** A generated name is never requested over HTTP;
- a candidate that does not resolve is **discarded, not recorded**, so the inventory never fills with
  guesses. Only names that resolve appear, sourced as `permutation`.

A resolving name that appears in no certificate and no passive dataset produces
`subdomains.unlisted_host` (low). Hosts missing from public inventories are often forgotten environments
that are still reachable but no longer maintained.

The report's permutation summary records `generated`, `tested`, `resolved`, the cap and whether it
truncated, so the cost of the pass is auditable after the fact.

## Historical URLs

`--historical` queries web archives and URL indexes for the URLs they hold under the domain, then mines the
merged result for three things the live site no longer shows.

| Source | `--historical-source` |
|---|---|
| Wayback Machine (CDX) | `wayback` |
| Common Crawl index | `commoncrawl` |
| urlscan.io | `urlscan` |
| AlienVault OTX | `otx` |

```bash
siterecon scan example.com --historical
siterecon scan example.com --historical --historical-source wayback --max-historical-urls 5000
```

What it extracts:

- **Endpoint surface** — API-looking paths (`/api/v1/...`, `/graphql`, `/.well-known/...`, `/wp-json/...`)
  that the archives hold, including routes nothing links to any more.
- **Query parameters**, classified as `credential`, `redirect`, `file`, `identifier` or `other`. Parameter
  **names** only: values are redacted before anything is stored.
- **Technology hints** from paths and extensions (`.php`, `.aspx`, `/wp-content/`, `/_next/`, `.swf`), each
  with its own first/last-seen window.
- **Sensitive-looking paths** (backups, dumps, configs, key material) that were once fetchable.
- File-extension counts and the overall archive date range.

Findings: `historical.archived_urls` (informational inventory), `historical.sensitive_path` (low),
`historical.credential_in_url` (**medium** — a secret that ever travelled in a URL is now in archives,
proxy logs, browser history and Referer headers, so rotation is the only fix),
`historical.parameter_surface` (informational — the redirect/file-valued injection surface),
`historical.legacy_technology` (low), and `historical.discovery_incomplete` when a source failed.

**Technology hints are never merged into the `technology` module.** They describe the stack that served a
path when it was archived, which may be several rewrites ago. After the technology scan runs, each hint is
annotated with `still_detected` (`yes` / `no` / `not checked`) so a report can separate "still running
this" from "used to run this" — annotation, not promotion.

Because this and the subdomain `wayback`/`commoncrawl` sources ask the same archives different questions,
enabling both makes two independent requests per archive.

## Managed-cloud inventory

Every passive scan classifies the managed-cloud endpoints the application references — from page and crawl
resources, bundle-referenced hosts and endpoint URLs, CNAME targets and the CSP allow-list — against the
patterns in `recon/analysis/cloud_signatures.py`. No flag, and no extra traffic: it reads evidence the scan
already has.

Recognized classes, with the finding each produces:

| Class | Examples | Finding | Severity |
|---|---|---|---|
| `object_storage` | S3, Azure Blob, GCS, Firebase Storage, R2, Spaces, B2, Wasabi, OSS | `cloud.object_storage_referenced` | low |
| `serverless_function` | Lambda Function URLs, API Gateway, Cloud Functions/Run, Azure Functions, Netlify/Vercel functions, Supabase edge functions | `cloud.serverless_endpoint` | low |
| `managed_database` | Supabase (PostgREST), Firebase RTDB, Firestore, Cosmos DB, Atlas, PlanetScale, Neon, Upstash, Hasura, AppSync | `cloud.backend_endpoint` | **medium** |
| `edge_worker` | Cloudflare Workers, Deno Deploy, Fastly Compute | `cloud.serverless_endpoint` | low |
| `hosting`, `auth`, `search`, `container` | Vercel, Netlify, Pages, App Service, Auth0, Clerk, Okta, Algolia, ACR | `cloud.inventory` | informational |

Both addressing styles resolve to the same bucket, so `bucket.s3.amazonaws.com/key` and
`s3.amazonaws.com/bucket/key` are one entry. Path-style signatures also separate same-host roles: on one
Supabase project ref, `/rest/v1/…` is the database, `/functions/v1/…` a function, and
`/storage/v1/object/public/…` a bucket.

Why `managed_database` is medium while a bucket reference is low: that pattern moves authorization entirely
into provider-side rules (row-level security, database/storage rules), the public client key ships in the
bundle by design, and a default-open policy exposes everything the endpoint can read. A bucket reference is
worth checking — buckets are the most common accidental-exposure class — but says nothing on its own.

**Nothing is requested.** SiteRecon cannot and does not claim a bucket is listable, that a function answers
anonymously, or that a resource still exists. Every cloud finding carries that limitation, and confirming
exposure is what the authorized `backend_read_access` and `function_url_reachability` checks in
[`siterecon active`](active.md) are for.

`public_by_default` marks resource classes that are world-readable unless explicitly restricted (S3, Azure
Blob, GCS, an `r2.dev` URL, Spaces) — a property of the class, not a finding about this deployment.

## How it reaches observations, findings and history

Everything above flows through the existing pipeline rather than beside it:

| Observation type | Provenance |
|---|---|
| `subdomain`, `subdomain.sources` | `ct_log`, `dns_query` (permutation-only) or `external_api` (passive-only), per name |
| `subdomain.coverage`, `subdomain.permutation` | which sources ran; what the permutation pass yielded |
| `cloud.resource` | `derived` — one per provider/kind/identifier |
| `historical.summary`, `.endpoints`, `.parameter`, `.technology`, `.sensitive_paths` | `external_api`, freshness `historical`, with the archive's last-seen as `observed_at` |

Because these are ordinary observations, the scan-to-scan diff picks them up for free: a new subdomain, a
new bucket in the client surface, or a newly archived endpoint appears as `added`. A module that failed or
was skipped still yields `unknown`, never `removed` — missing data is never mistaken for a fixed problem.

The confidence calibration pass also applies: a finding whose evidence is entirely stale or historical
external-provider data is weakened automatically, which is why `historical.*` findings settle at low or
medium confidence even when the extraction itself is certain.

Individual archived URLs are deliberately *not* recorded as observations. A URL set churns constantly, and
a diff of thousands of archived URLs would bury the real changes; the summary, endpoint surface, parameter
classes and hints are what stay comparable.
