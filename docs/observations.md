# The observation model

Every fact SiteRecon collects flows through one normalization unit — the **`Observation`** — and every
interpreted conclusion is a **`Finding`** that references the observations supporting it. Collectors
produce observations; they never produce findings directly. This is the contract the whole pipeline
(collection → analysis → reporting → comparison) is built on, and the one new collectors must use.

Schema version **2.1** added provenance and freshness to observations and a lifecycle state to findings.
All of it is additive with safe defaults, so reports written by 2.0 still load.

## What an observation records

Four independent axes keep "what we saw" honest. Confusing them is the usual way a recon tool overclaims.

| Axis | Field(s) | Question it answers | Values |
|---|---|---|---|
| **Provenance** | `source`, `collection_method`, `module`, `external_provider` | *How and where did we get this?* | `source` is human-readable; `collection_method` is the machine-readable mechanism (see below) |
| **Time** | `timestamp` (= `collected_at`), `observed_at`, `expires_at` | *When did we collect it, and when was it actually true?* | timezone-aware datetimes |
| **Confidence** | `confidence` | *How strong is the evidence?* | `low` / `medium` / `high` (= possible / probable / confirmed via `Confidence.label`) |
| **Freshness** | `freshness` | *How current is the value?* | `fresh` / `stale` / `historical` / `unknown` |

`limitations` holds what the observation explicitly *cannot* establish.

### `collection_method`

The mechanism behind the free-text `source`, so passive, external and active facts stay distinguishable.
Typed as `str` (a new collector can introduce a value without a model change); the known values are the
`CollectionMethod` enum:

`dns_query`, `network_lookup` (ASN/RDAP/PTR), `http_request`, `tls_handshake`, `whois_lookup`, `ct_log`,
`static_analysis` (parsing already-fetched HTML/JS, which is also how the SEO audit is stamped),
`derived` (inferred from other observations),
`external_api` (third-party provider), `browser_render` (Playwright), `port_connect`, `traceroute`,
`unknown`.

Passive collectors are stamped automatically in `ObservationBuilder._add` from the module name, and a
handler overrides that default where one module has several genuinely different provenances. Subdomain
discovery is the clearest case: the same `subdomain` observation type carries `ct_log` when a certificate
named the host, `external_api` when only a passive dataset knows it, and `dns_query` when the name was
generated locally and confirmed by a lookup. External-intelligence and active collectors set their own
method (and, for providers, `external_provider` and `expires_at`).

### Confidence vs. freshness vs. source

Three things that are easy to conflate:

- **Confidence** is evidence strength, *not* the reputation of the source. A high-reputation provider
  returning a weak signal is still low confidence.
- **Freshness** is about the information, not the finding. A Wayback snapshot or a cached Shodan answer is
  `historical`/`stale` even when it was retrieved correctly a second ago — so it is never presented as the
  current state. Directly-collected passive observations are `fresh` as produced.
- `evaluate_freshness(now, stale_after)` computes freshness without mutating: `historical` when
  `observed_at` predates collection by more than the window, `stale` past `expires_at` (or past
  `stale_after` from `collected_at`), `fresh` within the window, `unknown` when there is no basis.

## Finding lifecycle

A finding's `state` is **orthogonal** to its severity (how bad) and confidence (how strong). States:

| State | Meaning |
|---|---|
| `suspected` | initial evidence suggests a potential issue |
| `corroborated` | multiple independent observations support it |
| `confirmed` | evidence is sufficient to establish the issue |
| `false_positive` | reviewed and dismissed |
| `resolved` | previously detected, no longer observed |
| `unknown` | current evidence is insufficient to determine status |

When a producer does not set `state`, it is derived from confidence on construction:
`low → suspected`, otherwise `confirmed` (`FindingState.from_confidence`). `corroborated`, `resolved` and
`false_positive` depend on cross-source correlation or history and are assigned **only** by the analysis
engine — a single collector never invents them.

> **A missing observation is not evidence that an issue is resolved.** The scan comparison already reports
> data absent from either scan (failed/partial/skipped modules) as `unknown`, never `removed`; the
> `resolved` state follows the same rule — it requires prior positive evidence that is now genuinely gone.

## Regression detection across scans

When history is on, each scan is compared with the previous stored scan of the same target at two levels:
the **observations** (`report.comparison` — added/removed/modified/unchanged/unknown) and the **findings**
(`report.finding_changes` — a `FindingDelta` of `new` / `persisting` / `resolved`).

Because the analysis engine already turns a weakened posture into findings (a dropped HSTS header, a legacy
TLS version, an insecure cookie, a newly exposed port), a finding that is **new** since the last scan is,
generically, a **regression**; one that is **gone** is a fix. The analyzer also updates lifecycle states:
a finding reproduced across scans (or backed by two or more modules' observations) becomes `corroborated`;
a finding that disappeared becomes `resolved` — **only** when the module(s) that produce its category ran
successfully this scan, so missing data is never mistaken for a fix.

### Named change findings

Beyond the generic new/resolved tracking, the specific security-relevant transitions are named as
`regression.*` findings with the before/after in the evidence: `security_header_removed` (e.g. HSTS gone),
`cookie_weakened` (Secure/HttpOnly dropped), `tls_downgrade`, `dnssec_disabled`, `caa_removed`,
`new_subdomain`. These are transient — they fire on the scan where the change happened — and only on a
genuine regression (a TLS *upgrade* produces nothing).

### Gating CI on a regression

The `scan` command exposes two gates (exit code **3**):

- `--fail-on <severity>` — fail if **any** finding is at least that severe (a standard gate).
- `--fail-on-new <severity>` — fail only on findings **new since the previous scan** at least that severe:
  a **regression ratchet**, so a baseline with known issues stays green until the posture actually
  regresses. With no previous scan there is nothing to compare, so it exits 0 (the first run bootstraps).

```bash
siterecon scan example.com --fail-on-new high     # go red only when a new high-severity issue appears
```

The "previous scan" is just the last stored scan in `reports/` (scan history). On your machine that
persists between runs; in CI, cache or persist the `reports/` directory between runs (standard build
caching) and the comparison works the same way — no special baseline flag needed.

## Correlation and calibration

Two small passes run at the end of analysis, before the findings are reported:

- **Correlation** collapses findings that describe the same issue on the same subject but were surfaced by
  more than one module into a single finding, merging their evidence (findings are already de-duplicated
  by code and subject upstream; this catches the same issue reported under different codes).
- **Calibration** lowers a finding's confidence by one level when *all* of its supporting evidence is stale
  or historical external-provider data — such data is less certain than a live observation. Fresh or
  multi-sourced evidence is left alone. This is why `historical.*` findings (built entirely from web
  archives) settle at low or medium confidence even when the extraction itself is exact: the extraction is
  certain, the third party's record of the past is not.

## For new collectors

- Emit `Observation`s through the normalization pipeline; set `collection_method` (and `external_provider`
  / `expires_at` / `observed_at` for provider data) rather than leaving them `unknown`.
- Set `freshness` honestly: `fresh` only for a value collected directly and now; `historical`/`stale` for
  archived or cached provider data.
- Build `Finding`s with evidence and `evidence_refs`; let `state` derive from `confidence` unless you have
  a reason to set it.
- Keep secrets and session material out of observations — store a type and fingerprint, never the value.
  This applies to data retrieved *about* the target too: an archived URL can carry a real token in its query
  string, so the `historical` module redacts query values and records parameter names only.
- Summarize high-churn collections rather than emitting one observation per item. Archived URLs are a
  worked example: the summary, endpoint surface, parameter classes and technology hints are comparable
  across scans, while a per-URL diff of thousands of archive entries would bury the real changes.
