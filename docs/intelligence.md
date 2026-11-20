# External intelligence

External intelligence queries third-party providers **about** the target (its domain and resolved IPs)
rather than probing the target itself. Because contacting those providers *discloses the target to them*,
it runs as part of **`siterecon active`** and is gated by the authorization file — the same explicit,
windowed, audited permission as any other active capability. It is never part of the passive `scan`.

Everything a provider returns is an ordinary finding, so it flows through the active report alongside the
other checks, clearly attributed to its provider and marked as historical/indexed estimates.

## Enabling it

List `external_intelligence` in the authorization's `checks_enabled`:

```yaml
checks_enabled:
  - external_intelligence
# optional — restrict which providers run (default: all keyless providers):
external_intelligence:
  providers: [wayback, shodan_internetdb]
```

Then run the active command as usual:

```bash
siterecon active example.com --authorization auth.yaml
```

The passive scan the active command runs first supplies the resolved IPs the IP-keyed providers need. With
`--no-passive` and no stored IPs, host-only providers (Wayback) still run and IP-keyed ones (Shodan) skip.

## Providers (keyless — no account, no API key)

| Provider | Needs | What it adds |
|---|---|---|
| **Wayback Machine** (Internet Archive) | the domain | Archived-URL history; flags sensitive-looking archived paths (backups, dumps, config/secret files) once public. |
| **Shodan InternetDB** | resolved IPs | Per IP: open ports, CVE *candidates*, CPEs and hostnames from Shodan's index. |

Both are keyless. The provider interface (`recon/intel/base.py`) carries a `requires_key` flag and an
`unavailable()` check, so key-gated providers (Google Safe Browsing, abuse.ch, Have I Been Pwned, full
Shodan) can be added later as optional, disabled-without-a-key providers.

> **Wayback appears in two places, deliberately.** The provider above asks the archive one question —
> "how long has this domain been archived, and were sensitive-looking paths ever public?" — as part of an
> authorized active engagement. The passive `historical` module (`scan --historical`) asks the archives for
> the URLs themselves and mines them for the endpoint, parameter and legacy-technology surface; it also
> covers Common Crawl, urlscan.io and OTX. They are independent: enabling both makes two requests to the
> archive for different data. See [passive-discovery.md](passive-discovery.md).

## Audit and safety

- **It runs only when authorized.** No `external_intelligence` in `checks_enabled` → no third-party
  contact. The engagement window and authorization apply.
- **Full audit log.** Although providers use a separate client scoped to their own hosts (never the
  target's scope), every provider request is recorded in the engagement audit log and counted toward the
  request total, so the log stays complete.
- **Fail-soft.** A missing input, a provider outage or an unparseable response skips/fails that provider
  only — never the run.
- **Disclosure.** Running it sends the target's domain (Wayback) and resolved IPs (Shodan) to those
  providers. That is the cost of external intelligence, which is why it is gated.

## Honesty rules (in the findings)

- **Historical ≠ current** (Wayback): an archived path is evidence a file *was* reachable, not that it
  still is — verify, and rotate any credential that may have been exposed.
- **Indexed ≠ exposed now** (Shodan): the index refreshes ~weekly, a shared IP may host unrelated domains,
  and indexed hostnames are not verified as the target's.
- **CVE candidates are not confirmed** (Shodan): version-matched CVEs include false positives and are
  marked low confidence — verify against the deployed software before acting.
