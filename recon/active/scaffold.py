from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from recon.models import ReconReport

_FUNCTION_URL_CAP = 15


@dataclass(slots=True)
class BackendCandidate:
    '''
    A discovered backend that could be probed for anonymous read access.
    '''
    kind: str
    host: str | None = None
    project_id: str | None = None
    scope_host: str = ""


@dataclass(slots=True)
class Candidates:
    '''
    Everything the scaffold discovered, ready to render into a draft authorization.
    '''
    target: str
    scope_hosts: list[str] = field(default_factory=list)
    tls_hosts: list[str] = field(default_factory=list)
    backends: list[BackendCandidate] = field(default_factory=list)
    function_urls: list[str] = field(default_factory=list)


def _config_field(config, keys: tuple[str, ...]) -> str | None:
    '''
    Pull a non-sensitive value from a client config by field key (case-insensitive).
    Parameters:
        config (ClientConfig): The client configuration block.
        keys (tuple[str, ...]): Candidate field keys.
    Returns:
        str | None: The value, or None if absent or redacted.
    '''
    wanted = {k.lower() for k in keys}
    for fld in config.fields:
        if fld.key.lower() in wanted and not fld.sensitive:
            return fld.value
    return None


def discover_candidates(report: ReconReport) -> Candidates:
    '''
    Extract authorization candidates from a passive report's discovered assets.
    Parameters:
        report (ReconReport): A completed passive scan report.
    Returns:
        Candidates: Discovered scope hosts, backends and function-URL candidates.
    '''
    host = report.target.hostname
    candidates = Candidates(target=host, tls_hosts=[host])
    assets = report.javascript.data if report.javascript and report.javascript.data else None
    scope_hosts: list[str] = [host]
    if assets is None:
        candidates.scope_hosts = scope_hosts
        return candidates

    service_hosts = list(assets.service_hosts)
    supabase_host = next((h for h in service_hosts if h.endswith(".supabase.co")), None)
    seen: set[tuple[str, str]] = set()
    for asset in assets.assets:
        for config in asset.client_configs:
            if config.kind == "supabase" and supabase_host and ("supabase", supabase_host) not in seen:
                seen.add(("supabase", supabase_host))
                candidates.backends.append(BackendCandidate("supabase", host=supabase_host, scope_host=supabase_host))
            elif config.kind == "firebase":
                project_id = _config_field(config, ("projectId", "project_id"))
                if project_id and ("firebase", project_id) not in seen:
                    seen.add(("firebase", project_id))
                    candidates.backends.append(BackendCandidate(
                        "firebase", project_id=project_id, scope_host="firestore.googleapis.com"))

    endpoint_hosts: set[str] = set()
    for ref in assets.endpoints():
        if ref.host and ref.value.startswith(("http://", "https://")):
            if ref.value not in candidates.function_urls and len(candidates.function_urls) < _FUNCTION_URL_CAP:
                candidates.function_urls.append(ref.value)
            endpoint_hosts.add(ref.host)

    extra = {b.scope_host for b in candidates.backends if b.scope_host} | endpoint_hosts | set(service_hosts)
    candidates.scope_hosts = [host] + sorted(h for h in extra if h and h != host)
    return candidates


def _yaml_list(items: list[str], indent: str) -> list[str]: return [f'{indent}- "{i}"' for i in items]


def render_draft(candidates: Candidates, *, now: datetime | None = None) -> str:
    '''
    Render a draft authorization YAML from discovered candidates.

    Every check is left out of ``checks_enabled`` and every safety-critical field is left blank, so the
    draft is inert until the operator reviews it, confirms ownership, fills the blanks and opts checks in.
    Parameters:
        candidates (Candidates): Discovered candidates.
        now (datetime | None): Reference time for the window (defaults to now).
    Returns:
        str: The draft authorization as YAML text.
    '''
    moment = now or datetime.now(UTC)
    start = moment.replace(microsecond=0)
    end = (start + timedelta(hours=6))
    host = candidates.target
    lines: list[str] = [
        f"# DRAFT active-testing authorization for {host}, scaffolded from a passive scan.",
        "#",
        "# This is a DRAFT. SiteRecon pre-filled DISCOVERED candidates below, but nothing here runs yet:",
        "# checks_enabled is empty on purpose. Before enabling anything you MUST:",
        "#   1. Confirm you own / are authorized to test each host listed below (discovery is not ownership).",
        "#   2. Fill the blanks the tool cannot know (anon keys, table names, state_changing, etc.).",
        "#   3. Add the checks you want to run to checks_enabled, and set a real window and authorized_by.",
        "# Preview with: siterecon active " + host + " --authorization <this-file> --dry-run",
        "",
        f"target: {host}",
        'authorized_by: "FILL ME — your name / role (required)"',
        f'authorized_on: "{start.date().isoformat()}"',
        "",
        "# Wall-clock window; active testing is refused outside it. Adjust to your engagement.",
        "window:",
        f'  start: "{start.isoformat().replace("+00:00", "Z")}"',
        f'  end: "{end.isoformat().replace("+00:00", "Z")}"',
        "",
        "rate_limit_rps: 1.0",
        "max_requests: 100",
        "max_requests_per_check: 25",
        "",
        "# DISCOVERED hosts — REVIEW and remove any you do not own / are not authorized to test.",
        "scope:",
        "  hosts:",
        *_yaml_list(candidates.scope_hosts, "    "),
        "  exclude_hosts: []",
        "  tls_authorized_hosts:    # per-host opt-in required for tls_protocol_enum",
        *_yaml_list(candidates.tls_hosts, "    "),
        "",
        "# No checks run until you list them here (and confirm the config each needs below).",
        "checks_enabled: []",
        "#   - external_intelligence   # keyless third-party intel (Wayback + Shodan); discloses target to them",
        "#   - tls_protocol_enum       # uses tls_authorized_hosts above",
    ]
    if candidates.backends:
        lines.append("#   - backend_read_access     # after filling credentials + resources under backends:")
    if candidates.function_urls:
        lines.append("#   - function_url_reachability  # after reviewing function_urls:")
    lines += ["", "external_intelligence:", "  providers: [wayback, shodan_internetdb]", ""]

    lines += _render_backends(candidates.backends)
    lines += _render_function_urls(candidates.function_urls)
    lines += _render_manual_templates()
    return "\n".join(lines) + "\n"


def _render_backends(backends: list[BackendCandidate]) -> list[str]:
    '''
    Render the discovered backends block (or a commented template if none were found).
    Parameters:
        backends (list[BackendCandidate]): Discovered backends.
    Returns:
        list[str]: Rendered lines.
    '''
    if not backends:
        return [
            "# backends:   # none auto-discovered; add by hand if you know of a backend to test",
            "#   - kind: supabase",
            "#     host: yourref.supabase.co",
            '#     credential: "eyJ...PUBLIC-anon-key..."   # PUBLIC anon key ONLY',
            "#     resources: [profiles, items]",
            "",
        ]
    out = ['# DISCOVERED backends. Fill the public credential and the resources (tables/collections) to probe.',
           "backends:"]
    for backend in backends:
        if backend.kind == "supabase":
            out += [
                "  - kind: supabase",
                f"    host: {backend.host}",
                '    credential: "FILL ME — the public anon/publishable key from the site (private keys are rejected)"',
                "    resources: []           # FILL ME — table names to probe, e.g. [profiles, items]",
            ]
        elif backend.kind == "firebase":
            out += [
                "  - kind: firebase",
                f"    project_id: {backend.project_id}",
                "    database: firestore     # or realtime_db",
                "    credential: null        # often none needed to test the open case",
                "    resources: []           # FILL ME — collection names, e.g. [users, orders]",
            ]
    out.append("")
    return out


def _render_function_urls(urls: list[str]) -> list[str]:
    '''
    Render the discovered function-URL candidates (or a commented template if none).
    Parameters:
        urls (list[str]): Discovered absolute endpoint URLs.
    Returns:
        list[str]: Rendered lines.
    '''
    if not urls:
        return [
            "# function_urls:   # none auto-discovered",
            '#   - url: "https://api.example.com/order"',
            "#     method: OPTIONS",
            "#     state_changing: true",
            "",
        ]
    out = ["# DISCOVERED endpoints referenced in the site's bundles. REVIEW each: remove third-party URLs,",
           "# and set state_changing: true for any that modify server state.",
           "function_urls:"]
    for url in urls:
        out += [
            f'  - url: "{url}"',
            "    method: OPTIONS",
            "    state_changing: false   # FILL ME — true if calling this changes server state",
        ]
    out.append("")
    return out


def _render_manual_templates() -> list[str]:
    '''
    Render commented templates for the checks that cannot be auto-discovered (human-only safety labels).
    Returns:
        list[str]: Rendered lines.
    '''
    return [
        "# NOT auto-discoverable — add by hand. These carry safety labels only a human can set:",
        "#",
        "# ip_trust_endpoints:                 # does the app trust client-supplied IP headers?",
        '#   - url: "https://' + "HOST/admin\"",
        "#     method: GET",
        "#     access_control: true",
        "#",
        "# email_endpoints:                    # rate-limit probe; NEVER runs without the confirmation below",
        '#   - url: "https://HOST/api/notify"',
        "#     method: POST",
        "#     burst: 5",
        "#     confirmed_no_real_delivery: true   # REQUIRED; only YOU can confirm this cannot email a real person",
    ]


def build_authorization_draft(report: ReconReport, *, now: datetime | None = None) -> str: return render_draft(discover_candidates(report), now=now)
