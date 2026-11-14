'''
Automated discover-and-test: synthesize an effective authorization from a passive scan.

Given a committed ``auto_discover`` authorization (the operator's standing assertion that they own certain
registrable domains), this turns what the passive scan found into the concrete targets the active checks
run against, with no per-run human step, so it fits a CI pipeline.

The boundary is enforced here and is deliberate: a discovered host is tested only if its registrable
domain is one the operator authorized — except, in ``complete`` mode (local ``--bypass-sec``), the backends
the authorized site itself embeds (its own Supabase/Firebase config), which are the operator's by
construction. Unrelated third-party hosts are always returned as "discovered, not tested" and never probed.
Email bursting is never synthesized, in any mode.
'''

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from recon.active.authorization import (
    ActiveScope,
    AuthorizationFile,
    AutoDiscover,
    Backend,
    FirebaseBackend,
    FunctionUrlTarget,
    IpTrustTarget,
    SupabaseBackend,
)
from recon.models import ReconReport
from recon.utils import registrable_domain

# Checks run when auto_discover.checks is unset (standing/CI mode): safe and non-destructive.
DEFAULT_SAFE_CHECKS: tuple[str, ...] = ("tls_protocol_enum", "function_url_reachability", "external_intelligence")
# Checks run in complete mode (local --bypass-sec): everything EXCEPT email bursting.
COMPLETE_CHECKS: tuple[str, ...] = ("tls_protocol_enum", "function_url_reachability", "client_ip_header_trust",
                                    "backend_read_access", "external_intelligence")
_FUNCTION_URL_CAP = 25
_SUPABASE_TABLE: re.Pattern[str] = re.compile(r"/rest/v1/([A-Za-z0-9_]+)")


@dataclass(slots=True)
class Synthesis:
    '''
    The concrete first-party targets synthesized from a passive scan, plus what was left out.
    '''
    scope_hosts: list[str] = field(default_factory=list)
    tls_hosts: list[str] = field(default_factory=list)
    function_urls: list[FunctionUrlTarget] = field(default_factory=list)
    ip_trust_endpoints: list[IpTrustTarget] = field(default_factory=list)
    backends: list[Backend] = field(default_factory=list)
    checks: list[str] = field(default_factory=list)
    third_party_hosts: list[str] = field(default_factory=list)


def _field_value(config, key: str) -> str | None:
    '''
    Read a client-config field value by key, or None.
    Parameters:
        config (ClientConfig): The config block.
        key (str): Field key.
    Returns:
        str | None: The value, or None.
    '''
    return next((f.value for f in config.fields if f.key == key), None)


def _supabase_backends(assets, authorized_host_tables: dict[str, set[str]]) -> list[SupabaseBackend]:
    '''
    Build Supabase backend targets from embedded configs, using the retained anon key and discovered tables.
    Parameters:
        assets (AssetData): The static-asset analysis.
        authorized_host_tables (dict[str, set[str]]): Supabase host → table names discovered in endpoints.
    Returns:
        list[SupabaseBackend]: Backends with a credential and resources (skipped later if either is empty).
    '''
    out: dict[str, SupabaseBackend] = {}
    for asset in assets.assets:
        for config in asset.client_configs:
            if config.kind != "supabase":
                continue
            ref = _field_value(config, "projectRef")
            host = f"{ref}.supabase.co" if ref else (urlsplit(_field_value(config, "url") or "").hostname or "")
            credential = _field_value(config, "anonKey")
            if not host or not credential or host in out:
                continue
            tables = sorted(authorized_host_tables.get(host, set()))
            out[host] = SupabaseBackend(host=host, credential=credential, resources=tables)
    return list(out.values())


def synthesize(auto: AutoDiscover, *, target: str, report: ReconReport | None,
               complete: bool = False) -> Synthesis:
    '''
    Build the effective targets for an automated run.
    Parameters:
        auto (AutoDiscover): The committed auto-discover authorization (the ownership boundary).
        target (str): The target hostname.
        report (ReconReport | None): The passive scan report, or None (e.g. --no-passive) for a minimal run.
        complete (bool): When True (local --bypass-sec), also synthesize embedded backends and IP-trust
            targets and run the complete check set except email.
    Returns:
        Synthesis: First-party targets, the checks to run, and third-party hosts skipped.
    '''
    authorized = set(auto.authorized_domains)

    def first_party(host: str | None) -> bool:
        if not host:
            return False
        return registrable_domain(host.lower().rstrip(".")) in authorized

    tls_hosts: set[str] = {target} if first_party(target) else set()
    function_urls: dict[str, FunctionUrlTarget] = {}
    third_party: set[str] = set()
    supabase_tables: dict[str, set[str]] = {}

    assets = report.javascript.data if (report and report.javascript and report.javascript.data) else None
    if assets is not None:
        for ref in assets.endpoints():
            if not (ref.host and ref.value.startswith(("http://", "https://"))):
                continue
            if first_party(ref.host):
                function_urls.setdefault(ref.value, FunctionUrlTarget(url=ref.value, method="OPTIONS",
                                                                      state_changing=False))
            else:
                third_party.add(ref.host)
                if ref.host.endswith(".supabase.co"):   # a table referenced on an embedded Supabase backend
                    table = _SUPABASE_TABLE.search(urlsplit(ref.value).path)
                    if table:
                        supabase_tables.setdefault(ref.host, set()).add(table.group(1))

    urls = list(function_urls.values())[:_FUNCTION_URL_CAP]
    ip_trust = ([IpTrustTarget(url=f.url, method="GET") for f in urls] if complete else [])
    backends: list[Backend] = (list(_supabase_backends(assets, supabase_tables))
                               if complete and assets is not None else [])

    # Backend hosts (the operator's own embedded Supabase/Firebase) join the scope so the check can reach them,
    # and are removed from the "third-party, not tested" list since they ARE tested as first-party backends.
    backend_hosts = {b.host for b in backends if isinstance(b, SupabaseBackend)} | {
        "firestore.googleapis.com" for b in backends if isinstance(b, FirebaseBackend)}
    third_party -= backend_hosts
    scope_hosts = sorted(tls_hosts | {h for f in urls if (h := urlsplit(f.url).hostname)} | backend_hosts)

    base_checks = list(auto.checks) or list(COMPLETE_CHECKS if complete else DEFAULT_SAFE_CHECKS)
    drop = {"function_url_reachability": not urls, "tls_protocol_enum": not tls_hosts,
            "client_ip_header_trust": not ip_trust, "backend_read_access": not backends,
            "email_endpoint_rate_limit": True}   # never auto-run email bursting
    checks = [c for c in base_checks if not drop.get(c, False)]
    return Synthesis(scope_hosts=scope_hosts or ([target] if first_party(target) else []),
                     tls_hosts=sorted(tls_hosts), function_urls=urls, ip_trust_endpoints=ip_trust,
                     backends=backends, checks=checks, third_party_hosts=sorted(third_party))


def apply_synthesis(auth: AuthorizationFile, synthesis: Synthesis) -> AuthorizationFile:
    '''
    Fold synthesized targets into a copy of the authorization, producing the effective authorization to run.
    Parameters:
        auth (AuthorizationFile): The committed authorization (with auto_discover).
        synthesis (Synthesis): The synthesized targets.
    Returns:
        AuthorizationFile: An effective authorization with scope, targets and checks filled.
    '''
    scope = ActiveScope(
        hosts=sorted(set(auth.scope.hosts) | set(synthesis.scope_hosts)),
        exclude_hosts=list(auth.scope.exclude_hosts),
        tls_authorized_hosts=sorted(set(auth.scope.tls_authorized_hosts) | set(synthesis.tls_hosts)))
    checks = list(dict.fromkeys([*auth.checks_enabled, *synthesis.checks]))
    return auth.model_copy(update={
        "scope": scope,
        "function_urls": [*auth.function_urls, *synthesis.function_urls],
        "ip_trust_endpoints": [*auth.ip_trust_endpoints, *synthesis.ip_trust_endpoints],
        "backends": [*auth.backends, *synthesis.backends],
        "checks_enabled": checks})
