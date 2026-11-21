'''
Subdomain discovery from public Certificate Transparency logs (crt.sh and Cert Spotter) plus optional
passive datasets (OTX, urlscan.io, Common Crawl, Wayback, RapidDNS, HackerTarget, Anubis, BufferOver),
with a local cache for provider outages and optional DNS / HTTPS / TLS verification.

Three discovery paths, in order of how much they are trusted:
  * **Certificate Transparency** — always on; a certificate publicly names the host.
  * **Passive datasets** — opt-in per source (``--subdomain-source``), because each discloses the target
    domain to another third party. What they return is a lead, verified here in DNS like any other name.
  * **Controlled permutation** — opt-in (``--permute-subdomains``); candidate names built from the labels
    already discovered plus a small fixed wordlist, hard-capped, scope-checked, and resolved in DNS only.
    Only names that actually resolve are kept, so this is name confirmation rather than brute-forcing: no
    HTTP request is ever sent to a generated name, and nothing unresolved is reported.
'''

from __future__ import annotations

import asyncio
import json
import re
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import quote

import httpx
from pydantic import BaseModel

from recon.analysis.takeover import match_cname
from recon.models import CollectionError, DnsQueryStatus, SubdomainData, SubdomainRecord, TlsProbe
from recon.models.subdomains import (
    CtEntry,
    HostState,
    PassiveEntry,
    PermutationStats,
    ProviderResult,
    SourceKind,
)
from recon.modules.base import Collector
from recon.modules.sources import SourceError, fetch_json
from recon.modules.subdomain_sources import PassiveSource, in_scope_names
from recon.utils import (
    BlockedRequestError,
    DnsClient,
    SafeHttpClient,
    Scope,
    is_public_ip,
    normalize_discovered,
)

TlsProbeFn = Callable[[str], Awaitable[TlsProbe]]


class CtProviderError(SourceError):
    '''
    Raised when a CT provider cannot return complete results.
    '''


class CtProvider(ABC):
    '''
    A Certificate Transparency search provider.
    '''

    name: ClassVar[str]
    HOSTS: ClassVar[tuple[str, ...]]

    @abstractmethod
    async def fetch(self, client: SafeHttpClient, hostname: str) -> list[CtEntry]:
        '''
        Return certificates covering the hostname and its subdomains.
        Parameters:
            client (SafeHttpClient): Client scoped to the provider hosts.
            hostname (str): Target hostname.
        Returns:
            list[CtEntry]: Normalized certificate entries.
        Raises:
            CtProviderError: If the provider fails or returns unusable data.
        '''

    @staticmethod
    async def _get_json(client: SafeHttpClient, url: str) -> Any:
        '''
        GET a URL and decode JSON, rejecting failures and truncated bodies.
        Parameters:
            client (SafeHttpClient): Provider-scoped client.
            url (str): URL to fetch.
        Returns:
            Any: Decoded JSON.
        Raises:
            CtProviderError: On HTTP failure, truncation or invalid JSON.
        '''
        try:
            return await fetch_json(client, url)
        except SourceError as exc:
            raise CtProviderError(str(exc)) from exc

    @staticmethod
    def _time(value: Any) -> datetime | None:
        '''
        Parse an ISO timestamp, assuming UTC when no offset is present.
        Parameters:
            value (Any): Raw timestamp value.
        Returns:
            datetime | None: The datetime, or None if unparseable.
        '''
        if not value:
            return None
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


class CrtShProvider(CtProvider):
    '''
    crt.sh JSON search (https://crt.sh/).
    '''

    name: ClassVar[str] = "crt.sh"
    HOSTS: ClassVar[tuple[str, ...]] = ("crt.sh",)
    URL: ClassVar[str] = "https://crt.sh/?q={query}&output=json"

    async def fetch(self, client: SafeHttpClient, hostname: str) -> list[CtEntry]:
        '''
        Query crt.sh for '%.<hostname>'.
        Parameters:
            client (SafeHttpClient): Provider-scoped client.
            hostname (str): Target hostname.
        Returns:
            list[CtEntry]: Normalized entries.
        Raises:
            CtProviderError: On failure.
        '''
        data = await self._get_json(client, self.URL.format(query=quote(f"%.{hostname}")))
        if not isinstance(data, list):
            raise CtProviderError("unexpected response shape")
        entries = []
        for e in data:
            names = [n for n in str(e.get("name_value", "")).split("\n") if n]
            if e.get("common_name"):
                names.append(str(e["common_name"]))
            entries.append(CtEntry(
                provider=self.name, cert_id=str(e["id"]) if e.get("id") is not None else None, names=names,
                issuer=self._issuer_org(str(e.get("issuer_name", ""))),
                not_before=self._time(e.get("not_before")), not_after=self._time(e.get("not_after"))))
        return entries

    @staticmethod
    def _issuer_org(issuer_dn: str) -> str | None:
        '''
        Extract the O= component from an issuer distinguished name.
        Parameters:
            issuer_dn (str): Issuer DN string.
        Returns:
            str | None: Organization name, the full DN as fallback, or None.
        '''
        for part in issuer_dn.split(","):
            key, _, value = part.strip().partition("=")
            if key.strip().upper() == "O" and value:
                return value.strip().strip('"')
        return issuer_dn or None


class CertSpotterProvider(CtProvider):
    '''
    SSLMate Cert Spotter issuances API (unauthenticated tier, rate-limited).
    '''

    name: ClassVar[str] = "certspotter"
    HOSTS: ClassVar[tuple[str, ...]] = ("api.certspotter.com",)
    URL: ClassVar[str] = ("https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true"
                          "&expand=dns_names&expand=issuer")
    MAX_PAGES: ClassVar[int] = 5

    async def fetch(self, client: SafeHttpClient, hostname: str) -> list[CtEntry]:
        '''
        Query Cert Spotter, following 'after' pagination up to MAX_PAGES.
        Parameters:
            client (SafeHttpClient): Provider-scoped client.
            hostname (str): Target hostname.
        Returns:
            list[CtEntry]: Normalized entries.
        Raises:
            CtProviderError: On failure.
        '''
        entries: list[CtEntry] = []
        after: str | None = None
        for _ in range(self.MAX_PAGES):
            url = self.URL.format(domain=quote(hostname)) + (f"&after={quote(after)}" if after else "")
            page = await self._get_json(client, url)
            if not isinstance(page, list):
                raise CtProviderError("unexpected response shape")
            if not page:
                break
            for e in page:
                issuer = e.get("issuer") or {}
                entries.append(CtEntry(
                    provider=self.name, cert_id=str(e.get("id")) if e.get("id") is not None else None,
                    names=[str(n) for n in e.get("dns_names", []) or []],
                    issuer=(issuer.get("friendly_name") or issuer.get("name")) if isinstance(issuer, dict) else None,
                    not_before=self._time(e.get("not_before")), not_after=self._time(e.get("not_after"))))
            after = str(page[-1].get("id")) if page[-1].get("id") is not None else None
            if after is None:
                break
        return entries


class SourceCache[E: BaseModel]:
    '''
    JSON cache of one source's entries per (source, hostname), used when a live source fails.

    Caching exists so a provider outage degrades to slightly stale coverage instead of no coverage, which
    is why a cached result is always labelled as such (``cache:<source>``) and is refused once older than
    the TTL. Writes are best-effort: a cache that cannot be written never fails a scan.
    '''

    subdir: ClassVar[str] = "ct"

    def __init__(self, directory: Path | None, ttl: timedelta, model: type[E]) -> None:
        '''
        Create a cache.
        Parameters:
            directory (Path | None): Cache directory; None disables caching.
            ttl (timedelta): Maximum age of cached results that may be used.
            model (type[E]): Pydantic model the cached entries are validated against.
        '''
        self.directory = directory
        self.ttl = ttl
        self.model = model

    def _path(self, provider: str, hostname: str) -> Path | None:
        '''
        Cache file for a source and hostname.
        Parameters:
            provider (str): Source name.
            hostname (str): Target hostname.
        Returns:
            Path | None: File path, or None when caching is disabled.
        '''
        if self.directory is None:
            return None
        safe = "".join(c if c.isalnum() or c in ".-" else "_" for c in f"{provider}__{hostname}")
        return self.directory / self.subdir / f"{safe}.json"

    def save(self, provider: str, hostname: str, entries: list[E]) -> None:
        '''
        Store entries; failures to write are ignored (the cache is best-effort).
        Parameters:
            provider (str): Source name.
            hostname (str): Target hostname.
            entries (list[E]): Entries to store.
        '''
        path = self._path(provider, hostname)
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = {"saved_at": datetime.now(UTC).isoformat(),
                       "entries": [e.model_dump(mode="json") for e in entries]}
            path.write_text(json.dumps(payload), encoding="utf-8")
        except OSError:
            pass

    def load(self, provider: str, hostname: str, now: datetime) -> tuple[list[E], datetime] | None:
        '''
        Return cached entries if present and fresher than the TTL.
        Parameters:
            provider (str): Source name.
            hostname (str): Target hostname.
            now (datetime): Current time.
        Returns:
            tuple[list[E], datetime] | None: Entries and when they were saved, or None.
        '''
        path = self._path(provider, hostname)
        if path is None or not path.is_file():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            saved_at = datetime.fromisoformat(payload["saved_at"])
            entries = [self.model.model_validate(e) for e in payload["entries"]]
        except (OSError, ValueError, KeyError, TypeError):
            return None
        if now - saved_at > self.ttl:
            return None
        return entries, saved_at


class CtCache(SourceCache[CtEntry]):
    '''
    Cache of Certificate Transparency entries.
    '''

    subdir: ClassVar[str] = "ct"

    def __init__(self, directory: Path | None, ttl: timedelta) -> None:
        '''
        Create the CT cache.
        Parameters:
            directory (Path | None): Cache directory; None disables caching.
            ttl (timedelta): Maximum age of cached results that may be used.
        '''
        super().__init__(directory, ttl, CtEntry)


class PassiveCache(SourceCache[PassiveEntry]):
    '''
    Cache of passive-source entries, kept separate from the CT cache so the two never mix.
    '''

    subdir: ClassVar[str] = "passive"

    def __init__(self, directory: Path | None, ttl: timedelta) -> None:
        '''
        Create the passive-source cache.
        Parameters:
            directory (Path | None): Cache directory; None disables caching.
            ttl (timedelta): Maximum age of cached results that may be used.
        '''
        super().__init__(directory, ttl, PassiveEntry)


class SubdomainPermuter:
    '''
    Builds a small, bounded set of candidate hostnames from the names already discovered.

    This is the only discovery path that generates names rather than reading them from a dataset, so it is
    deliberately conservative:
      * candidates come from the *observed* label structure (environment words applied to the zones that
        actually exist, and mutations of labels that were actually seen), not from a large dictionary;
      * the wordlist is small and fixed — this is not a brute-force list, and it is not extended at run time;
      * every candidate is scope-checked against the target before it is ever resolved;
      * the total is hard-capped by the caller, and the cap is reported along with whether it truncated;
      * generation is pure (no I/O) — the collector decides what, if anything, to resolve.
    '''

    # Small, fixed set of environment/function words. Kept short on purpose: the goal is to catch the
    # staging host nobody inventoried, not to enumerate a namespace.
    WORDS: ClassVar[tuple[str, ...]] = (
        "dev", "development", "staging", "stage", "test", "testing", "qa", "uat", "sandbox", "demo",
        "preview", "beta", "alpha", "canary", "prod", "production", "internal", "intranet", "corp",
        "admin", "administrator", "portal", "dashboard", "console", "manage", "api", "api-dev", "api-staging",
        "app", "web", "www2", "mobile", "m", "auth", "login", "sso", "id", "accounts", "oauth",
        "static", "assets", "cdn", "img", "images", "media", "files", "uploads", "download", "docs",
        "mail", "smtp", "imap", "webmail", "mx", "ns1", "ns2", "vpn", "remote", "gateway", "gw", "proxy",
        "git", "gitlab", "jenkins", "ci", "cd", "build", "registry", "nexus", "artifacts",
        "grafana", "kibana", "prometheus", "monitor", "monitoring", "metrics", "status", "logs", "log",
        "db", "database", "mysql", "postgres", "redis", "mongo", "elastic", "search", "queue", "cache",
        "backup", "backups", "archive", "legacy", "old", "new", "v1", "v2", "v3", "blog", "shop", "store",
        "pay", "payments", "billing", "invoice", "support", "help", "helpdesk", "crm", "erp", "hr",
        "data", "analytics", "reports", "ml", "ai", "k8s", "cluster", "edge", "lb", "origin",
    )
    # Suffix/prefix mutations applied to labels that were actually observed (e.g. api → api-dev, api2).
    AFFIXES: ClassVar[tuple[str, ...]] = ("dev", "staging", "test", "qa", "prod", "internal", "new", "old",
                                          "v2", "beta", "1", "2", "3")

    def __init__(self, hostname: str, scope: Scope, *, words: tuple[str, ...] | None = None) -> None:
        '''
        Create a permuter for one target.
        Parameters:
            hostname (str): Normalized target hostname.
            scope (Scope): Authorized scope every candidate must satisfy.
            words (tuple[str, ...] | None): Wordlist override (tests); defaults to WORDS.
        '''
        self.hostname = hostname
        self.scope = scope
        self.words = words if words is not None else self.WORDS

    def generate(self, known: list[str], limit: int) -> tuple[list[str], int]:
        '''
        Build candidate hostnames from the known names, excluding names already known.

        Candidates are produced in priority order — environment words on the target apex, then on each
        discovered sub-zone, then mutations of observed labels — so a tight limit keeps the most valuable
        candidates rather than an arbitrary slice.
        Parameters:
            known (list[str]): Hostnames already discovered (any source).
            limit (int): Maximum candidates to return; 0 disables generation.
        Returns:
            tuple[list[str], int]: The capped candidate list and the total number generated before capping.
        '''
        if limit <= 0:
            return [], 0
        existing = {h.lower().rstrip(".") for h in known} | {self.hostname}
        candidates: dict[str, None] = {}
        for base in self._bases(existing):
            for word in self.words:
                self._offer(candidates, f"{word}.{base}", existing)
        for host in sorted(existing):
            for mutation in self._mutations(host):
                self._offer(candidates, mutation, existing)
        total = len(candidates)
        return list(candidates)[:limit], total

    def _bases(self, known: set[str]) -> list[str]:
        '''
        Zones to apply the wordlist to: the target itself plus each parent zone of a discovered name that
        is still inside the target (so ``a.eu.example.com`` contributes ``eu.example.com``).
        Parameters:
            known (set[str]): Known hostnames.
        Returns:
            list[str]: Distinct base zones, shortest first.
        '''
        bases: dict[str, None] = {self.hostname: None}
        for host in known:
            labels = host.split(".")
            for index in range(1, len(labels) - 1):
                parent = ".".join(labels[index:])
                if parent != self.hostname and self.scope.allows(parent) and parent.endswith("." + self.hostname):
                    bases.setdefault(parent, None)
        return sorted(bases, key=lambda b: (b.count("."), b))

    def _mutations(self, host: str) -> list[str]:
        '''
        Affix mutations of a hostname's leftmost label (api → api-dev, api2, dev-api).
        Parameters:
            host (str): An observed hostname.
        Returns:
            list[str]: Candidate hostnames.
        '''
        label, _, parent = host.partition(".")
        if not parent or not label or label == "*":
            return []
        stem = re.sub(r"[-_]?(?:\d+|dev|staging|test|qa|prod)$", "", label) or label
        out: list[str] = []
        for affix in self.AFFIXES:
            joiner = "" if affix.isdigit() else "-"
            out.append(f"{stem}{joiner}{affix}.{parent}")
            if not affix.isdigit():
                out.append(f"{affix}-{stem}.{parent}")
        return out

    def _offer(self, candidates: dict[str, None], name: str, existing: set[str]) -> None:
        '''
        Record a candidate when it is new, in scope and a usable hostname.
        Parameters:
            candidates (dict[str, None]): Ordered candidate accumulator, updated in place.
            name (str): Candidate hostname.
            existing (set[str]): Names already known (never re-offered).
        '''
        normalized = normalize_discovered(name)
        if normalized is None:
            return
        host, wildcard = normalized
        if wildcard or host in existing or host in candidates:
            return
        if not self.scope.allows(host) or len(host) > 253:
            return
        candidates[host] = None


class SubdomainCollector(Collector[SubdomainData]):
    '''
    Discovers in-scope names from CT providers and (optionally) passive datasets and controlled
    permutation, then verifies them via DNS (and optionally HTTPS/TLS).
    '''

    name: ClassVar[str] = "subdomains"
    PROVIDERS: ClassVar[tuple[type[CtProvider], ...]] = (CrtShProvider, CertSpotterProvider)
    CT_SCOPE: ClassVar[Scope] = Scope(hosts=[h for p in (CrtShProvider, CertSpotterProvider) for h in p.HOSTS])

    def __init__(
        self,
        hostname: str,
        ct_client: SafeHttpClient,
        dns_client: DnsClient,
        *,
        verify_limit: int = 100,
        http_client: SafeHttpClient | None = None,
        tls_probe: TlsProbeFn | None = None,
        providers: list[CtProvider] | None = None,
        cache: CtCache | None = None,
        now: datetime | None = None,
        passive_client: SafeHttpClient | None = None,
        passive_sources: list[PassiveSource] | None = None,
        passive_cache: PassiveCache | None = None,
        permute: bool = False,
        permutation_limit: int = 0,
    ) -> None:
        '''
        Create the collector.
        Parameters:
            hostname (str): Normalized target hostname.
            ct_client (SafeHttpClient): HTTP client scoped to the CT provider hosts.
            dns_client (DnsClient): DNS client used for verification.
            verify_limit (int): Maximum names to verify.
            http_client (SafeHttpClient | None): Target-scoped client for HTTPS checks, or None to skip them.
            tls_probe (TlsProbeFn | None): Coroutine function performing a TLS check, or None to skip it.
            providers (list[CtProvider] | None): CT providers to query; defaults to all known providers.
            cache (CtCache | None): CT result cache; None disables caching.
            now (datetime | None): Reference time for cache freshness; defaults to the current UTC time.
            passive_client (SafeHttpClient | None): Client scoped to the enabled passive sources' hosts,
                or None when no passive source is enabled.
            passive_sources (list[PassiveSource] | None): Passive sources to query; None/empty means
                Certificate Transparency only.
            passive_cache (PassiveCache | None): Passive-source result cache; None disables caching.
            permute (bool): Generate and DNS-confirm candidate names from the discovered labels.
            permutation_limit (int): Hard cap on candidates resolved when permutation is enabled.
        '''
        self.hostname = hostname
        self.ct_client = ct_client
        self.dns_client = dns_client
        self.verify_limit = verify_limit
        self.http_client = http_client
        self.tls_probe = tls_probe
        self.providers = providers if providers is not None else [p() for p in self.PROVIDERS]
        self.cache = cache or CtCache(None, timedelta(0))
        self.now = now
        self.passive_client = passive_client
        self.passive_sources = list(passive_sources or [])
        self.passive_cache = passive_cache or PassiveCache(None, timedelta(0))
        self.permute = permute
        self.permutation_limit = max(0, permutation_limit)
        self.scope = Scope.for_target(hostname)
        self._candidates: list[str] = []      # generated candidates actually resolved
        self._generated_total = 0             # candidates generated before the cap was applied
        self._dropped: set[str] = set()       # distinct out-of-scope names a passive source returned

    async def collect(self) -> tuple[SubdomainData, list[CollectionError]]:
        '''
        Query every enabled source concurrently, merge results, optionally confirm generated candidates,
        then verify up to the limit.
        Returns:
            tuple[SubdomainData, list[CollectionError]]: Discovery results and source/verification errors.
        Raises:
            RuntimeError: If every CT provider failed, no cached results were available, and no passive
                source produced any name — i.e. the module has nothing to report at all.
        '''
        data = SubdomainData(query=f"%.{self.hostname}", verification_limit=self.verify_limit,
                             http_checked=self.http_client is not None)
        errors: list[CollectionError] = []
        ct_results, passive_results = await asyncio.gather(
            asyncio.gather(*(self._query_provider(p) for p in self.providers)),
            asyncio.gather(*(self._query_passive(s) for s in self.passive_sources)),
        )
        entries: list[CtEntry] = []
        for status, provider_entries, error in ct_results:
            data.providers.append(status)
            entries.extend(provider_entries)
            if error:
                errors.append(error)
        passive_entries: list[PassiveEntry] = []
        for status, source_entries, error in passive_results:
            data.sources.append(status)
            passive_entries.extend(source_entries)
            if error:
                errors.append(error)

        ct_failed = bool(data.providers) and all(p.status == "failed" for p in data.providers)
        if ct_failed and not passive_entries:
            raise RuntimeError("all CT providers failed: " + "; ".join(
                f"{p.provider}: {p.error}" for p in data.providers))

        records, dropped = self.aggregate_ct_entries(entries, self.scope)
        records, passive_dropped = self.merge_passive_entries(records, passive_entries, self.scope)
        data.certificates_seen = len(entries)
        data.passive_entries_seen = len(passive_entries)
        # _dropped only ever holds out-of-scope names, so it cannot overlap the kept records.
        data.out_of_scope_dropped = dropped + passive_dropped + len(self._dropped)
        for status in data.sources:
            status.names = sum(1 for r in records if status.provider in r.sources
                               or f"cache:{status.provider}" in r.sources)

        # Concrete names first; for wildcard-only names the base name itself is checked.
        to_verify = sorted(records, key=lambda r: r.wildcard)[:self.verify_limit]
        await asyncio.gather(*(self._verify(r) for r in to_verify))
        data.verified_count = len(to_verify)
        if len(records) > self.verify_limit:
            errors.append(self.error(self.hostname, "verification_limit",
                                     f"{len(records)} names found; only the first {self.verify_limit} were verified"))

        generated = await self._permute(records)
        records.extend(generated)
        data.hostnames = sorted(records, key=lambda r: (r.hostname.count("."), r.hostname))
        self._permutation_stats(data, len(generated))
        return data, errors

    async def _permute(self, records: list[SubdomainRecord]) -> list[SubdomainRecord]:
        '''
        Generate candidate names from the discovered ones and keep only those that resolve.

        Candidates are resolved with A/AAAA queries only — never fetched — and a candidate that does not
        resolve is discarded rather than recorded, so a generated guess never enters the inventory.
        Parameters:
            records (list[SubdomainRecord]): Names discovered by the passive sources.
        Returns:
            list[SubdomainRecord]: Records for candidates that resolve (possibly empty).
        '''
        if not self.permute or self.permutation_limit <= 0:
            return []
        permuter = SubdomainPermuter(self.hostname, self.scope)
        self._candidates, self._generated_total = permuter.generate(
            [r.hostname for r in records], self.permutation_limit)
        if not self._candidates:
            return []
        confirmed = await asyncio.gather(*(self._confirm(name) for name in self._candidates))
        return [record for record in confirmed if record is not None]

    def _permutation_stats(self, data: SubdomainData, resolved: int) -> None:
        '''
        Record what the permutation pass generated, tested and confirmed.
        Parameters:
            data (SubdomainData): Result to update in place.
            resolved (int): Candidates that resolved and were added.
        '''
        data.permutation = PermutationStats(
            enabled=self.permute, generated=self._generated_total, tested=len(self._candidates),
            resolved=resolved, limit=self.permutation_limit,
            wordlist_size=len(SubdomainPermuter.WORDS),
            truncated=self._generated_total > len(self._candidates))

    async def _confirm(self, hostname: str) -> SubdomainRecord | None:
        '''
        Resolve one generated candidate and build a record only if it resolves.
        Parameters:
            hostname (str): Candidate hostname (already scope-checked).
        Returns:
            SubdomainRecord | None: The record, or None when the name does not resolve.
        '''
        a, aaaa = await asyncio.gather(self.dns_client.query(hostname, "A"),
                                       self.dns_client.query(hostname, "AAAA"))
        addresses = list(dict.fromkeys(a.values + aaaa.values))
        if not addresses:
            return None
        record = SubdomainRecord(hostname=hostname, wildcard=False, sources=[SourceKind.PERMUTATION.value],
                                 verified=True, resolves=True, dns_status=DnsQueryStatus.NOERROR.value,
                                 addresses=addresses, state=HostState.RESOLVING)
        record.private_addresses = [ip for ip in addresses if not is_public_ip(ip)]
        return record

    async def _query_passive(self, source: PassiveSource) -> tuple[ProviderResult, list[PassiveEntry],
                                                                   CollectionError | None]:
        '''
        Query one passive source live, falling back to fresh cached results on failure.

        A source needing a credential it does not have is reported as skipped with the reason, never as a
        silent absence, so report readers can tell "found nothing" from "never asked".
        Parameters:
            source (PassiveSource): Source to query.
        Returns:
            tuple[ProviderResult, list[PassiveEntry], CollectionError | None]: Outcome, entries and any error.
        '''
        reason = source.unavailable()
        if reason is not None:
            return (ProviderResult(provider=source.name, status="skipped", kind=source.kind,
                                   skip_reason=reason), [], None)
        if self.passive_client is None:
            return (ProviderResult(provider=source.name, status="skipped", kind=source.kind,
                                   skip_reason="no client configured for passive sources"), [], None)
        try:
            returned = await source.fetch(self.passive_client, self.hostname)
        except (SourceError, BlockedRequestError, httpx.HTTPError, OSError) as exc:
            error = self.error(source.name, "source_failed", str(exc)[:300])
            cached = self.passive_cache.load(source.name, self.hostname, self.now or datetime.now(UTC))
            if cached is None:
                return (ProviderResult(provider=source.name, status="failed", kind=source.kind,
                                       error=str(exc)[:300]), [], error)
            cached_entries, saved_at = cached
            for entry in cached_entries:
                entry.source = f"cache:{source.name}"
            return (ProviderResult(provider=source.name, status="cached", kind=source.kind,
                                   entries=len(cached_entries), error=str(exc)[:300], cached_at=saved_at),
                    cached_entries, error)
        # Scope-filter before caching, so only in-scope names are ever written to disk, and record what was
        # dropped so the report's out-of-scope count covers passive sources as well as CT.
        entries = in_scope_names(returned, self.hostname)
        kept = {e.hostname.lower().rstrip(".") for e in entries}
        self._dropped |= {e.hostname.lower().rstrip(".") for e in returned
                          if e.hostname and e.hostname.lower().rstrip(".") not in kept}
        self.passive_cache.save(source.name, self.hostname, entries)
        return (ProviderResult(provider=source.name, status="live", kind=source.kind,
                               entries=len(entries)), entries, None)

    @staticmethod
    def merge_passive_entries(records: list[SubdomainRecord], entries: list[PassiveEntry],
                              scope: Scope) -> tuple[list[SubdomainRecord], int]:
        '''
        Fold passive-source entries into the CT-derived records, crediting every source per hostname.

        A name only a passive source knows about becomes a new record with no certificate count; a name CT
        already had gains the extra source and, where the source reports an earlier/later sighting, a wider
        first/last-seen window.
        Parameters:
            records (list[SubdomainRecord]): Records aggregated from CT entries.
            entries (list[PassiveEntry]): Entries from the passive sources.
            scope (Scope): Authorized target scope.
        Returns:
            tuple[list[SubdomainRecord], int]: Merged records and the number of distinct out-of-scope names dropped.
        '''
        by_host: dict[str, SubdomainRecord] = {r.hostname: r for r in records}
        dropped: set[str] = set()
        for entry in entries:
            normalized = normalize_discovered(entry.hostname)
            if normalized is None:
                continue
            host, wildcard = normalized
            if not scope.allows(host):
                dropped.add(host)
                continue
            record = by_host.get(host)
            if record is None:
                record = SubdomainRecord(hostname=host, wildcard=wildcard)
                by_host[host] = record
            elif not wildcard:
                record.wildcard = False
            if entry.source not in record.sources:
                record.sources.append(entry.source)
            if entry.first_seen and (record.first_seen is None or entry.first_seen < record.first_seen):
                record.first_seen = entry.first_seen
            if entry.last_seen and (record.last_seen is None or entry.last_seen > record.last_seen):
                record.last_seen = entry.last_seen
        for record in by_host.values():
            record.sources.sort()
        ordered = sorted(by_host.values(), key=lambda r: (r.hostname.count("."), r.hostname))
        return ordered, len(dropped)

    async def _query_provider(self, provider: CtProvider) -> tuple[ProviderResult, list[CtEntry], CollectionError | None]:
        '''
        Query one provider live, falling back to fresh cached results on failure.
        Parameters:
            provider (CtProvider): Provider to query.
        Returns:
            tuple[ProviderResult, list[CtEntry], CollectionError | None]: Outcome, entries and any error.
        '''
        try:
            entries = await provider.fetch(self.ct_client, self.hostname)
        except (CtProviderError, BlockedRequestError, httpx.HTTPError, OSError) as exc:
            error = self.error(provider.name, "provider_failed", str(exc)[:300])
            cached = self.cache.load(provider.name, self.hostname, self.now or datetime.now(UTC))
            if cached is None:
                return ProviderResult(provider=provider.name, status="failed", error=str(exc)[:300]), [], error
            cached_entries, saved_at = cached
            for e in cached_entries:
                e.provider = f"cache:{provider.name}"
            return (ProviderResult(provider=provider.name, status="cached", entries=len(cached_entries),
                                   error=str(exc)[:300], cached_at=saved_at), cached_entries, error)
        self.cache.save(provider.name, self.hostname, entries)
        return ProviderResult(provider=provider.name, status="live", entries=len(entries)), entries, None

    @staticmethod
    def aggregate_ct_entries(entries: list[CtEntry], scope: Scope) -> tuple[list[SubdomainRecord], int]:
        '''
        Normalize, scope-filter and aggregate CT entries per hostname, recording each provider.
        Parameters:
            entries (list[CtEntry]): Entries from all providers.
            scope (Scope): Authorized target scope.
        Returns:
            tuple[list[SubdomainRecord], int]: Hostname records and the number of distinct out-of-scope names dropped.
        '''
        by_host: dict[str, SubdomainRecord] = {}
        seen_concrete: set[str] = set()
        dropped: set[str] = set()
        for entry in entries:
            hosts: set[str] = set()  # one count per certificate even if listed as name and *.name
            for raw in entry.names:
                norm = normalize_discovered(raw)
                if norm is None:
                    continue
                host, wildcard = norm
                if not scope.allows(host):
                    dropped.add(host)
                    continue
                if not wildcard:
                    seen_concrete.add(host)
                hosts.add(host)
            for host in hosts:
                rec = by_host.setdefault(host, SubdomainRecord(hostname=host, wildcard=True))
                rec.certificate_count += 1
                if entry.provider not in rec.sources:
                    rec.sources.append(entry.provider)
                if entry.not_before and (rec.first_seen is None or entry.not_before < rec.first_seen):
                    rec.first_seen = entry.not_before
                if entry.not_after and (rec.last_seen is None or entry.not_after > rec.last_seen):
                    rec.last_seen = entry.not_after
                if entry.issuer and entry.issuer not in rec.issuers:
                    rec.issuers.append(entry.issuer)
                if entry.cert_id and len(rec.cert_ids) < 5 and entry.cert_id not in rec.cert_ids:
                    rec.cert_ids.append(entry.cert_id)
        for host, rec in by_host.items():
            rec.wildcard = host not in seen_concrete
            rec.sources.sort()
        ordered = sorted(by_host.values(), key=lambda r: (r.hostname.count("."), r.hostname))
        return ordered, len(dropped)

    async def _assess_takeover(self, rec: SubdomainRecord) -> None:
        '''
        Assess subdomain-takeover risk from the record's CNAME: match a takeover-prone provider, then confirm
        via a non-resolving target (dangling) or the provider's unclaimed-resource fingerprint in the response.
        Parameters:
            rec (SubdomainRecord): Record to update in place (sets takeover_* fields).
        '''
        if not rec.cname:
            return
        sig = match_cname(rec.cname)
        if sig is None:
            return
        rec.takeover_provider = sig.provider
        if rec.resolves is False:
            if sig.nxdomain_vulnerable:
                rec.takeover_vulnerable = True
                rec.takeover_detail = f"CNAME → {rec.cname}; {sig.provider} target does not resolve (dangling)"
            else:
                rec.takeover_detail = f"CNAME → {rec.cname} ({sig.provider}); target does not resolve"
            return
        if rec.resolves and self.http_client is not None and sig.fingerprints and not rec.private_addresses:
            try:
                resp = await self.http_client.get(f"https://{rec.hostname}/")
                if sig.body_unclaimed(resp.body.decode("utf-8", "replace")[:20000]):
                    rec.takeover_vulnerable = True
                    rec.takeover_detail = (f"CNAME → {rec.cname} ({sig.provider}); unclaimed-resource "
                                           "fingerprint in the response")
                else:
                    rec.takeover_detail = f"CNAME → {rec.cname} ({sig.provider}); appears claimed"
            except BlockedRequestError as exc:
                rec.takeover_detail = f"CNAME → {rec.cname} ({sig.provider}); blocked: {exc.reason}"
            except (httpx.HTTPError, OSError) as exc:
                rec.takeover_detail = f"CNAME → {rec.cname} ({sig.provider}); fetch failed: {type(exc).__name__}"
        else:
            rec.takeover_detail = f"CNAME → {rec.cname} ({sig.provider})"

    async def _verify(self, rec: SubdomainRecord) -> None:
        '''
        Resolve a hostname and optionally check HTTPS and TLS; private addresses are never contacted.
        Parameters:
            rec (SubdomainRecord): Record to update in place.
        '''
        a, aaaa, cname = await asyncio.gather(self.dns_client.query(rec.hostname, "A"),
                                              self.dns_client.query(rec.hostname, "AAAA"),
                                              self.dns_client.query(rec.hostname, "CNAME"))
        rec.verified = True
        rec.addresses = list(dict.fromkeys(a.values + aaaa.values))
        rec.private_addresses = [ip for ip in rec.addresses if not is_public_ip(ip)]
        rec.cname = cname.values[0].rstrip(".") if cname.values else None
        statuses = {a.status, aaaa.status}
        if rec.addresses:
            rec.resolves, rec.dns_status, rec.state = True, DnsQueryStatus.NOERROR.value, HostState.RESOLVING
        elif DnsQueryStatus.NXDOMAIN in statuses:
            rec.resolves, rec.dns_status, rec.state = False, DnsQueryStatus.NXDOMAIN.value, HostState.HISTORICAL
        elif all(s.is_definitive for s in statuses):
            rec.resolves, rec.dns_status, rec.state = False, DnsQueryStatus.NODATA.value, HostState.HISTORICAL
        else:
            rec.resolves, rec.dns_status = None, a.status.value  # inconclusive: stays UNVERIFIED

        await self._assess_takeover(rec)   # before the early-return: a dangling CNAME often does not resolve

        if not rec.resolves or rec.private_addresses:
            return
        if self.http_client is not None:
            try:
                resp = await self.http_client.get(f"https://{rec.hostname}/")
                rec.http_status = resp.status_code
                rec.http_location = resp.header("location")
                rec.state = HostState.REACHABLE
            except BlockedRequestError as exc:
                rec.http_error = exc.reason
            except (httpx.HTTPError, OSError) as exc:
                rec.http_error = f"{type(exc).__name__}: {str(exc)[:120]}"
        if self.tls_probe is not None:
            probe = await self.tls_probe(rec.hostname)
            rec.tls_ok = probe.success
            rec.tls_hostname_match = probe.hostname_match
            rec.tls_error = probe.error
            if probe.success:
                rec.state = HostState.REACHABLE
