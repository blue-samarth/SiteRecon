'''
Subdomain discovery from public Certificate Transparency logs (crt.sh and Cert Spotter), with a
local cache for provider outages and optional DNS / HTTPS / TLS verification. No brute-forcing.
'''

from __future__ import annotations

import asyncio
import json
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import quote

import httpx

from recon.models import CollectionError, DnsQueryStatus, SubdomainData, SubdomainRecord, TlsProbe
from recon.models.subdomains import CtEntry, HostState, ProviderResult
from recon.modules.base import Collector
from recon.utils import (
    BlockedRequestError,
    DnsClient,
    SafeHttpClient,
    Scope,
    is_public_ip,
    normalize_discovered,
)

TlsProbeFn = Callable[[str], Awaitable[TlsProbe]]


class CtProviderError(Exception):
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
        outcome = await client.fetch(url)
        resp = outcome.final
        if resp is None or resp.status_code != 200:
            status = resp.status_code if resp else None
            raise CtProviderError(outcome.error or outcome.stopped_reason or f"HTTP {status}")
        if resp.truncated:
            raise CtProviderError("response exceeded the size limit; results would be incomplete")
        try:
            return json.loads(resp.body or b"[]")
        except json.JSONDecodeError as exc:
            raise CtProviderError(f"invalid JSON: {exc}") from exc

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


class CtCache:
    '''
    JSON cache of CT entries per (provider, hostname), used when a live provider fails.
    '''

    def __init__(self, directory: Path | None, ttl: timedelta) -> None:
        '''
        Create a cache.
        Parameters:
            directory (Path | None): Cache directory; None disables caching.
            ttl (timedelta): Maximum age of cached results that may be used.
        '''
        self.directory = directory
        self.ttl = ttl

    def _path(self, provider: str, hostname: str) -> Path | None:
        '''
        Cache file for a provider and hostname.
        Parameters:
            provider (str): Provider name.
            hostname (str): Target hostname.
        Returns:
            Path | None: File path, or None when caching is disabled.
        '''
        if self.directory is None:
            return None
        safe = "".join(c if c.isalnum() or c in ".-" else "_" for c in f"{provider}__{hostname}")
        return self.directory / "ct" / f"{safe}.json"

    def save(self, provider: str, hostname: str, entries: list[CtEntry]) -> None:
        '''
        Store entries; failures to write are ignored (the cache is best-effort).
        Parameters:
            provider (str): Provider name.
            hostname (str): Target hostname.
            entries (list[CtEntry]): Entries to store.
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

    def load(self, provider: str, hostname: str, now: datetime) -> tuple[list[CtEntry], datetime] | None:
        '''
        Return cached entries if present and fresher than the TTL.
        Parameters:
            provider (str): Provider name.
            hostname (str): Target hostname.
            now (datetime): Current time.
        Returns:
            tuple[list[CtEntry], datetime] | None: Entries and when they were saved, or None.
        '''
        path = self._path(provider, hostname)
        if path is None or not path.is_file():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            saved_at = datetime.fromisoformat(payload["saved_at"])
            entries = [CtEntry.model_validate(e) for e in payload["entries"]]
        except (OSError, ValueError, KeyError, TypeError):
            return None
        if now - saved_at > self.ttl:
            return None
        return entries, saved_at


class SubdomainCollector(Collector[SubdomainData]):
    '''
    Discovers in-scope names from several CT providers and verifies them via DNS (and optionally HTTPS/TLS).
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
            providers (list[CtProvider] | None): Providers to query; defaults to all known providers.
            cache (CtCache | None): Result cache; None disables caching.
            now (datetime | None): Reference time for cache freshness; defaults to the current UTC time.
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

    async def collect(self) -> tuple[SubdomainData, list[CollectionError]]:
        '''
        Query every provider concurrently, merge results, then verify up to the limit.
        Returns:
            tuple[SubdomainData, list[CollectionError]]: Discovery results and provider/verification errors.
        Raises:
            RuntimeError: If every provider failed and no cached results were available.
        '''
        data = SubdomainData(query=f"%.{self.hostname}", verification_limit=self.verify_limit,
                             http_checked=self.http_client is not None)
        errors: list[CollectionError] = []
        results = await asyncio.gather(*(self._query_provider(p) for p in self.providers))
        entries: list[CtEntry] = []
        for status, provider_entries, error in results:
            data.providers.append(status)
            entries.extend(provider_entries)
            if error:
                errors.append(error)
        if all(p.status == "failed" for p in data.providers):
            raise RuntimeError("all CT providers failed: " + "; ".join(f"{p.provider}: {p.error}" for p in data.providers))

        records, dropped = self.aggregate_ct_entries(entries, Scope.for_target(self.hostname))
        data.certificates_seen = len(entries)
        data.out_of_scope_dropped = dropped
        data.hostnames = records

        # Concrete names first; for wildcard-only names the base name itself is checked.
        to_verify = sorted(records, key=lambda r: r.wildcard)[:self.verify_limit]
        await asyncio.gather(*(self._verify(r) for r in to_verify))
        data.verified_count = len(to_verify)
        if len(records) > self.verify_limit:
            errors.append(self.error(self.hostname, "verification_limit",
                                     f"{len(records)} names found; only the first {self.verify_limit} were verified"))
        return data, errors

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

    async def _verify(self, rec: SubdomainRecord) -> None:
        '''
        Resolve a hostname and optionally check HTTPS and TLS; private addresses are never contacted.
        Parameters:
            rec (SubdomainRecord): Record to update in place.
        '''
        a, aaaa = await asyncio.gather(self.dns_client.query(rec.hostname, "A"),
                                       self.dns_client.query(rec.hostname, "AAAA"))
        rec.verified = True
        rec.addresses = list(dict.fromkeys(a.values + aaaa.values))
        rec.private_addresses = [ip for ip in rec.addresses if not is_public_ip(ip)]
        statuses = {a.status, aaaa.status}
        if rec.addresses:
            rec.resolves, rec.dns_status, rec.state = True, DnsQueryStatus.NOERROR.value, HostState.RESOLVING
        elif DnsQueryStatus.NXDOMAIN in statuses:
            rec.resolves, rec.dns_status, rec.state = False, DnsQueryStatus.NXDOMAIN.value, HostState.HISTORICAL
        elif all(s.is_definitive for s in statuses):
            rec.resolves, rec.dns_status, rec.state = False, DnsQueryStatus.NODATA.value, HostState.HISTORICAL
        else:
            rec.resolves, rec.dns_status = None, a.status.value  # inconclusive: stays UNVERIFIED

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
