'''
Historical URL collection (web archives and URL indexes), GAU-style.

Four keyless sources are queried for the URLs they hold under the target domain — the Wayback Machine, the
Common Crawl index, urlscan.io and AlienVault OTX — and the merged result is mined for three things the
live site no longer shows: the **endpoint surface** it used to expose, the **query parameters** its links
carried, and **technology hints** from paths and extensions (``.php``, ``/wp-content/``, ``/_next/``).

Three honesty rules shape this module:
  * It never contacts the target. Every request goes to an archive, so a URL here proves the archive
    crawled it once — not that it resolves, responds, or exists today.
  * Query *values* are redacted before anything is stored. An archived URL can carry a real token, and a
    recon report is not the place to copy one; parameter *names* are what the analysis needs.
  * Technology hints stay in this module and are never merged into the ``technology`` inventory. They
    describe the stack that served a path when it was archived, which may be several rewrites ago.
'''

from __future__ import annotations

import asyncio
import re
from abc import ABC, abstractmethod
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any, ClassVar
from urllib.parse import parse_qsl, quote, urlsplit

import httpx

from recon.analysis.historical_signatures import SENSITIVE_PATH, classify_parameter, match_tech_hints
from recon.models import CollectionError, Confidence
from recon.models.historical import (
    HistoricalData,
    HistoricalParameter,
    HistoricalSourceResult,
    HistoricalTechHint,
    HistoricalUrl,
)
from recon.modules.base import Collector
from recon.modules.sources import SourceError, fetch_json, fetch_json_lines, parse_timestamp
from recon.utils import BlockedRequestError, SafeHttpClient, Scope, matches_suffix, redact_url

# Sentinel for sorting URLs the archive gave no timestamp for; they sort last, never first.
_EPOCH: datetime = datetime(1970, 1, 1, tzinfo=UTC)

# Paths that look like an API surface worth reviewing by hand (not a guarantee any still exists).
_API_PATH: re.Pattern[str] = re.compile(
    r"^/(?:api|rest|graphql|gql|v\d{1,2}|rpc|jsonrpc|oauth|auth|login|logout|signup|register|admin|internal|"
    r"webhook|webhooks|callback|upload|uploads|export|import|download|backup|debug|actuator|swagger|"
    r"openapi|api-docs|\.well-known|wp-json|\.netlify|\.vercel)(?:/|$)", re.IGNORECASE)


class HistoricalSource(ABC):
    '''
    A source of historical URLs for a domain.
    '''

    name: ClassVar[str]
    label: ClassVar[str]
    HOSTS: ClassVar[tuple[str, ...]]

    @abstractmethod
    async def fetch(self, client: SafeHttpClient, hostname: str, limit: int) -> list[dict[str, Any]]:
        '''
        Return raw URL rows for the hostname.
        Parameters:
            client (SafeHttpClient): Client scoped to the source hosts.
            hostname (str): Target hostname.
            limit (int): Maximum rows to request.
        Returns:
            list[dict[str, Any]]: Rows with at least a 'url' key, optionally 'timestamp', 'status', 'mime'.
        Raises:
            SourceError: If the source fails or returns unusable data.
        '''

    @staticmethod
    def row(url: Any, timestamp: Any = None, status: Any = None, mime: Any = None) -> dict[str, Any]:
        '''
        Build a normalized row.
        Parameters:
            url (Any): The archived URL.
            timestamp (Any): When the archive saw it, in any supported format.
            status (Any): HTTP status the archive recorded.
            mime (Any): Content type the archive recorded.
        Returns:
            dict[str, Any]: The row.
        '''
        return {"url": str(url or ""), "timestamp": timestamp, "status": status, "mime": mime}


class WaybackUrlSource(HistoricalSource):
    '''
    Internet Archive Wayback Machine CDX API: every distinct archived URL under the domain. Keyless.
    '''

    name: ClassVar[str] = "wayback"
    label: ClassVar[str] = "Wayback Machine"
    HOSTS: ClassVar[tuple[str, ...]] = ("web.archive.org",)
    URL: ClassVar[str] = ("https://web.archive.org/cdx/search/cdx?url={domain}&matchType=domain&output=json"
                          "&fl=original,timestamp,statuscode,mimetype&collapse=urlkey&limit={limit}")

    async def fetch(self, client: SafeHttpClient, hostname: str, limit: int) -> list[dict[str, Any]]:
        '''
        Query the CDX API for archived URLs.
        Parameters:
            client (SafeHttpClient): Source-scoped client.
            hostname (str): Target hostname.
            limit (int): Maximum rows to request.
        Returns:
            list[dict[str, Any]]: Normalized rows.
        Raises:
            SourceError: On failure or an unexpected response shape.
        '''
        data = await fetch_json(client, self.URL.format(domain=quote(hostname), limit=limit))
        if not isinstance(data, list):
            raise SourceError("unexpected response shape")
        rows: list[dict[str, Any]] = []
        for raw in data[1:]:                      # row 0 is the column header
            if isinstance(raw, list) and raw:
                padded = list(raw) + [None] * (4 - len(raw))
                rows.append(self.row(padded[0], padded[1], padded[2], padded[3]))
        return rows


class CommonCrawlUrlSource(HistoricalSource):
    '''
    Common Crawl index: URLs the most recent published crawl holds for the domain. Keyless.
    '''

    name: ClassVar[str] = "commoncrawl"
    label: ClassVar[str] = "Common Crawl"
    HOSTS: ClassVar[tuple[str, ...]] = ("index.commoncrawl.org",)
    COLLECTIONS: ClassVar[str] = "https://index.commoncrawl.org/collinfo.json"

    async def fetch(self, client: SafeHttpClient, hostname: str, limit: int) -> list[dict[str, Any]]:
        '''
        Query the latest Common Crawl index for URLs under the domain.
        Parameters:
            client (SafeHttpClient): Source-scoped client.
            hostname (str): Target hostname.
            limit (int): Maximum rows to request.
        Returns:
            list[dict[str, Any]]: Normalized rows.
        Raises:
            SourceError: On failure or an unexpected response shape.
        '''
        collections = await fetch_json(client, self.COLLECTIONS)
        if not isinstance(collections, list) or not collections:
            raise SourceError("collection list was empty or malformed")
        endpoint = next((c["cdx-api"] for c in collections
                         if isinstance(c, dict) and isinstance(c.get("cdx-api"), str)
                         and urlsplit(c["cdx-api"]).hostname in self.HOSTS), None)
        if endpoint is None:
            raise SourceError("collection list named no usable cdx-api endpoint")
        url = (f"{endpoint}?url={quote(f'*.{hostname}')}&output=json&fl=url,timestamp,status,mime"
               f"&limit={limit}")
        return [self.row(r.get("url"), r.get("timestamp"), r.get("status"), r.get("mime"))
                for r in await fetch_json_lines(client, url)]


class UrlScanUrlSource(HistoricalSource):
    '''
    urlscan.io search: the page URLs of public scans of the domain. Keyless (anonymous tier).
    '''

    name: ClassVar[str] = "urlscan"
    label: ClassVar[str] = "urlscan.io"
    HOSTS: ClassVar[tuple[str, ...]] = ("urlscan.io",)
    URL: ClassVar[str] = "https://urlscan.io/api/v1/search/?q=domain%3A{domain}&size={limit}"
    MAX_SIZE: ClassVar[int] = 1000

    async def fetch(self, client: SafeHttpClient, hostname: str, limit: int) -> list[dict[str, Any]]:
        '''
        Query the urlscan.io search API.
        Parameters:
            client (SafeHttpClient): Source-scoped client.
            hostname (str): Target hostname.
            limit (int): Maximum rows to request (capped at the API's page size).
        Returns:
            list[dict[str, Any]]: Normalized rows.
        Raises:
            SourceError: On failure or an unexpected response shape.
        '''
        size = min(limit, self.MAX_SIZE)
        data = await fetch_json(client, self.URL.format(domain=quote(hostname), limit=size))
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            raise SourceError("unexpected response shape")
        rows: list[dict[str, Any]] = []
        for result in data["results"]:
            if not isinstance(result, dict):
                continue
            raw_page, raw_task = result.get("page"), result.get("task")
            page: dict[str, Any] = raw_page if isinstance(raw_page, dict) else {}
            task: dict[str, Any] = raw_task if isinstance(raw_task, dict) else {}
            rows.append(self.row(page.get("url") or task.get("url"), task.get("time") or page.get("scanDate"),
                                 page.get("status"), page.get("mimeType")))
        return rows


class OtxUrlSource(HistoricalSource):
    '''
    AlienVault OTX URL list: URLs OTX has recorded for the domain. Keyless.
    '''

    name: ClassVar[str] = "otx"
    label: ClassVar[str] = "AlienVault OTX"
    HOSTS: ClassVar[tuple[str, ...]] = ("otx.alienvault.com",)
    URL: ClassVar[str] = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500&page=1"

    async def fetch(self, client: SafeHttpClient, hostname: str, limit: int) -> list[dict[str, Any]]:
        '''
        Query the OTX URL list.
        Parameters:
            client (SafeHttpClient): Source-scoped client.
            hostname (str): Target hostname.
            limit (int): Maximum rows to keep.
        Returns:
            list[dict[str, Any]]: Normalized rows.
        Raises:
            SourceError: On failure or an unexpected response shape.
        '''
        data = await fetch_json(client, self.URL.format(domain=quote(hostname)))
        if not isinstance(data, dict) or not isinstance(data.get("url_list"), list):
            raise SourceError("unexpected response shape")
        rows: list[dict[str, Any]] = []
        for item in data["url_list"][:limit]:
            if not isinstance(item, dict):
                continue
            raw_result = item.get("result")
            result: dict[str, Any] = raw_result if isinstance(raw_result, dict) else {}
            raw_worker = result.get("urlworker")
            worker: dict[str, Any] = raw_worker if isinstance(raw_worker, dict) else {}
            rows.append(self.row(item.get("url"), item.get("date"), worker.get("http_code"),
                                 worker.get("filetype")))
        return rows


REGISTRY: dict[str, type[HistoricalSource]] = {
    source.name: source for source in (WaybackUrlSource, CommonCrawlUrlSource, UrlScanUrlSource, OtxUrlSource)
}
ALL_SOURCES: tuple[str, ...] = tuple(REGISTRY)


def resolve_sources(requested: Iterable[object] | None) -> list[str]:
    '''
    Resolve requested historical-source ids to known ones, in registry order.
    Parameters:
        requested (Iterable[object] | None): Source ids, possibly containing 'all'/'none', or None for all.
    Returns:
        list[str]: Source ids to query.
    '''
    if requested is None:
        return list(ALL_SOURCES)
    names = {str(n).strip().lower() for n in requested if str(n).strip()}
    if not names or "all" in names:
        return list(ALL_SOURCES)
    if "none" in names:
        return []
    return [name for name in REGISTRY if name in names]


def unknown_sources(requested: Iterable[object] | None) -> list[str]:
    '''
    The requested historical-source ids that are not registered, so a typo is rejected rather than
    silently reducing coverage.
    Parameters:
        requested (Iterable[object] | None): Requested source ids, or None.
    Returns:
        list[str]: Sorted unknown ids.
    '''
    if requested is None:
        return []
    return sorted({str(n).strip().lower() for n in requested if str(n).strip()}
                  - set(REGISTRY) - {"all", "none"})


def scope_hosts(sources: list[str]) -> list[str]:
    '''
    Every provider host the given sources contact, for building their allow-listed client.
    Parameters:
        sources (list[str]): Source ids.
    Returns:
        list[str]: Sorted provider hostnames.
    '''
    return sorted({host for name in sources for host in REGISTRY[name].HOSTS})


class HistoricalUrlCollector(Collector[HistoricalData]):
    '''
    Collects archived URLs for a target from web archives and URL indexes, then extracts the endpoint,
    parameter and legacy-technology surface they reveal.
    '''

    name: ClassVar[str] = "historical"
    MAX_URL_SAMPLE: ClassVar[int] = 300      # archived URLs kept in the report (full counts are still reported)
    MAX_PATHS: ClassVar[int] = 500
    MAX_PARAMETERS: ClassVar[int] = 150
    MAX_SENSITIVE: ClassVar[int] = 40
    MAX_ENDPOINTS: ClassVar[int] = 150
    MAX_HINT_EVIDENCE: ClassVar[int] = 5

    def __init__(self, hostname: str, client: SafeHttpClient | None, *,
                 sources: list[HistoricalSource] | None = None, limit: int = 1000) -> None:
        '''
        Create the collector.
        Parameters:
            hostname (str): Normalized target hostname.
            client (SafeHttpClient | None): Client scoped to the enabled sources' hosts; None skips every
                source (used when the module runs with nothing enabled).
            sources (list[HistoricalSource] | None): Sources to query; defaults to every known source.
            limit (int): Per-source cap on URLs requested.
        '''
        self.hostname = hostname
        self.client = client
        self.sources = list(sources if sources is not None else (cls() for cls in REGISTRY.values()))
        self.limit = max(1, limit)
        self.scope = Scope.for_target(hostname)

    async def collect(self) -> tuple[HistoricalData, list[CollectionError]]:
        '''
        Query every enabled source concurrently and build the historical surface.
        Returns:
            tuple[HistoricalData, list[CollectionError]]: Historical data and per-source errors.
        Raises:
            RuntimeError: If every source failed, so the module has nothing to report.
        '''
        data = HistoricalData(host=self.hostname, limit=self.limit)
        errors: list[CollectionError] = []
        results = await asyncio.gather(*(self._query(source) for source in self.sources))
        merged: dict[str, HistoricalUrl] = {}
        dropped: set[str] = set()
        for status, rows, error in results:
            data.sources.append(status)
            if error:
                errors.append(error)
            kept = self._absorb(merged, rows, status.source, dropped)
            status.urls = kept
            if kept >= self.limit:
                data.truncated = True
        if data.sources and all(s.status == "failed" for s in data.sources):
            raise RuntimeError("every historical source failed: " + "; ".join(
                f"{s.source}: {s.error}" for s in data.sources))

        urls = list(merged.values())
        data.urls_seen = len(urls)
        data.out_of_scope_dropped = len(dropped)
        self._summarize(data, urls)
        return data, errors

    async def _query(self, source: HistoricalSource) -> tuple[HistoricalSourceResult, list[dict[str, Any]],
                                                              CollectionError | None]:
        '''
        Query one source, converting any failure into a failed-source result rather than an exception.
        Parameters:
            source (HistoricalSource): Source to query.
        Returns:
            tuple[HistoricalSourceResult, list[dict[str, Any]], CollectionError | None]: Outcome, rows, error.
        '''
        if self.client is None:
            return (HistoricalSourceResult(source=source.name, status="skipped",
                                           skip_reason="no client configured"), [], None)
        try:
            rows = await source.fetch(self.client, self.hostname, self.limit)
        except (SourceError, BlockedRequestError, httpx.HTTPError, OSError) as exc:
            detail = str(exc)[:300]
            return (HistoricalSourceResult(source=source.name, status="failed", error=detail), [],
                    self.error(source.name, "source_failed", detail))
        return HistoricalSourceResult(source=source.name, status="live"), rows, None

    def _absorb(self, merged: dict[str, HistoricalUrl], rows: list[dict[str, Any]], source: str,
                dropped: set[str]) -> int:
        '''
        Fold one source's rows into the merged URL map, redacting query values and dropping off-scope hosts.
        Parameters:
            merged (dict[str, HistoricalUrl]): Accumulator keyed by redacted URL, updated in place.
            rows (list[dict[str, Any]]): Rows from one source.
            source (str): Source name, credited on each URL.
            dropped (set[str]): Accumulator of off-scope hostnames seen.
        Returns:
            int: How many in-scope URLs this source contributed.
        '''
        kept = 0
        for row in rows:
            raw = str(row.get("url") or "").strip()
            if not raw:
                continue
            parts = self._split(raw)
            if parts is None:
                continue
            host, path, query = parts
            if not matches_suffix(host, self.hostname):
                dropped.add(host)
                continue
            redacted = redact_url(raw if "//" in raw else f"https://{raw}")
            record = merged.get(redacted)
            if record is None:
                record = HistoricalUrl(url=redacted, path=path or "/", host=host)
                merged[redacted] = record
            if source not in record.sources:
                record.sources.append(source)
            seen = parse_timestamp(row.get("timestamp"))
            if seen and (record.first_seen is None or seen < record.first_seen):
                record.first_seen = seen
            if seen and (record.last_seen is None or seen > record.last_seen):
                record.last_seen = seen
            status = self._status(row.get("status"))
            if status is not None and status not in record.status_codes:
                record.status_codes.append(status)
            if not record.mime and row.get("mime"):
                record.mime = str(row["mime"])[:80]
            for key, _ in parse_qsl(query, keep_blank_values=True):
                if key and key not in record.parameters:
                    record.parameters.append(key[:80])
            kept += 1
        return kept

    @staticmethod
    def _split(raw: str) -> tuple[str, str, str] | None:
        '''
        Split an archived URL into host, path and query.
        Parameters:
            raw (str): The raw URL, possibly scheme-relative or scheme-less.
        Returns:
            tuple[str, str, str] | None: (host, path, query), or None when it is not a usable URL.
        '''
        try:
            parts = urlsplit(raw if "//" in raw else f"//{raw}")
            host = parts.hostname
        except ValueError:
            return None
        if not host:
            return None
        return host.lower().rstrip("."), parts.path, parts.query

    @staticmethod
    def _status(value: Any) -> int | None:
        '''
        Parse an HTTP status recorded by an archive ('-' and empty values mean 'not recorded').
        Parameters:
            value (Any): Raw status value.
        Returns:
            int | None: The status, or None.
        '''
        text = str(value or "").strip()
        return int(text) if text.isdigit() and 100 <= int(text) <= 599 else None

    def _summarize(self, data: HistoricalData, urls: list[HistoricalUrl]) -> None:
        '''
        Derive the reported surface from the merged URLs: hosts, paths, endpoints, parameters, technology
        hints, sensitive paths, extensions and the overall date range.
        Parameters:
            data (HistoricalData): Result to fill in place.
            urls (list[HistoricalUrl]): Merged, in-scope archived URLs.
        '''
        lasts: list[datetime] = [s for u in urls if (s := u.last_seen or u.first_seen) is not None]
        firsts: list[datetime] = [u.first_seen for u in urls if u.first_seen is not None]
        data.first_seen = min(firsts) if firsts else None
        data.last_seen = max(lasts) if lasts else None
        data.hosts = sorted({u.host for u in urls})
        paths = sorted({u.path for u in urls})
        data.paths = paths[: self.MAX_PATHS]
        data.endpoints = [p for p in paths if _API_PATH.match(p)][: self.MAX_ENDPOINTS]
        data.sensitive_paths = [u.url for u in urls if SENSITIVE_PATH.search(u.path)][: self.MAX_SENSITIVE]
        extensions: dict[str, int] = {}
        for url in urls:
            suffix = url.path.rsplit("/", 1)[-1]
            if "." in suffix:
                ext = suffix.rsplit(".", 1)[-1].lower()
                if ext.isalnum() and len(ext) <= 6:
                    extensions[ext] = extensions.get(ext, 0) + 1
        data.extensions = dict(sorted(extensions.items(), key=lambda kv: (-kv[1], kv[0]))[:30])
        data.parameters = self._parameters(urls)
        data.tech_hints = self._tech_hints(urls)
        # Most recently archived first, so the sample favours what the archive saw last; undated URLs last.
        data.urls = sorted(urls, key=lambda u: (u.last_seen or _EPOCH, u.path), reverse=True)[: self.MAX_URL_SAMPLE]

    def _parameters(self, urls: list[HistoricalUrl]) -> list[HistoricalParameter]:
        '''
        Aggregate query-parameter names across archived URLs and classify each one.
        Parameters:
            urls (list[HistoricalUrl]): Merged archived URLs.
        Returns:
            list[HistoricalParameter]: Parameters, credential/redirect/file classes first, then by frequency.
        '''
        by_name: dict[str, HistoricalParameter] = {}
        for url in urls:
            for name in url.parameters:
                param = by_name.get(name)
                if param is None:
                    signature = classify_parameter(name)
                    param = HistoricalParameter(name=name, category=signature.category if signature else "other",
                                                note=signature.note if signature else None)
                    by_name[name] = param
                param.occurrences += 1
                if len(param.paths) < 5 and url.path not in param.paths:
                    param.paths.append(url.path)
                for source in url.sources:
                    if source not in param.sources:
                        param.sources.append(source)
                if url.first_seen and (param.first_seen is None or url.first_seen < param.first_seen):
                    param.first_seen = url.first_seen
                if url.last_seen and (param.last_seen is None or url.last_seen > param.last_seen):
                    param.last_seen = url.last_seen
        priority = {"credential": 0, "redirect": 1, "file": 2, "identifier": 3, "other": 4}
        ordered = sorted(by_name.values(), key=lambda p: (priority.get(p.category, 9), -p.occurrences, p.name))
        return ordered[: self.MAX_PARAMETERS]

    def _tech_hints(self, urls: list[HistoricalUrl]) -> list[HistoricalTechHint]:
        '''
        Aggregate technology hints from archived paths, keeping a first/last-seen window per hint.
        Parameters:
            urls (list[HistoricalUrl]): Merged archived URLs.
        Returns:
            list[HistoricalTechHint]: Hints, strongest and most frequent first.
        '''
        by_name: dict[str, HistoricalTechHint] = {}
        for url in urls:
            for signature in match_tech_hints(url.path):
                hint = by_name.get(signature.name)
                if hint is None:
                    hint = HistoricalTechHint(name=signature.name, category=signature.category,
                                              confidence=signature.confidence, note=signature.note or None)
                    by_name[signature.name] = hint
                hint.occurrences += 1
                if len(hint.evidence) < self.MAX_HINT_EVIDENCE and url.path not in hint.evidence:
                    hint.evidence.append(url.path)
                if url.first_seen and (hint.first_seen is None or url.first_seen < hint.first_seen):
                    hint.first_seen = url.first_seen
                if url.last_seen and (hint.last_seen is None or url.last_seen > hint.last_seen):
                    hint.last_seen = url.last_seen
        return sorted(by_name.values(), key=lambda h: (-h.confidence.rank, -h.occurrences, h.name))

    @staticmethod
    def mark_current(data: HistoricalData, current: set[str]) -> None:
        '''
        Flag the hints whose technology the current scan also detected, so a report can separate "still
        running this" from "used to run this".

        Done as a post-pass by the orchestrator because the technology module runs after this one; the
        hints themselves are never promoted into the current technology inventory.
        Parameters:
            data (HistoricalData): Historical data to annotate in place.
            current (set[str]): Technology names the current scan detected.
        '''
        lowered = {name.lower() for name in current}
        for hint in data.tech_hints:
            hint.still_detected = hint.name.lower() in lowered

    @staticmethod
    def confidence_for(hint: HistoricalTechHint) -> Confidence:
        '''
        The confidence a hint carries once history is taken into account: a hint the current scan still
        detects is stronger evidence than one only the archive saw.
        Parameters:
            hint (HistoricalTechHint): The hint.
        Returns:
            Confidence: The hint's effective confidence.
        '''
        if hint.still_detected:
            return Confidence.MEDIUM if hint.confidence is Confidence.LOW else Confidence.HIGH
        return hint.confidence
