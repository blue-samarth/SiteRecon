'''
Passive (non-CT) subdomain discovery sources.

Each source answers one question — "which names under this domain have you seen?" — with one or two GETs
against a single allow-listed provider host. None of them touch the target: they query a third party's
existing dataset, which is why they are opt-in (``--subdomain-source``) and why what they return is
treated as a *lead* that the module then verifies in DNS itself.

Evidence strength by source family (see ``SourceKind``):
  passive DNS (OTX, BufferOver) → the dataset observed the name resolving at some point
  URL index (URLScan, Common Crawl, Wayback) → a URL on that host was crawled at some point
  scrape (RapidDNS) → an HTML listing was parsed; the weakest, because the page format can change

Sources that need a credential declare ``key_env`` and are skipped with a clear reason when it is unset,
so a keyless run never silently loses coverage it thought it had.
'''

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Any, ClassVar
from urllib.parse import quote, urlsplit

from recon.models.subdomains import PassiveEntry, SourceKind
from recon.modules.sources import SourceError, credential, fetch_json, fetch_json_lines, fetch_text, parse_timestamp
from recon.utils import SafeHttpClient, matches_suffix


class PassiveSource(ABC):
    '''
    A non-CT passive subdomain source.
    '''

    name: ClassVar[str]                        # stable id used on the CLI and in reports
    label: ClassVar[str]                       # human provider name
    kind: ClassVar[str]                        # SourceKind value
    HOSTS: ClassVar[tuple[str, ...]]           # provider hosts (used to scope the client)
    key_env: ClassVar[str | None] = None       # environment variable holding the required credential
    key_header: ClassVar[str | None] = None    # header the credential is sent in

    @abstractmethod
    async def fetch(self, client: SafeHttpClient, hostname: str) -> list[PassiveEntry]:
        '''
        Return the names this source has seen under the hostname.
        Parameters:
            client (SafeHttpClient): Client scoped to the provider hosts.
            hostname (str): Target hostname.
        Returns:
            list[PassiveEntry]: Normalized entries (not yet scope-filtered or verified).
        Raises:
            SourceError: If the provider fails or returns unusable data.
        '''

    def unavailable(self) -> str | None:
        '''
        Reason this source cannot run (a missing credential), or None when it can.
        Returns:
            str | None: A human-readable skip reason, or None.
        '''
        if self.key_env and credential(self.key_env) is None:
            return f"needs an API key in ${self.key_env}"
        return None

    def headers(self) -> dict[str, str]:
        '''
        Request headers for this source, including its credential when one is configured.
        Returns:
            dict[str, str]: Headers to send.
        '''
        head = {"Accept": "application/json"}
        if self.key_env and self.key_header:
            key = credential(self.key_env)
            if key:
                head[self.key_header] = key
        return head

    def entry(self, hostname: str, *, first: Any = None, last: Any = None, address: str | None = None,
              detail: str | None = None) -> PassiveEntry:
        '''
        Build a normalized entry attributed to this source.
        Parameters:
            hostname (str): Raw hostname from the provider.
            first (Any): First-seen timestamp in any supported format.
            last (Any): Last-seen timestamp in any supported format.
            address (str | None): Address the provider reported, if any.
            detail (str | None): Short source-specific note.
        Returns:
            PassiveEntry: The entry.
        '''
        return PassiveEntry(source=self.name, hostname=hostname, first_seen=parse_timestamp(first),
                            last_seen=parse_timestamp(last), address=address, detail=detail)

    @staticmethod
    def hosts_in(text: str, hostname: str) -> list[str]:
        '''
        Extract hostnames under a domain from arbitrary text (used by the scraping sources).
        Parameters:
            text (str): Response text.
            hostname (str): The domain whose subdomains to keep.
        Returns:
            list[str]: Unique candidate hostnames, in appearance order.
        '''
        pattern = re.compile(r"(?<![\w.-])((?:[\w-]+\.)+" + re.escape(hostname) + r")(?![\w-])", re.IGNORECASE)
        seen: dict[str, None] = {}
        for match in pattern.finditer(text):
            seen.setdefault(match.group(1).lower().rstrip("."), None)
        return list(seen)

    @staticmethod
    def host_of_url(value: str) -> str | None:
        '''
        Hostname of a URL reported by a URL-index source.
        Parameters:
            value (str): Absolute or scheme-relative URL.
        Returns:
            str | None: The lowercased hostname, or None.
        '''
        try:
            host = urlsplit(value if "//" in value else f"//{value}").hostname
        except ValueError:
            return None
        return host.lower().rstrip(".") if host else None


class AlienVaultOtxSource(PassiveSource):
    '''
    AlienVault OTX passive DNS: names OTX has observed resolving under the domain. Keyless.
    '''

    name: ClassVar[str] = "otx"
    label: ClassVar[str] = "AlienVault OTX"
    kind: ClassVar[str] = SourceKind.PASSIVE_DNS
    HOSTS: ClassVar[tuple[str, ...]] = ("otx.alienvault.com",)
    URL: ClassVar[str] = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"

    async def fetch(self, client: SafeHttpClient, hostname: str) -> list[PassiveEntry]:
        '''
        Query the OTX passive-DNS endpoint.
        Parameters:
            client (SafeHttpClient): Provider-scoped client.
            hostname (str): Target hostname.
        Returns:
            list[PassiveEntry]: One entry per observed name.
        Raises:
            SourceError: On failure or an unexpected response shape.
        '''
        data = await fetch_json(client, self.URL.format(domain=quote(hostname)))
        if not isinstance(data, dict):
            raise SourceError("unexpected response shape")
        rows = data.get("passive_dns")
        if not isinstance(rows, list):
            raise SourceError("response had no passive_dns list")
        entries: list[PassiveEntry] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = row.get("hostname") or row.get("address")
            if not isinstance(name, str):
                continue
            address = row.get("address") if isinstance(row.get("address"), str) else None
            entries.append(self.entry(name, first=row.get("first"), last=row.get("last"),
                                      address=address if address != name else None,
                                      detail=str(row.get("record_type") or "") or None))
        return entries


class UrlScanSource(PassiveSource):
    '''
    urlscan.io search: hostnames appearing in scans of the domain. Keyless (anonymous tier, rate-limited).
    '''

    name: ClassVar[str] = "urlscan"
    label: ClassVar[str] = "urlscan.io"
    kind: ClassVar[str] = SourceKind.URL_INDEX
    HOSTS: ClassVar[tuple[str, ...]] = ("urlscan.io",)
    URL: ClassVar[str] = "https://urlscan.io/api/v1/search/?q=domain%3A{domain}&size={size}"
    SIZE: ClassVar[int] = 1000

    async def fetch(self, client: SafeHttpClient, hostname: str) -> list[PassiveEntry]:
        '''
        Query the urlscan.io search API for scans of the domain.
        Parameters:
            client (SafeHttpClient): Provider-scoped client.
            hostname (str): Target hostname.
        Returns:
            list[PassiveEntry]: One entry per distinct hostname seen.
        Raises:
            SourceError: On failure or an unexpected response shape.
        '''
        data = await fetch_json(client, self.URL.format(domain=quote(hostname), size=self.SIZE))
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            raise SourceError("unexpected response shape")
        entries: list[PassiveEntry] = []
        for row in data["results"]:
            if not isinstance(row, dict):
                continue
            raw_page, raw_task = row.get("page"), row.get("task")
            page: dict[str, Any] = raw_page if isinstance(raw_page, dict) else {}
            task: dict[str, Any] = raw_task if isinstance(raw_task, dict) else {}
            seen = task.get("time") or page.get("scanDate")
            for name in (page.get("domain"), page.get("apexDomain"), self.host_of_url(str(page.get("url") or ""))):
                if isinstance(name, str) and name:
                    entries.append(self.entry(name, first=seen, last=seen, detail="urlscan result"))
        return entries


class CommonCrawlSource(PassiveSource):
    '''
    Common Crawl index: hostnames in URLs the crawl holds for the domain. Keyless.

    The index is published per crawl, so the collection list is fetched first and the most recent crawl's
    CDX endpoint is queried. Only that one crawl is searched, which bounds the work; older crawls would add
    names that are correspondingly more historical.
    '''

    name: ClassVar[str] = "commoncrawl"
    label: ClassVar[str] = "Common Crawl"
    kind: ClassVar[str] = SourceKind.URL_INDEX
    HOSTS: ClassVar[tuple[str, ...]] = ("index.commoncrawl.org",)
    COLLECTIONS: ClassVar[str] = "https://index.commoncrawl.org/collinfo.json"
    LIMIT: ClassVar[int] = 2000

    async def fetch(self, client: SafeHttpClient, hostname: str) -> list[PassiveEntry]:
        '''
        Query the most recent Common Crawl index for URLs under the domain.
        Parameters:
            client (SafeHttpClient): Provider-scoped client.
            hostname (str): Target hostname.
        Returns:
            list[PassiveEntry]: One entry per distinct hostname seen.
        Raises:
            SourceError: On failure or an unexpected response shape.
        '''
        endpoint = await self.latest_index(client)
        url = f"{endpoint}?url={quote(f'*.{hostname}')}&output=json&fl=url,timestamp&limit={self.LIMIT}"
        rows = await fetch_json_lines(client, url)
        entries: list[PassiveEntry] = []
        for row in rows:
            name = self.host_of_url(str(row.get("url") or ""))
            if name:
                stamp = row.get("timestamp")
                entries.append(self.entry(name, first=stamp, last=stamp, detail="indexed URL"))
        return entries

    async def latest_index(self, client: SafeHttpClient) -> str:
        '''
        The CDX endpoint of the most recent published crawl.
        Parameters:
            client (SafeHttpClient): Provider-scoped client.
        Returns:
            str: Absolute CDX API URL.
        Raises:
            SourceError: If the collection list is unusable or names no in-scope endpoint.
        '''
        collections = await fetch_json(client, self.COLLECTIONS)
        if not isinstance(collections, list) or not collections:
            raise SourceError("collection list was empty or malformed")
        for entry in collections:                       # newest first in Common Crawl's own ordering
            api = entry.get("cdx-api") if isinstance(entry, dict) else None
            if isinstance(api, str) and urlsplit(api).hostname in self.HOSTS:
                return api
        raise SourceError("collection list named no usable cdx-api endpoint")


class WaybackSource(PassiveSource):
    '''
    Wayback Machine CDX: hostnames in URLs the Internet Archive holds for the domain. Keyless.

    This asks the archive only for distinct hostnames. The ``historical`` module queries the same archive
    for the URLs themselves; enabling both makes two independent requests.
    '''

    name: ClassVar[str] = "wayback"
    label: ClassVar[str] = "Wayback Machine"
    kind: ClassVar[str] = SourceKind.URL_INDEX
    HOSTS: ClassVar[tuple[str, ...]] = ("web.archive.org",)
    URL: ClassVar[str] = ("https://web.archive.org/cdx/search/cdx?url={domain}&matchType=domain&output=json"
                          "&fl=original,timestamp&collapse=urlkey&limit={limit}")
    LIMIT: ClassVar[int] = 5000

    async def fetch(self, client: SafeHttpClient, hostname: str) -> list[PassiveEntry]:
        '''
        Query the Wayback CDX API for archived URLs under the domain.
        Parameters:
            client (SafeHttpClient): Provider-scoped client.
            hostname (str): Target hostname.
        Returns:
            list[PassiveEntry]: One entry per distinct hostname seen.
        Raises:
            SourceError: On failure or an unexpected response shape.
        '''
        data = await fetch_json(client, self.URL.format(domain=quote(hostname), limit=self.LIMIT))
        if not isinstance(data, list):
            raise SourceError("unexpected response shape")
        entries: list[PassiveEntry] = []
        for row in data[1:]:                             # row 0 is the column header
            if not isinstance(row, list) or not row:
                continue
            name = self.host_of_url(str(row[0]))
            if name:
                stamp = row[1] if len(row) > 1 else None
                entries.append(self.entry(name, first=stamp, last=stamp, detail="archived URL"))
        return entries


class RapidDnsSource(PassiveSource):
    '''
    RapidDNS subdomain listing. Keyless, but an HTML page rather than an API: names are extracted from the
    markup, so a layout change degrades this source to "no results" instead of wrong ones.
    '''

    name: ClassVar[str] = "rapiddns"
    label: ClassVar[str] = "RapidDNS"
    kind: ClassVar[str] = SourceKind.SCRAPE
    HOSTS: ClassVar[tuple[str, ...]] = ("rapiddns.io",)
    URL: ClassVar[str] = "https://rapiddns.io/subdomain/{domain}?full=1"

    async def fetch(self, client: SafeHttpClient, hostname: str) -> list[PassiveEntry]:
        '''
        Fetch and parse the RapidDNS subdomain listing.
        Parameters:
            client (SafeHttpClient): Provider-scoped client.
            hostname (str): Target hostname.
        Returns:
            list[PassiveEntry]: One entry per name found in the listing.
        Raises:
            SourceError: On failure.
        '''
        text = await fetch_text(client, self.URL.format(domain=quote(hostname)))
        return [self.entry(name, detail="listing row") for name in self.hosts_in(text, hostname)]


class HackerTargetSource(PassiveSource):
    '''
    HackerTarget hostsearch: a plain ``hostname,address`` listing. Keyless (free tier, rate-limited).
    '''

    name: ClassVar[str] = "hackertarget"
    label: ClassVar[str] = "HackerTarget"
    kind: ClassVar[str] = SourceKind.PASSIVE_DNS
    HOSTS: ClassVar[tuple[str, ...]] = ("api.hackertarget.com",)
    URL: ClassVar[str] = "https://api.hackertarget.com/hostsearch/?q={domain}"

    async def fetch(self, client: SafeHttpClient, hostname: str) -> list[PassiveEntry]:
        '''
        Fetch the hostsearch listing and split each ``hostname,address`` row.
        Parameters:
            client (SafeHttpClient): Provider-scoped client.
            hostname (str): Target hostname.
        Returns:
            list[PassiveEntry]: One entry per row.
        Raises:
            SourceError: On failure or when the service returns an error line.
        '''
        text = await fetch_text(client, self.URL.format(domain=quote(hostname)))
        if "error" in text[:120].lower() or "api count exceeded" in text.lower():
            raise SourceError(text.strip()[:200] or "provider returned an error")
        entries: list[PassiveEntry] = []
        for line in text.splitlines():
            name, _, address = line.strip().partition(",")
            if name:
                entries.append(self.entry(name, address=address.strip() or None, detail="hostsearch row"))
        return entries


class AnubisSource(PassiveSource):
    '''
    Anubis-DB (jldc.me): a community subdomain dataset returning a plain JSON array. Keyless.
    '''

    name: ClassVar[str] = "anubis"
    label: ClassVar[str] = "Anubis-DB"
    kind: ClassVar[str] = SourceKind.PASSIVE_DNS
    HOSTS: ClassVar[tuple[str, ...]] = ("jldc.me",)
    URL: ClassVar[str] = "https://jldc.me/anubis/subdomains/{domain}"

    async def fetch(self, client: SafeHttpClient, hostname: str) -> list[PassiveEntry]:
        '''
        Query Anubis-DB for the domain's known subdomains.
        Parameters:
            client (SafeHttpClient): Provider-scoped client.
            hostname (str): Target hostname.
        Returns:
            list[PassiveEntry]: One entry per name.
        Raises:
            SourceError: On failure or an unexpected response shape.
        '''
        data = await fetch_json(client, self.URL.format(domain=quote(hostname)))
        if data is None:
            return []
        if not isinstance(data, list):
            raise SourceError("unexpected response shape")
        return [self.entry(name, detail="dataset entry") for name in data if isinstance(name, str) and name]


class BufferOverSource(PassiveSource):
    '''
    BufferOver (tls.bufferover.run): names seen in TLS certificates and reverse DNS across internet-wide
    scan data. Needs a free API key in ``$SITERECON_BUFFEROVER_KEY``; without it the source is skipped.
    '''

    name: ClassVar[str] = "bufferover"
    label: ClassVar[str] = "BufferOver"
    kind: ClassVar[str] = SourceKind.PASSIVE_DNS
    HOSTS: ClassVar[tuple[str, ...]] = ("tls.bufferover.run",)
    key_env: ClassVar[str | None] = "SITERECON_BUFFEROVER_KEY"
    key_header: ClassVar[str | None] = "x-api-key"
    URL: ClassVar[str] = "https://tls.bufferover.run/dns?q=.{domain}"

    async def fetch(self, client: SafeHttpClient, hostname: str) -> list[PassiveEntry]:
        '''
        Query BufferOver's DNS dataset.

        Rows come as ``address,hostname`` strings under ``Results`` (current format) or under the legacy
        ``FDNS_A``/``RDNS`` keys; both are accepted so a format rollover does not silently drop coverage.
        Parameters:
            client (SafeHttpClient): Provider-scoped client.
            hostname (str): Target hostname.
        Returns:
            list[PassiveEntry]: One entry per row.
        Raises:
            SourceError: On failure or an unexpected response shape.
        '''
        data = await fetch_json(client, self.URL.format(domain=quote(hostname)), headers=self.headers())
        if not isinstance(data, dict):
            raise SourceError("unexpected response shape")
        rows: list[str] = []
        for key in ("Results", "FDNS_A", "RDNS"):
            value = data.get(key)
            if isinstance(value, list):
                rows.extend(str(item) for item in value)
        if not rows and data.get("Error"):
            raise SourceError(str(data["Error"])[:200])
        entries: list[PassiveEntry] = []
        for row in rows:
            parts = [p.strip() for p in row.split(",") if p.strip()]
            names = [p for p in parts if not re.fullmatch(r"[0-9a-fA-F:.]+", p)]
            address = next((p for p in parts if re.fullmatch(r"[0-9a-fA-F:.]+", p)), None)
            for name in names:
                entries.append(self.entry(name, address=address, detail="scan dataset row"))
        return entries


REGISTRY: dict[str, type[PassiveSource]] = {
    source.name: source for source in (
        AlienVaultOtxSource, UrlScanSource, CommonCrawlSource, WaybackSource, RapidDnsSource,
        HackerTargetSource, AnubisSource, BufferOverSource,
    )
}

# Sources that need no account and no API key.
KEYLESS: tuple[str, ...] = tuple(name for name, cls in REGISTRY.items() if cls.key_env is None)

# What ``--subdomain-source all`` resolves to: every registered source. Keyed sources in the list are
# skipped (with a reason) when their credential is unset, so 'all' is safe to pass unconditionally.
ALL_SOURCES: tuple[str, ...] = tuple(REGISTRY)


def resolve_sources(requested: Iterable[object] | None) -> list[str]:
    '''
    Resolve requested source ids to known ones, in registry order.

    ``None`` or an empty selection means "CT only" — the passive sources stay off unless asked for, because
    each one discloses the target to another third party. ``all`` expands to every registered source.
    Parameters:
        requested (Iterable[object] | None): Source ids, possibly containing 'all'/'none', or None.
    Returns:
        list[str]: Known source ids to query (possibly empty).
    '''
    if requested is None:
        return []
    names = {str(n).strip().lower() for n in requested if str(n).strip()}
    if not names or "none" in names:
        return []
    if "all" in names:
        return list(ALL_SOURCES)
    if "keyless" in names:
        return list(KEYLESS)
    return [name for name in REGISTRY if name in names]


def unknown_sources(requested: Iterable[object] | None) -> list[str]:
    '''
    The requested source ids that are not registered, so the CLI can reject a typo instead of silently
    running fewer sources than the operator asked for.
    Parameters:
        requested (Iterable[object] | None): Requested source ids, or None.
    Returns:
        list[str]: Sorted unknown ids.
    '''
    if requested is None:
        return []
    special = {"all", "none", "keyless"}
    return sorted({str(n).strip().lower() for n in requested if str(n).strip()} - set(REGISTRY) - special)


def scope_hosts(sources: list[str]) -> list[str]:
    '''
    Every provider host the given sources contact, for building their allow-listed client.
    Parameters:
        sources (list[str]): Source ids.
    Returns:
        list[str]: Sorted provider hostnames.
    '''
    return sorted({host for name in sources for host in REGISTRY[name].HOSTS})


def in_scope_names(entries: list[PassiveEntry], hostname: str) -> list[PassiveEntry]:
    '''
    Keep only entries whose hostname is the target or one of its subdomains.
    Parameters:
        entries (list[PassiveEntry]): Entries from any source.
        hostname (str): Target hostname.
    Returns:
        list[PassiveEntry]: The in-scope subset.
    '''
    return [e for e in entries if e.hostname and matches_suffix(e.hostname.lower().rstrip("."), hostname)]
