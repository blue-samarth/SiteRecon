'''
Standard public resources: robots.txt, sitemaps, security.txt, web manifest, favicon and humans.txt.
Each is fetched independently through the scope-restricted client; one failure never affects the others.
'''

from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import zlib
from datetime import UTC, datetime
from typing import ClassVar
from urllib.parse import urljoin, urlsplit
from xml.etree import ElementTree

from recon.models import (
    CollectionError,
    FetchedResource,
    HtmlData,
    ManifestInfo,
    ResourcesData,
    RobotsInfo,
    SecurityTxtInfo,
    SitemapInfo,
    TextResourceInfo,
)
from recon.modules.base import Collector
from recon.utils import RawResponse, SafeHttpClient, Scope


class RobotsParser:
    '''
    Parses robots.txt into sitemaps, user agents and the rules for '*'.
    '''

    @staticmethod
    def parse(text: str, info: RobotsInfo) -> None:
        '''
        Fill a RobotsInfo from robots.txt text.
        Parameters:
            text (str): robots.txt body.
            info (RobotsInfo): Object to update in place.
        '''
        agents: list[str] = []
        in_group_for_all = False
        last_was_agent = False
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if ":" not in line:
                continue
            key, value = (p.strip() for p in line.split(":", 1))
            key = key.lower()
            if key == "sitemap" and value:
                info.sitemaps.append(value)
            elif key == "user-agent":
                if not last_was_agent:
                    agents = []
                agents.append(value)
                if value not in info.user_agents:
                    info.user_agents.append(value)
                in_group_for_all = "*" in agents
                last_was_agent = True
                continue
            elif in_group_for_all and key == "disallow" and value:
                info.disallow.append(value)
            elif in_group_for_all and key == "allow" and value:
                info.allow.append(value)
            elif in_group_for_all and key == "crawl-delay":
                try:
                    info.crawl_delay = float(value)
                except ValueError:
                    pass
            last_was_agent = False


class SecurityTxtParser:
    '''
    Parses security.txt fields (RFC 9116).
    '''

    @staticmethod
    def parse(text: str, info: SecurityTxtInfo, now: datetime) -> None:
        '''
        Fill a SecurityTxtInfo from security.txt text.
        Parameters:
            text (str): security.txt body (may be PGP clear-signed).
            info (SecurityTxtInfo): Object to update in place.
            now (datetime): Reference time for the Expires check.
        '''
        info.signed = "-----BEGIN PGP SIGNED MESSAGE-----" in text
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", "-----", "Hash:")) or ":" not in line:
                continue
            key, value = (p.strip() for p in line.split(":", 1))
            if not key or " " in key or not value:
                continue
            info.fields.setdefault(key.lower(), []).append(value)
        info.contacts = info.fields.get("contact", [])
        expires = info.fields.get("expires", [None])[0]
        if expires:
            try:
                parsed = datetime.fromisoformat(expires.replace("Z", "+00:00"))
                info.expires = parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
                info.expired = info.expires < now
            except ValueError:
                info.expires = None


class SitemapParser:
    '''
    Parses sitemap XML (urlset or sitemapindex), namespace-agnostic.
    '''

    MAX_URLS: ClassVar[int] = 1000

    @classmethod
    def parse(cls, body: bytes, info: SitemapInfo, scope: Scope) -> None:
        '''
        Fill a SitemapInfo from sitemap XML.
        Parameters:
            body (bytes): XML document (already decompressed).
            info (SitemapInfo): Object to update in place.
            scope (Scope): Only in-scope URLs are kept.
        Raises:
            ValueError: If the document is not parseable XML.
        '''
        try:
            root = ElementTree.fromstring(body)  # expat: no external entities, entity-expansion limits
        except ElementTree.ParseError as exc:
            raise ValueError(f"invalid sitemap XML: {exc}") from exc
        tag = root.tag.rsplit("}", 1)[-1].lower()
        info.kind = tag
        locs = [el.text.strip() for el in root.iter() if el.tag.rsplit("}", 1)[-1] == "loc" and el.text]
        info.url_count = len(locs)
        in_scope = [u for u in locs if urlsplit(u).scheme in ("http", "https") and scope.allows(urlsplit(u).hostname)]
        if tag == "sitemapindex":
            info.nested = in_scope[:50]
        else:
            info.urls = in_scope[: cls.MAX_URLS]


class ResourcesCollector(Collector[ResourcesData]):
    '''
    Fetches the standard public resources of the target origin.
    '''

    name: ClassVar[str] = "resources"
    MAX_SITEMAPS: ClassVar[int] = 5
    MAX_DECOMPRESSED: ClassVar[int] = 10 * 1024 * 1024

    def __init__(self, hostname: str, client: SafeHttpClient, origin: str, html: HtmlData | None = None,
                 now: datetime | None = None) -> None:
        '''
        Create the collector.
        Parameters:
            hostname (str): Normalized target hostname.
            client (SafeHttpClient): Target-scoped HTTP client.
            origin (str): Origin to inspect, e.g. 'https://example.com'.
            html (HtmlData | None): Parsed landing page, used to find the declared manifest and favicon.
            now (datetime | None): Reference time for security.txt expiry; defaults to the current UTC time.
        '''
        self.scope = Scope.for_target(hostname)
        self.client = client
        self.origin = origin.rstrip("/")
        self.html = html
        self.now = now or datetime.now(UTC)
        self._errors: list[CollectionError] = []

    async def collect(self) -> tuple[ResourcesData, list[CollectionError]]:
        '''
        Fetch every resource concurrently; sitemaps follow robots.txt.
        Returns:
            tuple[ResourcesData, list[CollectionError]]: Resource observations and fetch errors.
        '''
        data = ResourcesData(origin=self.origin)
        data.robots, data.security_txt, data.manifest, data.favicon, data.humans = await asyncio.gather(
            self._robots(), self._security_txt(), self._manifest(), self._favicon(), self._humans())
        data.sitemaps = await self._sitemaps(data.robots)
        return data, self._errors

    # ------------------------------------------------------------------ fetch helpers

    async def _get(self, url: str, info: FetchedResource) -> RawResponse | None:
        '''
        GET a resource, recording status, type, size and hash on the info object.
        Parameters:
            url (str): Absolute URL.
            info (FetchedResource): Object to update in place.
        Returns:
            RawResponse | None: The final response, or None on failure.
        '''
        outcome = await self.client.fetch(url)
        resp = outcome.final
        if resp is None:
            info.error = outcome.error or outcome.stopped_reason
            if outcome.error_type not in (None, "dns_resolution"):
                self._errors.append(self.error(url, outcome.error_type or "fetch_failed", info.error or ""))
            return None
        info.status_code = resp.status_code
        info.content_type = resp.header("content-type")
        if resp.status_code == 200:
            info.size = len(resp.body)
            info.sha256 = hashlib.sha256(resp.body).hexdigest()
        return resp

    @staticmethod
    def _is_html(resp: RawResponse) -> bool:
        '''
        Whether a response is an HTML page (a soft 404 for non-HTML resources).
        Parameters:
            resp (RawResponse): Response to inspect.
        Returns:
            bool: True if the content type or body looks like HTML.
        '''
        ctype = (resp.header("content-type") or "").lower()
        head = resp.body[:200].lstrip().lower()
        return "html" in ctype or head.startswith((b"<!doctype html", b"<html"))

    def _text_present(self, resp: RawResponse | None, info: FetchedResource) -> str | None:
        '''
        Decide whether a text resource exists and return its body.
        Parameters:
            resp (RawResponse | None): Response, if any.
            info (FetchedResource): Object to update in place (present / soft_404).
        Returns:
            str | None: Decoded text, or None if absent.
        '''
        if resp is None or resp.status_code != 200:
            return None
        if self._is_html(resp):
            info.soft_404 = True
            return None
        info.present = True
        return resp.body.decode("utf-8", "replace")

    # ------------------------------------------------------------------ resources

    async def _robots(self) -> RobotsInfo:
        '''
        Fetch and parse /robots.txt.
        Returns:
            RobotsInfo: Parsed robots.txt (present=False if absent).
        '''
        info = RobotsInfo(url=f"{self.origin}/robots.txt")
        text = self._text_present(await self._get(info.url, info), info)
        if text is not None:
            RobotsParser.parse(text, info)
        return info

    async def _security_txt(self) -> SecurityTxtInfo:
        '''
        Fetch /.well-known/security.txt, falling back to the legacy /security.txt.
        Returns:
            SecurityTxtInfo: Parsed security.txt (present=False if absent at both locations).
        '''
        info = SecurityTxtInfo(url=f"{self.origin}/.well-known/security.txt")
        for path in ("/.well-known/security.txt", "/security.txt"):
            info.url = f"{self.origin}{path}"
            text = self._text_present(await self._get(info.url, info), info)
            if text is not None:
                SecurityTxtParser.parse(text, info, self.now)
                break
        return info

    async def _manifest(self) -> ManifestInfo:
        '''
        Fetch the web app manifest declared by the page (or /manifest.json) and parse it.
        Returns:
            ManifestInfo: Parsed manifest (present=False if absent or invalid).
        '''
        declared = next((r.url for r in (self.html.resources if self.html else [])
                         if r.kind == "manifest" and r.same_site), None)
        info = ManifestInfo(url=declared or f"{self.origin}/manifest.json")
        resp = await self._get(info.url, info)
        if resp is None or resp.status_code != 200 or self._is_html(resp):
            info.soft_404 = bool(resp is not None and resp.status_code == 200)
            return info
        try:
            doc = json.loads(resp.body)
        except json.JSONDecodeError as exc:
            info.error = f"invalid JSON: {exc}"
            return info
        if not isinstance(doc, dict):
            info.error = "manifest is not a JSON object"
            return info
        info.present = True
        for key in ("name", "short_name", "start_url", "scope", "display", "theme_color"):
            value = doc.get(key)
            setattr(info, key, str(value) if value is not None else None)
        info.icon_count = len(doc.get("icons") or []) if isinstance(doc.get("icons"), list) else 0
        return info

    async def _favicon(self) -> FetchedResource:
        '''
        Fetch the page-declared favicon (if same-site) or /favicon.ico.
        Returns:
            FetchedResource: Favicon status, type, size and SHA-256.
        '''
        declared = next((u for u in (self.html.favicons if self.html else [])
                         if self.scope.allows(urlsplit(u).hostname)), None)
        info = FetchedResource(url=declared or f"{self.origin}/favicon.ico")
        resp = await self._get(info.url, info)
        if resp is not None and resp.status_code == 200:
            info.soft_404 = self._is_html(resp)
            info.present = not info.soft_404
        return info

    async def _humans(self) -> TextResourceInfo:
        '''
        Fetch /humans.txt and keep a short excerpt.
        Returns:
            TextResourceInfo: humans.txt status and first lines.
        '''
        info = TextResourceInfo(url=f"{self.origin}/humans.txt")
        text = self._text_present(await self._get(info.url, info), info)
        if text is not None:
            info.excerpt = [line.rstrip()[:200] for line in text.splitlines() if line.strip()][:20]
        return info

    async def _sitemaps(self, robots: RobotsInfo) -> list[SitemapInfo]:
        '''
        Fetch sitemaps listed in robots.txt (plus /sitemap.xml), following in-scope sitemap indexes.
        Parameters:
            robots (RobotsInfo): Parsed robots.txt.
        Returns:
            list[SitemapInfo]: Every sitemap fetched (up to MAX_SITEMAPS).
        '''
        queue: list[tuple[str, str]] = [(u, "robots.txt") for u in robots.sitemaps
                                        if self.scope.allows(urlsplit(urljoin(self.origin, u)).hostname)]
        if not queue:
            queue.append((f"{self.origin}/sitemap.xml", "default"))
        seen: set[str] = set()
        results: list[SitemapInfo] = []
        while queue and len(results) < self.MAX_SITEMAPS:
            url, source = queue.pop(0)
            url = urljoin(self.origin + "/", url)
            if url in seen:
                continue
            seen.add(url)
            info = SitemapInfo(url=url, source=source)
            results.append(info)
            resp = await self._get(url, info)
            if resp is None or resp.status_code != 200:
                continue
            if self._is_html(resp):
                info.soft_404 = True
                continue
            try:
                body = self._decompress(resp.body, url)
                SitemapParser.parse(body, info, self.scope)
                info.present = True
            except ValueError as exc:
                info.error = str(exc)
                continue
            queue.extend((n, url) for n in info.nested)
        return results

    def _decompress(self, body: bytes, url: str) -> bytes:
        '''
        Decompress a gzip sitemap with a size cap (decompression-bomb protection).
        Parameters:
            body (bytes): Raw body.
            url (str): Sitemap URL (used to detect .gz).
        Returns:
            bytes: XML bytes.
        Raises:
            ValueError: If decompression fails or exceeds the cap.
        '''
        if not (url.endswith(".gz") or body[:2] == b"\x1f\x8b"):
            return body
        try:
            decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
            out = decomp.decompress(body, self.MAX_DECOMPRESSED + 1)
        except (zlib.error, gzip.BadGzipFile) as exc:
            raise ValueError(f"invalid gzip sitemap: {exc}") from exc
        if len(out) > self.MAX_DECOMPRESSED:
            raise ValueError("decompressed sitemap exceeds size limit")
        return out

