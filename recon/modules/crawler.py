'''
Scope-limited website crawler. GET requests only; forms are recorded but never submitted.
Respects robots.txt (Disallow/Allow for '*', Crawl-delay), depth and page limits.
'''

from __future__ import annotations

import asyncio
import re
from typing import ClassVar
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from recon.models import CollectionError, CrawlData, CrawledPage, DiscoveredUrl, FormRecord, RobotsInfo
from recon.modules.base import Collector
from recon.modules.html import HtmlParser
from recon.modules.http import SecurityHeaderParser
from recon.utils import SafeHttpClient, Scope, redact_url


class RobotsRules:
    '''
    Evaluates robots.txt Allow/Disallow rules for '*' (longest match wins; supports '*' and '$').
    '''

    def __init__(self, disallow: list[str], allow: list[str]) -> None:
        '''
        Compile rules.
        Parameters:
            disallow (list[str]): Disallow path patterns.
            allow (list[str]): Allow path patterns.
        '''
        self._rules = [(len(p), True, self._compile(p)) for p in allow] + \
                      [(len(p), False, self._compile(p)) for p in disallow]

    @classmethod
    def from_info(cls, info: RobotsInfo | None) -> RobotsRules:
        '''
        Build rules from parsed robots.txt (no rules when absent).
        Parameters:
            info (RobotsInfo | None): Parsed robots.txt.
        Returns:
            RobotsRules: Rules object.
        '''
        if info is None or not info.present:
            return cls([], [])
        return cls(info.disallow, info.allow)

    @staticmethod
    def _compile(pattern: str) -> re.Pattern[str]:
        '''
        Translate a robots path pattern into a regex anchored at the path start.
        Parameters:
            pattern (str): Rule path, possibly containing '*' and a trailing '$'.
        Returns:
            re.Pattern[str]: Compiled matcher.
        '''
        anchored = pattern.endswith("$")
        body = re.escape(pattern.rstrip("$")).replace(r"\*", ".*")
        return re.compile("^" + body + ("$" if anchored else ""))

    def allows(self, path: str) -> bool:
        '''
        Whether a path (with query) may be fetched.
        Parameters:
            path (str): URL path plus optional '?query'.
        Returns:
            bool: True if allowed.
        '''
        matches = [(length, allow) for length, allow, rx in self._rules if rx.match(path)]
        if not matches:
            return True
        longest = max(m[0] for m in matches)
        return any(allow for length, allow in matches if length == longest)  # ties favour Allow


class Crawler(Collector[CrawlData]):
    '''
    Breadth-first crawl of in-scope pages starting from seed URLs.
    '''

    name: ClassVar[str] = "crawler"
    SKIP_EXTENSIONS: ClassVar[frozenset[str]] = frozenset({
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".avif", ".pdf", ".zip", ".gz",
        ".tar", ".rar", ".7z", ".mp3", ".mp4", ".webm", ".mov", ".avi", ".woff", ".woff2", ".ttf", ".otf",
        ".eot", ".css", ".js", ".mjs", ".map", ".json", ".xml", ".txt", ".csv", ".dmg", ".exe", ".apk",
    })
    MAX_BODY_KEPT: ClassVar[int] = 512 * 1024
    MAX_ROBOTS_DELAY: ClassVar[float] = 5.0

    def __init__(
        self,
        hostname: str,
        client: SafeHttpClient,
        seeds: list[str],
        *,
        max_depth: int = 1,
        max_pages: int = 25,
        delay: float = 0.25,
        robots: RobotsInfo | None = None,
        respect_robots: bool = True,
        concurrency: int = 2,
    ) -> None:
        '''
        Create the crawler.
        Parameters:
            hostname (str): Normalized target hostname (defines scope).
            client (SafeHttpClient): Target-scoped HTTP client.
            seeds (list[str]): Starting URLs (depth 0).
            max_depth (int): Maximum link depth from a seed.
            max_pages (int): Maximum pages to fetch.
            delay (float): Seconds to wait between request batches.
            robots (RobotsInfo | None): Parsed robots.txt.
            respect_robots (bool): Skip URLs disallowed for '*'.
            concurrency (int): Concurrent page fetches.
        '''
        self.scope = Scope.for_target(hostname)
        self.client = client
        self.seeds = list(dict.fromkeys(u for u in (self.normalize(s) for s in seeds) if u))
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.respect_robots = respect_robots
        self.rules = RobotsRules.from_info(robots) if respect_robots else RobotsRules([], [])
        robots_delay = min(robots.crawl_delay or 0.0, self.MAX_ROBOTS_DELAY) if robots else 0.0
        self.delay = max(delay, robots_delay if respect_robots else 0.0)
        self.concurrency = max(1, concurrency)

    def normalize(self, url: str, base: str | None = None) -> str | None:
        '''
        Resolve and normalize a link; return None if it is out of scope or not crawlable.
        Parameters:
            url (str): Link as written.
            base (str | None): Page URL to resolve relative links against.
        Returns:
            str | None: Normalized absolute URL without fragment, or None.
        '''
        try:
            parts = urlsplit(urljoin(base, url.strip()) if base else url.strip())
        except ValueError:
            return None
        if parts.scheme not in ("http", "https") or not self.scope.allows(parts.hostname):
            return None
        host = parts.hostname.lower()
        default = {"http": 80, "https": 443}[parts.scheme]
        try:
            port = parts.port
        except ValueError:
            return None
        netloc = host if port in (None, default) else f"{host}:{port}"
        query = "&".join(sorted(parts.query.split("&"))) if parts.query else ""
        return urlunsplit((parts.scheme, netloc, parts.path or "/", query, ""))

    def _skippable(self, url: str) -> bool:
        '''
        Whether a URL points at a non-HTML asset by extension.
        Parameters:
            url (str): Normalized URL.
        Returns:
            bool: True to skip fetching.
        '''
        path = urlsplit(url).path.lower()
        return any(path.endswith(ext) for ext in self.SKIP_EXTENSIONS)

    async def collect(self) -> tuple[CrawlData, list[CollectionError]]:
        '''
        Crawl breadth-first within depth, page and robots limits.
        Returns:
            tuple[CrawlData, list[CollectionError]]: Pages, unfetched discovered URLs, forms and fetch errors.
        '''
        data = CrawlData(seeds=[redact_url(s) for s in self.seeds], max_depth=self.max_depth,
                         max_pages=self.max_pages, robots_respected=self.respect_robots, crawl_delay=self.delay)
        errors: list[CollectionError] = []
        queued: set[str] = set(self.seeds)
        frontier: list[tuple[str, int, str | None]] = [(s, 0, None) for s in self.seeds]

        while frontier:
            current, frontier = frontier, []
            for i in range(0, len(current), self.concurrency):
                remaining = self.max_pages - len(data.pages)
                if remaining <= 0:
                    data.page_limit_reached = True
                    data.discovered += [DiscoveredUrl(url=redact_url(u), source_url=s and redact_url(s), reason="page_limit")
                                        for u, _, s in current[i:]]
                    frontier = []
                    break
                batch = current[i:i + min(self.concurrency, remaining)]
                results = await asyncio.gather(*(self._fetch(url, depth, src, data) for url, depth, src in batch))
                for (url, depth, _), (page, links) in zip(batch, results):
                    if page is None:
                        continue
                    data.pages.append(page)
                    if page.error:
                        errors.append(self.error(page.url, "fetch_failed", page.error))
                    for link in links:
                        if link in queued:
                            continue
                        queued.add(link)
                        if self._skippable(link):
                            data.discovered.append(DiscoveredUrl(url=redact_url(link), source_url=page.url, reason="non_html"))
                        elif depth + 1 > self.max_depth:
                            data.discovered.append(DiscoveredUrl(url=redact_url(link), source_url=page.url, reason="depth_limit"))
                        else:
                            frontier.append((link, depth + 1, url))
                if self.delay:
                    await asyncio.sleep(self.delay)
        return data, errors

    async def _fetch(self, url: str, depth: int, source: str | None,
                     data: CrawlData) -> tuple[CrawledPage | None, list[str]]:
        '''
        Fetch one page (unless robots disallows it) and extract links, forms and resources.
        Parameters:
            url (str): Normalized URL to fetch.
            depth (int): Link depth.
            source (str | None): Page that linked here.
            data (CrawlData): Crawl results, updated with discovered URLs and forms.
        Returns:
            tuple[CrawledPage | None, list[str]]: The page (None if skipped) and normalized in-scope links.
        '''
        parts = urlsplit(url)
        path = parts.path + (f"?{parts.query}" if parts.query else "")
        if not self.rules.allows(path):
            data.discovered.append(DiscoveredUrl(url=redact_url(url), source_url=source and redact_url(source),
                                                 reason="robots_disallowed"))
            return None, []
        page = CrawledPage(url=redact_url(url), source_url=source and redact_url(source), depth=depth,
                           query_params=sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)}))
        outcome = await self.client.fetch(url)
        resp = outcome.final
        if resp is None:
            page.error = outcome.error or f"stopped: {outcome.stopped_reason}"
            page.final_url = outcome.stopped_url and redact_url(outcome.stopped_url)
            return page, []
        headers: dict[str, list[str]] = {}
        for key, value in resp.headers:
            headers.setdefault(key.lower(), []).append(value)
        page.status_code = resp.status_code
        page.final_url = redact_url(resp.url)
        page.content_type = resp.header("content-type")
        page.response_time_ms = resp.elapsed_ms
        page.security_headers = {name: sh.value for name, sh in SecurityHeaderParser.inspect_all(headers).items()}
        page.cache_control = resp.header("cache-control")
        page.cors = SecurityHeaderParser.cors(headers)
        page.set_cookies = headers.get("set-cookie", [])
        if "html" not in (page.content_type or "").lower() or resp.status_code >= 400:
            return page, []

        page.body = resp.body[: self.MAX_BODY_KEPT]
        soup = BeautifulSoup(resp.body, "html.parser")
        if soup.title and soup.title.string:
            page.title = soup.title.string.strip()[:300]
        links = [n for n in (self.normalize(a.get("href", ""), resp.url) for a in soup.find_all(["a", "area"], href=True)) if n]
        page.links_found = len(links)
        for form in soup.find_all("form"):
            action = urljoin(resp.url, form.get("action") or resp.url)
            names = [str(f.get("name")) for f in form.find_all(["input", "select", "textarea"]) if f.get("name")]
            data.forms.append(FormRecord(
                page_url=page.url, action=redact_url(action), method=(form.get("method") or "get").lower(),
                input_names=names[:50],
                has_password_field=any((f.get("type") or "").lower() == "password" for f in form.find_all("input"))))
        parsed = HtmlParser(resp.body, resp.url, self.scope).parse()
        page.resource_urls = [r.url for r in parsed.resources if r.kind in ("script", "stylesheet", "modulepreload", "iframe", "image")][:200]
        page.external_domains = parsed.external_domains
        return page, list(dict.fromkeys(links))
