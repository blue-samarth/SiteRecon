'''
On-page SEO evidence, derived from pages the HTTP and crawler modules already fetched.

This collector sends no requests of its own and queries no search engine: it re-parses the retained
response bodies for the markup search engines read (title, description, canonical, robots directives,
headings, link graph, structured data) and computes the site-wide facts that only exist across pages —
duplicate titles, orphan pages, sitemap coverage, broken internal links.

What it deliberately does not do:
  * judge anything. No page is "too slow" or "too thin" here; lengths, word counts and timings are
    recorded as measured and the thresholds live in ``recon.analysis.seo_checks``.
  * claim indexation. Everything about indexability is what the *site declares* (robots meta,
    X-Robots-Tag, robots.txt, rel=canonical). Whether a URL is in an index, and where it ranks, is
    knowable only from the search engine.
  * measure real-user performance. Response times are the single server timings the crawl recorded,
    never Core Web Vitals.

Coverage equals the crawl's coverage. Without ``--crawl`` there is exactly one page to analyze, which is
recorded in ``pages_source`` so a one-page result is never mistaken for a site-wide one.
'''

from __future__ import annotations

import json
import statistics
from collections import Counter
from typing import Any, ClassVar
from urllib.parse import urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup, Tag

from recon.models import (
    BrokenLink,
    CollectionError,
    CrawlData,
    DuplicateGroup,
    HostCanonical,
    HtmlData,
    HttpData,
    PageSeo,
    RedirectRecord,
    ResourcesData,
    SeoData,
    SitemapAudit,
)
from recon.modules.base import Collector
from recon.modules.crawler import RobotsRules
from recon.modules.html import HtmlCollector
from recon.utils import Scope, redact_url, registrable_domain

# Core Open Graph properties a social preview needs; missing ones are listed per page.
OG_CORE: tuple[str, ...] = ("og:title", "og:type", "og:image", "og:url")
# Elements whose text is markup or code, never page copy, so they are excluded from the word count.
_NON_CONTENT: tuple[str, ...] = ("script", "style", "noscript", "template", "svg", "iframe")


def normalize_url(url: str) -> str:
    '''
    Normalize a URL for comparing the same page across sources (sitemap, crawl, canonical).

    Only differences that never identify a different page are removed: scheme/host case, the default
    port, the fragment and a trailing slash on a non-root path. The query is kept, because '?p=1' and
    '?p=2' are genuinely different pages, and the scheme is kept, because http:// and https:// versions
    of a page are exactly the duplicate-content case the audit needs to see.
    Parameters:
        url (str): Absolute URL.
    Returns:
        str: Comparable form of the URL ('' when it cannot be parsed).
    '''
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return ""
    if not parts.hostname:
        return ""
    host = parts.hostname.lower()
    if parts.port and not ((parts.scheme == "https" and parts.port == 443)
                           or (parts.scheme == "http" and parts.port == 80)):
        host = f"{host}:{parts.port}"
    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return urlunsplit((parts.scheme.lower(), host, path, parts.query, ""))


class PageSeoParser:
    '''
    Extracts the on-page SEO facts of a single HTML document.

    Measurements only: every value is what the markup says, with no threshold applied. The internal link
    targets are exposed separately (``link_targets``) because they belong to the site-wide link graph the
    collector builds, not to this page's record.
    '''

    MAX_H1: ClassVar[int] = 10
    MAX_HREFLANG: ClassVar[int] = 50
    MAX_LINK_TARGETS: ClassVar[int] = 2000
    MAX_STRUCTURED_TYPES: ClassVar[int] = 25

    def __init__(self, body: bytes, url: str, scope: Scope) -> None:
        '''
        Prepare a parser for one page.
        Parameters:
            body (bytes): Retained response body.
            url (str): The page's own URL (base for relative references).
            scope (Scope): Scope used to tell internal links from external ones.
        '''
        self.url = url
        self.scope = scope
        self.soup = BeautifulSoup(body, "html.parser")
        self.data = PageSeo(url=redact_url(url), html_bytes=len(body))
        self.link_targets: list[str] = []

    def parse(self) -> PageSeo:
        '''
        Run every extraction step.
        Returns:
            PageSeo: The page's on-page facts.
        '''
        self._document()
        self._meta()
        self._links()
        self._headings()
        self._content()
        self._structured_data()
        return self.data

    def _document(self) -> None:
        '''
        Extract the title and the document language.
        '''
        if self.soup.title and self.soup.title.string:
            self.data.title = self.soup.title.string.strip()
            self.data.title_length = len(self.data.title)
        html_tag = self.soup.find("html")
        if isinstance(html_tag, Tag) and (lang := html_tag.get("lang")):
            self.data.lang = str(lang).strip() or None

    def _meta(self) -> None:
        '''
        Extract description, robots, viewport and the social-card metadata.
        '''
        d = self.data
        og: set[str] = set()
        for meta in self.soup.find_all("meta"):
            key = str(meta.get("name") or meta.get("property") or "").strip().lower()
            content = str(meta.get("content") or "").strip()
            if not key or not content:
                continue
            if key == "description":
                d.meta_description, d.description_length = content, len(content)
            elif key == "robots":
                d.robots_meta = content
            elif key == "viewport":
                d.viewport = content
            elif key.startswith("og:"):
                og.add(key)
            elif key == "twitter:card":
                d.twitter_card = content
        d.open_graph_present = bool(og)
        d.open_graph_missing = [k for k in OG_CORE if k not in og]
        directives = {p.strip().lower() for p in (d.robots_meta or "").split(",")}
        if "noindex" in directives or "none" in directives:
            d.indexable = False
            d.index_blockers.append("noindex_meta")
        d.nofollow = "nofollow" in directives or "none" in directives

    def _links(self) -> None:
        '''
        Extract canonical, hreflang alternates and the internal/external link counts.
        '''
        d = self.data
        for link in self.soup.find_all("link", href=True):
            rels = [r.lower() for r in (link.get("rel") or [])]
            href = str(link.get("href") or "").strip()
            if "canonical" in rels and href and d.canonical is None:
                d.canonical = redact_url(urljoin(self.url, href))
                canonical_norm = normalize_url(urljoin(self.url, href))
                d.canonical_self = bool(canonical_norm) and canonical_norm == normalize_url(self.url)
                canon_host = urlsplit(urljoin(self.url, href)).hostname
                page_reg = registrable_domain((urlsplit(self.url).hostname or "").lower())
                canon_reg = registrable_domain((canon_host or "").lower())
                d.canonical_offsite = bool(page_reg and canon_reg and page_reg != canon_reg)
            elif ("alternate" in rels and (hl := link.get("hreflang"))
                    and len(d.hreflang) < self.MAX_HREFLANG):
                d.hreflang.append(str(hl).strip().lower())
        for anchor in self.soup.find_all("a", href=True):
            href = str(anchor.get("href") or "").strip()
            if not href or href.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
                continue
            anchor_rels = {str(r).lower() for r in (anchor.get("rel") or [])}
            if "nofollow" in anchor_rels:
                d.nofollow_links += 1
            absolute = urljoin(self.url, href)
            host = (urlsplit(absolute).hostname or "").lower()
            if not host:
                continue
            if self.scope.allows(host):
                d.internal_links += 1
                if len(self.link_targets) < self.MAX_LINK_TARGETS:
                    self.link_targets.append(normalize_url(absolute))
            else:
                d.external_links += 1

    def _headings(self) -> None:
        '''
        Count headings per level, keep the H1 text and record hierarchy skips (e.g. h2 followed by h4).
        '''
        d = self.data
        counts: Counter[str] = Counter()
        previous = 0
        for tag in self.soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"]):
            level = int(tag.name[1])
            counts[tag.name] += 1
            if level == 1 and len(d.h1) < self.MAX_H1:
                d.h1.append(" ".join(tag.get_text(" ", strip=True).split())[:300])
            if previous and level > previous + 1 and len(d.heading_skips) < 10:
                d.heading_skips.append(f"h{previous} → h{level}")
            previous = level
        d.heading_counts = {f"h{i}": counts[f"h{i}"] for i in range(1, 7) if counts[f"h{i}"]}

    def _content(self) -> None:
        '''
        Count the words of visible copy and the images that declare no alt attribute at all.

        Text inside script, style and similar elements is skipped by filtering the text nodes rather than
        removing those elements: a page's JSON-LD often lives in the body, and deleting it here would make
        the structured-data inventory silently empty.

        An empty ``alt=""`` is a deliberate "decorative" declaration and is correct markup, so only a
        missing attribute counts against the page.
        '''
        body = self.soup.body or self.soup
        words = 0
        for text in body.find_all(string=True):
            if any(parent.name in _NON_CONTENT for parent in text.parents):
                continue
            words += len(text.split())
        self.data.word_count = words
        images = body.find_all("img")
        self.data.images = len(images)
        self.data.images_missing_alt = sum(1 for i in images if not i.has_attr("alt"))

    def _structured_data(self) -> None:
        '''
        Inventory the structured-data types the page declares (JSON-LD @type and microdata itemtype).
        '''
        types: list[str] = []
        for script in self.soup.find_all("script", attrs={"type": "application/ld+json"}):
            try:
                payload = json.loads(script.string or "")
            except (json.JSONDecodeError, TypeError):
                self.data.structured_data_errors += 1
                continue
            types.extend(self._jsonld_types(payload))
        for node in self.soup.find_all(itemtype=True):
            value = str(node.get("itemtype") or "").rstrip("/")
            if value:
                types.append(value.rsplit("/", 1)[-1])
        self.data.structured_data_types = list(dict.fromkeys(types))[: self.MAX_STRUCTURED_TYPES]

    @classmethod
    def _jsonld_types(cls, payload: Any) -> list[str]:
        '''
        Collect every @type in a JSON-LD payload, descending through lists and @graph.
        Parameters:
            payload (Any): Parsed JSON-LD value.
        Returns:
            list[str]: Declared type names.
        '''
        found: list[str] = []
        if isinstance(payload, list):
            for item in payload:
                found.extend(cls._jsonld_types(item))
        elif isinstance(payload, dict):
            value = payload.get("@type")
            if isinstance(value, str):
                found.append(value)
            elif isinstance(value, list):
                found.extend(str(v) for v in value if isinstance(v, str))
            for nested in ("@graph", "mainEntity", "itemListElement"):
                if nested in payload:
                    found.extend(cls._jsonld_types(payload[nested]))
        return found


class SeoCollector(Collector[SeoData]):
    '''
    Builds the site-wide SEO record from the landing page and every crawled HTML page.
    '''

    name: ClassVar[str] = "seo"
    MAX_PAGES: ClassVar[int] = 500
    MAX_SAMPLES: ClassVar[int] = 25
    MAX_DUPLICATE_GROUPS: ClassVar[int] = 40

    def __init__(self, hostname: str, origin: str, *, html: HtmlData | None, http: HttpData | None,
                 crawl: CrawlData | None, resources: ResourcesData | None) -> None:
        '''
        Create the collector.
        Parameters:
            hostname (str): Normalized target hostname.
            origin (str): Target origin, e.g. 'https://example.com'.
            html (HtmlData | None): Parsed landing page (used for its URL and parse warnings).
            http (HttpData | None): HTTP probes; supplies the landing body, headers and host variants.
            crawl (CrawlData | None): Crawled pages with their retained bodies.
            resources (ResourcesData | None): robots.txt and sitemaps for the crawlability checks.
        '''
        self.hostname = hostname
        self.origin = origin
        self.html = html
        self.http = http
        self.crawl = crawl
        self.resources = resources
        self.scope = Scope.for_target(hostname)

    async def collect(self) -> tuple[SeoData | None, list[CollectionError]]:
        '''
        Parse every available page and compute the site-wide aggregates.
        Returns:
            tuple[SeoData | None, list[CollectionError]]: SEO evidence (None when no HTML page was
                available to analyze) and any pages that could not be parsed.
        '''
        errors: list[CollectionError] = []
        rules = RobotsRules.from_info(self.resources.robots if self.resources else None)
        sitemap_norm = {normalize_url(u) for u in (self.resources.sitemap_urls() if self.resources else [])}
        sitemap_norm.discard("")

        pages: list[PageSeo] = []
        graph: Counter[str] = Counter()
        seen: set[str] = set()
        sources = self._sources()
        landing_first = bool(sources) and sources[0][2].get("is_landing", False)
        for url, body, meta in sources:
            key = normalize_url(url)
            if not key or key in seen or len(pages) >= self.MAX_PAGES:
                continue
            seen.add(key)
            try:
                parser = PageSeoParser(body, url, self.scope)
                page = parser.parse()
            except Exception as exc:  # noqa: BLE001 - one unparseable page must not lose the rest
                errors.append(self.error(redact_url(url), "parse_error", f"{type(exc).__name__}: {exc}"))
                continue
            for field, value in meta.items():
                if field != "is_landing":
                    setattr(page, field, value)
            path = urlsplit(url).path or "/"
            if not rules.allows(path):
                page.indexable = False
                page.index_blockers.append("robots_txt")
            if "noindex" in (page.x_robots_tag or "").lower():
                page.indexable = False
                page.index_blockers.append("x_robots_tag")
            if sitemap_norm:
                page.in_sitemap = key in sitemap_norm
            graph.update(t for t in set(parser.link_targets) if t != key)
            pages.append(page)

        if not pages:
            return None, [*errors, self.error(self.hostname, "no_pages",
                                              "no HTML page was available to analyze (the HTTP module "
                                              "fetched no in-scope HTML document)")]
        for page in pages:
            page.inbound_internal_links = graph.get(normalize_url(page.url), 0)

        crawled = self.crawl
        broken = self._broken_links()
        data = SeoData(
            host=self.hostname, origin=self.origin, pages=pages, pages_analyzed=len(pages),
            landing_url=pages[0].url if landing_first else None,
            pages_source="landing page + crawl" if crawled and crawled.pages else "landing page",
            crawl_max_depth=crawled.max_depth if crawled else None,
            crawl_page_limit_reached=bool(crawled and crawled.page_limit_reached),
            indexable_pages=sum(1 for p in pages if p.indexable),
            duplicates=self._duplicates(pages),
            orphan_pages=self._orphans(pages),
            broken_links=broken,
            redirects=self._redirects(),
            # None (not an empty audit) when the resources module did not run: the robots.txt and
            # sitemap checks must report "not checked", never "absent".
            sitemap=self._sitemap_audit(pages, rules, sitemap_norm, broken) if self.resources else None,
            host_canonical=self._host_canonical(),
            structured_data=self._structured_data(pages),
            languages=sorted({p.lang.split("-")[0].lower() for p in pages if p.lang}
                             | {h.split("-")[0] for p in pages for h in p.hreflang if h != "x-default"}),
            total_html_bytes=sum(p.html_bytes for p in pages),
        )
        timings = [p.response_time_ms for p in pages if p.response_time_ms is not None]
        if timings:
            data.median_response_ms = round(statistics.median(timings), 2)
            data.slowest_response_ms = round(max(timings), 2)
        landing = HtmlCollector.select_page(self.http)
        if landing is not None:
            data.compression = next(iter(landing.headers.get("content-encoding", [])), None)
            data.http_version = landing.http_version
        return data, errors

    def _sources(self) -> list[tuple[str, bytes, dict[str, Any]]]:
        '''
        The pages to analyze: the landing page first, then every crawled HTML page with a body.

        Per-page response metadata the markup cannot carry (status, depth, timing, X-Robots-Tag) is
        passed alongside the body, so a page record keeps the response it came from.
        Returns:
            list[tuple[str, bytes, dict[str, Any]]]: (url, body, extra PageSeo fields) per page.
        '''
        out: list[tuple[str, bytes, dict[str, Any]]] = []
        landing = HtmlCollector.select_page(self.http)
        if landing is not None and landing.body:
            url = landing.final_url or landing.requested_url
            out.append((url, landing.body, {
                "status_code": landing.status_code, "content_type": landing.content_type,
                "response_time_ms": landing.response_time_ms, "truncated": landing.body_truncated,
                "x_robots_tag": next(iter(landing.headers.get("x-robots-tag", [])), None),
                "final_url": redact_url(url), "depth": 0, "is_landing": True,
            }))
        for page in (self.crawl.pages if self.crawl else []):
            if not page.body or "html" not in (page.content_type or "").lower():
                continue
            out.append((page.final_url or page.url, page.body, {
                "status_code": page.status_code, "content_type": page.content_type,
                "response_time_ms": page.response_time_ms, "depth": page.depth,
                "x_robots_tag": page.x_robots_tag, "final_url": page.final_url,
                "truncated": len(page.body) >= 512 * 1024,
            }))
        return out

    def _duplicates(self, pages: list[PageSeo]) -> list[DuplicateGroup]:
        '''
        Group pages that share a title, meta description or H1.

        Only indexable pages are grouped: two blocked URLs sharing a title compete for nothing.
        Parameters:
            pages (list[PageSeo]): Analyzed pages.
        Returns:
            list[DuplicateGroup]: Groups of two or more pages, largest first.
        '''
        indexable = [p for p in pages if p.indexable]
        groups: list[DuplicateGroup] = []
        for kind, getter in (("title", lambda p: p.title),
                             ("description", lambda p: p.meta_description),
                             ("h1", lambda p: p.h1[0] if p.h1 else None)):
            buckets: dict[str, list[str]] = {}
            for page in indexable:
                value = (getter(page) or "").strip()
                if value:
                    buckets.setdefault(value, []).append(page.url)
            groups += [DuplicateGroup(kind=kind, value=value[:300], pages=urls[: self.MAX_SAMPLES])
                       for value, urls in buckets.items() if len(urls) > 1]
        groups.sort(key=lambda g: (-len(g.pages), g.kind, g.value))
        return groups[: self.MAX_DUPLICATE_GROUPS]

    def _orphans(self, pages: list[PageSeo]) -> list[str]:
        '''
        Analyzed pages that no other analyzed page links to.

        The home page is excluded (it is the entry point). This is bounded by what was crawled: a page
        here has no inbound link *among the analyzed pages*, which is a lead, not proof of a site-wide
        orphan — a page linked only from an uncrawled page looks the same.
        Parameters:
            pages (list[PageSeo]): Analyzed pages.
        Returns:
            list[str]: Orphan candidate URLs (capped).
        '''
        home = {normalize_url(self.origin), normalize_url(self.origin + "/")}
        return [p.url for p in pages
                if p.inbound_internal_links == 0 and normalize_url(p.url) not in home][: self.MAX_SAMPLES]

    def _broken_links(self) -> list[BrokenLink]:
        '''
        In-scope URLs the crawl fetched that answered with a 4xx/5xx status or a transport error.
        Returns:
            list[BrokenLink]: Broken internal targets with the page that linked to them.
        '''
        out: list[BrokenLink] = []
        for page in (self.crawl.pages if self.crawl else []):
            if (page.status_code or 0) >= 400 or page.error:
                out.append(BrokenLink(url=page.url, status_code=page.status_code,
                                      linked_from=page.source_url, error=page.error))
        return out[: self.MAX_SAMPLES]

    def _redirects(self) -> list[RedirectRecord]:
        '''
        In-scope URLs that redirected during the crawl: an internal link pointing at a non-final URL.
        Returns:
            list[RedirectRecord]: Redirecting internal URLs (capped).
        '''
        out: list[RedirectRecord] = []
        for page in (self.crawl.pages if self.crawl else []):
            if page.final_url and normalize_url(page.final_url) != normalize_url(page.url):
                out.append(RedirectRecord(url=page.url, final_url=page.final_url,
                                          linked_from=page.source_url))
        return out[: self.MAX_SAMPLES]

    def _sitemap_audit(self, pages: list[PageSeo], rules: RobotsRules, sitemap_norm: set[str],
                       broken: list[BrokenLink]) -> SitemapAudit:
        '''
        Compare the declared sitemap(s) with robots.txt and with the pages actually crawled.
        Parameters:
            pages (list[PageSeo]): Analyzed pages.
            rules (RobotsRules): Compiled robots.txt rules.
            sitemap_norm (set[str]): Normalized URLs listed across every sitemap.
            broken (list[BrokenLink]): Internal URLs that answered with an error during the crawl.
        Returns:
            SitemapAudit: The sitemap/robots/crawl comparison.
        '''
        res = self.resources
        robots = res.robots if res else None
        sitemaps = [s for s in (res.sitemaps if res else []) if s.present]
        audit = SitemapAudit(
            robots_txt_present=bool(robots and robots.present),
            robots_declares_sitemap=bool(robots and robots.sitemaps),
            sitemap_count=len(sitemaps), sitemap_urls=len(sitemap_norm),
            sitemaps_fetched=[s.url for s in sitemaps][: self.MAX_SAMPLES],
            crawled_pages=len(pages),
        )
        crawled_norm = {normalize_url(p.url) for p in pages}
        if sitemap_norm:
            audit.crawled_in_sitemap = sum(1 for p in pages if p.in_sitemap)
            audit.crawled_not_in_sitemap = [p.url for p in pages
                                            if p.in_sitemap is False and p.indexable][: self.MAX_SAMPLES]
            audit.in_sitemap_not_crawled = len(sitemap_norm - crawled_norm)
            audit.sitemap_noindex = [p.url for p in pages if p.in_sitemap and not p.indexable][: self.MAX_SAMPLES]
            listed_errors = [b.url for b in broken if normalize_url(b.url) in sitemap_norm]
            audit.sitemap_errors = listed_errors[: self.MAX_SAMPLES]
            audit.robots_blocked_pages = [u for u in sorted(sitemap_norm)
                                          if not rules.allows(urlsplit(u).path or "/")][: self.MAX_SAMPLES]
        blocked_crawled = [p.url for p in pages if "robots_txt" in p.index_blockers]
        audit.robots_blocked_pages = list(dict.fromkeys([*audit.robots_blocked_pages,
                                                         *blocked_crawled]))[: self.MAX_SAMPLES]
        return audit

    def _host_canonical(self) -> HostCanonical | None:
        '''
        Whether one host and scheme serve the site, from the HTTP module's apex/www/http probes.

        A host counts as "serving" only when it answered 2xx with HTML at its *own* hostname; a host that
        redirects elsewhere is consolidating correctly and is not listed.
        Returns:
            HostCanonical | None: The host-canonicalization picture, or None without HTTP results.
        '''
        if not self.http or not self.http.probes:
            return None
        out = HostCanonical()
        for probe in self.http.probes:
            if urlsplit(probe.requested_url).scheme == "http" and probe.redirects_to_https is not None:
                out.https_redirects = probe.redirects_to_https
            if not (probe.final_fetched and probe.status_code and 200 <= probe.status_code < 300):
                continue
            if "html" not in (probe.content_type or "").lower():
                continue
            final_host = (urlsplit(probe.final_url or "").hostname or "").lower()
            requested_host = (urlsplit(probe.requested_url).hostname or "").lower()
            if final_host and final_host == requested_host:
                out.hosts_serving.append(final_host)
        out.hosts_serving = sorted(set(out.hosts_serving))
        out.split = len(out.hosts_serving) > 1
        out.canonical_host = out.hosts_serving[0] if len(out.hosts_serving) == 1 else None
        return out

    @staticmethod
    def _structured_data(pages: list[PageSeo]) -> dict[str, int]:
        '''
        How many analyzed pages declare each structured-data type.
        Parameters:
            pages (list[PageSeo]): Analyzed pages.
        Returns:
            dict[str, int]: Type name → page count, most common first.
        '''
        counts: Counter[str] = Counter()
        for page in pages:
            counts.update(set(page.structured_data_types))
        return dict(counts.most_common(40))
