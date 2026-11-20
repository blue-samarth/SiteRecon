'''
SEO models: per-page on-page facts and the site-wide aggregates computed from them.

Everything here is *evidence*, not judgement: a page's title length is recorded, never scored, and a
duplicate-title group is a computed fact about the collected pages. Which of those facts matter, and how
much, is decided in the analysis layer (``recon.analysis.seo_checks``) so the collector keeps its usual
contract. Nothing in this module is fetched specially for SEO — every value is derived from pages the HTTP
and crawler modules already retrieved, which is also why coverage is exactly the crawl's coverage and is
recorded as such on ``SeoData``.
'''

from __future__ import annotations

from pydantic import BaseModel, Field


class PageSeo(BaseModel):
    '''
    On-page SEO facts for one HTML page that was already fetched.

    ``indexable`` is the page's own declaration plus robots.txt — it says whether a compliant crawler is
    permitted to index this URL, never whether it *is* indexed (that is only knowable from a search
    engine). ``index_blockers`` names every reason found, so a page blocked twice is explainable.
    '''
    url: str
    final_url: str | None = None
    status_code: int | None = None
    depth: int = 0
    content_type: str | None = None
    html_bytes: int = 0
    response_time_ms: float | None = None
    truncated: bool = False          # body hit the crawler's retained-size cap; counts may undercount

    # indexability
    indexable: bool = True
    index_blockers: list[str] = Field(default_factory=list)   # noindex_meta, x_robots_tag, robots_txt
    robots_meta: str | None = None
    x_robots_tag: str | None = None
    nofollow: bool = False
    canonical: str | None = None
    canonical_self: bool | None = None       # None when no canonical is declared
    canonical_offsite: bool = False

    # metadata
    title: str | None = None
    title_length: int = 0
    meta_description: str | None = None
    description_length: int = 0
    lang: str | None = None
    hreflang: list[str] = Field(default_factory=list)
    viewport: str | None = None
    open_graph_present: bool = False
    open_graph_missing: list[str] = Field(default_factory=list)
    twitter_card: str | None = None

    # content
    h1: list[str] = Field(default_factory=list)
    heading_counts: dict[str, int] = Field(default_factory=dict)   # 'h1'…'h6' → count
    heading_skips: list[str] = Field(default_factory=list)         # e.g. 'h2 → h4'
    word_count: int = 0
    images: int = 0
    images_missing_alt: int = 0

    # links
    internal_links: int = 0
    external_links: int = 0
    nofollow_links: int = 0
    inbound_internal_links: int = 0     # how many crawled pages link here (orphan detection)

    # structured data
    structured_data_types: list[str] = Field(default_factory=list)   # JSON-LD @type / microdata itemtype
    structured_data_errors: int = 0
    in_sitemap: bool | None = None      # None when no sitemap was found at all


class DuplicateGroup(BaseModel):
    '''
    One value that several pages share, for the duplicate title/description/H1 checks.
    '''
    kind: str                            # title, description, h1
    value: str
    pages: list[str] = Field(default_factory=list)


class BrokenLink(BaseModel):
    '''
    An in-scope URL the crawl fetched that answered with an error status.
    '''
    url: str
    status_code: int | None = None
    linked_from: str | None = None
    error: str | None = None


class RedirectRecord(BaseModel):
    '''
    An in-scope URL that redirected during the crawl (one hop of internal link equity lost).
    '''
    url: str
    final_url: str
    linked_from: str | None = None


class SitemapAudit(BaseModel):
    '''
    How the declared sitemap(s) line up with robots.txt and with the pages actually crawled.

    Coverage comparisons are only as wide as the crawl: ``crawled_not_in_sitemap`` is exact for the pages
    this scan fetched, while ``in_sitemap_not_crawled`` mostly reflects the page cap, not a site problem —
    both are reported with their counts so neither is mistaken for the whole picture.
    '''
    robots_txt_present: bool = False
    robots_declares_sitemap: bool = False
    sitemap_count: int = 0
    sitemap_urls: int = 0                            # URLs listed across every sitemap
    sitemaps_fetched: list[str] = Field(default_factory=list)
    crawled_pages: int = 0
    crawled_in_sitemap: int = 0
    crawled_not_in_sitemap: list[str] = Field(default_factory=list)
    in_sitemap_not_crawled: int = 0
    sitemap_noindex: list[str] = Field(default_factory=list)      # listed for indexing, but blocked
    sitemap_errors: list[str] = Field(default_factory=list)       # listed URL that answered 4xx/5xx in the crawl
    robots_blocked_pages: list[str] = Field(default_factory=list)  # crawled/listed URLs robots.txt disallows


class HostCanonical(BaseModel):
    '''
    Whether the origin resolves to a single canonical host and scheme.

    Serving the same content on both the apex and ``www`` (or on http without redirecting) splits ranking
    signals between two addresses. Derived from the HTTP module's probes, so it covers exactly the
    apex/www/http URLs that module requests.
    '''
    https_redirects: bool | None = None      # http:// reaches https://
    hosts_serving: list[str] = Field(default_factory=list)   # hosts that answered 2xx with HTML themselves
    canonical_host: str | None = None        # the host everything else redirects to, when there is one
    split: bool = False                      # more than one host serves the page without redirecting


class SeoData(BaseModel):
    '''
    Site-wide SEO evidence: one record per analyzed page plus the aggregates computed across them.
    '''
    host: str
    origin: str
    landing_url: str | None = None           # the page the HTTP module fetched; it has its own findings
    pages_analyzed: int = 0
    pages_source: str = "landing page"       # 'landing page' or 'landing page + crawl'
    crawl_max_depth: int | None = None       # the crawl's depth limit (None when no crawl ran)
    crawl_page_limit_reached: bool = False
    indexable_pages: int = 0
    pages: list[PageSeo] = Field(default_factory=list)
    duplicates: list[DuplicateGroup] = Field(default_factory=list)
    orphan_pages: list[str] = Field(default_factory=list)
    broken_links: list[BrokenLink] = Field(default_factory=list)
    redirects: list[RedirectRecord] = Field(default_factory=list)
    sitemap: SitemapAudit | None = None
    host_canonical: HostCanonical | None = None
    structured_data: dict[str, int] = Field(default_factory=dict)   # @type → pages declaring it
    languages: list[str] = Field(default_factory=list)
    compression: str | None = None           # content-encoding of the landing HTML, if any
    http_version: str | None = None
    median_response_ms: float | None = None
    slowest_response_ms: float | None = None
    total_html_bytes: int = 0
    note: str = (
        "On-page SEO derived from the pages this scan already fetched — no page was requested for SEO and "
        "no search engine was queried. Coverage equals the crawl's coverage, so a site-wide count describes "
        "the analyzed pages, not every page that exists. Indexability is what the site declares (robots "
        "meta, X-Robots-Tag, robots.txt, canonical); whether a page is actually indexed, and how it ranks, "
        "can only be answered by the search engine itself. Nothing here measures real-user performance: "
        "load timings are single server-response times, not Core Web Vitals."
    )
