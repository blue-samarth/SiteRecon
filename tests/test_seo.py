from __future__ import annotations

import datetime as dt

import pytest

from recon.analysis import AnalysisEngine, ObservationBuilder, compute_seo_grade, run_checks
from recon.analysis.seo_checks import (
    DESC_MAX_CHARS,
    SEO_CHECKS,
    TITLE_MAX_CHARS,
    TITLE_MIN_CHARS,
)
from recon.models import (
    CollectionMethod,
    CrawlData,
    CrawledPage,
    Freshness,
    HttpData,
    HttpProbe,
    ModuleResult,
    ModuleStatus,
    ResourcesData,
    RobotsInfo,
    SitemapInfo,
)
from recon.modules import SeoCollector
from recon.modules.seo import PageSeoParser, normalize_url
from recon.utils import Scope

T0 = dt.datetime(2026, 11, 20, tzinfo=dt.UTC)
SCOPE = Scope.for_target("acme.test")

GOOD_HEAD = (b'<title>Acme Widgets: industrial fasteners and fittings</title>'
             b'<meta name="description" content="' + b"Acme supplies fasteners and fittings. " * 3 + b'">'
             b'<meta name="viewport" content="width=device-width, initial-scale=1">'
             b'<link rel="canonical" href="https://acme.test/">'
             b'<meta property="og:title" content="Acme"><meta property="og:type" content="website">'
             b'<meta property="og:image" content="https://acme.test/og.png">'
             b'<meta property="og:url" content="https://acme.test/">')


def page_bytes(head: bytes = GOOD_HEAD, body: bytes = b"", h1: bytes = b"Fasteners") -> bytes:
    words = b"<p>" + b"widget " * 200 + b"</p>"
    return b'<!doctype html><html lang="en"><head>' + head + b"</head><body><h1>" + h1 + b"</h1>" \
        + words + body + b'<a href="/about">About</a></body></html>'


def parse(body: bytes, url: str = "https://acme.test/"):
    return PageSeoParser(body, url, SCOPE)


def probe(url: str, body: bytes, *, status: int = 200, encoding: str | None = None,
          version: str = "HTTP/2", ms: float = 120.0, final: str | None = None,
          x_robots: str | None = None) -> HttpProbe:
    headers: dict[str, list[str]] = {"content-type": ["text/html; charset=utf-8"]}
    if encoding:
        headers["content-encoding"] = [encoding]
    if x_robots:
        headers["x-robots-tag"] = [x_robots]
    return HttpProbe(requested_url=url, success=True, final_url=final or url, final_fetched=True,
                     status_code=status, http_version=version, headers=headers,
                     content_type="text/html; charset=utf-8", response_time_ms=ms, body=body)


def crawled(url: str, body: bytes, *, depth: int = 1, source: str | None = "https://acme.test/",
            status: int = 200, ms: float = 150.0, final: str | None = None,
            x_robots: str | None = None) -> CrawledPage:
    return CrawledPage(url=url, source_url=source, depth=depth, status_code=status, final_url=final or url,
                       content_type="text/html", response_time_ms=ms, x_robots_tag=x_robots, body=body)


def crawl_of(*pages: CrawledPage, max_depth: int = 2, limit_reached: bool = False) -> CrawlData:
    return CrawlData(seeds=["https://acme.test/"], max_depth=max_depth, max_pages=25, robots_respected=True,
                     crawl_delay=0.25, pages=list(pages), page_limit_reached=limit_reached)


def resources_of(*, robots: bool = True, disallow: list[str] | None = None,
                 declares: bool = True, sitemap_urls: list[str] | None = None) -> ResourcesData:
    urls = sitemap_urls if sitemap_urls is not None else ["https://acme.test/", "https://acme.test/about"]
    return ResourcesData(
        origin="https://acme.test",
        robots=RobotsInfo(url="https://acme.test/robots.txt", present=robots, disallow=disallow or [],
                          sitemaps=["https://acme.test/sitemap.xml"] if declares else []) if robots else None,
        sitemaps=[SitemapInfo(url="https://acme.test/sitemap.xml", present=True, kind="urlset",
                              url_count=len(urls), urls=urls)] if urls else [])


async def collect(*, http: HttpData | None = None, crawl: CrawlData | None = None,
                  resources: ResourcesData | None = None):
    http = http if http is not None else HttpData(probes=[probe("https://acme.test/", page_bytes(),
                                                                encoding="br")])
    return await SeoCollector("acme.test", "https://acme.test", html=None, http=http, crawl=crawl,
                              resources=resources).collect()


# ------------------------------------------------------------------ URL normalization

def test_normalize_url_folds_only_differences_that_are_not_a_different_page():
    same = {normalize_url("https://ACME.test/about/"), normalize_url("https://acme.test:443/about"),
            normalize_url("https://acme.test/about#top"), normalize_url("https://acme.test/about")}
    assert len(same) == 1
    # the query identifies a different page, and http:// vs https:// is the duplicate-content case itself
    assert normalize_url("https://acme.test/p?a=1") != normalize_url("https://acme.test/p?a=2")
    assert normalize_url("http://acme.test/") != normalize_url("https://acme.test/")
    assert normalize_url("/relative") == "" and normalize_url("not a url") == ""


# ------------------------------------------------------------------ per-page extraction

def test_parser_extracts_the_metadata_search_engines_read():
    d = parse(page_bytes()).parse()
    assert d.title and d.title_length == len(d.title) and d.meta_description
    assert d.lang == "en" and d.viewport and d.canonical == "https://acme.test/"
    assert d.canonical_self is True and d.canonical_offsite is False
    assert d.open_graph_present and d.open_graph_missing == []
    assert d.h1 == ["Fasteners"] and d.heading_counts == {"h1": 1} and d.indexable


def test_canonical_is_self_relative_and_offsite():
    assert parse(page_bytes(b'<link rel="canonical" href="/">')).parse().canonical_self is True
    other = parse(page_bytes(b'<link rel="canonical" href="https://acme.test/other">')).parse()
    assert other.canonical_self is False and other.canonical_offsite is False
    off = parse(page_bytes(b'<link rel="canonical" href="https://elsewhere.test/x">')).parse()
    assert off.canonical_offsite is True
    assert parse(page_bytes()).parse().canonical_self is True
    assert parse(page_bytes(b"<title>t</title>")).parse().canonical_self is None   # none declared


def test_robots_meta_directives_block_indexing_and_name_the_blocker():
    d = parse(page_bytes(b'<meta name="robots" content="NoIndex, nofollow">')).parse()
    assert d.indexable is False and d.index_blockers == ["noindex_meta"] and d.nofollow is True
    assert parse(page_bytes(b'<meta name="robots" content="none">')).parse().indexable is False
    assert parse(page_bytes(b'<meta name="robots" content="index,follow">')).parse().indexable is True


def test_heading_counts_and_skipped_levels():
    d = parse(page_bytes(body=b"<h2>a</h2><h4>b</h4><h3>c</h3>")).parse()
    assert d.heading_counts == {"h1": 1, "h2": 1, "h3": 1, "h4": 1}
    assert d.heading_skips == ["h2 → h4"]        # h4 → h3 is a step back, not a skip
    assert parse(page_bytes(body=b"<h2>a</h2><h3>b</h3>")).parse().heading_skips == []


def test_word_count_ignores_scripts_styles_and_markup():
    body = b"<script>var noise = 'aaa bbb ccc ddd eee';</script><style>.x{color:red}</style><p>one two</p>"
    d = parse(b'<!doctype html><html><head><title>t</title></head><body>' + body + b"</body></html>").parse()
    assert d.word_count == 2


def test_only_a_missing_alt_attribute_counts_against_a_page():
    d = parse(page_bytes(body=b'<img src="a.png" alt="bolt"><img src="b.png" alt=""><img src="c.png">')).parse()
    assert d.images == 3 and d.images_missing_alt == 1       # alt="" is a valid decorative declaration


def test_link_counts_and_internal_targets():
    body = (b'<a href="/x">x</a><a href="https://acme.test/y">y</a><a href="https://other.test/">o</a>'
            b'<a href="/z" rel="nofollow">z</a><a href="#frag">f</a><a href="mailto:a@b.c">m</a>')
    p = parse(page_bytes(body=body))
    d = p.parse()
    assert (d.internal_links, d.external_links, d.nofollow_links) == (4, 1, 1)   # /about from the template
    assert normalize_url("https://acme.test/x") in p.link_targets
    assert not any("other.test" in t for t in p.link_targets)


def test_structured_data_types_from_json_ld_graph_and_microdata():
    body = (b'<script type="application/ld+json">{"@graph":[{"@type":"Article"},{"@type":["FAQPage"]}]}</script>'
            b'<div itemtype="https://schema.org/Product"></div>'
            b'<script type="application/ld+json">{broken</script>')
    d = parse(page_bytes(body=body)).parse()
    assert set(d.structured_data_types) == {"Article", "FAQPage", "Product"}
    assert d.structured_data_errors == 1


def test_hreflang_alternates_are_collected():
    head = GOOD_HEAD + (b'<link rel="alternate" hreflang="en" href="/">'
                        b'<link rel="alternate" hreflang="de-DE" href="/de/">')
    assert parse(page_bytes(head)).parse().hreflang == ["en", "de-de"]


# ------------------------------------------------------------------ collection

async def test_landing_page_only_is_labeled_as_such():
    data, errors = await collect()
    assert errors == [] and data.pages_analyzed == 1 and data.pages_source == "landing page"
    assert data.landing_url == "https://acme.test/" and data.crawl_max_depth is None
    assert data.compression == "br" and data.http_version == "HTTP/2"


async def test_crawled_pages_are_analyzed_and_deduplicated_against_the_landing_page():
    data, _ = await collect(crawl=crawl_of(
        crawled("https://acme.test/", page_bytes()),                  # same page as the landing probe
        crawled("https://acme.test/about", page_bytes(b"<title>About Acme and its history</title>"))))
    assert data.pages_analyzed == 2 and data.pages_source == "landing page + crawl"
    assert [p.url for p in data.pages] == ["https://acme.test/", "https://acme.test/about"]
    assert data.crawl_max_depth == 2


async def test_non_html_and_bodyless_crawl_pages_are_not_analyzed():
    data, _ = await collect(crawl=crawl_of(
        crawled("https://acme.test/feed.xml", b"<rss/>")._copy_as(content_type="application/xml")
        if hasattr(CrawledPage, "_copy_as") else
        CrawledPage(url="https://acme.test/feed.xml", depth=1, status_code=200,
                    content_type="application/xml", body=b"<rss/>"),
        CrawledPage(url="https://acme.test/empty", depth=1, status_code=200, content_type="text/html")))
    assert [p.url for p in data.pages] == ["https://acme.test/"]


async def test_robots_txt_and_x_robots_tag_block_indexing_per_page():
    data, _ = await collect(
        crawl=crawl_of(crawled("https://acme.test/private/x", page_bytes()),
                       crawled("https://acme.test/header", page_bytes(), x_robots="noindex")),
        resources=resources_of(disallow=["/private/"]))
    blockers = {p.url: p.index_blockers for p in data.pages}
    assert blockers["https://acme.test/private/x"] == ["robots_txt"]
    assert blockers["https://acme.test/header"] == ["x_robots_tag"]
    assert data.indexable_pages == 1


async def test_sitemap_membership_duplicates_and_coverage():
    data, _ = await collect(
        crawl=crawl_of(crawled("https://acme.test/about", page_bytes()),
                       crawled("https://acme.test/extra", page_bytes())),
        resources=resources_of())
    assert {p.url: p.in_sitemap for p in data.pages} == {
        "https://acme.test/": True, "https://acme.test/about": True, "https://acme.test/extra": False}
    sm = data.sitemap
    assert sm.sitemap_urls == 2 and sm.crawled_in_sitemap == 2
    assert sm.crawled_not_in_sitemap == ["https://acme.test/extra"]
    # all three pages come from one template, so title, description and H1 all collide
    assert {g.kind for g in data.duplicates} == {"title", "description", "h1"}
    assert len(next(g for g in data.duplicates if g.kind == "title").pages) == 3


async def test_duplicate_groups_ignore_pages_that_are_blocked_from_indexing():
    noindex = page_bytes(b'<title>Acme Widgets: industrial fasteners</title>'
                         b'<meta name="robots" content="noindex">')
    data, _ = await collect(http=HttpData(probes=[probe("https://acme.test/", noindex)]),
                            crawl=crawl_of(crawled("https://acme.test/copy", noindex)))
    assert data.duplicates == [] and data.indexable_pages == 0


async def test_inbound_link_graph_finds_orphans_but_not_the_home_page():
    linked = page_bytes(body=b'<a href="/deep">deep</a>')
    data, _ = await collect(http=HttpData(probes=[probe("https://acme.test/", linked)]),
                            crawl=crawl_of(crawled("https://acme.test/deep", page_bytes()),
                                           crawled("https://acme.test/orphan", page_bytes(), source=None)))
    inbound = {p.url: p.inbound_internal_links for p in data.pages}
    assert inbound["https://acme.test/deep"] == 1 and inbound["https://acme.test/orphan"] == 0
    assert data.orphan_pages == ["https://acme.test/orphan"]      # the home page is never an orphan


async def test_broken_links_and_redirects_are_recorded_with_their_source():
    data, _ = await collect(crawl=crawl_of(
        crawled("https://acme.test/gone", b"", status=404),
        crawled("https://acme.test/old", b"", final="https://acme.test/new")))
    assert [(b.url, b.status_code, b.linked_from) for b in data.broken_links] == [
        ("https://acme.test/gone", 404, "https://acme.test/")]
    assert [(r.url, r.final_url) for r in data.redirects] == [
        ("https://acme.test/old", "https://acme.test/new")]


async def test_host_canonicalization_sees_a_split_between_apex_and_www():
    split = HttpData(probes=[probe("https://acme.test/", page_bytes()),
                             probe("https://www.acme.test/", page_bytes())])
    data, _ = await collect(http=split)
    assert data.host_canonical.split is True
    assert data.host_canonical.hosts_serving == ["acme.test", "www.acme.test"]
    assert data.host_canonical.canonical_host is None

    consolidated = HttpData(probes=[probe("https://acme.test/", page_bytes()),
                                    probe("https://www.acme.test/", page_bytes(),
                                          final="https://acme.test/")])
    data, _ = await collect(http=consolidated)
    assert data.host_canonical.split is False and data.host_canonical.canonical_host == "acme.test"


async def test_http_to_https_redirect_is_recorded_from_the_plain_http_probe():
    http = HttpData(probes=[probe("http://acme.test/", page_bytes(), final="https://acme.test/"),
                            probe("https://acme.test/", page_bytes())])
    http.probes[0].redirects_to_https = True
    data, _ = await collect(http=http)
    assert data.host_canonical.https_redirects is True


async def test_response_timings_and_total_size_are_summarized():
    data, _ = await collect(http=HttpData(probes=[probe("https://acme.test/", page_bytes(), ms=100.0)]),
                            crawl=crawl_of(crawled("https://acme.test/a", page_bytes(), ms=300.0),
                                           crawled("https://acme.test/b", page_bytes(), ms=2000.0)))
    assert data.median_response_ms == 300.0 and data.slowest_response_ms == 2000.0
    assert data.total_html_bytes > 0


async def test_no_html_page_available_is_a_failed_module_not_an_empty_audit():
    data, errors = await collect(http=HttpData(probes=[]))
    assert data is None and errors[0].error_type == "no_pages"


async def test_an_unparseable_page_is_reported_and_the_rest_still_analyzed(monkeypatch):
    real = PageSeoParser.parse
    calls = {"n": 0}

    def flaky(self):
        calls["n"] += 1
        if calls["n"] == 2:
            raise ValueError("bad markup")
        return real(self)

    monkeypatch.setattr(PageSeoParser, "parse", flaky)
    data, errors = await collect(crawl=crawl_of(crawled("https://acme.test/a", page_bytes()),
                                                crawled("https://acme.test/b", page_bytes())))
    assert data.pages_analyzed == 2 and len(errors) == 1 and errors[0].error_type == "parse_error"


# ------------------------------------------------------------------ checks and grading

async def clean_site():
    '''A site with no SEO problems to find, crawled over several pages.'''
    def unique(slug: str, extra: bytes = b"") -> bytes:
        head = (f'<title>Acme {slug}: fasteners, fittings and precision hardware</title>'
                f'<meta name="description" content="Everything about {slug} at Acme, including sizes, '
                f'materials, tolerances and delivery times for engineering teams.">'
                f'<meta name="viewport" content="width=device-width, initial-scale=1">'
                f'<link rel="canonical" href="https://acme.test/{slug}">'
                f'<meta property="og:title" content="{slug}"><meta property="og:type" content="website">'
                f'<meta property="og:image" content="https://acme.test/og.png">'
                f'<meta property="og:url" content="https://acme.test/{slug}">').encode()
        sd = b'<script type="application/ld+json">{"@type":"WebPage"}</script>'
        return page_bytes(head + sd, extra, h1=f"Acme {slug}".encode())

    home = (b'<title>Acme Widgets: fasteners, fittings and precision hardware</title>'
            b'<meta name="description" content="Acme supplies industrial fasteners, fittings and '
            b'precision hardware to engineering teams, with next-day delivery across Europe.">'
            b'<meta name="viewport" content="width=device-width, initial-scale=1">'
            b'<link rel="canonical" href="https://acme.test/">'
            b'<meta property="og:title" content="Acme"><meta property="og:type" content="website">'
            b'<meta property="og:image" content="https://acme.test/og.png">'
            b'<meta property="og:url" content="https://acme.test/">')
    landing = page_bytes(home + b'<script type="application/ld+json">{"@type":"Organization"}</script>',
                         b'<a href="/bolts">bolts</a><a href="/nuts">nuts</a>', h1=b"Acme Widgets")
    http = HttpData(probes=[probe("https://acme.test/", landing, encoding="br"),
                            probe("https://www.acme.test/", landing, final="https://acme.test/")])
    http.probes[0].redirects_to_https = True
    crawl = crawl_of(crawled("https://acme.test/bolts", unique("bolts")),
                     crawled("https://acme.test/nuts", unique("nuts")))
    resources = resources_of(sitemap_urls=["https://acme.test/", "https://acme.test/bolts",
                                           "https://acme.test/nuts"])
    data, _ = await collect(http=http, crawl=crawl, resources=resources)
    return data


async def test_a_clean_site_fails_no_check_and_grades_a_plus():
    checks = run_checks(await clean_site())
    assert [c.id for c in checks if c.status == "fail"] == []
    grade = compute_seo_grade(await clean_site(), checks)
    assert grade.score == 100 and grade.grade == "A+"
    assert {a.area for a in grade.areas} == {"indexability", "metadata", "content", "crawlability",
                                             "performance"}


async def test_a_clean_site_produces_no_seo_findings():
    data = await clean_site()
    result = AnalysisEngine(T0).analyze(dns=None, network=None, http=None, tls=None, seo=data)
    assert [f.id for f in result.findings if f.category == "seo"] == []


async def test_every_check_has_a_recommendation_and_fires_as_one_finding():
    data, _ = await collect(crawl=crawl_of(crawled("https://acme.test/a", b"<html><body>x</body></html>")))
    result = AnalysisEngine(T0).analyze(dns=None, network=None, http=None, tls=None, seo=data)
    seo_findings = [f for f in result.findings if f.category == "seo"]
    assert seo_findings
    for f in seo_findings:
        assert f.recommendation and f.limitations and f.state is not None
        assert f.id.startswith("seo.") and f.subject == "acme.test" and f.evidence
    assert len(seo_findings) == len({f.id for f in seo_findings})           # one finding per check


async def test_missing_evidence_is_not_checked_rather_than_passed():
    checks = {c.id: c for c in run_checks((await collect())[0])}            # landing page only
    assert checks["broken_internal_links"].status == "not_checked"
    assert checks["internal_redirects"].status == "not_checked"
    assert checks["orphan_pages"].status == "not_checked"
    assert checks["robots_txt_missing"].status == "not_checked"             # no resources module
    assert checks["titles_missing"].status == "not_checked"                 # landing page has its own code
    assert all(c.penalty == 0 for c in checks.values() if c.status == "not_checked")


async def test_not_checked_areas_are_left_out_of_the_average_not_scored_as_perfect():
    data, _ = await collect()
    checks = run_checks(data)
    grade = compute_seo_grade(data, checks)
    evaluated = {c.area for c in checks if c.status != "not_checked"}
    assert {a.area for a in grade.areas} == evaluated
    assert "crawlability" not in evaluated                                  # nothing to evaluate alone


async def test_a_penalty_is_proportional_to_the_share_of_pages_affected():
    missing_h1 = page_bytes(b"<title>A page about fasteners and fittings</title>", b"")
    missing_h1 = missing_h1.replace(b"<h1>Fasteners</h1>", b"")
    data, _ = await collect(crawl=crawl_of(crawled("https://acme.test/a", missing_h1),
                                           crawled("https://acme.test/b", page_bytes()),
                                           crawled("https://acme.test/c", page_bytes()),
                                           crawled("https://acme.test/d", page_bytes())))
    row = next(c for c in run_checks(data) if c.id == "h1_missing")
    weight = next(s.weight for s in SEO_CHECKS if s.id == "h1_missing")
    assert (row.affected, row.checked) == (1, 5) and row.penalty == round(weight * 1 / 5)


async def test_the_landing_page_is_not_reported_twice_for_the_same_problem():
    bare = b'<!doctype html><html><head></head><body><h1>x</h1></body></html>'
    data, _ = await collect(http=HttpData(probes=[probe("https://acme.test/", bare)]))
    checks = {c.id: c for c in run_checks(data)}
    # the landing page has no title and no description, but those codes exclude it
    assert checks["titles_missing"].status == "not_checked"
    assert checks["descriptions_missing"].status == "not_checked"
    assert checks["social_metadata_missing"].status == "not_checked"
    assert checks["viewport_missing"].status == "fail"        # no landing-page code exists for this one


@pytest.mark.parametrize("length,expected", [
    (TITLE_MIN_CHARS - 1, "fail"), (TITLE_MIN_CHARS, "pass"), (TITLE_MAX_CHARS, "pass"),
    (TITLE_MAX_CHARS + 1, "fail")])
async def test_title_length_thresholds_are_inclusive(length, expected):
    title = b"<title>" + b"t" * length + b"</title>"
    data, _ = await collect(http=HttpData(probes=[probe("https://acme.test/", page_bytes(title))]))
    assert next(c for c in run_checks(data) if c.id == "title_length").status == expected


async def test_description_over_the_limit_is_flagged():
    head = b'<title>A title of a perfectly reasonable length</title><meta name="description" content="' \
           + b"x" * (DESC_MAX_CHARS + 1) + b'">'
    data, _ = await collect(http=HttpData(probes=[probe("https://acme.test/", page_bytes(head))]))
    assert next(c for c in run_checks(data) if c.id == "description_length").status == "fail"


async def test_malformed_hreflang_is_flagged_and_valid_tags_are_not():
    head = GOOD_HEAD + (b'<link rel="alternate" hreflang="en-GB" href="/">'
                        b'<link rel="alternate" hreflang="x-default" href="/">'
                        b'<link rel="alternate" hreflang="english" href="/en/">')
    data, _ = await collect(http=HttpData(probes=[probe("https://acme.test/", page_bytes(head))]))
    row = next(c for c in run_checks(data) if c.id == "hreflang_invalid")
    assert row.status == "fail" and "english" in row.samples[0]

    ok = GOOD_HEAD + b'<link rel="alternate" hreflang="pt-BR" href="/br/">'
    data, _ = await collect(http=HttpData(probes=[probe("https://acme.test/", page_bytes(ok))]))
    assert next(c for c in run_checks(data) if c.id == "hreflang_invalid").status == "pass"


async def test_depth_check_is_skipped_when_the_crawl_could_not_reach_that_depth():
    shallow, _ = await collect(crawl=crawl_of(crawled("https://acme.test/a", page_bytes()), max_depth=1))
    assert next(c for c in run_checks(shallow) if c.id == "deep_pages").status == "not_checked"
    deep, _ = await collect(crawl=crawl_of(crawled("https://acme.test/a", page_bytes(), depth=5),
                                           max_depth=5))
    row = next(c for c in run_checks(deep) if c.id == "deep_pages")
    assert row.status == "fail" and row.affected == 1


async def test_uncompressed_and_legacy_http_are_flagged_from_the_landing_response():
    data, _ = await collect(http=HttpData(probes=[probe("https://acme.test/", page_bytes(),
                                                        version="HTTP/1.1")]))
    checks = {c.id: c for c in run_checks(data)}
    assert checks["no_compression"].status == "fail" and checks["legacy_http_version"].status == "fail"


# ------------------------------------------------------------------ coverage honesty

async def test_a_one_page_audit_says_so():
    data, _ = await collect()
    result = AnalysisEngine(T0).analyze(dns=None, network=None, http=None, tls=None, seo=data)
    ids = {f.id for f in result.findings}
    assert "seo.coverage_single_page:acme.test" in ids
    finding = next(f for f in result.findings if f.id == "seo.coverage_single_page:acme.test")
    assert "--crawl" in (finding.recommendation or "") and "skipped" in finding.evidence[1]


async def test_a_truncated_crawl_says_so_instead():
    data, _ = await collect(crawl=crawl_of(crawled("https://acme.test/a", page_bytes()),
                                           limit_reached=True))
    result = AnalysisEngine(T0).analyze(dns=None, network=None, http=None, tls=None, seo=data)
    ids = {f.id for f in result.findings}
    assert "seo.coverage_truncated:acme.test" in ids and "seo.coverage_single_page:acme.test" not in ids


async def test_seo_findings_never_move_the_security_grade():
    data, _ = await collect(crawl=crawl_of(crawled("https://acme.test/a", b"<html><body>x</body></html>")))
    with_seo = AnalysisEngine(T0).analyze(dns=None, network=None, http=None, tls=None, seo=data)
    without = AnalysisEngine(T0).analyze(dns=None, network=None, http=None, tls=None)
    assert [f for f in with_seo.findings if f.category == "seo"]          # there are SEO findings
    assert with_seo.grade.score == without.grade.score == 100
    assert with_seo.seo is not None and with_seo.seo.score < 100          # they land on the SEO grade only
    assert without.seo is None


# ------------------------------------------------------------------ observations

async def test_seo_observations_carry_provenance_and_catch_page_level_regressions():
    data, _ = await collect(crawl=crawl_of(crawled("https://acme.test/about", page_bytes())),
                            resources=resources_of())
    r = ModuleResult(module="seo", status=ModuleStatus.SUCCESS, started_at=T0, finished_at=T0,
                     duration_ms=1.0, data=data)
    obs = {(o.type, o.target, o.key): o for o in ObservationBuilder("acme.test", {"seo": r}).build()}
    assert ("seo.summary", "acme.test", "pages_analyzed") in obs
    assert ("seo.page", "https://acme.test/about", "title") in obs
    assert ("seo.page", "https://acme.test/about", "indexable") in obs
    assert ("seo.sitemap", "acme.test", "urls_listed") in obs
    assert all(o.collection_method == CollectionMethod.STATIC_ANALYSIS and o.freshness is Freshness.FRESH
               for o in obs.values())
    # volatile measurements are deliberately not observed, so a diff shows structure, not every edit
    assert not any(k[2] in ("word_count", "response_time_ms", "html_bytes") for k in obs)


async def test_absent_page_metadata_is_not_recorded_as_a_null_observation():
    bare = b'<!doctype html><html><head></head><body><p>x</p></body></html>'
    data, _ = await collect(http=HttpData(probes=[probe("https://acme.test/", bare)]))
    r = ModuleResult(module="seo", status=ModuleStatus.SUCCESS, started_at=T0, finished_at=T0,
                     duration_ms=1.0, data=data)
    keys = {(o.type, o.key) for o in ObservationBuilder("acme.test", {"seo": r}).build()}
    assert ("seo.page", "title") not in keys and ("seo.page", "canonical") not in keys
    assert ("seo.page", "indexable") in keys          # always recorded: its absence would read as removed


async def test_the_number_of_pages_observed_is_capped():
    pages = [crawled(f"https://acme.test/p{i}", page_bytes()) for i in range(80)]
    data, _ = await collect(crawl=crawl_of(*pages))
    r = ModuleResult(module="seo", status=ModuleStatus.SUCCESS, started_at=T0, finished_at=T0,
                     duration_ms=1.0, data=data)
    targets = {o.target for o in ObservationBuilder("acme.test", {"seo": r}).build() if o.type == "seo.page"}
    assert data.pages_analyzed == 81 and len(targets) == ObservationBuilder.MAX_SEO_PAGES


# ------------------------------------------------------------------ pipeline wiring

from recon.config import Config
from recon.models import DnssecData, DnssecStatus, SubdomainData, TlsData
from recon.modules import (
    DnsCollector,
    DnssecCollector,
    HttpCollector,
    NetworkCollector,
    ResourcesCollector,
    SubdomainCollector,
    TlsCollector,
    WhoisCollector,
)
from recon.orchestrator import ScanOrchestrator


@pytest.fixture
def offline(monkeypatch):
    '''Replace every networked collector so the orchestrator runs without any I/O.'''
    async def dns(self):
        from recon.models import DnsData, DnsQueryResult, DnsQueryStatus, DnsRecord, EmailSecurity
        return DnsData(hostname="acme.test", email=EmailSecurity(), queries={
            "A": DnsQueryResult(name="acme.test", record_type="A", status=DnsQueryStatus.NOERROR,
                                records=[DnsRecord(value="93.184.216.34", ttl=60)], response_time_ms=1)}), []

    async def http(self):
        return HttpData(probes=[probe("https://acme.test/", page_bytes(), encoding="gzip")]), []

    async def nothing(self):
        return None, []

    async def resources(self):
        return resources_of(), []

    for cls, fake in [(DnsCollector, dns), (HttpCollector, http), (NetworkCollector, nothing),
                      (TlsCollector, nothing), (WhoisCollector, nothing),
                      (ResourcesCollector, resources)]:
        monkeypatch.setattr(cls, "collect", fake)

    async def subs(self):
        return SubdomainData(query="%.acme.test", verification_limit=0), []

    async def dnssec(self):
        return DnssecData(zone="acme.test", status=DnssecStatus.UNSIGNED, ds_status="NODATA",
                          dnskey_status="NODATA"), []

    async def tls(self):
        return TlsData(probes=[]), []

    monkeypatch.setattr(SubdomainCollector, "collect", subs)
    monkeypatch.setattr(DnssecCollector, "collect", dnssec)
    monkeypatch.setattr(TlsCollector, "collect", tls)


async def run_scan(**cfg):
    cfg.setdefault("target_input", "acme.test")
    return await ScanOrchestrator(Config(hostname="acme.test", history=False, **cfg)).run()


async def test_the_seo_module_is_skipped_unless_asked_for(offline):
    report = await run_scan()
    assert report.seo.status is ModuleStatus.SKIPPED and report.analysis.seo is None
    assert "seo" in report.module_results()


async def test_the_seo_module_runs_and_reaches_the_analysis_and_the_report(offline):
    report = await run_scan(seo=True)
    assert report.seo.status is ModuleStatus.SUCCESS and report.seo.data.pages_analyzed == 1
    assert report.analysis.seo is not None and report.analysis.seo.grade
    assert report.options["seo"] is True
    assert any(o.type.startswith("seo.") for o in report.observations)
    assert any(lim.startswith("The SEO audit") for lim in report.limitations)


async def test_the_seo_module_sends_no_requests_of_its_own(offline, monkeypatch):
    # The collector is derived: it must never be handed a client, so it cannot contact anything.
    import inspect
    assert "client" not in inspect.signature(SeoCollector.__init__).parameters
    report = await run_scan(seo=True)
    assert report.seo.data.compression == "gzip"          # read from the HTTP module's own response


# ------------------------------------------------------------------ CLI

from typer.testing import CliRunner

from recon.cli import app

runner = CliRunner()


def _captured_config(monkeypatch, argv):
    captured: dict[str, Config] = {}
    real_init = ScanOrchestrator.__init__

    def capture(self, config, **kwargs):
        captured["config"] = config
        real_init(self, config, **kwargs)

    async def stop(self, progress=None):
        raise RuntimeError("stop once the config exists")

    monkeypatch.setattr(ScanOrchestrator, "__init__", capture)
    monkeypatch.setattr(ScanOrchestrator, "run", stop)
    result = runner.invoke(app, argv)
    return captured.get("config"), result


def test_seo_turns_the_crawler_on_because_a_site_audit_needs_more_than_one_page(monkeypatch, tmp_path):
    cfg, result = _captured_config(monkeypatch, ["scan", "acme.test", "--seo", "-o", str(tmp_path)])
    assert cfg.seo is True and cfg.crawl is True
    assert "crawling in-scope pages" in " ".join(result.output.split())


def test_no_crawl_wins_over_the_seo_implication(monkeypatch, tmp_path):
    cfg, result = _captured_config(monkeypatch,
                                   ["scan", "acme.test", "--seo", "--no-crawl", "-o", str(tmp_path)])
    assert cfg.seo is True and cfg.crawl is False
    assert "landing page only" in " ".join(result.output.split())


def test_a_plain_scan_neither_audits_nor_crawls(monkeypatch, tmp_path):
    cfg, _ = _captured_config(monkeypatch, ["scan", "acme.test", "-o", str(tmp_path)])
    assert cfg.seo is False and cfg.crawl is False


def test_crawl_without_seo_still_works_on_its_own(monkeypatch, tmp_path):
    cfg, _ = _captured_config(monkeypatch, ["scan", "acme.test", "--crawl", "-o", str(tmp_path)])
    assert cfg.seo is False and cfg.crawl is True


# ------------------------------------------------------------------ reporting

from recon.reporting import HtmlReportWriter, MarkdownReportWriter


async def test_both_report_formats_render_the_audit_including_what_was_not_checked(offline):
    report = await run_scan(seo=True)
    md = MarkdownReportWriter(report).render()
    assert "## 13. SEO Audit" in md and "SEO grade:" in md
    assert "not checked" in md and "scored nothing (they are not passes)" in md
    assert "Analyzed pages" in md and "Delivery" in md

    page = HtmlReportWriter(report).render()
    assert '<section id="seo">' in page and 'href="#seo"' in page
    assert "SEO grade:" in page and "not checked" in page
    assert "Scored separately from the security grade" in page


async def test_the_html_report_escapes_page_metadata_from_the_site(offline):
    report = await run_scan(seo=True)
    report.seo.data.pages[0].title = "<script>alert(1)</script>"
    report.seo.data.duplicates = [report.seo.data.duplicates[0]] if report.seo.data.duplicates else []
    page = HtmlReportWriter(report).render()
    assert "<script>alert(1)</script>" not in page


async def test_the_terminal_summary_prints_the_grade_and_the_failing_checks(offline):
    from rich.console import Console

    from recon.cli import TerminalSummary

    report = await run_scan(seo=True)
    console = Console(record=True, width=200)
    TerminalSummary(console).print(report)
    out = " ".join(console.export_text().split())
    assert "SEO grade" in out and "separate from the security grade" in out
    assert "SEO issues:" in out and "had no evidence to evaluate" in out


async def test_the_terminal_summary_says_nothing_about_seo_when_the_audit_did_not_run(offline):
    from rich.console import Console

    from recon.cli import TerminalSummary

    report = await run_scan()
    console = Console(record=True, width=200)
    TerminalSummary(console).print(report)
    assert "SEO" not in console.export_text()
