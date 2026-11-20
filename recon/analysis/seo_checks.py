'''
The SEO check table: one declarative entry per thing that can be wrong, with the threshold it applies.

Every judgement the SEO audit makes lives here, so the thresholds are auditable in one place instead of
being buried in branches, and the same table drives both outputs: a failing check becomes a finding, and
its weight times the share of pages affected becomes the deduction behind the SEO grade.

Three rules keep the result honest:
  * A check that has no evidence to work with is ``not_checked``. It produces no finding and scores
    nothing — a missing crawl must never read as a clean bill of health.
  * Checks are proportional. One bad page out of forty deducts a fortieth of the weight, because an
    isolated page and a site-wide template bug are not the same problem.
  * The four checks that would restate a landing-page finding skip the landing page (``skip_landing``),
    so a single-page site is never told about the same missing title twice.

Thresholds are the common, publicly documented guidance (SERP title truncation, description length,
one H1 per document) rather than anything SiteRecon can measure. They are conventions, not laws: a
failing check means "this differs from the usual guidance", which is why most carry informational or low
severity and the grade note says plainly that it predicts nothing about rankings.
'''

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from recon.models import Confidence, PageSeo, SeoData, Severity

# Calendar version of this table, recorded in the audit so a score change can be told from a rule change.
SEO_CHECKS_VERSION: str = "2026.11.20"

# Score areas, in report order.
AREAS: tuple[str, ...] = ("indexability", "metadata", "content", "crawlability", "performance")
AREA_LABEL: dict[str, str] = {
    "indexability": "Indexability & canonicalization", "metadata": "Titles & metadata",
    "content": "Content & structure", "crawlability": "Crawlability & internal links",
    "performance": "Delivery",
}

# --- thresholds -------------------------------------------------------------------------------------
# Titles are truncated in result pages at roughly 60 characters; under ~20 they rarely describe the page.
TITLE_MIN_CHARS: int = 20
TITLE_MAX_CHARS: int = 60
# Descriptions are truncated at roughly 160 characters; under ~70 they usually waste the snippet.
DESC_MIN_CHARS: int = 70
DESC_MAX_CHARS: int = 160
# Below this, a page rarely has enough copy to be the best result for anything. Navigation and legal
# pages legitimately sit under it, which is why this check is informational.
THIN_CONTENT_WORDS: int = 150
# Server response time, not a user-perceived metric: a page the server takes this long to produce is
# slow before rendering even starts.
SLOW_RESPONSE_MS: float = 1500.0
# HTML document size (markup only; subresources excluded).
HEAVY_HTML_BYTES: int = 300 * 1024
# Click depth from the home page at which a page starts to be hard to reach.
DEEP_PAGE_DEPTH: int = 4
# hreflang values: a language subtag, optional script and optional region, or 'x-default'.
HREFLANG_RE: re.Pattern[str] = re.compile(r"^(x-default|[a-z]{2,3}(-[a-z]{4})?(-([a-z]{2}|\d{3}))?)$")

S, C = Severity, Confidence


@dataclass(slots=True)
class CheckOutcome:
    '''
    What one check found: its own denominator, how much of it failed, and a few examples.
    '''
    checked: int = 0                                    # pages (or site-level items) actually evaluated
    affected: int = 0                                   # how many of them failed
    samples: list[str] = field(default_factory=list)    # display strings for the report/finding evidence
    detail: str | None = None                           # one line of context (counts, thresholds)
    note: str | None = None                             # why nothing could be evaluated

    @property
    def share(self) -> float:
        '''
        The fraction of evaluated items that failed, used to scale the check's weight.
        Returns:
            float: 0.0–1.0 (0.0 when nothing was evaluated).
        '''
        return self.affected / self.checked if self.checked else 0.0


@dataclass(frozen=True, slots=True)
class SeoCheckSpec:
    '''
    One SEO check: how to evaluate it, what to call the resulting finding, and what it costs.
    '''
    id: str                       # finding code is 'seo.<id>'
    label: str                    # short label for the report table
    area: str
    weight: int                   # points deducted from its area when every evaluated page fails
    severity: Severity
    title: str                    # finding title
    description: str              # finding description
    evaluate: Callable[[SeoData], CheckOutcome]
    scope: str = "page"           # 'page' (proportional) or 'site' (all-or-nothing)
    confidence: Confidence = C.HIGH


# --- evaluation helpers -----------------------------------------------------------------------------

def page_rule(failing: Callable[[PageSeo], bool], *,
              eligible: Callable[[PageSeo], bool] | None = None,
              indexable_only: bool = True, skip_landing: bool = False,
              unavailable: str = "no analyzed page carried this evidence",
              detail: Callable[[list[PageSeo]], str] | None = None) -> Callable[[SeoData], CheckOutcome]:
    '''
    Build a per-page evaluator that counts how many eligible pages fail a predicate.

    Pages blocked from indexing are excluded by default: a title or word count on a URL the site asks
    search engines to ignore is not a problem to report.
    Parameters:
        failing (Callable[[PageSeo], bool]): True when a page fails the check.
        eligible (Callable[[PageSeo], bool] | None): Restricts which pages the check applies to.
        indexable_only (bool): Evaluate only pages that are indexable.
        skip_landing (bool): Exclude the landing page (it has its own dedicated finding).
        unavailable (str): Note recorded when no page is eligible.
        detail (Callable[[list[PageSeo]], str] | None): Builds the detail line from the failing pages.
    Returns:
        Callable[[SeoData], CheckOutcome]: The evaluator.
    '''
    def run(seo: SeoData) -> CheckOutcome:
        pool = [p for p in seo.pages if not (skip_landing and p.url == seo.landing_url)]
        if indexable_only:
            pool = [p for p in pool if p.indexable]
        if eligible is not None:
            pool = [p for p in pool if eligible(p)]
        if not pool:
            return CheckOutcome(note=unavailable)
        bad = [p for p in pool if failing(p)]
        return CheckOutcome(checked=len(pool), affected=len(bad), samples=[p.url for p in bad][:10],
                            detail=detail(bad) if detail and bad else None)
    return run


def site_rule(fn: Callable[[SeoData], CheckOutcome]) -> Callable[[SeoData], CheckOutcome]:
    '''
    Identity wrapper that marks an evaluator as site-level, for symmetry with ``page_rule``.
    Parameters:
        fn (Callable[[SeoData], CheckOutcome]): The evaluator.
    Returns:
        Callable[[SeoData], CheckOutcome]: The same evaluator.
    '''
    return fn


def _fired(samples: list[str], detail: str | None = None) -> CheckOutcome:
    '''
    A site-level outcome: one item evaluated, failing when samples were found.
    Parameters:
        samples (list[str]): The offending items (empty means the check passed).
        detail (str | None): Context line.
    Returns:
        CheckOutcome: Site-level outcome.
    '''
    return CheckOutcome(checked=1, affected=1 if samples else 0, samples=samples[:10], detail=detail)


def _duplicates(seo: SeoData, kind: str) -> CheckOutcome:
    '''
    Count the indexable pages that share a title, description or H1 with another page.
    Parameters:
        seo (SeoData): SEO evidence.
        kind (str): 'title', 'description' or 'h1'.
    Returns:
        CheckOutcome: Pages involved in a duplicate group, out of the indexable pages.
    '''
    pool = [p for p in seo.pages if p.indexable]
    if len(pool) < 2:
        return CheckOutcome(note="fewer than two indexable pages were analyzed")
    groups = [g for g in seo.duplicates if g.kind == kind]
    involved = {url for g in groups for url in g.pages}
    return CheckOutcome(checked=len(pool), affected=len(involved),
                        samples=[f"{g.value[:70]!r} on {len(g.pages)} pages: {', '.join(g.pages[:4])}"
                                 for g in groups[:10]],
                        detail=f"{len(groups)} duplicate {kind} value(s)" if groups else None)


def _sitemap(seo: SeoData) -> CheckOutcome | None:
    '''
    Guard for the sitemap checks: the audit is absent when the resources module did not run.
    Parameters:
        seo (SeoData): SEO evidence.
    Returns:
        CheckOutcome | None: A not_checked outcome, or None when the audit is available.
    '''
    return None if seo.sitemap else CheckOutcome(note="robots.txt/sitemap evidence was not collected")


def _sitemap_not_declared(seo: SeoData) -> CheckOutcome:
    '''
    Whether an existing sitemap is referenced from robots.txt.
    Parameters:
        seo (SeoData): SEO evidence.
    Returns:
        CheckOutcome: Site-level outcome; not_checked when there is no sitemap to declare.
    '''
    audit = seo.sitemap
    if audit is None or not audit.sitemap_count:
        return CheckOutcome(note="no sitemap was found, so there is nothing to declare")
    return _fired([] if audit.robots_declares_sitemap
                  else ["sitemap found, but robots.txt has no Sitemap: line"])


def _hreflang_invalid(seo: SeoData) -> CheckOutcome:
    '''
    Find pages whose hreflang alternates are not well-formed language tags.
    Parameters:
        seo (SeoData): SEO evidence.
    Returns:
        CheckOutcome: Pages with malformed values, out of the pages declaring any.
    '''
    pool = [p for p in seo.pages if p.hreflang]
    if not pool:
        return CheckOutcome(note="no analyzed page declares hreflang alternates")
    bad: list[str] = []
    for page in pool:
        broken = [h for h in page.hreflang if not HREFLANG_RE.match(h)]
        if broken:
            bad.append(f"{page.url} — {', '.join(broken[:5])}")
    return CheckOutcome(checked=len(pool), affected=len(bad), samples=bad[:10])


def _coverage_gap(seo: SeoData) -> CheckOutcome:
    '''
    Count indexable analyzed pages that no sitemap lists.
    Parameters:
        seo (SeoData): SEO evidence.
    Returns:
        CheckOutcome: Pages absent from the sitemap, out of the indexable pages checked against it.
    '''
    audit = seo.sitemap
    if audit is None or not audit.sitemap_urls:
        return CheckOutcome(note="no sitemap URLs were available to compare against")
    pool = [p for p in seo.pages if p.indexable and p.in_sitemap is not None]
    if not pool:
        return CheckOutcome(note="no indexable page could be compared with the sitemap")
    missing = [p.url for p in pool if p.in_sitemap is False]
    return CheckOutcome(checked=len(pool), affected=len(missing), samples=missing[:10],
                        detail=f"{audit.sitemap_urls} URL(s) listed across {audit.sitemap_count} sitemap(s); "
                               f"{audit.in_sitemap_not_crawled} listed URL(s) were not reached by this crawl")


def _orphans(seo: SeoData) -> CheckOutcome:
    '''
    Count analyzed pages that no other analyzed page links to.
    Parameters:
        seo (SeoData): SEO evidence.
    Returns:
        CheckOutcome: Orphan candidates, out of the analyzed pages (needs more than one page).
    '''
    if seo.pages_analyzed < 2:
        return CheckOutcome(note="internal linking needs more than one analyzed page (run with --crawl)")
    return CheckOutcome(checked=seo.pages_analyzed, affected=len(seo.orphan_pages),
                        samples=seo.orphan_pages[:10],
                        detail=("no inbound link from any analyzed page; a page linked only from an "
                                "uncrawled page looks the same, so confirm before acting")
                        if seo.orphan_pages else None)


def _deep_pages(seo: SeoData) -> CheckOutcome:
    '''
    Count pages the crawl reached only at or beyond the click-depth threshold.
    Parameters:
        seo (SeoData): SEO evidence.
    Returns:
        CheckOutcome: Deep pages, or not_checked when the crawl could not reach that depth.
    '''
    if seo.crawl_max_depth is None or seo.crawl_max_depth < DEEP_PAGE_DEPTH:
        return CheckOutcome(note=f"the crawl's depth limit ({seo.crawl_max_depth}) cannot observe pages at "
                                 f"depth {DEEP_PAGE_DEPTH}")
    deep = [p.url for p in seo.pages if p.depth >= DEEP_PAGE_DEPTH]
    return CheckOutcome(checked=seo.pages_analyzed, affected=len(deep), samples=deep[:10])


def _host_split(seo: SeoData) -> CheckOutcome:
    '''
    Whether more than one host serves the site without redirecting to a single canonical host.
    Parameters:
        seo (SeoData): SEO evidence.
    Returns:
        CheckOutcome: Site-level outcome over the apex/www probes.
    '''
    hc = seo.host_canonical
    if hc is None or not hc.hosts_serving:
        return CheckOutcome(note="no HTTP probe of the host variants was available")
    return _fired(hc.hosts_serving if hc.split else [],
                  detail=f"serving hosts: {', '.join(hc.hosts_serving)}")


def _https_canonical(seo: SeoData) -> CheckOutcome:
    '''
    Whether plain HTTP reaches HTTPS, so one scheme is canonical.
    Parameters:
        seo (SeoData): SEO evidence.
    Returns:
        CheckOutcome: Site-level outcome, not_checked when no http:// probe ran.
    '''
    hc = seo.host_canonical
    if hc is None or hc.https_redirects is None:
        return CheckOutcome(note="no plain-HTTP probe result was available")
    return _fired([] if hc.https_redirects else [f"http://{seo.host}/ does not reach https://"])


# --- the table --------------------------------------------------------------------------------------

SEO_CHECKS: tuple[SeoCheckSpec, ...] = (
    # ---------------------------------------------------------------- indexability
    SeoCheckSpec(
        id="pages_blocked_from_indexing", label="Pages blocked from indexing", area="indexability",
        weight=30, severity=S.LOW, title="Pages ask search engines not to index them",
        description="These pages are blocked from indexing by a robots meta tag, an X-Robots-Tag header or "
                    "robots.txt. That is correct for staging, thank-you and filter URLs, and a shipped "
                    "accident on anything meant to be found — each blocker is named so the intent can be "
                    "confirmed per page.",
        evaluate=page_rule(lambda p: not p.indexable, indexable_only=False, skip_landing=True,
                           unavailable="only the landing page was analyzed, which has its own indexability "
                                       "finding",
                           detail=lambda bad: "blockers: " + ", ".join(sorted(
                               {b for p in bad for b in p.index_blockers}))),
    ),
    SeoCheckSpec(
        id="robots_blocked_pages", label="robots.txt blocks indexable URLs", area="indexability",
        weight=20, severity=S.LOW, scope="site", title="robots.txt disallows URLs the site publishes",
        description="robots.txt disallows URLs that appear in the sitemap or were crawled as ordinary "
                    "pages. A disallowed URL cannot be crawled, so its content and any canonical or "
                    "noindex directive on it are never read.",
        evaluate=site_rule(lambda seo: _sitemap(seo)
                           or _fired(seo.sitemap.robots_blocked_pages if seo.sitemap else [])),
    ),
    SeoCheckSpec(
        id="canonical_missing", label="No rel=canonical", area="indexability", weight=20,
        severity=S.INFORMATIONAL, title="Pages declare no canonical URL",
        description="These indexable pages have no rel=canonical link. Search engines then pick a "
                    "canonical themselves, which splits signals whenever the same content is reachable "
                    "at more than one URL (tracking parameters, trailing slashes, index.html).",
        evaluate=page_rule(lambda p: p.canonical is None),
    ),
    SeoCheckSpec(
        id="canonical_not_self", label="Canonical points elsewhere on the site", area="indexability",
        weight=10, severity=S.INFORMATIONAL, title="Pages name a different URL as canonical",
        description="The canonical link points at another URL on the same site, which asks search engines "
                    "to index that URL instead of this one. Intentional for parameterised and paginated "
                    "duplicates; unintentional when a template hardcodes one page's canonical everywhere.",
        evaluate=page_rule(lambda p: p.canonical_self is False and not p.canonical_offsite,
                           eligible=lambda p: p.canonical is not None,
                           unavailable="no analyzed page declares a canonical URL"),
    ),
    SeoCheckSpec(
        id="canonical_offsite_pages", label="Canonical points off-site", area="indexability", weight=15,
        severity=S.LOW, title="Pages name another domain as canonical",
        description="The canonical link names a different registrable domain, telling search engines "
                    "another site is the original. Legitimate for syndicated content, and otherwise a "
                    "symptom of a copy-paste template or canonical hijacking.",
        evaluate=page_rule(lambda p: p.canonical_offsite, skip_landing=True,
                           eligible=lambda p: p.canonical is not None,
                           unavailable="no analyzed page beyond the landing page declares a canonical URL"),
    ),
    SeoCheckSpec(
        id="sitemap_noindex_conflict", label="Sitemap lists blocked URLs", area="indexability", weight=15,
        severity=S.LOW, scope="site", title="The sitemap lists URLs that are blocked from indexing",
        description="A sitemap is a request to index; noindex is a request not to. URLs carrying both send "
                    "search engines contradictory instructions, and the usual cause is a sitemap generated "
                    "from a different rule set than the pages themselves.",
        evaluate=site_rule(lambda seo: _sitemap(seo) or _fired(seo.sitemap.sitemap_noindex if seo.sitemap else [])),
    ),
    SeoCheckSpec(
        id="host_not_canonicalized", label="More than one host serves the site", area="indexability",
        weight=20, severity=S.LOW, scope="site", title="Both host variants serve the site without redirecting",
        description="The apex and www hostnames each answer with the page instead of one redirecting to "
                    "the other, so the same content lives at two addresses and ranking signals are split "
                    "between them.",
        evaluate=site_rule(_host_split),
    ),
    SeoCheckSpec(
        id="no_https_canonicalization", label="HTTP does not reach HTTPS", area="indexability", weight=10,
        severity=S.LOW, scope="site", title="Plain HTTP does not redirect to HTTPS",
        description="Requests to http:// are not redirected to https://, so the site is reachable under "
                    "two schemes. Beyond the transport exposure, that is a duplicate-content split.",
        evaluate=site_rule(_https_canonical),
    ),

    # ---------------------------------------------------------------- metadata
    SeoCheckSpec(
        id="titles_missing", label="Pages without a title", area="metadata", weight=25, severity=S.LOW,
        title="Pages have no <title>", description=
        "These pages have no title element. It is the headline of every search result, browser tab and "
        "shared link, and its absence usually means a template or rendering path dropped it.",
        evaluate=page_rule(lambda p: not p.title, skip_landing=True,
                           unavailable="only the landing page was analyzed, which has its own title finding"),
    ),
    SeoCheckSpec(
        id="title_length", label="Title length outside guidance", area="metadata", weight=10,
        severity=S.INFORMATIONAL, title="Page titles are very short or will be truncated",
        description=f"Titles under {TITLE_MIN_CHARS} characters rarely describe the page, and those over "
                    f"{TITLE_MAX_CHARS} are usually cut off in result pages. Both are conventions, not "
                    "rules — a deliberately short brand title is fine.",
        evaluate=page_rule(lambda p: not (TITLE_MIN_CHARS <= p.title_length <= TITLE_MAX_CHARS),
                           eligible=lambda p: bool(p.title),
                           unavailable="no analyzed indexable page has a title",
                           detail=lambda bad: "lengths: " + ", ".join(str(p.title_length) for p in bad[:10])),
    ),
    SeoCheckSpec(
        id="duplicate_titles", label="Duplicate titles", area="metadata", weight=20, severity=S.LOW,
        title="Several pages share the same title",
        description="Pages with identical titles look like the same page in search results and compete "
                    "with each other. The usual cause is a template that never fills in the page name.",
        evaluate=site_rule(lambda seo: _duplicates(seo, "title")),
    ),
    SeoCheckSpec(
        id="descriptions_missing", label="Pages without a meta description", area="metadata", weight=20,
        severity=S.INFORMATIONAL, title="Pages have no meta description",
        description="Without a description, search engines build the snippet from arbitrary page text "
                    "instead of a chosen summary.",
        evaluate=page_rule(lambda p: not p.meta_description, skip_landing=True,
                           unavailable="only the landing page was analyzed, which has its own description "
                                       "finding"),
    ),
    SeoCheckSpec(
        id="description_length", label="Description length outside guidance", area="metadata", weight=8,
        severity=S.INFORMATIONAL, title="Meta descriptions are very short or will be truncated",
        description=f"Descriptions under {DESC_MIN_CHARS} characters waste the snippet and those over "
                    f"{DESC_MAX_CHARS} are usually cut off.",
        evaluate=page_rule(lambda p: not (DESC_MIN_CHARS <= p.description_length <= DESC_MAX_CHARS),
                           eligible=lambda p: bool(p.meta_description),
                           unavailable="no analyzed indexable page has a meta description"),
    ),
    SeoCheckSpec(
        id="duplicate_descriptions", label="Duplicate descriptions", area="metadata", weight=15,
        severity=S.INFORMATIONAL, title="Several pages share the same meta description",
        description="Identical descriptions give every one of these pages the same snippet, so none of "
                    "them explains what makes it the right result.",
        evaluate=site_rule(lambda seo: _duplicates(seo, "description")),
    ),
    SeoCheckSpec(
        id="viewport_missing", label="No viewport meta tag", area="metadata", weight=15, severity=S.LOW,
        title="Pages declare no mobile viewport",
        description="Without a viewport meta tag, mobile browsers render the page at desktop width and "
                    "scale it down. Mobile usability is a ranking factor and this is its most basic signal.",
        evaluate=page_rule(lambda p: not p.viewport),
    ),
    SeoCheckSpec(
        id="lang_missing", label="No lang attribute", area="metadata", weight=10,
        severity=S.INFORMATIONAL, title="Pages declare no document language",
        description="The <html> element has no lang attribute, so search engines and screen readers must "
                    "guess the page's language.",
        evaluate=page_rule(lambda p: not p.lang),
    ),
    SeoCheckSpec(
        id="hreflang_invalid", label="Malformed hreflang values", area="metadata", weight=10,
        severity=S.LOW, title="hreflang alternates are not valid language tags",
        description="These hreflang values are not well-formed language (optionally script and region) "
                    "tags, so the alternates they declare are ignored and the pages stay unlinked for "
                    "international search.",
        evaluate=site_rule(_hreflang_invalid),
    ),
    SeoCheckSpec(
        id="social_metadata_missing", label="No social preview metadata", area="metadata", weight=10,
        severity=S.INFORMATIONAL, title="Pages have no Open Graph preview metadata",
        description="These pages carry no og:* tags, so links shared to social platforms and chat apps "
                    "get no controlled title, description or image.",
        evaluate=page_rule(lambda p: not p.open_graph_present, skip_landing=True,
                           unavailable="only the landing page was analyzed, which has its own Open Graph "
                                       "finding"),
    ),

    # ---------------------------------------------------------------- content
    SeoCheckSpec(
        id="h1_missing", label="Pages without an H1", area="content", weight=20, severity=S.LOW,
        title="Pages have no H1 heading",
        description="These pages have no top-level heading, so neither a reader nor a crawler is told what "
                    "the page is about in its own content.",
        evaluate=page_rule(lambda p: not p.h1),
    ),
    SeoCheckSpec(
        id="h1_multiple", label="Several H1 headings", area="content", weight=10,
        severity=S.INFORMATIONAL, title="Pages use more than one H1",
        description="More than one H1 leaves the page's main subject ambiguous. HTML5 sectioning permits "
                    "it, so this is a clarity observation rather than an error.",
        evaluate=page_rule(lambda p: len(p.h1) > 1),
    ),
    SeoCheckSpec(
        id="heading_hierarchy", label="Heading levels skipped", area="content", weight=8,
        severity=S.INFORMATIONAL, title="Heading levels are skipped",
        description="The heading sequence jumps a level (for example H2 straight to H4), so the document "
                    "outline that crawlers and screen readers build does not match the visual structure.",
        evaluate=page_rule(lambda p: bool(p.heading_skips),
                           detail=lambda bad: "; ".join(f"{p.url}: {', '.join(p.heading_skips[:3])}"
                                                        for p in bad[:5])),
    ),
    SeoCheckSpec(
        id="duplicate_h1", label="Duplicate H1 headings", area="content", weight=10,
        severity=S.INFORMATIONAL, title="Several pages share the same H1",
        description="Pages with the same H1 usually have near-identical content or an unfilled template "
                    "heading; either way nothing distinguishes them to a search engine.",
        evaluate=site_rule(lambda seo: _duplicates(seo, "h1")),
    ),
    SeoCheckSpec(
        id="thin_content", label="Very little page copy", area="content", weight=15,
        severity=S.INFORMATIONAL, title="Pages have very little text content",
        description=f"These pages contain under {THIN_CONTENT_WORDS} words of visible copy. Navigation, "
                    "legal and gallery pages are legitimately short, and text rendered by JavaScript is "
                    "not counted here unless the page was rendered — so confirm before rewriting anything.",
        evaluate=page_rule(lambda p: p.word_count < THIN_CONTENT_WORDS,
                           detail=lambda bad: "word counts: " + ", ".join(str(p.word_count) for p in bad[:10])),
    ),
    SeoCheckSpec(
        id="images_missing_alt", label="Images without alt text", area="content", weight=15,
        severity=S.LOW, title="Images have no alt attribute",
        description="These pages contain images with no alt attribute at all. Alt text is what search "
                    "engines and screen readers use to understand an image. An explicit empty alt=\"\" is "
                    "the correct way to mark a decorative image and is not counted here.",
        evaluate=page_rule(lambda p: p.images_missing_alt > 0, eligible=lambda p: p.images > 0,
                           unavailable="no analyzed indexable page contains images",
                           detail=lambda bad: f"{sum(p.images_missing_alt for p in bad)} image(s) without alt "
                                              f"across {len(bad)} page(s)"),
    ),
    SeoCheckSpec(
        id="structured_data_missing", label="No structured data", area="content", weight=12,
        severity=S.INFORMATIONAL, scope="site", title="The site declares no structured data",
        description="No JSON-LD or microdata was found on any analyzed page. Structured data is what makes "
                    "a result eligible for rich presentation (breadcrumbs, products, articles, FAQs); its "
                    "absence costs nothing in ranking but forfeits those features.",
        evaluate=site_rule(lambda seo: _fired([] if seo.structured_data else
                                              [(f"{seo.pages_analyzed} page(s) analyzed, none declaring "
                                                "JSON-LD or microdata")])),
    ),
    SeoCheckSpec(
        id="structured_data_invalid", label="Unparseable structured data", area="content", weight=10,
        severity=S.LOW, title="JSON-LD blocks could not be parsed",
        description="These pages contain JSON-LD that is not valid JSON, so the structured data in them is "
                    "discarded entirely rather than partially read.",
        evaluate=page_rule(lambda p: p.structured_data_errors > 0, indexable_only=False,
                           detail=lambda bad: f"{sum(p.structured_data_errors for p in bad)} unparseable "
                                              f"block(s)"),
    ),

    # ---------------------------------------------------------------- crawlability
    SeoCheckSpec(
        id="robots_txt_missing", label="No robots.txt", area="crawlability", weight=15,
        severity=S.INFORMATIONAL, scope="site", title="The origin serves no robots.txt",
        description="There is no robots.txt. Crawling still works — everything is allowed by default — but "
                    "there is nowhere to declare sitemaps or exclude URLs that should not be crawled.",
        evaluate=site_rule(lambda seo: _sitemap(seo)
                           or _fired([] if seo.sitemap and seo.sitemap.robots_txt_present
                                     else [f"{seo.origin}/robots.txt was not served"])),
    ),
    SeoCheckSpec(
        id="sitemap_missing", label="No XML sitemap", area="crawlability", weight=25, severity=S.LOW,
        scope="site", title="No XML sitemap was found",
        description="No sitemap was found at the conventional locations or declared in robots.txt. Search "
                    "engines then rely entirely on following links, which leaves weakly linked and new "
                    "pages to be found slowly or not at all.",
        evaluate=site_rule(lambda seo: _sitemap(seo)
                           or _fired([] if seo.sitemap and seo.sitemap.sitemap_count
                                     else ["no sitemap at the conventional paths or in robots.txt"])),
    ),
    SeoCheckSpec(
        id="sitemap_not_declared", label="Sitemap not declared in robots.txt", area="crawlability",
        weight=10, severity=S.INFORMATIONAL, scope="site",
        title="The sitemap is not declared in robots.txt",
        description="A sitemap exists but robots.txt does not point to it, so a crawler has to guess its "
                    "location. One Sitemap: line makes it discoverable.",
        evaluate=site_rule(_sitemap_not_declared),
    ),
    SeoCheckSpec(
        id="sitemap_coverage_gap", label="Pages absent from the sitemap", area="crawlability", weight=15,
        severity=S.INFORMATIONAL, title="Indexable pages are not listed in any sitemap",
        description="These indexable pages were reached by crawling but no sitemap lists them, so they "
                    "depend entirely on internal links to be discovered.",
        evaluate=site_rule(_coverage_gap),
    ),
    SeoCheckSpec(
        id="sitemap_errors", label="Sitemap lists failing URLs", area="crawlability", weight=20,
        severity=S.LOW, scope="site", title="The sitemap lists URLs that return an error",
        description="URLs listed in the sitemap answered with an error status when this scan fetched them. "
                    "A sitemap of dead URLs wastes crawl budget and signals a stale generation step.",
        evaluate=site_rule(lambda seo: _sitemap(seo) or _fired(seo.sitemap.sitemap_errors if seo.sitemap else [])),
    ),
    SeoCheckSpec(
        id="orphan_pages", label="Pages with no inbound internal link", area="crawlability", weight=15,
        severity=S.INFORMATIONAL, title="Pages have no inbound link from any analyzed page",
        description="No analyzed page links to these URLs, so within the crawled part of the site they are "
                    "unreachable by following links and receive no internal link equity.",
        evaluate=site_rule(_orphans),
    ),
    SeoCheckSpec(
        id="broken_internal_links", label="Broken internal links", area="crawlability", weight=25,
        severity=S.LOW, scope="site", title="Internal links point at URLs that return an error",
        description="These in-scope URLs were linked from the site but answered with a 4xx/5xx status or "
                    "failed to load, so visitors and crawlers following those links hit a dead end.",
        evaluate=site_rule(lambda seo: _fired(
            [f"{b.url} → {b.status_code or b.error}" + (f" (from {b.linked_from})" if b.linked_from else "")
             for b in seo.broken_links],
            detail=f"{len(seo.broken_links)} failing internal URL(s)" if seo.broken_links else None)
            if seo.pages_source != "landing page"
            else CheckOutcome(note="internal links were not followed (run with --crawl)")),
    ),
    SeoCheckSpec(
        id="internal_redirects", label="Internal links to redirecting URLs", area="crawlability",
        weight=10, severity=S.INFORMATIONAL, scope="site",
        title="Internal links point at URLs that redirect",
        description="These internal URLs redirect before serving the page. Each hop costs a round trip and "
                    "the destination is the URL that should have been linked; updating the links removes both.",
        evaluate=site_rule(lambda seo: _fired([f"{r.url} → {r.final_url}" for r in seo.redirects],
                                              detail=f"{len(seo.redirects)} redirecting internal URL(s)"
                                              if seo.redirects else None)
                           if seo.pages_source != "landing page"
                           else CheckOutcome(note="internal links were not followed (run with --crawl)")),
    ),
    SeoCheckSpec(
        id="deep_pages", label="Pages far from the home page", area="crawlability", weight=8,
        severity=S.INFORMATIONAL, title="Pages sit deep in the link structure",
        description=f"These pages were first reached {DEEP_PAGE_DEPTH} or more clicks from the home page. "
                    "Depth is a rough proxy for importance, and deep pages are crawled less often.",
        evaluate=site_rule(_deep_pages),
    ),

    # ---------------------------------------------------------------- performance / delivery
    SeoCheckSpec(
        id="no_compression", label="HTML served uncompressed", area="performance", weight=25,
        severity=S.LOW, scope="site", title="HTML is served without compression",
        description="The landing page's HTML came back with no Content-Encoding, so markup that compresses "
                    "several times over is sent in full. Enabling gzip or brotli is usually a one-line "
                    "change at the server or CDN.",
        evaluate=site_rule(lambda seo: _fired([] if seo.compression else
                                              ["no Content-Encoding on the landing page response"])
                           if seo.http_version else
                           CheckOutcome(note="no landing-page response headers were available")),
    ),
    SeoCheckSpec(
        id="slow_pages", label="Slow server responses", area="performance", weight=25,
        severity=S.INFORMATIONAL, title="Pages are slow to respond",
        description=f"The server took over {SLOW_RESPONSE_MS:.0f} ms to respond for these pages. This is "
                    "server response time only — not a user-perceived metric and not Core Web Vitals — but "
                    "it is time no amount of front-end work can recover.",
        evaluate=page_rule(lambda p: (p.response_time_ms or 0) > SLOW_RESPONSE_MS, indexable_only=False,
                           eligible=lambda p: p.response_time_ms is not None,
                           unavailable="no page recorded a response time",
                           detail=lambda bad: "slowest: " + ", ".join(
                               f"{p.response_time_ms:.0f} ms" for p in
                               sorted(bad, key=lambda q: -(q.response_time_ms or 0))[:5])),
    ),
    SeoCheckSpec(
        id="heavy_html", label="Very large HTML documents", area="performance", weight=20,
        severity=S.INFORMATIONAL, title="HTML documents are very large",
        description=f"These documents exceed {HEAVY_HTML_BYTES // 1024} KB of markup alone, before any "
                    "images, scripts or styles. Oversized HTML is usually inlined data or markup that "
                    "could be paginated.",
        evaluate=page_rule(lambda p: p.html_bytes > HEAVY_HTML_BYTES, indexable_only=False,
                           detail=lambda bad: "sizes: " + ", ".join(f"{p.html_bytes // 1024} KB"
                                                                    for p in bad[:5])),
    ),
    SeoCheckSpec(
        id="legacy_http_version", label="HTTP/1.1 only", area="performance", weight=15,
        severity=S.INFORMATIONAL, scope="site", title="The site is served over HTTP/1.1",
        description="The landing page was served over HTTP/1.1. HTTP/2 and HTTP/3 multiplex requests over "
                    "one connection, which matters most for pages with many subresources.",
        evaluate=site_rule(lambda seo: _fired([f"negotiated {seo.http_version}"]
                                              if (seo.http_version or "").startswith("HTTP/1") else [])
                           if seo.http_version
                           else CheckOutcome(note="no negotiated HTTP version was recorded")),
    ),
)

CHECKS_BY_ID: dict[str, SeoCheckSpec] = {c.id: c for c in SEO_CHECKS}
