import datetime as dt

from recon.analysis import AnalysisEngine, ObservationBuilder
from recon.models import CollectionMethod, Freshness, HtmlData, ModuleResult, ModuleStatus

T0 = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)

OG_FULL = {"og:title": "t", "og:type": "website", "og:image": "https://example.com/i.png",
           "og:url": "https://example.com/"}


def analyze(html):
    return {f.id.split(":", 1)[0]: f
            for f in AnalysisEngine(T0).analyze(dns=None, network=None, http=None, tls=None, html=html).findings}


def page(**over):
    base = dict(source_url="https://example.com/", title="Home", meta_description="A description",
                canonical="https://example.com/", robots="index,follow", open_graph=dict(OG_FULL),
                twitter={"twitter:card": "summary"})
    base.update(over)
    return HtmlData(**base)


# ------------------------------------------------------------------ no false positives

def test_complete_metadata_produces_no_seo_or_social_findings():
    ids = analyze(page())
    assert not any(k.startswith(("seo.", "og.", "twitter.")) for k in ids)


# ------------------------------------------------------------------ SEO

def test_missing_title_and_description():
    ids = analyze(page(title=None, meta_description=None))
    assert "seo.title_missing" in ids and "seo.meta_description_missing" in ids
    assert ids["seo.title_missing"].severity.value == "informational"


def test_noindex_landing_page_is_flagged_low():
    ids = analyze(page(robots="noindex, nofollow"))
    assert ids["seo.noindex"].severity.value == "low"
    assert 'noindex' in ids["seo.noindex"].evidence[0]


def test_canonical_offsite_flagged_but_same_registrable_domain_is_not():
    assert "seo.canonical_offsite" in analyze(page(canonical="https://evil.net/x"))
    assert "seo.canonical_offsite" not in analyze(page(canonical="https://www.example.com/"))   # subdomain, same site
    assert "seo.canonical_offsite" not in analyze(page(canonical="/relative/path"))              # relative = same site


def test_seo_findings_carry_recommendation_and_derived_state():
    f = analyze(page(title=None))["seo.title_missing"]
    assert f.recommendation and f.limitations and f.state is not None and f.category == "seo"


# ------------------------------------------------------------------ Open Graph / Twitter

def test_open_graph_missing_entirely():
    ids = analyze(page(open_graph={}, twitter={}))
    assert "og.missing" in ids
    # when OG is absent we do not also nag about incompleteness/twitter — og.missing is the single signal
    assert "og.incomplete" not in ids and "og.malformed" not in ids and "twitter.card_missing" not in ids


def test_open_graph_incomplete():
    ids = analyze(page(open_graph={"og:title": "t"}))
    assert "og.incomplete" in ids
    ev = " ".join(ids["og.incomplete"].evidence)
    assert "og:url" in ev and "og:image" in ev


def test_open_graph_malformed_urls():
    ids = analyze(page(open_graph={**OG_FULL, "og:image": "/rel.png", "og:url": "//cdn/x"}))
    assert "og.malformed" in ids and ids["og.malformed"].severity.value == "low"
    assert "og.incomplete" not in ids   # all core properties are present, just not absolute


def test_twitter_card_missing_only_when_og_present():
    assert "twitter.card_missing" in analyze(page(twitter={}))
    assert "twitter.card_missing" not in analyze(page(open_graph={}, twitter={}))   # no OG → no twitter nag
    assert "twitter.card_missing" not in analyze(page())                            # card present


# ------------------------------------------------------------------ observation pipeline

def test_html_metadata_becomes_observations_with_provenance():
    r = ModuleResult(module="html", status=ModuleStatus.SUCCESS, started_at=T0, finished_at=T0,
                     duration_ms=1, data=page(verification_tokens={"google-site-verification": "secret-token"}))
    obs = {(o.type, o.key): o for o in ObservationBuilder("example.com", {"html": r}).build()}
    assert ("html.metadata", "title") in obs and ("html.open_graph", "properties") in obs
    assert ("html.twitter", "card") in obs and ("html.verification", "providers") in obs
    assert all(o.collection_method == CollectionMethod.STATIC_ANALYSIS and o.freshness is Freshness.FRESH
               for o in obs.values())
    # verification token VALUES are never stored, only provider names
    assert obs[("html.verification", "providers")].value == ["google-site-verification"]


def test_absent_metadata_is_not_recorded_as_a_null_observation():
    r = ModuleResult(module="html", status=ModuleStatus.SUCCESS, started_at=T0, finished_at=T0,
                     duration_ms=1, data=page(title=None, open_graph={}, twitter={}, meta_description=None))
    keys = {(o.type, o.key) for o in ObservationBuilder("example.com", {"html": r}).build()}
    assert ("html.metadata", "title") not in keys        # absent → no observation (a later drop reads as removed)
    assert ("html.open_graph", "properties") not in keys
