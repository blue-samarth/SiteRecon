import datetime as dt

from recon.analysis import (
    SIGNATURES_VERSION,
    AnalysisEngine,
    TrackerCategory,
    classify_tracker,
)
from recon.models import Confidence, HtmlData, ThirdPartyData, ThirdPartyService

T0 = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
HTML = HtmlData(source_url="https://example.com/")


def svc(provider, category, domains, sources=("loaded script",), confidence=Confidence.HIGH):
    return ThirdPartyService(provider=provider, category=category, domains=list(domains),
                             sources=list(sources), confidence=confidence)


def trackers(*services):
    res = AnalysisEngine(T0).analyze(dns=None, network=None, http=None, tls=None, html=HTML,
                                     third_party=ThirdPartyData(services=list(services)))
    return {f.id.split(":", 1)[0]: f for f in res.findings if f.category == "trackers"}


# ------------------------------------------------------------------ classification

def test_classify_known_trackers_by_purpose():
    assert classify_tracker("www.google-analytics.com").category is TrackerCategory.ANALYTICS
    assert classify_tracker("static.hotjar.com").category is TrackerCategory.SESSION_REPLAY
    assert classify_tracker("clarity.ms").category is TrackerCategory.SESSION_REPLAY
    assert classify_tracker("stats.g.doubleclick.net").category is TrackerCategory.ADVERTISING
    assert classify_tracker("connect.facebook.net").category is TrackerCategory.SOCIAL
    assert classify_tracker("cdn.segment.com").category is TrackerCategory.CDP
    assert classify_tracker("cdn.cookielaw.org").category is TrackerCategory.CONSENT
    assert classify_tracker("googletagmanager.com").category is TrackerCategory.TAG_MANAGER


def test_classify_rejects_non_trackers_and_respects_label_boundaries():
    assert classify_tracker("cdnjs.cloudflare.com") is None            # a CDN, not a tracker
    assert classify_tracker("api.example.com") is None
    assert classify_tracker("evilgoogle-analytics.com") is None        # suffix must be at a label boundary
    assert classify_tracker("") is None


# ------------------------------------------------------------------ inventory finding

def test_tracker_inventory_groups_and_excludes_non_trackers():
    ids = trackers(
        svc("Google Analytics", "analytics", ["www.google-analytics.com"]),
        svc("DoubleClick", "advertising", ["stats.g.doubleclick.net"], sources=["CSP allow-list"]),
        svc("Cloudflare", "cdn", ["cdnjs.cloudflare.com"]),            # not a tracker
    )
    assert "trackers.detected" in ids
    f = ids["trackers.detected"]
    assert f.severity.value == "informational" and f.subject == "example.com"
    ev = "\n".join(f.evidence)
    assert "2 tracker(s)" in ev and "analytics: 1" in ev and "advertising: 1" in ev
    assert "Cloudflare" not in ev                                      # the CDN was not classified as a tracker
    assert f"signature DB version: {SIGNATURES_VERSION}" in ev
    assert "via CSP allow-list" in ev                                  # the detection source is recorded


def test_no_trackers_produces_no_finding():
    assert trackers(svc("Cloudflare", "cdn", ["cdnjs.cloudflare.com"])) == {}
    assert AnalysisEngine(T0).analyze(dns=None, network=None, http=None, tls=None, html=HTML,
                                      third_party=None) is not None   # None third_party is safe


def test_session_replay_escalated_separately():
    ids = trackers(
        svc("Hotjar", "analytics", ["static.hotjar.com"]),
        svc("Google Analytics", "analytics", ["www.google-analytics.com"]),
    )
    assert "trackers.session_replay" in ids
    sr = ids["trackers.session_replay"]
    assert sr.severity.value == "low" and "Hotjar" in " ".join(sr.evidence)
    assert sr.recommendation and sr.limitations


def test_advertising_only_has_inventory_but_no_session_replay_finding():
    ids = trackers(svc("Criteo", "advertising", ["criteo.com"]))
    assert "trackers.detected" in ids and "trackers.session_replay" not in ids


def test_inventory_finding_carries_recommendation_and_derived_state():
    f = trackers(svc("Google Analytics", "analytics", ["www.google-analytics.com"]))["trackers.detected"]
    assert f.recommendation and f.limitations and f.state is not None


# ------------------------------------------------------------------ versioned signatures

def test_signature_database_is_versioned():
    assert isinstance(SIGNATURES_VERSION, str) and SIGNATURES_VERSION


def test_scan_options_record_the_signature_version():
    # the orchestrator stamps the signature DB version into the scan's recorded options (reproducibility)
    from recon.config import Config
    from recon.orchestrator import ScanOrchestrator

    options = ScanOrchestrator(Config(target_input="example.com", hostname="example.com")).options()
    assert options["signatures_version"] == SIGNATURES_VERSION
