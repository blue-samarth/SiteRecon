import datetime as dt

from recon.analysis import AnalysisEngine, SIGNATURES_VERSION, detect_wafs
from recon.models import CookieData, CookieRecord, HttpData, HttpProbe

T0 = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)


def http_with(headers=None, server=None, url="https://example.com/"):
    return HttpData(probes=[HttpProbe(requested_url=url, success=True, final_fetched=True, final_url=url,
                                      status_code=200, server=server, headers=headers or {})])


def waf_findings(http, cookies=None):
    res = AnalysisEngine(T0).analyze(dns=None, network=None, http=http, tls=None, cookies=cookies)
    return [f for f in res.findings if f.category == "waf"]


def cookies_named(*names):
    return CookieData(cookies=[CookieRecord(name=n, source_url="https://example.com/", over_https=True) for n in names])


# ------------------------------------------------------------------ detector

def test_dedicated_header_and_banner_are_high_confidence():
    assert detect_wafs({"x-sucuri-id": ["z"]}, [], None)[0].confidence.value == "high"
    assert detect_wafs({}, [], "Sucuri/Cloudproxy")[0].vendor == "Sucuri CloudProxy"
    assert detect_wafs({"x-iinfo": ["1"]}, [], None)[0].vendor == "Imperva (Incapsula)"


def test_shared_proxy_signal_is_only_medium_confidence():
    det = detect_wafs({"cf-ray": ["7a"]}, [], "cloudflare")
    assert det[0].vendor == "Cloudflare" and det[0].confidence.value == "medium"
    assert "capable" in det[0].note or "may or may not" in det[0].note   # WAF-capable, not proven-enabled


def test_strongest_signal_wins_and_evidence_is_merged():
    det = detect_wafs({"cf-ray": ["7a"]}, ["__cf_bm"], "cloudflare")
    assert len(det) == 1 and det[0].vendor == "Cloudflare" and det[0].confidence.value == "high"
    assert any("cf-ray" in e for e in det[0].evidence) and any("__cf_bm" in e for e in det[0].evidence)


def test_cookie_name_prefixes_detect_incapsula():
    det = detect_wafs({}, ["visid_incap_123", "nlbi_55"], None)
    assert det[0].vendor == "Imperva (Incapsula)" and det[0].confidence.value == "high"


def test_multiple_vendors_can_be_detected():
    vendors = {d.vendor for d in detect_wafs({"cf-ray": ["x"], "x-sucuri-id": ["y"]}, [], "cloudflare")}
    assert vendors == {"Cloudflare", "Sucuri CloudProxy"}


def test_no_signature_means_no_detection():
    assert detect_wafs({"server": ["nginx"], "x-powered-by": ["php"]}, ["sessionid", "csrftoken"], "nginx") == []


# ------------------------------------------------------------------ engine finding

def test_waf_finding_is_informational_with_version_and_caveats():
    findings = waf_findings(http_with(headers={"cf-ray": ["7a"]}, server="cloudflare"), cookies_named("__cf_bm"))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity.value == "informational" and f.confidence.value == "high" and f.subject == "example.com"
    assert f"signature DB version: {SIGNATURES_VERSION}" in f.evidence
    assert "NOT proof" in f.description                          # absence is not proof of no WAF
    assert f.recommendation and f.limitations


def test_no_waf_signature_produces_no_finding_not_a_negative_claim():
    # the honesty rule: a non-match must yield nothing, never a "no WAF" finding
    assert waf_findings(http_with(headers={"server": ["nginx"]}, server="nginx")) == []


def test_waf_uses_cookies_even_without_headers():
    findings = waf_findings(http_with(headers={}, server=None), cookies_named("incap_ses_9", "visid_incap_1"))
    assert findings and findings[0].title.startswith("Web Application Firewall detected: Imperva")


def test_no_successful_probe_is_safe():
    http = HttpData(probes=[HttpProbe(requested_url="https://x/", success=False)])
    assert waf_findings(http) == []
