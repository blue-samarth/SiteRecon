from recon.models.common import Confidence
from recon.models.http import HttpData, HttpProbe, SecurityHeader
from recon.models.technology import DetectionStatus
from recon.modules import FingerprintInputs, HtmlParser, SecurityHeaderParser, TechnologyFingerprinter
from recon.utils.scope import Scope


def techs(inp):
    return {t.name: t for t in TechnologyFingerprinter().fingerprint(inp).technologies}


def test_header_evidence_is_confirmed_with_version():
    t = techs(FingerprintInputs(headers={"server": ["nginx/1.25.3"], "x-powered-by": ["Next.js"]}))
    assert t["Nginx"].status is DetectionStatus.CONFIRMED and t["Nginx"].version == "1.25.3"
    assert t["Next.js"].confidence is Confidence.HIGH
    # Implied technology is only possible, low confidence
    assert t["React"].status is DetectionStatus.POSSIBLE and t["React"].confidence is Confidence.LOW


def test_single_weak_signal_is_probable_and_two_sources_confirm():
    t = techs(FingerprintInputs(urls=["https://example.com/_next/static/chunks/main.js"]))
    assert t["Next.js"].status is DetectionStatus.PROBABLE
    t = techs(FingerprintInputs(urls=["https://example.com/_next/static/chunks/main.js"],
                      html='<script id="__NEXT_DATA__" type="application/json">'))
    assert t["Next.js"].status is DetectionStatus.CONFIRMED
    assert {e.source for e in t["Next.js"].evidence} == {"resource_url", "html"}


def test_csp_only_domain_is_low_confidence():
    t = techs(FingerprintInputs(csp_domains={"abc.supabase.co"}))
    assert t["Supabase"].confidence is Confidence.LOW
    assert t["Supabase"].status is DetectionStatus.POSSIBLE
    t = techs(FingerprintInputs(domains={"abc.supabase.co"}))
    assert t["Supabase"].confidence is Confidence.MEDIUM and t["Supabase"].status is DetectionStatus.PROBABLE


def test_version_from_url_and_generator():
    t = techs(FingerprintInputs(urls=["https://code.jquery.com/jquery-3.7.1.min.js"], generator="WordPress 6.4.2"))
    assert t["jQuery"].version == "3.7.1"
    assert t["WordPress"].version == "6.4.2" and t["WordPress"].status is DetectionStatus.CONFIRMED


def test_no_false_positive_on_empty_inputs():
    assert TechnologyFingerprinter().fingerprint(FingerprintInputs()).technologies == []


def test_csp_hosts():
    parsed = SecurityHeaderParser.parse_csp("default-src 'self'; connect-src https://*.supabase.co wss://rt.example.io data: 'unsafe-inline'; img-src *")
    assert SecurityHeaderParser.csp_hosts(parsed) == {"supabase.co", "rt.example.io"}


def test_comments_excluded_from_html_matching():
    body = b'<html><!-- <div id="___gatsby"></div> --><body></body></html>'
    probe = HttpProbe(requested_url="https://example.com/", success=True, final_url="https://example.com/",
                      final_fetched=True, content_type="text/html", body=body,
                      security_headers={"content-security-policy": SecurityHeader(name="content-security-policy", present=False)})
    http = HttpData(probes=[probe])
    html = HtmlParser(body, "https://example.com/", Scope.for_target("example.com")).parse()
    assert "Gatsby" not in techs(FingerprintInputs.from_collected(http, html))
