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


# ------------------------------------------------------------------ expanded signature set

import re

import pytest

from recon.analysis import SIGNATURES_VERSION, TECH_SIGNATURES


def test_every_signature_pattern_compiles_and_names_are_unique():
    names = [s.name for s in TECH_SIGNATURES]
    assert len(names) == len(set(names))
    for sig in TECH_SIGNATURES:
        for pattern in (*[p for _, p in sig.headers], sig.generator, *sig.urls, *sig.html, *sig.dns):
            if pattern:
                re.compile(pattern)          # a bad regex would silently disable the signature


def test_implications_only_reference_known_signatures():
    known = {s.name for s in TECH_SIGNATURES}
    assert not {implied for s in TECH_SIGNATURES for implied in s.implies if implied not in known}


def test_signature_coverage_spans_the_categories_a_review_needs():
    categories = {s.category for s in TECH_SIGNATURES}
    assert {"cdn", "waf" if "waf" in categories else "security", "analytics", "backend_framework",
            "object_storage", "serverless", "managed_database", "authentication", "consent",
            "monitoring", "payment", "web_server", "cms"} <= categories
    assert len(TECH_SIGNATURES) > 400        # expanded from the original 87


def test_signatures_version_is_recorded_for_reproducibility():
    assert re.fullmatch(r"\d{4}\.\d{2}\.\d{2}(?:\.\d+)?", SIGNATURES_VERSION)


@pytest.mark.parametrize("inputs, expected", [
    ({"headers": {"server": ["openresty/1.25.3.1"]}}, "OpenResty"),
    ({"headers": {"x-amzn-waf-action": ["challenge"]}}, None),          # WAFs live in their own table
    ({"headers": {"set-cookie": ["csrftoken=abc"]}}, "Django"),
    ({"headers": {"server": ["gunicorn/21.2.0"]}}, "Python"),
    ({"headers": {"set-cookie": ["ci_session=x"]}}, "CodeIgniter"),
    ({"headers": {"x-azure-ref": ["0ABC"]}}, "Azure Front Door"),
    ({"headers": {"cdn-pullzone": ["12345"]}}, "BunnyCDN"),
    ({"generator": "Joomla! 4.2.1"}, "Joomla"),
    ({"generator": "MkDocs 1.5.3"}, "MkDocs"),
    ({"urls": ["https://cdn.example.com/swiper-bundle.min.js"]}, "Swiper"),
    ({"urls": ["https://cdn.example.com/d3.v7.min.js"]}, "D3.js"),
    ({"urls": ["https://example.com/plugins/woocommerce/assets/js/x.js"]}, "WooCommerce"),
    ({"domains": {"cdn.cookielaw.org"}}, "OneTrust"),
    ({"domains": {"cdn.amplitude.com"}}, "Amplitude"),
    ({"domains": {"js.squareup.com"}}, "Square"),
    ({"domains": {"tenant.auth0.com"}}, "Auth0"),
    ({"domains": {"acct.blob.core.windows.net"}}, "Azure Blob Storage"),
    ({"html": '<div wire:model="name"></div>'}, "Livewire"),
    ({"html": '<turbo-frame id="x">'}, "Turbo (Hotwire)"),
])
def test_expanded_signatures_detect_their_technology(inputs, expected):
    found = techs(FingerprintInputs(**inputs))
    if expected is None:
        assert not found
    else:
        assert expected in found, f"expected {expected}, got {sorted(found)}"


def test_a_plain_page_produces_no_speculative_detections():
    # The expanded set must not fire on ordinary markup and conventional asset names.
    plain = FingerprintInputs(
        headers={"server": ["nginx"], "content-type": ["text/html"]},
        urls=["https://example.com/static/app.js", "https://example.com/css/site.css",
              "https://example.com/api/items", "/images/logo.png",
              "https://example.com/assets/main-a1b2c3d4.js"],
        html='<html><head><title>x</title></head><body><div class="container">'
             '<p>We use video.js and browserify here</p></div></body></html>')
    assert set(techs(plain)) == {"Nginx"}


# ------------------------------------------------------------------ confidence grading

def test_two_weak_signals_never_corroborate_into_confirmed():
    # CSP-allowed plus a matching CNAME means "permitted and perhaps delivered", not "in use".
    t = techs(FingerprintInputs(csp_domains={"static.wixstatic.com"}, dns_targets={"x.wixdns.net"}))
    assert {e.source for e in t["Wix"].evidence} == {"csp", "dns"}
    assert t["Wix"].status is DetectionStatus.PROBABLE
    assert t["Wix"].confidence is Confidence.LOW
    # one weak signal on its own stays merely possible
    assert techs(FingerprintInputs(dns_targets={"x.wixdns.net"}))["Wix"].status is DetectionStatus.POSSIBLE


def test_two_independent_real_signals_do_corroborate():
    t = techs(FingerprintInputs(urls=["https://example.com/_next/static/chunks/main.js"],
                                html="__NEXT_DATA__"))
    assert t["Next.js"].status is DetectionStatus.CONFIRMED and t["Next.js"].confidence is Confidence.HIGH


def test_an_implication_alone_stays_possible():
    t = techs(FingerprintInputs(headers={"x-powered-by": ["Next.js"]}))
    assert t["Next.js"].status is DetectionStatus.CONFIRMED
    assert t["React"].status is DetectionStatus.POSSIBLE and t["React"].confidence is Confidence.LOW


def test_a_weak_signal_plus_a_real_one_is_confirmed_by_the_real_one():
    t = techs(FingerprintInputs(domains={"abc.supabase.co"}, csp_domains={"abc.supabase.co"}))
    assert t["Supabase"].status is DetectionStatus.PROBABLE      # one real medium signal
    t = techs(FingerprintInputs(headers={"server": ["nginx/1.25.3"]}, csp_domains={"x.example.com"}))
    assert t["Nginx"].status is DetectionStatus.CONFIRMED


# ------------------------------------------------------------------ version detection

def test_version_from_a_cdn_package_path():
    t = techs(FingerprintInputs(urls=["https://cdn.jsdelivr.net/npm/swiper@11.0.5/swiper-bundle.min.js"]))
    assert t["Swiper"].version == "11.0.5"


def test_platform_version_from_the_asset_query_of_a_versioned_cms():
    # WordPress stops disclosing its version in the generator tag, but its own assets still carry ?ver=.
    t = techs(FingerprintInputs(urls=["https://example.com/wp-includes/js/wp-embed.min.js?ver=6.5.3",
                                      "https://example.com/wp-content/themes/t/style.css?ver=6.5.3"]))
    assert t["WordPress"].version == "6.5.3"


def test_a_library_version_comes_from_its_own_query_not_the_platforms():
    t = techs(FingerprintInputs(urls=["https://example.com/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"]))
    assert t["jQuery"].version == "3.7.1"


def test_no_version_is_invented_from_a_content_hash():
    t = techs(FingerprintInputs(urls=["https://example.com/assets/swiper-a1b2c3d4e5.js"],
                                html='<div class="swiper-container"></div>'))
    assert t["Swiper"].version is None
