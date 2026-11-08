import datetime as dt
import gzip
import json

import httpx
import pytest
import respx

from recon.models import HttpData, HttpProbe, RobotsInfo
from recon.modules import (
    CookieCollector,
    CookieParser,
    Crawler,
    HttpCollector,
    ResourcesCollector,
    RobotsParser,
    RobotsRules,
    SecurityHeaderParser,
)
from recon.utils.http_client import SafeHttpClient
from recon.utils.scope import Scope
from tests.conftest import public_resolve

NOW = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)


def client(**kw):
    return SafeHttpClient(Scope.for_target("example.com"), user_agent="t", retries=0, resolve=public_resolve, **kw)


def html(body: str, **headers):
    return httpx.Response(200, headers={"content-type": "text/html", **headers}, content=body.encode())


# ------------------------------------------------------------------ robots

def test_robots_parser_groups_and_rules():
    info = RobotsInfo(url="https://example.com/robots.txt", present=True)
    RobotsParser.parse("""
User-agent: Googlebot
Disallow: /only-google
User-agent: *
Disallow: /admin
Disallow: /*.pdf$
Allow: /admin/public
Crawl-delay: 2
Sitemap: https://example.com/sitemap.xml
""", info)
    assert info.disallow == ["/admin", "/*.pdf$"] and info.allow == ["/admin/public"]
    assert info.crawl_delay == 2.0 and info.sitemaps == ["https://example.com/sitemap.xml"]
    assert "/only-google" not in info.disallow
    rules = RobotsRules.from_info(info)
    assert not rules.allows("/admin/secret") and rules.allows("/admin/public/page")
    assert not rules.allows("/files/a.pdf") and rules.allows("/files/a.pdf?x=1")
    assert rules.allows("/")


# ------------------------------------------------------------------ crawler

@respx.mock
async def test_crawler_scope_depth_robots_forms_and_sources():
    respx.get("https://example.com/").mock(return_value=html("""
        <title>Home</title>
        <a href="/about">About</a> <a href="/admin/x">Admin</a> <a href="https://evil.test/">Off-site</a>
        <a href="/logo.png">img</a> <a href="/about#team">dup</a> <a href="mailto:a@b.c">m</a>
        <form action="/login" method="post"><input name="user"><input type="password" name="pw"></form>
        <script src="https://cdn.jsdelivr.net/npm/x.js"></script>""",
        **{"set-cookie": "sid=SECRETVALUE; Path=/; HttpOnly", "strict-transport-security": "max-age=1"}))
    respx.get("https://example.com/about").mock(return_value=html('<a href="/deep">Deep</a><a href="/">Home</a>'))
    login = respx.post("https://example.com/login").mock(return_value=httpx.Response(200))
    admin = respx.get("https://example.com/admin/x").mock(return_value=html("x"))
    robots = RobotsInfo(url="https://example.com/robots.txt", present=True, disallow=["/admin"])

    async with client() as c:
        data, errors = await Crawler("example.com", c, ["https://example.com/"], max_depth=1, max_pages=10,
                                     delay=0, robots=robots).collect()

    urls = [p.url for p in data.pages]
    assert urls == ["https://example.com/", "https://example.com/about"]
    about = data.pages[1]
    assert about.source_url == "https://example.com/" and about.depth == 1
    reasons = {u.url: (u.reason, u.source_url) for u in data.discovered}
    assert reasons["https://example.com/admin/x"][0] == "robots_disallowed" and not admin.called
    assert reasons["https://example.com/logo.png"][0] == "non_html"
    assert reasons["https://example.com/deep"] == ("depth_limit", "https://example.com/about")
    assert not any("evil.test" in u for u in reasons) and not login.called      # forms never submitted
    form = data.forms[0]
    assert form.method == "post" and form.has_password_field and form.input_names == ["user", "pw"]
    home = data.pages[0]
    assert home.security_headers["strict-transport-security"] == "max-age=1"
    assert home.security_headers["content-security-policy"] is None
    assert home.set_cookies == ["sid=SECRETVALUE; Path=/; HttpOnly"]
    assert "cdn.jsdelivr.net" in home.external_domains and errors == []
    dumped = data.model_dump_json()
    assert "SECRETVALUE" not in dumped and "set_cookies" not in dumped and '"body"' not in dumped


@respx.mock
async def test_crawler_page_limit_and_query_redaction():
    links = "".join(f'<a href="/p{i}?token=abc{i}&id={i}">x</a>' for i in range(10))
    respx.get("https://example.com/").mock(return_value=html(links))
    respx.get(url__regex=r"https://example.com/p\d").mock(return_value=html("leaf"))
    async with client() as c:
        data, _ = await Crawler("example.com", c, ["https://example.com/"], max_depth=2, max_pages=3,
                                delay=0).collect()
    assert len(data.pages) == 3 and data.page_limit_reached
    assert all("abc" not in p.url for p in data.pages)                  # token values redacted in reports
    assert data.pages[1].query_params == ["id", "token"]
    assert sum(1 for u in data.discovered if u.reason == "page_limit") == 8   # 10 links - 2 fetched


def test_crawler_normalization():
    crawler = Crawler("example.com", None, [])
    assert crawler.normalize("HTTPS://Example.com:443/a?b=2&a=1#frag") == "https://example.com/a?a=1&b=2"
    assert crawler.normalize("/x", "https://www.example.com/dir/") == "https://www.example.com/x"
    assert crawler.normalize("https://evil.test/") is None
    assert crawler.normalize("javascript:alert(1)") is None


def test_robots_crawl_delay_raises_delay_but_is_capped():
    robots = RobotsInfo(url="x", present=True, crawl_delay=60)
    assert Crawler("example.com", None, [], delay=0.1, robots=robots).delay == Crawler.MAX_ROBOTS_DELAY
    assert Crawler("example.com", None, [], delay=0.1, robots=robots, respect_robots=False).delay == 0.1


@respx.mock
async def test_crawler_out_of_scope_redirect_not_followed():
    respx.get("https://example.com/").mock(return_value=httpx.Response(302, headers={"location": "https://evil.test/"}))
    evil = respx.get("https://evil.test/").mock(return_value=html("x"))
    async with client() as c:
        data, errors = await Crawler("example.com", c, ["https://example.com/"], delay=0).collect()
    assert not evil.called and data.pages[0].error and errors


# ------------------------------------------------------------------ resources

SITEMAP_INDEX = b"""<?xml version="1.0"?><sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<sitemap><loc>https://example.com/sitemap-pages.xml.gz</loc></sitemap>
<sitemap><loc>https://evil.test/sitemap.xml</loc></sitemap></sitemapindex>"""
SITEMAP_PAGES = b"""<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>https://example.com/a</loc></url><url><loc>https://example.com/b</loc></url>
<url><loc>https://other.test/c</loc></url></urlset>"""


@respx.mock
async def test_resources_collector_end_to_end():
    respx.get("https://example.com/robots.txt").mock(return_value=httpx.Response(
        200, headers={"content-type": "text/plain"},
        content=b"User-agent: *\nDisallow: /private\nSitemap: https://example.com/sitemap_index.xml\n"))
    respx.get("https://example.com/sitemap_index.xml").mock(return_value=httpx.Response(200, content=SITEMAP_INDEX))
    respx.get("https://example.com/sitemap-pages.xml.gz").mock(return_value=httpx.Response(
        200, content=gzip.compress(SITEMAP_PAGES)))
    evil = respx.get("https://evil.test/sitemap.xml").mock(return_value=httpx.Response(200))
    respx.get("https://example.com/.well-known/security.txt").mock(return_value=httpx.Response(
        200, headers={"content-type": "text/plain"},
        content=b"Contact: mailto:security@example.com\nExpires: 2025-01-01T00:00:00Z\nPolicy: https://example.com/p\n"))
    respx.get("https://example.com/manifest.json").mock(return_value=httpx.Response(
        200, content=json.dumps({"name": "Ex", "start_url": "/", "icons": [{}, {}]}).encode()))
    respx.get("https://example.com/favicon.ico").mock(return_value=httpx.Response(
        200, headers={"content-type": "image/x-icon"}, content=b"\x00\x00\x01\x00"))
    respx.get("https://example.com/humans.txt").mock(return_value=html("<!doctype html><html>SPA fallback</html>"))

    async with client() as c:
        data, errors = await ResourcesCollector("example.com", c, "https://example.com", now=NOW).collect()

    assert data.robots.present and data.robots.disallow == ["/private"]
    assert [s.kind for s in data.sitemaps] == ["sitemapindex", "urlset"] and not evil.called
    assert data.sitemap_urls() == ["https://example.com/a", "https://example.com/b"]
    st = data.security_txt
    assert st.present and st.contacts == ["mailto:security@example.com"] and st.expired is True
    assert data.manifest.present and data.manifest.name == "Ex" and data.manifest.icon_count == 2
    assert data.favicon.present and data.favicon.sha256 and data.favicon.size == 4
    assert data.humans.present is False and data.humans.soft_404 is True    # HTML fallback is not humans.txt
    assert errors == []


@respx.mock
async def test_resources_missing_and_security_txt_fallback():
    respx.get("https://example.com/.well-known/security.txt").mock(return_value=httpx.Response(404))
    respx.get("https://example.com/security.txt").mock(return_value=httpx.Response(
        200, headers={"content-type": "text/plain"}, content=b"Contact: https://example.com/report\n"))
    respx.route().mock(return_value=httpx.Response(404))
    async with client() as c:
        data, _ = await ResourcesCollector("example.com", c, "https://example.com", now=NOW).collect()
    assert data.robots.present is False and data.robots.status_code == 404
    assert data.security_txt.url == "https://example.com/security.txt" and data.security_txt.present
    assert data.sitemaps[0].present is False


# ------------------------------------------------------------------ cookies & http

@pytest.mark.parametrize("header, expect", [
    ("sid=abc; Secure; HttpOnly; SameSite=Lax; Path=/", dict(secure=True, http_only=True, same_site="Lax", persistent=False)),
    ("t=1; Max-Age=3600; Domain=.Example.com", dict(max_age=3600, domain="example.com", persistent=True)),
    ("__Host-x=1; Secure; Path=/", dict(prefix="__Host-", prefix_valid=True)),
    ("__Host-y=1; Secure; Path=/; Domain=example.com", dict(prefix="__Host-", prefix_valid=False)),
    ("__Secure-z=1", dict(prefix="__Secure-", prefix_valid=False)),
])
def test_cookie_parser(header, expect):
    rec = CookieParser.parse(header, "https://example.com/")
    for key, value in expect.items():
        assert getattr(rec, key) == value, key
    assert rec.value_length == len(header.split(";")[0].split("=", 1)[1])


async def test_cookie_collector_never_keeps_values():
    probe = HttpProbe(requested_url="https://example.com/", success=True, final_url="https://example.com/",
                      final_fetched=True, set_cookies=["session=TOPSECRET; HttpOnly", "session=TOPSECRET2; HttpOnly"])
    data, _ = await CookieCollector(HttpData(probes=[probe])).collect()
    assert [c.name for c in data.cookies] == ["session"] and data.responses_inspected == 1
    assert "TOPSECRET" not in data.model_dump_json()


@respx.mock
async def test_http_collector_redacts_set_cookie_and_records_new_headers():
    respx.get(url__regex=r"https://(www\.)?example\.com/").mock(return_value=httpx.Response(200, headers=[
        ("set-cookie", "sid=VALUE1; Secure"), ("set-cookie", "pref=VALUE2"), ("cache-control", "public, max-age=60"),
        ("cross-origin-opener-policy", "same-origin"), ("access-control-allow-origin", "*")]))
    respx.get("http://example.com/").mock(return_value=httpx.Response(301, headers={"location": "https://example.com/"}))
    async with client() as c:
        data, _ = await HttpCollector("example.com", c).collect()
    probe = data.probes[1]
    assert probe.headers["set-cookie"] == ["sid=[REDACTED]; Secure", "pref=[REDACTED]"]
    assert probe.set_cookies == ["sid=VALUE1; Secure", "pref=VALUE2"]
    assert probe.cache_control == "public, max-age=60" and probe.cors == {"access-control-allow-origin": "*"}
    assert probe.security_headers["cross-origin-opener-policy"].parsed == ["same-origin"]
    assert "VALUE1" not in data.model_dump_json() and "VALUE2" not in data.model_dump_json()


def test_redact_set_cookie_without_attributes():
    assert SecurityHeaderParser.redact_set_cookie("a=b") == "a=[REDACTED]"
