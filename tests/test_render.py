import asyncio
import datetime as dt
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from recon.models import RenderedPage, RenderRequest
from recon.modules.render import Renderer

SUPA = "ref0abcdef0123456789.supabase.co"


# ------------------------------------------------------------------ pure build (no browser)

def _reqs(*triples):
    return [RenderRequest(method=m, url=u, resource_type=t) for m, u, t in triples]


def _build(*, requests=(), htmls=(), pages=None, hostname="app.test", retain=False):
    pages = pages if pages is not None else [RenderedPage(url="https://app.test/")]
    return Renderer._build(pages=pages, requests=list(requests), htmls=list(htmls),
                           console_errors=[], hostname=hostname, retain=retain)


def test_runtime_api_calls_become_endpoints():
    # the signal the static path misses: real xhr/fetch calls the running app made
    data = _build(requests=_reqs(("POST", f"https://{SUPA}/rest/v1/orders", "fetch"),
                                 ("GET", "https://app.test/api/me", "xhr"),
                                 ("GET", "https://cdn.test/logo.png", "image")))   # non-API → not an endpoint
    eps = {e.value: e for e in data.endpoints}
    assert f"https://{SUPA}/rest/v1/orders" in eps and eps[f"https://{SUPA}/rest/v1/orders"].method == "POST"
    assert "https://app.test/api/me" in eps and eps["https://app.test/api/me"].same_site is True
    assert not any("logo.png" in v for v in eps)                 # image request is not an endpoint
    assert data.request_count == 3                               # but it stays in the full inventory
    assert SUPA in data.hosts_contacted and "cdn.test" in data.hosts_contacted


def test_dom_endpoints_are_focused_on_api_routes():
    # API-ish routes in the rendered DOM are kept; static assets and plain page links are not
    html = ('<html><body><script>fetch("/api/v1/profile");const u="https://x.test/graphql";</script>'
            '<a href="/about">about</a><img src="https://cdn.test/hero.png"></body></html>')
    data = _build(htmls=[html])
    values = {e.value for e in data.endpoints}
    assert any("/api/v1/profile" in v for v in values)
    assert any("graphql" in v for v in values)
    assert not any("/about" in v for v in values)                # plain page link → not an API route
    assert not any("hero.png" in v for v in values)              # static asset → dropped


def test_client_config_is_read_from_the_rendered_dom():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.s1gnatureAbcdef0123"
    html = f'<script>const url="https://{SUPA}";const key="{jwt}";</script>'
    data = _build(htmls=[html])
    assert any(c.kind == "supabase" for c in data.client_configs)


def test_multiple_pages_are_aggregated():
    data = _build(
        pages=[RenderedPage(url="https://app.test/", request_count=2),
               RenderedPage(url="https://app.test/dashboard", request_count=1)],
        requests=_reqs(("GET", "https://app.test/api/a", "fetch"),
                       ("GET", "https://app.test/api/b", "xhr")))
    assert data.pages_rendered == 2 and len(data.pages) == 2
    assert {e.value for e in data.endpoints} == {"https://app.test/api/a", "https://app.test/api/b"}


def test_missing_playwright_is_a_clean_error(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "playwright.async_api":
            raise ImportError("no playwright")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    data, errors = asyncio.run(Renderer(["https://app.test/"], "app.test").collect())
    assert data is None and errors and errors[0].error_type == "playwright_missing"


# ------------------------------------------------------------------ live browser (skipped if unavailable)

def _chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):   # noqa: N802
        body = (b'<html><body><div id="app"></div>'
                b'<script>fetch("/api/runtime-only").then(()=>{});'
                b'document.getElementById("app").innerHTML="<a href=/dashboard>go</a>";</script>'
                b'</body></html>')
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):   # silence
        pass


@pytest.mark.skipif(not _chromium_available(), reason="Playwright Chromium not installed")
def test_live_render_captures_a_runtime_fetch():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        data, errors = asyncio.run(
            Renderer([f"http://127.0.0.1:{port}/"], "127.0.0.1", timeout=15.0).collect())
    finally:
        server.shutdown()
    assert not errors, errors
    assert data is not None and data.pages_rendered == 1
    # the /api/runtime-only call exists only after JS runs — static parsing of the shipped HTML would miss it
    assert any("/api/runtime-only" in e.value for e in data.endpoints)


# ------------------------------------------------------------------ analysis (render → findings)

def test_render_findings_flag_third_party_egress_and_mixed_content():
    from recon.analysis.engine import AnalysisEngine
    from recon.analysis.findings import FindingCollector
    from recon.models import RenderData

    data = RenderData(
        pages=[RenderedPage(url="https://app.test/")],
        hosts_contacted=["app.test", "www.google-analytics.com", "api.stripe.com"],
        requests=_reqs(("GET", "http://cdn.evil.test/pixel.gif", "image"),
                       ("GET", "https://app.test/api/x", "fetch")))
    f = FindingCollector(dt.datetime(2026, 11, 18, tzinfo=dt.UTC))
    AnalysisEngine._analyze_render(data, "app.test", f)
    codes = {x.id.split(":", 1)[0] for x in f.sorted()}
    assert "render.third_party_egress" in codes      # GA + stripe are off-domain
    assert "render.mixed_content" in codes           # https page fetched http://cdn.evil.test
    egress = next(x for x in f.sorted() if x.id.startswith("render.third_party_egress"))
    assert "google-analytics" in egress.evidence[0] and "app.test" not in egress.evidence[0].split(": ", 1)[1]


def test_render_findings_quiet_when_all_first_party_and_https():
    from recon.analysis.engine import AnalysisEngine
    from recon.analysis.findings import FindingCollector
    from recon.models import RenderData

    data = RenderData(pages=[RenderedPage(url="https://app.test/")], hosts_contacted=["app.test", "cdn.app.test"],
                      requests=_reqs(("GET", "https://app.test/api/x", "fetch")))
    f = FindingCollector(dt.datetime(2026, 11, 18, tzinfo=dt.UTC))
    AnalysisEngine._analyze_render(data, "app.test", f)
    assert f.sorted() == []
