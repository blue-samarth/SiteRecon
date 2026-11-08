import httpx
import pytest
import respx

from recon.modules import HttpCollector, SecurityHeaderParser
from recon.utils.http_client import SafeHttpClient
from recon.utils.scope import Scope
from tests.conftest import public_resolve


def make_client(resolve=public_resolve, **kw) -> SafeHttpClient:
    return SafeHttpClient(Scope.for_target("example.com"), user_agent="test", retries=kw.pop("retries", 0),
                          resolve=resolve, **kw)


@respx.mock
async def test_redirect_chain_and_security_headers():
    respx.get("http://example.com/").mock(return_value=httpx.Response(301, headers={"Location": "https://example.com/"}))
    respx.get("https://example.com/").mock(return_value=httpx.Response(200, headers={
        "Server": "nginx", "Content-Type": "text/html",
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'; script-src 'self' cdn.example.net",
        "X-Content-Type-Options": "nosniff",
    }, content=b"<html>hi</html>"))
    respx.get("https://www.example.com/").mock(return_value=httpx.Response(308, headers={"Location": "/"}))
    # www → "/" on www, which then 200s
    async with make_client() as c:
        data, errors = await HttpCollector("example.com", c).collect()

    http_probe, https_probe, www_probe = data.probes
    assert errors == []
    assert http_probe.redirect_count == 1 and http_probe.redirects_to_https is True
    assert [h.status_code for h in http_probe.hops] == [301, 200]
    assert http_probe.hops[0].location == "https://example.com/"
    assert https_probe.final_url == "https://example.com/" and https_probe.server == "nginx"
    sh = https_probe.security_headers
    assert sh["strict-transport-security"].parsed == {"max-age": 63072000, "includesubdomains": True, "preload": True}
    assert sh["content-security-policy"].parsed["script-src"] == ["'self'", "cdn.example.net"]
    assert sh["x-frame-options"].present is False
    assert https_probe.body_bytes == len(b"<html>hi</html>")
    # www redirected to itself → loop detection
    assert www_probe.redirect_stopped_reason == "redirect_loop"


@respx.mock
async def test_out_of_scope_redirect_is_recorded_not_followed():
    respx.get("https://example.com/").mock(return_value=httpx.Response(302, headers={"Location": "https://evil.test/x"}))
    evil = respx.get("https://evil.test/x").mock(return_value=httpx.Response(200))
    async with make_client() as c:
        outcome = await c.fetch("https://example.com/")
    assert not evil.called
    probe = HttpCollector.build_probe(outcome)
    assert probe.success and not probe.final_fetched
    assert probe.redirect_stopped_reason == "out_of_scope"
    assert probe.final_url == "https://evil.test/x"


@respx.mock
async def test_private_address_is_blocked():
    route = respx.get("https://example.com/").mock(return_value=httpx.Response(200))

    async def resolve_metadata(host, port):
        return ["169.254.169.254"]

    async with make_client(resolve=resolve_metadata) as c:
        outcome = await c.fetch("https://example.com/")
    assert not route.called
    assert outcome.error_type == "blocked_address"


@respx.mock
async def test_redirect_to_internal_host_in_scope_is_blocked():
    respx.get("https://example.com/").mock(return_value=httpx.Response(302, headers={"Location": "http://internal.example.com/"}))
    internal = respx.get("http://internal.example.com/").mock(return_value=httpx.Response(200))

    async def resolve(host, port):
        return ["10.0.0.8"] if host.startswith("internal") else ["93.184.216.34"]

    async with make_client(resolve=resolve) as c:
        outcome = await c.fetch("https://example.com/")
    assert not internal.called
    assert outcome.stopped_reason == "blocked_address"


@respx.mock
async def test_transient_errors_are_retried():
    route = respx.get("https://example.com/").mock(side_effect=[
        httpx.ConnectTimeout("t"), httpx.Response(503), httpx.Response(200, content=b"ok"),
    ])
    async with make_client(retries=2) as c:
        resp = await c.get("https://example.com/")
    assert resp.status_code == 200 and route.call_count == 3


@respx.mock
async def test_retries_exhausted_reports_error():
    route = respx.route().mock(side_effect=httpx.ConnectTimeout("t"))
    async with make_client(retries=1) as c:
        data, errors = await HttpCollector("example.com", c).collect()
    assert all(not p.success for p in data.probes)
    assert len(errors) == 3 and {e.error_type for e in errors} == {"ConnectTimeout"}
    assert route.call_count == 6  # 3 URLs × (1 try + 1 retry)


@respx.mock
async def test_response_size_limit():
    respx.get("https://example.com/").mock(return_value=httpx.Response(200, content=b"x" * 5000))
    async with make_client(max_response_bytes=1000) as c:
        resp = await c.get("https://example.com/")
    assert len(resp.body) == 1000 and resp.truncated


async def test_unsupported_scheme_blocked():
    async with make_client() as c:
        outcome = await c.fetch("file:///etc/passwd")
    assert outcome.error_type == "unsupported_scheme"


@pytest.mark.parametrize("value, expected", [
    ("max-age=300", {"max-age": 300}),
    ('max-age="31536000"; includeSubDomains', {"max-age": 31536000, "includesubdomains": True}),
    ("includeSubDomains", {"includesubdomains": True}),
    ("max-age=abc", {"max-age": None}),
])
def test_parse_hsts(value, expected):
    assert SecurityHeaderParser.parse_hsts(value) == expected


def test_parse_csp_merges_multiple_policies():
    parsed = SecurityHeaderParser.parse_csp("default-src 'self'; img-src *, frame-ancestors 'none'")
    assert parsed == {"default-src": ["'self'"], "img-src": ["*"], "frame-ancestors": ["'none'"]}
