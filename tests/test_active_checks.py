import datetime as dt
import json

import httpx
import pytest
import respx

from recon.active import ActiveContext, AuthorizationFile, BudgetExceeded
from recon.active.authorization import (
    ActiveScope,
    EmailEndpointTarget,
    FunctionUrlTarget,
    SupabaseTarget,
    TimeWindow,
)
from recon.active.authorization import IpTrustTarget
from recon.active.checks import (
    ClientIpHeaderTrustCheck,
    EmailEndpointRateLimitCheck,
    FunctionUrlReachabilityCheck,
    SupabaseRlsCheck,
)
from recon.utils.http_client import SafeHttpClient
from recon.utils.scope import Scope
from tests.conftest import public_resolve

NOW = dt.datetime(2026, 11, 10, 3, 0, tzinfo=dt.UTC)
WINDOW = TimeWindow(start=dt.datetime(2026, 11, 10, 0, 0, tzinfo=dt.UTC),
                    end=dt.datetime(2026, 11, 10, 6, 0, tzinfo=dt.UTC))


def auth(**kw):
    base = dict(target="app.test", authorized_by="op", authorized_on="2026-11-08", window=WINDOW,
                scope=ActiveScope(hosts=["app.test", "sb.test"]), rate_limit_rps=5.0, max_requests=100)
    base.update(kw)
    return AuthorizationFile(**base)


def context(a, **client_kw):
    client = SafeHttpClient(Scope(hosts=sorted(a.scope.normalized_hosts())), user_agent="t", retries=0,
                            resolve=public_resolve, max_redirects=0, **client_kw)
    # make rate limiting instant and deterministic in tests
    ctx = ActiveContext(a, client, clock=lambda: 0.0, sleep=_noop_sleep())
    return ctx, client


def _noop_sleep():
    async def sleep(_):
        return None
    return sleep


# ------------------------------------------------------------------ budget / rate

async def test_budget_is_enforced_by_context_not_the_check():
    a = auth(max_requests=3, max_requests_per_check=2)
    ctx, client = context(a)
    with respx.mock:
        respx.get(url__startswith="https://app.test/").mock(return_value=httpx.Response(200))
        async with client:
            assert await ctx.request("c1", "GET", "https://app.test/1") is not None
            assert await ctx.request("c1", "GET", "https://app.test/2") is not None
            with pytest.raises(BudgetExceeded, match="per-check"):
                await ctx.request("c1", "GET", "https://app.test/3")
            # a different check can still use the remaining engagement budget (1 left)
            assert await ctx.request("c2", "GET", "https://app.test/4") is not None
            with pytest.raises(BudgetExceeded, match="engagement"):
                await ctx.request("c2", "GET", "https://app.test/5")
    assert ctx.requests_made == 3 and len(ctx.request_log) == 3


async def test_out_of_scope_request_is_blocked_and_logged():
    ctx, client = context(auth())
    with respx.mock:
        evil = respx.get("https://evil.test/").mock(return_value=httpx.Response(200))
        async with client:
            assert await ctx.request("c", "GET", "https://evil.test/") is None
    assert not evil.called and ctx.request_log[-1].note.startswith("blocked")
    assert ctx.requests_made == 1   # a blocked attempt still spends budget (can't retry around it)


# ------------------------------------------------------------------ supabase RLS

def sb_auth(tables, key="eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.sig"):
    return auth(scope=ActiveScope(hosts=["sb.test"]),
                supabase=SupabaseTarget(host="sb.test", anon_key=key, tables=tables))


async def test_supabase_rls_flags_readable_table_only():
    a = sb_auth(["open_table", "locked_table", "empty_table"])
    ctx, client = context(a)
    with respx.mock:
        respx.get(url__startswith="https://sb.test/rest/v1/open_table").mock(
            return_value=httpx.Response(200, content=json.dumps([{"id": 1}]).encode()))
        respx.get(url__startswith="https://sb.test/rest/v1/locked_table").mock(
            return_value=httpx.Response(401, content=b'{"message":"permission denied"}'))
        respx.get(url__startswith="https://sb.test/rest/v1/empty_table").mock(
            return_value=httpx.Response(200, content=b"[]"))
        async with client:
            result = await SupabaseRlsCheck().run(ctx)
    assert result.requests_made == 3                       # one per table, no pagination
    ids = {f.id for f in result.findings}
    assert "active.supabase_rls_open:sb.test/open_table" in ids
    assert len(result.findings) == 1                       # locked (401) and empty produce no finding
    assert "eyJyb2xlIjoiYW5vbiJ9" not in result.model_dump_json()   # anon key redacted in evidence


def test_supabase_rls_skips_without_config():
    assert SupabaseRlsCheck().prerequisites(auth()) is not None
    assert SupabaseRlsCheck().prerequisites(sb_auth([])) is not None             # no tables
    assert SupabaseRlsCheck().prerequisites(sb_auth(["t"])) is None


# ------------------------------------------------------------------ function URLs

async def test_function_url_reachability_classifies_auth_posture():
    a = auth(function_urls=[
        FunctionUrlTarget(url="https://app.test/open", method="GET", state_changing=True),
        FunctionUrlTarget(url="https://app.test/protected", method="GET"),
        FunctionUrlTarget(url="https://app.test/public-read", method="GET"),
        FunctionUrlTarget(url="https://evil.test/x", method="GET"),   # out of scope → never sent
    ])
    ctx, client = context(a)
    with respx.mock:
        respx.get("https://app.test/open").mock(return_value=httpx.Response(200))
        respx.get("https://app.test/protected").mock(return_value=httpx.Response(403))
        respx.get("https://app.test/public-read").mock(return_value=httpx.Response(200))
        evil = respx.get("https://evil.test/x").mock(return_value=httpx.Response(200))
        async with client:
            result = await FunctionUrlReachabilityCheck().run(ctx)
    assert not evil.called and result.requests_made == 3
    by = {f.id.split(":")[0]: f for f in result.findings}
    assert by["active.endpoint_open"].severity.value == "high"        # state-changing + reachable
    assert by["active.endpoint_reachable"].severity.value == "informational"
    assert not any("protected" in f.subject for f in result.findings)  # 403 → no finding


async def test_client_ip_header_trust_flags_allowlist_bypass():
    # baseline 403, but 200 once X-Forwarded-For is set → access control trusts the header
    a = auth(ip_trust_endpoints=[IpTrustTarget(url="https://app.test/admin", method="GET")])
    ctx, client = context(a)
    with respx.mock:
        route = respx.get("https://app.test/admin")
        route.side_effect = [httpx.Response(403), httpx.Response(200), httpx.Response(200)]
        async with client:
            result = await ClientIpHeaderTrustCheck().run(ctx)
    assert result.requests_made == 3                      # baseline + 2 spoofed-IP variants
    assert result.findings[0].id.startswith("active.client_ip_header_bypass")
    assert result.findings[0].severity.value == "high"
    # the spoof headers were actually sent on the follow-ups, not the baseline
    assert "x-forwarded-for" not in {k.lower() for k in route.calls[0].request.headers}
    assert route.calls[1].request.headers["x-forwarded-for"] == "127.0.0.1"
    assert route.calls[1].request.headers["forwarded"] == "for=127.0.0.1"


async def test_client_ip_header_trust_no_finding_when_stable():
    # not labeled access_control: a stable 200 across baseline + spoofs yields nothing
    a = auth(ip_trust_endpoints=[IpTrustTarget(url="https://app.test/api", method="GET")])
    ctx, client = context(a)
    with respx.mock:
        respx.get("https://app.test/api").mock(return_value=httpx.Response(200))
        async with client:
            result = await ClientIpHeaderTrustCheck().run(ctx)
    assert result.requests_made == 3 and result.findings == []   # same status → not trusted for the decision


async def test_client_ip_trust_flags_baseline_reachable_access_control_endpoint():
    # access_control endpoint that already answers 200 with NO spoofing is the finding (no silent miss)
    a = auth(ip_trust_endpoints=[IpTrustTarget(url="https://app.test/admin", access_control=True)])
    ctx, client = context(a)
    with respx.mock:
        respx.get("https://app.test/admin").mock(return_value=httpx.Response(200))
        async with client:
            result = await ClientIpHeaderTrustCheck().run(ctx)
    assert [f.id.split(":")[0] for f in result.findings] == ["active.access_control_open"]
    assert result.findings[0].severity.value == "high" and result.findings[0].recommendation


async def test_client_ip_header_trust_low_when_non_access_change():
    # status changes but baseline wasn't an access/rate denial and endpoint not labeled access_control
    a = auth(ip_trust_endpoints=[IpTrustTarget(url="https://app.test/page", method="GET")])
    ctx, client = context(a)
    with respx.mock:
        route = respx.get("https://app.test/page")
        route.side_effect = [httpx.Response(200), httpx.Response(302), httpx.Response(200)]
        async with client:
            result = await ClientIpHeaderTrustCheck().run(ctx)
    assert result.findings[0].id.startswith("active.client_ip_header_trusted")
    assert result.findings[0].severity.value == "low"


def test_client_ip_header_trust_requires_in_scope_endpoint():
    check = ClientIpHeaderTrustCheck()
    assert check.prerequisites(auth()) is not None
    assert check.prerequisites(auth(ip_trust_endpoints=[IpTrustTarget(url="https://evil.test/x")])) is not None
    assert check.prerequisites(auth(ip_trust_endpoints=[IpTrustTarget(url="https://app.test/x")])) is None


async def test_function_url_never_sends_body_on_get():
    a = auth(function_urls=[FunctionUrlTarget(url="https://app.test/x", method="GET")])
    ctx, client = context(a)
    with respx.mock:
        route = respx.get("https://app.test/x").mock(return_value=httpx.Response(200))
        async with client:
            await FunctionUrlReachabilityCheck().run(ctx)
    assert route.calls.last.request.content == b""


# ------------------------------------------------------------------ email rate limit

def email_auth(confirmed, burst=5, payload=None):
    return auth(email_endpoints=[EmailEndpointTarget(
        url="https://app.test/api/notify", method="POST", burst=burst, test_payload=payload,
        confirmed_no_real_delivery=confirmed)])


async def test_email_rate_limit_requires_explicit_confirmation():
    check = EmailEndpointRateLimitCheck()
    assert check.prerequisites(email_auth(False)) is not None          # not confirmed → skipped entirely
    assert "confirmed_no_real_delivery" in check.prerequisites(email_auth(False))
    assert check.prerequisites(email_auth(True)) is None


async def test_email_rate_limit_flags_missing_throttle_and_caps_burst():
    a = email_auth(True, burst=20)                                     # requests 20, but model caps to 10
    ctx, client = context(a)
    with respx.mock:
        route = respx.post("https://app.test/api/notify").mock(return_value=httpx.Response(200))
        async with client:
            result = await EmailEndpointRateLimitCheck().run(ctx)
    assert route.call_count == 10 and result.requests_made == 10       # hard cap enforced
    assert [f.id.split(":")[0] for f in result.findings] == ["active.no_rate_limit"]
    assert result.findings[0].severity.value == "medium"
    assert route.calls.last.request.headers["X-SiteRecon-Test"] == "rate-limit-probe"


async def test_email_rate_limit_no_finding_when_throttled():
    a = email_auth(True, burst=5)
    ctx, client = context(a)
    with respx.mock:
        respx.post("https://app.test/api/notify").mock(side_effect=[
            httpx.Response(200), httpx.Response(200), httpx.Response(429),
            httpx.Response(429), httpx.Response(429)])
        async with client:
            result = await EmailEndpointRateLimitCheck().run(ctx)
    assert result.findings == []                                       # throttling observed → good


async def test_email_rate_limit_inconclusive_on_partial_burst():
    # some requests fail at transport, so the full burst was never observed accepted → no finding
    a = email_auth(True, burst=5)
    ctx, client = context(a)
    with respx.mock:
        respx.post("https://app.test/api/notify").mock(side_effect=[
            httpx.Response(200), httpx.ConnectError("x"), httpx.Response(200),
            httpx.Response(200), httpx.ConnectError("x")])
        async with client:
            result = await EmailEndpointRateLimitCheck().run(ctx)
    assert result.findings == []                                       # 3/5 returned → inconclusive, not flagged


async def test_email_rate_limit_skips_unconfirmed_endpoint_even_if_run_directly():
    a = email_auth(False, burst=5)
    ctx, client = context(a)
    with respx.mock:
        route = respx.post("https://app.test/api/notify").mock(return_value=httpx.Response(200))
        async with client:
            result = await EmailEndpointRateLimitCheck().run(ctx)
    assert not route.called and result.requests_made == 0             # belt-and-suspenders: run() re-checks
