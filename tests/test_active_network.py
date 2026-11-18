import datetime as dt
import socket

import pytest
from pydantic import ValidationError

from recon.active import ActiveContext, AuthorizationFile, redact_authorization
from recon.active.authorization import ActiveScope, PortScanTarget, TimeWindow, TracerouteTarget
from recon.active.checks import PortScanCheck, TracerouteCheck
from recon.utils.http_client import SafeHttpClient
from recon.utils.scope import Scope
from tests.conftest import public_resolve

WINDOW = TimeWindow(start=dt.datetime(2026, 11, 15, 0, 0, tzinfo=dt.UTC),
                    end=dt.datetime(2026, 11, 15, 23, 0, tzinfo=dt.UTC))


def auth(**kw):
    base = dict(target="app.test", authorized_by="op", authorized_on="2026-11-15", window=WINDOW,
                scope=ActiveScope(hosts=["app.test"]), rate_limit_rps=5.0, max_requests=100)
    base.update(kw)
    return AuthorizationFile(**base)


def context(a):
    client = SafeHttpClient(Scope(hosts=sorted(a.scope.normalized_hosts())), user_agent="t", retries=0,
                            resolve=public_resolve)

    async def _noop(_):
        return None

    return ActiveContext(a, client, clock=lambda: 0.0, sleep=_noop)


# ------------------------------------------------------------------ authorization

def test_resolved_ports_merges_explicit_and_profile():
    t = PortScanTarget(host="h", ports=[443, 22, 22], profile="web")
    assert t.resolved_ports() == [22, 80, 443, 8080, 8443]


def test_unknown_profile_and_oversized_port_list_rejected():
    with pytest.raises(ValidationError, match="unknown port profile"):
        PortScanTarget(host="h", profile="nope")
    with pytest.raises(ValidationError, match="1024 ports"):
        PortScanTarget(host="h", ports=list(range(1, 1030)))


def test_traceroute_hops_capped():
    assert TracerouteTarget(host="h", max_hops=99).max_hops == 30


def test_redaction_includes_network_targets():
    a = auth(port_scan_targets=[PortScanTarget(host="app.test", ports=[443], profile="web")],
             traceroute_targets=[TracerouteTarget(host="app.test", max_hops=10)])
    summary = redact_authorization(a)
    assert summary["port_scan_targets"][0]["ports"] == [80, 443, 8080, 8443]
    assert summary["traceroute_targets"][0]["max_hops"] == 10


# ------------------------------------------------------------------ port scan

async def test_port_scan_flags_open_and_sensitive_ports(monkeypatch):
    a = auth(port_scan_targets=[PortScanTarget(host="app.test", ports=[443, 22, 9999])])

    async def resolve(host):
        return "203.0.113.9", ["203.0.113.9"]

    async def connect(self, ip, port):
        return {443: "open", 22: "open"}.get(port, "closed")

    monkeypatch.setattr(PortScanCheck, "_resolve_public", staticmethod(resolve))
    monkeypatch.setattr(PortScanCheck, "_connect", connect)
    ctx = context(a)
    result = await PortScanCheck().run(ctx)
    assert result.requests_made == 3                              # one connect per listed port
    ids = {f.id.split(":")[0] for f in result.findings}
    assert "active.open_ports" in ids and "active.sensitive_port_exposed" in ids
    openf = next(f for f in result.findings if f.id.startswith("active.open_ports"))
    assert "443/https" in openf.evidence[0] and "22/ssh" in openf.evidence[0]
    assert any("203.0.113.9" in e for e in openf.evidence)        # records which address was scanned
    sens = next(f for f in result.findings if f.id.startswith("active.sensitive_port_exposed"))
    assert sens.severity.value == "medium" and "22 (SSH)" in sens.evidence[0]
    # audit log: one row per connection, and it matches the reported request count
    assert len([e for e in ctx.request_log if e.method == "TCP"]) == 3
    assert len(ctx.request_log) == ctx.requests_made


async def test_port_scan_labels_multi_address_hosts(monkeypatch):
    # a host fronting several public IPs (CDN/proxy) — the finding says which one was scanned and warns
    a = auth(port_scan_targets=[PortScanTarget(host="app.test", ports=[443])])

    async def resolve(host):
        return "203.0.113.9", ["203.0.113.9", "203.0.113.10"]

    async def connect(self, ip, port):
        return "open"

    monkeypatch.setattr(PortScanCheck, "_resolve_public", staticmethod(resolve))
    monkeypatch.setattr(PortScanCheck, "_connect", connect)
    result = await PortScanCheck().run(context(a))
    openf = next(f for f in result.findings if f.id.startswith("active.open_ports"))
    blob = " ".join(openf.evidence)
    assert "203.0.113.9" in blob and "2 public addresses" in blob and "edge" in blob


async def test_port_scan_no_open_ports_no_finding(monkeypatch):
    a = auth(port_scan_targets=[PortScanTarget(host="app.test", ports=[80, 443])])

    async def resolve(host):
        return "203.0.113.9", ["203.0.113.9"]

    async def connect(self, ip, port):
        return "filtered"

    monkeypatch.setattr(PortScanCheck, "_resolve_public", staticmethod(resolve))
    monkeypatch.setattr(PortScanCheck, "_connect", connect)
    result = await PortScanCheck().run(context(a))
    assert result.findings == [] and result.requests_made == 2


async def test_port_scan_budget_stops_the_scan_and_surfaces_it(monkeypatch):
    a = auth(max_requests=2, port_scan_targets=[PortScanTarget(host="app.test", ports=[80, 443, 22, 8080])])

    async def resolve(host):
        return "203.0.113.9", ["203.0.113.9"]

    async def connect(self, ip, port):
        return "closed"

    monkeypatch.setattr(PortScanCheck, "_resolve_public", staticmethod(resolve))
    monkeypatch.setattr(PortScanCheck, "_connect", connect)
    result = await PortScanCheck().run(context(a))   # budget cuts it off at 2 of 4 ports
    assert result.requests_made == 2 and result.status.value == "partial"
    assert any(e.error_type == "budget_exceeded" for e in result.errors)
    # the truncation is surfaced in a finding, not only in the error list
    inc = next(f for f in result.findings if f.id.startswith("active.port_scan_incomplete"))
    assert "incomplete" in " ".join(inc.evidence).lower()


async def test_connect_classifies_open_and_closed():
    srv = socket.create_server(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    try:
        check = PortScanCheck(timeout=1.0)
        assert await check._connect("127.0.0.1", port) == "open"
        assert await check._connect("127.0.0.1", 1) == "closed"
    finally:
        srv.close()


async def test_resolve_public_rejects_non_public_address():
    # a host resolving only to loopback/private space yields no scannable address (SSRF guard)
    vetted, public = await PortScanCheck(timeout=1.0)._resolve_public("127.0.0.1")
    assert vetted is None and public == []


def test_port_scan_prerequisites():
    assert PortScanCheck().prerequisites(auth()) is not None                       # no targets
    assert PortScanCheck().prerequisites(
        auth(port_scan_targets=[PortScanTarget(host="evil.test", ports=[80])])) is not None   # out of scope
    assert PortScanCheck().prerequisites(
        auth(port_scan_targets=[PortScanTarget(host="app.test", ports=[80])])) is None


# ------------------------------------------------------------------ traceroute

async def test_traceroute_produces_a_path_finding(monkeypatch):
    a = auth(traceroute_targets=[TracerouteTarget(host="app.test", max_hops=5)])

    async def vetted(host):
        return "203.0.113.9"

    async def trace(self, ip, max_hops):
        return ["1  10.0.0.1  1.2 ms", "2  203.0.113.1  8.0 ms"]

    monkeypatch.setattr(TracerouteCheck, "_vetted_ip", staticmethod(vetted))
    monkeypatch.setattr(TracerouteCheck, "_trace", trace)
    ctx = context(a)
    result = await TracerouteCheck().run(ctx)
    assert result.requests_made == 1 and len([e for e in ctx.request_log if e.method == "TRACE"]) == 1
    f = next(f for f in result.findings if f.id.startswith("active.network_path"))
    assert f.severity.value == "informational" and "203.0.113.1" in " ".join(f.evidence)
    assert f.recommendation and f.limitations


async def test_traceroute_unavailable_binary_is_an_error_not_a_crash(monkeypatch):
    a = auth(traceroute_targets=[TracerouteTarget(host="app.test")])

    async def vetted(host):
        return "203.0.113.9"

    async def trace(self, ip, max_hops):
        return None   # binary missing / failed

    monkeypatch.setattr(TracerouteCheck, "_vetted_ip", staticmethod(vetted))
    monkeypatch.setattr(TracerouteCheck, "_trace", trace)
    result = await TracerouteCheck().run(context(a))
    assert result.findings == [] and result.status.value == "partial"
    assert any(e.error_type == "traceroute_unavailable" for e in result.errors)


async def test_traceroute_blocks_non_public_target(monkeypatch):
    a = auth(traceroute_targets=[TracerouteTarget(host="app.test")])

    async def vetted(host):
        return None   # resolves only to private/blocked space

    monkeypatch.setattr(TracerouteCheck, "_vetted_ip", staticmethod(vetted))
    result = await TracerouteCheck().run(context(a))
    assert result.findings == [] and any(e.error_type == "blocked_address" for e in result.errors)


def test_traceroute_prerequisites():
    assert TracerouteCheck().prerequisites(auth()) is not None
    assert TracerouteCheck().prerequisites(
        auth(traceroute_targets=[TracerouteTarget(host="app.test")])) is None
