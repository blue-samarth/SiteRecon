import datetime as dt
import socket
import ssl
import threading

import httpx
import pytest
import respx

from recon.active import ActiveOrchestrator, AuthorizationFile
from recon.active.authorization import ActiveScope, SupabaseTarget, TimeWindow
from recon.active.checks import TlsProtocolEnumCheck
from recon.active.context import ActiveContext
from recon.models import ModuleStatus
from recon.reporting import ActiveHtmlReportWriter, ActiveJsonReportWriter, ActiveMarkdownReportWriter
from recon.utils.http_client import SafeHttpClient
from recon.utils.scope import Scope
from tests.conftest import make_cert, public_resolve

NOW = dt.datetime(2026, 11, 10, 3, 0, tzinfo=dt.UTC)
WINDOW = TimeWindow(start=dt.datetime(2026, 11, 10, 0, 0, tzinfo=dt.UTC),
                    end=dt.datetime(2026, 11, 10, 6, 0, tzinfo=dt.UTC))


def auth(**kw):
    base = dict(target="app.test", authorized_by="op", authorized_on="2026-11-08", window=WINDOW,
                scope=ActiveScope(hosts=["app.test"]), rate_limit_rps=5.0, max_requests=100)
    base.update(kw)
    return AuthorizationFile(**base)


# ------------------------------------------------------------------ TLS enumeration (real local server)

@pytest.fixture
def tls_server(cert_files):
    """A local TLS 1.2-max server (no 1.3), so enumeration sees a bounded version set."""
    cert_path, key_path = cert_files
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    srv = socket.create_server(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except TimeoutError:
                continue
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(16)
            except (ssl.SSLError, OSError):
                pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield port
    stop.set()
    t.join(timeout=2)
    srv.close()


async def test_tls_enum_detects_accepted_version(tls_server, monkeypatch):
    monkeypatch.setattr(TlsProtocolEnumCheck, "VERSIONS",
                        (("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3)))
    a = auth(scope=ActiveScope(hosts=[f"127.0.0.1:{tls_server}"]))
    # scope stores host only; the check connects on 443, so target the loopback host directly.
    a.scope = ActiveScope(hosts=["127.0.0.1"], tls_authorized_hosts=["127.0.0.1"])
    client = SafeHttpClient(Scope(hosts=["127.0.0.1"]), user_agent="t", retries=0, resolve=public_resolve,
                            allow_private_networks=True)
    ctx = ActiveContext(a, client, clock=lambda: 0.0, sleep=_noop())

    check = TlsProtocolEnumCheck(timeout=3)
    # redirect the real connection to the ephemeral loopback port, keeping the version-pinned context
    orig = check._handshake

    async def handshake(host, ssl_ctx):
        return await _handshake_port(host, tls_server, ssl_ctx, 3)

    check._handshake = handshake  # type: ignore[method-assign]
    async with client:
        result = await check.run(ctx)
    assert result.requests_made == 2                 # one handshake attempt per client-supported version
    # TLS 1.2 accepted, 1.3 refused → informational tls_versions finding, no legacy finding
    ids = {f.id.split(":")[0] for f in result.findings}
    assert "active.tls_versions" in ids and "active.legacy_tls_accepted" not in ids
    assert orig is not handshake
    # every handshake is written to the audit log (point: audit log must not drop handshakes)
    tls_log = [e for e in ctx.request_log if e.method == "TLS"]
    assert len(tls_log) == 2 and len(ctx.request_log) == ctx.requests_made
    # evidence shows attempted-vs-accepted, not just the accepted version
    finding = next(f for f in result.findings if f.id.startswith("active.tls_versions"))
    assert any("TLSv1.2: accepted" in e for e in finding.evidence)
    assert any("TLSv1.3: offered, rejected" in e for e in finding.evidence)
    assert finding.recommendation and finding.limitations   # active findings carry recommendation text


def test_tls_enum_requires_per_host_opt_in():
    a = auth(scope=ActiveScope(hosts=["app.test"]))        # in scope, but NOT tls_authorized
    assert TlsProtocolEnumCheck().prerequisites(a) is not None
    a2 = auth(scope=ActiveScope(hosts=["app.test"], tls_authorized_hosts=["app.test"]))
    assert TlsProtocolEnumCheck().prerequisites(a2) is None


async def test_tls_enum_spends_no_budget_on_client_unsupported_versions(monkeypatch):
    # if the local OpenSSL cannot offer a version, no connection is made and no budget is spent
    a = auth(scope=ActiveScope(hosts=["app.test"], tls_authorized_hosts=["app.test"]), max_requests=100)
    client = SafeHttpClient(Scope(hosts=["app.test"]), user_agent="t", retries=0, resolve=public_resolve)
    ctx = ActiveContext(a, client, clock=lambda: 0.0, sleep=_noop())
    monkeypatch.setattr(TlsProtocolEnumCheck, "_client_context", staticmethod(lambda version: None))

    connected = False

    async def never(host, ssl_ctx):   # pragma: no cover - must not be called
        nonlocal connected
        connected = True
        return "x"

    check = TlsProtocolEnumCheck()
    check._handshake = never  # type: ignore[method-assign]
    async with client:
        result = await check.run(ctx)
    assert result.requests_made == 0 and ctx.requests_made == 0 and not connected
    assert result.findings == [] and result.status is ModuleStatus.SUCCESS


# ------------------------------------------------------------------ orchestrator

async def test_empty_registry_run_produces_valid_empty_report():
    a = auth(checks_enabled=[])
    report = await ActiveOrchestrator(a, now=NOW).run()
    assert report.checks == [] and report.requests_made == 0 and report.window_ok
    assert report.scan_id and report.target.hostname == "app.test"
    assert "ACTIVE TESTING" in report.notice


async def test_orchestrator_skips_unready_and_unknown_checks():
    a = auth(checks_enabled=["backend_read_access", "bogus_check", "tls_protocol_enum"])
    report = await ActiveOrchestrator(a, now=NOW).run()
    by = {c.check_id: c for c in report.checks}
    assert by["backend_read_access"].status is ModuleStatus.SKIPPED and "backends" in by["backend_read_access"].skipped_reason
    assert by["bogus_check"].status is ModuleStatus.SKIPPED and "unknown" in by["bogus_check"].skipped_reason
    assert by["tls_protocol_enum"].status is ModuleStatus.SKIPPED   # no tls_authorized host
    assert report.requests_made == 0


async def test_orchestrator_isolates_check_exceptions(monkeypatch):
    a = auth(checks_enabled=["supabase_rls"],
             supabase=SupabaseTarget(host="app.test", anon_key="eyJ0.eyJyb2xlIjoiYW5vbiJ9.s", tables=["t"]))

    async def boom(self, ctx):
        raise RuntimeError("check blew up")

    monkeypatch.setattr("recon.active.checks.SupabaseRlsCheck.run", boom)
    report = await ActiveOrchestrator(a, now=NOW).run()
    assert report.checks[0].status is ModuleStatus.FAILED
    assert report.checks[0].errors[0].message == "check blew up"


async def test_orchestrator_plan_is_pure():
    a = auth(checks_enabled=["backend_read_access", "tls_protocol_enum"])
    plan = dict(ActiveOrchestrator(a, now=NOW).plan())
    assert plan["backend_read_access"] is not None and plan["tls_protocol_enum"] is not None   # both would skip


async def test_run_through_a_registered_check_end_to_end():
    a = auth(checks_enabled=["function_url_reachability"],
             function_urls=[{"url": "https://app.test/fn", "method": "GET", "state_changing": True}])
    client = SafeHttpClient(Scope(hosts=["app.test"]), user_agent="t", retries=0, resolve=public_resolve,
                            max_redirects=0)
    with respx.mock:
        respx.get("https://app.test/fn").mock(return_value=httpx.Response(200))
        report = await ActiveOrchestrator(a, now=NOW, client=client).run()
    assert report.requests_made == 1
    assert report.checks[0].status is ModuleStatus.SUCCESS
    assert report.findings()[0].id.startswith("active.endpoint_open")
    assert report.request_log[0].url == "https://app.test/fn" and report.request_log[0].status == 200


# ------------------------------------------------------------------ reporting

async def test_active_reports_render_with_banner(tmp_path):
    a = auth(checks_enabled=["function_url_reachability"],
             function_urls=[{"url": "https://app.test/fn?token=SECRET", "method": "GET", "state_changing": True}])
    client = SafeHttpClient(Scope(hosts=["app.test"]), user_agent="t", retries=0, resolve=public_resolve,
                            max_redirects=0)
    with respx.mock:
        respx.get(url__startswith="https://app.test/fn").mock(return_value=httpx.Response(200))
        report = await ActiveOrchestrator(a, now=NOW, client=client).run()

    md = ActiveMarkdownReportWriter(report).render()
    html = ActiveHtmlReportWriter(report).render()
    assert "ACTIVE TESTING" in md and "ACTIVE TESTING" in html.replace("&mdash;", "")
    assert "Request Audit Log" in md and "Authorization" in md
    assert "token=[REDACTED]" in md and "SECRET" not in md          # query redacted in the audit log
    assert html.startswith("<!doctype html>") and "default-src 'none'" in html
    paths = (ActiveJsonReportWriter(report).write(tmp_path) + ActiveMarkdownReportWriter(report).write(tmp_path)
             + ActiveHtmlReportWriter(report).write(tmp_path))
    assert sorted(p.name for p in paths) == ["active.html", "active.json", "active.md"]
    assert "SECRET" not in (tmp_path / "active.json").read_text()


def _noop():
    async def sleep(_):
        return None
    return sleep


async def _handshake_port(host, port, ssl_ctx, timeout):
    import asyncio

    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port, ssl=ssl_ctx, server_hostname=host),
                                           timeout=timeout)
    except (ssl.SSLError, OSError, TimeoutError):
        return None
    try:
        obj = writer.get_extra_info("ssl_object")
        cipher = obj.cipher() if obj else None
        return cipher[0] if cipher else "unknown"
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=2)
        except (OSError, ssl.SSLError, TimeoutError):
            pass


_ = make_cert   # re-exported for the cert_files fixture
