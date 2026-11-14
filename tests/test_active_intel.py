import datetime as dt
import json

import httpx
import respx

from recon.active import ActiveOrchestrator, AuthorizationFile, EXTERNAL_INTELLIGENCE
from recon.active.authorization import ActiveScope, ExternalIntelligence, TimeWindow
from recon.intel import IntelRunner
from recon.models import ModuleStatus
from recon.utils.http_client import SafeHttpClient
from recon.utils.scope import Scope
from tests.conftest import public_resolve

NOW = dt.datetime(2026, 11, 10, 3, 0, tzinfo=dt.UTC)
WINDOW = TimeWindow(start=dt.datetime(2026, 11, 10, 0, 0, tzinfo=dt.UTC),
                    end=dt.datetime(2026, 11, 10, 6, 0, tzinfo=dt.UTC))
CDX = json.dumps([["original", "timestamp", "statuscode"],
                  ["https://app.test/", "20190101000000", "200"],
                  ["https://app.test/db.sql", "20200101000000", "200"]]).encode()
SHODAN = {"ip": "203.0.113.9", "ports": [443], "vulns": [], "hostnames": [], "cpes": [], "tags": []}


def auth(providers=None, checks=(EXTERNAL_INTELLIGENCE,)):
    return AuthorizationFile(
        target="app.test", authorized_by="op", authorized_on="2026-11-08", window=WINDOW,
        scope=ActiveScope(hosts=["app.test"]), checks_enabled=list(checks),
        external_intelligence=ExternalIntelligence(providers=list(providers)) if providers is not None else None)


def intel_runner(providers):
    client = SafeHttpClient(Scope(hosts=["web.archive.org", "archive.org", "internetdb.shodan.io"]),
                            user_agent="t", retries=0, resolve=public_resolve, max_redirects=0)
    return IntelRunner(providers=providers, client=client)


async def test_external_intelligence_runs_as_an_active_phase_and_is_audited():
    orch = ActiveOrchestrator(auth(providers=["wayback"]), now=NOW, ips=["203.0.113.9"],
                              intel_runner=intel_runner(["wayback"]))
    with respx.mock:
        respx.get(url__startswith="https://web.archive.org/cdx/search/cdx").mock(
            return_value=httpx.Response(200, content=CDX))
        report = await orch.run()
    check = next(c for c in report.checks if c.check_id == EXTERNAL_INTELLIGENCE)
    assert check.status is ModuleStatus.SUCCESS
    codes = {f.id.split(":", 1)[0] for f in check.findings}
    assert "intel.archived_history" in codes and "intel.archived_sensitive_path" in codes
    # the third-party request is recorded in the engagement audit log AND counted toward the total
    intel_rows = [r for r in report.request_log if r.check_id == EXTERNAL_INTELLIGENCE]
    assert intel_rows and intel_rows[0].status == 200
    assert check.requests_made == len(intel_rows)
    assert report.requests_made == len(report.request_log)   # invariant: one log row per counted request


async def test_shodan_phase_uses_passive_ips():
    orch = ActiveOrchestrator(auth(providers=["shodan_internetdb"]), now=NOW, ips=["203.0.113.9"],
                              intel_runner=intel_runner(["shodan_internetdb"]))
    with respx.mock:
        respx.get("https://internetdb.shodan.io/203.0.113.9").mock(return_value=httpx.Response(200, json=SHODAN))
        report = await orch.run()
    check = next(c for c in report.checks if c.check_id == EXTERNAL_INTELLIGENCE)
    assert any(f.id.startswith("intel.exposed_ports") for f in check.findings)


async def test_intel_phase_without_ips_still_runs_host_only_providers():
    # no IPs (e.g. --no-passive): Shodan skips, Wayback still runs — the phase does not fail
    orch = ActiveOrchestrator(auth(providers=None), now=NOW, ips=[],
                              intel_runner=intel_runner(["wayback", "shodan_internetdb"]))
    with respx.mock:
        respx.get(url__startswith="https://web.archive.org/cdx/search/cdx").mock(
            return_value=httpx.Response(200, content=CDX))
        report = await orch.run()
    check = next(c for c in report.checks if c.check_id == EXTERNAL_INTELLIGENCE)
    assert check.status is ModuleStatus.SUCCESS and check.findings


def test_plan_shows_external_intelligence_would_run():
    plan = dict(ActiveOrchestrator(auth(providers=["wayback"]), now=NOW).plan())
    assert plan[EXTERNAL_INTELLIGENCE] is None   # None = would run


def test_redaction_includes_external_intelligence():
    from recon.active import redact_authorization
    summary = redact_authorization(auth(providers=["wayback"]))
    assert summary["external_intelligence"] == {"providers": ["wayback"]}
