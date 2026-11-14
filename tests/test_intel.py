import datetime as dt
import json

import httpx
import respx

from recon.intel import IntelRunner, REGISTRY
from recon.intel.base import IntelContext, IntelResult, IntelligenceProvider
from recon.models import CollectionMethod, Confidence, Freshness
from recon.utils.http_client import SafeHttpClient
from recon.utils.scope import Scope
from tests.conftest import public_resolve

NOW = dt.datetime(2026, 11, 10, tzinfo=dt.UTC)
ALL_HOSTS = ["web.archive.org", "archive.org", "internetdb.shodan.io"]

CDX = json.dumps([
    ["original", "timestamp", "statuscode"],
    ["https://example.com/", "20190101000000", "200"],
    ["https://example.com/about", "20200601120000", "200"],
    ["https://example.com/backup.zip", "20210101000000", "200"],
]).encode()

SHODAN = {"ip": "203.0.113.5", "ports": [22, 443], "vulns": ["CVE-2021-1234"],
          "hostnames": ["a.example.com"], "cpes": ["cpe:/a:nginx:nginx"], "tags": ["cloud"]}


def runner(providers):
    client = SafeHttpClient(Scope(hosts=ALL_HOSTS), user_agent="t", retries=0, resolve=public_resolve,
                            max_redirects=0, allow_private_networks=False)
    return IntelRunner(providers=providers, client=client)


async def run(providers, host="example.com", ips=("203.0.113.5",)):
    return await runner(providers).run(host, list(ips), now=NOW)


# ------------------------------------------------------------------ Wayback

async def test_wayback_summarizes_history_and_flags_sensitive_paths():
    with respx.mock:
        respx.get(url__startswith="https://web.archive.org/cdx/search/cdx").mock(
            return_value=httpx.Response(200, content=CDX))
        agg = await run(["wayback"])
    codes = {f.id.split(":", 1)[0] for f in agg.findings}
    assert "intel.archived_history" in codes and "intel.archived_sensitive_path" in codes
    sensitive = next(f for f in agg.findings if f.id.startswith("intel.archived_sensitive_path"))
    assert any("backup.zip" in e for e in sensitive.evidence) and sensitive.severity.value == "low"
    hist_obs = next(o for o in agg.observations if o.type == "intel.wayback.history")
    assert hist_obs.value["snapshots"] == 3 and hist_obs.freshness is Freshness.HISTORICAL
    assert hist_obs.external_provider == "Wayback Machine"
    assert hist_obs.collection_method == CollectionMethod.EXTERNAL_API


async def test_wayback_no_history_yields_nothing():
    with respx.mock:
        respx.get(url__startswith="https://web.archive.org/cdx/search/cdx").mock(
            return_value=httpx.Response(200, content=b"[]"))
        agg = await run(["wayback"])
    assert agg.findings == [] and agg.observations == [] and agg.errors == []


async def test_wayback_http_error_is_recorded_not_raised():
    with respx.mock:
        respx.get(url__startswith="https://web.archive.org/cdx/search/cdx").mock(
            return_value=httpx.Response(503))
        agg = await run(["wayback"])
    assert agg.findings == [] and agg.errors and agg.errors[0].module == "wayback"


# ------------------------------------------------------------------ Shodan InternetDB

async def test_shodan_records_ports_and_cve_candidates():
    with respx.mock:
        respx.get("https://internetdb.shodan.io/203.0.113.5").mock(return_value=httpx.Response(200, json=SHODAN))
        agg = await run(["shodan_internetdb"])
    by = {f.id.split(":", 1)[0]: f for f in agg.findings}
    assert by["intel.exposed_ports"].severity.value == "informational"
    assert "22" in " ".join(by["intel.exposed_ports"].evidence)
    vuln = by["intel.indexed_vulnerability"]
    assert vuln.confidence is Confidence.LOW and "CVE-2021-1234" in " ".join(vuln.evidence)  # candidate, low
    obs = next(o for o in agg.observations if o.type == "intel.shodan.exposure")
    assert obs.external_provider == "Shodan InternetDB" and obs.limitations    # caveats recorded


async def test_shodan_404_is_not_an_error():
    with respx.mock:
        respx.get("https://internetdb.shodan.io/203.0.113.5").mock(return_value=httpx.Response(404))
        agg = await run(["shodan_internetdb"])
    assert agg.findings == [] and agg.errors == []


async def test_shodan_skipped_without_ips():
    agg = await run(["shodan_internetdb"], ips=())
    assert agg.findings == [] and agg.notes[0].status == "skipped" and "IP" in agg.notes[0].detail


# ------------------------------------------------------------------ runner

async def test_one_provider_failing_does_not_stop_others(monkeypatch):
    class _Boom(IntelligenceProvider):
        name = "boom"
        label = "Boom"
        hosts = ("internetdb.shodan.io",)

        async def collect(self, ctx):
            raise RuntimeError("provider blew up")

    monkeypatch.setitem(REGISTRY, "boom", _Boom)
    with respx.mock:
        respx.get("https://internetdb.shodan.io/203.0.113.5").mock(return_value=httpx.Response(200, json=SHODAN))
        agg = await run(["boom", "shodan_internetdb"])
    statuses = {n.provider: n.status for n in agg.notes}
    assert statuses["boom"] == "failed" and statuses["shodan_internetdb"] == "ran"
    assert any(f.id.startswith("intel.exposed_ports") for f in agg.findings)   # the healthy provider still ran
    assert any(e.module == "boom" for e in agg.errors)


def test_resolve_defaults_to_keyless_providers():
    assert set(IntelRunner.resolve(None)) == {"wayback", "shodan_internetdb"}
    assert IntelRunner.resolve(["wayback", "unknown"]) == ["wayback"]
