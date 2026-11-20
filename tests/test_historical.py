'''
Historical URL collection: per-source parsing, merging, redaction, extraction and the findings it produces.

Every archive is mocked with respx; nothing contacts a real service, and nothing contacts the target.
'''

import datetime as dt
import json

import httpx
import pytest
import respx

from recon.analysis import AnalysisEngine, ObservationBuilder
from recon.analysis.historical_signatures import SENSITIVE_PATH, classify_parameter, match_tech_hints
from recon.models import CollectionMethod, Confidence, Freshness, ModuleResult, ModuleStatus, Severity, utcnow
from recon.modules import (
    CommonCrawlUrlSource,
    HistoricalUrlCollector,
    OtxUrlSource,
    SourceError,
    UrlScanUrlSource,
    WaybackUrlSource,
)
from recon.modules.historical import ALL_SOURCES, REGISTRY, resolve_sources, scope_hosts, unknown_sources
from recon.utils.http_client import SafeHttpClient
from recon.utils.scope import Scope
from tests.conftest import public_resolve

NOW = dt.datetime(2026, 11, 18, tzinfo=dt.UTC)
ALL_HOSTS = sorted({h for cls in REGISTRY.values() for h in cls.HOSTS})

CDX = json.dumps([
    ["original", "timestamp", "statuscode", "mimetype"],
    ["https://example.com/index.php?id=1&token=SECRET", "20190101000000", "200", "text/html"],
    ["https://old.example.com/wp-content/themes/t/style.css", "20200601120000", "200", "text/css"],
    ["https://example.com/db_backup.sql", "20210101000000", "200", "application/sql"],
    ["https://example.com/api/v1/orders?redirect_uri=https://evil.test", "20220101000000", "404", "text/html"],
    ["https://unrelated.test/x", "20220101000000", "200", "text/html"],
]).encode()


def client():
    return SafeHttpClient(Scope(hosts=ALL_HOSTS), user_agent="t", retries=0, resolve=public_resolve)


async def collect(sources, hostname="example.com", limit=100):
    async with client() as http:
        return await HistoricalUrlCollector(hostname, http, sources=sources, limit=limit).collect()


def mock_wayback(body=CDX, status=200):
    return respx.get(url__startswith="https://web.archive.org/cdx/search/cdx").mock(
        return_value=httpx.Response(status, content=body))


# ------------------------------------------------------------------ sources

@respx.mock
async def test_wayback_rows_are_parsed_with_status_and_mime():
    mock_wayback()
    async with client() as http:
        rows = await WaybackUrlSource().fetch(http, "example.com", 100)
    assert len(rows) == 5 and rows[0]["url"].startswith("https://example.com/index.php")
    assert rows[0]["status"] == "200" and rows[0]["mime"] == "text/html"


@respx.mock
async def test_commoncrawl_reads_json_lines_from_the_latest_index():
    respx.get("https://index.commoncrawl.org/collinfo.json").mock(return_value=httpx.Response(200, json=[
        {"id": "CC-MAIN-2026-05", "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2026-05-index"}]))
    respx.get(url__startswith="https://index.commoncrawl.org/CC-MAIN-2026-05-index").mock(
        return_value=httpx.Response(200, content=b'{"url":"https://example.com/a","timestamp":"20250101000000","status":"200"}\n'))
    async with client() as http:
        rows = await CommonCrawlUrlSource().fetch(http, "example.com", 100)
    assert rows == [{"url": "https://example.com/a", "timestamp": "20250101000000", "status": "200", "mime": None}]


@respx.mock
async def test_urlscan_rows_come_from_page_urls():
    respx.get(url__startswith="https://urlscan.io/api/v1/search/").mock(
        return_value=httpx.Response(200, json={"results": [
            {"page": {"url": "https://example.com/pricing", "status": "200", "mimeType": "text/html"},
             "task": {"time": "2025-06-01T10:00:00.000Z"}}]}))
    async with client() as http:
        rows = await UrlScanUrlSource().fetch(http, "example.com", 100)
    assert rows[0]["url"] == "https://example.com/pricing"


@respx.mock
async def test_otx_url_list_is_parsed():
    respx.get(url__startswith="https://otx.alienvault.com/api/v1/indicators/domain/").mock(
        return_value=httpx.Response(200, json={"url_list": [
            {"url": "https://example.com/login", "date": "2024-02-02T00:00:00",
             "result": {"urlworker": {"http_code": 200, "filetype": "html"}}}]}))
    async with client() as http:
        rows = await OtxUrlSource().fetch(http, "example.com", 100)
    assert rows[0]["url"] == "https://example.com/login" and rows[0]["status"] == 200


@respx.mock
async def test_a_malformed_response_is_a_source_error_not_a_crash():
    mock_wayback(body=b'{"not": "a list"}')
    with pytest.raises(SourceError, match="unexpected response shape"):
        async with client() as http:
            await WaybackUrlSource().fetch(http, "example.com", 100)


def test_source_registry_and_scoping():
    assert resolve_sources(None) == list(ALL_SOURCES)        # --historical enables every archive
    assert resolve_sources(["wayback"]) == ["wayback"] and resolve_sources(["none"]) == []
    assert unknown_sources(["wayback", "typo"]) == ["typo"]
    assert scope_hosts(["wayback"]) == ["web.archive.org"]


# ------------------------------------------------------------------ collection and extraction

@respx.mock
async def test_scope_filtering_dedup_and_query_redaction():
    mock_wayback()
    data, errors = await collect([WaybackUrlSource()])
    assert data.urls_seen == 4 and data.out_of_scope_dropped == 1      # unrelated.test dropped
    assert data.hosts == ["example.com", "old.example.com"]
    # A real token can sit in an archived URL; it must never be stored.
    joined = json.dumps(data.model_dump(mode="json"))
    assert "SECRET" not in joined and "[REDACTED]" in joined
    assert errors == []


@respx.mock
async def test_endpoints_parameters_hints_and_sensitive_paths_are_extracted():
    mock_wayback()
    data, _ = await collect([WaybackUrlSource()])
    assert data.endpoints == ["/api/v1/orders"]
    params = {p.name: p for p in data.parameters}
    assert params["token"].category == "credential" and params["redirect_uri"].category == "redirect"
    assert params["id"].category == "identifier"
    assert params["token"].paths == ["/index.php"] and params["token"].note
    hints = {h.name: h for h in data.tech_hints}
    assert hints["PHP"].confidence is Confidence.MEDIUM and hints["WordPress"].occurrences == 1
    assert hints["PHP"].still_detected is None                          # not annotated yet
    assert data.sensitive_paths and data.sensitive_paths[0].endswith("db_backup.sql")
    assert data.extensions["php"] == 1 and data.extensions["sql"] == 1
    assert data.first_seen.year == 2019 and data.last_seen.year == 2022


@respx.mock
async def test_dates_and_statuses_merge_across_sources():
    mock_wayback(body=json.dumps([["original", "timestamp", "statuscode"],
                                  ["https://example.com/p", "20200101000000", "200"]]).encode())
    respx.get(url__startswith="https://otx.alienvault.com/").mock(
        return_value=httpx.Response(200, json={"url_list": [
            {"url": "https://example.com/p", "date": "2024-01-01T00:00:00",
             "result": {"urlworker": {"http_code": 301}}}]}))
    data, _ = await collect([WaybackUrlSource(), OtxUrlSource()])
    assert data.urls_seen == 1
    url = data.urls[0]
    assert url.sources == ["wayback", "otx"]
    assert url.first_seen.year == 2020 and url.last_seen.year == 2024
    assert sorted(url.status_codes) == [200, 301]
    assert [(s.source, s.urls) for s in data.sources] == [("wayback", 1), ("otx", 1)]


@respx.mock
async def test_one_failing_source_is_recorded_and_the_rest_still_run():
    mock_wayback(status=503)
    respx.get(url__startswith="https://otx.alienvault.com/").mock(
        return_value=httpx.Response(200, json={"url_list": [{"url": "https://example.com/ok"}]}))
    data, errors = await collect([WaybackUrlSource(), OtxUrlSource()])
    statuses = {s.source: s.status for s in data.sources}
    assert statuses == {"wayback": "failed", "otx": "live"}
    assert data.urls_seen == 1 and [e.error_type for e in errors] == ["source_failed"]


@respx.mock
async def test_every_source_failing_raises_so_the_module_is_marked_failed():
    mock_wayback(status=502)
    with pytest.raises(RuntimeError, match="every historical source failed"):
        await collect([WaybackUrlSource()])


async def test_no_client_means_every_source_is_skipped():
    data, errors = await HistoricalUrlCollector("example.com", None, sources=[WaybackUrlSource()]).collect()
    assert [s.status for s in data.sources] == ["skipped"] and errors == []
    assert data.urls_seen == 0


@respx.mock
async def test_hitting_the_per_source_cap_is_reported_as_truncated():
    rows = [["original", "timestamp"]] + [[f"https://example.com/{i}", "20200101000000"] for i in range(3)]
    mock_wayback(body=json.dumps(rows).encode())
    data, _ = await collect([WaybackUrlSource()], limit=3)
    assert data.truncated and data.limit == 3


def test_mark_current_annotates_hints_without_promoting_them():
    from recon.models.historical import HistoricalData, HistoricalTechHint
    data = HistoricalData(host="example.com", tech_hints=[
        HistoricalTechHint(name="PHP", category="language", confidence=Confidence.MEDIUM),
        HistoricalTechHint(name="Adobe Flash", category="deprecated", confidence=Confidence.MEDIUM)])
    HistoricalUrlCollector.mark_current(data, {"PHP", "Nginx"})
    assert [h.still_detected for h in data.tech_hints] == [True, False]
    # a hint is evidence about the past; it is annotated, never turned into a current detection
    assert HistoricalUrlCollector.confidence_for(data.tech_hints[0]) is Confidence.HIGH
    assert HistoricalUrlCollector.confidence_for(data.tech_hints[1]) is Confidence.MEDIUM


# ------------------------------------------------------------------ signatures

@pytest.mark.parametrize("path, expected", [
    ("/index.php", "PHP"), ("/default.aspx", "ASP.NET"), ("/x.jsp", "JavaServer Pages"),
    ("/wp-content/plugins/a.js", "WordPress"), ("/_next/static/x.js", "Next.js"),
    ("/cgi-bin/test.pl", "CGI"), ("/banner.swf", "Adobe Flash"), ("/graphql", "GraphQL"),
    ("/administrator/index.php", "Joomla"), ("/actuator/health", "Spring Boot Actuator"),
])
def test_technology_hints_from_paths(path, expected):
    assert expected in [s.name for s in match_tech_hints(path)]


def test_plain_paths_produce_no_technology_hint():
    assert match_tech_hints("/about-us") == [] and match_tech_hints("/") == []


@pytest.mark.parametrize("name, category", [
    ("token", "credential"), ("access_token", "credential"), ("password", "credential"),
    ("redirect_uri", "redirect"), ("next", "redirect"), ("returnUrl", "redirect"),
    ("filename", "file"), ("path", "file"), ("order_id", "identifier"), ("zzz_unknown", None),
])
def test_parameter_classification(name, category):
    signature = classify_parameter(name)
    assert (signature.category if signature else None) == category


@pytest.mark.parametrize("path, sensitive", [
    ("/db.sql", True), ("/.env", True), ("/backup/site.zip", True), ("/.git/config", True),
    ("/wp-config.php.bak", True), ("/actuator/env", True), ("/about", False), ("/style.css", False),
])
def test_sensitive_path_detection(path, sensitive):
    assert bool(SENSITIVE_PATH.search(path)) is sensitive


# ------------------------------------------------------------------ observations and findings

def result(data):
    now = utcnow()
    return ModuleResult(module="historical", status=ModuleStatus.SUCCESS, started_at=now, finished_at=now,
                        duration_ms=1.0, data=data)


@respx.mock
async def test_observations_are_marked_historical_and_externally_sourced():
    mock_wayback()
    data, _ = await collect([WaybackUrlSource()])
    observations = ObservationBuilder("example.com", {"historical": result(data)}).build()
    kinds = {o.type for o in observations}
    assert {"historical.summary", "historical.endpoints", "historical.parameter",
            "historical.technology", "historical.sensitive_paths"} <= kinds
    for o in observations:
        assert o.freshness is Freshness.HISTORICAL
        assert o.collection_method == CollectionMethod.EXTERNAL_API
        assert o.external_provider and o.limitations
    summary = next(o for o in observations if o.type == "historical.summary")
    assert summary.value["urls"] == 4 and summary.observed_at is not None


@respx.mock
async def test_findings_cover_the_archived_surface_with_recommendations():
    mock_wayback()
    data, _ = await collect([WaybackUrlSource()])
    observations = ObservationBuilder("example.com", {"historical": result(data)}).build()
    analysis = AnalysisEngine(utcnow()).analyze(dns=None, network=None, http=None, tls=None,
                                                host="example.com", historical=data, observations=observations)
    by_code = {f.id.split(":", 1)[0]: f for f in analysis.findings}
    assert {"historical.archived_urls", "historical.sensitive_path", "historical.credential_in_url",
            "historical.parameter_surface", "historical.legacy_technology"} <= set(by_code)
    credential = by_code["historical.credential_in_url"]
    assert credential.severity is Severity.MEDIUM and credential.recommendation and credential.limitations
    assert "rotate" in credential.recommendation.lower()
    assert all("SECRET" not in e for e in credential.evidence)       # the value is never echoed
    for finding in analysis.findings:
        assert finding.recommendation and finding.limitations
        assert finding.confidence.rank <= Confidence.MEDIUM.rank     # third-party history is never 'high'


@respx.mock
async def test_a_failed_source_produces_an_incomplete_coverage_finding():
    mock_wayback(status=500)
    respx.get(url__startswith="https://otx.alienvault.com/").mock(
        return_value=httpx.Response(200, json={"url_list": [{"url": "https://example.com/ok"}]}))
    data, _ = await collect([WaybackUrlSource(), OtxUrlSource()])
    analysis = AnalysisEngine(utcnow()).analyze(dns=None, network=None, http=None, tls=None,
                                                host="example.com", historical=data)
    incomplete = next(f for f in analysis.findings if f.id.startswith("historical.discovery_incomplete"))
    assert incomplete.severity is Severity.INFORMATIONAL
    assert any("wayback" in e for e in incomplete.evidence)


def test_no_archived_urls_means_no_findings():
    from recon.models.historical import HistoricalData, HistoricalSourceResult
    empty = HistoricalData(host="example.com", sources=[HistoricalSourceResult(source="wayback", status="live")])
    analysis = AnalysisEngine(utcnow()).analyze(dns=None, network=None, http=None, tls=None,
                                                host="example.com", historical=empty)
    assert analysis.findings == []
