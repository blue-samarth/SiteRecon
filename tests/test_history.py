import datetime as dt
import sys

import pytest

from recon.analysis import AnalysisEngine, ObservationBuilder, ScanComparator
from recon.cli import run
from recon.config import Config
from recon.models import (
    AnalysisResult,
    ChangeKind,
    CookieData,
    CookieRecord,
    CrawlData,
    CrawledPage,
    DnssecData,
    DnssecStatus,
    DomainRegistration,
    FormRecord,
    HttpData,
    HttpProbe,
    ModuleResult,
    ModuleStatus,
    ReconReport,
    ResourcesData,
    SecurityHeader,
    SecurityTxtInfo,
    TargetInfo,
    ToolInfo,
)
from recon.orchestrator import ScanHistory, ScanOrchestrator
from recon.storage import JsonScanStore
from tests.test_reporting import _dns, patched_collectors  # noqa: F401  (fixture re-export)

T0 = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)


def mr(name, data, status=ModuleStatus.SUCCESS):
    return ModuleResult(module=name, status=status, started_at=T0, finished_at=T0, duration_ms=1, data=data)


def report(scan_id, *, dns=None, dns_status=ModuleStatus.SUCCESS, cookies=None, cookies_status=ModuleStatus.SUCCESS,
           started=T0):
    r = ReconReport(
        scan_id=scan_id, tool=ToolInfo(name="t", version="0", user_agent="u"),
        target=TargetInfo(input="example.com", hostname="example.com", scope=[]), options={},
        started_at=started, finished_at=started, duration_ms=1,
        dns=mr("dns", dns, dns_status), network=ModuleResult.skipped("network", "x"),
        http=ModuleResult.skipped("http", "x"), tls=ModuleResult.skipped("tls", "x"),
        whois=ModuleResult.skipped("whois", "x"), html=ModuleResult.skipped("html", "x"),
        technology=ModuleResult.skipped("technology", "x"), subdomains=ModuleResult.skipped("subdomains", "x"),
        third_party=ModuleResult.skipped("third_party", "x"),
        cookies=mr("cookies", cookies, cookies_status) if cookies else ModuleResult.skipped("cookies", "x"),
        analysis=AnalysisResult())
    r.observations = ObservationBuilder("example.com", r.module_results()).build()
    return r


def cookie(name, secure=True):
    return CookieRecord(name=name, source_url="https://example.com/", over_https=True, secure=secure)


def test_comparison_classifies_changes():
    d1, d2 = _dns(), _dns()
    d2.queries["A"].records[0].value = "93.184.216.99"
    prev = report("20260101T000000Z-aaaaaa", dns=d1, cookies=CookieData(cookies=[cookie("a"), cookie("gone")]))
    cur = report("20260102T000000Z-bbbbbb", dns=d2, cookies=CookieData(cookies=[cookie("a", secure=False), cookie("new")]),
                 started=T0 + dt.timedelta(days=1))
    result = ScanComparator.compare(prev, cur)
    kinds = {(c.type, c.key): c.kind for c in result.changes}
    assert kinds[("dns.record", "A")] is ChangeKind.MODIFIED
    assert kinds[("cookie", "a||")] is ChangeKind.MODIFIED
    assert kinds[("cookie", "new||")] is ChangeKind.ADDED
    assert kinds[("cookie", "gone||")] is ChangeKind.REMOVED
    assert result.counts["unchanged"] == result.unchanged_count > 0
    assert result.previous.scan_id.endswith("aaaaaa") and result.current.scan_id.endswith("bbbbbb")


def test_missing_data_is_unknown_not_removed():
    prev = report("20260101T000000Z-aaaaaa", dns=_dns(), cookies=CookieData(cookies=[cookie("a")]))
    # current scan: dns failed entirely, cookies only partially collected
    cur = report("20260102T000000Z-bbbbbb", dns=None, dns_status=ModuleStatus.FAILED,
                 cookies=CookieData(cookies=[]), cookies_status=ModuleStatus.PARTIAL)
    result = ScanComparator.compare(prev, cur)
    assert result.counts["removed"] == 0
    assert all(c.kind is ChangeKind.UNKNOWN for c in result.changes)
    assert any("'dns' was failed in the current scan" in (c.reason or "") for c in result.changes)


def test_comparison_rejects_different_targets():
    a = report("20260101T000000Z-aaaaaa", dns=_dns())
    b = report("20260102T000000Z-bbbbbb", dns=_dns())
    b.target.hostname = "other.com"
    with pytest.raises(ValueError):
        ScanComparator.compare(a, b)


def test_json_store_roundtrip_and_validation(tmp_path):
    store = JsonScanStore(tmp_path)
    first = report("20260101T000000Z-aaaaaa", dns=_dns())
    second = report("20260102T000000Z-bbbbbb", dns=_dns(), started=T0 + dt.timedelta(days=1))
    store.save(second)
    store.save(first)
    assert [r.scan_id for r in store.list("example.com")] == [first.scan_id, second.scan_id]
    loaded = store.load(first.scan_id)
    assert loaded.observations == first.observations
    assert store.latest("example.com").scan_id == second.scan_id
    assert store.latest("example.com", exclude=second.scan_id).scan_id == first.scan_id
    with pytest.raises(ValueError):
        store.load("../../etc/passwd")
    with pytest.raises(KeyError):
        store.load("20990101T000000Z-ffffff")
    with pytest.raises(ValueError):
        store.list("../evil")


def test_scan_history_attaches_comparison(tmp_path):
    history = ScanHistory(JsonScanStore(tmp_path))
    first = report("20260101T000000Z-aaaaaa", dns=_dns())
    history.record(first)
    assert first.comparison is None
    second = report("20260102T000000Z-bbbbbb", dns=_dns(), started=T0 + dt.timedelta(days=1))
    history.record(second)
    assert second.comparison and second.comparison.previous.scan_id == first.scan_id
    assert second.comparison.counts["unchanged"] > 0 and second.comparison.changes == []


def test_observation_ids_are_stable():
    a = report("20260101T000000Z-aaaaaa", dns=_dns())
    b = report("20260102T000000Z-bbbbbb", dns=_dns())
    assert [o.id for o in a.observations] == [o.id for o in b.observations]
    assert {o.type for o in a.observations} >= {"dns.record", "email.spf", "email.dmarc"}
    assert len({o.id for o in a.observations}) == len(a.observations)       # one observation per key


async def test_module_selection_skips_unselected(patched_collectors):  # noqa: F811
    cfg = Config(target_input="example.com", hostname="example.com", modules=frozenset({"dns", "tls"}))
    r = await ScanOrchestrator(cfg).run()
    assert r.dns.status is ModuleStatus.SUCCESS and r.tls.status is ModuleStatus.SUCCESS
    assert r.http.status is ModuleStatus.SKIPPED and r.http.note == "not selected"
    assert r.html.status is ModuleStatus.SKIPPED and r.crawler.status is ModuleStatus.SKIPPED
    assert r.scan_id and r.observations


def test_cli_routes_bare_domain_to_scan(monkeypatch):
    seen = {}
    monkeypatch.setattr("recon.cli.app", lambda: seen.setdefault("argv", list(sys.argv)))
    monkeypatch.setattr(sys, "argv", ["siterecon", "example.com", "--no-history"])
    run()
    assert seen["argv"][1:3] == ["scan", "example.com"]
    monkeypatch.setattr(sys, "argv", ["siterecon", "history", "example.com"])
    seen.clear()
    run()
    assert seen["argv"][1] == "history"


def test_engine_v02_findings_have_recommendations_and_refs():
    https = HttpProbe(requested_url="https://example.com/", success=True, final_url="https://example.com/",
                      final_fetched=True, status_code=200, set_cookies=["a=1"], cache_control="public, max-age=600",
                      cors={"access-control-allow-origin": "*", "access-control-allow-credentials": "true"},
                      security_headers={"strict-transport-security": SecurityHeader(name="strict-transport-security",
                                                                                     present=True, value="max-age=31536000",
                                                                                     parsed={"max-age": 31536000})})
    crawl = CrawlData(max_depth=1, max_pages=5, robots_respected=True, crawl_delay=0, pages=[
        CrawledPage(url="https://example.com/other", depth=1, status_code=200, final_url="https://example.com/other",
                    security_headers={"strict-transport-security": None})],
        forms=[FormRecord(page_url="http://example.com/login", action="http://example.com/login", method="post",
                          has_password_field=True)])
    cookies = CookieData(cookies=[CookieRecord(name="sid", source_url="https://example.com/", over_https=True,
                                               same_site="None")])
    dnssec = DnssecData(zone="example.com", status=DnssecStatus.BROKEN, ds_status="NOERROR", dnskey_status="NODATA")
    resources = ResourcesData(origin="https://example.com", security_txt=SecurityTxtInfo(
        url="https://example.com/.well-known/security.txt", present=True, contacts=[], fields={"policy": ["x"]}))
    whois = DomainRegistration(domain="example.com", source="rdap", dnssec=False)
    r = AnalysisEngine(T0).analyze(dns=None, network=None, http=HttpData(probes=[https]), tls=None, whois=whois,
                                   crawl=crawl, cookies=cookies, dnssec=dnssec, resources=resources)
    by = {f.id.split(":")[0]: f for f in r.findings}
    for code in ("http.cookie_cacheable", "http.cors_wildcard_credentials", "http.header_inconsistency",
                 "crawl.password_over_http", "cookies.missing_secure", "cookies.missing_httponly",
                 "cookies.samesite_none_insecure", "dnssec.broken", "resources.security_txt_incomplete"):
        assert code in by, code
        assert by[code].recommendation, code
    assert by["dnssec.broken"].severity.value == "medium"
    assert by["crawl.password_over_http"].severity.value == "medium"
    assert "dnssec.registry_mismatch" not in by   # BROKEN is not compared with the registry flag


def test_findings_reference_supporting_observations():
    r = report("20260101T000000Z-aaaaaa", dns=_dns())
    result = AnalysisEngine(T0).analyze(dns=r.dns.data, network=None, http=None, tls=None, observations=r.observations)
    dmarc = next(f for f in result.findings if f.id.startswith("dns.dmarc_missing"))
    obs_by_id = {o.id: o for o in r.observations}
    assert dmarc.evidence_refs and all(obs_by_id[ref].module == "dns" for ref in dmarc.evidence_refs)
    assert dmarc.limitations is None and dmarc.recommendation.startswith("Publish a DMARC record")
