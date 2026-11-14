import json

import pytest

from recon.config import Config
from recon.models.common import CollectionError, ModuleStatus
from recon.models.dns import DmarcAnalysis, DnsData, DnsQueryResult, DnsQueryStatus, DnsRecord, EmailSecurity, SpfAnalysis
from recon.models.http import HttpData, HttpProbe
from recon.models.subdomains import SubdomainData
from recon.models.tls import TlsData
from recon.models import DnssecData, DnssecStatus, ResourcesData
from recon.modules import (
    DnsCollector,
    DnssecCollector,
    ResourcesCollector,
    HttpCollector,
    NetworkCollector,
    SubdomainCollector,
    TlsCollector,
    WhoisCollector,
)
from recon.orchestrator import ScanOrchestrator
from recon.models.html import HtmlData, ResourceRef
from recon.models.http import SecurityHeader
from recon.reporting import HtmlReportWriter, JsonReportWriter, MarkdownReportWriter


def _dns():
    return DnsData(
        hostname="example.com",
        queries={"A": DnsQueryResult(name="example.com", record_type="A", status=DnsQueryStatus.NOERROR,
                                     records=[DnsRecord(value="93.184.216.34", ttl=60)], response_time_ms=3)},
        email=EmailSecurity(spf=SpfAnalysis(lookup_status=DnsQueryStatus.NODATA),
                            dmarc=DmarcAnalysis(name="_dmarc.example.com", lookup_status=DnsQueryStatus.NXDOMAIN),
                            dkim_selectors_checked=["default"]),
    )


def scan(**cfg):
    cfg.setdefault("target_input", "example.com")
    return ScanOrchestrator(Config(hostname="example.com", **cfg)).run()


@pytest.fixture
def patched_collectors(monkeypatch):
    """Replace every networked collector's collect() so no real I/O happens."""
    async def fake_dns(self):
        return _dns(), []

    async def fake_network(self):
        raise RuntimeError("rdap exploded")

    async def fake_http(self):
        probe = HttpProbe(requested_url="https://example.com/", success=False,
                          error="refused | piped", error_type="ConnectError")
        return HttpData(probes=[probe]), [self.error(probe.requested_url, "ConnectError", "refused")]

    async def fake_tls(self):
        return TlsData(probes=[]), []

    async def fake_whois(self):
        return None, [CollectionError(module="whois", target=self.domain, error_type="whois_failed", message="x")]

    async def fake_subdomains(self):
        return SubdomainData(query=f"%.{self.hostname}", verification_limit=0), []

    async def fake_dnssec(self):
        return DnssecData(zone="example.com", status=DnssecStatus.UNSIGNED, ds_status="NODATA",
                          dnskey_status="NODATA"), []

    async def fake_resources(self):
        return ResourcesData(origin=self.origin), []

    for cls, fake in [(DnsCollector, fake_dns), (NetworkCollector, fake_network), (HttpCollector, fake_http),
                      (TlsCollector, fake_tls), (WhoisCollector, fake_whois), (SubdomainCollector, fake_subdomains),
                      (DnssecCollector, fake_dnssec), (ResourcesCollector, fake_resources)]:
        monkeypatch.setattr(cls, "collect", fake)


async def test_partial_scan_when_a_module_fails(patched_collectors):
    report = await scan(target_input="https://Example.com/x")
    assert report.dns.status is ModuleStatus.SUCCESS
    assert report.network.status is ModuleStatus.FAILED and report.network.data is None
    assert report.network.errors[0].message == "rdap exploded"
    assert report.http.status is ModuleStatus.PARTIAL
    assert report.tls.status is ModuleStatus.SUCCESS
    assert report.whois.status is ModuleStatus.FAILED
    assert report.subdomains.status is ModuleStatus.SUCCESS
    # html has no document to parse; derived modules still run
    assert report.html.status is ModuleStatus.FAILED
    assert report.technology.status is ModuleStatus.SUCCESS
    assert report.third_party.status is ModuleStatus.SUCCESS
    assert {e.module for e in report.errors} == {"network", "http", "whois", "html"}
    assert any("JavaScript/CSS analysis is static" in lim for lim in report.limitations)


async def test_disabled_modules_are_skipped(patched_collectors):
    report = await scan(subdomains=False, whois=False)
    assert report.subdomains.status is ModuleStatus.SKIPPED
    assert report.whois.status is ModuleStatus.SKIPPED


async def test_network_skipped_without_addresses(monkeypatch, patched_collectors):
    async def no_ips(self):
        d = _dns()
        d.queries["A"].records = []
        return d, []

    monkeypatch.setattr(DnsCollector, "collect", no_ips)
    report = await scan()
    assert report.network.status is ModuleStatus.SKIPPED


async def test_every_module_failing_still_produces_a_report(monkeypatch, patched_collectors):
    async def boom(self):
        raise RuntimeError("offline")

    for cls in (DnsCollector, HttpCollector, TlsCollector, WhoisCollector, SubdomainCollector,
                DnssecCollector, ResourcesCollector):
        monkeypatch.setattr(cls, "collect", boom)
    report = await scan()
    assert report.dns.status is ModuleStatus.FAILED and report.http.status is ModuleStatus.FAILED
    assert report.analysis.findings == []


async def test_json_and_markdown_reports(tmp_path, patched_collectors):
    report = await scan()
    paths = JsonReportWriter(report).write(tmp_path / "example.com")
    [md_path] = MarkdownReportWriter(report).write(tmp_path / "example.com")

    names = sorted(p.relative_to(tmp_path).as_posix() for p in paths)
    assert names == sorted([f"example.com/raw/{m}.json" for m in report.module_results()] + ["example.com/report.json"])
    assert len(report.module_results()) == 14

    doc = json.loads((tmp_path / "example.com/report.json").read_text())
    assert doc["schema_version"] == "2.1" and doc["scan_id"]
    assert doc["target"]["hostname"] == "example.com"
    assert doc["network"]["status"] == "failed" and doc["network"]["data"] is None
    assert "body" not in doc["http"]["data"]["probes"][0]   # raw bodies never serialized
    assert doc["analysis"]["severity_counts"].keys() >= {"informational", "critical"}

    md = md_path.read_text()
    for heading in ("Executive Summary", "DNS Reconnaissance", "Network and IP Intelligence",
                    "Technology Fingerprinting", "Subdomain Discovery", "Third-Party Integrations",
                    "Security Observations", "Collection Errors and Limitations"):
        assert heading in md
    assert "refused \\| piped" in md                          # table cells escaped
    assert "Module failed; no data collected" in md


async def test_markdown_renders_without_findings(patched_collectors):
    report = await scan()
    report.analysis.findings = []
    assert "_No findings._" in MarkdownReportWriter(report).render()


async def test_html_report_contains_every_section_and_raw_data(tmp_path, patched_collectors):
    report = await scan()
    [path] = HtmlReportWriter(report).write(tmp_path / "example.com")
    page = path.read_text()
    assert path.name == "report.html" and page.startswith("<!doctype html>")
    for sid in ("summary", "findings", "dns", "network", "http", "tls", "whois", "technology", "html",
                "subdomains", "third-party", "infrastructure", "errors", "raw", "sources"):
        assert f'<section id="{sid}">' in page
    for module in report.module_results():
        assert f"{module} <span class=\"muted\">(" in page       # raw JSON block per module
    assert "rdap exploded" in page                                  # failed module's error shown
    assert "Module failed; no data collected" in page


async def test_html_report_escapes_untrusted_content_and_loads_nothing(patched_collectors):
    report = await scan()
    evil = "<script>alert(1)</script>"
    report.html.data = HtmlData(source_url="https://example.com/", title=evil, resources=[
        ResourceRef(url="javascript:alert(2)", kind="script", host=None, same_site=False,
                    attributes={"x": '"><img src=x onerror=alert(3)>'})])
    report.http.data.probes[0].success = True
    report.http.data.probes[0].headers = {"server": ['nginx"><svg onload=alert(4)>']}
    report.http.data.probes[0].security_headers = {
        "content-security-policy": SecurityHeader(name="content-security-policy", present=True, value=evil)}
    page = HtmlReportWriter(report).render()

    lowered = page.lower()
    assert "<script" not in lowered and "<img" not in lowered and "<svg" not in lowered   # no live tags
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page                                # shown as text
    assert "&lt;img src=x onerror=alert(3)&gt;" in page and "&lt;svg onload=alert(4)&gt;" in page
    assert 'href="javascript:' not in page and "<a href=\"http" not in page   # URLs shown as text only
    assert "default-src 'none'" in page                                     # CSP blocks scripts/remote loads
    import re
    assert not re.search(r'(src|href)="(https?:)?//', page)                 # no external resources


def test_config_output_format_selection():
    from recon.config import OutputFormat
    cfg = lambda f: Config(target_input="x.io", hostname="x.io", output_format=f)  # noqa: E731
    assert (cfg(OutputFormat.ALL).wants_html, cfg(OutputFormat.ALL).wants_json) == (True, True)
    assert (cfg(OutputFormat.BOTH).wants_html, cfg(OutputFormat.BOTH).wants_markdown) == (False, True)
    assert (cfg(OutputFormat.HTML).wants_html, cfg(OutputFormat.HTML).wants_json) == (True, False)
