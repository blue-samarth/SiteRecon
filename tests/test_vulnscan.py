import datetime as dt

import httpx
import respx

from recon.analysis.engine import AnalysisEngine
from recon.analysis.findings import FindingCollector
from recon.models import AssetData, AssetRecord, LibraryHit, VulnerabilityData, VulnerableComponent, VulnMatch
from recon.models.common import Confidence
from recon.modules.vulnscan import VulnerabilityScanner, npm_name, severity_from_osv
from recon.utils.http_client import SafeHttpClient
from recon.utils.scope import Scope
from tests.conftest import public_resolve

T0 = dt.datetime(2026, 11, 18, tzinfo=dt.UTC)


# ------------------------------------------------------------------ pure helpers

def test_npm_name_maps_display_names():
    assert npm_name("jQuery") == "jquery"
    assert npm_name("Vue.js") == "vue"
    assert npm_name("Moment.js") == "moment"
    assert npm_name("Tailwind CSS") == "tailwindcss"
    assert npm_name("Unknown Lib") == "unknown-lib"   # fallback slug


def test_severity_from_osv_prefers_label_then_cvss():
    assert severity_from_osv({"database_specific": {"severity": "HIGH"}}) == ("high", None)
    assert severity_from_osv({"severity": [{"type": "CVSS_V3", "score": "9.8"}]}) == ("critical", 9.8)
    assert severity_from_osv({"severity": [{"type": "CVSS_V3", "score": "5.4"}]}) == ("medium", 5.4)
    assert severity_from_osv({})[0] == "medium"   # advisory with no machine-readable severity


# ------------------------------------------------------------------ inventory + OSV lookup

def _assets():
    return AssetData(assets=[AssetRecord(url="https://app.test/app.js", kind="script", libraries=[
        LibraryHit(name="jQuery", category="javascript_library", version="1.12.4", confidence=Confidence.HIGH,
                   evidence="jQuery v1.12.4"),
        LibraryHit(name="React", category="frontend_framework", version=None, confidence=Confidence.MEDIUM,
                   evidence="@license React")])])   # no version → not queryable


def _client():
    return SafeHttpClient(Scope(hosts=["api.osv.dev"]), user_agent="t", retries=0, resolve=public_resolve)


def test_only_versioned_components_are_queried():
    scanner = VulnerabilityScanner(_assets(), _client())
    assert [(c.package, c.version) for c in scanner.components] == [("jquery", "1.12.4")]


async def test_osv_lookup_builds_vulnerable_components():
    scanner = VulnerabilityScanner(_assets(), _client())
    batch = {"results": [{"vulns": [{"id": "GHSA-rmxg-73gg-4p98"}]}]}
    detail = {"id": "GHSA-rmxg-73gg-4p98", "aliases": ["CVE-2020-11022"], "summary": "jQuery XSS",
              "database_specific": {"severity": "MEDIUM"},
              "references": [{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-rmxg-73gg-4p98"}]}
    with respx.mock:
        respx.post("https://api.osv.dev/v1/querybatch").mock(return_value=httpx.Response(200, json=batch))
        respx.get("https://api.osv.dev/v1/vulns/GHSA-rmxg-73gg-4p98").mock(
            return_value=httpx.Response(200, json=detail))
        async with scanner.client:
            data, errors = await scanner.collect()
    assert not errors
    assert data.components_checked == 1 and len(data.vulnerable) == 1
    comp = data.vulnerable[0]
    assert comp.package == "jquery" and comp.vulns[0].aliases == ["CVE-2020-11022"]
    assert comp.vulns[0].severity == "medium"


async def test_osv_failure_is_soft():
    scanner = VulnerabilityScanner(_assets(), _client())
    with respx.mock:
        respx.post("https://api.osv.dev/v1/querybatch").mock(return_value=httpx.Response(500))
        async with scanner.client:
            data, errors = await scanner.collect()
    assert data.vulnerable == [] and errors and errors[0].error_type == "osv_query_failed"


# ------------------------------------------------------------------ findings

def test_known_component_finding_uses_worst_severity():
    data = VulnerabilityData(components_checked=1, vulnerable=[VulnerableComponent(
        name="jQuery", package="jquery", ecosystem="npm", version="1.12.4",
        vulns=[VulnMatch(id="A", aliases=["CVE-1"], severity="medium", summary="xss"),
               VulnMatch(id="B", aliases=["CVE-2"], severity="high", summary="proto")])])
    f = FindingCollector(T0)
    AnalysisEngine._analyze_vulnerabilities(data, "app.test", f)
    finding = next(x for x in f.sorted() if x.id.startswith("vuln.known_component"))
    assert finding.severity.value == "high" and finding.id.endswith("jquery@1.12.4")
    assert finding.recommendation and finding.limitations
    assert any("CVE-2" in e for e in finding.evidence)
