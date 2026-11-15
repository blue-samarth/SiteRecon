import datetime as dt

from recon.analysis import RegressionAnalyzer
from recon.models import (
    AnalysisResult,
    Finding,
    ModuleResult,
    ModuleStatus,
    Observation,
    ReconReport,
    TargetInfo,
    ToolInfo,
)
from recon.models.common import Confidence, FindingState, Severity

T0 = dt.datetime(2026, 11, 15, tzinfo=dt.UTC)


def finding(fid, *, category="http", severity=Severity.HIGH, confidence=Confidence.HIGH, refs=()):
    return Finding(id=fid, category=category, title="t", description="d", severity=severity,
                   confidence=confidence, source="s", subject="sub", timestamp=T0, evidence_refs=list(refs))


def obs(oid, module):
    return Observation(id=oid, module=module, target="x", type="t", key="k", value=1, source="s",
                       timestamp=T0, status="success")


def report(scan_id, findings, *, http=ModuleStatus.SUCCESS, observations=()):
    sk = lambda n: ModuleResult.skipped(n, "x")
    return ReconReport(
        scan_id=scan_id, tool=ToolInfo(name="t", version="0", user_agent="u"),
        target=TargetInfo(input="x", hostname="x", scope=[]), options={}, started_at=T0, finished_at=T0,
        duration_ms=1, dns=sk("dns"), network=sk("network"),
        http=ModuleResult(module="http", status=http, started_at=T0, finished_at=T0, duration_ms=1, data=None),
        tls=sk("tls"), whois=sk("whois"), html=sk("html"), technology=sk("technology"),
        subdomains=sk("subdomains"), third_party=sk("third_party"),
        observations=list(observations), analysis=AnalysisResult(findings=findings))


# ------------------------------------------------------------------ lifecycle

def test_new_persisting_and_resolved():
    prev = report("s1", [finding("http.a:x"), finding("http.gone:x")])
    curr = report("s2", [finding("http.a:x"), finding("http.new:x", severity=Severity.MEDIUM)])
    delta = RegressionAnalyzer.analyze(prev, curr)
    assert delta.new == ["http.new:x"]
    assert delta.persisting == ["http.a:x"]
    assert [r.id for r in delta.resolved] == ["http.gone:x"]
    assert delta.resolved[0].state is FindingState.RESOLVED
    assert delta.counts() == {"new": 1, "persisting": 1, "resolved": 1}


def test_persisting_finding_is_corroborated():
    prev = report("s1", [finding("http.a:x")])
    curr = report("s2", [finding("http.a:x")])
    RegressionAnalyzer.analyze(prev, curr)
    assert curr.analysis.findings[0].state is FindingState.CORROBORATED   # reproduced across scans


def test_resolution_requires_the_module_to_have_run():
    # http.gone disappears, but http was SKIPPED this scan → not a resolution (missing data is not a fix)
    prev = report("s1", [finding("http.gone:x")])
    curr = report("s2", [], http=ModuleStatus.SKIPPED)
    assert RegressionAnalyzer.analyze(prev, curr).resolved == []
    # when http ran, the same disappearance IS a resolution
    curr_ok = report("s3", [], http=ModuleStatus.SUCCESS)
    assert [r.id for r in RegressionAnalyzer.analyze(prev, curr_ok).resolved] == ["http.gone:x"]


def test_active_and_intel_categories_are_never_called_resolved():
    # these have no passive module in _CATEGORY_MODULES, so their absence is never a "fix"
    prev = report("s1", [finding("active.x:h", category="active"), finding("intel.y:h", category="intel")])
    curr = report("s2", [])
    assert RegressionAnalyzer.analyze(prev, curr).resolved == []


def test_new_multi_source_finding_is_corroborated():
    refs = ["o1", "o2"]
    observations = [obs("o1", "http"), obs("o2", "crawler")]   # two distinct modules back the finding
    prev = report("s1", [])
    curr = report("s2", [finding("http.a:x", refs=refs)], observations=observations)
    RegressionAnalyzer.analyze(prev, curr)
    assert curr.analysis.findings[0].state is FindingState.CORROBORATED


def test_single_source_new_finding_keeps_derived_state():
    curr = report("s2", [finding("http.a:x", refs=["o1"])], observations=[obs("o1", "http")])
    RegressionAnalyzer.analyze(report("s1", []), curr)
    assert curr.analysis.findings[0].state is FindingState.CONFIRMED   # one source → not corroborated


def test_different_targets_rejected():
    import pytest
    a = report("s1", [])
    b = report("s2", [])
    b.target = TargetInfo(input="y", hostname="y", scope=[])
    with pytest.raises(ValueError, match="different targets"):
        RegressionAnalyzer.analyze(a, b)


# ------------------------------------------------------------------ interpreted change findings

from recon.analysis import ChangeAnalyzer, ScanComparator
from recon.models import Change, ChangeKind, ComparisonResult, ScanRef


def _changes(*changes):
    ref = ScanRef(scan_id="s", hostname="x", started_at=T0)
    return ComparisonResult(previous=ref, current=ref, changes=list(changes))


def _codes(comparison):
    return {f.id.split(":", 1)[0]: f for f in ChangeAnalyzer.analyze(comparison, T0)}


def test_change_findings_name_security_regressions():
    cmp = _changes(
        Change(kind=ChangeKind.REMOVED, type="http.security_header", target="https://x/",
               key="strict-transport-security", module="http", previous="max-age=31536000"),
        Change(kind=ChangeKind.MODIFIED, type="tls.protocol", target="x:443", key="version", module="tls",
               previous="TLSv1.3", current="TLSv1.2"),
        Change(kind=ChangeKind.MODIFIED, type="cookie", target="x", key="sid", module="cookies",
               previous={"secure": True, "http_only": True}, current={"secure": False, "http_only": True}),
        Change(kind=ChangeKind.MODIFIED, type="dnssec.status", target="x", key="status", module="dnssec",
               previous="signed", current="unsigned"),
        Change(kind=ChangeKind.ADDED, type="subdomain", target="x", key="new.x", module="subdomains"),
    )
    codes = _codes(cmp)
    assert codes["regression.security_header_removed"].severity.value == "medium"
    assert codes["regression.tls_downgrade"].severity.value == "medium"
    assert "secure" in " ".join(codes["regression.cookie_weakened"].evidence)
    assert "regression.dnssec_disabled" in codes
    assert codes["regression.new_subdomain"].severity.value == "informational"
    assert all(f.recommendation and f.limitations for f in codes.values())


def test_change_findings_ignore_improvements_and_non_security_changes():
    cmp = _changes(
        Change(kind=ChangeKind.MODIFIED, type="tls.protocol", target="x:443", key="v", module="tls",
               previous="TLSv1.2", current="TLSv1.3"),                         # upgrade
        Change(kind=ChangeKind.MODIFIED, type="cookie", target="x", key="s", module="cookies",
               previous={"secure": True}, current={"secure": True}),           # unchanged attrs
        Change(kind=ChangeKind.ADDED, type="dns.record", target="x", key="A", module="dns"),  # not a rule
    )
    assert ChangeAnalyzer.analyze(cmp, T0) == []


# ------------------------------------------------------------------ change findings via the scan history

def test_change_findings_are_merged_and_classified_new(tmp_path):
    from recon.orchestrator import ScanHistory
    from recon.storage import JsonScanStore

    def fqdn(r):   # the store requires a real hostname
        r.target = TargetInfo(input="example.com", hostname="example.com", scope=[])
        return r

    history = ScanHistory(JsonScanStore(tmp_path))
    hsts = Observation(id="o1", module="http", target="https://example.com/", type="http.security_header",
                       key="strict-transport-security", value="max-age=1", source="s", timestamp=T0,
                       status="success")
    history.record(fqdn(report("20260101T000000Z-aaaaaa", [], observations=[hsts])))   # HSTS present
    curr = fqdn(report("20260102T000000Z-bbbbbb", []))                                 # HSTS gone, http ran
    history.record(curr)
    ids = [f.id.split(":", 1)[0] for f in curr.analysis.findings]
    assert "regression.security_header_removed" in ids
    assert any(fid.startswith("regression.security_header_removed") for fid in curr.finding_changes.new)
