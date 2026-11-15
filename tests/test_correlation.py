import datetime as dt

from recon.analysis import calibrate, correlate
from recon.models import Finding, Observation
from recon.models.common import Confidence, Freshness, Severity

T0 = dt.datetime(2026, 11, 15, tzinfo=dt.UTC)


def finding(fid, *, title, subject="sub", severity=Severity.LOW, confidence=Confidence.HIGH, refs=()):
    return Finding(id=fid, category="c", title=title, description="d", severity=severity, confidence=confidence,
                   source="s", subject=subject, timestamp=T0, evidence=[fid], evidence_refs=list(refs))


def obs(oid, module, *, provider=None, freshness=Freshness.FRESH):
    return Observation(id=oid, module=module, target="x", type="t", key="k", value=1, source="s",
                       timestamp=T0, external_provider=provider, freshness=freshness, status="success")


# ------------------------------------------------------------------ correlation (dedup)

def test_correlate_merges_same_issue_across_modules():
    out = correlate([finding("a:sub", title="Same Issue", severity=Severity.LOW, confidence=Confidence.MEDIUM),
                     finding("b:sub", title="same issue", severity=Severity.HIGH, confidence=Confidence.HIGH)])
    assert len(out) == 1
    assert out[0].severity is Severity.HIGH and out[0].confidence is Confidence.HIGH   # strongest kept
    assert out[0].evidence == ["a:sub", "b:sub"]                                       # evidence unioned


def test_correlate_keeps_distinct_issues():
    out = correlate([finding("a:sub", title="Issue A"), finding("b:sub", title="Issue B"),
                     finding("c:other", title="Issue A", subject="other")])  # same title, other subject → kept
    assert len(out) == 3


# ------------------------------------------------------------------ calibration

def test_calibrate_lowers_confidence_of_stale_external_only_evidence():
    f = finding("a:sub", title="Indexed vuln", confidence=Confidence.HIGH, refs=["o1"])
    calibrate([f], [obs("o1", "shodan_internetdb", provider="Shodan", freshness=Freshness.HISTORICAL)])
    assert f.confidence is Confidence.MEDIUM     # HIGH → MEDIUM (one level down)


def test_calibrate_leaves_fresh_or_local_evidence_alone():
    f = finding("a:sub", title="Local", confidence=Confidence.HIGH, refs=["o1"])
    calibrate([f], [obs("o1", "http", freshness=Freshness.FRESH)])
    assert f.confidence is Confidence.HIGH

    g = finding("b:sub", title="Mixed", confidence=Confidence.HIGH, refs=["o1", "o2"])
    calibrate([g], [obs("o1", "shodan_internetdb", provider="Shodan", freshness=Freshness.HISTORICAL),
                    obs("o2", "http", freshness=Freshness.FRESH)])   # not ALL stale/external
    assert g.confidence is Confidence.HIGH


def test_calibrate_does_not_touch_findings_without_resolvable_evidence():
    f = finding("a:sub", title="No refs", confidence=Confidence.HIGH)   # no evidence_refs
    calibrate([f], [])
    assert f.confidence is Confidence.HIGH
