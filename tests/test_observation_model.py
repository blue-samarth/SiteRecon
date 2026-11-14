import datetime as dt

from recon.analysis import ObservationBuilder
from recon.models import (
    CollectionMethod,
    Confidence,
    FindingState,
    Freshness,
    ModuleResult,
    ModuleStatus,
    Observation,
)
from recon.models.common import Severity
from recon.models.report import SCHEMA_VERSION, Finding
from tests.test_reporting import _dns

T0 = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
NOW = dt.datetime(2026, 11, 10, tzinfo=dt.UTC)
SA = dt.timedelta(days=30)


def _finding(confidence, state=None):
    return Finding(id="f", category="c", title="t", description="d", severity=Severity.HIGH,
                   confidence=confidence, state=state, source="s", subject="sub", timestamp=T0)


# ------------------------------------------------------------------ schema version

def test_schema_version_bumped_to_2_1():
    assert SCHEMA_VERSION == "2.1"


# ------------------------------------------------------------------ provenance stamping

def test_observation_builder_stamps_collection_method_and_freshness():
    r = ModuleResult(module="dns", status=ModuleStatus.SUCCESS, started_at=T0, finished_at=T0,
                     duration_ms=1, data=_dns())
    observations = ObservationBuilder("example.com", {"dns": r}).build()
    assert observations                                     # the dns module produced facts
    assert all(o.collection_method == CollectionMethod.DNS_QUERY for o in observations)
    assert all(o.freshness is Freshness.FRESH for o in observations)   # collected directly, at scan time
    assert all(o.collected_at == o.timestamp for o in observations)


# ------------------------------------------------------------------ backward compatibility

def test_pre_2_1_observation_json_loads_with_defaults():
    old = {"id": "a", "module": "dns", "target": "x", "type": "dns.record", "key": "A",
           "value": ["1.2.3.4"], "source": "DNS A", "timestamp": "2026-01-01T00:00:00Z", "status": "success"}
    o = Observation.model_validate(old)
    assert o.collection_method == CollectionMethod.UNKNOWN and o.freshness is Freshness.UNKNOWN
    assert o.observed_at is None and o.external_provider is None and o.expires_at is None
    assert o.limitations == [] and o.collected_at == o.timestamp


def test_pre_2_1_finding_json_gets_a_derived_state():
    old = {"id": "f", "category": "c", "title": "t", "description": "d", "severity": "medium",
           "confidence": "medium", "source": "s", "subject": "sub", "timestamp": "2026-01-01T00:00:00Z"}
    assert Finding.model_validate(old).state is FindingState.CONFIRMED


# ------------------------------------------------------------------ finding lifecycle

def test_finding_state_is_derived_from_confidence_when_unset():
    assert _finding(Confidence.HIGH).state is FindingState.CONFIRMED
    assert _finding(Confidence.MEDIUM).state is FindingState.CONFIRMED
    assert _finding(Confidence.LOW).state is FindingState.SUSPECTED


def test_explicit_finding_state_is_preserved():
    assert _finding(Confidence.HIGH, state=FindingState.RESOLVED).state is FindingState.RESOLVED
    assert _finding(Confidence.LOW, state=FindingState.FALSE_POSITIVE).state is FindingState.FALSE_POSITIVE


def test_from_confidence_never_invents_correlated_states():
    # SUSPECTED/CONFIRMED only — CORROBORATED/RESOLVED/FALSE_POSITIVE require the analysis engine
    assert {FindingState.from_confidence(c) for c in Confidence} == {FindingState.SUSPECTED, FindingState.CONFIRMED}


# ------------------------------------------------------------------ freshness evaluation

def _obs(**over):
    base = {"id": "a", "module": "m", "target": "x", "type": "t", "key": "k", "value": 1,
            "source": "s", "timestamp": NOW, "status": "success"}
    base.update(over)
    return Observation.model_validate(base)


def test_evaluate_freshness_fresh_and_stale():
    assert _obs(timestamp=NOW).evaluate_freshness(NOW, SA) is Freshness.FRESH
    assert _obs(timestamp=NOW - dt.timedelta(days=90)).evaluate_freshness(NOW, SA) is Freshness.STALE


def test_evaluate_freshness_historical_from_archive():
    archived = _obs(external_provider="wayback", timestamp=NOW, observed_at=NOW - dt.timedelta(days=2000))
    assert archived.evaluate_freshness(NOW, SA) is Freshness.HISTORICAL


def test_evaluate_freshness_uses_provider_expiry():
    expired = _obs(external_provider="shodan", timestamp=NOW - dt.timedelta(days=1),
                   expires_at=NOW - dt.timedelta(hours=1))
    valid = _obs(external_provider="shodan", timestamp=NOW, expires_at=NOW + dt.timedelta(days=1))
    assert expired.evaluate_freshness(NOW, SA) is Freshness.STALE
    assert valid.evaluate_freshness(NOW, SA) is Freshness.FRESH


# ------------------------------------------------------------------ confidence labels

def test_confidence_label_maps_to_evidence_vocabulary():
    assert (Confidence.HIGH.label, Confidence.MEDIUM.label, Confidence.LOW.label) == (
        "confirmed", "probable", "possible")
