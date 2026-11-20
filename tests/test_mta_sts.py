from __future__ import annotations

import datetime as dt

import pytest
import respx
from httpx import Response

from recon.analysis import AnalysisEngine, FindingCollector, ObservationBuilder
from recon.analysis.engine import mta_sts_covers, mta_sts_uncovered
from recon.models import (
    CaaAnalysis,
    DmarcAnalysis,
    DnsData,
    DnsQueryStatus,
    EmailSecurity,
    EmailTransportSecurity,
    ModuleResult,
    ModuleStatus,
    MtaStsPolicy,
    ResourcesData,
    SpfAnalysis,
)
from recon.modules import ResourcesCollector
from recon.modules.resources import MtaStsParser
from recon.utils import SafeHttpClient, Scope
from tests.conftest import public_resolve

T0 = dt.datetime(2026, 11, 20, tzinfo=dt.UTC)
POLICY_URL = "https://mta-sts.example.com/.well-known/mta-sts.txt"
ENFORCING = "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: *.mail.example.com\nmax_age: 604800\n"


def parsed(text: str) -> MtaStsPolicy:
    info = MtaStsPolicy(url=POLICY_URL, present=True)
    MtaStsParser.parse(text, info)
    return info


def dns_of(transport: EmailTransportSecurity) -> DnsData:
    return DnsData(hostname="example.com", queries={},
                   email=EmailSecurity(spf=SpfAnalysis(lookup_status=DnsQueryStatus.NODATA),
                                       dmarc=DmarcAnalysis(name="_dmarc.example.com",
                                                           lookup_status=DnsQueryStatus.NXDOMAIN),
                                       dkim_selectors_checked=[], transport=transport),
                   caa=CaaAnalysis(records=[], complete=True))


def codes(transport: EmailTransportSecurity, policy: MtaStsPolicy | None) -> dict[str, object]:
    f = FindingCollector(T0)
    resources = ResourcesData(origin="https://example.com", mta_sts=policy) if policy else None
    AnalysisEngine._analyze_email_transport(dns_of(transport), resources, f)
    return {x.id.split(":", 1)[0]: x for x in f.sorted()}


MX = EmailTransportSecurity(mx_hosts=["mx1.example.com"], mta_sts_present=True)
NO_RECORD = EmailTransportSecurity(mx_hosts=["mx1.example.com"], mta_sts_present=False)


# ------------------------------------------------------------------ parsing

def test_a_well_formed_policy_parses():
    p = parsed(ENFORCING)
    assert p.valid and p.version == "STSv1" and p.mode == "enforce" and p.max_age == 604800
    assert p.mx == ["mx1.example.com", "*.mail.example.com"] and p.parse_errors == []


def test_parsing_is_case_and_whitespace_tolerant_where_the_rfc_is():
    p = parsed("Version: STSv1\n  MODE:  Enforce  \nMX: MX1.Example.COM.\nmax_age: 604800\n")
    assert p.valid and p.mode == "enforce" and p.mx == ["mx1.example.com"]   # trailing dot normalized


@pytest.mark.parametrize("text,expected", [
    ("mode: enforce\nmx: a.example.com\nmax_age: 100\n", "version must be 'STSv1'"),
    ("version: STSv1\nmx: a.example.com\nmax_age: 100\n", "no mode field"),
    ("version: STSv1\nmode: enfroce\nmx: a.example.com\nmax_age: 100\n", "mode must be enforce"),
    ("version: STSv1\nmode: enforce\nmx: a.example.com\n", "no max_age field"),
    ("version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: 99999999999\n", "max_age must be between"),
    ("version: STSv1\nmode: enforce\nmax_age: 100\n", "no mx patterns"),
])
def test_a_policy_senders_would_reject_is_marked_invalid(text, expected):
    p = parsed(text)
    assert not p.valid and any(expected in e for e in p.parse_errors), p.parse_errors


def test_withdrawal_needs_no_mx_list():
    p = parsed("version: STSv1\nmode: none\nmax_age: 1\n")
    assert p.valid and p.mode == "none"          # 'none' is the documented way to retract a policy


def test_unparseable_lines_are_recorded_not_silently_dropped():
    p = parsed(ENFORCING + "this line has no colon\n")
    assert any("unparseable line" in e for e in p.parse_errors) and not p.valid


def test_the_mx_list_is_capped():
    text = "version: STSv1\nmode: enforce\nmax_age: 604800\n" + "".join(
        f"mx: mx{i}.example.com\n" for i in range(MtaStsParser.MAX_MX + 50))
    assert len(parsed(text).mx) == MtaStsParser.MAX_MX


# ------------------------------------------------------------------ mx coverage (RFC 8461 §4.1)

@pytest.mark.parametrize("pattern,host,covered", [
    ("mx1.example.com", "mx1.example.com", True),
    ("mx1.example.com", "MX1.Example.com.", True),
    ("mx1.example.com", "mx2.example.com", False),
    ("*.example.com", "mx1.example.com", True),
    ("*.example.com", "example.com", False),            # a wildcard needs a label to consume
    ("*.example.com", "a.b.example.com", False),        # and matches exactly one
    ("", "mx1.example.com", False),
    ("*.example.com", "", False),
])
def test_wildcards_match_exactly_one_label(pattern, host, covered):
    assert mta_sts_covers(pattern, host) is covered


def test_uncovered_lists_the_mx_hosts_the_policy_forgets():
    p = parsed(ENFORCING)
    hosts = ["mx1.example.com", "relay.mail.example.com", "backup.other.net"]
    assert mta_sts_uncovered(p, hosts) == ["backup.other.net"]


# ------------------------------------------------------------------ the record and the policy together

def test_a_record_without_a_fetchable_policy_enforces_nothing():
    absent = MtaStsPolicy(url=POLICY_URL, present=False, status_code=404)
    found = codes(MX, absent)
    assert "email.mta_sts_policy_unreachable" in found
    assert "email.mta_sts_missing" not in found           # the record exists; that is not the fault
    assert "404" in " ".join(found["email.mta_sts_policy_unreachable"].evidence)


def test_a_policy_nobody_announces_is_reported_instead_of_plain_absence():
    found = codes(NO_RECORD, parsed(ENFORCING))
    assert "email.mta_sts_policy_without_record" in found
    assert "email.mta_sts_missing" not in found           # sharper: the work is one DNS record away
    assert "one DNS record" in found["email.mta_sts_policy_without_record"].description


def test_no_record_and_no_policy_is_still_the_plain_missing_finding():
    assert "email.mta_sts_missing" in codes(NO_RECORD, MtaStsPolicy(url=POLICY_URL, present=False))


def test_an_enforcing_policy_that_covers_every_mx_is_quiet():
    found = codes(MX, parsed(ENFORCING))
    assert not [c for c in found if c.startswith("email.mta_sts")]


# ------------------------------------------------------------------ what the DNS record alone cannot say

def test_testing_mode_is_reported_because_it_enforces_nothing():
    found = codes(MX, parsed(ENFORCING.replace("enforce", "testing")))
    assert "email.mta_sts_testing_mode" in found
    finding = found["email.mta_sts_testing_mode"]
    assert finding.severity.value == "low" and "prevents no downgrade" in finding.description
    assert finding.recommendation and "enforce" in finding.recommendation


def test_a_withdrawn_policy_is_informational_not_a_problem():
    found = codes(MX, parsed("version: STSv1\nmode: none\nmax_age: 1\n"))
    assert found["email.mta_sts_withdrawn"].severity.value == "informational"


def test_an_invalid_policy_short_circuits_the_mode_and_coverage_checks():
    found = codes(MX, parsed("mode: enfroce\n"))
    assert "email.mta_sts_policy_invalid" in found
    assert not any(c in found for c in ("email.mta_sts_testing_mode", "email.mta_sts_mx_mismatch"))


def test_an_uncovered_mx_under_enforce_is_a_delivery_failure_not_a_weakness():
    transport = EmailTransportSecurity(mx_hosts=["mx1.example.com", "backup.other.net"], mta_sts_present=True)
    finding = codes(transport, parsed(ENFORCING))["email.mta_sts_mx_mismatch"]
    assert finding.severity.value == "medium"
    assert "delivery failure" in finding.description
    assert "backup.other.net" in " ".join(finding.evidence)


def test_the_same_gap_in_testing_mode_is_only_a_warning():
    transport = EmailTransportSecurity(mx_hosts=["mx1.example.com", "backup.other.net"], mta_sts_present=True)
    finding = codes(transport, parsed(ENFORCING.replace("enforce", "testing")))["email.mta_sts_mx_mismatch"]
    assert finding.severity.value == "low" and "moment the policy moves to enforce" in finding.description


def test_a_policy_cached_for_under_a_day_is_flagged():
    found = codes(MX, parsed(ENFORCING.replace("604800", "3600")))
    assert "email.mta_sts_short_max_age" in found
    assert "1209600" in " ".join(found["email.mta_sts_short_max_age"].evidence)
    assert "email.mta_sts_short_max_age" not in codes(MX, parsed(ENFORCING))


def test_every_mta_sts_finding_carries_a_recommendation_and_a_limitation():
    transport = EmailTransportSecurity(mx_hosts=["mx1.example.com", "backup.other.net"], mta_sts_present=True)
    found = codes(transport, parsed(ENFORCING.replace("604800", "60").replace("enforce", "testing")))
    mta = {code: f for code, f in found.items() if code.startswith("email.mta_sts")}
    assert len(mta) == 3            # testing mode, uncovered MX and the short max_age
    for finding in mta.values():
        assert finding.recommendation and finding.limitations


# ------------------------------------------------------------------ fetching

def client_for(host="example.com"):
    return SafeHttpClient(Scope.for_target(host), user_agent="t", retries=0, resolve=public_resolve)


def origin_absent():
    # Answer 404 for every well-known file at the origin, leaving only the policy under test.
    respx.route(host="example.com").mock(return_value=Response(404))


@respx.mock
async def test_the_policy_is_fetched_from_its_own_host_when_the_domain_has_mx():
    respx.get(POLICY_URL).mock(return_value=Response(200, text=ENFORCING,
                                                     headers={"content-type": "text/plain"}))
    origin_absent()
    async with client_for() as client:
        data, _ = await ResourcesCollector("example.com", client, "https://example.com",
                                           mx_hosts=["mx1.example.com"]).collect()
    assert data.mta_sts.present and data.mta_sts.valid and data.mta_sts.mode == "enforce"
    assert data.mta_sts.url == POLICY_URL and data.mta_sts.not_applicable is None


@respx.mock
async def test_without_mx_records_the_policy_is_not_requested_at_all():
    route = respx.get(POLICY_URL).mock(return_value=Response(200, text=ENFORCING))
    origin_absent()
    async with client_for() as client:
        data, _ = await ResourcesCollector("example.com", client, "https://example.com").collect()
    assert not route.called                      # no sender consults a policy without MX
    assert data.mta_sts.present is False and "no MX records" in data.mta_sts.not_applicable


@respx.mock
async def test_an_html_error_page_is_a_soft_404_not_a_policy():
    respx.get(POLICY_URL).mock(return_value=Response(200, text="<!doctype html><html>nope</html>",
                                                     headers={"content-type": "text/html"}))
    origin_absent()
    async with client_for() as client:
        data, _ = await ResourcesCollector("example.com", client, "https://example.com",
                                           mx_hosts=["mx1.example.com"]).collect()
    assert data.mta_sts.soft_404 and not data.mta_sts.present


# ------------------------------------------------------------------ observations

def test_the_policy_mode_becomes_an_observation_so_a_regression_shows_in_the_diff():
    data = ResourcesData(origin="https://example.com", mta_sts=parsed(ENFORCING))
    r = ModuleResult(module="resources", status=ModuleStatus.SUCCESS, started_at=T0, finished_at=T0,
                     duration_ms=1.0, data=data)
    obs = {(o.type, o.key): o for o in ObservationBuilder("example.com", {"resources": r}).build()}
    value = obs[("resource", "mta_sts")].value
    assert value["mode"] == "enforce" and value["present"] is True and value["valid"] is True
    assert value["mx"] == ["*.mail.example.com", "mx1.example.com"]


def test_a_policy_that_was_never_applicable_records_no_observation():
    data = ResourcesData(origin="https://example.com",
                         mta_sts=MtaStsPolicy(url=POLICY_URL, not_applicable="no MX records"))
    r = ModuleResult(module="resources", status=ModuleStatus.SUCCESS, started_at=T0, finished_at=T0,
                     duration_ms=1.0, data=data)
    keys = {(o.type, o.key) for o in ObservationBuilder("example.com", {"resources": r}).build()}
    assert ("resource", "mta_sts") not in keys   # not fetched is not the same as not present
