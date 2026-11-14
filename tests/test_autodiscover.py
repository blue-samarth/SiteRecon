import datetime as dt

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from recon.active import apply_synthesis, synthesize
from recon.active.authorization import AuthorizationFile, AutoDiscover
from recon.cli import app
from recon.models import (
    AnalysisResult,
    AssetData,
    AssetRecord,
    EndpointRef,
    ModuleResult,
    ModuleStatus,
    ReconReport,
    TargetInfo,
    ToolInfo,
)

T0 = dt.datetime(2026, 11, 11, tzinfo=dt.UTC)
runner = CliRunner()


def _report(endpoints, host="clusterheart.com"):
    sk = lambda n: ModuleResult.skipped(n, "x")
    ad = AssetData(assets=[AssetRecord(url=f"https://{host}/app.js", kind="script",
                                       endpoints=[EndpointRef(**e) for e in endpoints])])
    return ReconReport(
        tool=ToolInfo(name="t", version="0", user_agent="u"),
        target=TargetInfo(input=host, hostname=host, scope=[]), options={}, started_at=T0, finished_at=T0,
        duration_ms=1, dns=sk("dns"), network=sk("network"), http=sk("http"), tls=sk("tls"), whois=sk("whois"),
        html=sk("html"), technology=sk("technology"), subdomains=sk("subdomains"), third_party=sk("third_party"),
        javascript=ModuleResult(module="javascript", status=ModuleStatus.SUCCESS, started_at=T0, finished_at=T0,
                                duration_ms=1, data=ad), analysis=AnalysisResult())


AUTO = AutoDiscover(authorized_domains=["clusterheart.com"])


# ------------------------------------------------------------------ the boundary

def test_synthesis_tests_first_party_and_skips_third_party():
    report = _report([
        {"value": "https://api.clusterheart.com/v1/orders", "host": "api.clusterheart.com", "method": "POST"},
        {"value": "https://api.stripe.com/v1/charges", "host": "api.stripe.com"},          # third party
        {"value": "https://abc123.supabase.co/rest/v1/items", "host": "abc123.supabase.co"},  # third party
        {"value": "/relative", "host": None},                                               # relative, ignored
    ])
    s = synthesize(AUTO, target="clusterheart.com", report=report)
    assert [f.url for f in s.function_urls] == ["https://api.clusterheart.com/v1/orders"]
    assert s.third_party_hosts == ["abc123.supabase.co", "api.stripe.com"]   # discovered, NOT tested
    assert s.tls_hosts == ["clusterheart.com"]
    assert s.checks == ["tls_protocol_enum", "function_url_reachability", "external_intelligence"]


def test_email_burst_is_never_in_the_auto_check_set():
    s = synthesize(AUTO, target="clusterheart.com",
                   report=_report([{"value": "https://clusterheart.com/x", "host": "clusterheart.com"}]))
    assert "email_endpoint_rate_limit" not in s.checks and "backend_read_access" not in s.checks


def test_checks_drop_when_their_targets_are_absent():
    # no first-party endpoints → no reachability check; target not first-party → no tls
    s = synthesize(AUTO, target="other.com", report=_report([]))
    assert "function_url_reachability" not in s.checks and "tls_protocol_enum" not in s.checks
    assert s.checks == ["external_intelligence"] and s.tls_hosts == []


def test_subdomain_of_authorized_domain_is_first_party():
    s = synthesize(AUTO, target="app.clusterheart.com",
                   report=_report([{"value": "https://cdn.clusterheart.com/a", "host": "cdn.clusterheart.com"}]))
    assert s.tls_hosts == ["app.clusterheart.com"]
    assert [f.url for f in s.function_urls] == ["https://cdn.clusterheart.com/a"]


def test_no_report_still_yields_a_minimal_first_party_run():
    s = synthesize(AUTO, target="clusterheart.com", report=None)
    assert s.tls_hosts == ["clusterheart.com"] and s.function_urls == []
    assert "external_intelligence" in s.checks


# ------------------------------------------------------------------ effective authorization

def test_apply_synthesis_builds_runnable_effective_auth():
    base = AuthorizationFile(target="clusterheart.com", authorized_by="CI", authorized_on="2026-11-11",
                             window={"start": "2026-11-10T00:00:00Z", "end": "2026-12-01T00:00:00Z"},
                             auto_discover=AUTO)
    s = synthesize(AUTO, target="clusterheart.com",
                   report=_report([{"value": "https://api.clusterheart.com/o", "host": "api.clusterheart.com"}]))
    eff = apply_synthesis(base, s)
    assert "api.clusterheart.com" in eff.scope.normalized_hosts()
    assert eff.scope.tls_authorized("clusterheart.com")
    assert [t.url for t in eff.function_urls] == ["https://api.clusterheart.com/o"]
    assert "function_url_reachability" in eff.checks_enabled and "tls_protocol_enum" in eff.checks_enabled


# ------------------------------------------------------------------ authorization model

def test_auto_discover_requires_a_domain():
    with pytest.raises(ValidationError, match="authorized_domains"):
        AuthorizationFile(target="x", authorized_by="a", authorized_on="2026-01-01",
                          window={"start": "2026-11-10T00:00:00Z", "end": "2026-11-11T00:00:00Z"},
                          auto_discover={"authorized_domains": []})


# ------------------------------------------------------------------ CLI dry-run

AUTO_YAML = """
target: clusterheart.com
authorized_by: CI
authorized_on: "2026-11-11"
window: {start: "2026-11-10T00:00:00Z", end: "2026-12-01T00:00:00Z"}
auto_discover:
  authorized_domains: [clusterheart.com]
"""


SUPA_HOST = "ref0abcdef0123456789.supabase.co"
ANON = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.s1gnatureAbcdef0123"


def _report_with_backend():
    from recon.models import ClientConfig, ClientConfigValue
    cfg = ClientConfig(provider="Supabase", kind="supabase", source_asset="https://clusterheart.com/app.js",
                       fields=[ClientConfigValue(key="projectRef", value="ref0abcdef0123456789", sensitive=False),
                               ClientConfigValue(key="anonKey", value=ANON, sensitive=False)])   # retained
    from recon.models import AssetData, AssetRecord, EndpointRef, ModuleResult, ModuleStatus
    from recon.models import ReconReport as RR, TargetInfo as TI, ToolInfo as TO, AnalysisResult as AR
    sk = lambda n: ModuleResult.skipped(n, "x")
    ad = AssetData(assets=[AssetRecord(url="https://clusterheart.com/app.js", kind="script", client_configs=[cfg],
        endpoints=[EndpointRef(value="https://api.clusterheart.com/o", host="api.clusterheart.com"),
                   EndpointRef(value=f"https://{SUPA_HOST}/rest/v1/profiles", host=SUPA_HOST),
                   EndpointRef(value="https://api.stripe.com/charges", host="api.stripe.com")])])
    return RR(tool=TO(name="t", version="0", user_agent="u"),
              target=TI(input="clusterheart.com", hostname="clusterheart.com", scope=[]), options={},
              started_at=T0, finished_at=T0, duration_ms=1, dns=sk("dns"), network=sk("network"), http=sk("http"),
              tls=sk("tls"), whois=sk("whois"), html=sk("html"), technology=sk("technology"),
              subdomains=sk("subdomains"), third_party=sk("third_party"),
              javascript=ModuleResult(module="javascript", status=ModuleStatus.SUCCESS, started_at=T0,
                                      finished_at=T0, duration_ms=1, data=ad), analysis=AR())


def test_complete_mode_adds_embedded_backend_ip_trust_and_full_checks():
    s = synthesize(AUTO, target="clusterheart.com", report=_report_with_backend(), complete=True)
    assert s.checks == ["tls_protocol_enum", "function_url_reachability", "client_ip_header_trust",
                        "backend_read_access", "external_intelligence"]
    assert "email_endpoint_rate_limit" not in s.checks            # never
    assert [(b.kind, b.host, b.resources) for b in s.backends] == [("supabase", SUPA_HOST, ["profiles"])]
    assert s.backends[0].credential == ANON                       # retained public key used
    assert [t.url for t in s.ip_trust_endpoints] == ["https://api.clusterheart.com/o"]
    assert SUPA_HOST in s.scope_hosts                             # backend reachable
    assert s.third_party_hosts == ["api.stripe.com"]             # unrelated third party, NOT the embedded backend


def test_default_mode_does_not_synthesize_backends():
    s = synthesize(AUTO, target="clusterheart.com", report=_report_with_backend(), complete=False)
    assert s.backends == [] and "backend_read_access" not in s.checks and s.ip_trust_endpoints == []


def test_anon_key_retained_only_with_flag():
    from recon.modules.javascript import ClientConfigExtractor
    text = f'const u="https://{SUPA_HOST}";const k="{ANON}";'
    redacted = next(f for f in ClientConfigExtractor.extract(text, "a.js")[0].fields if f.key == "anonKey")
    assert redacted.sensitive and "REDACTED" in redacted.value
    kept = next(f for f in ClientConfigExtractor.extract(text, "a.js", retain=True)[0].fields if f.key == "anonKey")
    assert not kept.sensitive and kept.value == ANON


def test_bypass_sec_requires_auto_discover(tmp_path):
    plain = tmp_path / "plain.yaml"
    plain.write_text("target: clusterheart.com\nauthorized_by: x\nauthorized_on: \"2026-11-13\"\n"
                     "window: {start: \"2026-11-10T00:00:00Z\", end: \"2026-12-01T00:00:00Z\"}\n"
                     "scope: {hosts: [clusterheart.com]}\nchecks_enabled: [external_intelligence]\n", encoding="utf-8")
    res = runner.invoke(app, ["active", "clusterheart.com", "-A", str(plain), "--bypass-sec",
                              "--now", "2026-11-13T12:00:00Z"])
    assert res.exit_code == 2 and "requires an auto_discover" in res.output


def test_cli_dry_run_reports_auto_discover(tmp_path):
    path = tmp_path / "auto.yaml"
    path.write_text(AUTO_YAML, encoding="utf-8")
    res = runner.invoke(app, ["active", "clusterheart.com", "-A", str(path), "--dry-run",
                              "--now", "2026-11-11T12:00:00Z"])
    assert res.exit_code == 0, res.output
    flat = " ".join(res.output.split())   # rich wraps long lines in a narrow test terminal
    assert "Auto-discover enabled" in flat and "Third-party hosts are never tested" in flat
