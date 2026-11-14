import datetime as dt

from recon.active import build_authorization_draft, load_authorization
from recon.active.scaffold import discover_candidates
from recon.models import (
    AnalysisResult,
    AssetData,
    AssetRecord,
    ClientConfig,
    ClientConfigValue,
    EndpointRef,
    ModuleResult,
    ModuleStatus,
    ReconReport,
    TargetInfo,
    ToolInfo,
)

T0 = dt.datetime(2026, 11, 11, tzinfo=dt.UTC)


def _report(assets: AssetData | None, host: str = "jobbie.io") -> ReconReport:
    sk = lambda n: ModuleResult.skipped(n, "x")
    js = (ModuleResult(module="javascript", status=ModuleStatus.SUCCESS, started_at=T0, finished_at=T0,
                       duration_ms=1, data=assets) if assets is not None else sk("javascript"))
    return ReconReport(
        tool=ToolInfo(name="t", version="0", user_agent="u"),
        target=TargetInfo(input=host, hostname=host, scope=[]), options={}, started_at=T0, finished_at=T0,
        duration_ms=1, dns=sk("dns"), network=sk("network"), http=sk("http"), tls=sk("tls"), whois=sk("whois"),
        html=sk("html"), technology=sk("technology"), subdomains=sk("subdomains"), third_party=sk("third_party"),
        javascript=js, analysis=AnalysisResult())


def supabase_assets():
    cfg = ClientConfig(provider="Supabase", kind="supabase", source_asset="https://jobbie.io/app.js",
                       fields=[ClientConfigValue(key="url", value="https://ref0.supabase.co", sensitive=False),
                               ClientConfigValue(key="anonKey", value="[REDACTED]", sensitive=True)])
    asset = AssetRecord(url="https://jobbie.io/app.js", kind="script", client_configs=[cfg], endpoints=[
        EndpointRef(value="https://api.jobbie.io/v1/orders", host="api.jobbie.io", method="POST"),
        EndpointRef(value="/relative/path", host=None)])   # relative → not a function_url candidate
    return AssetData(assets=[asset], service_hosts={"ref0.supabase.co": ["https://jobbie.io/app.js"],
                                                    "api.jobbie.io": ["https://jobbie.io/app.js"]})


# ------------------------------------------------------------------ discovery

def test_discovers_supabase_backend_and_absolute_endpoints():
    c = discover_candidates(_report(supabase_assets()))
    assert [(b.kind, b.host) for b in c.backends] == [("supabase", "ref0.supabase.co")]
    assert c.function_urls == ["https://api.jobbie.io/v1/orders"]   # relative path excluded
    assert c.scope_hosts[0] == "jobbie.io" and "ref0.supabase.co" in c.scope_hosts
    assert c.tls_hosts == ["jobbie.io"]


def test_discovers_firebase_project_and_adds_firestore_scope_host():
    cfg = ClientConfig(provider="Firebase", kind="firebase", source_asset="a.js",
                       fields=[ClientConfigValue(key="projectId", value="my-app-1234", sensitive=False)])
    assets = AssetData(assets=[AssetRecord(url="https://jobbie.io/a.js", kind="script", client_configs=[cfg])])
    c = discover_candidates(_report(assets))
    assert [(b.kind, b.project_id) for b in c.backends] == [("firebase", "my-app-1234")]
    assert "firestore.googleapis.com" in c.scope_hosts


def test_no_assets_yields_only_the_target():
    c = discover_candidates(_report(None))
    assert c.backends == [] and c.function_urls == [] and c.scope_hosts == ["jobbie.io"]


# ------------------------------------------------------------------ draft rendering

def test_draft_is_valid_and_inert():
    draft = build_authorization_draft(_report(supabase_assets()), now=T0)
    import tempfile
    import pathlib
    path = pathlib.Path(tempfile.mkdtemp()) / "draft.yaml"
    path.write_text(draft)
    auth = load_authorization(path)
    assert auth.checks_enabled == []                       # nothing enabled → inert
    assert auth.target == "jobbie.io" and "ref0.supabase.co" in auth.scope.normalized_hosts()


def test_draft_prefills_candidates_but_leaves_human_only_blanks():
    draft = build_authorization_draft(_report(supabase_assets()), now=T0)
    assert "host: ref0.supabase.co" in draft                     # discovered backend pre-filled
    assert "https://api.jobbie.io/v1/orders" in draft            # discovered endpoint pre-filled
    assert "FILL ME" in draft                                    # credential/resources left blank
    assert "state_changing: false   # FILL ME" in draft          # human-only label, not guessed
    assert "confirmed_no_real_delivery: true" in draft           # email template present (commented)
    assert "discovery is not ownership" in draft                 # the review banner
    assert 'authorized_by: "FILL ME' in draft


def test_draft_without_candidates_still_valid_with_templates():
    draft = build_authorization_draft(_report(None), now=T0)
    import tempfile
    import pathlib
    path = pathlib.Path(tempfile.mkdtemp()) / "draft.yaml"
    path.write_text(draft)
    assert load_authorization(path).checks_enabled == []
    assert "# backends:" in draft and "# function_urls:" in draft   # commented templates when nothing found
