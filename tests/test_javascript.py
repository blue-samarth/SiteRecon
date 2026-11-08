import datetime as dt

import httpx
import respx

from recon.analysis import AnalysisEngine
from recon.models import Confidence, DetectionStatus, HtmlData, ResourceRef
from recon.models.assets import AssetData, AssetRecord, LibraryHit
from recon.modules import AssetCollector, BundleAnalyzer, FingerprintInputs, TechnologyFingerprinter, ThirdPartyCollector
from recon.utils.http_client import SafeHttpClient
from recon.utils.scope import Scope
from tests.conftest import public_resolve

STRIPE_SK = "sk_live_" + "51AbCdEfGhIjKlMnOpQrStUvWx"
STRIPE_SK_LONG = STRIPE_SK + "Yz"

BUNDLE = """/*! jQuery v3.7.1 | (c) OpenJS Foundation and other contributors | jquery.org/license */
!function(){var e="framer-motion";fetch("https://abc123.supabase.co/rest/v1/items?select=*");
var docs="https://reactjs.org/docs/error-decoder.html";var cdn='//cdn.example-cdn.net/x.js';
var api=`https://api.acme-shop.io/v2/users`;}();
//# sourceMappingURL=app.js.map
"""


def html_with(*refs):
    return HtmlData(source_url="https://example.com/", resources=[
        ResourceRef(url=u, kind=k, host=u.split("/")[2], same_site=u.split("/")[2].endswith("example.com"),
                    attributes=attrs) for u, k, attrs in refs])


def clients(allowed=(), cap=2_000_000):
    scope = Scope(roots=["example.com"], hosts=allowed)
    kw = dict(user_agent="t", retries=0, resolve=public_resolve)
    return SafeHttpClient(scope, max_response_bytes=cap, **kw), SafeHttpClient(scope, max_response_bytes=4096, **kw)


def test_analyzer_libraries_versions_and_strength():
    hits = {h.name: h for h in BundleAnalyzer.libraries(BUNDLE)}
    assert hits["jQuery"].version == "3.7.1" and hits["jQuery"].confidence is Confidence.HIGH
    assert hits["Framer Motion"].confidence is Confidence.LOW and hits["Framer Motion"].version is None
    assert "React" not in hits          # a docs URL is not a React marker


def test_analyzer_hosts_only_hostnames_and_no_noise():
    hosts = BundleAnalyzer.hosts(BUNDLE)
    assert hosts == ["abc123.supabase.co", "api.acme-shop.io", "cdn.example-cdn.net"]
    assert "reactjs.org" not in hosts and not any("/" in h for h in hosts)


def test_source_map_reference_detection():
    assert BundleAnalyzer.source_map(BUNDLE, None) == "app.js.map"
    assert BundleAnalyzer.source_map("a{}/*# sourceMappingURL=s.css.map */", None) == "s.css.map"
    assert BundleAnalyzer.source_map("x", "/maps/x.map") == "/maps/x.map"
    assert BundleAnalyzer.source_map("no map here", None) is None


@respx.mock
async def test_collector_scope_limits_and_source_maps():
    respx.get("https://example.com/assets/app.js").mock(return_value=httpx.Response(200, content=BUNDLE.encode()))
    respx.get("https://example.com/assets/app.js.map").mock(return_value=httpx.Response(
        200, content=b'{"version":3,"sources":["src/App.tsx"],"mappings":"AAAA"}' + b" " * 10_000))
    respx.get("https://example.com/assets/style.css").mock(return_value=httpx.Response(
        200, content=b"/*! tailwindcss v3.4.1 | MIT */ .a{--tw-ring:0}\n/*# sourceMappingURL=style.css.map */"))
    respx.get("https://example.com/assets/style.css.map").mock(return_value=httpx.Response(
        200, headers={"content-type": "text/html"}, content=b"<!doctype html><html>app shell</html>"))
    respx.get("https://static.allowed-cdn.net/lib.js").mock(return_value=httpx.Response(
        200, content=b"var x=1;//# sourceMappingURL=data:application/json;base64,eyJ9"))
    third = respx.get("https://cdn.jsdelivr.net/npm/x.js").mock(return_value=httpx.Response(200))
    html = html_with(("https://example.com/assets/app.js", "script", {"type": "module"}),
                     ("https://example.com/assets/style.css", "stylesheet", {}),
                     ("https://static.allowed-cdn.net/lib.js", "script", {}),
                     ("https://cdn.jsdelivr.net/npm/x.js", "script", {}),
                     ("https://example.com/img.png", "image", {}))
    client, map_client = clients(allowed=("static.allowed-cdn.net",))
    async with client, map_client:
        data, errors = await AssetCollector("example.com", client, map_client, html=html,
                                            allowed_hosts=("static.allowed-cdn.net",)).collect()

    by = {a.url: a for a in data.assets}
    assert set(by) == {"https://example.com/assets/app.js", "https://example.com/assets/style.css",
                       "https://static.allowed-cdn.net/lib.js"}
    assert not third.called and data.skipped[0].reason == "out_of_scope"
    app = by["https://example.com/assets/app.js"]
    assert app.source_map_status == "public" and app.sha256 and app.size == len(BUNDLE.encode())
    assert {h.name for h in app.libraries} >= {"jQuery", "Framer Motion"}
    assert by["https://example.com/assets/style.css"].source_map_status == "not_public"   # HTML fallback
    assert by["https://static.allowed-cdn.net/lib.js"].source_map_status == "inline"
    assert data.service_hosts["abc123.supabase.co"] == ["https://example.com/assets/app.js"]
    # endpoints are now inventoried (query values redacted)
    endpoint_values = {e.value for e in data.endpoints()}
    assert "https://abc123.supabase.co/rest/v1/items?select=%2A" in endpoint_values
    assert "https://api.acme-shop.io/v2/users" in endpoint_values
    dumped = data.model_dump_json()
    assert "src/App.tsx" not in dumped and "OpenJS Foundation" not in dumped   # no bundle or map contents
    assert errors == []


@respx.mock
async def test_collector_asset_and_byte_limits():
    for i in range(5):
        respx.get(f"https://example.com/a{i}.js").mock(return_value=httpx.Response(200, content=b"x" * 1000))
    html = html_with(*((f"https://example.com/a{i}.js", "script", {}) for i in range(5)))
    client, map_client = clients()
    async with client, map_client:
        data, _ = await AssetCollector("example.com", client, map_client, html=html, max_assets=3,
                                       max_total_bytes=1500, concurrency=1).collect()
    reasons = sorted(s.reason for s in data.skipped)
    assert reasons == ["asset_limit", "asset_limit", "byte_limit"]
    assert len(data.assets) == 2 and data.total_bytes == 2000


@respx.mock
async def test_out_of_scope_source_map_not_requested():
    respx.get("https://example.com/app.js").mock(return_value=httpx.Response(
        200, content=b"x//# sourceMappingURL=https://maps.other.test/app.js.map"))
    other = respx.get("https://maps.other.test/app.js.map").mock(return_value=httpx.Response(200))
    client, map_client = clients()
    async with client, map_client:
        data, _ = await AssetCollector("example.com", client, map_client,
                                       html=html_with(("https://example.com/app.js", "script", {}))).collect()
    assert data.assets[0].source_map_status == "out_of_scope" and not other.called


def test_bundle_evidence_grading_in_technology():
    hits = [(LibraryHit(name="jQuery", category="javascript_library", version="3.7.1", confidence=Confidence.HIGH,
                        evidence="marker"), "a.js"),
            (LibraryHit(name="Framer Motion", category="javascript_library", confidence=Confidence.LOW,
                        evidence="marker"), "a.js")]
    techs = {t.name: t for t in TechnologyFingerprinter().fingerprint(
        FingerprintInputs(bundle_hits=hits, bundle_hosts={"abc.supabase.co"})).technologies}
    assert techs["jQuery"].status is DetectionStatus.CONFIRMED and techs["jQuery"].version == "3.7.1"
    assert techs["Framer Motion"].status is DetectionStatus.POSSIBLE      # package name alone proves nothing
    assert techs["Supabase"].status is DetectionStatus.PROBABLE
    assert techs["Supabase"].evidence[0].source == "bundle_host"


def test_third_party_and_finding_from_assets():
    assets = AssetData(assets=[AssetRecord(url="https://example.com/app.js", kind="script", status_code=200,
                                           source_map_url="https://example.com/app.js.map", source_map_status="public")],
                       service_hosts={"abc.supabase.co": ["https://example.com/app.js"],
                                      "api.example.com": ["https://example.com/app.js"]})
    services = {s.provider: s for s in ThirdPartyCollector("example.com", dns=None, http=None, html=None, tls=None,
                                                           assets=assets).build().services}
    assert services["Supabase"].sources == ["bundle"] and "example.com" not in services
    result = AnalysisEngine(dt.datetime(2026, 1, 1, tzinfo=dt.UTC)).analyze(
        dns=None, network=None, http=None, tls=None, assets=assets)
    finding = next(f for f in result.findings if f.id.startswith("js.source_map_public"))
    assert finding.severity.value == "low" and finding.recommendation and finding.limitations


# ------------------------------------------------------------------ endpoints

def test_endpoint_extraction_redacts_queries_and_attaches_methods():
    from recon.modules import EndpointExtractor
    text = """
    fetch("/api/v1/users?token=SEKRET&page=2");
    axios.post('https://api.acme-shop.io/v2/orders', body);
    const g = `/graphql`;
    POST "/api/login";
    var img = "/static/logo.png";
    """
    refs = {r.value: r for r in EndpointExtractor.extract(text, "example.com", Scope.for_target("example.com"))}
    assert "/api/v1/users?token=[REDACTED]&page=2" in refs          # query redacted, path kept
    assert refs["/api/v1/users?token=[REDACTED]&page=2"].same_site is True
    assert "https://api.acme-shop.io/v2/orders" in refs
    assert refs["https://api.acme-shop.io/v2/orders"].same_site is False
    assert refs["/api/login"].method == "POST"
    assert "/static/logo.png" not in refs                            # not an API-ish path


# ------------------------------------------------------------------ client config

def test_firebase_config_shows_identifiers_and_redacts_key():
    from recon.modules import ClientConfigExtractor
    text = ('var c={apiKey:"AIzaSyA-REALLOOKINGKE-1234567890abcdefghi",authDomain:"demo.firebaseapp.com",'
            'projectId:"demo-proj",storageBucket:"demo.appspot.com",appId:"1:123:web:abc"};')
    [cfg] = ClientConfigExtractor.extract(text, "https://example.com/app.js")
    fields = {f.key: f for f in cfg.fields}
    assert cfg.provider == "Firebase"
    assert fields["projectId"].value == "demo-proj" and fields["projectId"].sensitive is False
    assert fields["apiKey"].sensitive is True and "AIzaSy" not in fields["apiKey"].value
    assert "REALLOOKINGKE" not in cfg.model_dump_json()              # key value never stored


def test_supabase_config_redacts_anon_key():
    from recon.modules import ClientConfigExtractor
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.c2lnbmF0dXJlLXZhbHVlLWhlcmU"
    text = f'const url="https://muvsftgwvzuttktqtkmc.supabase.co";const key="{jwt}";'
    [cfg] = ClientConfigExtractor.extract(text, "https://example.com/app.js")
    fields = {f.key: f for f in cfg.fields}
    assert cfg.provider == "Supabase" and fields["projectRef"].value == "muvsftgwvzuttktqtkmc"
    assert fields["anonKey"].sensitive is True and jwt not in cfg.model_dump_json()


# ------------------------------------------------------------------ secrets

def test_secret_scanner_redacts_values_and_excludes_public_keys():
    from recon.modules import SecretScanner
    text = f"""
    const stripe = "{STRIPE_SK}";
    const pub = "pk_live_51PublicPublishableKeyValue00";
    const aws = "AKIAIOSFODNN7EXAMPLE";
    const ga = "G-ABCDE12345";
    const gh = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
    const apiSecret = "s3cr3t-value-not-public-abcdef";
    """
    findings = {f.type: f for f in SecretScanner.scan(text, "https://example.com/app.js")}
    assert "stripe_secret_key" in findings and "aws_access_key_id" in findings and "github_token" in findings
    assert findings["stripe_secret_key"].severity == "high"
    joined = SecretScanner.scan(text, "https://example.com/app.js")
    dumped = str([f.model_dump() for f in joined])
    for raw in (STRIPE_SK, "AKIAIOSFODNN7EXAMPLE",
                "ghp_0123456789abcdefghijklmnopqrstuvwxyz", "s3cr3t-value-not-public"):
        assert raw not in dumped                                     # raw values never stored
    assert "stripe_publishable" not in findings and "pk_live_" not in dumped   # public key excluded
    assert all("sha256:" in f.redacted for f in joined)


def test_secret_scanner_context_without_value():
    from recon.modules import SecretScanner
    [finding] = [f for f in SecretScanner.scan('var awsSecretKey="AKIAIOSFODNN7EXAMPLE"', "a.js")
                 if f.type == "aws_access_key_id"]
    assert finding.context_key == "awsSecretKey" and "AKIA" not in (finding.context_key or "")


@respx.mock
async def test_findings_for_secret_and_config_from_collector():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.c2lnbmF0dXJldmFsdWVoZXJl"
    body = (f'fetch("https://muvsftgwvzuttktqtkmc.supabase.co/rest/v1/x");var k="{jwt}";'
            f'var s="{STRIPE_SK}";').encode()
    respx.get("https://example.com/app.js").mock(return_value=httpx.Response(200, content=body))
    client, map_client = clients()
    async with client, map_client:
        data, _ = await AssetCollector("example.com", client, map_client,
                                       html=html_with(("https://example.com/app.js", "script", {}))).collect()
    assert data.secret_count == 1 and data.endpoint_count >= 1
    asset = data.assets[0]
    assert asset.secrets[0].type == "stripe_secret_key"
    assert [c.provider for c in asset.client_configs] == ["Supabase"]

    result = AnalysisEngine(dt.datetime(2026, 1, 1, tzinfo=dt.UTC)).analyze(
        dns=None, network=None, http=None, tls=None, assets=data)
    by = {f.id.split(":")[0]: f for f in result.findings}
    assert by["js.exposed_secret"].severity.value == "high" and by["js.exposed_secret"].recommendation
    assert STRIPE_SK not in by["js.exposed_secret"].model_dump_json()
    assert "js.client_config" in by and by["js.client_config"].severity.value == "informational"


def test_supabase_service_role_jwt_is_flagged_but_anon_is_not():
    import base64
    import json

    from recon.modules import SecretScanner

    def jwt(role):
        enc = lambda d: base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).decode().rstrip("=")
        return f"{enc({'alg': 'HS256', 'typ': 'JWT'})}.{enc({'role': role})}.c2lnbmF0dXJldmFsdWVoZXJldG9rZW4"

    anon = {f.type for f in SecretScanner.scan(f'k="{jwt("anon")}"', "a.js")}
    service = {f.type for f in SecretScanner.scan(f'k="{jwt("service_role")}"', "a.js")}
    assert "jwt_hs256" not in anon and "supabase_service_role_jwt" not in anon   # anon is public
    assert "supabase_service_role_jwt" in service                                 # service_role is a leak
    finding = next(f for f in SecretScanner.scan(f'k="{jwt("service_role")}"', "a.js")
                   if f.type == "supabase_service_role_jwt")
    assert finding.severity == "high"


def test_reports_never_contain_raw_secret_values():
    from recon.models import ReconReport, ModuleResult, ModuleStatus, ToolInfo, TargetInfo, AnalysisResult
    from recon.models.assets import AssetData, AssetRecord, ClientConfig, ClientConfigValue, EndpointRef, SecretFinding
    from recon.reporting import HtmlReportWriter, MarkdownReportWriter
    from recon.utils import redact_secret

    raw = STRIPE_SK_LONG
    asset = AssetRecord(url="https://example.com/app.js", kind="script", status_code=200,
                        secrets=[SecretFinding(type="stripe_secret_key", source_asset="https://example.com/app.js",
                                               context_key="stripeKey", redacted=redact_secret(raw), severity="high")],
                        client_configs=[ClientConfig(provider="Firebase", kind="firebase",
                                                     source_asset="https://example.com/app.js",
                                                     fields=[ClientConfigValue(key="projectId", value="demo-proj"),
                                                             ClientConfigValue(key="apiKey", value=redact_secret("AIzaSECRET"),
                                                                               sensitive=True)])],
                        endpoints=[EndpointRef(value="/api/v1/users?token=[REDACTED]", host="example.com", same_site=True)])
    data = AssetData(assets=[asset], endpoint_count=1, secret_count=1)
    now = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)

    def mr(name, d=None):
        return ModuleResult(module=name, status=ModuleStatus.SUCCESS if d else ModuleStatus.SKIPPED,
                            started_at=now, finished_at=now, duration_ms=0, data=d)

    report = ReconReport(scan_id="20260101T000000Z-abcdef", tool=ToolInfo(name="t", version="0", user_agent="u"),
                         target=TargetInfo(input="example.com", hostname="example.com", scope=[]), options={},
                         started_at=now, finished_at=now, duration_ms=0,
                         dns=mr("dns"), network=mr("network"), http=mr("http"), tls=mr("tls"), whois=mr("whois"),
                         html=mr("html"), technology=mr("technology"), subdomains=mr("subdomains"),
                         third_party=mr("third_party"), javascript=mr("javascript", data), analysis=AnalysisResult())
    for rendered in (MarkdownReportWriter(report).render(), HtmlReportWriter(report).render(),
                     report.model_dump_json()):
        assert raw not in rendered and "AIzaSECRET" not in rendered
        assert "demo-proj" in rendered and "stripe_secret_key" in rendered   # non-secret info is shown
        assert "sha256:" in rendered                                         # fingerprint present


# ------------------------------------------------------------------ SRI verification

def test_integrity_verifier_matches_mismatches_and_edge_cases():
    import base64
    import hashlib

    from recon.modules import IntegrityVerifier

    body = b"console.log(1)"
    good384 = base64.b64encode(hashlib.sha384(body).digest()).decode()
    good256 = base64.b64encode(hashlib.sha256(body).digest()).decode()
    assert IntegrityVerifier.verify(f"sha384-{good384}", body, False) == ("verified", "sha384")
    # several hashes: valid if any matches
    assert IntegrityVerifier.verify(f"sha256-bogus sha384-{good384}", body, False) == ("verified", "sha384")
    # SRI options after '?' are ignored
    assert IntegrityVerifier.verify(f"sha256-{good256}?foo=bar", body, False) == ("verified", "sha256")
    assert IntegrityVerifier.verify(f"sha384-{good384}", b"tampered", False)[0] == "mismatch"
    assert IntegrityVerifier.verify(None, body, False) == ("absent", None)
    assert IntegrityVerifier.verify(f"sha384-{good384}", body, True) == ("unverifiable", None)
    assert IntegrityVerifier.verify("md5-abc", body, False) == ("unsupported_algorithm", None)


@respx.mock
async def test_collector_verifies_declared_integrity_and_reports_mismatch():
    import base64
    import hashlib

    good = b"/*! ok */var a=1;"
    digest = base64.b64encode(hashlib.sha384(good).digest()).decode()
    respx.get("https://example.com/good.js").mock(return_value=httpx.Response(200, content=good))
    respx.get("https://example.com/bad.js").mock(return_value=httpx.Response(200, content=b"var tampered=1;"))
    respx.get("https://example.com/plain.js").mock(return_value=httpx.Response(200, content=b"var p=1;"))
    html = html_with(("https://example.com/good.js", "script", {"integrity": f"sha384-{digest}"}),
                     ("https://example.com/bad.js", "script", {"integrity": f"sha384-{digest}"}),
                     ("https://example.com/plain.js", "script", {}))
    client, map_client = clients()
    async with client, map_client:
        data, _ = await AssetCollector("example.com", client, map_client, html=html).collect()
    by = {a.url: a for a in data.assets}
    assert by["https://example.com/good.js"].integrity_status == "verified"
    assert by["https://example.com/good.js"].integrity_algorithm == "sha384"
    assert by["https://example.com/bad.js"].integrity_status == "mismatch"
    assert by["https://example.com/plain.js"].integrity_status == "absent"
    assert data.integrity_verified == 1 and data.integrity_mismatched == 1

    result = AnalysisEngine(dt.datetime(2026, 1, 1, tzinfo=dt.UTC)).analyze(
        dns=None, network=None, http=None, tls=None, assets=data)
    finding = next(f for f in result.findings if f.id.startswith("js.integrity_mismatch"))
    assert finding.severity.value == "medium" and "bad.js" in " ".join(finding.evidence)


# ------------------------------------------------------------------ source maps

def test_source_map_reader_lists_sources_but_not_code():
    import json

    from recon.modules import SourceMapReader

    body = json.dumps({"version": 3, "sourceRoot": "", "sources": ["src/App.tsx", "src/admin/Secret.tsx"],
                       "sourcesContent": ["const SECRET_CODE = 1;", "// internal"], "mappings": "AAAA"}).encode()
    assert SourceMapReader.looks_like_map(body)
    count, sources = SourceMapReader.sources(body)
    assert count == 2 and sources == ["src/App.tsx", "src/admin/Secret.tsx"]
    assert "SECRET_CODE" not in str(sources)            # original code is never returned
    assert SourceMapReader.sources(b"not json") == (0, [])
    assert not SourceMapReader.looks_like_map(b"<!doctype html><html>app</html>")


@respx.mock
async def test_public_source_map_enumerates_exposed_files():
    import json

    respx.get("https://example.com/app.js").mock(return_value=httpx.Response(
        200, content=b"var a=1;\n//# sourceMappingURL=app.js.map"))
    respx.get("https://example.com/app.js.map").mock(return_value=httpx.Response(200, content=json.dumps({
        "version": 3, "sources": ["src/App.tsx", "src/admin/Billing.tsx"],
        "sourcesContent": ["TOPSECRETCODE"], "mappings": "AAAA"}).encode()))
    client, map_client = clients()
    async with client, map_client:
        data, _ = await AssetCollector("example.com", client, map_client,
                                       html=html_with(("https://example.com/app.js", "script", {}))).collect()
    asset = data.assets[0]
    assert asset.source_map_status == "public" and asset.source_map_source_count == 2
    assert asset.source_map_sources == ["src/App.tsx", "src/admin/Billing.tsx"]
    assert "TOPSECRETCODE" not in data.model_dump_json()      # map contents are discarded

    result = AnalysisEngine(dt.datetime(2026, 1, 1, tzinfo=dt.UTC)).analyze(
        dns=None, network=None, http=None, tls=None, assets=data)
    finding = next(f for f in result.findings if f.id.startswith("js.source_map_public"))
    assert "2 original source file(s)" in finding.description
    assert any("src/admin/Billing.tsx" in e for e in finding.evidence)


# ------------------------------------------------------------------ version recovery

def test_versions_recovered_from_versioned_asset_paths():
    from recon.models import DetectionStatus
    inputs = FingerprintInputs(urls=[
        "https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js",
        "https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.2/css/bootstrap.min.css",
        "https://unpkg.com/vue@3.4.21/dist/vue.global.js",
    ])
    techs = {t.name: t for t in TechnologyFingerprinter().fingerprint(inputs).technologies}
    assert techs["jQuery"].version == "3.7.1"
    assert techs["Bootstrap"].version == "5.3.2"
    assert techs["Vue.js"].version == "3.4.21"
    assert any(e.source == "versioned_path" for e in techs["jQuery"].evidence)
    # a bundle banner version still wins over path recovery
    hit = LibraryHit(name="jQuery", category="javascript_library", version="2.0.0",
                     confidence=Confidence.HIGH, evidence="banner")
    both = FingerprintInputs(urls=inputs.urls, bundle_hits=[(hit, "a.js")])
    assert TechnologyFingerprinter().fingerprint(both).technologies[0].status is DetectionStatus.CONFIRMED
    assert {t.name: t.version for t in TechnologyFingerprinter().fingerprint(both).technologies}["jQuery"] == "2.0.0"
