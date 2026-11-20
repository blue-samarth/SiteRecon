'''
Managed-cloud detection: host/path signature matching, the inventory built from collected evidence, and
the findings it produces.

Nothing here performs I/O: the inventory is derived from evidence the passive scan already holds, and the
tests assert that the findings say "referenced", never "exposed".
'''

import pytest

from recon.analysis import AnalysisEngine, ObservationBuilder, match_cloud
from recon.analysis.cloud_signatures import CLOUD_SIGNATURES
from recon.models import (
    AssetData,
    AssetRecord,
    Confidence,
    EndpointRef,
    HtmlData,
    ModuleResult,
    ModuleStatus,
    ResourceRef,
    Severity,
    utcnow,
)
from recon.models.crawl import CrawlData, CrawledPage
from recon.models.dns import (
    DmarcAnalysis,
    DnsData,
    DnsQueryResult,
    DnsQueryStatus,
    DnsRecord,
    EmailSecurity,
    SpfAnalysis,
)
from recon.models.http import HttpData, HttpProbe, SecurityHeader
from recon.modules import ThirdPartyCollector

SUPABASE = "abcdefghijklmnopqrst.supabase.co"


# ------------------------------------------------------------------ signature matching

@pytest.mark.parametrize("host, url, provider, kind, identifier", [
    # object storage, both addressing styles
    ("my-bucket.s3.ap-south-1.amazonaws.com", "", "Amazon S3", "object_storage", "my-bucket"),
    ("s3.amazonaws.com", "https://s3.amazonaws.com/legacy-assets/x.png", "Amazon S3", "object_storage",
     "legacy-assets"),
    ("assets.s3-website-us-east-1.amazonaws.com", "", "Amazon S3 (website endpoint)", "object_storage", "assets"),
    ("acct1.blob.core.windows.net", "", "Azure Blob Storage", "object_storage", "acct1"),
    ("storage.googleapis.com", "https://storage.googleapis.com/public-assets/l.png", "Google Cloud Storage",
     "object_storage", "public-assets"),
    ("firebasestorage.googleapis.com", "https://firebasestorage.googleapis.com/v0/b/proj.appspot.com/o/a",
     "Firebase Storage", "object_storage", "proj.appspot.com"),
    ("pub-" + "a" * 32 + ".r2.dev", "", "Cloudflare R2", "object_storage", "a" * 32),
    ("files.sgp1.digitaloceanspaces.com", "", "DigitalOcean Spaces", "object_storage", "files"),
    # serverless and edge
    ("abc123def4.execute-api.ap-south-1.amazonaws.com", "", "Amazon API Gateway", "serverless_function",
     "abc123def4"),
    ("a" * 32 + ".lambda-url.us-east-1.on.aws", "", "AWS Lambda Function URL", "serverless_function", "a" * 32),
    ("asia-south1-proj.cloudfunctions.net", "", "Google Cloud Functions", "serverless_function", "proj"),
    ("myworker.workers.dev", "", "Cloudflare Workers", "edge_worker", "myworker"),
    ("site.netlify.app", "https://site.netlify.app/.netlify/functions/order", "Netlify Functions",
     "serverless_function", "site/order"),
    ("app.vercel.app", "https://app.vercel.app/api/checkout", "Vercel Functions", "serverless_function", "app"),
    # managed databases / backends
    (SUPABASE, "https://" + SUPABASE + "/rest/v1/users", "Supabase (PostgREST)", "managed_database",
     "abcdefghijklmnopqrst"),
    (SUPABASE, "https://" + SUPABASE + "/functions/v1/send", "Supabase Edge Function", "serverless_function",
     "abcdefghijklmnopqrst"),
    (SUPABASE, "https://" + SUPABASE + "/storage/v1/object/public/avatars/a.png", "Supabase Storage",
     "object_storage", "abcdefghijklmnopqrst/avatars"),
    ("proj-default-rtdb.asia-southeast1.firebasedatabase.app", "", "Firebase Realtime Database",
     "managed_database", "proj-default-rtdb"),
    ("cluster0.ab12c.mongodb.net", "", "MongoDB Atlas", "managed_database", "cluster0"),
    # hosting, auth, search
    ("app.vercel.app", "/", "Vercel", "hosting", "app"),
    ("site.netlify.app", "/", "Netlify", "hosting", "site"),
    ("x.azurewebsites.net", "/", "Azure App Service", "hosting", "x"),
    ("x.azurewebsites.net", "https://x.azurewebsites.net/api/orders", "Azure Functions", "serverless_function", "x"),
    ("tenant.auth0.com", "", "Auth0", "auth", "tenant"),
    ("app.algolia.net", "", "Algolia", "search", "app"),
])
def test_cloud_signature_matching(host, url, provider, kind, identifier):
    matched = match_cloud(host, url)
    assert matched is not None, f"{host} did not match"
    assert (matched.signature.provider, matched.signature.kind, matched.identifier) == (provider, kind, identifier)


@pytest.mark.parametrize("host", ["example.com", "www.google.com", "cdn.jsdelivr.net", "", "localhost"])
def test_ordinary_hosts_are_not_cloud_resources(host):
    assert match_cloud(host) is None


def test_regions_are_recovered_where_the_hostname_states_one():
    assert match_cloud("assets.s3.ap-south-1.amazonaws.com").region == "ap-south-1"
    assert match_cloud("files.sgp1.digitaloceanspaces.com").region == "sgp1"
    assert match_cloud("myworker.workers.dev").region is None


def test_public_by_default_marks_only_the_world_readable_classes():
    public = {s.provider for s in CLOUD_SIGNATURES if s.public_by_default}
    assert "Amazon S3" in public and "Azure Blob Storage" in public and "Cloudflare R2" in public
    assert "Cloudflare Workers" not in public and "Auth0" not in public


def test_specific_signatures_win_over_generic_ones():
    # A bucket host must never be reported as plain hosting, and a plain path must not become a function.
    assert match_cloud("assets.s3.amazonaws.com").signature.kind == "object_storage"
    assert match_cloud("site.netlify.app", "https://site.netlify.app/index.html").signature.kind == "hosting"


# ------------------------------------------------------------------ inventory from collected evidence

def dns_with_cname(target):
    return DnsData(hostname="example.com", queries={"CNAME": DnsQueryResult(
        name="example.com", record_type="CNAME", status=DnsQueryStatus.NOERROR,
        records=[DnsRecord(value=target)], response_time_ms=1)},
        email=EmailSecurity(spf=SpfAnalysis(lookup_status=DnsQueryStatus.NODATA),
                            dmarc=DmarcAnalysis(name="_dmarc.example.com", lookup_status=DnsQueryStatus.NXDOMAIN),
                            dkim_selectors_checked=[]))


def crawl_of(*resource_urls):
    return CrawlData(max_depth=1, max_pages=10, robots_respected=True, crawl_delay=0.0,
                     pages=[CrawledPage(url="https://example.com/p", depth=1, status_code=200,
                                        resource_urls=list(resource_urls))])


def inventory(**kwargs):
    defaults = {"dns": None, "http": None, "html": None, "tls": None, "crawl": None, "assets": None}
    return ThirdPartyCollector("example.com", **{**defaults, **kwargs}).build()


def test_resources_are_collected_from_every_evidence_source():
    html = HtmlData(source_url="https://example.com/", resources=[ResourceRef(
        url="https://my-bucket.s3.ap-south-1.amazonaws.com/logo.png", kind="image",
        host="my-bucket.s3.ap-south-1.amazonaws.com", same_site=False)])
    crawl = crawl_of("https://acct1.blob.core.windows.net/media/v.mp4")
    assets = AssetData(assets=[AssetRecord(url="https://example.com/a.js", kind="script", endpoints=[
        EndpointRef(value=f"https://{SUPABASE}/rest/v1/users", host=SUPABASE)])],
        service_hosts={"myworker.workers.dev": ["https://example.com/a.js"]})
    data = inventory(html=html, crawl=crawl, assets=assets, dns=dns_with_cname("app.vercel.app."))
    found = {(r.provider, r.kind, r.identifier): r for r in data.cloud_resources}
    assert ("Amazon S3", "object_storage", "my-bucket") in found
    assert ("Azure Blob Storage", "object_storage", "acct1") in found
    assert ("Supabase (PostgREST)", "managed_database", "abcdefghijklmnopqrst") in found
    assert ("Cloudflare Workers", "edge_worker", "myworker") in found
    assert ("Vercel", "hosting", "app") in found
    assert found[("Amazon S3", "object_storage", "my-bucket")].sources == ["html:image"]
    assert found[("Vercel", "hosting", "app")].sources == ["dns:cname"]


def test_confidence_reflects_how_the_resource_was_referenced():
    html = HtmlData(source_url="https://example.com/", resources=[ResourceRef(
        url="https://assets.s3.amazonaws.com/x.png", kind="image", host="assets.s3.amazonaws.com", same_site=False)])
    loaded = inventory(html=html).cloud_resources[0]
    assert loaded.confidence is Confidence.HIGH          # the page actually loads it

    csp = HttpData(probes=[HttpProbe(
        requested_url="https://example.com/", success=True, final_url="https://example.com/", final_fetched=True,
        security_headers={"content-security-policy": SecurityHeader(
            name="content-security-policy", present=True, value="default-src 'self' https://static.s3.amazonaws.com",
            parsed={"default-src": ["'self'", "https://static.s3.amazonaws.com"]})})])
    allowed = inventory(http=csp).cloud_resources[0]
    assert allowed.confidence is Confidence.LOW          # permitted by CSP, not necessarily used

    delegated = inventory(dns=dns_with_cname("app.vercel.app.")).cloud_resources[0]
    assert delegated.confidence is Confidence.MEDIUM     # delivery, not proof of ownership


def test_the_same_resource_seen_twice_merges_its_sources():
    html = HtmlData(source_url="https://example.com/", resources=[ResourceRef(
        url="https://assets.s3.amazonaws.com/x.png", kind="image", host="assets.s3.amazonaws.com", same_site=False)])
    crawl = crawl_of("https://assets.s3.amazonaws.com/y.png")
    [resource] = inventory(html=html, crawl=crawl).cloud_resources
    assert sorted(resource.sources) == ["crawl", "html:image"] and len(resource.evidence) == 2


def test_url_samples_are_redacted():
    html = HtmlData(source_url="https://example.com/", resources=[ResourceRef(
        url="https://assets.s3.amazonaws.com/x.png?token=SECRETVALUE", kind="image",
        host="assets.s3.amazonaws.com", same_site=False)])
    [resource] = inventory(html=html).cloud_resources
    assert "SECRETVALUE" not in (resource.url_sample or "") and "SECRETVALUE" not in str(resource.evidence)


def test_no_cloud_references_yields_an_empty_inventory():
    html = HtmlData(source_url="https://example.com/", resources=[ResourceRef(
        url="https://cdn.jsdelivr.net/npm/x/y.js", kind="script", host="cdn.jsdelivr.net", same_site=False)])
    assert inventory(html=html).cloud_resources == []


# ------------------------------------------------------------------ observations and findings

def analyze(data):
    now = utcnow()
    modules = {"third_party": ModuleResult(module="third_party", status=ModuleStatus.SUCCESS, started_at=now,
                                           finished_at=now, duration_ms=1.0, data=data)}
    observations = ObservationBuilder("example.com", modules).build()
    return observations, AnalysisEngine(now).analyze(dns=None, network=None, http=None, tls=None,
                                                     host="example.com", third_party=data,
                                                     observations=observations)


def full_inventory():
    html = HtmlData(source_url="https://example.com/", resources=[ResourceRef(
        url="https://assets.s3.amazonaws.com/x.png", kind="image", host="assets.s3.amazonaws.com", same_site=False)])
    assets = AssetData(assets=[AssetRecord(url="https://example.com/a.js", kind="script", endpoints=[
        EndpointRef(value=f"https://{SUPABASE}/rest/v1/users", host=SUPABASE),
        EndpointRef(value="https://site.netlify.app/.netlify/functions/pay", host="site.netlify.app")])])
    return inventory(html=html, assets=assets)


def test_cloud_observations_are_comparable_across_scans():
    observations, _ = analyze(full_inventory())
    cloud = [o for o in observations if o.type == "cloud.resource"]
    assert len(cloud) == 3
    keys = {o.key for o in cloud}
    assert "Amazon S3|object_storage|assets" in keys
    assert all(set(o.value) == {"host", "region", "sources"} for o in cloud)


def test_findings_are_scoped_to_what_a_reference_justifies():
    _, analysis = analyze(full_inventory())
    by_code = {f.id.split(":", 1)[0]: f for f in analysis.findings}
    assert by_code["cloud.inventory"].severity is Severity.INFORMATIONAL
    assert by_code["cloud.object_storage_referenced"].severity is Severity.LOW
    assert by_code["cloud.serverless_endpoint"].severity is Severity.LOW
    # a client-side path straight to a database moves authorization into provider rules → medium
    assert by_code["cloud.backend_endpoint"].severity is Severity.MEDIUM
    for finding in analysis.findings:
        assert finding.confidence.rank <= Confidence.HIGH.rank and finding.recommendation and finding.limitations
        # nothing was requested, so no finding may claim exposure
        assert "SiteRecon" in finding.description or "not tested" in finding.description.lower() \
            or "did not" in finding.description.lower()


def test_findings_never_claim_a_bucket_is_public():
    _, analysis = analyze(full_inventory())
    bucket = next(f for f in analysis.findings if f.id.startswith("cloud.object_storage_referenced"))
    assert "did not request" in bucket.description
    assert "requires an authorized active check" in (bucket.limitations or "")
    assert bucket.confidence is Confidence.MEDIUM


def test_an_empty_inventory_produces_no_cloud_findings():
    _, analysis = analyze(inventory())
    assert [f for f in analysis.findings if f.category == "cloud"] == []
