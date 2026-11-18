import datetime as dt

from recon.analysis.engine import AnalysisEngine
from recon.analysis.findings import FindingCollector
from recon.analysis.takeover import TAKEOVER_SIGNATURES, match_cname
from recon.models import SubdomainData, SubdomainRecord
from recon.models.subdomains import HostState

T0 = dt.datetime(2026, 11, 18, tzinfo=dt.UTC)


# ------------------------------------------------------------------ fingerprint matching

def test_match_cname_identifies_providers_by_suffix_and_keyword():
    assert match_cname("mysite.github.io").provider == "GitHub Pages"
    assert match_cname("myapp.herokudns.com").provider == "Heroku"
    assert match_cname("bucket.s3-website-us-east-1.amazonaws.com").provider == "AWS S3"   # keyword/regional
    assert match_cname("example.com") is None


def test_body_unclaimed_matches_provider_fingerprint():
    gh = next(s for s in TAKEOVER_SIGNATURES if s.provider == "GitHub Pages")
    assert gh.body_unclaimed("<h1>There isn't a GitHub Pages site here.</h1>")
    assert not gh.body_unclaimed("<h1>Welcome to my site</h1>")


# ------------------------------------------------------------------ findings

def _data(records):
    return SubdomainData(query="example.com", verification_limit=100, hostnames=records)


def test_vulnerable_record_produces_a_high_takeover_finding():
    rec = SubdomainRecord(hostname="blog.example.com", state=HostState.HISTORICAL, cname="ghost.github.io",
                          takeover_provider="GitHub Pages", takeover_vulnerable=True,
                          takeover_detail="CNAME → ghost.github.io (GitHub Pages); unclaimed fingerprint")
    f = FindingCollector(T0)
    AnalysisEngine._analyze_subdomains(_data([rec]), f)
    finding = next(x for x in f.sorted() if x.id.startswith("subdomain.takeover"))
    assert finding.severity.value == "high"
    assert "ghost.github.io" in finding.evidence[0]
    assert finding.recommendation and finding.limitations


def test_claimed_provider_cname_is_only_a_low_dangling_note():
    rec = SubdomainRecord(hostname="shop.example.com", cname="x.myshopify.com",
                          takeover_provider="Shopify", takeover_vulnerable=False)
    f = FindingCollector(T0)
    AnalysisEngine._analyze_subdomains(_data([rec]), f)
    codes = {x.id.split(":", 1)[0] for x in f.sorted()}
    assert "subdomain.dangling_cname" in codes and "subdomain.takeover" not in codes
    note = next(x for x in f.sorted() if x.id.startswith("subdomain.dangling_cname"))
    assert note.severity.value == "low" and "Shopify" in note.evidence[0]


def test_no_takeover_findings_for_ordinary_subdomains():
    rec = SubdomainRecord(hostname="www.example.com", state=HostState.REACHABLE, cname="lb.example.com")
    f = FindingCollector(T0)
    AnalysisEngine._analyze_subdomains(_data([rec]), f)
    assert not any(x.id.startswith("subdomain.takeover") or x.id.startswith("subdomain.dangling") for x in f.sorted())
