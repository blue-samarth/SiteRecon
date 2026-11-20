import datetime as dt

from recon.analysis.engine import AnalysisEngine
from recon.analysis.findings import FindingCollector
from recon.models import CertificateInfo, HttpData, HttpProbe, SecurityHeader, TlsData, TlsProbe
from recon.modules.tls import TlsCollector

T0 = dt.datetime(2026, 11, 18, tzinfo=dt.UTC)


# ------------------------------------------------------------------ forward-secrecy helper

def test_forward_secret_classification():
    assert TlsCollector._forward_secret("TLSv1.3", "TLS_AES_128_GCM_SHA256") is True
    assert TlsCollector._forward_secret("TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256") is True
    assert TlsCollector._forward_secret("TLSv1.2", "AES256-SHA") is False       # RSA key exchange
    assert TlsCollector._forward_secret("TLSv1.2", None) is None


# ------------------------------------------------------------------ TLS-depth findings

def _cert(sct=1):
    return CertificateInfo(subject="CN=x", issuer="CN=ca", serial_number="1", version="v3",
                           not_before=T0 - dt.timedelta(days=1), not_after=T0 + dt.timedelta(days=300),
                           signature_algorithm="sha256WithRSAEncryption", public_key_algorithm="RSA",
                           fingerprint_sha256="AB", self_issued=False, sct_count=sct)


def _probe(**kw):
    base = dict(hostname="example.com", port=443, success=True, tls_version="TLSv1.2",
                cipher="ECDHE-RSA-AES128-GCM-SHA256", forward_secret=True, chain_length=2,
                chain_complete=True, certificate=_cert(), currently_valid=True, days_remaining=200,
                hostname_match=True)
    base.update(kw)
    return TlsProbe(**base)


def _codes(probe):
    f = FindingCollector(T0)
    AnalysisEngine._analyze_tls(TlsData(probes=[probe]), f)
    return {x.id.split(":", 1)[0] for x in f.sorted()}


def test_depth_findings_fire_on_weak_posture():
    codes = _codes(_probe(forward_secret=False, cipher="AES256-SHA", chain_complete=False, chain_length=1,
                          certificate=_cert(sct=0)))
    assert {"tls.no_forward_secrecy", "tls.incomplete_chain", "tls.no_sct"} <= codes


def test_depth_findings_quiet_on_strong_posture():
    codes = _codes(_probe())
    assert not any(c in codes for c in ("tls.no_forward_secrecy", "tls.incomplete_chain", "tls.no_sct"))


# ------------------------------------------------------------------ HSTS preload eligibility

READY = "max-age=63072000; includeSubDomains; preload"


def _http(hsts, preload=None):
    sh = {"strict-transport-security": SecurityHeader(name="strict-transport-security", present=True, value=hsts)}
    return HttpData(probes=[HttpProbe(requested_url="https://example.com/", success=True, final_fetched=True,
                                      final_url="https://example.com/", status_code=200, security_headers=sh)],
                    hsts_preload=preload)


def _hsts_codes(hsts, preload=None):
    f = FindingCollector(T0)
    AnalysisEngine._analyze_hsts_preload(_http(hsts, preload), "example.com", f)
    return {x.id.split(":", 1)[0] for x in f.sorted()}


def _listed(preloaded=True, **over):
    from recon.models import HstsPreload
    return HstsPreload(checked=True, preloaded=preloaded, hostname="example.com",
                       matched_name="example.com" if preloaded else None,
                       snapshot_date="2026-11-20", entries=95_544, **over)


def test_hsts_preload_ready_is_quiet():
    assert _hsts_codes(READY) == set()


def test_hsts_not_preload_ready_is_flagged():
    assert "http.hsts_not_preload_ready" in _hsts_codes("max-age=600")


# ---- membership and eligibility are two facts, and the pairing is what carries the information

def test_ready_header_on_a_listed_domain_is_quiet():
    assert _hsts_codes(READY, _listed()) == set()


def test_ready_header_on_an_unlisted_domain_says_it_was_never_submitted():
    codes = _hsts_codes(READY, _listed(preloaded=False))
    assert codes == {"http.hsts_preload_eligible_not_listed"}


def test_a_listed_domain_whose_header_no_longer_qualifies_is_its_own_finding():
    codes = _hsts_codes("max-age=600", _listed())
    assert codes == {"http.hsts_preloaded_header_ineligible"}
    assert "http.hsts_not_preload_ready" not in codes      # not both; the listed case supersedes it


def test_the_ineligible_listed_finding_names_what_is_missing_and_the_snapshot():
    f = FindingCollector(T0)
    AnalysisEngine._analyze_hsts_preload(_http("max-age=600", _listed()), "example.com", f)
    evidence = " ".join(f.sorted()[0].evidence)
    assert "includeSubDomains" in evidence and "preload" in evidence and "max-age" in evidence
    assert "2026-11-20" in evidence and "95,544" in evidence
    assert f.sorted()[0].severity.value == "low"           # protection is real; the drift is what matters


def test_an_ancestor_entry_is_reported_as_covering_the_host():
    from recon.models import HstsPreload
    covered = HstsPreload(checked=True, preloaded=True, hostname="shop.example.com",
                          matched_name="example.com", via_subdomains=True, snapshot_date="2026-11-20",
                          entries=95_544)
    f = FindingCollector(T0)
    AnalysisEngine._analyze_hsts_preload(_http("max-age=600", covered), "shop.example.com", f)
    assert "covered by the preload entry for 'example.com'" in " ".join(f.sorted()[0].evidence)


def test_without_a_snapshot_nothing_is_claimed_about_membership():
    from recon.models import HstsPreload
    unchecked = HstsPreload(checked=False, hostname="example.com", note="no snapshot bundled")
    assert _hsts_codes(READY, unchecked) == set()                   # no "not listed" claim
    assert _hsts_codes("max-age=600", unchecked) == {"http.hsts_not_preload_ready"}
