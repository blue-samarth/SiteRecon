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

def _http(hsts):
    sh = {"strict-transport-security": SecurityHeader(name="strict-transport-security", present=True, value=hsts)}
    return HttpData(probes=[HttpProbe(requested_url="https://example.com/", success=True, final_fetched=True,
                                      final_url="https://example.com/", status_code=200, security_headers=sh)])


def _hsts_codes(hsts):
    f = FindingCollector(T0)
    AnalysisEngine._analyze_hsts_preload(_http(hsts), f)
    return {x.id.split(":", 1)[0] for x in f.sorted()}


def test_hsts_preload_ready_is_quiet():
    assert _hsts_codes("max-age=63072000; includeSubDomains; preload") == set()


def test_hsts_not_preload_ready_is_flagged():
    assert "http.hsts_not_preload_ready" in _hsts_codes("max-age=600")
