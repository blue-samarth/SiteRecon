import datetime as dt

from recon.analysis import AnalysisEngine
from recon.models.dns import (
    CaaAnalysis,
    DmarcAnalysis,
    DnsData,
    DnsQueryResult,
    DnsQueryStatus,
    DnsRecord,
    EmailSecurity,
    SpfAnalysis,
)
from recon.models.http import HttpData, HttpProbe, SecurityHeader
from recon.models.network import AsnInfo, IpIntel, NetworkData, RdapNetwork
from recon.models.report import Severity
from recon.models.tls import TlsData, TlsProbe
from recon.modules import CertificateParser, DnsCollector
from tests.conftest import make_cert
from cryptography.hazmat.primitives import serialization

NOW = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)


def q(rtype, status=DnsQueryStatus.NOERROR, values=(), name="example.com"):
    return DnsQueryResult(name=name, record_type=rtype, status=status,
                          records=[DnsRecord(value=v) for v in values], response_time_ms=1)


def dns_data(spf=("v=spf1 +all",), dmarc_status=DnsQueryStatus.NXDOMAIN, caa=DnsQueryStatus.NODATA,
             ns=("ana.ns.cloudflare.com",), mx=("1 smtp.google.com",)):
    return DnsData(
        hostname="example.com",
        queries={"A": q("A", values=["1.2.3.4"]), "AAAA": q("AAAA", DnsQueryStatus.NODATA),
                 "CAA": q("CAA", caa), "NS": q("NS", values=list(ns)), "MX": q("MX", values=list(mx))},
        email=EmailSecurity(
            spf=SpfAnalysis(lookup_status=DnsQueryStatus.NOERROR, records=[DnsCollector.parse_spf_record(s) for s in spf]),
            dmarc=DmarcAnalysis(name="_dmarc.example.com", lookup_status=dmarc_status),
            dkim_selectors_checked=[],
        ),
        caa=CaaAnalysis(checked={"example.com": caa.value}, complete=caa.is_definitive),
    )


def ids(result):
    return {f.id.split(":")[0] for f in result.findings}


def test_dns_findings_and_providers():
    r = AnalysisEngine(NOW).analyze(dns=dns_data(spf=("v=spf1 +all", "v=spf1 -all")), network=None, http=None, tls=None)
    assert {"dns.spf_pass_all", "dns.spf_multiple", "dns.dmarc_missing", "dns.caa_absent"} <= ids(r)
    by_id = {f.id.split(":")[0]: f for f in r.findings}
    assert by_id["dns.spf_pass_all"].severity is Severity.MEDIUM
    assert by_id["dns.dmarc_missing"].severity is Severity.INFORMATIONAL  # absence ≠ vulnerability
    assert r.findings[0].severity is Severity.MEDIUM                      # sorted most severe first
    providers = {(o.provider, o.role) for o in r.infrastructure}
    assert ("Cloudflare DNS", "authoritative_dns") in providers
    assert ("Google Workspace", "mail_exchange") in providers


def test_inconclusive_lookups_do_not_produce_absence_findings():
    d = dns_data(spf=(), dmarc_status=DnsQueryStatus.TIMEOUT, caa=DnsQueryStatus.SERVFAIL)
    d.email.spf.lookup_status = DnsQueryStatus.TIMEOUT
    r = AnalysisEngine(NOW).analyze(dns=d, network=None, http=None, tls=None)
    assert not ids(r) & {"dns.spf_missing", "dns.dmarc_missing", "dns.caa_absent"}


def test_http_findings():
    missing = {n: SecurityHeader(name=n, present=False) for n in (
        "strict-transport-security", "content-security-policy", "x-content-type-options",
        "x-frame-options", "referrer-policy", "permissions-policy")}
    probes = [
        HttpProbe(requested_url="http://example.com/", success=True, final_url="http://example.com/",
                  final_fetched=True, status_code=200, redirects_to_https=False),
        HttpProbe(requested_url="https://example.com/", success=True, final_url="https://example.com/",
                  final_fetched=True, status_code=200, security_headers=missing,
                  headers={"server": ["Vercel"], "x-vercel-id": ["abc"]}),
        HttpProbe(requested_url="https://www.example.com/", success=False, error="boom", error_type="ConnectError"),
    ]
    r = AnalysisEngine(NOW).analyze(dns=None, network=None, http=HttpData(probes=probes), tls=None)
    assert {"http.no_https_redirect", "http.hsts_missing", "http.security_headers_missing",
            "http.unreachable.https"} <= ids(r)
    assert [o.provider for o in r.infrastructure] == ["Vercel"]
    assert len(r.infrastructure[0].evidence) == 2  # merged header evidence


def test_tls_findings():
    cert, _ = make_cert(sans=("other.com",))
    info = CertificateParser.parse(cert.public_bytes(serialization.Encoding.DER))
    probes = [
        TlsProbe(hostname="example.com", success=True, tls_version="TLSv1.1", verified=False,
                 hostname_match=False, currently_valid=True, days_remaining=10, certificate=info),
        TlsProbe(hostname="www.example.com", success=True, tls_version="TLSv1.3", verified=True,
                 hostname_match=True, currently_valid=False, days_remaining=-3, certificate=info),
    ]
    r = AnalysisEngine(NOW).analyze(dns=None, network=None, http=None, tls=TlsData(probes=probes))
    found = {f.id for f in r.findings}
    assert "tls.expiring_soon:example.com:443" in found
    assert "tls.hostname_mismatch:example.com:443" in found
    assert "tls.legacy_protocol:example.com:443" in found
    assert "tls.untrusted:example.com:443" not in found  # mismatch explains the failure
    assert "tls.expired:www.example.com:443" in found
    assert r.severity_counts["high"] == 1


def test_network_provider_inference_distinguishes_sources():
    net = NetworkData(ips=[IpIntel(
        ip="76.76.21.21", version=4, is_public=True,
        asn=AsnInfo(asn=16509, name="AMAZON-02 - Amazon.com, Inc., US"),
        rdap=RdapNetwork(name="VERCEL-01", organizations=["Vercel, Inc"]),
    )])
    r = AnalysisEngine(NOW).analyze(dns=None, network=net, http=None, tls=None)
    by_provider = {o.provider: o for o in r.infrastructure}
    assert set(by_provider) == {"Amazon Web Services", "Vercel"}
    assert by_provider["Vercel"].source == "RDAP"
    assert all(o.role == "ip_allocation" and o.note for o in r.infrastructure)
