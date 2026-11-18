import datetime as dt

from recon.analysis.engine import AnalysisEngine, _caa_issue_tags, _issuer_allowed
from recon.analysis.findings import FindingCollector
from recon.models import (
    CaaAnalysis,
    DmarcAnalysis,
    DnsData,
    DnsQueryStatus,
    EmailSecurity,
    EmailTransportSecurity,
    SpfAnalysis,
    SubdomainData,
    SubdomainRecord,
)
from recon.modules.dns import DnsCollector

T0 = dt.datetime(2026, 11, 18, tzinfo=dt.UTC)


# ------------------------------------------------------------------ parsers

def test_tag_parses_policy_records():
    assert DnsCollector._tag("v=STSv1; id=20260101T000000Z", "id") == "20260101T000000Z"
    assert DnsCollector._tag("v=TLSRPTv1; rua=mailto:x@e.com", "rua") == "mailto:x@e.com"
    assert DnsCollector._tag("v=BIMI1; l=https://e.com/logo.svg", "a") is None


def test_caa_issue_tags_and_issuer_matching():
    allowed = _caa_issue_tags(['0 issue "letsencrypt.org"', '0 issuewild "digicert.com"', '0 iodef "mailto:x"'])
    assert allowed == {"letsencrypt.org", "digicert.com"}
    assert _issuer_allowed("Let's Encrypt", allowed)       # hint map
    assert _issuer_allowed("DigiCert Inc", allowed)        # hint map
    assert not _issuer_allowed("GlobalSign nv-sa", allowed)


# ------------------------------------------------------------------ transport findings

def _dns(transport=None, caa_records=()):
    return DnsData(hostname="example.com", queries={},
                   email=EmailSecurity(spf=SpfAnalysis(lookup_status=DnsQueryStatus.NODATA),
                                       dmarc=DmarcAnalysis(name="_dmarc.example.com",
                                                           lookup_status=DnsQueryStatus.NXDOMAIN),
                                       dkim_selectors_checked=[],
                                       transport=transport or EmailTransportSecurity()),
                   caa=CaaAnalysis(records=list(caa_records), complete=True))


def _codes(dns, subdomains=None):
    f = FindingCollector(T0)
    AnalysisEngine._analyze_email_transport(dns, f)
    AnalysisEngine._analyze_caa_ct_mismatch(dns, subdomains, None, f)
    return {x.id.split(":", 1)[0] for x in f.sorted()}


def test_mail_domain_missing_transport_security_is_flagged():
    codes = _codes(_dns(EmailTransportSecurity(mx_hosts=["mail.example.com"])))
    assert {"email.mta_sts_missing", "email.tls_rpt_missing", "email.dane_missing"} <= codes


def test_fully_configured_mail_domain_has_no_transport_findings():
    t = EmailTransportSecurity(mx_hosts=["mail.example.com"], mta_sts_present=True, mta_sts_id="1",
                               tls_rpt_present=True, dane_mx=["mail.example.com"], bimi_present=True)
    codes = _codes(_dns(t))
    assert not any(c.startswith("email.mta_sts") or c.startswith("email.tls_rpt") or c.startswith("email.dane")
                   for c in codes)
    assert "email.bimi_present" in codes   # BIMI presence is surfaced as informational


def test_domain_without_mx_gets_no_transport_findings():
    assert _codes(_dns(EmailTransportSecurity())) == set()   # no MX → mail transport-security does not apply


# ------------------------------------------------------------------ CAA ↔ CT mismatch

def _subs(issuers):
    return SubdomainData(query="example.com", verification_limit=100,
                         hostnames=[SubdomainRecord(hostname="example.com", issuers=issuers)])


def test_caa_ct_mismatch_flags_unlisted_issuer():
    dns = _dns(caa_records=['0 issue "letsencrypt.org"'])
    assert "dns.caa_ct_mismatch" in _codes(dns, _subs(["DigiCert Inc"]))


def test_caa_ct_no_mismatch_when_issuer_is_permitted():
    dns = _dns(caa_records=['0 issue "letsencrypt.org"'])
    assert "dns.caa_ct_mismatch" not in _codes(dns, _subs(["Let's Encrypt"]))
