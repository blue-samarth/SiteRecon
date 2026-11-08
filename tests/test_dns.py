import dns.exception
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest

from recon.models.dns import DnsQueryStatus
from recon.modules import DnsCollector
from recon.utils.resolver import DnsClient


class FakeAnswer:
    def __init__(self, rtype, texts, ttl=300):
        self._rdatas = [dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.from_text(rtype), t)
                        for t in texts]
        self.rrset = type("RRset", (), {"ttl": ttl})()

    def __iter__(self):
        return iter(self._rdatas)


class FakeResolver:
    """Maps (name, rtype) to texts or an exception; unknown keys → NXDOMAIN."""

    def __init__(self, table):
        self.table = table
        self.calls: list[tuple[str, str]] = []

    async def resolve(self, name, rtype, lifetime=None):
        self.calls.append((name, rtype))
        entry = self.table.get((name, rtype), dns.resolver.NXDOMAIN())
        if isinstance(entry, list) and entry and isinstance(entry[0], BaseException):
            exc = entry.pop(0)  # sequence of failures, then success
            if not entry:
                self.table[(name, rtype)] = dns.resolver.NoAnswer()
            raise exc
        if isinstance(entry, BaseException):
            raise entry
        if isinstance(entry, list) and len(entry) == 1 and isinstance(entry[0], FakeAnswer):
            return entry[0]
        return FakeAnswer(rtype, entry)


TABLE = {
    ("example.com", "A"): ["93.184.216.34"],
    ("example.com", "AAAA"): dns.resolver.NoAnswer(),
    ("example.com", "MX"): ["10 aspmx.l.google.com.", "0 ."],
    ("example.com", "NS"): ["ns1.example.net.", "ns2.example.net."],
    ("example.com", "TXT"): ['"v=spf1 include:_spf.google.com ~all"', '"google-site-verification=abc"'],
    ("example.com", "SOA"): ["ns1.example.net. admin.example.com. 1 7200 3600 1209600 300"],
    ("example.com", "CAA"): dns.resolver.NoAnswer(),
    ("example.com", "CNAME"): dns.resolver.NoAnswer(),
    ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=quarantine; sp=reject; pct=50; rua=mailto:a@x.com,mailto:b@x.com"'],
    ("google._domainkey.example.com", "TXT"): ['"v=DKIM1; k=rsa; p=MIIBIjAN"'],
}


def client(table, retries=0):
    return DnsClient(timeout=1, retries=retries, resolver=FakeResolver(dict(table)))


async def test_collect_dns_records_and_email():
    data, errors = await DnsCollector("example.com", client(TABLE), ("google", "selector1")).collect()
    assert errors == []
    q = data.queries
    assert q["A"].values == ["93.184.216.34"] and q["A"].records[0].ttl == 300
    assert q["AAAA"].status is DnsQueryStatus.NODATA
    assert q["MX"].values == ["10 aspmx.l.google.com", "0 ."]
    assert q["NS"].values == ["ns1.example.net", "ns2.example.net"]
    assert data.addresses() == ["93.184.216.34"]

    spf = data.email.spf.records
    assert len(spf) == 1 and spf[0].all_qualifier == "~" and spf[0].includes == ["_spf.google.com"]

    dmarc = data.email.dmarc
    assert dmarc.policy == "quarantine" and dmarc.subdomain_policy == "reject" and dmarc.pct == 50
    assert dmarc.rua == ["mailto:a@x.com", "mailto:b@x.com"]

    assert [k.selector for k in data.email.dkim_found] == ["google"]


async def test_failures_are_classified_and_isolated():
    table = dict(TABLE)
    table[("example.com", "MX")] = dns.resolver.NoNameservers()
    table[("example.com", "NS")] = dns.exception.Timeout()
    table[("example.com", "SOA")] = dns.resolver.NXDOMAIN()
    data, errors = await DnsCollector("example.com", client(table)).collect()
    assert data.queries["MX"].status is DnsQueryStatus.SERVFAIL
    assert data.queries["NS"].status is DnsQueryStatus.TIMEOUT
    assert data.queries["SOA"].status is DnsQueryStatus.NXDOMAIN
    assert data.queries["A"].status is DnsQueryStatus.NOERROR  # others unaffected
    # Only non-definitive answers are collection errors; NXDOMAIN/NODATA are observations.
    assert {e.error_type for e in errors} == {"SERVFAIL", "TIMEOUT"}


async def test_timeout_is_retried_then_succeeds():
    table = {("example.com", "A"): [dns.exception.Timeout(), dns.exception.Timeout()]}
    c = client(table, retries=2)
    result = await c.query("example.com", "A")
    assert result.attempts == 3
    assert result.status is DnsQueryStatus.NODATA


async def test_nxdomain_is_not_retried():
    c = client({}, retries=3)
    result = await c.query("missing.example.com", "A")
    assert result.status is DnsQueryStatus.NXDOMAIN and result.attempts == 1


@pytest.mark.parametrize("raw, qualifier", [
    ("v=spf1 -all", "-"), ("v=spf1 +all", "+"), ("v=spf1 all", "+"),
    ("v=spf1 ?all", "?"), ("v=spf1 include:x.com", None),
])
def test_spf_all_qualifier(raw, qualifier):
    assert DnsCollector.parse_spf_record(raw).all_qualifier == qualifier


async def test_multiple_dmarc_records_are_not_parsed():
    table = dict(TABLE)
    table[("_dmarc.example.com", "TXT")] = ['"v=DMARC1; p=reject"', '"v=DMARC1; p=none"']
    data, _ = await DnsCollector("example.com", client(table)).collect()
    assert len(data.email.dmarc.raw_records) == 2 and data.email.dmarc.policy is None
