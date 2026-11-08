import asyncio
import datetime as dt
import json

import httpx
import pytest
import respx

from recon.analysis import AnalysisEngine
from recon.models.common import Confidence
from recon.models.dns import (
    DmarcAnalysis,
    DnsData,
    DnsQueryResult,
    DnsQueryStatus,
    DnsRecord,
    EmailSecurity,
    SpfAnalysis,
)
from recon.models.html import HtmlData, ResourceRef
from recon.models.http import HttpData, HttpProbe
from recon.models.subdomains import SubdomainData, SubdomainRecord
from recon.models.whois import DomainRegistration
from recon.modules import (
    DnsCollector,
    SecurityHeaderParser,
    ThirdPartyCollector,
    WhoisClient,
    WhoisCollector,
    WhoisError,
    WhoisParser,
)
from recon.utils.http_client import SafeHttpClient
from tests.conftest import public_resolve

NOW = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)


def q(rtype, values):
    return DnsQueryResult(name="example.com", record_type=rtype, status=DnsQueryStatus.NOERROR,
                          records=[DnsRecord(value=v) for v in values], response_time_ms=1)


def test_third_party_inventory_sources_and_confidence():
    dns = DnsData(
        hostname="example.com",
        queries={"MX": q("MX", ["1 smtp.google.com"]), "NS": q("NS", ["ns1.unknown-dns.test"]),
                 "TXT": q("TXT", ["stripe-verification=abc", "v=spf1 include:sendgrid.net -all"])},
        email=EmailSecurity(spf=SpfAnalysis(lookup_status=DnsQueryStatus.NOERROR,
                                            records=[DnsCollector.parse_spf_record("v=spf1 include:sendgrid.net -all")]),
                            dmarc=DmarcAnalysis(name="_dmarc.example.com", lookup_status=DnsQueryStatus.NXDOMAIN),
                            dkim_selectors_checked=[]),
    )
    html = HtmlData(source_url="https://example.com/", resources=[
        ResourceRef(url="https://www.googletagmanager.com/gtag/js", kind="script", host="www.googletagmanager.com", same_site=False),
        ResourceRef(url="https://api.mystery-saas.test/", kind="preconnect", host="api.mystery-saas.test", same_site=False),
        ResourceRef(url="https://example.com/app.js", kind="script", host="example.com", same_site=True),
    ])
    csp = SecurityHeaderParser.inspect("content-security-policy", ["connect-src https://xyz.supabase.co"])
    http = HttpData(probes=[HttpProbe(requested_url="https://example.com/", success=True,
                                      security_headers={"content-security-policy": csp})])
    services = {s.provider: s for s in ThirdPartyCollector("example.com", dns=dns, http=http, html=html, tls=None).build().services}

    assert services["Google Tag Manager"].confidence is Confidence.HIGH
    assert services["Google Workspace"].sources == ["dns:mx"]
    assert services["SendGrid"].confidence is Confidence.MEDIUM
    assert services["Stripe"].sources == ["dns:txt"]
    assert services["Supabase"].confidence is Confidence.LOW and services["Supabase"].sources == ["csp"]
    assert services["mystery-saas.test"].known is False and services["mystery-saas.test"].category == "other"
    assert services["unknown-dns.test"].category == "dns" and not services["unknown-dns.test"].known
    assert "example.com" not in services  # same-site resources are not third parties


BOOTSTRAP = {"services": [[["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
                          [["dev"], ["http://insecure.test/", "https://rdap.nic.google/"]]]}
RDAP_DOMAIN = {
    "ldhName": "EXAMPLE.COM", "status": ["client transfer prohibited"],
    "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
               {"eventAction": "expiration", "eventDate": "2026-01-20T05:00:00Z"}],
    "entities": [{"roles": ["registrar"], "publicIds": [{"type": "IANA Registrar ID", "identifier": "376"}],
                  "vcardArray": ["vcard", [["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]]]},
                 {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Private Person"],
                                                                     ["email", {}, "text", "me@example.com"]]]}],
    "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}, {"ldhName": "B.IANA-SERVERS.NET"}],
    "secureDNS": {"delegationSigned": True},
}


def test_find_rdap_base_prefers_https():
    assert WhoisCollector.find_rdap_base(BOOTSTRAP, "COM") == "https://rdap.verisign.com/com/v1/"
    assert WhoisCollector.find_rdap_base(BOOTSTRAP, "dev") == "https://rdap.nic.google/"
    assert WhoisCollector.find_rdap_base(BOOTSTRAP, "io") is None


def test_parse_rdap_domain_excludes_registrant():
    reg = WhoisCollector.parse_rdap_domain("example.com", RDAP_DOMAIN)
    assert reg.registrar.startswith("RESERVED") and reg.registrar_iana_id == "376"
    assert reg.nameservers == ["a.iana-servers.net", "b.iana-servers.net"]
    assert reg.dnssec is True and reg.created.year == 1995
    assert "me@example.com" not in reg.model_dump_json() and "Private Person" not in reg.model_dump_json()


def _factory(scope):
    return SafeHttpClient(scope, user_agent="t", retries=0, resolve=public_resolve)


@respx.mock
async def test_collect_whois_rdap_path():
    respx.get("https://data.iana.org/rdap/dns.json").mock(return_value=httpx.Response(200, content=json.dumps(BOOTSTRAP)))
    respx.get("https://rdap.verisign.com/com/v1/domain/example.com").mock(
        return_value=httpx.Response(200, content=json.dumps(RDAP_DOMAIN)))
    reg, errors = await WhoisCollector("www.example.com", _factory, now=NOW).collect()
    assert errors == [] and reg.source == "rdap" and reg.days_until_expiry == 19


WHOIS_IO = """\
Domain Name: example.io
Registry Domain ID: abc123
Registrar WHOIS Server: whois.namecheap.com
Updated Date: 2026-08-12T06:33:13Z
Creation Date: 2024-07-25T05:40:00Z
Registry Expiry Date: 2027-07-25T05:40:00Z
Registrar: NAMECHEAP INC
Registrar IANA ID: 1068
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Registrant Email: private@example.io
Registrant Name: Private Person
Name Server: DNS1.REGISTRAR-SERVERS.COM
Name Server: dns2.registrar-servers.com.
DNSSEC: unsigned
>>> Last update of WHOIS database: 2026-11-07T10:00:00Z <<<
Registrar: SHOULD-BE-IGNORED (legal footer)
"""
IANA_IO = "% IANA WHOIS server\n\ndomain:       IO\nrefer:        whois.nic.io\nstatus:       ACTIVE\n"


class FakeWhoisClient:
    def __init__(self, result=None, error=None):
        self.result, self.error, self.calls = result, error, []

    async def lookup(self, domain):
        self.calls.append(domain)
        if self.error:
            raise self.error
        return self.result


@respx.mock
async def test_collect_whois_falls_back_without_rdap():
    respx.get("https://data.iana.org/rdap/dns.json").mock(return_value=httpx.Response(200, content=json.dumps(BOOTSTRAP)))
    client = FakeWhoisClient(result=("whois.nic.io", WHOIS_IO))
    reg, errors = await WhoisCollector("www.example.io", _factory, whois_client=client, now=NOW).collect()
    assert client.calls == ["example.io"]
    assert errors == [] and reg.source == "whois" and reg.source_url == "whois://whois.nic.io"
    assert reg.registrar == "NAMECHEAP INC" and reg.registrar_iana_id == "1068"
    assert reg.created == dt.datetime(2024, 7, 25, 5, 40, tzinfo=dt.UTC)
    assert reg.days_until_expiry == (dt.datetime(2027, 7, 25, 5, 40, tzinfo=dt.UTC) - NOW).days
    assert reg.status == ["clientTransferProhibited"] and reg.dnssec is False
    assert reg.nameservers == ["dns1.registrar-servers.com", "dns2.registrar-servers.com"]
    dumped = reg.model_dump_json()
    assert "private@example.io" not in dumped and "Private Person" not in dumped


@respx.mock
async def test_collect_whois_total_failure_is_reported():
    respx.get("https://data.iana.org/rdap/dns.json").mock(return_value=httpx.Response(503))
    client = FakeWhoisClient(error=WhoisError("whois.nic.io: TimeoutError"))
    reg, errors = await WhoisCollector("example.io", _factory, whois_client=client, now=NOW).collect()
    assert reg is None and {e.error_type for e in errors} == {"rdap_unavailable", "whois_failed"}


@respx.mock
async def test_collect_whois_not_found_is_reported():
    respx.get("https://data.iana.org/rdap/dns.json").mock(return_value=httpx.Response(503))
    client = FakeWhoisClient(result=("whois.nic.io", "NOT FOUND\n>>> Last update of WHOIS database: x <<<"))
    reg, errors = await WhoisCollector("example.io", _factory, whois_client=client, now=NOW).collect()
    assert reg is None and errors[-1].error_type == "whois_no_data"


def test_whois_parser_formats():
    assert WhoisParser.referral(IANA_IO) == "whois.nic.io"
    assert WhoisParser.referral("% nothing here") is None
    reg = WhoisParser.parse("example.de", "Domain: example.de\nNserver: ns1.example.net\nStatus: connect\n"
                                          "Changed: 2020-01-02T03:04:05+01:00\n")
    assert reg.nameservers == ["ns1.example.net"] and reg.status == ["connect"]
    assert reg.updated == dt.datetime(2020, 1, 2, 2, 4, 5, tzinfo=dt.UTC)
    reg = WhoisParser.parse("example.uk", "Registrar: Foo Ltd\nRegistered on: 15-Mar-2001\nExpiry date: 15-Mar-2027\n")
    assert reg.created.date() == dt.date(2001, 3, 15) and reg.expires.year == 2027
    assert WhoisParser.parse("example.com", "No match for \"EXAMPLE.COM\".") is None


class LocalWhoisServer:
    """asyncio WHOIS server: answers each query from a dict and records what it received."""

    def __init__(self, answers):
        self.answers, self.queries = answers, []

    async def handle(self, reader, writer):
        query = (await reader.readline()).decode().strip()
        self.queries.append(query)
        writer.write(self.answers.get(query, "NOT FOUND").encode())
        await writer.drain()
        writer.close()


async def test_whois_client_end_to_end_against_local_server(monkeypatch):
    server = LocalWhoisServer({"io": IANA_IO, "example.io": WHOIS_IO})
    srv = await asyncio.start_server(server.handle, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    monkeypatch.setattr(WhoisClient, "PORT", port)

    async def loopback(host, p):
        return ["127.0.0.1"]

    async with srv:
        client = WhoisClient(timeout=3, retries=0, resolve=loopback, allow_private_networks=True)
        used, text = await client.lookup("example.io")
    assert used == "whois.nic.io" and server.queries == ["io", "example.io"]
    assert WhoisParser.parse("example.io", text, used).registrar == "NAMECHEAP INC"


async def test_whois_client_blocks_private_servers_and_bad_names():
    async def private(host, p):
        return ["10.0.0.5"]

    client = WhoisClient(timeout=1, resolve=private)
    with pytest.raises(WhoisError, match="non-public"):
        await client.query("whois.nic.io", "example.io")
    with pytest.raises(WhoisError, match="invalid WHOIS server"):
        await client.query("evil host; rm", "x")


async def test_whois_client_caps_response_size(monkeypatch):
    server = LocalWhoisServer({"big.io": "x" * 50_000})
    srv = await asyncio.start_server(server.handle, "127.0.0.1", 0)
    monkeypatch.setattr(WhoisClient, "PORT", srv.sockets[0].getsockname()[1])

    async def loopback(host, p):
        return ["127.0.0.1"]

    async with srv:
        client = WhoisClient(timeout=3, retries=0, resolve=loopback, allow_private_networks=True,
                             max_response_bytes=1000)
        text = await client.query("whois.nic.io", "big.io")
    assert len(text) == 1000


def test_engine_new_findings():
    reg = DomainRegistration(domain="example.com", source="rdap", days_until_expiry=10,
                             expires=NOW + dt.timedelta(days=10), status=["client hold"])
    html = HtmlData(source_url="https://example.com/", resources=[
        ResourceRef(url="http://cdn.test/a.js", kind="script", host="cdn.test", same_site=False),
        ResourceRef(url="http://img.test/a.png", kind="image", host="img.test", same_site=False),
        ResourceRef(url="https://cdn.test/b.js", kind="script", host="cdn.test", same_site=False,
                    attributes={"integrity": "present"}),
    ])
    subs = SubdomainData(query="%.example.com", verification_limit=10, hostnames=[
        SubdomainRecord(hostname="vpn.example.com", verified=True, resolves=True,
                        addresses=["10.0.0.1"], private_addresses=["10.0.0.1"])])
    probe = HttpProbe(requested_url="https://example.com/", success=True, final_url="https://example.com/",
                      final_fetched=True, status_code=200, headers={"server": ["nginx/1.18.0"]})
    r = AnalysisEngine(NOW).analyze(dns=None, network=None, http=HttpData(probes=[probe]), tls=None, whois=reg, html=html,
                subdomains=subs)
    found = {f.id.split(":")[0]: f for f in r.findings}
    assert {"whois.expiring", "whois.hold", "html.mixed_active_content", "html.mixed_passive_content",
            "html.third_party_script_no_sri", "subdomains.private_address", "http.version_disclosure"} <= set(found)
    assert found["html.third_party_script_no_sri"].evidence == ["http://cdn.test/a.js"]
