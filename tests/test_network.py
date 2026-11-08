import ipaddress
import json

import httpx
import respx

from recon.models.dns import DnsQueryResult, DnsQueryStatus, DnsRecord
from recon.modules import NetworkCollector
from recon.utils.http_client import SafeHttpClient
from tests.conftest import public_resolve

RDAP = {
    "handle": "NET-76-76-21-0-1", "name": "VERCEL-01", "type": "DIRECT ALLOCATION",
    "startAddress": "76.76.21.0", "endAddress": "76.76.21.255", "country": "US",
    "cidr0_cidrs": [{"v4prefix": "76.76.21.0", "length": 24}],
    "entities": [
        {"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Abuse Desk"]]]},
        {"roles": ["registrant"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                          ["fn", {}, "text", "Vercel, Inc"]]]},
    ],
}


def test_cymru_names():
    assert NetworkCollector.cymru_origin_name(ipaddress.ip_address("76.76.21.21")) == "21.21.76.76.origin.asn.cymru.com"
    v6 = NetworkCollector.cymru_origin_name(ipaddress.ip_address("2606:4700::1"))
    assert v6.endswith(".origin6.asn.cymru.com") and v6.startswith("1.0.0.0.")


def test_parse_cymru():
    info = NetworkCollector.parse_cymru_origin("16509 13335 | 76.76.21.0/24 | US | arin | 2020-01-01")
    assert info.asn == 16509 and info.prefix == "76.76.21.0/24" and info.registry == "arin"
    assert NetworkCollector.parse_cymru_origin("garbage") is None
    assert NetworkCollector.parse_cymru_asname("16509 | US | arin | 2000-05-04 | AMAZON-02 - Amazon.com, Inc., US") \
        == "AMAZON-02 - Amazon.com, Inc., US"


def test_parse_rdap_prefers_registrant():
    net = NetworkCollector.parse_rdap(RDAP)
    assert net.name == "VERCEL-01" and net.cidrs == ["76.76.21.0/24"]
    assert net.organizations == ["Vercel, Inc"]


class StubDns:
    def __init__(self):
        self.calls = []

    async def query(self, name, rtype):
        self.calls.append((name, rtype))
        answers = {
            "21.21.76.76.in-addr.arpa": DnsQueryStatus.NXDOMAIN,
            "21.21.76.76.origin.asn.cymru.com": ["16509 | 76.76.21.0/24 | US | arin | 2020-01-01"],
            "AS16509.asn.cymru.com": ["16509 | US | arin | 2000-05-04 | AMAZON-02 - Amazon.com, Inc., US"],
        }
        a = answers.get(name, DnsQueryStatus.NXDOMAIN)
        if isinstance(a, DnsQueryStatus):
            return DnsQueryResult(name=name, record_type=rtype, status=a, response_time_ms=1)
        return DnsQueryResult(name=name, record_type=rtype, status=DnsQueryStatus.NOERROR,
                              records=[DnsRecord(value=v) for v in a], response_time_ms=1)


@respx.mock
async def test_collect_network_dedupes_and_follows_rdap_redirect():
    respx.get("https://rdap.org/ip/76.76.21.21").mock(
        return_value=httpx.Response(302, headers={"Location": "https://rdap.arin.net/registry/ip/76.76.21.21"}))
    arin = respx.get("https://rdap.arin.net/registry/ip/76.76.21.21").mock(
        return_value=httpx.Response(200, content=json.dumps(RDAP)))
    stub = StubDns()
    async with SafeHttpClient(NetworkCollector.RDAP_SCOPE, user_agent="t", retries=0, resolve=public_resolve) as rdap:
        data, errors = await NetworkCollector(["76.76.21.21", "76.76.21.21", "10.0.0.1"], stub, rdap).collect()

    assert [i.ip for i in data.ips] == ["76.76.21.21", "10.0.0.1"]
    pub, priv = data.ips
    assert arin.call_count == 1
    assert pub.asn.asn == 16509 and pub.asn.name.startswith("AMAZON-02")
    assert pub.rdap.organizations == ["Vercel, Inc"]
    assert pub.ptr == [] and pub.ptr_status is DnsQueryStatus.NXDOMAIN
    assert priv.is_public is False and priv.asn is None and priv.rdap is None
    assert errors == []


@respx.mock
async def test_rdap_failure_is_recorded_not_raised():
    respx.get("https://rdap.org/ip/76.76.21.21").mock(return_value=httpx.Response(404))
    async with SafeHttpClient(NetworkCollector.RDAP_SCOPE, user_agent="t", retries=0, resolve=public_resolve) as rdap:
        data, errors = await NetworkCollector(["76.76.21.21"], StubDns(), rdap).collect()
    assert data.ips[0].rdap is None and data.ips[0].asn is not None
    assert errors and errors[0].error_type == "http_404"
