import datetime as dt
import json

import httpx
import pytest
import respx

from recon.models import TlsProbe
from recon.models.dns import DnsQueryResult, DnsQueryStatus, DnsRecord
from recon.models.subdomains import CtEntry, HostState
from recon.modules import CertSpotterProvider, CrtShProvider, CtCache, SubdomainCollector
from recon.utils.domains import normalize_discovered, registrable_domain
from recon.utils.http_client import SafeHttpClient
from recon.utils.scope import Scope
from tests.conftest import public_resolve

NOW = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)

CRTSH = [
    {"id": 1, "issuer_name": "C=US, O=Let's Encrypt, CN=R3", "common_name": "example.com",
     "name_value": "example.com\n*.example.com", "not_before": "2023-01-01T00:00:00", "not_after": "2023-04-01T00:00:00"},
    {"id": 2, "issuer_name": "C=US, O=Let's Encrypt, CN=R10", "common_name": "www.example.com",
     "name_value": "WWW.example.com\napi.example.com", "not_before": "2024-01-01T00:00:00", "not_after": "2024-04-01T00:00:00"},
    {"id": 3, "issuer_name": "C=GB, O=Sectigo Limited, CN=x", "common_name": "old.example.com",
     "name_value": "old.example.com\nexample.com.evil.test\nnotexample.com", "not_before": "2020-01-01T00:00:00",
     "not_after": "2021-01-01T00:00:00"},
    {"id": 4, "issuer_name": "O=Let's Encrypt", "common_name": "*.dev.example.com",
     "name_value": "*.dev.example.com", "not_before": "bad-date", "not_after": None},
    {"id": 5, "issuer_name": "O=Let's Encrypt", "name_value": "internal.example.com",
     "not_before": "2024-06-01T00:00:00", "not_after": "2024-09-01T00:00:00"},
]
CERTSPOTTER = [
    {"id": "9001", "dns_names": ["www.example.com", "shop.example.com"], "not_before": "2025-01-01T00:00:00Z",
     "not_after": "2025-04-01T00:00:00Z", "issuer": {"friendly_name": "Google Trust Services"}},
]


class StubDns:
    async def query(self, name, rtype):
        table = {
            ("www.example.com", "A"): ["93.184.216.34"],
            ("example.com", "A"): ["93.184.216.34"],
            ("shop.example.com", "A"): ["93.184.216.35"],
            ("internal.example.com", "A"): ["10.1.2.3"],
        }
        if (name, rtype) in table:
            return DnsQueryResult(name=name, record_type=rtype, status=DnsQueryStatus.NOERROR,
                                  records=[DnsRecord(value=v) for v in table[(name, rtype)]], response_time_ms=1)
        status = DnsQueryStatus.NODATA if rtype == "AAAA" and name != "old.example.com" else DnsQueryStatus.NXDOMAIN
        if name == "api.example.com" and rtype == "A":
            status = DnsQueryStatus.TIMEOUT
        return DnsQueryResult(name=name, record_type=rtype, status=status, response_time_ms=1)


def ct_client():
    return SafeHttpClient(SubdomainCollector.CT_SCOPE, user_agent="t", retries=0, resolve=public_resolve)


def mock_providers(crtsh=None, certspotter=None):
    respx.get(url__startswith="https://crt.sh/").mock(
        return_value=crtsh if crtsh is not None else httpx.Response(200, content=json.dumps(CRTSH)))
    respx.get(url__startswith="https://api.certspotter.com/").mock(side_effect=[
        certspotter if certspotter is not None else httpx.Response(200, content=json.dumps(CERTSPOTTER)),
        httpx.Response(200, content="[]"),
    ])


def test_aggregate_filters_scope_dedupes_and_records_sources():
    entries = [CtEntry(provider="crt.sh", cert_id="1", names=["example.com", "*.example.com"]),
               CtEntry(provider="certspotter", cert_id="9", names=["EXAMPLE.com.", "x.example.com", "evil.test"])]
    records, dropped = SubdomainCollector.aggregate_ct_entries(entries, Scope.for_target("example.com"))
    by = {r.hostname: r for r in records}
    assert set(by) == {"example.com", "x.example.com"} and dropped == 1
    assert by["example.com"].certificate_count == 2           # one per certificate, not per name
    assert by["example.com"].sources == ["certspotter", "crt.sh"]
    assert by["example.com"].wildcard is False


@respx.mock
async def test_multi_provider_collect_and_verify():
    mock_providers()
    www = respx.get("https://www.example.com/").mock(return_value=httpx.Response(301, headers={"Location": "/x"}))
    internal = respx.get("https://internal.example.com/").mock(return_value=httpx.Response(200))
    respx.get("https://example.com/").mock(return_value=httpx.Response(200))
    respx.get("https://shop.example.com/").mock(side_effect=httpx.ConnectError("refused"))

    async def tls_probe(host):
        return TlsProbe(hostname=host, success=host == "shop.example.com", hostname_match=True)

    async with ct_client() as ct, SafeHttpClient(Scope.for_target("example.com"), user_agent="t", retries=0,
                                                 resolve=public_resolve) as target:
        data, errors = await SubdomainCollector("example.com", ct, StubDns(), http_client=target,
                                                tls_probe=tls_probe).collect()

    assert {p.provider: p.status for p in data.providers} == {"crt.sh": "live", "certspotter": "live"}
    by = {r.hostname: r for r in data.hostnames}
    assert by["www.example.com"].sources == ["certspotter", "crt.sh"]
    assert by["shop.example.com"].sources == ["certspotter"]
    assert by["www.example.com"].state is HostState.REACHABLE and by["www.example.com"].http_status == 301
    assert by["shop.example.com"].state is HostState.REACHABLE and by["shop.example.com"].tls_ok  # TLS answered
    assert by["old.example.com"].state is HostState.HISTORICAL
    assert by["api.example.com"].state is HostState.UNVERIFIED and by["api.example.com"].resolves is None
    assert by["internal.example.com"].private_addresses == ["10.1.2.3"] and not internal.called
    assert www.called and errors == []


@respx.mock
async def test_one_provider_failing_gives_partial_results():
    mock_providers(crtsh=httpx.Response(502))
    async with ct_client() as ct:
        data, errors = await SubdomainCollector("example.com", ct, StubDns()).collect()
    statuses = {p.provider: p.status for p in data.providers}
    assert statuses == {"crt.sh": "failed", "certspotter": "live"}
    assert {r.hostname for r in data.hostnames} == {"www.example.com", "shop.example.com"}
    assert [e.error_type for e in errors] == ["provider_failed"]        # module will report 'partial'


@respx.mock
async def test_cache_is_used_when_a_provider_fails(tmp_path):
    cache = CtCache(tmp_path, dt.timedelta(hours=24))
    mock_providers()
    async with ct_client() as ct:
        await SubdomainCollector("example.com", ct, StubDns(), cache=cache).collect()
    respx.reset()
    mock_providers(crtsh=httpx.Response(503))
    async with ct_client() as ct:
        data, errors = await SubdomainCollector("example.com", ct, StubDns(), cache=cache).collect()
    crtsh = next(p for p in data.providers if p.provider == "crt.sh")
    assert crtsh.status == "cached" and crtsh.cached_at is not None and crtsh.entries == len(CRTSH)
    by = {r.hostname: r for r in data.hostnames}
    assert "cache:crt.sh" in by["old.example.com"].sources
    assert errors and errors[0].error_type == "provider_failed"


def test_stale_cache_is_ignored(tmp_path):
    cache = CtCache(tmp_path, dt.timedelta(hours=1))
    cache.save("crt.sh", "example.com", [CtEntry(provider="crt.sh", names=["a.example.com"])])
    assert cache.load("crt.sh", "example.com", dt.datetime.now(dt.UTC)) is not None
    assert cache.load("crt.sh", "example.com", dt.datetime.now(dt.UTC) + dt.timedelta(hours=2)) is None


@respx.mock
async def test_all_providers_failing_raises_for_module_isolation():
    mock_providers(crtsh=httpx.Response(502), certspotter=httpx.Response(429))
    async with ct_client() as ct:
        with pytest.raises(RuntimeError, match="all CT providers failed"):
            await SubdomainCollector("example.com", ct, StubDns()).collect()


@respx.mock
async def test_verification_limit_reported():
    mock_providers()
    async with ct_client() as ct:
        data, errors = await SubdomainCollector("example.com", ct, StubDns(), verify_limit=2).collect()
    assert data.verified_count == 2 and errors[0].error_type == "verification_limit"
    assert sum(r.verified for r in data.hostnames) == 2


@respx.mock
async def test_certspotter_pagination_and_parsing():
    page1 = [{"id": "1", "dns_names": ["a.example.com"], "issuer": {"name": "C=US, O=X"}},
             {"id": "2", "dns_names": ["b.example.com"], "issuer": None}]
    route = respx.get(url__startswith="https://api.certspotter.com/").mock(side_effect=[
        httpx.Response(200, content=json.dumps(page1)), httpx.Response(200, content="[]")])
    async with ct_client() as ct:
        entries = await CertSpotterProvider().fetch(ct, "example.com")
    assert [e.names for e in entries] == [["a.example.com"], ["b.example.com"]]
    assert "after=2" in str(route.calls[1].request.url)


@respx.mock
async def test_crtsh_truncated_response_is_a_provider_failure():
    respx.get(url__startswith="https://crt.sh/").mock(return_value=httpx.Response(200, content=b"[" + b" " * 5000))
    async with SafeHttpClient(SubdomainCollector.CT_SCOPE, user_agent="t", retries=0, resolve=public_resolve,
                              max_response_bytes=100) as ct:
        from recon.modules import CtProviderError
        with pytest.raises(CtProviderError, match="size limit"):
            await CrtShProvider().fetch(ct, "example.com")


@pytest.mark.parametrize("raw, expected", [
    ("*.Example.com.", ("example.com", True)), ("api.example.com", ("api.example.com", False)),
    ("user@example.com", None), ("foo bar", None), ("localhost", None), ("a.*.example.com", None),
])
def test_normalize_discovered(raw, expected):
    assert normalize_discovered(raw) == expected


@pytest.mark.parametrize("host, expected", [
    ("www.example.com", "example.com"), ("a.b.example.co.uk", "example.co.uk"), ("example.io", "example.io"),
])
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected
