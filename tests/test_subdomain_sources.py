'''
Passive (non-CT) subdomain sources: parsing, scope filtering, failure isolation and credential gating.

Every provider is mocked with respx; no test touches a real service.
'''

import datetime as dt
import json

import httpx
import pytest
import respx

from recon.models.dns import DnsQueryResult, DnsQueryStatus, DnsRecord
from recon.modules import (
    AlienVaultOtxSource,
    AnubisSource,
    BufferOverSource,
    CommonCrawlSource,
    HackerTargetSource,
    PassiveCache,
    RapidDnsSource,
    SourceError,
    SubdomainCollector,
    UrlScanSource,
    WaybackSource,
)
from recon.modules.subdomain_sources import (
    ALL_SOURCES,
    KEYLESS,
    REGISTRY,
    in_scope_names,
    resolve_sources,
    scope_hosts,
    unknown_sources,
)
from recon.utils.http_client import SafeHttpClient
from recon.utils.scope import Scope
from tests.conftest import public_resolve

ALL_HOSTS = sorted({h for cls in REGISTRY.values() for h in cls.HOSTS})


def client():
    return SafeHttpClient(Scope(hosts=ALL_HOSTS), user_agent="t", retries=0, resolve=public_resolve)


async def fetch(source, hostname="example.com"):
    async with client() as http:
        return await source.fetch(http, hostname)


class StubDns:
    '''Resolves only the names listed; everything else is NXDOMAIN.'''

    def __init__(self, table=None):
        self.table = table or {}
        self.queried: list[tuple[str, str]] = []

    async def query(self, name, rtype):
        self.queried.append((name, rtype))
        values = self.table.get((name, rtype))
        if values:
            return DnsQueryResult(name=name, record_type=rtype, status=DnsQueryStatus.NOERROR,
                                  records=[DnsRecord(value=v) for v in values], response_time_ms=1)
        return DnsQueryResult(name=name, record_type=rtype, status=DnsQueryStatus.NXDOMAIN, response_time_ms=1)


# ------------------------------------------------------------------ individual sources

@respx.mock
async def test_otx_parses_passive_dns_rows():
    respx.get(url__startswith="https://otx.alienvault.com/api/v1/indicators/domain/").mock(
        return_value=httpx.Response(200, json={"passive_dns": [
            {"hostname": "api.example.com", "address": "93.184.216.34", "first": "2024-01-01T00:00:00",
             "last": "2025-01-01T00:00:00", "record_type": "A"},
            {"hostname": "WWW.example.com", "address": "93.184.216.35"},
            {"address": "1.2.3.4"},                       # no hostname → the address is not a name
        ]}))
    entries = await fetch(AlienVaultOtxSource())
    hosts = [e.hostname for e in entries]
    assert "api.example.com" in hosts and "WWW.example.com" in hosts
    first = next(e for e in entries if e.hostname == "api.example.com")
    assert first.first_seen == dt.datetime(2024, 1, 1, tzinfo=dt.UTC)
    assert first.last_seen == dt.datetime(2025, 1, 1, tzinfo=dt.UTC)
    assert first.address == "93.184.216.34" and first.detail == "A"


@respx.mock
async def test_otx_rejects_unexpected_shape():
    respx.get(url__startswith="https://otx.alienvault.com/").mock(return_value=httpx.Response(200, json={"x": 1}))
    with pytest.raises(SourceError, match="passive_dns"):
        await fetch(AlienVaultOtxSource())


@respx.mock
async def test_urlscan_collects_hostnames_from_results():
    respx.get(url__startswith="https://urlscan.io/api/v1/search/").mock(
        return_value=httpx.Response(200, json={"results": [
            {"page": {"domain": "shop.example.com", "url": "https://shop.example.com/cart"},
             "task": {"time": "2025-06-01T10:00:00.000Z"}},
            {"page": {"domain": "example.com", "apexDomain": "example.com"}},
            {"not": "a dict page"},
        ]}))
    entries = await fetch(UrlScanSource())
    assert "shop.example.com" in {e.hostname for e in entries}
    dated = next(e for e in entries if e.hostname == "shop.example.com")
    assert dated.last_seen is not None and dated.last_seen.year == 2025


@respx.mock
async def test_commoncrawl_follows_the_latest_collection_index():
    respx.get("https://index.commoncrawl.org/collinfo.json").mock(return_value=httpx.Response(200, json=[
        {"id": "CC-MAIN-2026-05", "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2026-05-index"},
        {"id": "CC-MAIN-2025-50", "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2025-50-index"},
    ]))
    index = respx.get(url__startswith="https://index.commoncrawl.org/CC-MAIN-2026-05-index").mock(
        return_value=httpx.Response(200, content=b'{"url": "https://cdn.example.com/a.js", "timestamp": "20250101000000"}\n'
                                                 b'{"url": "https://example.com/"}\n'
                                                 b'not json\n'))
    entries = await fetch(CommonCrawlSource())
    assert {e.hostname for e in entries} == {"cdn.example.com", "example.com"}
    assert index.called                                   # the newest crawl, not the older one


@respx.mock
async def test_commoncrawl_refuses_an_offsite_cdx_endpoint():
    # A collection list naming a host outside the source's allow-list must not be followed.
    respx.get("https://index.commoncrawl.org/collinfo.json").mock(return_value=httpx.Response(
        200, json=[{"id": "x", "cdx-api": "https://evil.test/index"}]))
    with pytest.raises(SourceError, match="no usable cdx-api"):
        await fetch(CommonCrawlSource())


@respx.mock
async def test_wayback_extracts_hostnames_and_skips_the_header_row():
    respx.get(url__startswith="https://web.archive.org/cdx/search/cdx").mock(
        return_value=httpx.Response(200, content=json.dumps([
            ["original", "timestamp"],
            ["https://old.example.com/index.php", "20190101000000"],
            ["http://example.com/", "20200101000000"],
        ]).encode()))
    entries = await fetch(WaybackSource())
    assert {e.hostname for e in entries} == {"old.example.com", "example.com"}


@respx.mock
async def test_rapiddns_extracts_names_from_markup():
    page = ("<table><tr><td>dev.example.com</td><td>10.0.0.1</td></tr>"
            "<tr><td>mail.example.com</td></tr><tr><td>other.test</td></tr></table>")
    respx.get(url__startswith="https://rapiddns.io/subdomain/").mock(return_value=httpx.Response(200, text=page))
    entries = await fetch(RapidDnsSource())
    assert {e.hostname for e in entries} == {"dev.example.com", "mail.example.com"}


@respx.mock
async def test_rapiddns_layout_change_yields_nothing_not_garbage():
    respx.get(url__startswith="https://rapiddns.io/").mock(
        return_value=httpx.Response(200, text="<html><body>no table here</body></html>"))
    assert await fetch(RapidDnsSource()) == []


@respx.mock
async def test_hackertarget_splits_host_and_address_rows():
    respx.get(url__startswith="https://api.hackertarget.com/hostsearch/").mock(
        return_value=httpx.Response(200, text="api.example.com,93.184.216.34\nvpn.example.com,198.51.100.7\n"))
    entries = await fetch(HackerTargetSource())
    assert [(e.hostname, e.address) for e in entries] == [
        ("api.example.com", "93.184.216.34"), ("vpn.example.com", "198.51.100.7")]


@respx.mock
async def test_hackertarget_quota_message_is_a_source_error():
    respx.get(url__startswith="https://api.hackertarget.com/").mock(
        return_value=httpx.Response(200, text="error check your api key or API count exceeded"))
    with pytest.raises(SourceError):
        await fetch(HackerTargetSource())


@respx.mock
async def test_anubis_parses_a_plain_array_and_tolerates_null():
    route = respx.get(url__startswith="https://jldc.me/anubis/subdomains/")
    route.mock(return_value=httpx.Response(200, json=["a.example.com", "b.example.com", 7]))
    assert {e.hostname for e in await fetch(AnubisSource())} == {"a.example.com", "b.example.com"}
    route.mock(return_value=httpx.Response(200, content=b"null"))
    assert await fetch(AnubisSource()) == []


async def test_bufferover_is_skipped_without_its_api_key(monkeypatch):
    monkeypatch.delenv("SITERECON_BUFFEROVER_KEY", raising=False)
    source = BufferOverSource()
    assert source.unavailable() == "needs an API key in $SITERECON_BUFFEROVER_KEY"
    monkeypatch.setenv("SITERECON_BUFFEROVER_KEY", "k")
    assert source.unavailable() is None
    assert source.headers()["x-api-key"] == "k"


@respx.mock
async def test_bufferover_accepts_current_and_legacy_shapes(monkeypatch):
    monkeypatch.setenv("SITERECON_BUFFEROVER_KEY", "k")
    route = respx.get(url__startswith="https://tls.bufferover.run/dns").mock(
        return_value=httpx.Response(200, json={"Results": ["93.184.216.34,api.example.com"],
                                               "FDNS_A": ["198.51.100.7,legacy.example.com"]}))
    entries = await fetch(BufferOverSource())
    assert {e.hostname for e in entries} == {"api.example.com", "legacy.example.com"}
    assert {e.address for e in entries} == {"93.184.216.34", "198.51.100.7"}
    assert route.calls[0].request.headers["x-api-key"] == "k"   # the key is sent, never logged


# ------------------------------------------------------------------ registry and scoping

def test_passive_sources_are_off_unless_requested():
    # Each source discloses the target to another third party, so the default is CT-only.
    assert resolve_sources(None) == [] and resolve_sources([]) == [] and resolve_sources(["none"]) == []
    assert resolve_sources(["all"]) == list(ALL_SOURCES)
    assert resolve_sources(["keyless"]) == list(KEYLESS)
    assert resolve_sources(["otx", "unknown"]) == ["otx"]
    assert "bufferover" not in KEYLESS            # it needs a credential


def test_unknown_source_names_are_reported_for_rejection():
    assert unknown_sources(["otx", "typo", "all"]) == ["typo"]
    assert unknown_sources(None) == [] and unknown_sources(["all", "none", "keyless"]) == []


def test_client_scope_covers_exactly_the_enabled_source_hosts():
    assert scope_hosts(["otx"]) == ["otx.alienvault.com"]
    assert scope_hosts([]) == []
    assert set(scope_hosts(list(ALL_SOURCES))) == set(ALL_HOSTS)


def test_out_of_scope_names_are_dropped_before_use():
    from recon.models.subdomains import PassiveEntry
    entries = [PassiveEntry(source="otx", hostname="api.example.com"),
               PassiveEntry(source="otx", hostname="example.com"),
               PassiveEntry(source="otx", hostname="example.com.evil.test"),
               PassiveEntry(source="otx", hostname="notexample.com")]
    assert [e.hostname for e in in_scope_names(entries, "example.com")] == ["api.example.com", "example.com"]


# ------------------------------------------------------------------ collector integration

def ct_client():
    return SafeHttpClient(SubdomainCollector.CT_SCOPE, user_agent="t", retries=0, resolve=public_resolve)


def mock_ct(entries="[]"):
    respx.get(url__startswith="https://crt.sh/").mock(return_value=httpx.Response(200, content=entries))
    respx.get(url__startswith="https://api.certspotter.com/").mock(return_value=httpx.Response(200, content="[]"))


@respx.mock
async def test_passive_names_merge_with_ct_names_crediting_every_source():
    crtsh = json.dumps([{"id": 1, "issuer_name": "O=Let's Encrypt", "name_value": "api.example.com",
                         "not_before": "2024-01-01T00:00:00", "not_after": "2024-04-01T00:00:00"}])
    mock_ct(crtsh)
    respx.get(url__startswith="https://otx.alienvault.com/").mock(
        return_value=httpx.Response(200, json={"passive_dns": [
            {"hostname": "api.example.com", "first": "2020-01-01T00:00:00"},
            {"hostname": "vpn.example.com", "last": "2026-01-01T00:00:00"},
            {"hostname": "elsewhere.test"}]}))
    async with ct_client() as ct, client() as passive:
        data, errors = await SubdomainCollector(
            "example.com", ct, StubDns(), passive_client=passive,
            passive_sources=[AlienVaultOtxSource()]).collect()
    by = {r.hostname: r for r in data.hostnames}
    assert by["api.example.com"].sources == ["crt.sh", "otx"]
    assert by["api.example.com"].certificate_count == 1
    assert by["vpn.example.com"].sources == ["otx"] and by["vpn.example.com"].certificate_count == 0
    # the passive source widened the window on a name CT already knew
    assert by["api.example.com"].first_seen == dt.datetime(2020, 1, 1, tzinfo=dt.UTC)
    assert "elsewhere.test" not in by and data.out_of_scope_dropped == 1
    assert [(s.provider, s.status, s.names) for s in data.sources] == [("otx", "live", 2)]
    assert errors == []


@respx.mock
async def test_a_failing_passive_source_never_fails_the_module():
    mock_ct(json.dumps([{"id": 1, "issuer_name": "O=X", "name_value": "api.example.com"}]))
    respx.get(url__startswith="https://otx.alienvault.com/").mock(return_value=httpx.Response(502))
    async with ct_client() as ct, client() as passive:
        data, errors = await SubdomainCollector("example.com", ct, StubDns(), passive_client=passive,
                                                passive_sources=[AlienVaultOtxSource()]).collect()
    assert [s.status for s in data.sources] == ["failed"]
    assert [e.error_type for e in errors] == ["source_failed"]
    assert {r.hostname for r in data.hostnames} == {"api.example.com"}      # CT results survive


@respx.mock
async def test_passive_results_fall_back_to_cache_when_the_source_fails(tmp_path):
    cache = PassiveCache(tmp_path, dt.timedelta(hours=24))
    mock_ct()
    otx = respx.get(url__startswith="https://otx.alienvault.com/")
    otx.mock(return_value=httpx.Response(200, json={"passive_dns": [{"hostname": "cached.example.com"}]}))
    async with ct_client() as ct, client() as passive:
        await SubdomainCollector("example.com", ct, StubDns(), passive_client=passive,
                                 passive_sources=[AlienVaultOtxSource()], passive_cache=cache).collect()
    otx.mock(return_value=httpx.Response(503))
    async with ct_client() as ct, client() as passive:
        data, errors = await SubdomainCollector("example.com", ct, StubDns(), passive_client=passive,
                                                passive_sources=[AlienVaultOtxSource()],
                                                passive_cache=cache).collect()
    source = next(s for s in data.sources if s.provider == "otx")
    assert source.status == "cached" and source.cached_at is not None
    # a cached name is labelled as cached, never presented as a live observation
    assert {r.hostname: r.sources for r in data.hostnames} == {"cached.example.com": ["cache:otx"]}
    assert errors and errors[0].error_type == "source_failed"


@respx.mock
async def test_ct_failure_is_survivable_when_a_passive_source_answered():
    mock_ct()
    respx.reset()
    respx.get(url__startswith="https://crt.sh/").mock(return_value=httpx.Response(502))
    respx.get(url__startswith="https://api.certspotter.com/").mock(return_value=httpx.Response(429))
    respx.get(url__startswith="https://otx.alienvault.com/").mock(
        return_value=httpx.Response(200, json={"passive_dns": [{"hostname": "api.example.com"}]}))
    async with ct_client() as ct, client() as passive:
        data, _ = await SubdomainCollector("example.com", ct, StubDns(), passive_client=passive,
                                           passive_sources=[AlienVaultOtxSource()]).collect()
    assert all(p.status == "failed" for p in data.providers)
    assert {r.hostname for r in data.hostnames} == {"api.example.com"}


@respx.mock
async def test_a_key_gated_source_is_recorded_as_skipped_with_its_reason(monkeypatch):
    monkeypatch.delenv("SITERECON_BUFFEROVER_KEY", raising=False)
    mock_ct()
    async with ct_client() as ct, client() as passive:
        data, errors = await SubdomainCollector("example.com", ct, StubDns(), passive_client=passive,
                                                passive_sources=[BufferOverSource()]).collect()
    skipped = next(s for s in data.sources if s.provider == "bufferover")
    assert skipped.status == "skipped" and "API key" in (skipped.skip_reason or "")
    assert errors == []          # a deliberate skip is not an error


@respx.mock
async def test_sources_are_skipped_when_no_client_was_configured():
    mock_ct()
    async with ct_client() as ct:
        data, _ = await SubdomainCollector("example.com", ct, StubDns(), passive_client=None,
                                           passive_sources=[AlienVaultOtxSource()]).collect()
    assert [s.status for s in data.sources] == ["skipped"]
