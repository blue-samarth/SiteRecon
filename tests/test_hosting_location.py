import datetime as dt

from recon.analysis import AnalysisEngine, ObservationBuilder
from recon.models import (
    AsnInfo,
    CollectionMethod,
    GeoLocation,
    IpIntel,
    ModuleResult,
    ModuleStatus,
    NetworkData,
    RdapNetwork,
)
from recon.utils import GeoLocator
from recon.utils.geoip import record_to_location

T0 = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)

CITY_RECORD = {
    "country": {"iso_code": "US", "names": {"en": "United States"}},
    "subdivisions": [{"iso_code": "VA", "names": {"en": "Virginia"}}],
    "city": {"names": {"en": "Ashburn"}},
    "location": {"latitude": 39.04, "longitude": -77.47},
}


class _FakeReader:
    def __init__(self, mapping):
        self._mapping = mapping

    def get(self, ip):
        if ip == "boom":
            raise ValueError("bad address")
        return self._mapping.get(ip)


def locator(mapping):
    return GeoLocator(_FakeReader(mapping), source="DBIP-City-Lite", database_date="2026-11-01")


# ------------------------------------------------------------------ GeoLocator fail-soft

def test_open_returns_none_without_a_database():
    assert GeoLocator.open(None) is None
    assert GeoLocator.open("/no/such/file.mmdb") is None


def test_record_parsing_maps_geoip2_schema():
    loc = record_to_location(CITY_RECORD, "DBIP-City-Lite", "2026-11-01")
    assert (loc.country, loc.country_code, loc.region, loc.city) == ("United States", "US", "Virginia", "Ashburn")
    assert loc.latitude == 39.04 and loc.source == "DBIP-City-Lite" and loc.database_date == "2026-11-01"


def test_lookup_hit_miss_and_bad_input():
    loc = locator({"1.2.3.4": CITY_RECORD})
    assert locator({"1.2.3.4": CITY_RECORD}).lookup("1.2.3.4").city == "Ashburn"
    assert loc.lookup("9.9.9.9") is None          # not in the database
    assert loc.lookup("boom") is None             # reader error is swallowed, not raised


# ------------------------------------------------------------------ hosting finding

def ip(addr, *, asn_name=None, country=None, orgs=None, city=None, is_public=True):
    return IpIntel(
        ip=addr, version=4, is_public=is_public,
        asn=AsnInfo(asn=1, name=asn_name, country=country) if asn_name or country else None,
        rdap=RdapNetwork(country=country, organizations=list(orgs or [])) if (country or orgs) else None,
        geo=GeoLocation(country_code=country, city=city, region="Virginia", source="DBIP-City-Lite",
                        database_date="2026-11-01") if city else None)


def hosting(net):
    res = AnalysisEngine(T0).analyze(dns=None, network=net, http=None, tls=None, host="example.com")
    return next((f for f in res.findings if f.category == "hosting"), None)


def test_country_and_org_from_registry_without_a_geo_db():
    f = hosting(NetworkData(ips=[ip("203.0.113.5", asn_name="AMAZON-AES", country="US", orgs=["Amazon"])]))
    assert f is not None and f.severity.value == "informational" and f.subject == "example.com"
    assert "country US" in f.evidence[0] and "org Amazon" in f.evidence[0]
    assert "city" not in f.evidence[0]          # no geo DB → no city, and no attribution line
    assert not any("attribution" in e for e in f.evidence)
    assert "estimate" in f.description.lower()


def test_city_and_attribution_when_geo_present():
    f = hosting(NetworkData(ips=[ip("203.0.113.5", country="US", orgs=["Amazon"], city="Ashburn")]))
    joined = "\n".join(f.evidence)
    assert "city ~Ashburn, Virginia" in joined and "DBIP-City-Lite" in joined
    assert any("attribution required" in e for e in f.evidence)


def test_cdn_ip_is_reported_as_anycast_without_a_location():
    f = hosting(NetworkData(ips=[ip("104.16.0.1", asn_name="CLOUDFLARENET", country="US", orgs=["Cloudflare, Inc."])]))
    assert "CDN/anycast" in f.evidence[0] and "not meaningful" in f.evidence[0]
    assert "country" not in f.evidence[0]       # location suppressed for anycast


def test_no_public_ip_means_no_finding():
    assert hosting(NetworkData(ips=[ip("10.0.0.1", is_public=False)])) is None
    assert hosting(NetworkData(ips=[])) is None


# ------------------------------------------------------------------ geo observation provenance

def test_geo_observation_carries_provenance():
    net = NetworkData(ips=[ip("203.0.113.5", country="US", orgs=["Amazon"], city="Ashburn"),
                           ip("104.16.0.1", asn_name="CLOUDFLARENET", country="US")])  # no geo on #2
    r = ModuleResult(module="network", status=ModuleStatus.SUCCESS, started_at=T0, finished_at=T0,
                     duration_ms=1, data=net)
    obs = {(o.type, o.target): o for o in ObservationBuilder("example.com", {"network": r}).build()}
    geo = obs[("network.geo", "203.0.113.5")]
    assert geo.value == {"country": "US", "region": "Virginia", "city": "Ashburn"}
    assert geo.collection_method == CollectionMethod.LOCAL_DATABASE
    assert geo.external_provider == "DBIP-City-Lite" and geo.observed_at == dt.datetime(2026, 11, 1, tzinfo=dt.UTC)
    assert ("network.geo", "104.16.0.1") not in obs   # no geo data → no geo observation
