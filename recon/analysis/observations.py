from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from recon.models import CollectionMethod, Confidence, Freshness, ModuleResult, ModuleStatus, Observation


def _parse_date(value: str | None) -> datetime | None:
    '''
    Parse a YYYY-MM-DD database-build date into a timezone-aware datetime, or None.
    Parameters:
        value (str | None): The date string.
    Returns:
        datetime | None: The parsed datetime (UTC), or None if absent/unparseable.
    '''
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=UTC)
    except ValueError:
        return None

_COLLECTION_METHOD: dict[str, CollectionMethod] = {
    "dns": CollectionMethod.DNS_QUERY,
    "dnssec": CollectionMethod.DNS_QUERY,
    "network": CollectionMethod.NETWORK_LOOKUP,
    "http": CollectionMethod.HTTP_REQUEST,
    "tls": CollectionMethod.TLS_HANDSHAKE,
    "whois": CollectionMethod.WHOIS_LOOKUP,
    "resources": CollectionMethod.HTTP_REQUEST,
    "crawler": CollectionMethod.HTTP_REQUEST,
    "html": CollectionMethod.STATIC_ANALYSIS,
    "javascript": CollectionMethod.STATIC_ANALYSIS,
    "technology": CollectionMethod.DERIVED,
    "cookies": CollectionMethod.HTTP_REQUEST,
    "subdomains": CollectionMethod.CT_LOG,
    "third_party": CollectionMethod.DERIVED,
}


class ObservationBuilder:
    '''
    Converts module data into Observation records (one per comparable fact).
    Volatile values (timings, TTLs, request IDs) are deliberately excluded so comparisons stay meaningful.
    '''

    def __init__(self, hostname: str, modules: dict[str, ModuleResult]) -> None:
        '''
        Create a builder.
        Parameters:
            hostname (str): Target hostname.
            modules (dict[str, ModuleResult]): Module results keyed by name.
        '''
        self.hostname = hostname
        self.modules = modules
        self._out: dict[str, Observation] = {}

    @staticmethod
    def make_id(type_: str, target: str, key: str) -> str: return hashlib.sha1(f"{type_}|{target}|{key}".encode()).hexdigest()[:12]

    def build(self) -> list[Observation]:
        '''
        Build observations for every module that produced data.
        Returns:
            list[Observation]: Observations sorted by type, target and key.
        '''
        for name, result in self.modules.items():
            if result.data is None or result.status in (ModuleStatus.FAILED, ModuleStatus.SKIPPED):
                continue
            handler = getattr(self, f"_{name}", None)
            if handler:
                handler(result)
        return sorted(self._out.values(), key=lambda o: (o.type, o.target, o.key))

    def _add(self, result: ModuleResult, type_: str, target: str, key: str, value: Any, source: str,
             confidence: Confidence = Confidence.HIGH, *, collection_method: str | None = None,
             external_provider: str | None = None, observed_at: datetime | None = None,
             freshness: Freshness | None = None) -> None:
        '''
        Record one observation; the first one recorded for a (type, target, key) wins, so probes that end
        at the same URL (e.g. https:// and https://www. redirecting to one page) are not duplicated.
        Parameters:
            result (ModuleResult): Module result the observation came from.
            type_ (str): Observation type.
            target (str): Observed target.
            key (str): Distinguishing key.
            value (Any): JSON-serializable value.
            source (str): Evidence source description.
            confidence (Confidence): Confidence in the observation.
            collection_method (str | None): Override the module's default collection method.
            external_provider (str | None): Third-party/offline provider this fact came from, if any.
            observed_at (datetime | None): When the fact was true at the source, if different from collection.
            freshness (Freshness | None): Override the default freshness (FRESH for direct collection).
        '''
        obs_id: str = self.make_id(type_, target, key)
        if obs_id in self._out: return

        self._out[obs_id] = Observation(
            id=obs_id, module=result.module, target=target, type=type_, key=key,
            value=value, source=source,
            collection_method=collection_method or _COLLECTION_METHOD.get(result.module, CollectionMethod.UNKNOWN),
            timestamp=result.finished_at, observed_at=observed_at, confidence=confidence,
            freshness=freshness or Freshness.FRESH, external_provider=external_provider,
            status=result.status.value)

    def _dns(self, r: ModuleResult) -> None:
        '''
        DNS records (definitive answers only), SPF, DMARC, DKIM and effective CAA.
        Parameters:
            r (ModuleResult): DNS module result.
        '''
        d = r.data
        for key, q in d.queries.items():
            if q.status.is_definitive:
                self._add(r, "dns.record", q.name, key, sorted(q.values), f"DNS {q.record_type} {q.name}")
        self._add(r, "email.spf", d.hostname, "records", sorted(rec.raw for rec in d.email.spf.records), "DNS TXT")
        if d.email.spf.lookup_count is not None:
            self._add(r, "email.spf", d.hostname, "lookup_count", d.email.spf.lookup_count, "SPF evaluation")
        self._add(r, "email.dmarc", d.email.dmarc.name, "records", sorted(d.email.dmarc.raw_records), "DNS TXT")
        for k in d.email.dkim_found:
            self._add(r, "email.dkim", k.name, k.selector, {"key_type": k.key_type, "key_bits": k.key_bits,
                                                             "revoked": k.revoked}, "DNS TXT")
        if d.caa.complete:
            self._add(r, "dns.caa_effective", d.hostname, "policy",
                      {"name": d.caa.effective_name, "records": sorted(d.caa.records), "inherited": d.caa.inherited},
                      "DNS CAA (parent climb)")

    def _dnssec(self, r: ModuleResult) -> None:
        '''
        DNSSEC status for the zone.
        Parameters:
            r (ModuleResult): DNSSEC module result.
        '''
        d = r.data
        self._add(r, "dnssec.status", d.zone, "status", d.status.value, "DS + DNSKEY + resolver AD flag")

    def _network(self, r: ModuleResult) -> None:
        '''
        Per-IP allocation (ASN, RDAP network, PTR).
        Parameters:
            r (ModuleResult): Network module result.
        '''
        for ip in r.data.ips:
            self._add(r, "network.ip", ip.ip, "allocation", {
                "asn": ip.asn.asn if ip.asn else None, "asn_name": ip.asn.name if ip.asn else None,
                "rdap_network": ip.rdap.name if ip.rdap else None, "ptr": sorted(ip.ptr)}, "ASN/RDAP/PTR")
            geo = ip.geo
            if geo is not None and (geo.country or geo.city):
                observed = _parse_date(geo.database_date)
                self._add(r, "network.geo", ip.ip, "location",
                          {"country": geo.country_code or geo.country, "region": geo.region, "city": geo.city},
                          f"offline geolocation database ({geo.source})", confidence=Confidence.MEDIUM,
                          collection_method=CollectionMethod.LOCAL_DATABASE, external_provider=geo.source,
                          observed_at=observed, freshness=Freshness.UNKNOWN)

    def _http(self, r: ModuleResult) -> None:
        '''
        Per-probe final response, security headers, cache and CORS headers.
        Parameters:
            r (ModuleResult): HTTP module result.
        '''
        for p in r.data.probes:
            if not p.success:
                continue
            self._add(r, "http.response", p.requested_url, "final", {
                "status": p.status_code, "final_url": p.final_url, "redirects_to_https": p.redirects_to_https,
                "server": p.server}, f"GET {p.requested_url}")
            if p.final_fetched and p.final_url:
                for name, sh in p.security_headers.items():
                    self._add(r, "http.security_header", p.final_url, name, sh.value, f"GET {p.final_url}")
                self._add(r, "http.header", p.final_url, "cache-control", p.cache_control, f"GET {p.final_url}")
                self._add(r, "http.header", p.final_url, "cors", p.cors, f"GET {p.final_url}")

    def _tls(self, r: ModuleResult) -> None:
        '''
        Per-host certificate identity and negotiated protocol.
        Parameters:
            r (ModuleResult): TLS module result.
        '''
        for p in r.data.probes:
            if p.success and p.certificate:
                c = p.certificate
                self._add(r, "tls.certificate", f"{p.hostname}:{p.port}", "certificate", {
                    "fingerprint_sha256": c.fingerprint_sha256, "issuer": c.issuer_org or c.issuer,
                    "not_after": c.not_after.isoformat(), "san_count": len(c.san_dns)}, "TLS handshake")
                self._add(r, "tls.protocol", f"{p.hostname}:{p.port}", "version", p.tls_version, "TLS handshake")

    def _whois(self, r: ModuleResult) -> None:
        '''
        Registrar, expiry, status and nameservers.
        Parameters:
            r (ModuleResult): Registration module result.
        '''
        d = r.data
        self._add(r, "registration", d.domain, "registrar", d.registrar, d.source)
        self._add(r, "registration", d.domain, "expires", d.expires.isoformat() if d.expires else None, d.source)
        self._add(r, "registration", d.domain, "status", sorted(d.status), d.source)
        self._add(r, "registration", d.domain, "nameservers", sorted(d.nameservers), d.source)

    def _html(self, r: ModuleResult) -> None:
        '''
        Landing-page SEO metadata and social (Open Graph / Twitter) cards, so metadata changes are tracked
        across scans and can back SEO/social findings as evidence. Only present values are recorded, so a
        later scan that drops a tag shows up as a removed observation rather than a change to null.
        Parameters:
            r (ModuleResult): HTML module result.
        '''
        d = r.data
        page = d.source_url
        for key, value in (("title", d.title), ("description", d.meta_description), ("canonical", d.canonical),
                           ("robots", d.robots), ("generator", d.generator), ("lang", d.lang)):
            if value is not None:
                self._add(r, "html.metadata", page, key, value, f"<head> metadata on {page}")
        if d.open_graph:
            self._add(r, "html.open_graph", page, "properties", dict(sorted(d.open_graph.items())),
                      f"og:* meta on {page}")
        if d.twitter:
            self._add(r, "html.twitter", page, "card", dict(sorted(d.twitter.items())), f"twitter:* meta on {page}")
        if d.verification_tokens:
            # names only (e.g. google-site-verification); the token values are not recorded
            self._add(r, "html.verification", page, "providers", sorted(d.verification_tokens),
                      f"site-verification meta on {page}")

    def _resources(self, r: ModuleResult) -> None:
        '''
        Presence and content hash of each public resource.
        Parameters:
            r (ModuleResult): Resources module result.
        '''
        d = r.data
        for name in ("robots", "security_txt", "manifest", "favicon", "humans"):
            res = getattr(d, name)
            if res is not None and res.error is None:
                self._add(r, "resource", d.origin, name, {"present": res.present, "sha256": res.sha256 if res.present else None},
                          f"GET {res.url}")
        for s in d.sitemaps:
            if s.error is None:
                self._add(r, "resource", d.origin, f"sitemap:{s.url}", {"present": s.present, "url_count": s.url_count},
                          f"GET {s.url}")

    def _crawler(self, r: ModuleResult) -> None:
        '''
        Crawled pages (status) and forms (method).
        Parameters:
            r (ModuleResult): Crawler module result.
        '''
        for p in r.data.pages:
            self._add(r, "page", p.url, "status", p.status_code if not p.error else "error", "crawler")
        for f in r.data.forms:
            self._add(r, "form", f.page_url, f.action, {"method": f.method, "password": f.has_password_field}, "crawler")

    def _javascript(self, r: ModuleResult) -> None:
        '''
        Assets (content hash), bundle libraries, referenced service hosts and source-map exposure.
        Parameters:
            r (ModuleResult): JavaScript asset module result.
        '''
        for a in r.data.assets:
            if a.sha256:
                self._add(r, "asset", a.url, "content", {"sha256": a.sha256, "size": a.size}, f"GET {a.url}")
            for hit in a.libraries:
                self._add(r, "js.library", self.hostname, f"{hit.name}|{a.url}", hit.version, hit.evidence, hit.confidence)
            if a.source_map_status:
                self._add(r, "js.source_map", a.url, "status", a.source_map_status, "sourceMappingURL")
        for host in r.data.service_hosts:
            self._add(r, "js.service_host", self.hostname, host, True, "hostname referenced in a bundle")
        for ref in r.data.endpoints():
            self._add(r, "js.endpoint", ref.host or self.hostname, ref.value,
                      {"method": ref.method, "same_site": ref.same_site}, "referenced in a bundle")
        for a in r.data.assets:
            for cfg in a.client_configs:
                self._add(r, "js.client_config", self.hostname, f"{cfg.provider}|{a.url}",
                          sorted(fld.key for fld in cfg.fields), f"client config in {a.url}")
            for sec in a.secrets:
                # fingerprint only (no raw value) keeps this comparable without ever storing the secret
                self._add(r, "js.secret", self.hostname, f"{sec.type}|{sec.redacted}",
                          {"type": sec.type, "severity": sec.severity}, f"pattern match in {a.url}", Confidence.MEDIUM)

    def _technology(self, r: ModuleResult) -> None:
        '''
        Detected technologies with status and version.
        Parameters:
            r (ModuleResult): Technology module result.
        '''
        for t in r.data.technologies:
            self._add(r, "technology", self.hostname, t.name, {"status": t.status.value, "version": t.version},
                      ", ".join(sorted({e.source for e in t.evidence})), t.confidence)

    def _cookies(self, r: ModuleResult) -> None:
        '''
        Cookie attributes (never values).
        Parameters:
            r (ModuleResult): Cookies module result.
        '''
        for c in r.data.cookies:
            self._add(r, "cookie", self.hostname, f"{c.name}|{c.domain or ''}|{c.path or ''}", {
                "secure": c.secure, "http_only": c.http_only, "same_site": c.same_site,
                "persistent": c.persistent}, f"Set-Cookie on {c.source_url}")

    def _subdomains(self, r: ModuleResult) -> None:
        '''
        Discovered hostnames and their verified state.
        Parameters:
            r (ModuleResult): Subdomains module result.
        '''
        for h in r.data.hostnames:
            self._add(r, "subdomain", self.hostname, h.hostname, h.state.value, ", ".join(h.sources))

    def _third_party(self, r: ModuleResult) -> None:
        '''
        External services and their domains.
        Parameters:
            r (ModuleResult): Third-party module result.
        '''
        for s in r.data.services:
            self._add(r, "third_party", self.hostname, f"{s.provider}|{s.category}", sorted(s.domains),
                      ", ".join(s.sources), s.confidence)
