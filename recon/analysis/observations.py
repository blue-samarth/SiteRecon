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
    "render": CollectionMethod.BROWSER_RENDER,
    "vulnscan": CollectionMethod.EXTERNAL_API,
    "historical": CollectionMethod.EXTERNAL_API,
    "seo": CollectionMethod.STATIC_ANALYSIS,
}


class ObservationBuilder:
    '''
    Converts module data into Observation records (one per comparable fact).
    Volatile values (timings, TTLs, request IDs) are deliberately excluded so comparisons stay meaningful.
    '''

    MAX_SEO_PAGES: int = 50

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

    @staticmethod
    def _discovery_method(sources: list[str]) -> str:
        '''
        The collection method that actually produced a discovered hostname.

        The subdomains module now has three discovery paths with genuinely different provenance, and the
        module-level default (CT_LOG) would misattribute two of them: a name confirmed by resolving a
        generated candidate came from a DNS query, and a name only a passive dataset knows came from a
        third-party API. Certificate Transparency wins when any CT provider saw the name, because that is
        the strongest evidence present.
        Parameters:
            sources (list[str]): Source names credited on the record (may include 'cache:<source>').

        Returns:
            str: The CollectionMethod value describing how the name was learned.
        '''
        plain = {s.removeprefix("cache:") for s in sources}
        if plain & {"crt.sh", "certspotter"}:
            return CollectionMethod.CT_LOG
        if plain == {"permutation"}:
            return CollectionMethod.DNS_QUERY
        if plain:
            return CollectionMethod.EXTERNAL_API
        return CollectionMethod.CT_LOG

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
             freshness: Freshness | None = None, limitations: list[str] | None = None) -> None:
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
            limitations (list[str] | None): What this observation cannot establish (carried into reports so
                a historical or indirect value is never read as a current, direct one).
        '''
        obs_id: str = self.make_id(type_, target, key)
        if obs_id in self._out: return

        self._out[obs_id] = Observation(
            id=obs_id, module=result.module, target=target, type=type_, key=key,
            value=value, source=source,
            collection_method=collection_method or _COLLECTION_METHOD.get(result.module, CollectionMethod.UNKNOWN),
            timestamp=result.finished_at, observed_at=observed_at, confidence=confidence,
            freshness=freshness or Freshness.FRESH, external_provider=external_provider,
            limitations=list(limitations or []), status=result.status.value)

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
        t = d.email.transport
        if t.mx_hosts:   # transport-security posture only matters for a mail-receiving domain
            self._add(r, "email.transport", d.hostname, "posture",
                      {"mta_sts": t.mta_sts_present, "tls_rpt": t.tls_rpt_present, "bimi": t.bimi_present,
                       "dane_mx": sorted(t.dane_mx)}, "DNS TXT/TLSA (MTA-STS, TLS-RPT, BIMI, DANE)")

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
                self._add(r, "tls.transport", f"{p.hostname}:{p.port}", "depth",
                          {"forward_secret": p.forward_secret, "alpn": p.alpn, "chain_complete": p.chain_complete,
                           "sct": c.sct_count}, "TLS handshake (cipher/ALPN/chain/SCT)")

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

    def _render(self, r: ModuleResult) -> None:
        '''
        Runtime endpoints, contacted hosts and client configuration a headless-browser load produced.

        These carry the ``browser_render`` collection method, so runtime-only facts (endpoints that exist
        only after JavaScript runs) stay distinguishable from statically-parsed ones.
        Parameters:
            r (ModuleResult): Render module result.
        '''
        d = r.data
        for ref in d.endpoints:
            self._add(r, "render.endpoint", ref.host or self.hostname, ref.value,
                      {"method": ref.method, "same_site": ref.same_site}, "runtime request / rendered DOM")
        for host in d.hosts_contacted:
            self._add(r, "render.host", self.hostname, host, True, "contacted while rendering")
        for cfg in d.client_configs:
            self._add(r, "render.client_config", self.hostname, cfg.provider,
                      sorted(fld.key for fld in cfg.fields), "client config in the rendered DOM")

    def _vulnscan(self, r: ModuleResult) -> None:
        '''
        Known-vulnerable components and the advisories affecting them (external-provider provenance).
        Parameters:
            r (ModuleResult): Vulnerability-scan module result.
        '''
        for comp in r.data.vulnerable:
            self._add(r, "vuln.component", self.hostname, f"{comp.package}@{comp.version}",
                      {"name": comp.name, "advisories": sorted(v.id for v in comp.vulns),
                       "cves": sorted({a for v in comp.vulns for a in v.aliases})},
                      f"OSV lookup of {comp.package}@{comp.version}", Confidence.MEDIUM,
                      external_provider="OSV")

    def _historical(self, r: ModuleResult) -> None:
        '''
        Archived-URL surface: the paths, endpoints, parameters and legacy technology hints the archives hold.

        Everything here is explicitly historical — collected from a third-party archive, describing a past
        state — so each observation carries EXTERNAL_API provenance, HISTORICAL freshness and the archive's
        own last-seen timestamp as ``observed_at``. Individual URLs are not recorded one-by-one: a URL set
        churns constantly, and a diff of thousands of archived URLs would drown the real changes. The
        summary, the endpoint surface, the parameter classes and the hints are what stay comparable.
        Parameters:
            r (ModuleResult): Historical-URL module result.
        '''
        d = r.data
        providers = ", ".join(s.source for s in d.sources if s.status == "live") or "archives"
        limits = ["Archived data is historical; a URL here may no longer exist or be reachable."]
        self._add(r, "historical.summary", d.host, "urls",
                  {"urls": d.urls_seen, "hosts": len(d.hosts), "paths": len(d.paths),
                   "first": d.first_seen.date().isoformat() if d.first_seen else None,
                   "last": d.last_seen.date().isoformat() if d.last_seen else None},
                  providers, Confidence.MEDIUM, freshness=Freshness.HISTORICAL,
                  observed_at=d.last_seen, external_provider=providers, limitations=limits)
        if d.endpoints:
            self._add(r, "historical.endpoints", d.host, "paths", sorted(d.endpoints), providers,
                      Confidence.MEDIUM, freshness=Freshness.HISTORICAL, observed_at=d.last_seen,
                      external_provider=providers, limitations=limits)
        for param in d.parameters:
            if param.category in ("credential", "redirect", "file"):
                self._add(r, "historical.parameter", d.host, param.name,
                          {"category": param.category, "occurrences": param.occurrences}, providers,
                          Confidence.MEDIUM, freshness=Freshness.HISTORICAL, observed_at=param.last_seen,
                          external_provider=providers, limitations=limits)
        for hint in d.tech_hints:
            self._add(r, "historical.technology", d.host, hint.name,
                      {"category": hint.category, "occurrences": hint.occurrences,
                       "still_detected": hint.still_detected}, providers, hint.confidence,
                      freshness=Freshness.HISTORICAL, observed_at=hint.last_seen,
                      external_provider=providers,
                      limitations=["Describes the stack that served an archived path, not the current one."])
        if d.sensitive_paths:
            self._add(r, "historical.sensitive_paths", d.host, "count", len(d.sensitive_paths), providers,
                      Confidence.MEDIUM, freshness=Freshness.HISTORICAL, observed_at=d.last_seen,
                      external_provider=providers, limitations=limits)

    def _seo(self, r: ModuleResult) -> None:
        '''
        Record the SEO facts worth diffing across scans.

        Per-page records are the ones that catch real regressions — a title that disappears, a page that
        turns noindex, a canonical that starts pointing elsewhere — so they are recorded per URL rather
        than as a site-wide count. The number of pages observed is capped, because the page list grows
        with --max-pages and a diff of a thousand near-identical rows helps nobody. Volatile measurements
        (word counts, response times, byte sizes) are deliberately left out: they change on every edit and
        would bury the structural changes in noise.
        Parameters:
            r (ModuleResult): The seo module result.
        '''
        d = r.data
        source = f"SEO audit of {d.pages_analyzed} page(s) ({d.pages_source})"
        self._add(r, "seo.summary", d.host, "pages_analyzed", d.pages_analyzed, source)
        self._add(r, "seo.summary", d.host, "indexable_pages", d.indexable_pages, source)
        self._add(r, "seo.summary", d.host, "coverage", d.pages_source, source)
        self._add(r, "seo.delivery", d.host, "compression", d.compression or "none", source)
        if d.http_version:
            self._add(r, "seo.delivery", d.host, "http_version", d.http_version, source)
        if d.languages:
            self._add(r, "seo.content", d.host, "languages", d.languages, source)
        if d.structured_data:
            self._add(r, "seo.content", d.host, "structured_data_types", sorted(d.structured_data), source)
        for kind in ("title", "description", "h1"):
            groups = [g for g in d.duplicates if g.kind == kind]
            if groups:
                self._add(r, "seo.duplicates", d.host, kind, len(groups), source)
        if d.sitemap is not None:
            s = d.sitemap
            self._add(r, "seo.sitemap", d.host, "robots_txt", s.robots_txt_present, source)
            self._add(r, "seo.sitemap", d.host, "declared_in_robots", s.robots_declares_sitemap, source)
            self._add(r, "seo.sitemap", d.host, "urls_listed", s.sitemap_urls, source)
        if d.host_canonical is not None and d.host_canonical.hosts_serving:
            self._add(r, "seo.canonicalization", d.host, "hosts_serving",
                      d.host_canonical.hosts_serving, source)
        for page in d.pages[: self.MAX_SEO_PAGES]:
            where = f"HTML of {page.url}"
            self._add(r, "seo.page", page.url, "indexable", page.indexable, where)
            if page.index_blockers:
                self._add(r, "seo.page", page.url, "index_blockers", sorted(set(page.index_blockers)), where)
            for key, value in (("title", page.title), ("description", page.meta_description),
                               ("canonical", page.canonical), ("h1", page.h1 or None)):
                if value:
                    self._add(r, "seo.page", page.url, key, value, where)

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
        Discovered hostnames with their verified state, plus which sources know each one.

        The state is kept as the comparable value so a host becoming reachable (or disappearing) shows up
        in the scan diff. The source list is a separate observation, so gaining a name from a newly enabled
        source is visible as an added observation rather than silently changing the host's own record.
        Parameters:
            r (ModuleResult): Subdomains module result.
        '''
        d = r.data
        for h in d.hostnames:
            source_text = ", ".join(h.sources)
            method = self._discovery_method(h.sources)
            self._add(r, "subdomain", self.hostname, h.hostname, h.state.value, source_text,
                      collection_method=method)
            self._add(r, "subdomain.sources", h.hostname, "sources", sorted(h.sources),
                      source_text or "discovery source", collection_method=method)
        if d.sources:
            self._add(r, "subdomain.coverage", self.hostname, "sources",
                      {s.provider: s.status for s in sorted(d.sources, key=lambda s: s.provider)},
                      "passive discovery sources queried", Confidence.HIGH)
        if d.permutation.enabled:
            self._add(r, "subdomain.permutation", self.hostname, "summary",
                      {"generated": d.permutation.generated, "tested": d.permutation.tested,
                       "resolved": d.permutation.resolved},
                      "generated candidates confirmed in DNS", Confidence.HIGH,
                      collection_method=CollectionMethod.DNS_QUERY)

    def _third_party(self, r: ModuleResult) -> None:
        '''
        External services and their domains.
        Parameters:
            r (ModuleResult): Third-party module result.
        '''
        for s in r.data.services:
            self._add(r, "third_party", self.hostname, f"{s.provider}|{s.category}", sorted(s.domains),
                      ", ".join(s.sources), s.confidence)
        for c in r.data.cloud_resources:
            # The referenced identifier is the comparable fact; a new bucket or function appearing in the
            # client surface is exactly the kind of change the diff should surface.
            self._add(r, "cloud.resource", self.hostname, f"{c.provider}|{c.kind}|{c.identifier}",
                      {"host": c.host, "region": c.region, "sources": sorted(c.sources)},
                      ", ".join(c.sources) or "referenced in collected evidence", c.confidence)
