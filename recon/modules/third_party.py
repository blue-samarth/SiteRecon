'''
Third-party service inventory built from already-collected evidence (no network I/O).

Confidence by source:
  loaded resource (script/stylesheet/image/iframe), MX, NS, cert issuer → high
  preconnect / dns-prefetch, SPF include, TXT verification, redirect     → medium
  CSP allow-list only, unrecognized domain via weak source               → low

The same evidence also yields a **managed-cloud inventory**: buckets, serverless functions, managed
databases, edge workers and hosting targets the application references (see
``recon/analysis/cloud_signatures.py``). That inventory records references only — nothing is requested, so
it never claims a bucket is readable or a function is unauthenticated.
'''

from __future__ import annotations

from typing import ClassVar

from recon.analysis import (
    CERTIFICATE_AUTHORITIES,
    DNS_PROVIDERS,
    MAIL_PROVIDERS,
    SPF_SERVICES,
    THIRD_PARTY_DOMAINS,
    TXT_VERIFICATIONS,
    DomainService,
)
from recon.analysis.cloud_signatures import match_cloud
from recon.models import (
    AssetData,
    CloudResource,
    CollectionError,
    Confidence,
    CrawlData,
    DnsData,
    HtmlData,
    HttpData,
    ThirdPartyData,
    ThirdPartyService,
    TlsData,
)
from recon.modules.base import Collector
from recon.modules.http import SecurityHeaderParser
from recon.utils import Scope, host_of, matches_suffix, redact_url, registrable_domain


class ServiceInventory:
    '''
    Accumulates third-party services keyed by (provider, category).
    '''

    def __init__(self) -> None:
        '''
        Create an empty inventory.
        '''
        self._items: dict[tuple[str, str], ThirdPartyService] = {}

    def add(self, provider: str, category: str, *, domain: str | None, source: str,
            evidence: str, confidence: Confidence, known: bool = True) -> None:
        '''
        Add or merge a service, keeping the highest confidence seen.
        Parameters:
            provider (str): Provider name.
            category (str): Service category.
            domain (str | None): Associated domain, if any.
            source (str): Detection source (e.g. html:script, dns:mx).
            evidence (str): Supporting observation.
            confidence (Confidence): Confidence for this observation.
            known (bool): Whether the provider is recognized.
        '''
        svc = self._items.setdefault((provider, category), ThirdPartyService(
            provider=provider, category=category, confidence=confidence, known=known))
        if domain and domain not in svc.domains:
            svc.domains.append(domain)
        if source not in svc.sources:
            svc.sources.append(source)
        if evidence not in svc.evidence and len(svc.evidence) < 10:
            svc.evidence.append(evidence)
        if confidence.rank > svc.confidence.rank:
            svc.confidence = confidence

    def add_domain(self, host: str, *, source: str, evidence: str, confidence: Confidence) -> None:
        '''
        Add a service for an external host, falling back to an 'other' entry when unrecognized.
        Parameters:
            host (str): External hostname.
            source (str): Detection source.
            evidence (str): Supporting observation.
            confidence (Confidence): Confidence for this observation.
        '''
        svc = self.lookup(THIRD_PARTY_DOMAINS, host)
        if svc:
            self.add(svc.provider, svc.category, domain=host, source=source,
                     evidence=evidence, confidence=confidence)
        else:
            weak = Confidence.LOW if confidence is not Confidence.HIGH else Confidence.MEDIUM
            self.add(registrable_domain(host), "other", domain=host, source=source,
                     evidence=evidence, confidence=weak, known=False)

    def services(self) -> list[ThirdPartyService]:
        '''
        Return services with recognized providers first, then by category and confidence.
        Returns:
            list[ThirdPartyService]: Sorted services.
        '''
        return sorted(self._items.values(), key=lambda s: (not s.known, s.category, -s.confidence.rank, s.provider))

    @staticmethod
    def lookup(table: tuple[DomainService, ...], host: str) -> DomainService | None:
        '''
        Find the most specific suffix match for a host.
        Parameters:
            table (tuple[DomainService, ...]): Domain-to-service table.
            host (str): Hostname to look up.
        Returns:
            DomainService | None: The longest matching entry, or None.
        '''
        matches = [s for s in table if matches_suffix(host, s.suffix)]
        return max(matches, key=lambda s: len(s.suffix)) if matches else None


class ThirdPartyCollector(Collector[ThirdPartyData]):
    '''
    Combines HTML, CSP, redirect, DNS and certificate evidence into a service inventory.
    '''

    name: ClassVar[str] = "third_party"
    LOADED_KINDS: ClassVar[frozenset[str]] = frozenset({
        "script", "stylesheet", "image", "meta_image", "iframe", "icon", "modulepreload", "form", "manifest",
    })

    def __init__(self, hostname: str, *, dns: DnsData | None, http: HttpData | None,
                 html: HtmlData | None, tls: TlsData | None, crawl: CrawlData | None = None,
                 assets: AssetData | None = None) -> None:
        '''
        Create the collector.
        Parameters:
            hostname (str): Normalized target hostname.
            dns (DnsData | None): DNS results, or None.
            http (HttpData | None): HTTP results, or None.
            html (HtmlData | None): Parsed HTML, or None.
            tls (TlsData | None): TLS results, or None.
            crawl (CrawlData | None): Crawled pages, or None.
            assets (AssetData | None): Static bundle analysis (referenced service hosts), or None.
        '''
        self.scope = Scope.for_target(hostname)
        self.dns, self.http, self.html, self.tls, self.crawl = dns, http, html, tls, crawl
        self.assets = assets

    async def collect(self) -> tuple[ThirdPartyData, list[CollectionError]]:
        '''
        Build the inventory.
        Returns:
            tuple[ThirdPartyData, list[CollectionError]]: The inventory (this step never records errors).
        '''
        return self.build(), []

    def build(self) -> ThirdPartyData:
        '''
        Run every evidence source into a fresh inventory.
        Returns:
            ThirdPartyData: Services sorted with recognized providers first, plus the cloud inventory.
        '''
        inv = ServiceInventory()
        if self.html:
            self._from_html(self.html, inv)
        if self.crawl:
            self._from_crawl(self.crawl, inv)
        if self.assets:
            for host, refs in self.assets.service_hosts.items():
                if not self.scope.allows(host):
                    inv.add_domain(host, source="bundle", evidence=f"referenced in {refs[0]}",
                                   confidence=Confidence.MEDIUM)
        if self.http:
            self._from_http(self.http, inv)
        if self.dns:
            self._from_dns(self.dns, inv)
        if self.tls:
            self._from_tls(self.tls, inv)
        return ThirdPartyData(services=inv.services(), cloud_resources=self.cloud_resources())

    def cloud_resources(self) -> list[CloudResource]:
        '''
        Build the managed-cloud inventory from every reference the scan already holds.

        Candidate references come from page and crawl resources, bundle-referenced hosts and endpoint URLs,
        CNAME targets and the CSP allow-list. A hostname inside the target's own scope is still matched —
        a bucket the operator fronted with their own CNAME is exactly the kind of resource worth listing —
        but nothing is requested, so each entry means "referenced", never "reachable" or "public".
        Returns:
            list[CloudResource]: Resources, object storage and functions first, then by provider.
        '''
        resources: dict[tuple[str, str, str], CloudResource] = {}
        for url, host, source, evidence, confidence in self._cloud_candidates():
            matched = match_cloud(host, url)
            if matched is None:
                continue
            sig = matched.signature
            key = (sig.provider, sig.kind, matched.identifier)
            resource = resources.get(key)
            if resource is None:
                resource = CloudResource(
                    provider=sig.provider, kind=sig.kind, identifier=matched.identifier, host=matched.host,
                    region=matched.region, confidence=confidence,
                    public_by_default=sig.public_by_default, note=sig.note or None,
                    url_sample=redact_url(url) if url else None)
                resources[key] = resource
            if source not in resource.sources:
                resource.sources.append(source)
            if evidence not in resource.evidence and len(resource.evidence) < 8:
                resource.evidence.append(evidence)
            if resource.url_sample is None and url:
                resource.url_sample = redact_url(url)
            if resource.region is None and matched.region:
                resource.region = matched.region
            if confidence.rank > resource.confidence.rank:
                resource.confidence = confidence
        order = {"object_storage": 0, "serverless_function": 1, "managed_database": 2, "edge_worker": 3,
                 "auth": 4, "search": 5, "container": 6, "hosting": 7}
        return sorted(resources.values(),
                      key=lambda r: (order.get(r.kind, 9), r.provider, r.identifier))

    def _cloud_candidates(self) -> list[tuple[str, str, str, str, Confidence]]:
        '''
        Every (url, host, source, evidence, confidence) reference worth testing against the cloud patterns.

        Confidence mirrors the rest of this module: a resource the page or a bundle actually loads or calls
        is HIGH, a DNS delegation is MEDIUM (it proves delivery, not ownership of the content), and a host
        that is merely CSP-allowed is LOW (permitted, not necessarily used).
        Returns:
            list[tuple[str, str, str, str, Confidence]]: Candidate references.
        '''
        out: list[tuple[str, str, str, str, Confidence]] = []

        def offer(url: str, host: str | None, source: str, evidence: str, confidence: Confidence) -> None:
            if host:
                out.append((url, host, source, evidence[:200], confidence))

        for ref in (self.html.resources if self.html else []):
            offer(ref.url, ref.host, f"html:{ref.kind}", f"{ref.kind} {redact_url(ref.url)[:150]}",
                  Confidence.HIGH if ref.kind in self.LOADED_KINDS else Confidence.MEDIUM)
        for page in (self.crawl.pages if self.crawl else []):
            for url in page.resource_urls:
                offer(url, host_of(url), "crawl", f"{page.url}: {redact_url(url)[:150]}", Confidence.HIGH)
        if self.assets:
            for host, refs in self.assets.service_hosts.items():
                offer("", host, "bundle", f"referenced in {refs[0]}", Confidence.MEDIUM)
            for endpoint in self.assets.endpoints():
                if endpoint.host and "//" in endpoint.value:
                    offer(endpoint.value, endpoint.host, "bundle:endpoint",
                          f"endpoint {endpoint.value[:150]}", Confidence.HIGH)
        for probe in (self.http.probes if self.http else []):
            csp = probe.security_headers.get("content-security-policy")
            if csp and isinstance(csp.parsed, dict):
                for allowed in SecurityHeaderParser.csp_hosts(csp.parsed):
                    offer("", allowed, "csp", f"CSP allows {allowed}", Confidence.LOW)
        for key in ("CNAME", "CNAME(www)"):
            query = self.dns.queries.get(key) if self.dns else None
            for value in (query.values if query else []):
                target = value.rstrip(".").lower()
                offer("", target, "dns:cname", f"{key} → {target}", Confidence.MEDIUM)
        return out

    def _from_html(self, html: HtmlData, inv: ServiceInventory) -> None:
        '''
        Add services for external resources referenced by the page.
        Parameters:
            html (HtmlData): Parsed landing-page HTML.
            inv (ServiceInventory): Inventory to update.
        '''
        for r in html.resources:
            if not r.host or r.same_site:
                continue
            conf = Confidence.HIGH if r.kind in self.LOADED_KINDS else Confidence.MEDIUM
            inv.add_domain(r.host, source=f"html:{r.kind}", evidence=f"{r.kind} {r.url[:150]}", confidence=conf)

    def _from_crawl(self, crawl: CrawlData, inv: ServiceInventory) -> None:
        '''
        Add services for external resources referenced by crawled pages.
        Parameters:
            crawl (CrawlData): Crawl results.
            inv (ServiceInventory): Inventory to update.
        '''
        for page in crawl.pages:
            for url in page.resource_urls:
                host = host_of(url)
                if host and not self.scope.allows(host):
                    inv.add_domain(host, source="crawl", evidence=f"{page.url}: {url[:150]}",
                                   confidence=Confidence.HIGH)

    def _from_http(self, http: HttpData, inv: ServiceInventory) -> None:
        '''
        Add services allowed by CSP and destinations of off-scope redirects.
        Parameters:
            http (HttpData): HTTP probe results.
            inv (ServiceInventory): Inventory to update.
        '''
        for probe in http.probes:
            csp = probe.security_headers.get("content-security-policy")
            if csp and isinstance(csp.parsed, dict):
                for host in SecurityHeaderParser.csp_hosts(csp.parsed):
                    if not self.scope.allows(host):
                        inv.add_domain(host, source="csp", evidence=f"CSP allows {host}", confidence=Confidence.LOW)
            if probe.redirect_stopped_reason == "out_of_scope" and probe.final_url:
                host = host_of(probe.final_url)
                if host:
                    inv.add_domain(host, source="redirect",
                                   evidence=f"{probe.requested_url} redirects to {probe.final_url}",
                                   confidence=Confidence.MEDIUM)

    @staticmethod
    def _from_dns(dns: DnsData, inv: ServiceInventory) -> None:
        '''
        Add services evidenced by MX, NS, SPF includes and TXT verification tokens.
        Parameters:
            dns (DnsData): DNS collection results.
            inv (ServiceInventory): Inventory to update.
        '''
        mx, ns, txt = dns.queries.get("MX"), dns.queries.get("NS"), dns.queries.get("TXT")
        for value in (mx.values if mx else []):
            exchange = value.split()[-1]
            if exchange == ".":
                continue
            sig = next((s for s in MAIL_PROVIDERS if s.match_host(exchange)), None)
            inv.add(sig.provider if sig else registrable_domain(exchange), "email", domain=exchange,
                    source="dns:mx", evidence=f"MX {value}", confidence=Confidence.HIGH, known=sig is not None)
        for host in (ns.values if ns else []):
            sig = next((s for s in DNS_PROVIDERS if s.match_host(host)), None)
            inv.add(sig.provider if sig else registrable_domain(host), "dns", domain=host,
                    source="dns:ns", evidence=f"NS {host}", confidence=Confidence.HIGH, known=sig is not None)
        for rec in dns.email.spf.records:
            for include in rec.includes + ([rec.redirect] if rec.redirect else []):
                svc = ServiceInventory.lookup(SPF_SERVICES, include)
                inv.add(svc.provider if svc else registrable_domain(include), "email", domain=include,
                        source="dns:spf", evidence=f"SPF include:{include}", confidence=Confidence.MEDIUM,
                        known=svc is not None)
        for value in (txt.values if txt else []):
            lowered = value.lower()
            for prefix, provider, category in TXT_VERIFICATIONS:
                if lowered.startswith(prefix):
                    inv.add(provider, category, domain=None, source="dns:txt",
                            evidence=f"TXT verification token ({prefix.rstrip('=:')})",
                            confidence=Confidence.MEDIUM)
                    break

    @staticmethod
    def _from_tls(tls: TlsData, inv: ServiceInventory) -> None:
        '''
        Add the certificate authority that issued each presented certificate.
        Parameters:
            tls (TlsData): TLS probe results.
            inv (ServiceInventory): Inventory to update.
        '''
        for probe in tls.probes:
            cert = probe.certificate
            if not cert:
                continue
            issuer = (cert.issuer_org or cert.issuer or "").lower()
            ca = next((name for key, name in CERTIFICATE_AUTHORITIES if key in issuer), None)
            inv.add(ca or (cert.issuer_org or "Unknown CA"), "certificate_authority", domain=None,
                    source="tls", evidence=f"{probe.hostname}: issued by {cert.issuer}",
                    confidence=Confidence.HIGH, known=ca is not None)
