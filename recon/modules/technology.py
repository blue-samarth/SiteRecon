'''
Technology fingerprinting from evidence already collected (headers, HTML, resources).

Evidence strength by source:
  header / cookie name / meta generator → high   (the server or page says so directly)
  resource URL / active HTML            → medium (conventional paths and markers)
  referenced domain                     → medium
  CNAME target (DNS)                    → low    (delivery hint; not proof of the origin)
  bundle marker                         → banner+version high, runtime marker medium, package name low
  host referenced inside a bundle       → medium
  CSP-allowed domain only               → low    (permitted, not necessarily used)
  implied by another tech               → low

Grading: *confirmed* with any high-strength evidence or two independent source types;
*probable* with a single medium signal; *possible* when only low-strength signals exist.
'''

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import ClassVar

from recon.analysis import TECH_SIGNATURES, TechSignature
from recon.models import (
    AssetData,
    CollectionError,
    Confidence,
    DetectionStatus,
    CrawlData,
    DnsData,
    HtmlData,
    HttpData,
    LibraryHit,
    TechEvidence,
    Technology,
    TechnologyData,
)
from recon.modules.base import Collector
from recon.modules.html import HtmlCollector
from recon.modules.http import SecurityHeaderParser
from recon.utils import matches_suffix


@dataclass
class FingerprintInputs:
    '''
    Evidence gathered for fingerprinting: headers, generator, resource URLs, active HTML and domains.
    '''

    headers: dict[str, list[str]] = field(default_factory=dict)
    generator: str | None = None
    urls: list[str] = field(default_factory=list)
    html: str = ""
    domains: set[str] = field(default_factory=set)
    csp_domains: set[str] = field(default_factory=set)
    dns_targets: set[str] = field(default_factory=set)
    bundle_hits: list[tuple[LibraryHit, str]] = field(default_factory=list)   # (hit, asset url)
    bundle_hosts: set[str] = field(default_factory=set)

    _COMMENT: ClassVar[re.Pattern[str]] = re.compile(r"<!--.*?-->", re.S)
    _MAX_HTML_SCAN: ClassVar[int] = 2 * 1024 * 1024
    _MAX_CRAWL_HTML: ClassVar[int] = 4 * 1024 * 1024

    @classmethod
    def from_collected(cls, http: HttpData | None, html: HtmlData | None,
                       crawl: CrawlData | None = None, dns: DnsData | None = None,
                       assets: AssetData | None = None) -> FingerprintInputs:
        '''
        Assemble fingerprinting inputs; HTML comments are stripped before matching.
        Parameters:
            http (HttpData | None): HTTP probe results, or None.
            html (HtmlData | None): Parsed landing-page HTML, or None.
            crawl (CrawlData | None): Crawled pages (headers, HTML, resources), or None.
            dns (DnsData | None): DNS results (CNAME targets), or None.
            assets (AssetData | None): Static bundle analysis, or None.
        Returns:
            FingerprintInputs: Fingerprinting inputs.
        '''
        inp = cls()
        if http:
            for probe in http.probes:
                if probe.final_fetched:
                    for k, v in probe.headers.items():
                        inp.headers.setdefault(k, []).extend(v)
                    csp = probe.security_headers.get("content-security-policy")
                    if csp and isinstance(csp.parsed, dict):
                        inp.csp_domains |= SecurityHeaderParser.csp_hosts(csp.parsed)
        page = HtmlCollector.select_page(http)
        if page is not None:
            text = page.body[:cls._MAX_HTML_SCAN].decode("utf-8", "replace")
            inp.html = cls._COMMENT.sub("", text)
        if html:
            inp.generator = html.generator
            inp.urls = [r.url for r in html.resources]
            inp.domains = {r.host for r in html.resources if r.host}
        if crawl:
            budget = cls._MAX_CRAWL_HTML
            extra_html: list[str] = []
            for crawled in crawl.pages:
                for header_name, header_value in crawled.security_headers.items():
                    if header_value:
                        inp.headers.setdefault(header_name, []).append(header_value)
                for raw in crawled.set_cookies:  # names only reach the matcher
                    inp.headers.setdefault("set-cookie", []).append(raw.split("=", 1)[0] + "=")
                inp.urls.extend(crawled.resource_urls)
                inp.domains |= set(crawled.external_domains)
                if crawled.body and budget > 0:
                    chunk = crawled.body[:budget].decode("utf-8", "replace")
                    budget -= len(chunk)
                    extra_html.append(cls._COMMENT.sub("", chunk))
            if extra_html:
                inp.html = "\n".join([inp.html, *extra_html])
        if dns:
            for key in ("CNAME", "CNAME(www)"):
                q = dns.queries.get(key)
                inp.dns_targets |= set(q.values) if q else set()
        if assets:
            for rec in assets.assets:
                inp.bundle_hits.extend((hit, rec.url) for hit in rec.libraries)
            inp.bundle_hosts = set(assets.service_hosts)
        return inp

    def available(self) -> list[str]:
        '''
        Names of the evidence sources that contain data.
        Returns:
            list[str]: Subset of headers, html, resources, csp.
        '''
        sources = (("headers", self.headers), ("html", self.html), ("resources", self.urls),
                   ("csp", self.csp_domains), ("dns", self.dns_targets), ("bundles", self.bundle_hits))
        return [name for name, value in sources if value]


class TechnologyFingerprinter:
    '''
    Matches technology signatures against inputs and grades each detection.
    '''

    def __init__(self, signatures: tuple[TechSignature, ...] = TECH_SIGNATURES) -> None:
        '''
        Create a fingerprinter.
        Parameters:
            signatures (tuple[TechSignature, ...]): Signatures to evaluate.
        '''
        self.signatures = signatures
        self._by_name = {s.name: s for s in signatures}

    def fingerprint(self, inp: FingerprintInputs) -> TechnologyData:
        '''
        Match signatures against inputs and grade each detection as confirmed or probable.
        Parameters:
            inp (FingerprintInputs): Fingerprinting inputs.
        Returns:
            TechnologyData: Detections sorted by category.
        '''
        found: dict[str, Technology] = {}
        for sig in self.signatures:
            self._match(sig, inp, found)
        for hit, asset_url in inp.bundle_hits:
            sig = self._by_name.get(hit.name) or TechSignature(hit.name, hit.category)
            self._hit(found, sig, "bundle", f"{hit.evidence} in {asset_url}", hit.confidence, hit.version)
        # Implications (e.g. Next.js → React) add low-strength evidence only.
        for tech in list(found.values()):
            source_sig = self._by_name.get(tech.name)
            for implied in source_sig.implies if source_sig else ():
                if implied in self._by_name:
                    self._hit(found, self._by_name[implied], "implied", f"implied by {tech.name}", Confidence.LOW)
        for tech in found.values():
            if not tech.version and (recovered := self._version_from_urls(tech.name, inp.urls)):
                tech.version = recovered
                tech.evidence.append(TechEvidence(source="versioned_path", confidence=Confidence.MEDIUM,
                                                  detail=f"version {recovered} from a versioned asset path"))
            self._grade(tech)
        ordered = sorted(found.values(), key=lambda t: (t.category, -t.confidence.rank, t.name))
        return TechnologyData(technologies=ordered, signatures_checked=len(self.signatures), inputs=inp.available())

    def _match(self, sig: TechSignature, inp: FingerprintInputs, found: dict[str, Technology]) -> None:
        '''
        Evaluate one signature against every evidence source.
        Parameters:
            sig (TechSignature): Signature to evaluate.
            inp (FingerprintInputs): Fingerprinting inputs.
            found (dict[str, Technology]): Detections so far, updated in place.
        '''
        for header, pattern in sig.headers:
            for value in inp.headers.get(header, []):
                if not pattern:
                    self._hit(found, sig, "header", f"{header}: {value}", Confidence.HIGH)
                elif m := re.search(pattern, value, re.I):
                    self._hit(found, sig, "header", f"{header}: {value}", Confidence.HIGH, self._version(m))
        if sig.generator and inp.generator and (m := re.search(sig.generator, inp.generator, re.I)):
            self._hit(found, sig, "meta_generator", f"generator: {inp.generator}", Confidence.HIGH, self._version(m))
        for pattern in sig.urls:
            for url in inp.urls:
                if m := re.search(pattern, url, re.I):
                    self._hit(found, sig, "resource_url", url, Confidence.MEDIUM, self._version(m))
                    break
        for pattern in sig.html:
            if inp.html and (m := re.search(pattern, inp.html, re.I)):
                self._hit(found, sig, "html", f"matched /{pattern}/", Confidence.MEDIUM, self._version(m))
        for suffix in sig.domains:
            used = sorted(d for d in inp.domains if matches_suffix(d, suffix))
            if used:
                self._hit(found, sig, "domain", f"resource host {used[0]}", Confidence.MEDIUM)
            elif allowed := sorted(d for d in inp.csp_domains if matches_suffix(d, suffix)):
                self._hit(found, sig, "csp", f"allowed by CSP: {allowed[0]}", Confidence.LOW)
            if referenced := sorted(d for d in inp.bundle_hosts if matches_suffix(d, suffix)):
                self._hit(found, sig, "bundle_host", f"referenced in a bundle: {referenced[0]}", Confidence.MEDIUM)
        for pattern in sig.dns:
            for target in sorted(inp.dns_targets):
                if re.search(pattern, target, re.I):
                    self._hit(found, sig, "dns", f"CNAME → {target}", Confidence.LOW)
                    break

    @staticmethod
    def _hit(found: dict[str, Technology], sig: TechSignature, source: str, detail: str,
             conf: Confidence, version: str | None = None) -> None:
        '''
        Record one piece of evidence for a technology, creating the detection if needed.
        Parameters:
            found (dict[str, Technology]): Detections so far, updated in place.
            sig (TechSignature): Signature that matched.
            source (str): Evidence source type.
            detail (str): Evidence detail.
            conf (Confidence): Strength of this evidence.
            version (str | None): Version captured by the match, if any.
        '''
        tech = found.setdefault(sig.name, Technology(
            name=sig.name, category=sig.category, status=DetectionStatus.PROBABLE, confidence=conf))
        if not any(e.source == source and e.detail == detail for e in tech.evidence):
            tech.evidence.append(TechEvidence(source=source, detail=detail[:200], confidence=conf))
        if version and not tech.version:
            tech.version = version

    @staticmethod
    def _grade(tech: Technology) -> None:
        '''
        Set status and confidence: confirmed (high evidence or two independent sources),
        probable (a medium signal) or possible (only low-strength signals).
        Parameters:
            tech (Technology): Detection to grade in place.
        '''
        strengths = [e.confidence for e in tech.evidence]
        sources = {e.source for e in tech.evidence if e.source != "implied"}
        tech.confidence = max(strengths, key=lambda c: c.rank)
        if Confidence.HIGH in strengths or len(sources) >= 2:
            tech.status = DetectionStatus.CONFIRMED
            if len(sources) >= 2 and tech.confidence is not Confidence.HIGH:
                tech.confidence = Confidence.HIGH if tech.confidence is Confidence.MEDIUM else Confidence.MEDIUM
        elif Confidence.MEDIUM in strengths:
            tech.status = DetectionStatus.PROBABLE
        else:
            tech.status = DetectionStatus.POSSIBLE

    # Versioned asset paths: '/npm/pkg@1.2.3/', '/ajax/libs/pkg/1.2.3/', 'pkg-1.2.3.min.js', 'pkg.1.2.3.js'
    _URL_VERSION: ClassVar[tuple[str, ...]] = (
        r"[/@]{slug}@v?(?P<version>\d+\.\d+(?:\.\d+)?)",
        r"/{slug}/v?(?P<version>\d+\.\d+(?:\.\d+)?)/",
        r"{slug}[-.@_]v?(?P<version>\d+\.\d+(?:\.\d+)?)(?:[-.]|\.min|\.js|\.css|$)",
    )

    @classmethod
    def _version_from_urls(cls, name: str, urls: list[str]) -> str | None:
        '''
        Recover a version from a versioned asset path (CDN or filename) for a detected technology.
        Parameters:
            name (str): Technology name, e.g. 'jQuery'.
            urls (list[str]): Referenced resource URLs.
        Returns:
            str | None: Version string, or None if no path states one.
        '''
        tokens = [t for t in re.split(r"[^a-z0-9]+", name.lower()) if t]
        if not tokens:
            return None
        # 'Chart.js' → 'chart[-._]?js' and 'chart'; 'Vue.js' → 'vue[-._]?js' and 'vue'; 'jQuery' → 'jquery'
        variants = [r"[-._]?".join(re.escape(t) for t in tokens)]
        if len(tokens) > 1 and tokens[-1] == "js":
            variants.append(r"[-._]?".join(re.escape(t) for t in tokens[:-1]))
        for template in cls._URL_VERSION:
            for variant in dict.fromkeys(variants):
                pattern = template.replace("{slug}", variant)
                for url in urls:
                    if m := re.search(pattern, url, re.I):
                        return m.group("version")
        return None

    @staticmethod
    def _version(match: re.Match[str]) -> str | None:
        '''
        Return the 'version' named group from a regex match, if any.
        Parameters:
            match (re.Match[str]): Regex match.
        Returns:
            str | None: Version string or None.
        '''
        return match.groupdict().get("version") or None


class TechnologyCollector(Collector[TechnologyData]):
    '''
    Fingerprints technologies from collected HTTP and HTML evidence (no network I/O).
    '''

    name: ClassVar[str] = "technology"

    def __init__(self, http: HttpData | None, html: HtmlData | None,
                 fingerprinter: TechnologyFingerprinter | None = None, *,
                 crawl: CrawlData | None = None, dns: DnsData | None = None,
                 assets: AssetData | None = None) -> None:
        '''
        Create the collector.
        Parameters:
            http (HttpData | None): HTTP probe results, or None.
            html (HtmlData | None): Parsed landing-page HTML, or None.
            fingerprinter (TechnologyFingerprinter | None): Fingerprinter override; defaults to all signatures.
            crawl (CrawlData | None): Crawled pages, or None.
            dns (DnsData | None): DNS results, or None.
            assets (AssetData | None): Static bundle analysis, or None.
        '''
        self.assets = assets
        self.http = http
        self.html = html
        self.crawl = crawl
        self.dns = dns
        self.fingerprinter = fingerprinter or TechnologyFingerprinter()

    async def collect(self) -> tuple[TechnologyData, list[CollectionError]]:
        '''
        Fingerprint technologies.
        Returns:
            tuple[TechnologyData, list[CollectionError]]: Detections (this step never records errors).
        '''
        inputs = FingerprintInputs.from_collected(self.http, self.html, self.crawl, self.dns, self.assets)
        return self.fingerprinter.fingerprint(inputs), []
