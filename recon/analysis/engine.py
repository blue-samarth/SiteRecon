'''
Analysis engine: interprets collected observations into findings and infrastructure.

This module performs no network I/O. Every input is data already gathered by the
collection layer, which keeps the analysis deterministic and independently testable.
'''

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime
from urllib.parse import urlsplit

from recon.analysis.findings import FindingCollector
from recon.analysis.signatures import (
    DNS_PROVIDERS,
    HTTP_EDGE_PROVIDERS,
    MAIL_PROVIDERS,
    NETWORK_PROVIDERS,
    ProviderSignature,
)
from recon.models import (
    AnalysisResult,
    Confidence,
    DmarcAnalysis,
    DnsData,
    DnsQueryResult,
    DnsQueryStatus,
    DomainRegistration,
    Finding,
    HtmlData,
    HttpData,
    HttpProbe,
    InfrastructureObservation,
    NetworkData,
    Severity,
    SpfAnalysis,
    SubdomainData,
    TlsData,
    CookieData,
    CrawlData,
    DnssecData,
    DnssecStatus,
    Observation,
    ResourcesData,
    AssetData,
)

HSTS_RECOMMENDED_MAX_AGE: int = 15_552_000  # 180 days
TLS_EXPIRY_WARN_DAYS: int = 30
TLS_EXPIRY_URGENT_DAYS: int = 14
LEGACY_TLS: set[str] = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
DOMAIN_EXPIRY_WARN_DAYS: int = 30
HOLD_STATUSES: tuple[str, ...] = ("clienthold", "serverhold", "client hold", "server hold")
_VERSIONED_SERVER: re.Pattern[str] = re.compile(r"[a-z][\w.-]*/\d+(?:\.\d+)+", re.I)

S, C = Severity, Confidence  # enum aliases for brevity


class AnalysisEngine:
    '''
    Interprets collected observations into findings, inferred infrastructure and severity counts.
    Stateless apart from the timestamp stamped on every finding; performs no network I/O.
    '''

    def __init__(self, timestamp: datetime) -> None:
        '''
        Create an engine.
        Parameters:
            timestamp (datetime): The timestamp of the analysis, stamped on every finding.
        '''
        self.timestamp = timestamp

    def analyze(self, *, dns: DnsData | None, network: NetworkData | None, http: HttpData | None,
                tls: TlsData | None, whois: DomainRegistration | None = None,
                html: HtmlData | None = None, subdomains: SubdomainData | None = None,
                dnssec: DnssecData | None = None, resources: ResourcesData | None = None,
                crawl: CrawlData | None = None, cookies: CookieData | None = None,
                assets: AssetData | None = None, observations: list[Observation] | None = None,
                ) -> AnalysisResult:
        '''
        Analyze the results of various probes and produce a structured report of findings and inferred infrastructure.
        Any input may be None (its module failed or was skipped); with no inputs at all an empty
        result is returned, so a scan where every module failed still yields a partial report.
        Parameters:
            dns (DnsData | None): DNS probe results.
            network (NetworkData | None): Network probe results.
            http (HttpData | None): HTTP probe results.
            tls (TlsData | None): TLS probe results.
            whois (DomainRegistration | None): Domain registration information.
            html (HtmlData | None): HTML probe results.
            subdomains (SubdomainData | None): Subdomain probe results.
            dnssec (DnssecData | None): DNSSEC results.
            resources (ResourcesData | None): Public resource results.
            crawl (CrawlData | None): Crawl results.
            cookies (CookieData | None): Cookie attribute results.
            assets (AssetData | None): Static JS/CSS asset analysis.
            observations (list[Observation] | None): Normalized observations used as evidence references.
        Returns:
            AnalysisResult: A structured report containing findings, inferred infrastructure, and severity counts.
        '''
        findings: FindingCollector = FindingCollector(self.timestamp)
        if dns: self._analyze_dns(dns, findings)
        if http: self._analyze_http(http, findings)
        if tls: self._analyze_tls(tls, findings)
        if whois: self._analyze_whois(whois, findings)
        if html: self._analyze_html(html, findings)
        if subdomains: self._analyze_subdomains(subdomains, findings)
        if dnssec: self._analyze_dnssec(dnssec, whois, findings)
        if resources: self._analyze_resources(resources, findings)
        if crawl: self._analyze_crawl(crawl, http, findings)
        if cookies: self._analyze_cookies(cookies, findings)
        if assets: self._analyze_assets(assets, findings)
        if observations: findings.link(observations)

        infrastructure: list[InfrastructureObservation] = InfrastructureInference.infer(
            network=network, dns=dns, http=http)
        ordered: list[Finding] = findings.sorted()
        counts: Counter[str] = Counter(f.severity.value for f in ordered)

        return AnalysisResult(findings=ordered, infrastructure=infrastructure,
                              severity_counts={s.value: counts.get(s.value, 0) for s in Severity})

    @staticmethod
    def _analyze_dns(dns: DnsData, f: FindingCollector) -> None:
        '''
        Analyze DNS probe results and add findings to the provided FindingCollector.
        Parameters:
            dns (DnsData): DNS probe results.
            f (FindingCollector): Collector to which findings will be added.
        '''
        host: str = dns.hostname
        a: DnsQueryResult | None = dns.queries.get("A")
        aaaa: DnsQueryResult | None = dns.queries.get("AAAA")

        if a and aaaa and a.status is DnsQueryStatus.NXDOMAIN:
            f.add("dns.nxdomain", host, category="dns", title="Domain does not exist",
                  description="The resolver returned NXDOMAIN; most other checks cannot produce results.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH,
                  evidence=[f"A {host}: NXDOMAIN"], source="DNS A query")
            return None

        if a and aaaa and a.status.is_definitive and aaaa.status.is_definitive and not (a.records or aaaa.records):
            f.add("dns.no_address", host, category="dns", title="No A/AAAA records",
                  description="The hostname has no IPv4 or IPv6 address records.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH,
                  evidence=[f"A: {a.status}", f"AAAA: {aaaa.status}"], source="DNS A/AAAA queries")

        spf: SpfAnalysis = dns.email.spf
        has_mx: bool = bool(dns.queries.get("MX") and dns.queries["MX"].records)
    
        if spf.lookup_status.is_definitive and not spf.records:
            f.add("dns.spf_missing", host, category="email", title="No SPF record",
                  description="No v=spf1 TXT record was found. This matters only if the domain sends "
                              "email (or should explicitly declare that it sends none with 'v=spf1 -all').",
                  severity=S.INFORMATIONAL, confidence=C.HIGH,
                  evidence=[f"TXT {host}: {spf.lookup_status}"] + (["MX records present"] if has_mx else []),
                  source="DNS TXT query")

        if len(spf.records) > 1:
            f.add("dns.spf_multiple", host, category="email", title="Multiple SPF records",
                  description="RFC 7208 §3.2 requires a single SPF record; receivers return permerror "
                              "when several exist, so SPF evaluation fails.",
                  severity=S.LOW, confidence=C.HIGH,
                  evidence=[r.raw for r in spf.records], source="DNS TXT query")

        for rec in spf.records:
            if rec.all_qualifier == "+":
                f.add("dns.spf_pass_all", host, category="email", title="SPF authorizes all senders (+all)",
                      description="The SPF policy ends in '+all', which authorizes every host on the "
                                  "internet to send mail for this domain.",
                      severity=S.MEDIUM, confidence=C.HIGH, evidence=[rec.raw], source="DNS TXT query")
            elif rec.all_qualifier == "?":
                f.add("dns.spf_neutral_all", host, category="email", title="SPF ends in neutral '?all'",
                      description="'?all' asserts nothing about unlisted senders.",
                      severity=S.INFORMATIONAL, confidence=C.HIGH, evidence=[rec.raw], source="DNS TXT query")

        dmarc: DmarcAnalysis = dns.email.dmarc
        if dmarc.lookup_status.is_definitive and not dmarc.raw_records:
            f.add("dns.dmarc_missing", host, category="email", title="No DMARC record",
                  description=f"No v=DMARC1 record at {dmarc.name}. Without DMARC, receivers have no "
                              "domain-owner policy for mail failing SPF/DKIM alignment.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH,
                  evidence=[f"TXT {dmarc.name}: {dmarc.lookup_status}"], source="DNS TXT query")
        elif len(dmarc.raw_records) > 1:
            f.add("dns.dmarc_multiple", host, category="email", title="Multiple DMARC records",
                  description="Several DMARC records exist; receivers ignore DMARC in this case (RFC 7489).",
                  severity=S.LOW, confidence=C.HIGH, evidence=dmarc.raw_records, source="DNS TXT query")
        elif dmarc.policy == "none":
            f.add("dns.dmarc_monitor_only", host, category="email", title="DMARC policy is p=none",
                  description="DMARC is in monitoring mode: failing mail is reported but not quarantined "
                              "or rejected.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH, evidence=dmarc.raw_records, source="DNS TXT query")

        caa = dns.caa
        if caa.complete and caa.effective_name is None and any(v == "NODATA" for v in caa.checked.values()):
            f.add("dns.caa_absent", host, category="dns", title="No CAA policy in effect",
                  description="Neither the hostname nor its parent names publish CAA records, so any "
                              "publicly trusted CA may issue certificates for it.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH,
                  evidence=[f"CAA {name}: {status}" for name, status in caa.checked.items()],
                  source="DNS CAA queries (parent climb)")

        spf_rec = spf.records[0] if len(spf.records) == 1 else None
        if spf.lookup_limit_exceeded:
            f.add("dns.spf_lookup_limit", host, category="email", title="SPF exceeds DNS lookup limits",
                  description=f"Evaluating SPF needs {spf.lookup_count} DNS lookups (limit 10) and "
                              f"{spf.void_lookups} void lookups (limit 2); receivers return permerror.",
                  severity=S.LOW, confidence=C.HIGH, evidence=spf.lookup_tree[:20] + spf.evaluation_errors[:5],
                  source="SPF evaluation (RFC 7208 §4.6.4)")
        if spf_rec and spf_rec.parse_errors:
            f.add("dns.spf_parse_error", host, category="email", title="SPF record has invalid terms",
                  description="Receivers treat syntactically invalid SPF records as permerror.",
                  severity=S.LOW, confidence=C.HIGH, evidence=[spf_rec.raw, *spf_rec.parse_errors],
                  source="DNS TXT query")
        if spf_rec and spf_rec.uses_ptr:
            f.add("dns.spf_ptr", host, category="email", title="SPF uses the deprecated 'ptr' mechanism",
                  description="RFC 7208 §5.5 says 'ptr' should not be used; it is slow and unreliable.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH, evidence=[spf_rec.raw], source="DNS TXT query")
        if len(dmarc.raw_records) == 1 and dmarc.policy and not dmarc.rua:
            f.add("dns.dmarc_no_reports", host, category="email", title="DMARC requests no aggregate reports",
                  description="Without rua= the domain owner receives no reports about mail using the domain.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH, evidence=dmarc.raw_records, source="DNS TXT query")
        for k in dns.email.dkim_found:
            if k.revoked:
                continue
            if k.key_type == "rsa" and k.key_bits is not None and k.key_bits < 2048:
                f.add("dns.dkim_weak_key", k.name, category="email", title="Short DKIM RSA key",
                      description=f"The DKIM key for selector '{k.selector}' is {k.key_bits} bits; "
                                  "2048 bits is the current recommendation.",
                      severity=S.LOW if k.key_bits >= 1024 else S.MEDIUM, confidence=C.HIGH,
                      evidence=[f"{k.name}: k={k.key_type}, {k.key_bits} bits"], source="DNS TXT query")

    @staticmethod
    def _analyze_http(http: HttpData, f: FindingCollector) -> None:
        '''
        Analyze HTTP probe results: reachability, HTTPS redirection and out-of-scope redirects.
        Parameters:
            http (HttpData): HTTP probe results.
            f (FindingCollector): Collector to which findings will be added.
        '''
        for probe in http.probes:
            scheme = urlsplit(probe.requested_url).scheme
            host = urlsplit(probe.requested_url).hostname or probe.requested_url

            if not probe.success:
                title = "HTTPS endpoint unreachable" if scheme == "https" else "HTTP endpoint unreachable"
                f.add(f"http.unreachable.{scheme}", host, category="http", title=title,
                      description="The request did not complete; see the error for details.",
                      severity=S.INFORMATIONAL, confidence=C.HIGH,
                      evidence=[f"{probe.requested_url}: {probe.error_type}: {probe.error}"],
                      source=f"GET {probe.requested_url}")
                continue

            if probe.redirect_stopped_reason == "out_of_scope":
                f.add("http.redirect_out_of_scope", host, category="http",
                      title="Redirect leaves the authorized scope",
                      description="The redirect chain points to a host outside the target scope; it was "
                                  "recorded but not followed.",
                      severity=S.INFORMATIONAL, confidence=C.HIGH,
                      evidence=[f"{probe.requested_url} → {probe.final_url}"],
                      source=f"GET {probe.requested_url}")

            if scheme == "http" and probe.redirects_to_https is False and probe.final_fetched \
                    and probe.status_code and 200 <= probe.status_code < 300:
                f.add("http.no_https_redirect", host, category="http",
                      title="Plain HTTP served without redirect to HTTPS",
                      description="The HTTP endpoint returned content directly instead of redirecting "
                                  "to HTTPS.",
                      severity=S.LOW, confidence=C.HIGH,
                      evidence=[f"{probe.requested_url} → HTTP {probe.status_code} at {probe.final_url}"],
                      source=f"GET {probe.requested_url}")

            if probe.final_fetched and probe.final_url and urlsplit(probe.final_url).scheme == "https":
                AnalysisEngine._analyze_security_headers(probe, f)

    @staticmethod
    def _analyze_security_headers(probe: HttpProbe, f: FindingCollector) -> None:
        '''
        Analyze security headers on a final HTTPS response (HSTS, CSP, framing, version banners).
        Parameters:
            probe (HttpProbe): A probe whose final response was fetched over HTTPS.
            f (FindingCollector): Collector to which findings will be added.
        '''
        final = probe.final_url or probe.requested_url
        sh = probe.security_headers
        source = f"GET {final}"

        hsts = sh.get("strict-transport-security")
        if hsts and not hsts.present:
            f.add("http.hsts_missing", final, category="http", title="No Strict-Transport-Security header",
                  description="Browsers will not be instructed to require HTTPS on future visits.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH,
                  evidence=["strict-transport-security: absent"], source=source)
        elif hsts and isinstance(hsts.parsed, dict):
            max_age = hsts.parsed.get("max-age")
            if max_age == 0:
                f.add("http.hsts_disabled", final, category="http", title="HSTS max-age=0",
                      description="max-age=0 instructs browsers to forget any HSTS policy.",
                      severity=S.LOW, confidence=C.HIGH, evidence=[hsts.value or ""], source=source)
            elif max_age is None:
                f.add("http.hsts_invalid", final, category="http", title="HSTS header lacks a valid max-age",
                      description="Browsers ignore an HSTS header without a valid max-age directive.",
                      severity=S.LOW, confidence=C.HIGH, evidence=[hsts.value or ""], source=source)
            elif max_age < HSTS_RECOMMENDED_MAX_AGE:
                f.add("http.hsts_short", final, category="http", title="Short HSTS max-age",
                      description=f"max-age={max_age}s is below the commonly recommended 180 days.",
                      severity=S.INFORMATIONAL, confidence=C.HIGH, evidence=[hsts.value or ""], source=source)

        missing = []
        csp = sh.get("content-security-policy")
        if csp and not csp.present:
            missing.append("content-security-policy")
        for name in ("x-content-type-options", "referrer-policy", "permissions-policy",
                     "cross-origin-opener-policy", "cross-origin-resource-policy"):
            if name in sh and not sh[name].present:
                missing.append(name)
        xfo = sh.get("x-frame-options")
        frame_ancestors = bool(csp and isinstance(csp.parsed, dict) and "frame-ancestors" in csp.parsed)
        if xfo and not xfo.present and not frame_ancestors:
            missing.append("x-frame-options (and no CSP frame-ancestors)")
        if missing:
            f.add("http.security_headers_missing", final, category="http",
                  title="Security headers not set",
                  description="These response headers were absent. Their absence is not itself a "
                              "vulnerability; relevance depends on the application.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH,
                  evidence=[f"{m}: absent" for m in missing], source=source)

        cache = (probe.cache_control or "").lower()
        if probe.set_cookies and ("public" in cache or "s-maxage" in cache) and "no-store" not in cache:
            f.add("http.cookie_cacheable", final, category="http", title="Cookies set on a publicly cacheable response",
                  description="A shared cache may store this response including its Set-Cookie header and "
                              "serve it to other users.",
                  severity=S.LOW, confidence=C.MEDIUM,
                  evidence=[f"cache-control: {probe.cache_control}", f"{len(probe.set_cookies)} Set-Cookie header(s)"],
                  source=source)
        acao, acac = probe.cors.get("access-control-allow-origin"), probe.cors.get("access-control-allow-credentials")
        if acao == "*" and (acac or "").lower() == "true":
            f.add("http.cors_wildcard_credentials", final, category="http",
                  title="CORS allows any origin together with credentials",
                  description="Browsers reject this combination, so it signals a misconfigured CORS policy.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH,
                  evidence=[f"access-control-allow-origin: {acao}", f"access-control-allow-credentials: {acac}"],
                  source=source)

        banners = [f"{h}: {v}" for h in ("server", "x-powered-by") for v in probe.headers.get(h, [])
                   if _VERSIONED_SERVER.search(v)]
        if banners:
            f.add("http.version_disclosure", final, category="http", title="Software version disclosed in headers",
                  description="Response headers reveal software versions. This aids fingerprinting but is "
                              "not a vulnerability by itself.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH, evidence=banners, source=source)

        if csp and csp.present and isinstance(csp.parsed, dict):
            script_src = csp.parsed.get("script-src") or csp.parsed.get("default-src") or []
            weak = [t for t in script_src if t.strip("'") in ("unsafe-inline", "unsafe-eval")]
            if weak and "'strict-dynamic'" not in script_src and not any(t.startswith("'nonce-") for t in script_src):
                f.add("http.csp_unsafe_script", final, category="http",
                      title="CSP allows unsafe inline/eval scripts",
                      description="The script policy includes 'unsafe-inline' or 'unsafe-eval' without "
                                  "nonces or 'strict-dynamic', reducing CSP's XSS protection.",
                      severity=S.INFORMATIONAL, confidence=C.MEDIUM,
                      evidence=[f"script-src/default-src: {' '.join(script_src)}"], source=source)

    @staticmethod
    def _analyze_tls(tls: TlsData, f: FindingCollector) -> None:
        '''
        Analyze TLS probes: expiry, validity, hostname match, trust, protocol and key strength.
        Parameters:
            tls (TlsData): TLS probe results.
            f (FindingCollector): Collector to which findings will be added.
        '''
        for p in tls.probes:
            subject = f"{p.hostname}:{p.port}"
            source = f"TLS handshake {subject}"
            if not p.success:
                f.add("tls.connection_failed", subject, category="tls", title="TLS connection failed",
                      description="No TLS session could be established.",
                      severity=S.INFORMATIONAL, confidence=C.HIGH,
                      evidence=[f"{p.error_type}: {p.error}"], source=source)
                continue
            cert = p.certificate
            if cert is None:
                continue
            validity = f"valid {cert.not_before:%Y-%m-%d} → {cert.not_after:%Y-%m-%d}"

            if p.days_remaining is not None and p.days_remaining < 0:
                f.add("tls.expired", subject, category="tls", title="Certificate expired",
                      description=f"The certificate expired {-p.days_remaining} day(s) ago.",
                      severity=S.HIGH, confidence=C.HIGH, evidence=[validity], source=source)
            elif p.currently_valid is False:
                f.add("tls.not_yet_valid", subject, category="tls", title="Certificate not yet valid",
                      description="The certificate's validity period has not started.",
                      severity=S.MEDIUM, confidence=C.HIGH, evidence=[validity], source=source)
            elif p.days_remaining is not None and p.days_remaining <= TLS_EXPIRY_URGENT_DAYS:
                f.add("tls.expiring_soon", subject, category="tls", title="Certificate expires very soon",
                      description=f"The certificate expires in {p.days_remaining} day(s).",
                      severity=S.MEDIUM, confidence=C.HIGH, evidence=[validity], source=source)
            elif p.days_remaining is not None and p.days_remaining <= TLS_EXPIRY_WARN_DAYS:
                f.add("tls.expiring", subject, category="tls", title="Certificate approaching expiry",
                      description=f"The certificate expires in {p.days_remaining} day(s). Automated "
                                  "renewal (e.g. ACME) often renews around this point.",
                      severity=S.LOW, confidence=C.MEDIUM, evidence=[validity], source=source)

            if p.hostname_match is False:
                f.add("tls.hostname_mismatch", subject, category="tls",
                      title="Certificate does not cover hostname",
                      description="None of the certificate's SAN entries match the requested hostname.",
                      severity=S.MEDIUM, confidence=C.HIGH,
                      evidence=[f"SANs: {', '.join(cert.san_dns) or '(none)'}"], source=source)
            if p.verified is False and p.hostname_match is not False and (p.days_remaining or 0) >= 0:
                f.add("tls.untrusted", subject, category="tls", title="Certificate failed verification",
                      description="The certificate chain did not validate against the system trust store.",
                      severity=S.MEDIUM, confidence=C.HIGH,
                      evidence=[p.verification_error or "verification failed", f"issuer: {cert.issuer}"],
                      source=source)
            if p.tls_version in LEGACY_TLS:
                f.add("tls.legacy_protocol", subject, category="tls", title="Legacy TLS version negotiated",
                      description=f"The server negotiated {p.tls_version}, which is deprecated (RFC 8996).",
                      severity=S.LOW, confidence=C.HIGH, evidence=[f"negotiated: {p.tls_version}"], source=source)
            if cert.public_key_algorithm == "RSA" and (cert.public_key_size or 0) < 2048:
                f.add("tls.weak_key", subject, category="tls", title="Weak RSA key",
                      description="RSA keys shorter than 2048 bits are considered insufficient.",
                      severity=S.MEDIUM, confidence=C.HIGH,
                      evidence=[f"RSA {cert.public_key_size} bits"], source=source)
            if cert.signature_hash in ("md5", "sha1"):
                f.add("tls.weak_signature", subject, category="tls", title="Weak certificate signature hash",
                      description=f"The certificate is signed with {cert.signature_hash.upper()}.",
                      severity=S.MEDIUM, confidence=C.HIGH,
                      evidence=[cert.signature_algorithm], source=source)

    @staticmethod
    def _analyze_whois(reg: DomainRegistration, f: FindingCollector) -> None:
        '''
        Analyze domain registration data for expiry and hold statuses.
        Parameters:
            reg (DomainRegistration): Domain registration data.
            f (FindingCollector): Collector to which findings will be added.
        '''
        source = f"{reg.source.upper()} {reg.source_url or reg.domain}"
        expiry = f"expires {reg.expires:%Y-%m-%d}" if reg.expires else ""
        if reg.days_until_expiry is not None and reg.days_until_expiry < 0:
            f.add("whois.expired", reg.domain, category="registration", title="Domain registration expired",
                  description=f"The registration expired {-reg.days_until_expiry} day(s) ago and may be "
                              "in a grace or redemption period.",
                  severity=S.HIGH, confidence=C.HIGH, evidence=[expiry], source=source)
        elif reg.days_until_expiry is not None and reg.days_until_expiry <= DOMAIN_EXPIRY_WARN_DAYS:
            f.add("whois.expiring", reg.domain, category="registration", title="Domain registration expires soon",
                  description=f"The registration expires in {reg.days_until_expiry} day(s). Many "
                              "registrations auto-renew; verify renewal is configured.",
                  severity=S.LOW, confidence=C.MEDIUM, evidence=[expiry], source=source)
        holds = [st for st in reg.status if st.lower().replace("_", " ") in HOLD_STATUSES
                 or st.lower() in HOLD_STATUSES]
        if holds:
            f.add("whois.hold", reg.domain, category="registration", title="Domain is on hold",
                  description="A hold status removes the domain from the DNS zone.",
                  severity=S.MEDIUM, confidence=C.HIGH, evidence=holds, source=source)

    @staticmethod
    def _analyze_html(html: HtmlData, f: FindingCollector) -> None:
        '''
        Analyze the landing page for mixed content, insecure forms and scripts without SRI.
        Parameters:
            html (HtmlData): Parsed landing-page HTML.
            f (FindingCollector): Collector to which findings will be added.
        '''
        page = html.source_url
        source = f"HTML {page}"
        if page.startswith("https://"):
            active = [r.url for r in html.resources
                      if r.url.startswith("http://") and r.kind in ("script", "stylesheet", "iframe", "modulepreload")]
            passive = [r.url for r in html.resources if r.url.startswith("http://") and r.kind == "image"]
            forms = [r.url for r in html.resources if r.url.startswith("http://") and r.kind == "form"]
            if active:
                f.add("html.mixed_active_content", page, category="html", title="Active mixed content",
                      description="The HTTPS page references scripts/styles/frames over plain HTTP. "
                                  "Browsers block these, so the page may be partially broken.",
                      severity=S.LOW, confidence=C.HIGH, evidence=active[:10], source=source)
            if passive:
                f.add("html.mixed_passive_content", page, category="html", title="Passive mixed content",
                      description="Images are referenced over plain HTTP from an HTTPS page.",
                      severity=S.INFORMATIONAL, confidence=C.HIGH, evidence=passive[:10], source=source)
            if forms:
                f.add("html.insecure_form_action", page, category="html", title="Form submits over HTTP",
                      description="A form on the HTTPS page submits to a plain-HTTP URL.",
                      severity=S.LOW, confidence=C.HIGH, evidence=forms[:10], source=source)

        no_sri = [r.url for r in html.resources
                  if r.kind == "script" and not r.same_site and "integrity" not in r.attributes]
        if no_sri:
            f.add("html.third_party_script_no_sri", page, category="html",
                  title="Third-party scripts loaded without Subresource Integrity",
                  description="These cross-origin scripts have no integrity attribute, so a change at the "
                              "third party would load silently. SRI is often impractical for scripts that "
                              "change by design (analytics, tag managers); this is an inventory of supply-chain "
                              "trust, not a vulnerability. Assets that do declare integrity are hash-verified "
                              "when this scan downloaded them.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH, evidence=no_sri[:15], source=source)

    @staticmethod
    def _analyze_subdomains(data: SubdomainData, f: FindingCollector) -> None:
        '''
        Report CT-discovered hostnames that publicly resolve to private addresses.
        Parameters:
            data (SubdomainData): Subdomain discovery results.
            f (FindingCollector): Collector to which findings will be added.
        '''
        private = [r for r in data.hostnames if r.private_addresses]
        if private:
            f.add("subdomains.private_address", data.query.lstrip("%."), category="subdomains",
                  title="Public DNS names resolve to private addresses",
                  description="Hostnames from Certificate Transparency resolve publicly to internal "
                              "address space, which reveals internal naming/addressing. They were not "
                              "contacted.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH,
                  evidence=[f"{r.hostname} → {', '.join(r.private_addresses)}" for r in private[:15]],
                  source="crt.sh + DNS A/AAAA")


    @staticmethod
    def _analyze_dnssec(d: DnssecData, whois: DomainRegistration | None, f: FindingCollector) -> None:
        '''
        Report unsigned, broken or island DNSSEC states and registry/zone mismatches.
        Parameters:
            d (DnssecData): DNSSEC results.
            whois (DomainRegistration | None): Registration data (for the registry's DNSSEC flag).
            f (FindingCollector): Collector to which findings will be added.
        '''
        evidence = [f"DS: {d.ds_status} ({len(d.ds_records)})", f"DNSKEY: {d.dnskey_status} ({d.dnskey_count})",
                    f"resolver AD flag: {d.resolver_authenticated}"]
        source = f"DNS DS/DNSKEY {d.zone}"
        if d.status is DnssecStatus.UNSIGNED:
            f.add("dnssec.unsigned", d.zone, category="dnssec", title="Zone is not DNSSEC-signed",
                  description="No DS record at the parent and no DNSKEY in the zone; DNS answers cannot be "
                              "cryptographically validated.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH, evidence=evidence, source=source)
        elif d.status is DnssecStatus.BROKEN:
            f.add("dnssec.broken", d.zone, category="dnssec", title="DS record without matching DNSKEY",
                  description="The parent publishes a DS record but the zone serves no DNSKEY; validating "
                              "resolvers will fail to resolve the domain.",
                  severity=S.MEDIUM, confidence=C.HIGH, evidence=evidence, source=source)
        elif d.status is DnssecStatus.ISLAND:
            f.add("dnssec.island", d.zone, category="dnssec", title="Signed zone without a DS record",
                  description="The zone has DNSKEY records but no DS at the parent, so there is no chain of trust.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH, evidence=evidence, source=source)
        if whois and whois.dnssec is not None and d.status in (DnssecStatus.UNSIGNED, DnssecStatus.SIGNED_VALIDATED,
                                                               DnssecStatus.SIGNED_UNVALIDATED):
            signed = d.status is not DnssecStatus.UNSIGNED
            if whois.dnssec != signed:
                f.add("dnssec.registry_mismatch", d.zone, category="dnssec",
                      title="Registry DNSSEC flag disagrees with the zone",
                      description=f"The registry reports DNSSEC {'enabled' if whois.dnssec else 'disabled'} but "
                                  f"DNS shows the zone as {d.status.value}.",
                      severity=S.INFORMATIONAL, confidence=C.MEDIUM,
                      evidence=[*evidence, f"registry dnssec: {whois.dnssec}"], source=f"{source} + {whois.source}")

    @staticmethod
    def _analyze_resources(r: ResourcesData, f: FindingCollector) -> None:
        '''
        Report a missing, expired or incomplete security.txt.
        Parameters:
            r (ResourcesData): Public resource results.
            f (FindingCollector): Collector to which findings will be added.
        '''
        st = r.security_txt
        if st is None or st.error:
            return
        if not st.present:
            f.add("resources.security_txt_missing", r.origin, category="resources", title="No security.txt",
                  description="No security.txt at /.well-known/security.txt or /security.txt; researchers have "
                              "no published way to report vulnerabilities.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH,
                  evidence=[f"{st.url}: HTTP {st.status_code}" + (" (soft 404)" if st.soft_404 else "")],
                  source="GET /.well-known/security.txt, /security.txt")
            return
        if st.expired:
            f.add("resources.security_txt_expired", r.origin, category="resources", title="security.txt has expired",
                  description="RFC 9116 says consumers should treat expired security.txt files as stale.",
                  severity=S.LOW, confidence=C.HIGH, evidence=[f"Expires: {st.expires}"], source=f"GET {st.url}")
        missing = [name for name, ok in (("Contact", bool(st.contacts)), ("Expires", "expires" in st.fields)) if not ok]
        if missing:
            f.add("resources.security_txt_incomplete", r.origin, category="resources",
                  title="security.txt lacks required fields",
                  description=f"Required by RFC 9116 but missing: {', '.join(missing)}.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH,
                  evidence=[f"fields present: {', '.join(sorted(st.fields)) or 'none'}"], source=f"GET {st.url}")

    @staticmethod
    def _analyze_crawl(crawl: CrawlData, http: HttpData | None, f: FindingCollector) -> None:
        '''
        Report password forms on plain-HTTP pages, insecure form actions, and security headers that differ
        between the homepage and other crawled pages.
        Parameters:
            crawl (CrawlData): Crawl results.
            http (HttpData | None): HTTP results (homepage baseline).
            f (FindingCollector): Collector to which findings will be added.
        '''
        for form in crawl.forms:
            page_https = form.page_url.startswith("https://")
            if form.has_password_field and (not page_https or form.action.startswith("http://")):
                f.add("crawl.password_over_http", form.page_url, category="crawl",
                      title="Password form served or submitted over plain HTTP",
                      description="Credentials entered in this form travel unencrypted.",
                      severity=S.MEDIUM, confidence=C.HIGH,
                      evidence=[f"page: {form.page_url}", f"action: {form.method.upper()} {form.action}"],
                      source="crawler (form inspected, not submitted)")
            elif page_https and form.action.startswith("http://"):
                f.add("html.insecure_form_action", form.page_url, category="html", title="Form submits over HTTP",
                      description="A form on an HTTPS page submits to a plain-HTTP URL.",
                      severity=S.LOW, confidence=C.HIGH, evidence=[f"{form.method.upper()} {form.action}"],
                      source="crawler (form inspected, not submitted)")

        baseline = next((p for p in (http.probes if http else [])
                         if p.final_fetched and (p.final_url or "").startswith("https://")), None)
        if baseline is None:
            return
        base = {name: sh.present for name, sh in baseline.security_headers.items()}
        diffs: list[str] = []
        for page in crawl.pages:
            if page.error or not page.status_code or page.status_code >= 400 or not page.security_headers:
                continue
            if (page.final_url or page.url) == baseline.final_url:
                continue
            for name, present in base.items():
                here = page.security_headers.get(name) is not None
                if here != present:
                    diffs.append(f"{name}: {'present' if here else 'absent'} on {page.final_url or page.url} "
                                 f"({'present' if present else 'absent'} on homepage)")
        if diffs:
            f.add("http.header_inconsistency", baseline.final_url or "", category="http",
                  title="Security headers differ across pages",
                  description="Some pages send a different set of security headers than the homepage.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH, evidence=diffs[:20],
                  source=f"homepage + {len(crawl.pages)} crawled page(s)")

    @staticmethod
    def _analyze_assets(assets: AssetData, f: FindingCollector) -> None:
        '''
        Report publicly reachable source maps referenced by in-scope assets.
        Parameters:
            assets (AssetData): Static asset analysis.
            f (FindingCollector): Collector to which findings will be added.
        '''
        public = [a for a in assets.assets if a.source_map_status == "public"]
        if public:
            host = urlsplit(public[0].url).hostname or public[0].url
            exposed = sum(a.source_map_source_count for a in public)
            samples = [s for a in public for s in a.source_map_sources[:5]]
            f.add("js.source_map_public", host, category="javascript", title="Source maps are publicly accessible",
                  description="Production assets reference source maps that can be downloaded, exposing the "
                              "original (unminified) source code and project structure"
                              + (f" — {exposed} original source file(s) are listed." if exposed else "."),
                  severity=S.LOW, confidence=C.HIGH,
                  evidence=[f"{a.source_map_url} ({a.source_map_source_count} sources, referenced by {a.url})"
                            for a in public[:10]] + [f"exposed path: {s}" for s in samples[:15]],
                  source="sourceMappingURL references; map fetched and its 'sources' list parsed (code discarded)")

        mismatched = [a for a in assets.assets if a.integrity_status == "mismatch"]
        if mismatched:
            host = urlsplit(mismatched[0].url).hostname or mismatched[0].url
            f.add("js.integrity_mismatch", host, category="javascript",
                  title="Subresource Integrity hash does not match the served file",
                  description="The page declares an integrity hash for these assets, but the bytes served do not "
                              "match it. Browsers will refuse to load them, so the page is likely broken; it can "
                              "also mean the asset changed without the page being updated.",
                  severity=S.MEDIUM, confidence=C.HIGH,
                  evidence=[f"{a.url}: declared {a.integrity_declared} ({a.integrity_algorithm}), "
                            f"actual sha256:{a.sha256}" for a in mismatched[:10]],
                  source="integrity attribute verified against the downloaded bytes")

        secrets = [(a, s) for a in assets.assets for s in a.secrets]
        if secrets:
            host = urlsplit(secrets[0][0].url).hostname or secrets[0][0].url
            worst = S.HIGH if any(s.severity == "high" for _, s in secrets) else S.MEDIUM
            f.add("js.exposed_secret", host, category="javascript",
                  title="Possible private credential in client-side code",
                  description="Values matching private-credential patterns were found in downloaded bundles. "
                              "Client-side code is public, so anything embedded in it is readable by anyone. "
                              "Detection is heuristic and the raw values are not stored; confirm and, if real, "
                              "rotate the affected credential. Public keys (e.g. Stripe publishable, analytics IDs) "
                              "are excluded and not reported here.",
                  severity=worst, confidence=C.MEDIUM,
                  evidence=[f"{s.type} ({s.severity}) in {a.url}" + (f" [{s.context_key}]" if s.context_key else "")
                            + f" — {s.redacted}" for a, s in secrets[:20]],
                  source="static pattern match on downloaded bundles (values redacted)")

        configs = [(a, c) for a in assets.assets for c in a.client_configs]
        if configs:
            host = urlsplit(configs[0][0].url).hostname or configs[0][0].url
            f.add("js.client_config", host, category="javascript",
                  title="Public client configuration embedded in bundles",
                  description="Backend client configuration (e.g. Firebase, Supabase) ships in the browser by design. "
                              "This is informational: confirm that server-side authorization (database rules, "
                              "storage rules, row-level security) does not rely on these public values staying secret.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH,
                  evidence=[f"{c.provider} config in {a.url}: " + ", ".join(
                      field.key for field in c.fields if not field.sensitive) for a, c in configs[:10]],
                  source="static analysis of downloaded bundles")

    @staticmethod
    def _analyze_cookies(cookies: CookieData, f: FindingCollector) -> None:
        '''
        Report cookies lacking recommended attributes (values are never inspected).
        Parameters:
            cookies (CookieData): Cookie attribute results.
            f (FindingCollector): Collector to which findings will be added.
        '''
        def attrs(c) -> str:
            return f"{c.name}: {'; '.join(c.attributes) or '(no attributes)'} — set by {c.source_url}"

        for c in cookies.cookies:
            subject = f"{c.name}@{c.domain or c.source_url}"
            if c.over_https and not c.secure:
                f.add("cookies.missing_secure", subject, category="cookies", title="Cookie without Secure",
                      description="The cookie was set over HTTPS but may also be sent over plain HTTP.",
                      severity=S.LOW, confidence=C.HIGH, evidence=[attrs(c)], source=f"Set-Cookie on {c.source_url}")
            if not c.http_only:
                f.add("cookies.missing_httponly", subject, category="cookies", title="Cookie without HttpOnly",
                      description="Client-side scripts can read this cookie.",
                      severity=S.INFORMATIONAL, confidence=C.HIGH, evidence=[attrs(c)],
                      source=f"Set-Cookie on {c.source_url}")
            if (c.same_site or "").lower() == "none" and not c.secure:
                f.add("cookies.samesite_none_insecure", subject, category="cookies",
                      title="SameSite=None cookie without Secure",
                      description="Browsers reject SameSite=None cookies that are not also Secure.",
                      severity=S.LOW, confidence=C.HIGH, evidence=[attrs(c)], source=f"Set-Cookie on {c.source_url}")
            if c.prefix and c.prefix_valid is False:
                f.add("cookies.invalid_prefix", subject, category="cookies",
                      title=f"Cookie violates {c.prefix} prefix rules",
                      description="Browsers reject prefixed cookies that do not meet the prefix requirements.",
                      severity=S.LOW, confidence=C.HIGH, evidence=[attrs(c)], source=f"Set-Cookie on {c.source_url}")


class InfrastructureInference:
    '''
    Infers CDN, hosting, DNS and email providers from network, DNS and HTTP evidence.
    '''

    @classmethod
    def infer(cls, *, network: NetworkData | None, dns: DnsData | None,
              http: HttpData | None) -> list[InfrastructureObservation]:
        '''
        Run every inference and merge observations that share (provider, role).
        Parameters:
            network (NetworkData | None): Network intelligence results, or None.
            dns (DnsData | None): DNS collection results, or None.
            http (HttpData | None): HTTP probe results, or None.
        Returns:
            list[InfrastructureObservation]: Merged observations sorted by role and provider.
        '''
        return cls._merge_infrastructure(
            (cls._infer_network_providers(network) if network else [])
            + (cls._infer_dns_providers(dns) if dns else [])
            + (cls._infer_http_edge(http) if http else [])
        )

    @staticmethod
    def _first_match(
        sigs: tuple[ProviderSignature, ...], text: str, host: bool = False
    ) -> tuple[ProviderSignature | None, str | None]:
        '''
        Return the first provider signature matching the given text or hostname.
        Parameters:
            sigs (tuple[ProviderSignature, ...]): Signatures to test, in priority order.
            text (str): Free text or hostname to match.
            host (bool): Match as a hostname (suffix rules) instead of free text.
        Returns:
            tuple[ProviderSignature | None, str | None]: The matching signature and matched token, or (None, None).
        '''
        for sig in sigs:
            hit = sig.match_host(text) if host else sig.match_text(text)
            if hit:
                return sig, hit
        return None, None

    @staticmethod
    def _infer_network_providers(network: NetworkData) -> list[InfrastructureObservation]:
        '''
        Infer address-space providers for each IP from ASN, RDAP and PTR evidence.
        Parameters:
            network (NetworkData): Network intelligence results.
        Returns:
            list[InfrastructureObservation]: One observation per (IP, provider).
        '''
        out = []
        for ip in network.ips:
            texts = []
            if ip.asn:
                texts.append((f"ASN AS{ip.asn.asn} {ip.asn.name or ''}".strip(), "ASN (Team Cymru)"))
            if ip.rdap:
                for t in [ip.rdap.name, *ip.rdap.organizations]:
                    if t:
                        texts.append((f"RDAP: {t}", "RDAP"))
            for ptr in ip.ptr:
                texts.append((f"PTR {ptr}", "reverse DNS"))
            matched: dict[str, tuple[ProviderSignature, list[str], set[str]]] = {}
            for text, src in texts:
                sig, _ = InfrastructureInference._first_match(NETWORK_PROVIDERS, text)
                if sig:
                    entry = matched.setdefault(sig.provider, (sig, [], set()))
                    entry[1].append(text)
                    entry[2].add(src)
            for sig, evidence, sources in matched.values():
                out.append(InfrastructureObservation(
                    provider=sig.provider, category=sig.category, role="ip_allocation",
                    subjects=[ip.ip], evidence=evidence, source=", ".join(sorted(sources)),
                    confidence=C.HIGH if len(sources) > 1 else C.MEDIUM,
                    note="Address space is allocated to this provider; the origin server may be elsewhere.",
                ))
        return out

    @staticmethod
    def _infer_dns_providers(dns: DnsData) -> list[InfrastructureObservation]:
        '''
        Infer authoritative DNS and mail providers from NS and MX records.
        Parameters:
            dns (DnsData): DNS collection results.
        Returns:
            list[InfrastructureObservation]: Observations for matched NS/MX hosts.
        '''
        out = []
        ns = dns.queries.get("NS")
        for host in ns.values if ns else []:
            sig, hit = InfrastructureInference._first_match(DNS_PROVIDERS, host, host=True)
            if sig:
                out.append(InfrastructureObservation(
                    provider=sig.provider, category="dns", role="authoritative_dns", subjects=[host],
                    evidence=[f"NS {host} (matches {hit})"], source="DNS NS query", confidence=C.HIGH))
        mx = dns.queries.get("MX")
        for value in mx.values if mx else []:
            exchange = value.split()[-1]
            sig, hit = InfrastructureInference._first_match(MAIL_PROVIDERS, exchange, host=True)
            if sig:
                out.append(InfrastructureObservation(
                    provider=sig.provider, category="email", role="mail_exchange", subjects=[exchange],
                    evidence=[f"MX {value} (matches {hit})"], source="DNS MX query", confidence=C.HIGH))
        return out

    @staticmethod
    def _infer_http_edge(http: HttpData) -> list[InfrastructureObservation]:
        '''
        Infer CDN/hosting edges from final HTTP response headers.
        Parameters:
            http (HttpData): HTTP probe results.
        Returns:
            list[InfrastructureObservation]: Observations for matched header signatures.
        '''
        out = []
        for probe in http.probes:
            if not probe.final_fetched or not probe.final_url:
                continue
            for sig in HTTP_EDGE_PROVIDERS:
                values = probe.headers.get(sig.header)
                if not values:
                    continue
                joined = ", ".join(values)
                if sig.value_contains and sig.value_contains not in joined.lower():
                    continue
                out.append(InfrastructureObservation(
                    provider=sig.provider, category=sig.category, role="http_edge",
                    subjects=[probe.final_url], evidence=[f"{sig.header}: {joined[:120]}"],
                    source=f"GET {probe.final_url}", confidence=C.HIGH,
                    note="Response passed through this provider's edge; origin may differ.",
                ))
        return out

    @staticmethod
    def _merge_infrastructure(items: list[InfrastructureObservation]) -> list[InfrastructureObservation]:
        '''
        Merge observations sharing (provider, role), combining subjects, evidence and sources.
        Parameters:
            items (list[InfrastructureObservation]): Observations to merge.
        Returns:
            list[InfrastructureObservation]: Merged observations sorted by role and provider.
        '''
        merged: dict[tuple[str, str], InfrastructureObservation] = {}
        rank = {C.LOW: 0, C.MEDIUM: 1, C.HIGH: 2}
        for item in items:
            key = (item.provider, item.role)
            if key not in merged:
                merged[key] = item.model_copy(deep=True)
                continue
            cur = merged[key]
            cur.subjects = list(dict.fromkeys(cur.subjects + item.subjects))
            cur.evidence = list(dict.fromkeys(cur.evidence + item.evidence))
            cur.source = ", ".join(sorted(set(cur.source.split(", ")) | set(item.source.split(", "))))
            if rank[item.confidence] > rank[cur.confidence]:
                cur.confidence = item.confidence
        return sorted(merged.values(), key=lambda o: (o.role, o.provider))
