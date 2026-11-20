from __future__ import annotations

import re
from collections import Counter
from datetime import datetime
from urllib.parse import urlsplit

from recon.analysis.correlation import calibrate, correlate, recalc_states
from recon.analysis.grading import compute_grade
from recon.analysis.findings import FindingCollector
from recon.analysis.seo_checks import CHECKS_BY_ID
from recon.analysis.seo_grading import compute_seo_grade, run_checks
from recon.analysis.tech_signatures import SIGNATURES_VERSION
from recon.analysis.trackers import PRIVACY_SENSITIVE, TrackerCategory, classify_tracker
from recon.analysis.waf import detect_wafs
from recon.utils import registrable_domain
from recon.analysis.signatures import (
    DNS_PROVIDERS,
    HTTP_EDGE_PROVIDERS,
    MAIL_PROVIDERS,
    NETWORK_PROVIDERS,
    ProviderSignature,
)
from recon.models import (
    AnalysisResult,
    CloudResource,
    Confidence,
    DmarcAnalysis,
    DnsData,
    DnsQueryResult,
    DnsQueryStatus,
    DomainRegistration,
    Finding,
    HtmlData,
    HistoricalData,
    HttpData,
    HttpProbe,
    InfrastructureObservation,
    IpIntel,
    NetworkData,
    RenderData,
    VulnerabilityData,
    Severity,
    SpfAnalysis,
    SubdomainData,
    ThirdPartyData,
    TlsData,
    CookieData,
    CrawlData,
    DnssecData,
    DnssecStatus,
    Observation,
    ResourcesData,
    MtaStsPolicy,
    AssetData,
    SeoData,
    SeoCheck,
    SeoGrade,
)

HSTS_RECOMMENDED_MAX_AGE: int = 15_552_000  # 180 days
# RFC 8461 §6.4 recommends an MTA-STS max_age of at least two weeks; a policy cached for less than a day
# leaves a wide window in which a sender has no policy at all and can be downgraded.
MTA_STS_RECOMMENDED_MAX_AGE: int = 1_209_600   # 2 weeks
MTA_STS_SHORT_MAX_AGE: int = 86_400            # 1 day
TLS_EXPIRY_WARN_DAYS: int = 30
TLS_EXPIRY_URGENT_DAYS: int = 14
LEGACY_TLS: set[str] = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
DOMAIN_EXPIRY_WARN_DAYS: int = 30
HOLD_STATUSES: tuple[str, ...] = ("clienthold", "serverhold", "client hold", "server hold")
_VERSIONED_SERVER: re.Pattern[str] = re.compile(r"[a-z][\w.-]*/\d+(?:\.\d+)+", re.I)
# CAA issue/issuewild tag → the permitted CA's identifying domain.
_CAA_ISSUE_RE: re.Pattern[str] = re.compile(r'\d+\s+issue(?:wild)?\s+"([^"]*)"', re.I)
# Known CA issuer-org substrings per CAA domain, so a CT issuer like "Let's Encrypt" maps to "letsencrypt.org".
_CA_ISSUER_HINTS: dict[str, tuple[str, ...]] = {
    "letsencrypt.org": ("let's encrypt", "letsencrypt"), "pki.goog": ("google trust", "gts", "google"),
    "google.com": ("google trust", "gts"), "digicert.com": ("digicert",), "sectigo.com": ("sectigo", "comodo"),
    "globalsign.com": ("globalsign",), "amazon.com": ("amazon",), "amazontrust.com": ("amazon",),
    "ssl.com": ("ssl.com",), "certainly.com": ("certainly",), "buypass.com": ("buypass",),
    "zerossl.com": ("zerossl",), "entrust.net": ("entrust",), "actalis.it": ("actalis",),
    "godaddy.com": ("go daddy", "godaddy"), "microsoft.com": ("microsoft",),
}


def mta_sts_covers(pattern: str, host: str) -> bool:
    '''
    Whether an MTA-STS mx pattern covers an MX hostname.

    A wildcard is only valid as the whole first label and matches exactly one label (RFC 8461 §4.1), so
    '*.example.com' covers 'mx1.example.com' but neither 'example.com' nor 'a.mx1.example.com'.
    Parameters:
        pattern (str): An mx pattern from the policy.
        host (str): An MX hostname from DNS.
    Returns:
        bool: True if the pattern covers the host.
    '''
    pattern, host = pattern.strip().lower().rstrip("."), host.strip().lower().rstrip(".")
    if not pattern or not host:
        return False
    if pattern.startswith("*."):
        label, _, rest = host.partition(".")
        return bool(label) and rest == pattern[2:]
    return pattern == host


def mta_sts_uncovered(policy: MtaStsPolicy, mx_hosts: list[str]) -> list[str]:
    '''
    The MX hostnames from DNS that no pattern in the policy covers.

    Under ``enforce`` these are the hosts senders will refuse to deliver to, so this is the comparison
    that predicts a mail outage rather than merely describing configuration.
    Parameters:
        policy (MtaStsPolicy): Parsed policy.
        mx_hosts (list[str]): MX hostnames from DNS.
    Returns:
        list[str]: Uncovered MX hostnames, in DNS order.
    '''
    return [h for h in mx_hosts if not any(mta_sts_covers(p, h) for p in policy.mx)]


def _caa_issue_tags(records: list[str]) -> set[str]:
    '''
    The CA domains a CAA record set permits to issue (from issue/issuewild tags).
    Parameters:
        records (list[str]): Raw CAA record strings.
    Returns:
        set[str]: Permitted CA domains, lowercased ('issue ";"' — no CA — yields none).
    '''
    out: set[str] = set()
    for rec in records:
        for match in _CAA_ISSUE_RE.finditer(rec):
            domain = match.group(1).strip().lower().split(";")[0].strip()
            if domain:
                out.add(domain)
    return out


def _issuer_allowed(issuer: str, allowed: set[str]) -> bool:
    '''
    Whether a certificate issuer org name corresponds to one of the CAA-permitted CA domains (heuristic).
    Parameters:
        issuer (str): Issuer organization name (e.g. from CT or the leaf cert).
        allowed (set[str]): CAA-permitted CA domains.
    Returns:
        bool: True if the issuer maps to a permitted CA.
    '''
    low = issuer.lower()
    for ca in allowed:
        if any(hint in low for hint in _CA_ISSUER_HINTS.get(ca, ())):
            return True
        label = ca.split(".")[0]
        if label and label in low:   # fallback for CAs without an explicit hint list
            return True
    return False

S, C = Severity, Confidence  # enum aliases for brevity


def _is_absolute_url(value: str) -> bool:
    '''
    Whether a value is an absolute http(s) URL (as Open Graph requires for og:image/og:url).
    Parameters:
        value (str): The URL value to test.
    Returns:
        bool: True if it has an http/https scheme and a host.
    '''
    try:
        parts = urlsplit(value.strip())
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and bool(parts.hostname)


def _registrable_offsite(page_url: str, canonical: str) -> bool:
    '''
    Whether a canonical URL points to a different registrable domain than the page.

    A relative canonical (no host) is same-site by definition. When either registrable domain cannot be
    determined, this returns False so an uncertain case never produces a finding.
    Parameters:
        page_url (str): The page's own URL.
        canonical (str): The rel=canonical value.
    Returns:
        bool: True only when both registrable domains are known and differ.
    '''
    try:
        canon_host = urlsplit(canonical.strip()).hostname
        page_host = urlsplit(page_url).hostname
    except ValueError:
        return False
    if not canon_host or not page_host:
        return False
    canon_reg = registrable_domain(canon_host.lower())
    page_reg = registrable_domain(page_host.lower())
    return bool(canon_reg) and bool(page_reg) and canon_reg != page_reg


class AnalysisEngine:
    '''
    Interprets collected observations into findings, inferred infrastructure and severity counts.
    Stateless apart from the timestamp stamped on every finding; performs no network I/O.
    '''

    def __init__(self, timestamp: datetime) -> None: self.timestamp = timestamp

    def analyze(self, *, dns: DnsData | None, network: NetworkData | None, http: HttpData | None,
                tls: TlsData | None, host: str | None = None, whois: DomainRegistration | None = None,
                html: HtmlData | None = None, subdomains: SubdomainData | None = None,
                dnssec: DnssecData | None = None, resources: ResourcesData | None = None,
                crawl: CrawlData | None = None, cookies: CookieData | None = None,
                assets: AssetData | None = None, third_party: ThirdPartyData | None = None,
                render: RenderData | None = None, vulnerabilities: VulnerabilityData | None = None,
                historical: HistoricalData | None = None, seo: SeoData | None = None,
                observations: list[Observation] | None = None,
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
            host (str | None): Target hostname, used as the subject of host-level findings (e.g. hosting location).
            whois (DomainRegistration | None): Domain registration information.
            html (HtmlData | None): HTML probe results.
            subdomains (SubdomainData | None): Subdomain probe results.
            dnssec (DnssecData | None): DNSSEC results.
            resources (ResourcesData | None): Public resource results.
            crawl (CrawlData | None): Crawl results.
            cookies (CookieData | None): Cookie attribute results.
            assets (AssetData | None): Static JS/CSS asset analysis.
            third_party (ThirdPartyData | None): Third-party service inventory (classified into trackers)
                and the managed-cloud resource inventory.
            render (RenderData | None): Headless-browser render results.
            vulnerabilities (VulnerabilityData | None): OSV lookup results.
            historical (HistoricalData | None): Archived-URL surface from web archives and URL indexes.
            seo (SeoData | None): On-page SEO evidence for the analyzed pages. When present, the SEO check
                table is run over it and its own grade is attached to the result, separate from the
                security grade.
            observations (list[Observation] | None): Normalized observations used as evidence references.
        Returns:
            AnalysisResult: A structured report containing findings, inferred infrastructure, and severity counts.
        '''
        findings: FindingCollector = FindingCollector(self.timestamp)
        if dns:
            self._analyze_dns(dns, findings)
            self._analyze_email_transport(dns, resources, findings)
            self._analyze_caa_ct_mismatch(dns, subdomains, tls, findings)
        if http: self._analyze_http(http, findings)
        if http: self._analyze_hsts_preload(http, host, findings)
        if http: self._analyze_waf(http, cookies, findings)
        if tls: self._analyze_tls(tls, findings)
        if whois: self._analyze_whois(whois, findings)
        if html:
            self._analyze_html(html, findings)
            self._analyze_seo(html, findings)
            self._analyze_open_graph(html, findings)
        if subdomains: self._analyze_subdomains(subdomains, findings)
        if dnssec: self._analyze_dnssec(dnssec, whois, findings)
        if resources: self._analyze_resources(resources, findings)
        if crawl: self._analyze_crawl(crawl, http, findings)
        if cookies: self._analyze_cookies(cookies, findings)
        if assets: self._analyze_assets(assets, findings)
        if third_party:
            self._analyze_trackers(third_party, html, findings)
            self._analyze_cloud(third_party, host, findings)
        if network: self._analyze_hosting(network, host, findings)
        if render: self._analyze_render(render, host, findings)
        if vulnerabilities: self._analyze_vulnerabilities(vulnerabilities, host, findings)
        if historical: self._analyze_historical(historical, findings)
        seo_grade: SeoGrade | None = self._analyze_seo_site(seo, findings) if seo else None
        if observations: findings.link(observations)

        infrastructure: list[InfrastructureObservation] = InfrastructureInference.infer(
            network=network, dns=dns, http=http)
        ordered: list[Finding] = correlate(findings.sorted())   # merge same-issue duplicates across modules
        calibrate(ordered, observations or [])                  # weaken findings backed only by stale external data
        recalc_states(ordered)                                  # re-derive lifecycle state from adjusted confidence
        counts: Counter[str] = Counter(f.severity.value for f in ordered)

        return AnalysisResult(findings=ordered, infrastructure=infrastructure,
                              severity_counts={s.value: counts.get(s.value, 0) for s in Severity},
                              grade=compute_grade(ordered), seo=seo_grade)

    @staticmethod
    def _analyze_email_transport(dns: DnsData, resources: ResourcesData | None, f: FindingCollector) -> None:
        '''
        Report missing mail transport-security (MTA-STS, TLS-RPT, DANE) for domains that receive mail, and
        note BIMI when present. These apply only when the domain has MX records.

        The MTA-STS record and the policy file it points at are judged together, because each is useless
        without the other and the pairing names the actual fault: a record with no reachable policy
        enforces nothing, and a policy nobody announces is never fetched. Only one of those is ever
        reported, so the report says what is wrong rather than listing both halves.
        Parameters:
            dns (DnsData): DNS probe results (carries email.transport and MX).
            resources (ResourcesData | None): Public resources, carrying the fetched MTA-STS policy.
            f (FindingCollector): Collector to add findings to.
        '''
        host = dns.hostname
        t = dns.email.transport
        if not t.mx_hosts:
            return   # no MX → the domain does not receive mail; transport-security does not apply
        policy = resources.mta_sts if resources else None
        fetched = bool(policy and policy.present)
        if not t.mta_sts_present and fetched:
            # The policy file is deployed but nothing announces it, so no sender will ever fetch it. A
            # sharper statement than "no MTA-STS" — the work is done bar one DNS record.
            f.add("email.mta_sts_policy_without_record", host, category="email",
                  title="MTA-STS policy is published but not announced in DNS",
                  description="A valid-looking MTA-STS policy is served, but there is no _mta-sts TXT "
                              "record, and senders discover policies only through that record. The policy "
                              "is therefore never fetched and TLS is never required: the protection is "
                              "one DNS record away from working.",
                  severity=S.LOW, confidence=C.HIGH,
                  evidence=[f"policy at {policy.url} (mode: {policy.mode or 'unparsed'})",
                            f"no _mta-sts.{host} TXT record"],
                  source=f"GET {policy.url} and DNS TXT _mta-sts")
        elif not t.mta_sts_present:
            f.add("email.mta_sts_missing", host, category="email", title="No MTA-STS policy",
                  description="The domain receives mail but publishes no MTA-STS record, so sending servers "
                              "cannot require TLS for delivery and can be downgraded to plaintext by an "
                              "active network attacker.",
                  severity=S.LOW, confidence=C.HIGH, evidence=[f"no _mta-sts.{host} TXT; MX: {', '.join(t.mx_hosts[:5])}"],
                  source="DNS TXT _mta-sts")
        elif policy is not None and not fetched:
            f.add("email.mta_sts_policy_unreachable", host, category="email",
                  title="MTA-STS record announces a policy that cannot be fetched",
                  description="The _mta-sts TXT record tells senders a policy exists, but the policy file "
                              "itself could not be retrieved. A sender that cannot fetch the policy falls "
                              "back to unauthenticated delivery (or keeps serving a stale cached copy), so "
                              "the record on its own enforces nothing.",
                  severity=S.LOW, confidence=C.HIGH,
                  evidence=[f"GET {policy.url}: "
                            + (policy.error or f"HTTP {policy.status_code}" if policy.status_code
                               else policy.error or "no response"),
                            "soft 404 (an HTML page was served instead of the policy)" if policy.soft_404
                            else f"_mta-sts.{host} TXT record is present"],
                  source=f"GET {policy.url}")
        if fetched and policy is not None:
            AnalysisEngine._analyze_mta_sts_policy(policy, t.mx_hosts, host, f)
        if not t.tls_rpt_present:
            f.add("email.tls_rpt_missing", host, category="email", title="No SMTP TLS reporting (TLS-RPT)",
                  description="No TLS-RPT record, so the domain receives no reports of TLS delivery failures "
                              "or downgrade attempts against its mail.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH, evidence=[f"no _smtp._tls.{host} TXT"],
                  source="DNS TXT _smtp._tls")
        if not t.dane_mx:
            f.add("email.dane_missing", host, category="email", title="No DANE (TLSA) on MX hosts",
                  description="None of the MX hosts publish a TLSA record, so DANE does not protect SMTP "
                              "delivery TLS. MTA-STS or DANE (ideally both) should back mail transport.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH,
                  evidence=[f"no _25._tcp TLSA on: {', '.join(t.mx_hosts[:5])}"], source="DNS TLSA")
        if t.bimi_present:
            f.add("email.bimi_present", host, category="email", title="BIMI is published",
                  description="A BIMI record is published (brand logo in supporting mail clients). Informational; "
                              "BIMI requires an enforced DMARC policy to take effect.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH,
                  evidence=[f"default._bimi.{host}: l={t.bimi_location or '—'}"], source="DNS TXT default._bimi")

    @staticmethod
    def _analyze_mta_sts_policy(policy: MtaStsPolicy, mx_hosts: list[str], host: str,
                                f: FindingCollector) -> None:
        '''
        Interpret a fetched MTA-STS policy: whether it enforces anything, and whether it covers the mail.

        The DNS record alone cannot answer either question, which is why this exists. ``testing`` mode is
        the common surprise — it is widely deployed and widely believed to be protection, while it only
        produces reports. The MX coverage check is the one with operational teeth: under ``enforce``, a
        sender refuses delivery to an MX the policy does not list, so an uncovered MX predicts lost mail
        rather than merely weak configuration.
        Parameters:
            policy (MtaStsPolicy): The fetched, parsed policy.
            mx_hosts (list[str]): MX hostnames from DNS.
            host (str): Target hostname (finding subject).
            f (FindingCollector): Collector to add findings to.
        '''
        source = f"GET {policy.url}"
        if not policy.valid:
            f.add("email.mta_sts_policy_invalid", host, category="email",
                  title="MTA-STS policy is malformed",
                  description="The policy does not satisfy RFC 8461, so sending servers will reject it and "
                              "fall back to unauthenticated delivery. A malformed policy is equivalent to "
                              "no policy, while still looking configured from DNS.",
                  severity=S.LOW, confidence=C.HIGH,
                  evidence=policy.parse_errors[:8] or ["policy could not be parsed"], source=source)
            return      # mode and coverage below are meaningless once senders reject the file

        if policy.mode == "testing":
            f.add("email.mta_sts_testing_mode", host, category="email",
                  title="MTA-STS policy is in testing mode, so nothing is enforced",
                  description="The policy is published with mode=testing: senders report TLS failures but "
                              "still deliver over plaintext when TLS or certificate validation fails. "
                              "Testing mode is the correct place to start, and a common place to stop by "
                              "accident — until the mode is enforce, MTA-STS prevents no downgrade.",
                  severity=S.LOW, confidence=C.HIGH,
                  evidence=["mode: testing", f"max_age: {policy.max_age}",
                            f"mx: {', '.join(policy.mx[:5])}"], source=source)
        elif policy.mode == "none":
            f.add("email.mta_sts_withdrawn", host, category="email",
                  title="MTA-STS policy is withdrawn (mode=none)",
                  description="The policy declares mode=none, the documented way to withdraw MTA-STS. "
                              "Senders holding a cached policy stop enforcing it. This is intentional "
                              "during a decommission; confirm it was not left behind after one.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH,
                  evidence=["mode: none", f"max_age: {policy.max_age}"], source=source)

        if uncovered := mta_sts_uncovered(policy, mx_hosts):
            enforcing = policy.mode == "enforce"
            f.add("email.mta_sts_mx_mismatch", host, category="email",
                  title="MTA-STS policy does not cover every MX host",
                  description=("Mail is accepted at MX hosts the policy does not list. Under mode=enforce a "
                               "sending server refuses to deliver to a host absent from the policy, so these "
                               "MX records will reject legitimate mail rather than fall back — this is a "
                               "delivery failure, not a weakened defence."
                               if enforcing else
                               "Mail is accepted at MX hosts the policy does not list. In testing mode this "
                               "only generates failure reports, but it would block delivery to these hosts "
                               "the moment the policy moves to enforce."),
                  severity=S.MEDIUM if enforcing else S.LOW, confidence=C.HIGH,
                  evidence=[f"mode: {policy.mode}", f"policy mx: {', '.join(policy.mx[:8]) or 'none'}",
                            f"uncovered MX: {', '.join(uncovered[:8])}"], source=source)

        if policy.max_age is not None and policy.max_age < MTA_STS_SHORT_MAX_AGE:
            f.add("email.mta_sts_short_max_age", host, category="email",
                  title="MTA-STS policy is cached for less than a day",
                  description=f"max_age is {policy.max_age} seconds. Senders re-fetch the policy that "
                              "often, and a sender with no cached policy has no protection — so a short "
                              "lifetime widens the window an active attacker can use, and makes the "
                              "protection depend on the policy host staying reachable.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH,
                  evidence=[f"max_age: {policy.max_age}",
                            f"RFC 8461 recommends at least {MTA_STS_RECOMMENDED_MAX_AGE} (2 weeks)"],
                  source=source)

    @staticmethod
    def _analyze_caa_ct_mismatch(dns: DnsData, subdomains: SubdomainData | None, tls: TlsData | None,
                                 f: FindingCollector) -> None:
        '''
        Flag certificate issuers seen in CT or the live TLS cert that the current CAA policy does not permit.
        Parameters:
            dns (DnsData): DNS results (carries the CAA policy).
            subdomains (SubdomainData | None): CT discovery (issuer names).
            tls (TlsData | None): TLS results (live leaf issuer).
            f (FindingCollector): Collector to add findings to.
        '''
        allowed = _caa_issue_tags(dns.caa.records)
        if not allowed:
            return   # no CAA issue restriction in effect → nothing to contradict
        seen: set[str] = set()
        for rec in (subdomains.hostnames if subdomains else []):
            seen.update(i for i in rec.issuers if i)
        for probe in (tls.probes if tls else []):
            if probe.certificate and probe.certificate.issuer_org:
                seen.add(probe.certificate.issuer_org)
        unauthorized = sorted({i for i in seen if not _issuer_allowed(i, allowed)})
        if unauthorized:
            f.add("dns.caa_ct_mismatch", dns.hostname, category="dns",
                  title="Certificate issuer not permitted by the current CAA policy",
                  description="Certificate Transparency (or the live certificate) shows certificates from an "
                              "issuer the domain's current CAA policy does not list. This can be a certificate "
                              "issued before the policy was set, or evidence of mis-issuance; review it.",
                  severity=S.LOW, confidence=C.LOW,
                  evidence=[f"CAA allows: {', '.join(sorted(allowed))}", f"seen issuer(s): {', '.join(unauthorized[:8])}"],
                  source="CAA policy vs CT / TLS issuers")

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
    def _analyze_hsts_preload(http: HttpData, host: str | None, f: FindingCollector) -> None:
        '''
        Compare what the site's HSTS header asks for with whether the domain is actually preloaded.

        These are two different facts and the pairing is what carries information. A preloaded domain is
        upgraded by the browser whatever it sends today, so a header that no longer meets the criteria is
        worth saying out loud — the protection is real but the site has stopped documenting it, and
        removal from the list takes months to reach users. An eligible header on a domain that is not on
        the list simply means nobody submitted it, which is the actionable case.

        Membership comes from the bundled snapshot (see recon/utils/hsts.py). When no snapshot is
        available nothing is claimed about membership at all; only the header's eligibility is reported.
        Silent when HSTS is absent entirely — that is covered by http.hsts_missing.
        Parameters:
            http (HttpData): HTTP probe results (security headers and the preload lookup).
            host (str | None): Target hostname, the subject of the membership findings.
            f (FindingCollector): Collector to add findings to.
        '''
        for probe in http.probes:
            sh = probe.security_headers.get("strict-transport-security") if probe.security_headers else None
            if not (probe.final_fetched and sh and sh.value):
                continue
            url = probe.final_url or probe.requested_url
            value = sh.value.lower()
            max_age = re.search(r"max-age\s*=\s*(\d+)", value)
            missing = [name for name, present in (("max-age ≥ 1 year",
                                                   max_age is not None and int(max_age.group(1)) >= 31_536_000),
                                                  ("includeSubDomains", "includesubdomains" in value),
                                                  ("preload", "preload" in value)) if not present]
            pre = http.hsts_preload
            subject = host or url
            listed = bool(pre and pre.checked and pre.preloaded)
            coverage = (f"covered by the preload entry for '{pre.matched_name}'"
                        if pre and pre.via_subdomains and pre.matched_name
                        else f"listed as '{pre.matched_name}'" if pre and pre.matched_name else "listed")
            snapshot = (f"bundled preload snapshot of {pre.snapshot_date} ({pre.entries:,} entries)"
                        if pre and pre.snapshot_date else "bundled preload snapshot")

            if missing and listed:
                f.add("http.hsts_preloaded_header_ineligible", subject, category="http",
                      title="Domain is HSTS-preloaded but its header no longer qualifies",
                      description="The domain is in the browsers' HSTS preload list, so browsers upgrade "
                                  "requests to it regardless of what it sends — but the header served today "
                                  "would not meet the submission criteria. The protection is real and is not "
                                  "at immediate risk, yet the site no longer declares it, a resubmission "
                                  "would be rejected, and anything relying on the header alone (other agents, "
                                  "a future list removal) is unprotected.",
                      severity=S.LOW, confidence=C.HIGH,
                      evidence=[f"header: {sh.value}", f"missing for eligibility: {', '.join(missing)}",
                                f"{coverage} in the {snapshot}"],
                      source=f"HSTS header on {url} compared with the bundled preload list")
            elif missing:
                f.add("http.hsts_not_preload_ready", url, category="http",
                      title="HSTS not eligible for preloading",
                      description="An HSTS header is set but does not meet the browser preload criteria "
                                  "(max-age ≥ 1 year, includeSubDomains, and the preload directive), so the "
                                  "domain cannot be added to the HSTS preload list.",
                      severity=S.INFORMATIONAL, confidence=C.HIGH,
                      evidence=[sh.value, f"missing: {', '.join(missing)}"]
                               + ([f"not present in the {snapshot}"] if pre and pre.checked else []),
                      source=f"HSTS header on {url}")
            elif pre and pre.checked and not pre.preloaded:
                f.add("http.hsts_preload_eligible_not_listed", subject, category="http",
                      title="HSTS header is preload-ready but the domain is not on the list",
                      description="The header meets every preload criterion, including the preload "
                                  "directive, which signals an intent to be preloaded — but the domain is "
                                  "not in the bundled copy of the browser list. Either the submission was "
                                  "never made, or it was made too recently to appear in this snapshot. "
                                  "Until it is listed, the very first request to the domain is still "
                                  "unprotected.",
                      severity=S.INFORMATIONAL, confidence=C.MEDIUM,
                      evidence=[f"header: {sh.value}", f"absent from the {snapshot}"],
                      source=f"HSTS header on {url} compared with the bundled preload list")
            return   # one representative page is enough

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

            if p.forward_secret is False:
                f.add("tls.no_forward_secrecy", subject, category="tls", title="No forward secrecy",
                      description=f"The negotiated cipher ({p.cipher}) does not provide forward secrecy, so a "
                                  "future key compromise would expose recorded sessions. Prefer ECDHE or TLS 1.3.",
                      severity=S.MEDIUM, confidence=C.HIGH, evidence=[f"{p.tls_version} {p.cipher}"], source=source)
            if p.chain_complete is False:
                f.add("tls.incomplete_chain", subject, category="tls", title="Incomplete certificate chain",
                      description="The server sent only the leaf certificate, no intermediate(s). Clients that "
                                  "cannot fetch or cache the intermediate will fail to build a trust path; send "
                                  "the full chain.",
                      severity=S.LOW, confidence=C.MEDIUM,
                      evidence=[f"{p.chain_length} certificate(s) sent"], source=source)
            if cert.sct_count == 0:
                f.add("tls.no_sct", subject, category="tls", title="No embedded Certificate Transparency SCTs",
                      description="The certificate carries no embedded SCTs, so it may not be CT-logged. Modern "
                                  "publicly-trusted CAs embed SCTs; absence can indicate an old or privately "
                                  "issued certificate.",
                      severity=S.INFORMATIONAL, confidence=C.MEDIUM, evidence=["0 embedded SCTs"], source=source)

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
    def _analyze_seo(html: HtmlData, f: FindingCollector) -> None:
        '''
        Flag missing or conflicting SEO metadata on the landing page (quality signals, not vulnerabilities).
        Parameters:
            html (HtmlData): Parsed landing-page HTML.
            f (FindingCollector): Collector to which findings will be added.
        '''
        page = html.source_url
        source = f"HTML {page}"
        if not html.title:
            f.add("seo.title_missing", page, category="seo", title="Page has no <title>",
                  description="The landing page has no <title> element. Search engines, browser tabs and "
                              "shared links rely on it; its absence usually points to a template or rendering problem.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH, evidence=[f"no <title> on {page}"], source=source)
        if not html.meta_description:
            f.add("seo.meta_description_missing", page, category="seo", title="Page has no meta description",
                  description="There is no <meta name=\"description\">. Search engines will synthesize a snippet "
                              "from arbitrary page text instead of a chosen summary.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH, evidence=[f"no meta description on {page}"], source=source)
        if "noindex" in (html.robots or "").lower():
            f.add("seo.noindex", page, category="seo", title="Landing page asks search engines not to index it",
                  description="The robots meta directive contains 'noindex', so compliant search engines will not "
                              "list this page. On a production landing page this is frequently unintended — e.g. a "
                              "staging configuration shipped to production.",
                  severity=S.LOW, confidence=C.HIGH, evidence=[f'robots meta: "{html.robots}"'], source=source)
        if html.canonical and _registrable_offsite(page, html.canonical):
            f.add("seo.canonical_offsite", page, category="seo", title="Canonical URL points to another domain",
                  description="The rel=canonical link names a different registrable domain than the page itself, "
                              "telling search engines a different site is the original. This can be legitimate "
                              "(syndication) but is also a symptom of canonical hijacking or a template/copy-paste error.",
                  severity=S.LOW, confidence=C.MEDIUM,
                  evidence=[f"page: {page}", f"canonical: {html.canonical}"], source=source)

    @staticmethod
    def _analyze_seo_site(seo: SeoData, f: FindingCollector) -> SeoGrade | None:
        '''
        Run the SEO check table over the analyzed pages: one finding per failing check, plus the grade.

        Only failing checks produce findings. A check that could not be evaluated is reported in the
        grade's check list with the reason, never as a finding, so an absent crawl reads as "not looked
        at" rather than "clean". The coverage of the audit is itself reported as a finding, because a
        site-wide count drawn from one page is the easiest number in this report to over-read.
        Parameters:
            seo (SeoData): On-page SEO evidence.
            f (FindingCollector): Collector to add findings to.
        Returns:
            SeoGrade | None: The SEO grade, or None when no check could be evaluated.
        '''
        checks: list[SeoCheck] = run_checks(seo)
        source = f"SEO audit of {seo.pages_analyzed} page(s) ({seo.pages_source})"
        for row in checks:
            if row.status != "fail":
                continue
            spec = CHECKS_BY_ID[row.id]
            evidence: list[str] = []
            if row.scope == "page":
                evidence.append(f"{row.affected} of {row.checked} analyzed page(s) affected")
            if row.detail:
                evidence.append(row.detail)
            evidence += row.samples[:8]
            f.add(f"seo.{row.id}", seo.host, category="seo", title=spec.title,
                  description=spec.description, severity=spec.severity, confidence=spec.confidence,
                  evidence=evidence, source=source)
        if seo.pages_analyzed < 2:
            f.add("seo.coverage_single_page", seo.host, category="seo",
                  title="SEO audit covered one page only",
                  description="Only the landing page was available, so every site-wide check (duplicate "
                              "titles, internal links, sitemap coverage) had nothing to compare and was "
                              "skipped rather than passed. Re-run with --crawl for a site-wide audit.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH,
                  evidence=[f"pages analyzed: {seo.pages_analyzed}",
                            (f"checks skipped for lack of evidence: "
                             f"{sum(1 for c in checks if c.status == 'not_checked')} of {len(checks)}")],
                  source=source)
        elif seo.crawl_page_limit_reached:
            f.add("seo.coverage_truncated", seo.host, category="seo",
                  title="SEO audit covered only part of the site",
                  description="The crawl stopped at its page limit, so every count here describes the "
                              "pages that were analyzed, not the whole site. Raise --max-pages (and "
                              "--depth) for wider coverage before treating a count as complete.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH,
                  evidence=[f"pages analyzed: {seo.pages_analyzed}",
                            f"crawl depth limit: {seo.crawl_max_depth}",
                            f"sitemap lists {seo.sitemap.sitemap_urls} URL(s), "
                            f"{seo.sitemap.in_sitemap_not_crawled} of them not reached"
                            if seo.sitemap and seo.sitemap.sitemap_urls else "no sitemap to compare with"],
                  source=source)
        return compute_seo_grade(seo, checks)

    @staticmethod
    def _analyze_open_graph(html: HtmlData, f: FindingCollector) -> None:
        '''
        Flag missing, incomplete or malformed Open Graph / Twitter social-card metadata on the landing page.
        Parameters:
            html (HtmlData): Parsed landing-page HTML.
            f (FindingCollector): Collector to which findings will be added.
        '''
        page = html.source_url
        source = f"HTML {page}"
        og = html.open_graph
        if not og:
            f.add("og.missing", page, category="social", title="No Open Graph metadata",
                  description="The page has no Open Graph (og:*) tags, so links shared to social platforms and "
                              "chat apps get no controlled title, description or preview image.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH, evidence=[f"no og:* meta on {page}"], source=source)
            return
        missing = [k for k in ("og:title", "og:type", "og:image", "og:url") if k not in og]
        if missing:
            f.add("og.incomplete", page, category="social", title="Incomplete Open Graph metadata",
                  description="Open Graph tags are present but missing core properties, so social previews can "
                              "render inconsistently or incompletely across platforms.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH,
                  evidence=[f"present: {sorted(og)}", f"missing: {missing}"], source=source)
        malformed = [k for k in ("og:image", "og:url") if k in og and not _is_absolute_url(og[k])]
        if malformed:
            f.add("og.malformed", page, category="social", title="Open Graph URL properties are not absolute",
                  description="og:image and og:url must be absolute http(s) URLs; most crawlers ignore relative or "
                              "protocol-relative values, so the preview image or canonical link will not resolve.",
                  severity=S.LOW, confidence=C.HIGH,
                  evidence=[f"{k} = {og[k]!r}" for k in malformed], source=source)
        if html.open_graph and "twitter:card" not in html.twitter:
            f.add("twitter.card_missing", page, category="social", title="No Twitter/X card type",
                  description="Open Graph is present but there is no twitter:card tag, so X/Twitter may fall back "
                              "to a basic preview or none at all.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH,
                  evidence=[f"twitter keys: {sorted(html.twitter)}"], source=source)

    @staticmethod
    def _analyze_vulnerabilities(vulns: VulnerabilityData, host: str | None, f: FindingCollector) -> None:
        '''
        Turn OSV matches on inventoried component versions into one finding per vulnerable component.
        Parameters:
            vulns (VulnerabilityData): OSV lookup results.
            host (str | None): Target hostname (subject fallback).
            f (FindingCollector): Collector to add findings to.
        '''
        rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
        for comp in vulns.vulnerable:
            if not comp.vulns:
                continue
            worst = max(comp.vulns, key=lambda v: rank.get(v.severity, 2))
            severity = next(s for s in Severity if s.value == worst.severity) if worst.severity in rank else S.MEDIUM
            ids = []
            for v in comp.vulns[:10]:
                label = ", ".join(v.aliases[:3]) or v.id
                ids.append(f"{label}" + (f" ({v.severity})" if v.severity else "") + (f": {v.summary}" if v.summary else ""))
            f.add("vuln.known_component", f"{comp.package}@{comp.version}", category="vuln",
                  title=f"Known-vulnerable component: {comp.name} {comp.version}",
                  description=(f"The detected version of {comp.name} ({comp.package} {comp.version}) is affected "
                               f"by {len(comp.vulns)} published advisory(ies) in the OSV database. A match reflects "
                               "the version in use, not proof the vulnerable code path is reachable; confirm and "
                               "upgrade to a fixed release."),
                  severity=severity, confidence=C.MEDIUM, evidence=ids,
                  source=f"OSV ({comp.ecosystem}) lookup of {comp.package}@{comp.version}")

    @staticmethod
    def _analyze_render(render: RenderData, host: str | None, f: FindingCollector) -> None:
        '''
        Interpret dynamic-rendering results: third-party data egress and mixed content observed at runtime.
        Parameters:
            render (RenderData): Headless-browser render results.
            host (str | None): Target hostname (finding subject).
            f (FindingCollector): Collector to add findings to.
        '''
        subject = host or (render.pages[0].url if render.pages else "render")
        reg = registrable_domain(host) if host else None
        third = sorted({h for h in render.hosts_contacted
                        if h and (not reg or registrable_domain(h) != reg)})
        if third:
            f.add("render.third_party_egress", subject, category="render",
                  title="Runtime requests to third-party hosts",
                  description=("While rendering, the application sent requests to hosts outside the target's "
                               "registrable domain. Each is a party that may receive data about the page or its "
                               "visitors; confirm every one is intended and covered by your data-processing terms."),
                  severity=Severity.INFORMATIONAL, confidence=Confidence.HIGH,
                  evidence=[f"{len(third)} third-party host(s): " + ", ".join(third[:25])],
                  source="headless-browser runtime requests")
        https_page = any((p.url or "").startswith("https://") for p in render.pages)
        mixed = sorted({h for r in render.requests if r.url.startswith("http://")
                        and (h := urlsplit(r.url).hostname) and h not in ("127.0.0.1", "localhost")})
        if https_page and mixed:
            f.add("render.mixed_content", subject, category="render",
                  title="Mixed content: HTTPS page made plaintext HTTP requests",
                  description=("A page served over HTTPS triggered plaintext http:// requests at runtime. Mixed "
                               "content can be blocked by browsers and exposes those requests to tampering."),
                  severity=Severity.LOW, confidence=Confidence.HIGH,
                  evidence=["http:// requests to: " + ", ".join(mixed[:15])],
                  source="headless-browser runtime requests")

    @staticmethod
    def _analyze_cloud(third_party: ThirdPartyData, host: str | None, f: FindingCollector) -> None:
        '''
        Interpret the managed-cloud inventory: what the application points at, grouped by what each class of
        resource actually risks.

        Severity reflects what a *reference* justifies, which is never "exposed". An object-storage bucket
        wired into client code is LOW: buckets are the most common accidental-exposure class, so it is worth
        checking, but nothing here says this one is readable. A function endpoint is LOW for the same reason.
        A direct database/backend endpoint is MEDIUM, because that pattern moves authorization entirely into
        provider-side rules (row-level security, storage rules) where a default-open configuration exposes
        data to anyone holding the public client key — and the key is in the bundle by design. Confidence is
        MEDIUM throughout: the reference is certain, its security consequence is not.
        Parameters:
            third_party (ThirdPartyData): Inventory carrying the cloud resources.
            host (str | None): Target hostname (finding subject).
            f (FindingCollector): Collector to add findings to.
        '''
        resources = third_party.cloud_resources
        if not resources:
            return
        subject = host or "cloud"
        f.add("cloud.inventory", subject, category="cloud", title=f"{len(resources)} managed-cloud resource(s) referenced",
              description=("The application references these managed-cloud endpoints. This is an inventory of "
                           "the cloud surface reachable from the client, assembled from references only — "
                           "SiteRecon did not contact any of them, so nothing here states that a resource is "
                           "reachable, readable or even still provisioned."),
              severity=S.INFORMATIONAL, confidence=C.HIGH,
              evidence=[f"{r.provider} {r.kind}: {r.identifier}"
                        + (f" ({r.region})" if r.region else "")
                        + f" — via {', '.join(r.sources)}" for r in resources[:25]],
              source="references in collected pages, bundles, CSP and DNS")

        def group(kinds: tuple[str, ...]) -> list[CloudResource]:
            return [r for r in resources if r.kind in kinds]

        buckets = group(("object_storage",))
        if buckets:
            public = [r for r in buckets if r.public_by_default]
            f.add("cloud.object_storage_referenced", subject, category="cloud",
                  title="Object-storage bucket(s) referenced from client-side code",
                  description=("Client-side code or page markup points directly at object storage. Buckets are "
                               "the most frequent accidental-exposure class in cloud deployments: listing is "
                               "often left enabled, and objects uploaded later inherit whatever policy is in "
                               "place. Verify each bucket's access policy and that only intentionally public "
                               "objects are served. The reference itself is not an exposure, and SiteRecon did "
                               "not request these buckets."),
                  severity=S.LOW, confidence=C.MEDIUM,
                  evidence=[f"{r.provider}: {r.identifier}" + (f" [{r.region}]" if r.region else "")
                            + (" — this class is world-readable unless restricted" if r.public_by_default else "")
                            + f" (via {', '.join(r.sources)})" for r in (public + [b for b in buckets if b not in public])[:20]],
                  source="bucket hostnames and URLs referenced in collected evidence")

        functions = group(("serverless_function", "edge_worker"))
        if functions:
            f.add("cloud.serverless_endpoint", subject, category="cloud",
                  title=f"{len(functions)} serverless/edge endpoint(s) callable from the browser",
                  description=("The client references these serverless function or edge-worker endpoints, so "
                               "they are part of the application's externally reachable surface. Each needs its "
                               "own authentication, authorization and rate limiting — the browser is not a "
                               "trust boundary. Whether any of them answers an unauthenticated request was NOT "
                               "tested here; `siterecon active` has a bounded check for that."),
                  severity=S.LOW, confidence=C.MEDIUM,
                  evidence=[f"{r.provider}: {r.identifier}" + (f" [{r.region}]" if r.region else "")
                            + f" (via {', '.join(r.sources)})" for r in functions[:20]],
                  source="function endpoints referenced in collected evidence")

        backends = group(("managed_database",))
        if backends:
            f.add("cloud.backend_endpoint", subject, category="cloud",
                  title="Managed database/backend reached directly from the client",
                  description=("The browser talks straight to a managed database or backend-as-a-service "
                               "endpoint. In this pattern there is no server-side gatekeeper: the public client "
                               "key ships in the bundle by design, and the provider's own rules (row-level "
                               "security, database/storage rules, role permissions) are the only thing standing "
                               "between an anonymous caller and the data. A default-open or missing policy "
                               "exposes everything that endpoint can read. SiteRecon did not query these "
                               "endpoints; confirming the rules requires an authorized active check."),
                  severity=S.MEDIUM, confidence=C.MEDIUM,
                  evidence=[f"{r.provider}: {r.identifier}" + (f" [{r.region}]" if r.region else "")
                            + f" (via {', '.join(r.sources)})" for r in backends[:20]],
                  source="backend endpoints referenced in collected evidence")

    @staticmethod
    def _analyze_historical(historical: HistoricalData, f: FindingCollector) -> None:
        '''
        Interpret the archived-URL surface: what used to be reachable, and which of it still deserves a look.

        Every finding here is scoped to the past on purpose. Archives prove a URL was once fetchable, so the
        severity reflects what that history implies rather than a current exposure: the inventory is
        informational, sensitive-looking archived paths are LOW (worth verifying), and a credential-shaped
        query parameter is MEDIUM — if a real secret ever travelled in a URL it is now sitting in third-party
        archives, proxy logs and browser history, and rotation is the only fix. Confidence stays at MEDIUM or
        below because the evidence is a third party's record of a path, not an observation of this site today.
        Parameters:
            historical (HistoricalData): Archived-URL results.
            f (FindingCollector): Collector to add findings to.
        '''
        host = historical.host
        live = [s.source for s in historical.sources if s.status == "live"]
        failed = [s for s in historical.sources if s.status in ("failed", "skipped")]
        if historical.urls_seen:
            window = " to ".join(filter(None, [
                historical.first_seen.date().isoformat() if historical.first_seen else None,
                historical.last_seen.date().isoformat() if historical.last_seen else None])) or "unknown dates"
            f.add("historical.archived_urls", host, category="historical",
                  title=f"{historical.urls_seen} archived URL(s) across {len(live)} archive(s)",
                  description=("Web archives and URL indexes hold these URLs for the domain. They map the "
                               "endpoint and parameter surface the site exposed over time, including routes "
                               "that are no longer linked from anywhere. This is evidence of the past: a URL "
                               "here may 404 today, and the archive's coverage is not exhaustive."),
                  severity=S.INFORMATIONAL, confidence=C.MEDIUM,
                  evidence=[f"sources: {', '.join(live) or 'none'}", f"date range: {window}",
                            f"{len(historical.hosts)} hostname(s), {len(historical.paths)} distinct path(s)",
                            f"{len(historical.endpoints)} API-looking path(s)"]
                           + [f"endpoint: {p}" for p in historical.endpoints[:10]]
                           + ([f"extensions: {', '.join(f'{k} ({v})' for k, v in list(historical.extensions.items())[:8])}"]
                              if historical.extensions else []),
                  source=", ".join(live) or "web archives")

        if historical.sensitive_paths:
            f.add("historical.sensitive_path", host, category="historical",
                  title="Sensitive-looking paths exist in web archives",
                  description=("Archives hold URLs whose names suggest backups, database dumps, configuration "
                               "or key material that was publicly fetchable at some point. Confirm whether each "
                               "is still reachable; if a secret-bearing file was ever public, treat the secret "
                               "as compromised regardless of whether the file is reachable now."),
                  severity=S.LOW, confidence=C.MEDIUM, evidence=historical.sensitive_paths[:15],
                  source=", ".join(live) or "web archives")

        credentials = [p for p in historical.parameters if p.category == "credential"]
        if credentials:
            f.add("historical.credential_in_url", host, category="historical",
                  title="Credential-shaped query parameters in archived URLs",
                  description=("Archived URLs carried query parameters whose names indicate tokens, keys, "
                               "session identifiers or passwords. A secret placed in a URL is copied into web "
                               "archives, proxy and CDN logs, browser history and outbound Referer headers, so "
                               "it cannot be un-exposed by changing the application. Move these values out of "
                               "the query string and rotate anything that was ever carried in one. The values "
                               "themselves are redacted and never stored by SiteRecon, so the match is on the "
                               "parameter name alone."),
                  severity=S.MEDIUM, confidence=C.LOW,
                  evidence=[f"{p.name} ({p.occurrences} URL(s); e.g. {p.paths[0] if p.paths else '—'})"
                            for p in credentials[:12]],
                  source=", ".join(live) or "web archives")

        surface = [p for p in historical.parameters if p.category in ("redirect", "file")]
        if surface:
            f.add("historical.parameter_surface", host, category="historical",
                  title="Redirect- and file-valued parameters in archived URLs",
                  description=("These archived parameters took URLs or paths as values — the classic "
                               "open-redirect, SSRF and file-inclusion surface. Their presence is not a "
                               "vulnerability; it marks where to check that redirect targets are validated "
                               "against an allow-list and that no parameter is mapped onto a filesystem path."),
                  severity=S.INFORMATIONAL, confidence=C.MEDIUM,
                  evidence=[f"{p.name} [{p.category}] ({p.occurrences} URL(s); e.g. {p.paths[0] if p.paths else '—'})"
                            for p in surface[:15]],
                  source=", ".join(live) or "web archives")

        legacy = [h for h in historical.tech_hints
                  if h.still_detected is not True and h.confidence is not Confidence.LOW]
        if legacy:
            f.add("historical.legacy_technology", host, category="historical",
                  title="Archived URLs show a technology the current scan does not detect",
                  description=("Archived paths and file extensions identify a stack that served this site at "
                               "some point and that the current scan did not detect. Old handlers often survive "
                               "a migration behind a new front end, unmaintained and unpatched. Confirm whether "
                               "the legacy stack is still deployed; if it is not, make sure its routes fail "
                               "closed rather than reaching a forgotten handler."),
                  severity=S.LOW, confidence=C.LOW,
                  evidence=[f"{h.name} ({h.category}, {h.occurrences} path(s), last archived "
                            f"{h.last_seen.date().isoformat() if h.last_seen else 'unknown'}): "
                            f"{', '.join(h.evidence[:3])}" for h in legacy[:12]],
                  source=", ".join(live) or "web archives")

        if failed:
            f.add("historical.discovery_incomplete", host, category="historical",
                  title="Some archive sources did not return results",
                  description=("One or more historical sources failed or were skipped, so the archived surface "
                               "below is narrower than the sources enabled would normally provide. Absence of a "
                               "URL in this report is therefore not evidence it was never public."),
                  severity=S.INFORMATIONAL, confidence=C.HIGH,
                  evidence=[f"{s.source}: {s.status}" + (f" — {s.error or s.skip_reason}"
                                                         if (s.error or s.skip_reason) else "") for s in failed],
                  source="historical source outcomes")

    @staticmethod
    def _analyze_hosting(network: NetworkData, host: str | None, f: FindingCollector) -> None:
        '''
        Estimate where the target's resolved IPs are hosted, from ASN/RDAP allocation and (if available) an
        offline city database.

        Parameters:
            network (NetworkData): Per-IP intelligence.
            host (str | None): Target hostname (the finding subject); falls back to the first IP.
            f (FindingCollector): Collector to which the finding will be added.
        '''
        public: list[IpIntel] = [ip for ip in network.ips if ip.is_public]
        if not public: return
        lines: list[str] = []
        attribution: str | None = None
        for ip in public:
            text = " ".join(filter(None, [
                ip.asn.name if ip.asn else None, ip.rdap.name if ip.rdap else None,
                *(ip.rdap.organizations if ip.rdap else [])]))
            provider = next((s for s in NETWORK_PROVIDERS if text and s.match_text(text)), None)
            if provider is not None and provider.category == "cdn":
                lines.append(f"{ip.ip}: {provider.provider} (CDN/anycast — hosting location not meaningful)")
                continue
            country = ((ip.geo.country_code or ip.geo.country) if ip.geo else None) \
                or (ip.rdap.country if ip.rdap else None) or (ip.asn.country if ip.asn else None)
            org = (ip.rdap.organizations[0] if ip.rdap and ip.rdap.organizations else None) \
                or (ip.asn.name if ip.asn else None)
            parts = [f"country {country}" if country else "country unknown"]
            if org:
                parts.append(f"org {org}")
            if ip.geo and ip.geo.city:
                city = ", ".join(filter(None, [ip.geo.city, ip.geo.region]))
                parts.append(f"city ~{city} [{ip.geo.source} {ip.geo.database_date or ''}]".strip())
                attribution = ip.geo.source
            lines.append(f"{ip.ip}: " + ", ".join(parts))
        if attribution:
            lines.append(f"city-level data: {attribution} (offline database; attribution required by its licence)")
        description = ("Estimated hosting location of the target's resolved IPs, from ASN/RDAP allocation data"
                       + (" and an offline city database" if attribution else "")
                       + ". This is an estimate of where the address space is registered, not the physical "
                         "server; an address behind a CDN/anycast network has no single meaningful location.")
        f.add("hosting.location", host or public[0].ip, category="hosting", title="Hosting location (estimated)",
              description=description, severity=S.INFORMATIONAL, confidence=C.MEDIUM, evidence=lines[:20],
              source="ASN/RDAP allocation" + (" and offline geolocation database" if attribution else ""))

    @staticmethod
    def _analyze_waf(http: HttpData, cookies: CookieData | None, f: FindingCollector) -> None:
        '''
        Identify any WAF/edge-security provider from the primary probe's headers, banner and cookies.

        Informational intelligence, not a vulnerability. No finding is produced when nothing matches —
        absence of a signature is never reported as "no WAF", since many WAFs leave no trace on a 200.
        Parameters:
            http (HttpData): HTTP probe results.
            cookies (CookieData | None): Cookie attribute results (names only are used).
            f (FindingCollector): Collector to which findings will be added.
        '''
        probe = (next((p for p in http.probes if p.final_fetched and (p.final_url or "").startswith("https://")), None) or next((p for p in http.probes if p.success), None))
        if probe is None:
            return
        cookie_names = [c.name for c in cookies.cookies] if cookies else []
        detections = detect_wafs(probe.headers, cookie_names, probe.server)
        if not detections:
            return
        subject = urlsplit(probe.final_url or probe.requested_url).hostname or probe.requested_url
        confidence = max((d.confidence for d in detections), key=lambda c: c.rank)
        evidence = [f"signature DB version: {SIGNATURES_VERSION}"]
        for d in detections:
            note = f" — {d.note}" if d.note else ""
            evidence.append(f"{d.vendor} ({d.confidence.value}){note}: {'; '.join(d.evidence)}")
        vendors = ", ".join(d.vendor for d in detections)
        title = (f"Web Application Firewall detected: {detections[0].vendor}" if len(detections) == 1
                 else f"Web Application Firewall(s) detected: {vendors}")
        f.add("waf.detected", subject, category="waf", title=title,
              description="A WAF / edge-security provider was identified from response headers, the server "
                          "banner or cookies — informational intelligence about the target's defenses. Absence "
                          "of a signature is NOT proof there is no WAF (many are invisible on a normal response), "
                          "and a CDN/proxy signal shows the platform is WAF-capable, not that rules are enabled.",
              severity=S.INFORMATIONAL, confidence=confidence, evidence=evidence[:20],
              source="HTTP response headers, server banner and cookies")

    @staticmethod
    def _analyze_trackers(third_party: ThirdPartyData, html: HtmlData | None, f: FindingCollector) -> None:
        '''
        Classify the third-party inventory into trackers by purpose and inventory them.
        Parameters:
            third_party (ThirdPartyData): The third-party service inventory.
            html (HtmlData | None): Landing-page HTML, used only to name the finding subject.
            f (FindingCollector): Collector to which findings will be added.
        '''
        found: dict[str, dict] = {}
        for service in third_party.services:
            for domain in service.domains:
                sig = classify_tracker(domain)
                if sig is None:
                    continue
                rec = found.setdefault(sig.provider, {"category": sig.category, "domains": set(), "sources": set()})
                rec["domains"].add(domain)
                rec["sources"].update(service.sources)
        if not found:
            return

        subject = (urlsplit(html.source_url).hostname if html and html.source_url else None) or "trackers"
        by_category: Counter[TrackerCategory] = Counter(rec["category"] for rec in found.values())
        summary = ", ".join(f"{cat.value}: {n}" for cat, n in sorted(by_category.items(), key=lambda kv: kv[0].value))
        lines: list[str] = [f"signature DB version: {SIGNATURES_VERSION}",
                            f"{len(found)} tracker(s) — {summary}"]
        for provider, rec in sorted(found.items(), key=lambda kv: (kv[1]["category"].value, kv[0])):
            doms = ", ".join(sorted(rec["domains"])[:3])
            srcs = ", ".join(sorted(rec["sources"])[:2]) or "referenced"
            lines.append(f"{rec['category'].value}: {provider} — {doms} (via {srcs})")
        f.add("trackers.detected", subject, category="trackers", title="Third-party trackers in use",
              description="The site loads third-party services that track visitors, classified here by purpose "
                          "(analytics, tag manager, A/B testing, consent, CDP, social, advertising, session "
                          "replay, fingerprinting). This is an inventory for privacy/consent review, not a "
                          "vulnerability; confirm each is disclosed and consented to as your jurisdiction requires.",
              severity=S.INFORMATIONAL, confidence=C.HIGH, evidence=lines[:25], source="third-party inventory")

        sensitive = sorted(p for p, rec in found.items() if rec["category"] in PRIVACY_SENSITIVE
                           and rec["category"] is TrackerCategory.SESSION_REPLAY)
        if sensitive:
            f.add("trackers.session_replay", subject, category="trackers",
                  title="Session-replay/heatmap trackers present",
                  description="These trackers record user sessions — mouse movement, clicks, scrolling and "
                              "sometimes keystrokes and form input. They capture potentially sensitive personal "
                              "data and in most jurisdictions require explicit prior consent and input masking.",
                  severity=S.LOW, confidence=C.HIGH,
                  evidence=[f"session-replay providers: {', '.join(sensitive)}",
                            f"signature DB version: {SIGNATURES_VERSION}"], source="third-party inventory")

    @staticmethod
    def _analyze_subdomains(data: SubdomainData, f: FindingCollector) -> None:
        '''
        Report discovered hostnames that publicly resolve to private addresses, takeover-prone CNAMEs,
        incomplete source coverage, and hosts only the generated-candidate pass found.
        Parameters:
            data (SubdomainData): Subdomain discovery results.
            f (FindingCollector): Collector to which findings will be added.
        '''
        target = data.query.lstrip("%.")
        incomplete = [p for p in (*data.providers, *data.sources) if p.status in ("failed", "cached", "skipped")]
        if incomplete:
            # Saying "these N names exist" without saying "and one source never answered" overstates
            # coverage; a reader needs to know the list is narrower than the sources enabled would give.
            f.add("subdomains.discovery_incomplete", target, category="subdomains",
                  title="Subdomain discovery coverage was incomplete",
                  description=("One or more discovery sources failed, were served from cache, or were skipped, "
                               "so the hostname list reflects less coverage than the enabled sources would "
                               "normally provide. Absence of a name here is not evidence it does not exist."),
                  severity=S.INFORMATIONAL, confidence=C.HIGH,
                  evidence=[f"{p.provider} ({p.kind}): {p.status}"
                            + (f" — {p.error or p.skip_reason}" if (p.error or p.skip_reason) else "")
                            for p in incomplete],
                  source="per-source discovery outcomes")

        permutation_only = [r for r in data.hostnames
                            if r.resolves and r.sources == ["permutation"]]
        if permutation_only:
            # A name that resolves but appears in no certificate and no passive dataset is usually
            # infrastructure nobody inventoried — which is also infrastructure nobody is patching.
            f.add("subdomains.unlisted_host", target, category="subdomains",
                  title=f"{len(permutation_only)} resolving host(s) absent from every public dataset",
                  description=("These hostnames resolve in DNS but were found in no certificate and no passive "
                               "dataset — they were generated from the naming pattern of the names that were "
                               "found, then confirmed by a DNS lookup. Hosts missing from public inventories "
                               "are frequently forgotten environments (staging, admin, legacy) that are still "
                               "reachable but no longer maintained. Confirm each is intended and inventoried. "
                               "Only DNS was queried; none of these hosts was contacted over HTTP."),
                  severity=S.LOW, confidence=C.MEDIUM,
                  evidence=[f"{r.hostname} → {', '.join(r.addresses[:3])}" for r in permutation_only[:20]],
                  source="generated candidate confirmed by DNS resolution")

        private = [r for r in data.hostnames if r.private_addresses]
        if private:
            f.add("subdomains.private_address", target, category="subdomains",
                  title="Public DNS names resolve to private addresses",
                  description="Hostnames from Certificate Transparency resolve publicly to internal "
                              "address space, which reveals internal naming/addressing. They were not "
                              "contacted.",
                  severity=S.INFORMATIONAL, confidence=C.HIGH,
                  evidence=[f"{r.hostname} → {', '.join(r.private_addresses)}" for r in private[:15]],
                  source="discovery sources + DNS A/AAAA")

        for r in (x for x in data.hostnames if x.takeover_vulnerable):   # one high finding per vulnerable name
            f.add("subdomain.takeover", r.hostname, category="subdomains",
                  title=f"Possible subdomain takeover: {r.hostname}",
                  description="This name delegates (CNAME) to a third-party service whose backing resource "
                              "appears unclaimed, so anyone who registers that resource could serve content "
                              "on this subdomain. Reclaim the resource or remove the DNS record.",
                  severity=S.HIGH, confidence=C.MEDIUM,
                  evidence=[r.takeover_detail or f"CNAME → {r.cname}"],
                  source="CNAME + provider takeover fingerprint")

        dangling = [r for r in data.hostnames if r.takeover_provider and not r.takeover_vulnerable]
        if dangling:
            f.add("subdomain.dangling_cname", target, category="subdomains",
                  title="Subdomains delegate to takeover-prone providers",
                  description="These names CNAME to services commonly associated with dangling-record "
                              "takeovers. They appear claimed now; keep the backing resources provisioned, or "
                              "remove the records if the services are unused.",
                  severity=S.LOW, confidence=C.LOW,
                  evidence=[f"{r.hostname} → {r.cname} ({r.takeover_provider})" for r in dangling[:15]],
                  source="CNAME + provider list")


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
