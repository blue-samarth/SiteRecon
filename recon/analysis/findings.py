from __future__ import annotations

from datetime import datetime

from recon.models import Confidence, Finding, Observation, Severity

# Recommended action per finding code (exact code, or a prefix ending in '.').
RECOMMENDATIONS: dict[str, str] = {
    "dns.spf_missing": "If the domain sends mail, publish an SPF record listing its senders; if it never sends "
                       "mail, publish 'v=spf1 -all'.",
    "dns.spf_multiple": "Merge all SPF policies into a single v=spf1 TXT record.",
    "dns.spf_pass_all": "Replace '+all' with '~all' or '-all' once legitimate senders are listed.",
    "dns.spf_neutral_all": "Use '~all' or '-all' once all senders are listed.",
    "dns.spf_lookup_limit": "Reduce or flatten include: chains so evaluation needs at most 10 DNS lookups "
                            "and 2 void lookups.",
    "dns.spf_parse_error": "Correct the malformed SPF terms; receivers return permerror for invalid records.",
    "dns.spf_ptr": "Replace the deprecated 'ptr' mechanism with ip4/ip6/include terms.",
    "dns.dmarc_missing": "Publish a DMARC record; start with p=none plus rua reporting, then move to "
                         "quarantine or reject.",
    "dns.dmarc_multiple": "Keep exactly one DMARC record at _dmarc.<domain>.",
    "dns.dmarc_monitor_only": "After reviewing aggregate reports, move the policy to p=quarantine or p=reject.",
    "dns.dmarc_no_reports": "Add a rua= address to receive aggregate reports.",
    "dns.dkim_weak_key": "Rotate to a DKIM key of at least 2048 bits.",
    "dns.caa_absent": "Publish CAA records naming the certificate authorities you use.",
    "dnssec.unsigned": "Consider enabling DNSSEC at the DNS provider and publishing the DS record at the registrar.",
    "dnssec.broken": "Publish the zone's DNSKEY records or remove the stale DS record at the registrar.",
    "dnssec.island": "Publish the DS record at the registrar to complete the chain of trust.",
    "dnssec.registry_mismatch": "Check that the registrar's DNSSEC setting matches the zone's actual signing state.",
    "http.no_https_redirect": "Redirect all plain-HTTP requests to HTTPS.",
    "http.hsts_missing": "Send Strict-Transport-Security with a max-age of at least 180 days on HTTPS responses.",
    "http.hsts_": "Use a valid HSTS max-age of at least 180 days.",
    "http.security_headers_missing": "Evaluate whether each header suits the application and add those that do.",
    "http.csp_unsafe_script": "Use nonces or hashes (with 'strict-dynamic') instead of 'unsafe-inline'/'unsafe-eval'.",
    "http.version_disclosure": "Remove version numbers from Server and X-Powered-By headers.",
    "http.header_inconsistency": "Apply security headers consistently, e.g. at the CDN or reverse proxy.",
    "http.cookie_cacheable": "Mark responses that set cookies as private or no-store.",
    "http.cors_wildcard_credentials": "Return a specific origin (not '*') when credentials are allowed, or "
                                      "drop Access-Control-Allow-Credentials.",
    "http.unreachable.": "Check whether the endpoint is expected to be available.",
    "http.redirect_out_of_scope": "Confirm the redirect destination is expected.",
    "tls.expired": "Renew the certificate immediately.",
    "tls.expiring": "Renew the certificate or verify that automated renewal is working.",
    "tls.expiring_soon": "Renew the certificate now; automated renewal may have failed.",
    "tls.not_yet_valid": "Check the server clock and the certificate's validity period.",
    "tls.hostname_mismatch": "Issue a certificate whose SAN covers this hostname.",
    "tls.untrusted": "Serve a certificate chain issued by a publicly trusted CA, including intermediates.",
    "tls.legacy_protocol": "Disable TLS 1.0/1.1 and prefer TLS 1.2+ (ideally 1.3).",
    "tls.weak_": "Reissue the certificate with an RSA key ≥ 2048 bits (or ECDSA) and a SHA-256+ signature.",
    "whois.expired": "Renew the domain registration immediately.",
    "whois.expiring": "Confirm auto-renewal is enabled at the registrar.",
    "whois.hold": "Contact the registrar to resolve the hold status.",
    "html.mixed_": "Serve all subresources over HTTPS.",
    "html.insecure_form_action": "Submit forms only to HTTPS endpoints.",
    "html.third_party_script_no_sri": "Add integrity attributes to static third-party files where feasible.",
    "seo.title_missing": "Add a descriptive <title> element to the page.",
    "seo.meta_description_missing": "Add a concise <meta name=\"description\"> summarizing the page.",
    "seo.noindex": "If this page should be discoverable, remove 'noindex' from its robots directive; confirm a staging setting was not shipped to production.",
    "seo.canonical_offsite": "Confirm the canonical URL intentionally points to another domain; otherwise correct it to this page's own canonical URL.",
    "og.missing": "Add Open Graph tags (og:title, og:type, og:image, og:url) so shared links render a controlled preview.",
    "og.incomplete": "Add the missing core Open Graph properties (og:title, og:type, og:image, og:url).",
    "og.malformed": "Use absolute http(s) URLs for og:image and og:url.",
    "twitter.card_missing": "Add a twitter:card tag (e.g. summary_large_image) to control the X/Twitter preview.",
    "waf.detected": "No action required; confirm the WAF runs in blocking (not monitor-only) mode, covers every origin and subdomain, and that the origin cannot be reached directly to bypass it.",
    "hosting.location": "No action required; verify the hosting region and provider match your data-residency and compliance requirements.",
    "intel.archived_history": "Review archived snapshots for endpoints or data that should not be public; remove anything sensitive from the live site and request removal from the archive where warranted.",
    "intel.archived_sensitive_path": "Verify whether each archived sensitive path is still reachable; if a backup/config/secret file was ever public, treat it as exposed and rotate the affected credentials.",
    "intel.exposed_ports": "Confirm each indexed port should be internet-facing; firewall or close those that should not be, and verify the IP serves only intended hosts.",
    "intel.indexed_vulnerability": "Verify each CVE against the actually deployed software version before acting; version-based matches include false positives.",
    "trackers.detected": "Review each third-party tracker against your privacy policy and consent banner; ensure non-essential trackers load only after consent.",
    "trackers.session_replay": "Confirm session-replay tools have explicit prior consent and mask sensitive fields (passwords, payment and personal data); disable recording where consent is absent.",
    "crawl.password_over_http": "Serve login forms only over HTTPS.",
    "cookies.missing_secure": "Set the Secure attribute on cookies issued over HTTPS.",
    "cookies.missing_httponly": "Set HttpOnly on cookies that scripts do not need to read.",
    "cookies.samesite_none_insecure": "Cookies with SameSite=None must also carry Secure.",
    "cookies.invalid_prefix": "Meet the __Host-/__Secure- prefix requirements (Secure; for __Host-: Path=/ and no Domain).",
    "resources.security_txt_missing": "Publish /.well-known/security.txt with Contact and Expires (RFC 9116).",
    "resources.security_txt_expired": "Update the security.txt Expires field.",
    "resources.security_txt_incomplete": "Add the required Contact and Expires fields to security.txt.",
    "subdomains.private_address": "Avoid publishing internal addresses in public DNS where possible.",
    # active checks
    "active.backend_read_access_open": "Enforce server-side authorization (row-level security, database/storage "
                                       "rules, or role permissions) so this resource cannot be read with a public, "
                                       "client-side credential; expose only what is intended to be public.",
    "active.supabase_rls_open": "Enable row-level security on the table and add policies restricting anonymous "
                                "access to only what is intended to be public.",
    "active.endpoint_open": "Require authentication/authorization on this endpoint, or confirm it is intended to "
                            "be public and safe to call anonymously.",
    "active.endpoint_reachable": "Confirm this endpoint is intended to be publicly reachable.",
    "active.no_rate_limit": "Add per-IP/per-account rate limiting and abuse controls to this endpoint.",
    "active.legacy_tls_accepted": "Disable TLS 1.0 and 1.1 at the server/load balancer; require TLS 1.2+.",
    "active.tls_versions": "Confirm only the intended TLS versions are accepted (prefer TLS 1.2 and 1.3 only).",
    "active.client_ip_header_bypass": "Derive the client IP from the trusted proxy connection only; strip inbound "
                                      "X-Forwarded-For/X-Real-IP at the edge and do not key access or rate limits on "
                                      "client-supplied headers.",
    "active.client_ip_header_trusted": "Confirm no access or rate-limit decision depends on client-supplied IP "
                                       "headers.",
    "active.access_control_open": "This endpoint is labeled access-controlled but answered an unauthenticated "
                                  "request; require authentication, or correct the label if it is meant to be public.",
    "js.source_map_public": "Do not deploy source maps publicly; upload them to your error tracker or restrict access.",
    "js.integrity_mismatch": "Regenerate the integrity hash from the file you actually serve, or pin the asset to a versioned URL that cannot change.",
    "js.exposed_secret": "Confirm each match; if a value is a real private credential, rotate it and remove it from client-side code. Keep private keys server-side.",
    "js.client_config": "Public client keys are expected; ensure backend authorization (database/storage rules, row-level security) does not depend on them staying secret.",
}

LIMITATIONS: dict[str, str] = {
    "dns.caa_absent": "Only the hostname and its parents up to the registrable domain were checked.",
    "dns.spf_missing": "Relevant only if the domain sends email.",
    "dnssec.": "Validation status depends on the configured recursive resolver.",
    "http.security_headers_missing": "Observed on the fetched page(s) only; other paths may differ.",
    "http.hsts_missing": "Observed on the fetched page only.",
    "cookies.missing_httponly": "Some cookies must be readable by client-side scripts by design.",
    "subdomains.": "Discovery is limited to names in public Certificate Transparency logs.",
    "whois.": "Registration data is as reported by the registry and may lag recent changes.",
    "active.": "Active check: result reflects the target's behavior at scan time and the single, bounded "
               "request(s) this check sent.",
    "js.source_map_public": "Only maps referenced by downloaded in-scope assets were checked.",
    "js.integrity_mismatch": "Verified against the bytes served to this scan; a CDN serving variant encodings per client could differ.",
    "html.third_party_script_no_sri": "Presence of the attribute is checked for every referenced script; hash verification is performed only for assets the scan downloaded (in-scope plus --asset-host).",
    "js.exposed_secret": "Heuristic pattern match on downloaded in-scope bundles; raw values are not stored, so each must be confirmed manually. False positives are possible.",
    "js.client_config": "Public client configuration is not a vulnerability by itself.",
    "seo.": "Observed on the fetched landing page only; other pages and server-rendered variants may differ.",
    "og.": "Observed on the fetched landing page only; social previews also depend on each platform's own crawler.",
    "twitter.": "Observed on the fetched landing page only; the preview also depends on X/Twitter's own crawler.",
    "trackers.": "Classified from referenced third-party domains against a versioned signature set; coverage is not exhaustive and a tracker loaded only after consent or user action may not appear.",
    "waf.": "Passive identification from headers, cookies and the server banner only; absence of a signature does not prove there is no WAF, and a CDN/proxy signal does not prove WAF rules are enabled.",
    "hosting.": "An estimate from registry allocation and an optional offline geo database; it reflects where the address space is registered, not the physical server, and is not meaningful behind a CDN/anycast network.",
    "intel.": "Retrieved from a third-party provider; it reflects that provider's data about the IP/domain — which may be historical or stale — not a live observation by SiteRecon, and discloses the target to that provider.",
}

_CATEGORY_MODULES: dict[str, tuple[str, ...]] = {
    "dns": ("dns",), "email": ("dns",), "dnssec": ("dnssec", "whois"), "http": ("http", "crawler"),
    "tls": ("tls",), "registration": ("whois",), "html": ("html", "crawler"), "crawl": ("crawler",),
    "cookies": ("cookies",), "resources": ("resources",), "subdomains": ("subdomains",),
    "javascript": ("javascript",), "seo": ("html",), "social": ("html",),
    "trackers": ("third_party", "javascript", "html"), "waf": ("http", "cookies"),
    "hosting": ("network",), "intel": ("wayback", "shodan_internetdb"),
}


def lookup_text(table: dict[str, str], code: str) -> str | None:
    '''
    Find the entry for an exact code, else the longest matching prefix entry.
    Parameters:
        table (dict[str, str]): Code or prefix to text.
        code (str): Finding code.
    Returns:
        str | None: Matching text, or None.
    '''
    if code in table:
        return table[code]
    prefixes = [k for k in table if k.endswith((".", "_")) and code.startswith(k)]
    return table[max(prefixes, key=len)] if prefixes else None


_lookup = lookup_text


class FindingCollector:
    '''
    Accumulates findings, deduplicated by a stable '<code>:<subject>' identifier.
    '''

    def __init__(self, timestamp: datetime) -> None:
        '''
        Create an empty collector.
        Parameters:
            timestamp (datetime): Timestamp stamped on every finding.
        '''
        self.timestamp = timestamp
        self._items: dict[str, Finding] = {}

    def add(self, code: str, subject: str, *, category: str, title: str, description: str, severity: Severity, confidence: Confidence, evidence: list[str], source: str, ) -> None:
        '''
        Add a finding unless one with the same code and subject already exists.
        Recommendation and limitations are attached from the central tables by code.
        Parameters:
            code (str): Stable finding code, e.g. 'tls.expired'.
            subject (str): What the finding is about (host, URL, ...).
            category (str): Finding category (dns, http, tls, ...).
            title (str): Short title.
            description (str): Explanation of the observation.
            severity (Severity): Evidence-based severity.
            confidence (Confidence): Confidence in the observation.
            evidence (list[str]): Supporting observations.
            source (str): Where the evidence came from.
        '''
        finding_id: str = f"{code}:{subject}"
        if finding_id in self._items:
            return
        self._items[finding_id] = Finding(
            id=finding_id, category=category, title=title, description=description,
            severity=severity, confidence=confidence, evidence=evidence, source=source,
            subject=subject, timestamp=self.timestamp,
            recommendation=_lookup(RECOMMENDATIONS, code), limitations=_lookup(LIMITATIONS, code),
        )

    def link(self, observations: list[Observation], limit: int = 10) -> None:
        '''
        Attach evidence references: observations from the finding's modules whose target matches its subject.
        Parameters:
            observations (list[Observation]): All observations of the scan.
            limit (int): Maximum references per finding.
        '''
        for finding in self._items.values():
            modules = _CATEGORY_MODULES.get(finding.category, ())
            subject = finding.subject.split(":443")[0]
            refs = [o.id for o in observations
                    if o.module in modules and (o.target == finding.subject or o.target == subject
                                                or subject in o.target or o.target in subject)]
            finding.evidence_refs = refs[:limit]

    def sorted(self) -> list[Finding]: return sorted(self._items.values(), key=lambda f: (-f.severity.rank, f.category, f.id))
