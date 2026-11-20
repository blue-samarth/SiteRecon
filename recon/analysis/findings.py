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
    # --- SEO audit (one entry per check in recon.analysis.seo_checks, plus the two coverage notes)
    "seo.pages_blocked_from_indexing": "Confirm each blocked page is meant to be hidden; remove the "
                                       "noindex directive, X-Robots-Tag header or robots.txt rule from any "
                                       "page that should be findable.",
    "seo.robots_blocked_pages": "Allow the URLs you publish to be crawled; use noindex on the page itself "
                                "(which requires crawling to be read) rather than a robots.txt Disallow "
                                "when the goal is to keep a page out of the index.",
    "seo.canonical_missing": "Add a self-referencing rel=canonical link to each indexable page so "
                             "parameter and slash variants consolidate onto one URL.",
    "seo.canonical_not_self": "Point each page's canonical at itself unless it is deliberately a duplicate "
                              "of another URL; check the template is not emitting one hardcoded canonical.",
    "seo.canonical_offsite_pages": "Confirm the off-site canonical is intentional (syndicated content); "
                                   "otherwise correct it to the page's own URL.",
    "seo.sitemap_noindex_conflict": "Decide per URL: keep it in the sitemap and drop the noindex, or keep "
                                    "the noindex and remove it from the sitemap.",
    "seo.host_not_canonicalized": "Pick one hostname as canonical and 301-redirect the other to it, then "
                                  "make sure canonical links and the sitemap use the chosen host.",
    "seo.no_https_canonicalization": "Redirect all plain-HTTP requests to HTTPS with a 301 and serve HSTS.",
    "seo.titles_missing": "Give every indexable page a unique, descriptive <title>.",
    "seo.title_length": "Rewrite the flagged titles to describe the page within roughly 20–60 characters.",
    "seo.duplicate_titles": "Make each page's title describe that page; fill the page name into the "
                            "template instead of repeating a site-wide title.",
    "seo.descriptions_missing": "Add a concise meta description summarizing each page.",
    "seo.description_length": "Rewrite the flagged descriptions to roughly 70–160 characters.",
    "seo.duplicate_descriptions": "Write a per-page description, or remove the duplicate one and let the "
                                  "search engine build a snippet rather than repeating the same text.",
    "seo.viewport_missing": "Add <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> "
                            "to every page template.",
    "seo.lang_missing": "Set the lang attribute on <html> to the page's language.",
    "seo.hreflang_invalid": "Correct the hreflang values to valid language[-script][-region] tags, make "
                            "each alternate set self-referencing, and add an x-default entry.",
    "seo.social_metadata_missing": "Add og:title, og:type, og:image and og:url to these page templates so "
                                   "shared links render a controlled preview.",
    "seo.h1_missing": "Add one H1 per page stating what the page is about.",
    "seo.h1_multiple": "Keep one H1 per document and demote the others to H2/H3.",
    "seo.heading_hierarchy": "Use heading levels in order (no skipping) so the document outline matches "
                             "the visual structure.",
    "seo.duplicate_h1": "Give each page its own H1; check for an unfilled template heading.",
    "seo.thin_content": "Confirm each page is meant to be short; expand the ones that should rank, or mark "
                        "genuinely thin utility pages noindex so they do not compete.",
    "seo.images_missing_alt": "Add descriptive alt text to content images and an explicit alt=\"\" to "
                              "decorative ones.",
    "seo.structured_data_missing": "Add JSON-LD for the page types you have (Organization, Article, "
                                   "Product, BreadcrumbList) to become eligible for rich results.",
    "seo.structured_data_invalid": "Fix the malformed JSON-LD; an unparseable block is discarded whole.",
    "seo.robots_txt_missing": "Publish a robots.txt, even a permissive one, and declare your sitemap in it.",
    "seo.sitemap_missing": "Publish an XML sitemap of your indexable URLs and reference it from robots.txt.",
    "seo.sitemap_not_declared": "Add a 'Sitemap: <url>' line to robots.txt.",
    "seo.sitemap_coverage_gap": "Add the missing indexable URLs to the sitemap, or confirm they are "
                                "intentionally excluded.",
    "seo.sitemap_errors": "Remove dead URLs from the sitemap and fix the generation step that emitted "
                          "them; a sitemap should list only URLs that return 200.",
    "seo.orphan_pages": "Link to these pages from relevant navigation or related content so they can be "
                        "reached and receive internal link equity.",
    "seo.broken_internal_links": "Fix or remove the links pointing at these URLs, and restore or redirect "
                                 "the targets that should exist.",
    "seo.internal_redirects": "Update internal links to point at the final URL so each click costs no "
                              "extra round trip.",
    "seo.deep_pages": "Shorten the path to these pages with hub pages or navigation links if they matter; "
                      "depth is fine for genuinely peripheral content.",
    "seo.no_compression": "Enable gzip or brotli for HTML at the server or CDN.",
    "seo.slow_pages": "Profile the slow responses server-side (queries, template rendering, upstream "
                      "calls) and add caching where the content allows it.",
    "seo.heavy_html": "Reduce the markup: remove inlined data payloads, paginate long listings and move "
                      "repeated content out of the document.",
    "seo.legacy_http_version": "Enable HTTP/2 (and HTTP/3 where available) at the server or CDN.",
    "seo.coverage_single_page": "Re-run with --crawl (and --max-pages) to audit the site rather than one "
                                "page; the site-wide checks need more than one page to compare.",
    "seo.coverage_truncated": "Raise --max-pages and --depth until the crawl stops hitting its limit "
                              "before treating any site-wide count as complete.",
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
    "active.open_ports": "Confirm each open port is intended to be internet-facing; firewall or close the ones that are not.",
    "active.sensitive_port_exposed": "Place databases, remote-administration and file-sharing services behind a firewall/VPN or an IP allow-list instead of exposing them to the internet; verify authentication and patching.",
    "active.network_path": "Informational network-path observation; no action required.",
    "regression.security_header_removed": "Restore the removed security header unless its removal was intended and reviewed.",
    "regression.cookie_weakened": "Restore the Secure/HttpOnly attributes on this cookie; dropping them weakens its protection.",
    "regression.tls_downgrade": "Investigate why a lower TLS version is being negotiated and restore the stronger configuration.",
    "regression.dnssec_disabled": "If DNSSEC was disabled unintentionally, re-sign the zone and publish the DS record.",
    "regression.caa_removed": "Re-publish a CAA policy restricting which certificate authorities may issue for the domain, unless the removal was intentional.",
    "regression.new_subdomain": "Confirm the new hostname is intended and inventoried; unexpected names can indicate shadow IT or takeover setups.",
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
    "render.third_party_egress": "Review each third-party host and confirm it is intended and covered by your privacy / data-processing terms; remove any that are not.",
    "render.mixed_content": "Serve every subresource over HTTPS; replace or remove the plaintext http:// requests.",
    "subdomain.takeover": "Reclaim or re-provision the resource at the CNAME target, or remove the dangling DNS record; until then anyone can claim the subdomain.",
    "subdomain.dangling_cname": "Keep the backing resource provisioned, or remove the record if the delegated service is no longer used.",
    "vuln.known_component": "Upgrade the component to a release unaffected by the listed advisories; if upgrading is not possible, apply the vendor mitigation or remove the component.",
    "email.mta_sts_missing": "Publish an MTA-STS policy in enforce mode and the _mta-sts TXT record so sending servers require TLS for delivery.",
    "email.mta_sts_policy_without_record": "Publish the _mta-sts TXT record (v=STSv1; id=<version>) so "
                                           "senders discover the policy you are already serving.",
    "email.mta_sts_policy_unreachable": "Serve the policy at https://mta-sts.<domain>/.well-known/"
                                        "mta-sts.txt over HTTPS with a valid certificate and a text/plain "
                                        "content type, or remove the _mta-sts record until it is available.",
    "email.mta_sts_policy_invalid": "Correct the policy to RFC 8461: 'version: STSv1', a mode of enforce, "
                                    "testing or none, a max_age between 1 and 31557600, and one 'mx:' line "
                                    "per accepted mail host.",
    "email.mta_sts_testing_mode": "Review the TLS-RPT reports, then move the policy to mode: enforce; "
                                  "testing mode reports failures but still permits plaintext delivery.",
    "email.mta_sts_withdrawn": "If MTA-STS is still intended, set mode back to enforce; if the domain no "
                               "longer receives mail, remove the policy and the _mta-sts record together.",
    "email.mta_sts_mx_mismatch": "Add an 'mx:' line for every MX host that accepts mail (a '*.' wildcard "
                                 "covers one label), and keep the policy updated whenever MX records "
                                 "change — under enforce, an uncovered MX loses mail.",
    "email.mta_sts_short_max_age": "Raise max_age to at least 1209600 (two weeks) once the policy is "
                                   "stable; keep it short only while rolling out.",
    "email.tls_rpt_missing": "Publish a TLS-RPT (_smtp._tls) record so you receive reports of mail TLS failures and downgrade attempts.",
    "email.dane_missing": "Publish TLSA records for the MX hosts (with DNSSEC) to protect SMTP delivery TLS, as an alternative or complement to MTA-STS.",
    "dns.caa_ct_mismatch": "Confirm the certificate is legitimate; if it predates the current CAA policy that is expected, otherwise investigate possible mis-issuance.",
    "tls.no_forward_secrecy": "Disable non-forward-secret cipher suites; offer only ECDHE suites or TLS 1.3.",
    "tls.incomplete_chain": "Configure the server to send the full certificate chain (leaf plus intermediates), not just the leaf.",
    "tls.no_sct": "Use a publicly-trusted CA that embeds SCTs so the certificate is Certificate-Transparency logged.",
    "http.hsts_not_preload_ready": "Set Strict-Transport-Security with max-age≥31536000, includeSubDomains and preload, then submit the domain to the HSTS preload list.",
    "http.hsts_preloaded_header_ineligible": "Restore a header that matches the listing "
                                             "(max-age≥31536000, includeSubDomains, preload). The domain "
                                             "stays protected either way, but a header that no longer "
                                             "qualifies cannot be resubmitted and leaves anything not "
                                             "using the browser list unprotected.",
    "http.hsts_preload_eligible_not_listed": "Submit the domain at hstspreload.org if preloading is "
                                             "intended; the preload directive by itself does nothing until "
                                             "the submission is accepted. If it was submitted recently, "
                                             "refresh the bundled list (scripts/refresh_hsts_preload.py) "
                                             "and re-check.",
    # passive discovery (subdomain sources and permutation)
    "subdomains.discovery_incomplete": "Re-run the affected source(s) before treating the hostname list as "
                                       "complete; a failed or skipped source means coverage is narrower than "
                                       "it looks, not that no further names exist.",
    "subdomains.unlisted_host": "Confirm each generated name that resolves is an inventoried, intended host; "
                                "a resolving name absent from every public dataset is often forgotten "
                                "infrastructure (staging, admin or legacy) that nobody is patching.",
    # historical URLs
    "historical.archived_urls": "Review the archived endpoint and parameter surface for routes that should no "
                                "longer be reachable, and confirm anything still live is intended to be.",
    "historical.sensitive_path": "Verify whether each archived sensitive path is still reachable; if a "
                                 "backup, config or secret file was ever public, treat it as exposed and "
                                 "rotate the affected credentials.",
    "historical.credential_in_url": "Stop passing secrets in query strings (use headers or a POST body), and "
                                    "rotate any credential that was ever carried in a URL — those values sit "
                                    "in archives, proxy logs, browser history and Referer headers.",
    "historical.parameter_surface": "Treat archived redirect- and file-valued parameters as an injection "
                                    "surface: validate redirect targets against an allow-list and never map a "
                                    "request parameter onto a filesystem path.",
    "historical.legacy_technology": "Confirm whether the legacy stack is still deployed; if it is not, make "
                                    "sure its old routes return 404/410 rather than an unmaintained handler, "
                                    "and if it is, patch it like any other production component.",
    "historical.discovery_incomplete": "Re-run the affected archive source(s) before treating the historical "
                                       "URL surface as complete.",
    # managed cloud inventory
    "cloud.inventory": "Confirm every listed cloud resource is intended, owned by your organization and "
                       "covered by your monitoring and access reviews.",
    "cloud.object_storage_referenced": "Verify each bucket's access policy: block public listing, serve only "
                                       "the objects meant to be public (ideally through a CDN with signed "
                                       "URLs), and confirm no credential grants wider access than intended.",
    "cloud.serverless_endpoint": "Require authentication and authorization on every function endpoint that "
                                 "is not deliberately public, add per-caller rate limits, and confirm the "
                                 "function cannot be driven into a state-changing action anonymously.",
    "cloud.backend_endpoint": "Enforce authorization server-side (row-level security, database/storage rules, "
                              "or role permissions) rather than relying on the public client key staying "
                              "secret, and expose only the tables/collections intended to be readable.",
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
    # The four landing-page checks predate the SEO module and still look at exactly one page.
    "seo.title_missing": "Observed on the fetched landing page only; other pages may differ.",
    "seo.meta_description_missing": "Observed on the fetched landing page only; other pages may differ.",
    "seo.noindex": "Observed on the fetched landing page only; other pages may differ.",
    "seo.canonical_offsite": "Observed on the fetched landing page only; other pages may differ.",
    "seo.": "Derived from the pages this scan already fetched — one page without --crawl — and from the "
            "markup as served, so content or metadata added by JavaScript is included only when --render "
            "ran. Indexability is what the site declares (robots meta, X-Robots-Tag, robots.txt, "
            "canonical), never what a search engine has actually indexed, and no part of this audit "
            "measures rankings, traffic or real-user performance.",
    "seo.thin_content": "Words are counted in the served HTML; copy rendered by JavaScript is not counted "
                        "unless --render ran, so a client-rendered page can look thin while reading fine.",
    "seo.orphan_pages": "Inbound links are counted only among the analyzed pages. A page linked solely "
                        "from a page this crawl did not fetch is indistinguishable from a real orphan.",
    "seo.sitemap_coverage_gap": "Compares the sitemap against the crawled pages only, so it reports pages "
                                "missing from the sitemap, not sitemap URLs missing from the site.",
    "seo.broken_internal_links": "Covers only the in-scope URLs this crawl followed; external links and "
                                 "unfetched paths were not checked.",
    "seo.internal_redirects": "Covers only the in-scope URLs this crawl followed.",
    "seo.slow_pages": "A single server-response timing per page from this scan — not a user-perceived "
                      "metric, not Core Web Vitals, and sensitive to cache state and network conditions.",
    "seo.heavy_html": "Document markup only; images, scripts and stylesheets are not included in the size.",
    "seo.no_compression": "Observed on the landing-page response; another path, origin or edge node could "
                          "answer differently.",
    "seo.legacy_http_version": "The version negotiated for the landing-page request by this client; a "
                               "different client or path may negotiate another version.",
    "seo.coverage_single_page": "States the audit's own coverage; it is not a finding about the site.",
    "seo.coverage_truncated": "States the audit's own coverage; it is not a finding about the site.",
    "og.": "Observed on the fetched landing page only; social previews also depend on each platform's own crawler.",
    "twitter.": "Observed on the fetched landing page only; the preview also depends on X/Twitter's own crawler.",
    "trackers.": "Classified from referenced third-party domains against a versioned signature set; coverage is not exhaustive and a tracker loaded only after consent or user action may not appear.",
    "waf.": "Passive identification from headers, cookies and the server banner only; absence of a signature does not prove there is no WAF, and a CDN/proxy signal does not prove WAF rules are enabled.",
    "hosting.": "An estimate from registry allocation and an optional offline geo database; it reflects where the address space is registered, not the physical server, and is not meaningful behind a CDN/anycast network.",
    "intel.": "Retrieved from a third-party provider; it reflects that provider's data about the IP/domain — which may be historical or stale — not a live observation by SiteRecon, and discloses the target to that provider.",
    "regression.": "A change observed between this scan and the previous one; it reflects the two compared scans, and a change is reported only when the relevant module ran successfully in both.",
    "render.": "Observed while rendering the pages that were loaded; other pages or user-driven flows may contact different hosts or trigger different requests.",
    "subdomain.takeover": "Heuristic from the CNAME target plus an unclaimed-resource fingerprint or a non-resolving target; confirm manually, as some providers require account-level verification before a resource can actually be claimed.",
    "subdomain.dangling_cname": "The CNAME points at a takeover-prone provider but the resource appears claimed right now; status can change if the backing resource is later released.",
    "vuln.known_component": "Matched by package name and version against OSV; a match means a published advisory affects that version, not that the vulnerable code path is used or reachable. Version detection is best-effort.",
    "email.mta_sts_missing": "Detects the absence of the _mta-sts DNS record. The policy file is fetched "
                             "separately when the domain has MX records, so mode and MX coverage are "
                             "reported under their own findings.",
    "email.mta_sts_": "The policy is fetched from mta-sts.<domain> only when the domain publishes MX "
                      "records, because no sender consults a policy otherwise. Mode and MX coverage are "
                      "read from the policy as served at scan time; a sender holding a cached copy may "
                      "still be acting on a previous version for up to its max_age.",
    "dns.caa_ct_mismatch": "Issuer matching is heuristic and CT data can include historical certificates issued before the current CAA policy; treat as a lead, not proof.",
    "tls.no_sct": "Only SCTs embedded in the certificate are checked; SCTs delivered via the TLS handshake or OCSP stapling are not inspected.",
    "http.hsts_not_preload_ready": "Eligibility is read from the header's own directives. Membership in "
                                   "the browser preload list is reported alongside it when a bundled "
                                   "snapshot is available; without one, nothing is claimed about membership.",
    "http.hsts_preloaded_header_ineligible": "Membership is answered from a bundled point-in-time copy of the Chromium preload list, not a live query, so a submission accepted after the snapshot was taken reads as absent. The snapshot's date is recorded in the evidence; refresh it with scripts/refresh_hsts_preload.py.",
    "http.hsts_preload_eligible_not_listed": "Membership is answered from a bundled point-in-time copy of the Chromium preload list, not a live query, so a submission accepted after the snapshot was taken reads as absent. The snapshot's date is recorded in the evidence; refresh it with scripts/refresh_hsts_preload.py.",
    "subdomains.discovery_incomplete": "Lists which sources failed or were skipped; it cannot say how many "
                                       "names were missed.",
    "subdomains.unlisted_host": "The name was generated locally from observed labels and kept only because it "
                                "resolves in DNS. Resolution proves the record exists, not that a service "
                                "runs there; nothing was fetched from these hosts.",
    "historical.": "Retrieved from third-party web archives and URL indexes. It reflects what those archives "
                   "crawled in the past — not a live observation by SiteRecon — so a path here may be gone, "
                   "and absence here never proves a path never existed. Query values are redacted.",
    "historical.legacy_technology": "Inferred from archived URL paths and file extensions, which describe the "
                                    "stack that served those paths at the time. It is not a statement about "
                                    "the current stack; the technology module covers that.",
    "historical.credential_in_url": "Based on the parameter NAME only — the values are redacted and never "
                                    "stored, so whether a real secret was carried must be confirmed from your "
                                    "own logs.",
    "cloud.": "Derived from references in collected evidence (pages, bundles, CSP, CNAMEs). SiteRecon never "
              "requests these resources, so it cannot establish whether a bucket is listable, an endpoint "
              "answers, or the resource even still exists — only that the application points at it. "
              "Confirming exposure requires an authorized active check.",
}

_CATEGORY_MODULES: dict[str, tuple[str, ...]] = {
    "dns": ("dns",), "email": ("dns",), "dnssec": ("dnssec", "whois"), "http": ("http", "crawler"),
    "tls": ("tls",), "registration": ("whois",), "html": ("html", "crawler"), "crawl": ("crawler",),
    "cookies": ("cookies",), "resources": ("resources",), "subdomains": ("subdomains",),
    "javascript": ("javascript",), "seo": ("seo", "html", "crawler", "resources"),
    "social": ("html", "seo"),
    "trackers": ("third_party", "javascript", "html"), "waf": ("http", "cookies"),
    "hosting": ("network",), "intel": ("wayback", "shodan_internetdb"), "render": ("render",),
    "vuln": ("vulnscan",), "historical": ("historical",), "cloud": ("third_party", "javascript"),
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
