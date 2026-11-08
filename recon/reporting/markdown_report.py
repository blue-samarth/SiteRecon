'''
Human-readable Markdown report.
'''

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any, ClassVar

from recon.models import ModuleResult, ModuleStatus, Severity
from recon.reporting.base import ReportWriter


class MarkdownReportWriter(ReportWriter):
    '''
    Renders the report as numbered Markdown sections and writes report.md.
    '''

    SEVERITY_ICON: ClassVar[dict[Severity, str]] = {
        Severity.CRITICAL: "🟥", Severity.HIGH: "🟧", Severity.MEDIUM: "🟨",
        Severity.LOW: "🟦", Severity.INFORMATIONAL: "⬜",
    }

    def write(self, directory: Path) -> list[Path]:
        '''
        Render the report as Markdown and write report.md.
        Parameters:
            directory (Path): Directory to write into; created if missing.
        Returns:
            list[Path]: Path of the file written.
        Raises:
            OSError: If the directory cannot be written.
        '''
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "report.md"
        path.write_text(self.render(), encoding="utf-8")
        return [path]

    def render(self) -> str:
        '''
        Render the full report as Markdown with numbered sections.
        Returns:
            str: Markdown text.
        '''
        sections = [
            ("Executive Summary", self._summary()),
            ("Target Information", self._target()),
            ("DNS Reconnaissance", self._dns()),
            ("DNSSEC", self._dnssec()),
            ("Network and IP Intelligence", self._network()),
            ("HTTP and HTTPS Analysis", self._http()),
            ("TLS Certificate Analysis", self._tls()),
            ("Domain Registration", self._whois()),
            ("Public Resources", self._resources()),
            ("Technology Fingerprinting", self._technology()),
            ("HTML Analysis", self._html()),
            ("Website Crawl", self._crawl()),
            ("JavaScript and CSS Assets", self._assets()),
            ("Cookies", self._cookies()),
            ("Subdomain Discovery", self._subdomains()),
            ("Third-Party Integrations", self._third_party()),
            ("Infrastructure Providers", self._infrastructure()),
            ("Security Observations", self._findings()),
            ("Changes Since Previous Scan", self._changes()),
            ("Collection Errors and Limitations", self._errors()),
            ("Sources and References", self._sources()),
        ]
        out = [f"# Reconnaissance Report: `{self.report.target.hostname}`", ""]
        for i, (title, body) in enumerate(sections, 1):
            out += [f"## {i}. {title}", "", body.rstrip(), ""]
        return "\n".join(out)

    def _summary(self) -> str:
        '''
        Render the executive summary.
        Returns:
            str: Section body.
        '''
        counts = self.report.analysis.severity_counts
        lines = [
            f"Scan of **{self.report.target.hostname}** completed in {self.report.duration_ms / 1000:.1f}s "
            f"({self.report.started_at:%Y-%m-%d %H:%M:%S} UTC).",
            "",
            self._table(["Module", "Status", "Duration (ms)", "Errors"],
                   [(name, res.status.value, round(res.duration_ms), len(res.errors))
                    for name, res in self.report.module_results().items()]),
            "**Findings by severity:** " + ", ".join(
                f"{s.value} {counts.get(s.value, 0)}" for s in reversed(list(Severity))),
        ]
        providers = sorted({o.provider for o in self.report.analysis.infrastructure})
        if providers:
            lines += ["", "**Identified providers:** " + ", ".join(providers)]
        return "\n".join(lines) + "\n"

    def _target(self) -> str:
        '''
        Render target information.
        Returns:
            str: Section body.
        '''
        return self._table(["Field", "Value"], [
            ("Scan ID", self.report.scan_id),
            ("Input", self.report.target.input),
            ("Normalized hostname", self.report.target.hostname),
            ("Authorized scope", self.report.target.scope),
            ("Tool", f"{self.report.tool.name} {self.report.tool.version}"),
            ("Started", self.report.started_at.isoformat()),
            ("Finished", self.report.finished_at.isoformat()),
        ])

    def _dns(self) -> str:
        '''
        Render DNS records and email security.
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.dns):
            return msg
        d = self.report.dns.data
        rows = []
        for key, q in d.queries.items():
            ttl = q.records[0].ttl if q.records else None
            rows.append((key, q.name, q.status.value, "<br>".join(self._cell(v) for v in q.values) or None,
                         ttl, q.response_time_ms))
        out = [self._table(["Record", "Name", "Status", "Values", "TTL", "Time (ms)"], rows)]

        e = d.email
        out += ["### Email security", ""]
        spf_rows = [(rec.raw, rec.all_qualifier, rec.includes) for rec in e.spf.records]
        out += ["**SPF**", "", self._table(["Record", "'all' qualifier", "Includes"], spf_rows)
                if spf_rows else f"_No SPF record (TXT lookup: {e.spf.lookup_status})._\n"]
        if e.spf.lookup_count is not None:
            out += [f"DNS lookups: **{e.spf.lookup_count}**/10, void lookups: **{e.spf.void_lookups}**/2"
                    + (" — **limit exceeded**" if e.spf.lookup_limit_exceeded else ""), ""]
            if e.spf.lookup_tree:
                out += ["```text", *e.spf.lookup_tree, "```", ""]
        for rec in e.spf.records:
            if rec.parse_errors:
                out += [f"Parse errors: {self._cell(rec.parse_errors)}", ""]
        if e.spf.evaluation_errors:
            out += [f"Evaluation notes: {self._cell(e.spf.evaluation_errors)}", ""]
        if e.dmarc.raw_records:
            out += ["**DMARC**", "", self._table(["Field", "Value"], [
                ("Record(s)", e.dmarc.raw_records), ("Policy (p)", e.dmarc.policy),
                ("Subdomain policy (sp)", e.dmarc.subdomain_policy), ("pct", e.dmarc.pct),
                ("DKIM alignment (adkim)", e.dmarc.adkim or "r (default)"),
                ("SPF alignment (aspf)", e.dmarc.aspf or "r (default)"),
                ("Aggregate reports (rua)", e.dmarc.rua), ("Forensic reports (ruf)", e.dmarc.ruf),
            ])]
        else:
            out += ["**DMARC**", "", f"_No DMARC record at `{e.dmarc.name}` ({e.dmarc.lookup_status})._\n"]
        out += ["**DKIM**", ""]
        if e.dkim_found:
            out.append(self._table(["Selector", "Name", "Key", "Revoked", "Tags"],
                                   [(k.selector, k.name, f"{k.key_type} {k.key_bits or '?'} bits", k.revoked,
                                     [f"{t}={v}" for t, v in k.tags.items() if t != "v"]) for k in e.dkim_found]))
        else:
            out.append("_No DKIM record found for the selectors checked._\n")
        out.append(f"> {len(e.dkim_selectors_checked)} selectors checked: {', '.join(e.dkim_selectors_checked)}. "
                   f"{e.dkim_note}\n")
        caa = d.caa
        out += ["### CAA policy", ""]
        if caa.effective_name:
            out.append(f"In effect from `{caa.effective_name}`" + (" (inherited from a parent name)" if caa.inherited else "")
                       + ": " + ", ".join(f"`{self._cell(r)}`" for r in caa.records) + "\n")
        else:
            out.append("_No CAA policy found_" + ("" if caa.complete else " (lookup incomplete)") + ".\n")
        out.append("Names checked: " + ", ".join(f"`{n}` {st}" for n, st in caa.checked.items()) + "\n")
        return "\n".join(out)

    def _network(self) -> str:
        '''
        Render per-IP network intelligence.
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.network):
            return msg
        rows = []
        for ip in self.report.network.data.ips:
            asn = f"AS{ip.asn.asn} {ip.asn.name or ''}".strip() if ip.asn else None
            rdap = ip.rdap
            rows.append((ip.ip, f"IPv{ip.version}", ip.ptr or ip.ptr_status, asn,
                         ip.asn.prefix if ip.asn else None,
                         rdap.name if rdap else None, rdap.organizations if rdap else None,
                         (rdap.cidrs or rdap.start_address) if rdap else None))
        note = ("> ASN and RDAP data describe who the address space is allocated to (often a CDN or "
                "cloud edge), not necessarily where the origin server runs.\n")
        return self._table(["IP", "Ver", "PTR", "ASN", "BGP prefix", "RDAP network", "Organization", "Range"],
                      rows) + "\n" + note

    def _http(self) -> str:
        '''
        Render HTTP probes, redirect chains and security headers.
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.http):
            return msg
        out = []
        for p in self.report.http.data.probes:
            out += [f"### `{p.requested_url}`", ""]
            if not p.success:
                out += [f"**Failed:** `{p.error_type}` — {self._cell(p.error)}", ""]
                continue
            chain = " → ".join(f"{h.status_code} {h.url}" for h in p.hops)
            if p.redirect_stopped_reason:
                chain += f" → _(not followed: {p.redirect_stopped_reason})_ {p.final_url}"
            out += [self._table(["Field", "Value"], [
                ("Redirect chain", chain),
                ("Final URL", p.final_url),
                ("Status", p.status_code),
                ("Protocol", p.http_version),
                ("Server", p.server),
                ("Content-Type", p.content_type),
                ("Content-Length", p.content_length if p.content_length is not None else p.body_bytes),
                ("Response time (ms)", p.response_time_ms),
                ("Redirects to HTTPS", p.redirects_to_https),
            ])]
            if p.security_headers:
                out += ["**Security headers**", "",
                        self._table(["Header", "Present", "Value"],
                               [(h.name, "✅" if h.present else "❌", (h.value or "")[:160])
                                for h in p.security_headers.values()])]
        return "\n".join(out)

    def _tls(self) -> str:
        '''
        Render TLS certificate details.
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.tls):
            return msg
        out = []
        for p in self.report.tls.data.probes:
            out += [f"### `{p.hostname}:{p.port}`", ""]
            if not p.success:
                out += [f"**Failed:** `{p.error_type}` — {self._cell(p.error)}", ""]
                continue
            c = p.certificate
            key = f"{c.public_key_algorithm} {c.public_key_size or ''} {c.public_key_curve or ''}".strip()
            out.append(self._table(["Field", "Value"], [
                ("Connected IP", p.ip), ("TLS version", p.tls_version), ("Cipher", p.cipher),
                ("Chain verified", p.verified), ("Verification error", p.verification_error),
                ("Hostname matches SAN", p.hostname_match), ("Subject", c.subject),
                ("Issuer", c.issuer), ("Serial", c.serial_number),
                ("Valid from", c.not_before.isoformat()), ("Valid until", c.not_after.isoformat()),
                ("Days remaining", p.days_remaining), ("Currently valid", p.currently_valid),
                ("Signature", c.signature_algorithm), ("Public key", key),
                ("SANs", c.san_dns[:25] + ([f"(+{len(c.san_dns) - 25} more)"] if len(c.san_dns) > 25 else [])),
                ("SHA-256 fingerprint", f"`{c.fingerprint_sha256}`"),
            ]))
        return "\n".join(out)

    def _whois(self) -> str:
        '''
        Render domain registration data.
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.whois):
            return msg
        d = self.report.whois.data
        return self._table(["Field", "Value"], [
            ("Domain", d.domain), ("Source", f"{d.source} {d.source_url or ''}".strip()),
            ("Registrar", f"{d.registrar or '—'}" + (f" (IANA {d.registrar_iana_id})" if d.registrar_iana_id else "")),
            ("Created", d.created.isoformat() if d.created else None),
            ("Updated", d.updated.isoformat() if d.updated else None),
            ("Expires", d.expires.isoformat() if d.expires else None),
            ("Days until expiry", d.days_until_expiry), ("Status", d.status),
            ("Nameservers", d.nameservers), ("DNSSEC", d.dnssec),
        ]) + f"\n> {d.note}\n"

    def _technology(self) -> str:
        '''
        Render technology detections with evidence.
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.technology):
            return msg
        d = self.report.technology.data
        rows = [(t.name, t.category, t.version, t.status.value, t.confidence.value,
                 "<br>".join(self._cell(f"{e.source}: {e.detail}") for e in t.evidence[:4]))
                for t in d.technologies]
        return (self._table(["Technology", "Category", "Version", "Status", "Confidence", "Evidence"], rows)
                + f"\n_{d.signatures_checked} signatures checked against: {', '.join(d.inputs) or 'no inputs'}. "
                  "'Probable' detections rest on a single weaker signal._\n")

    def _html(self) -> str:
        '''
        Render HTML metadata, external domains and commented URLs.
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.html):
            return msg
        d = self.report.html.data
        kinds: dict[str, int] = {}
        for res in d.resources:
            kinds[res.kind] = kinds.get(res.kind, 0) + 1
        out = [self._table(["Field", "Value"], [
            ("Document", d.source_url), ("Title", d.title), ("Description", d.meta_description),
            ("Canonical", d.canonical), ("Language", d.lang), ("Robots", d.robots),
            ("Generator", d.generator), ("Favicons", d.favicons[:5]),
            ("Open Graph", [f"{k}={v}" for k, v in list(d.open_graph.items())[:8]]),
            ("Twitter", [f"{k}={v}" for k, v in list(d.twitter.items())[:6]]),
            ("Verification tokens", list(d.verification_tokens)),
            ("Resources", [f"{k}: {v}" for k, v in sorted(kinds.items())]),
            ("Inline scripts", d.inline_script_count), ("JSON-LD blocks", len(d.json_ld)),
            ("HTML comments", d.comment_count), ("Warnings", d.parse_warnings),
        ])]
        out += ["**External domains referenced**", "",
                ", ".join(f"`{h}`" for h in d.external_domains) or "_None._", ""]
        ext = [x for x in d.resources if not x.same_site and x.kind in ("script", "stylesheet", "preconnect", "iframe")]
        if ext:
            out += ["**External scripts, styles, frames and preconnects**", "",
                    self._table(["Kind", "URL", "Attributes"],
                           [(x.kind, x.url[:140], [f"{k}={v}" for k, v in x.attributes.items()]) for x in ext[:40]])]
        if d.commented_urls:
            out += ["**URLs inside HTML comments** (inactive markup, listed separately)", "",
                    "\n".join(f"- `{u[:140]}`" for u in d.commented_urls[:20]), ""]
        return "\n".join(out)

    def _subdomains(self) -> str:
        '''
        Render Certificate Transparency discoveries and verification results.
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.subdomains):
            return msg
        d = self.report.subdomains.data
        head = (f"{len(d.hostnames)} in-scope names from {d.certificates_seen} certificate entries "
                f"(`{d.query}`); {d.verified_count} verified via DNS"
                + (" + HTTPS/TLS" if d.http_checked else "") + f"; {d.out_of_scope_dropped} out-of-scope names dropped.\n")
        providers = self._table(["Provider", "Status", "Entries", "Cached at", "Error"],
                                [(p.provider, p.status, p.entries, p.cached_at.isoformat() if p.cached_at else None,
                                  p.error) for p in d.providers])
        rows = []
        for h in d.hostnames:
            rows.append((h.hostname + (" (wildcard only)" if h.wildcard else ""), h.state.value,
                         h.dns_status, h.addresses[:3], h.http_status or h.http_error,
                         {True: "ok", False: h.tls_error or "failed", None: None}[h.tls_ok],
                         h.sources, h.first_seen.date().isoformat() if h.first_seen else None,
                         h.last_seen.date().isoformat() if h.last_seen else None, h.certificate_count))
        return (head + "\n**Providers**\n\n" + providers + "\n" +
                self._table(["Hostname", "State", "DNS", "Addresses", "HTTPS", "TLS", "Sources", "First cert",
                             "Last expiry", "Certs"], rows) + f"\n> {d.note}\n")

    def _third_party(self) -> str:
        '''
        Render the third-party service inventory.
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.third_party):
            return msg
        services = self.report.third_party.data.services
        known = [s for s in services if s.known]
        unknown = [s for s in services if not s.known]
        out = [self._table(["Provider", "Category", "Domains", "Sources", "Confidence", "Evidence"],
                      [(s.provider, s.category, s.domains[:4], s.sources, s.confidence.value, s.evidence[:2])
                       for s in known])]
        if unknown:
            out += ["**Unrecognized external domains**", "",
                    self._table(["Domain group", "Hosts", "Sources", "Confidence"],
                           [(s.provider, s.domains[:4], s.sources, s.confidence.value) for s in unknown])]
        return "\n".join(out)

    def _infrastructure(self) -> str:
        '''
        Render inferred infrastructure providers.
        Returns:
            str: Section body.
        '''
        rows = [(o.provider, o.category, o.role, o.subjects, o.evidence, o.confidence.value)
                for o in self.report.analysis.infrastructure]
        return self._table(["Provider", "Category", "Role", "Subjects", "Evidence", "Confidence"], rows)

    def _findings(self) -> str:
        '''
        Render the findings summary table and details.
        Returns:
            str: Section body.
        '''
        if not self.report.analysis.findings:
            return "_No findings._\n"
        out = ["Severity reflects validated evidence; missing configuration is reported as "
               "informational unless its impact is demonstrable.", "",
               self._table(["", "Severity", "Confidence", "Title", "Subject"],
                      [(self.SEVERITY_ICON[f.severity], f.severity.value, f.confidence.value, f.title, f.subject)
                       for f in self.report.analysis.findings])]
        for f in self.report.analysis.findings:
            out += [f"#### {self.SEVERITY_ICON[f.severity]} {f.title} — `{f.subject}`", "",
                    f.description, "",
                    f"- **ID:** `{f.id}`  ",
                    f"- **Severity / confidence:** {f.severity.value} / {f.confidence.value}  ",
                    f"- **Source:** {f.source}  ",
                    *([f"- **Recommendation:** {f.recommendation}  "] if f.recommendation else []),
                    *([f"- **Limitations:** {f.limitations}  "] if f.limitations else []),
                    *([f"- **Evidence refs:** {', '.join(f'`{r}`' for r in f.evidence_refs)}  "] if f.evidence_refs else []),
                    "- **Evidence:**"]
            out += [f"  - `{self._cell(e)}`" for e in f.evidence]
            out.append("")
        return "\n".join(out)

    def _dnssec(self) -> str:
        '''
        Render DNSSEC status.
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.dnssec):
            return msg
        d = self.report.dnssec.data
        return self._table(["Field", "Value"], [
            ("Zone", d.zone), ("Status", f"**{d.status.value}**"), ("DS", f"{d.ds_status} ({len(d.ds_records)})"),
            ("DNSKEY", f"{d.dnskey_status} ({d.dnskey_count})"), ("Key algorithms", d.key_algorithms),
            ("DS digest types", d.ds_digest_types), ("Resolver AD flag", d.resolver_authenticated),
        ]) + f"\n> {d.note}\n"

    def _resources(self) -> str:
        '''
        Render robots.txt, sitemaps, security.txt, manifest, favicon and humans.txt.
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.resources):
            return msg
        d = self.report.resources.data

        def state(res) -> str:
            if res is None:
                return "not checked"
            if res.present:
                return "present"
            return "soft 404" if res.soft_404 else (res.error or f"absent (HTTP {res.status_code})")

        items = [("robots.txt", d.robots), ("security.txt", d.security_txt), ("manifest", d.manifest),
                 ("favicon", d.favicon), ("humans.txt", d.humans), *((f"sitemap ({s.source})", s) for s in d.sitemaps)]
        out = [self._table(["Resource", "URL", "State", "Type", "Size", "SHA-256"],
                           [(name, r.url, state(r), r.content_type, r.size, (r.sha256 or "")[:16] or None)
                            for name, r in items if r is not None])]
        if d.robots and d.robots.present:
            out += ["**robots.txt**", "", self._table(["Field", "Value"], [
                ("User agents", d.robots.user_agents), ("Disallow (*)", d.robots.disallow[:30]),
                ("Allow (*)", d.robots.allow[:30]), ("Crawl-delay", d.robots.crawl_delay), ("Sitemaps", d.robots.sitemaps)])]
        if d.security_txt and d.security_txt.present:
            st = d.security_txt
            out += ["**security.txt**", "", self._table(["Field", "Value"], [
                ("Contact", st.contacts), ("Expires", st.expires.isoformat() if st.expires else None),
                ("Expired", st.expired), ("PGP signed", st.signed),
                *((k, v) for k, v in st.fields.items() if k not in ("contact", "expires"))])]
        if d.manifest and d.manifest.present:
            m = d.manifest
            out += ["**Web app manifest**", "", self._table(["Field", "Value"], [
                ("Name", m.name), ("Short name", m.short_name), ("Start URL", m.start_url), ("Scope", m.scope),
                ("Display", m.display), ("Theme color", m.theme_color), ("Icons", m.icon_count)])]
        urls = d.sitemap_urls()
        if urls:
            out += [f"**Sitemap URLs** ({len(urls)} in scope)", "", "\n".join(f"- `{u}`" for u in urls[:50]), ""]
        if d.humans and d.humans.present:
            out += ["**humans.txt** (excerpt)", "", "```text", *d.humans.excerpt, "```", ""]
        return "\n".join(out)

    def _crawl(self) -> str:
        '''
        Render crawled pages, forms and unfetched discovered URLs.
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.crawler):
            return msg
        d = self.report.crawler.data
        out = [f"{len(d.pages)} page(s) fetched (depth ≤ {d.max_depth}, limit {d.max_pages}"
               + (", limit reached" if d.page_limit_reached else "") + "); robots.txt "
               + ("respected" if d.robots_respected else "ignored") + f"; delay {d.crawl_delay}s.", "",
               self._table(["URL", "From", "Depth", "Status", "Title", "Links", "Query params", "Error"],
                           [(p.url, p.source_url, p.depth, p.status_code, p.title, p.links_found, p.query_params, p.error)
                            for p in d.pages])]
        if d.forms:
            out += ["**Forms** (inspected only, never submitted)", "",
                    self._table(["Page", "Method", "Action", "Inputs", "Password field"],
                                [(f.page_url, f.method.upper(), f.action, f.input_names[:10], f.has_password_field)
                                 for f in d.forms])]
        if d.discovered:
            out += [f"**Discovered but not fetched** ({len(d.discovered)})", "",
                    self._table(["URL", "From", "Reason"], [(u.url, u.source_url, u.reason) for u in d.discovered[:100]])]
        return "\n".join(out)

    def _assets(self) -> str:
        '''
        Render static JS/CSS asset analysis.
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.javascript):
            return msg
        d = self.report.javascript.data
        out = [f"{len(d.assets)} asset(s) analyzed, {d.total_bytes:,} bytes read; {len(d.skipped)} skipped. "
               f"Allowed external asset hosts: {', '.join(d.allowed_external_hosts) or 'none'}.", "",
               self._table(["Asset", "Kind", "Status", "Size", "SHA-256", "Libraries", "Integrity", "Source map"],
                           [(a.url, a.kind, a.error or a.status_code, a.size, (a.sha256 or "")[:16] or None,
                             [f"{h.name} {h.version or ''} ({h.confidence.value})".replace("  ", " ") for h in a.libraries],
                             f"{a.integrity_status} ({a.integrity_algorithm})" if a.integrity_algorithm else a.integrity_status,
                             (f"{a.source_map_status}"
                              + (f" — {a.source_map_source_count} sources" if a.source_map_source_count else "")
                              + f": {a.source_map_url}") if a.source_map_status else None)
                            for a in d.assets])]
        exposed = [a for a in d.assets if a.source_map_sources]
        if exposed:
            out += [f"**Original source files exposed by public source maps** "
                    f"({sum(a.source_map_source_count for a in exposed)} total)", ""]
            for a in exposed:
                out += [f"From `{a.source_map_url}` ({a.source_map_source_count}):", "",
                        "\n".join(f"- `{self._cell(s)}`" for s in a.source_map_sources[:60]), ""]
        if d.service_hosts:
            out += ["**Service hosts referenced in bundles**", "",
                    self._table(["Host", "Referenced by"], [(h, refs) for h, refs in d.service_hosts.items()])]
        secrets = [(a, s) for a in d.assets for s in a.secrets]
        if secrets:
            out += [f"**Suspected credentials** ({len(secrets)}) — values redacted; confirm and rotate if real", "",
                    self._table(["Type", "Severity", "Context", "Fingerprint", "Asset"],
                                [(s.type, s.severity, s.context_key, s.redacted, a.url) for a, s in secrets])]
        configs = [(a, c) for a in d.assets for c in a.client_configs]
        if configs:
            rows = [(c.provider, a.url, "; ".join(f"{f.key}={'(redacted)' if f.sensitive else f.value}" for f in c.fields))
                    for a, c in configs]
            out += ["**Public client configuration** (ships in the browser by design)", "",
                    self._table(["Provider", "Asset", "Fields"], rows)]
        endpoints = d.endpoints()
        if endpoints:
            out += [f"**API endpoints referenced** ({len(endpoints)}; query values redacted)", "",
                    self._table(["Endpoint", "Host", "Method", "Same-site"],
                                [(e.value, e.host, e.method, e.same_site) for e in endpoints[:150]])]
        if d.skipped:
            out += [f"**Skipped assets** ({len(d.skipped)})", "",
                    self._table(["Asset", "From", "Reason"], [(s.url, s.source_page, s.reason) for s in d.skipped[:50]])]
        out.append(f"> {d.note}\n")
        return "\n".join(out)

    def _cookies(self) -> str:
        '''
        Render cookie attributes (values are never recorded).
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.cookies):
            return msg
        d = self.report.cookies.data
        if not d.cookies:
            return f"_No cookies set by {d.responses_inspected} inspected response(s)._\n"
        return self._table(["Name", "Secure", "HttpOnly", "SameSite", "Domain", "Path", "Persistent", "Prefix", "Set by"],
                           [(c.name, c.secure, c.http_only, c.same_site, c.domain, c.path, c.persistent,
                             f"{c.prefix} ({'valid' if c.prefix_valid else 'invalid'})" if c.prefix else None, c.source_url)
                            for c in d.cookies]) + f"\n> {d.note}\n"

    def _changes(self) -> str:
        '''
        Render the comparison with the previous stored scan, if any.
        Returns:
            str: Section body.
        '''
        c = self.report.comparison
        if c is None:
            return "_No previous scan of this target was stored; nothing to compare._\n"
        out = [f"Compared with `{c.previous.scan_id}` ({c.previous.started_at:%Y-%m-%d %H:%M:%S} UTC). "
               + ", ".join(f"{v} {k}" for k, v in c.counts.items()) + ".", "", f"> {c.note}", ""]
        if c.changes:
            out.append(self._table(["Change", "Type", "Target", "Key", "Previous", "Current"],
                                   [(ch.kind.value, ch.type, ch.target, ch.key, ch.previous, ch.current)
                                    for ch in c.changes[:100]]))
            if len(c.changes) > 100:
                out.append(f"_{len(c.changes) - 100} more in changes.md._\n")
        return "\n".join(out)

    def _errors(self) -> str:
        '''
        Render collection errors and limitations.
        Returns:
            str: Section body.
        '''
        out = []
        if self.report.errors:
            out.append(self._table(["Module", "Target", "Type", "Message"],
                              [(e.module, e.target, e.error_type, e.message[:200]) for e in self.report.errors]))
        else:
            out.append("_No collection errors._\n")
        if self.report.limitations:
            out += ["**Limitations**", ""] + [f"- {lim}" for lim in self.report.limitations] + [""]
        return "\n".join(out)

    @staticmethod
    def _cell(value: Any) -> str:
        '''
        Format a value for a Markdown table cell (escapes pipes, joins lists, '—' for empty).
        Parameters:
            value (Any): Value to format.
        Returns:
            str: Cell text.
        '''
        if value is None or value == "" or value == []:
            return "—"
        if isinstance(value, (list, tuple)):
            value = ", ".join(str(v) for v in value)
        return str(value).replace("|", "\\|").replace("\n", " ")

    @staticmethod
    def _table(headers: list[str], rows: Iterable[Iterable]) -> str:
        '''
        Render a Markdown table.
        Parameters:
            headers (list[str]): Column headers.
            rows (Iterable[Iterable]): Row values.
        Returns:
            str: Table text, or '_No data._'.
        '''
        rows = list(rows)
        if not rows:
            return "_No data._\n"
        lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
        lines += ["| " + " | ".join(MarkdownReportWriter._cell(c) for c in row) + " |" for row in rows]
        return "\n".join(lines) + "\n"

    @staticmethod
    def _unavailable(result: ModuleResult) -> str | None:
        '''
        Return a notice when a module produced no data.
        Parameters:
            result (ModuleResult): Module result.
        Returns:
            str | None: Notice text, or None when data exists.
        '''
        if result.data is not None:
            return None
        if result.status is ModuleStatus.SKIPPED:
            return f"_Skipped: {result.note or 'not run'}._\n"
        return f"_Module {result.status.value}; no data collected. See collection errors._\n"

    @staticmethod
    def _sources() -> str:
        '''
        Render the list of data sources and references.
        Returns:
            str: Section body.
        '''
        return "\n".join([
            "- DNS: system-configured recursive resolver (dnspython)",
            "- ASN: Team Cymru IP-to-ASN mapping via DNS (`origin.asn.cymru.com`)",
            "- IP allocation: RDAP via https://rdap.org/ bootstrap → Regional Internet Registries",
            "- Domain registration: RDAP via IANA bootstrap (https://data.iana.org/rdap/dns.json), WHOIS fallback",
            "- Subdomains: Certificate Transparency search at https://crt.sh/",
            "- HTML, technology and third-party analysis: derived from the fetched landing page and headers",
            "- HTTP/TLS: direct requests to in-scope hostnames",
            "- RFC 7208 (SPF), RFC 7489 (DMARC), RFC 6797 (HSTS), RFC 8659 (CAA), RFC 8996 (TLS 1.0/1.1 deprecation)",
        ]) + "\n"
