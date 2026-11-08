'''
Self-contained HTML report.

Every value is HTML-escaped (most of it comes from untrusted websites). The page loads no
external resources and runs no JavaScript; a strict Content-Security-Policy enforces both.
Discovered URLs are rendered as text, never as links, so opening the report contacts nothing.
'''

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any, ClassVar

from recon.models import Finding, ModuleResult, ModuleStatus, Severity
from recon.reporting.base import ReportWriter
from recon.reporting.html_theme import CSS, header_html, nav_html, severity_bar


class Safe(str):
    '''
    Marks a string as already-escaped HTML so helpers do not escape it again.
    '''


class HtmlReportWriter(ReportWriter):
    '''
    Renders the report as a single self-contained HTML page and writes report.html.
    '''

    CSP: ClassVar[str] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"
    SEVERITY_ORDER: ClassVar[tuple[Severity, ...]] = (
        Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL)
    SECTIONS: ClassVar[tuple[tuple[str, str], ...]] = (
        ("summary", "Executive Summary"), ("target", "Target"), ("findings", "Security Observations"),
        ("changes", "Changes"), ("dns", "DNS"), ("dnssec", "DNSSEC"), ("network", "Network & IP"),
        ("http", "HTTP / HTTPS"), ("tls", "TLS"), ("whois", "Registration"), ("resources", "Public Resources"),
        ("technology", "Technologies"), ("html", "HTML"), ("crawl", "Crawl"), ("assets", "JS / CSS Assets"), ("cookies", "Cookies"),
        ("subdomains", "Subdomains"), ("third-party", "Third Parties"), ("infrastructure", "Infrastructure"),
        ("errors", "Errors & Limitations"), ("raw", "Raw Data"), ("sources", "Sources"),
    )

    def write(self, directory: Path) -> list[Path]:
        '''
        Render the report as HTML and write report.html.
        Parameters:
            directory (Path): Directory to write into; created if missing.
        Returns:
            list[Path]: Path of the file written.
        Raises:
            OSError: If the directory cannot be written.
        '''
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "report.html"
        path.write_text(self.render(), encoding="utf-8")
        return [path]

    def render(self) -> str:
        '''
        Render the full page.
        Returns:
            str: HTML document.
        '''
        bodies = {
            "summary": self._summary(), "target": self._target(), "findings": self._findings(),
            "dns": self._dns(), "network": self._network(), "http": self._http(), "tls": self._tls(),
            "whois": self._whois(), "technology": self._technology(), "html": self._html(),
            "subdomains": self._subdomains(), "third-party": self._third_party(),
            "infrastructure": self._infrastructure(), "errors": self._errors(), "raw": self._raw(),
            "sources": self._sources(), "changes": self._changes(), "dnssec": self._dnssec(),
            "resources": self._resources(), "crawl": self._crawl(), "cookies": self._cookies(),
            "assets": self._assets(),
        }
        nav = nav_html(self.SECTIONS)
        sections = "".join(
            f'<section id="{sid}"><h2>{escape(title)}</h2>{bodies[sid]}</section>' for sid, title in self.SECTIONS)
        host = escape(self.report.target.hostname)
        return (
            "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            f'<meta http-equiv="Content-Security-Policy" content="{self.CSP}">'
            '<meta name="referrer" content="no-referrer">'
            '<meta name="color-scheme" content="light dark">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f"<title>Recon report: {host}</title><style>{CSS}</style></head><body>"
            + header_html(self.report.target.hostname, self.report.tool.name, self.report.tool.version,
                          self.report.started_at, self.report.duration_ms / 1000)
            + f'<div class="layout"><nav aria-label="Sections">{nav}</nav><main>{sections}</main></div></body></html>\n'
        )

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _e(value: Any) -> str:
        '''
        Escape and format a value for display ('–' for empty, lists joined, datetimes ISO).
        Parameters:
            value (Any): Value to display.
        Returns:
            str: Safe HTML.
        '''
        if isinstance(value, Safe):
            return value
        if value is None or value == "" or value == [] or value == {}:
            return '<span class="muted">–</span>'
        if isinstance(value, bool):
            return '<span class="yes">yes</span>' if value else '<span class="no">no</span>'
        if isinstance(value, datetime):
            return escape(value.isoformat())
        if isinstance(value, (list, tuple, set, frozenset)):
            return "<br>".join(HtmlReportWriter._e(v) for v in value)
        return escape(str(value))

    @classmethod
    def _table(cls, headers: list[str], rows: Iterable[Iterable[Any]], css: str = "") -> str:
        '''
        Render a data table.
        Parameters:
            headers (list[str]): Column headers.
            rows (Iterable[Iterable[Any]]): Row values (escaped unless Safe).
            css (str): Extra CSS class for the table.
        Returns:
            str: Safe HTML, or an empty-state paragraph when there are no rows.
        '''
        rows = list(rows)
        if not rows:
            return '<p class="muted">No data.</p>'
        head = "".join(f"<th>{escape(h)}</th>" for h in headers)
        body = "".join("<tr>" + "".join(f"<td>{cls._e(c)}</td>" for c in row) + "</tr>" for row in rows)
        return f'<div class="scroll"><table class="{css}"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'

    @classmethod
    def _kv(cls, pairs: Iterable[tuple[str, Any]]) -> str:
        '''
        Render a two-column field/value table.
        Parameters:
            pairs (Iterable[tuple[str, Any]]): (label, value) pairs.
        Returns:
            str: Safe HTML.
        '''
        rows = "".join(f"<tr><th>{escape(k)}</th><td>{cls._e(v)}</td></tr>" for k, v in pairs)
        return f'<div class="scroll"><table class="kv"><tbody>{rows}</tbody></table></div>'

    @staticmethod
    def _pill(text: str, kind: str) -> Safe:
        '''
        Render a coloured status/severity pill.
        Parameters:
            text (str): Label.
            kind (str): CSS modifier (a severity, module status or confidence value).
        Returns:
            Safe: Pill HTML.
        '''
        return Safe(f'<span class="pill {escape(kind)}">{escape(text)}</span>')

    @staticmethod
    def _code(text: Any) -> Safe:
        '''
        Render a value as inline code.
        Parameters:
            text (Any): Value to show.
        Returns:
            Safe: Code HTML.
        '''
        return Safe(f"<code>{escape(str(text))}</code>")

    @classmethod
    def _unavailable(cls, result: ModuleResult) -> str | None:
        '''
        Return a notice when a module produced no data.
        Parameters:
            result (ModuleResult): Module result.
        Returns:
            str | None: Notice HTML, or None when data exists.
        '''
        if result.data is not None:
            return None
        if result.status is ModuleStatus.SKIPPED:
            return f'<p class="notice">Skipped: {escape(result.note or "not run")}.</p>'
        return (f'<p class="notice bad">Module {escape(result.status.value)}; no data collected. '
                'See <a href="#errors">collection errors</a>.</p>')

    @staticmethod
    def _note(text: str) -> str:
        '''
        Render an explanatory note.
        Parameters:
            text (str): Note text.
        Returns:
            str: Safe HTML.
        '''
        return f'<p class="note">{escape(text)}</p>'

    # ------------------------------------------------------------------ sections

    def _summary(self) -> str:
        '''
        Render headline numbers, module status and identified providers.
        Returns:
            str: Section body.
        '''
        r = self.report
        counts = r.analysis.severity_counts
        statuses = [m.status for m in r.module_results().values()]
        module_line = " · ".join(f"{statuses.count(s)} {s.value}" for s in ModuleStatus if statuses.count(s))
        providers = sorted({o.provider for o in r.analysis.infrastructure})
        techs = [t.name for t in (r.technology.data.technologies if r.technology.data else [])]
        return (
            severity_bar(counts, self.SEVERITY_ORDER)
            + f"<p><strong>Modules:</strong> {escape(module_line)}</p>"
            + self._table(["Module", "Status", "Duration", "Errors"],
                          [(name, self._pill(m.status.value, m.status.value), f"{m.duration_ms:.0f} ms", len(m.errors))
                           for name, m in r.module_results().items()])
            + f"<p><strong>Providers:</strong> {self._e(', '.join(providers))}</p>"
            + f"<p><strong>Technologies:</strong> {self._e(', '.join(techs))}</p>"
        )

    def _target(self) -> str:
        '''
        Render target and run information.
        Returns:
            str: Section body.
        '''
        r = self.report
        return self._kv([
            ("Input", r.target.input), ("Normalized hostname", self._code(r.target.hostname)),
            ("Authorized scope", r.target.scope), ("Started", r.started_at), ("Finished", r.finished_at),
            ("Options", [f"{k}={v}" for k, v in r.options.items()]), ("User-Agent", r.tool.user_agent),
            ("Scan ID", self._code(r.scan_id)), ("Schema version", r.schema_version),
            ("Observations", len(r.observations)),
        ])

    def _findings(self) -> str:
        '''
        Render findings with a CSS-only severity filter.
        Returns:
            str: Section body.
        '''
        findings = self.report.analysis.findings
        if not findings:
            return '<p class="muted">No findings.</p>'
        present = [s for s in self.SEVERITY_ORDER if any(f.severity is s for f in findings)]
        radios = '<input type="radio" name="sev" id="sev-all" checked><label for="sev-all">all</label>' + "".join(
            f'<input type="radio" name="sev" id="sev-{s.value}"><label for="sev-{s.value}">{escape(s.value)}</label>'
            for s in present)
        items = "".join(self._finding(f) for f in findings)
        return (self._note("Severity reflects validated evidence; missing configuration is informational "
                           "unless its impact is demonstrable.")
                + f'<div class="findings"><div class="filter">{radios}</div>{items}</div>')

    def _finding(self, f: Finding) -> str:
        '''
        Render one finding as a collapsible card.
        Parameters:
            f (Finding): The finding.
        Returns:
            str: Safe HTML.
        '''
        evidence = "".join(f"<li>{self._code(e)}</li>" for e in f.evidence) or '<li class="muted">–</li>'
        return (
            f'<details class="finding" data-sev="{f.severity.value}"><summary>'
            f"{self._pill(f.severity.value, f.severity.value)} <span class=\"title\">{escape(f.title)}</span>"
            f' <span class="muted subject">{escape(f.subject)}</span></summary>'
            f"<p>{escape(f.description)}</p>"
            + self._kv([("ID", self._code(f.id)), ("Category", f.category),
                        ("Confidence", self._pill(f.confidence.value, f.confidence.value)),
                        ("Source", f.source), ("Timestamp", f.timestamp),
                        ("Recommendation", f.recommendation), ("Limitations", f.limitations),
                        ("Evidence refs", [self._code(r) for r in f.evidence_refs])])
            + f"<h4>Evidence</h4><ul>{evidence}</ul></details>"
        )

    def _dns(self) -> str:
        '''
        Render DNS records and email security.
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.dns):
            return msg
        d = self.report.dns.data
        out = self._table(["Record", "Name", "Status", "Values", "TTL", "Time"],
                          [(key, q.name, self._pill(q.status.value, "ok" if q.status.is_definitive else "failed"),
                            q.values, q.records[0].ttl if q.records else None, f"{q.response_time_ms} ms")
                           for key, q in d.queries.items()])
        e = d.email
        out += "<h3>SPF</h3>" + (self._table(["Record", "'all' qualifier", "Includes", "Redirect"],
                                             [(s.raw, s.all_qualifier, s.includes, s.redirect) for s in e.spf.records])
                                 if e.spf.records else f'<p class="muted">No SPF record ({escape(e.spf.lookup_status)}).</p>')
        if e.spf.lookup_count is not None:
            out += self._kv([("DNS lookups", f"{e.spf.lookup_count} / 10"), ("Void lookups", f"{e.spf.void_lookups} / 2"),
                             ("Limit exceeded", e.spf.lookup_limit_exceeded),
                             ("Parse errors", [x for rec in e.spf.records for x in rec.parse_errors]),
                             ("Evaluation notes", e.spf.evaluation_errors)])
            if e.spf.lookup_tree:
                out += f"<pre>{escape(chr(10).join(e.spf.lookup_tree))}</pre>"
        out += "<h3>DMARC</h3>" + (self._kv([
            ("Record(s)", e.dmarc.raw_records), ("Policy (p)", e.dmarc.policy),
            ("Subdomain policy (sp)", e.dmarc.subdomain_policy), ("pct", e.dmarc.pct),
            ("DKIM alignment (adkim)", e.dmarc.adkim or "r (default)"), ("SPF alignment (aspf)", e.dmarc.aspf or "r (default)"),
            ("Aggregate reports (rua)", e.dmarc.rua), ("Forensic reports (ruf)", e.dmarc.ruf),
            ("Tags", [f"{k}={v}" for k, v in e.dmarc.tags.items()]),
        ]) if e.dmarc.raw_records else
            f'<p class="muted">No DMARC record at {self._code(e.dmarc.name)} ({escape(e.dmarc.lookup_status)}).</p>')
        out += "<h3>DKIM</h3>" + self._table(["Selector", "Name", "Key", "Revoked", "Record"],
                                             [(k.selector, k.name, f"{k.key_type} {k.key_bits or '?'} bits", k.revoked,
                                               k.record) for k in e.dkim_found])
        out += self._note(f"{len(e.dkim_selectors_checked)} selectors checked: "
                          f"{', '.join(e.dkim_selectors_checked) or 'none'}. {e.dkim_note}")
        caa = d.caa
        out += "<h3>CAA policy</h3>" + self._kv([
            ("Effective at", caa.effective_name), ("Inherited from parent", caa.inherited), ("Records", caa.records),
            ("Names checked", [f"{n}: {st}" for n, st in caa.checked.items()]), ("Lookup complete", caa.complete)])
        return out

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
            asn, rdap = ip.asn, ip.rdap
            rows.append((self._code(ip.ip), f"IPv{ip.version}", ip.is_public, ip.ptr or ip.ptr_status,
                         f"AS{asn.asn} {asn.name or ''}".strip() if asn else None, asn.prefix if asn else None,
                         asn.country if asn else None, rdap.name if rdap else None,
                         rdap.organizations if rdap else None, (rdap.cidrs or rdap.start_address) if rdap else None))
        return (self._table(["IP", "Ver", "Public", "PTR", "ASN", "BGP prefix", "Country", "RDAP network",
                             "Organization", "Range"], rows)
                + self._note("ASN and RDAP data describe who the address space is allocated to (often a CDN "
                             "or cloud edge), not necessarily where the origin server runs."))

    def _http(self) -> str:
        '''
        Render each HTTP probe with its redirect chain, headers and security headers.
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.http):
            return msg
        out = []
        for p in self.report.http.data.probes:
            label = self._pill("ok" if p.success else "failed", "ok" if p.success else "failed")
            if not p.success:
                out.append(f"<details><summary>{label} {self._code(p.requested_url)}</summary>"
                           f'<p class="bad">{escape(p.error_type or "")}: {escape(p.error or "")}</p></details>')
                continue
            chain = self._table(["#", "Status", "URL", "Location", "Protocol", "Time"],
                                [(i + 1, h.status_code, h.url, h.location, h.http_version, f"{h.elapsed_ms} ms")
                                 for i, h in enumerate(p.hops)])
            fields = self._kv([
                ("Final URL", p.final_url), ("Final response fetched", p.final_fetched),
                ("Stopped because", p.redirect_stopped_reason), ("Status", p.status_code),
                ("Protocol", p.http_version), ("Server", p.server), ("Content-Type", p.content_type),
                ("Content-Length", p.content_length), ("Body bytes read", p.body_bytes),
                ("Body truncated", p.body_truncated), ("Response time", f"{p.response_time_ms} ms" if p.response_time_ms else None),
                ("Total time", f"{p.total_time_ms} ms" if p.total_time_ms else None),
                ("Redirects to HTTPS", p.redirects_to_https),
            ])
            security = self._table(["Header", "Present", "Value", "Parsed"],
                                   [(h.name, h.present, h.value,
                                     json.dumps(h.parsed, ensure_ascii=False) if h.parsed else None)
                                    for h in p.security_headers.values()])
            headers = self._table(["Header", "Value(s)"], [(k, v) for k, v in sorted(p.headers.items())])
            out.append(f'<details open><summary>{label} {self._code(p.requested_url)} → '
                       f'{self._e(p.status_code)} {self._code(p.final_url or "")}</summary>'
                       f"<h4>Redirect chain</h4>{chain}<h4>Response</h4>{fields}"
                       f"<h4>Security headers</h4>{security}<details><summary>All response headers "
                       f"({len(p.headers)})</summary>{headers}</details></details>")
        return "".join(out)

    def _tls(self) -> str:
        '''
        Render TLS certificate details per host.
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.tls):
            return msg
        out = []
        for p in self.report.tls.data.probes:
            title = f"{p.hostname}:{p.port}"
            if not p.success:
                out.append(f"<details open><summary>{self._pill('failed', 'failed')} {self._code(title)}</summary>"
                           f'<p class="bad">{escape(p.error_type or "")}: {escape(p.error or "")}</p></details>')
                continue
            c = p.certificate
            key = f"{c.public_key_algorithm} {c.public_key_size or ''} {c.public_key_curve or ''}".strip()
            out.append(
                f"<details open><summary>{self._pill('ok', 'ok')} {self._code(title)} · {escape(p.tls_version or '')}"
                f" · {self._e(p.days_remaining)} days remaining</summary>"
                + self._kv([
                    ("Connected IP", p.ip), ("TLS version", p.tls_version), ("Cipher", p.cipher),
                    ("Chain verified", p.verified), ("Verification error", p.verification_error),
                    ("Hostname matches SAN", p.hostname_match), ("Currently valid", p.currently_valid),
                    ("Days remaining", p.days_remaining), ("Subject", c.subject), ("Issuer", c.issuer),
                    ("Serial", self._code(c.serial_number)), ("Version", c.version),
                    ("Valid from", c.not_before), ("Valid until", c.not_after),
                    ("Signature", f"{c.signature_algorithm} ({c.signature_hash or 'n/a'})"), ("Public key", key),
                    ("Self-issued", c.self_issued), ("SAN DNS names", c.san_dns), ("SAN IPs", c.san_ip),
                    ("SHA-256 fingerprint", self._code(c.fingerprint_sha256)),
                ]) + "</details>")
        return "".join(out)

    def _whois(self) -> str:
        '''
        Render domain registration data.
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.whois):
            return msg
        d = self.report.whois.data
        return self._kv([
            ("Domain", d.domain), ("Source", f"{d.source} {d.source_url or ''}".strip()),
            ("Registrar", d.registrar), ("Registrar IANA ID", d.registrar_iana_id),
            ("Created", d.created), ("Updated", d.updated), ("Expires", d.expires),
            ("Days until expiry", d.days_until_expiry), ("Status", d.status),
            ("Nameservers", d.nameservers), ("DNSSEC", d.dnssec),
        ]) + self._note(d.note)

    def _technology(self) -> str:
        '''
        Render technology detections with all evidence.
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.technology):
            return msg
        d = self.report.technology.data
        rows = [(Safe(f"<strong>{escape(t.name)}</strong>"), t.category, t.version,
                 self._pill(t.status.value, "ok" if t.status.value == "confirmed" else "partial"),
                 self._pill(t.confidence.value, t.confidence.value),
                 [f"{e.source} ({e.confidence.value}): {e.detail}" for e in t.evidence])
                for t in d.technologies]
        return (self._table(["Technology", "Category", "Version", "Status", "Confidence", "Evidence"], rows)
                + self._note(f"{d.signatures_checked} signatures checked against: {', '.join(d.inputs) or 'no inputs'}. "
                             "'Probable' detections rest on a single weaker signal."))

    def _html(self) -> str:
        '''
        Render landing-page metadata, resources, external domains and commented URLs.
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.html):
            return msg
        d = self.report.html.data
        out = self._kv([
            ("Document", d.source_url), ("Content-Type", d.content_type), ("Truncated", d.body_truncated),
            ("Title", d.title), ("Description", d.meta_description), ("Canonical", d.canonical),
            ("Language", d.lang), ("Robots", d.robots), ("Generator", d.generator), ("Favicons", d.favicons),
            ("Open Graph", [f"{k} = {v}" for k, v in d.open_graph.items()]),
            ("Twitter", [f"{k} = {v}" for k, v in d.twitter.items()]),
            ("Verification tokens", [f"{k} = {v}" for k, v in d.verification_tokens.items()]),
            ("Inline scripts", d.inline_script_count), ("HTML comments", d.comment_count),
            ("Warnings", d.parse_warnings),
        ])
        out += "<h3>External domains</h3>" + (
            '<p class="chips">' + "".join(f"<span>{escape(h)}</span>" for h in d.external_domains) + "</p>"
            if d.external_domains else '<p class="muted">None.</p>')
        out += f"<h3>Resources ({len(d.resources)})</h3>" + self._table(
            ["Kind", "URL", "Same site", "Attributes"],
            [(r.kind, r.url, r.same_site, [f"{k}={v}" for k, v in r.attributes.items()]) for r in d.resources])
        if d.json_ld:
            out += "<h3>JSON-LD</h3>" + "".join(
                f"<pre>{escape(json.dumps(block, indent=2, ensure_ascii=False))}</pre>" for block in d.json_ld)
        if d.commented_urls:
            out += ("<h3>URLs inside HTML comments</h3>"
                    + self._note("Inactive markup, listed separately from live resources.")
                    + "<ul>" + "".join(f"<li>{self._code(u)}</li>" for u in d.commented_urls) + "</ul>")
        return out

    def _subdomains(self) -> str:
        '''
        Render Certificate Transparency discoveries and verification results.
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.subdomains):
            return msg
        d = self.report.subdomains.data
        live = sum(1 for h in d.hostnames if h.resolves)
        rows = []
        for h in d.hostnames:
            dns = (self._pill("resolves", "ok") if h.resolves else
                   self._pill(h.dns_status or "?", "failed") if h.resolves is False else
                   self._pill(h.dns_status or "not checked", "skipped"))
            state_kind = {"reachable": "ok", "resolving": "partial", "historical": "skipped"}.get(h.state.value, "skipped")
            rows.append((Safe(self._code(h.hostname) + (' <span class="muted">(wildcard only)</span>' if h.wildcard else "")),
                         self._pill(h.state.value, state_kind), dns, h.addresses, h.private_addresses,
                         h.http_status or h.http_error, {True: "ok", False: h.tls_error or "failed", None: None}[h.tls_ok],
                         h.sources, h.first_seen.date().isoformat() if h.first_seen else None,
                         h.last_seen.date().isoformat() if h.last_seen else None, h.certificate_count, h.issuers))
        providers = self._table(["Provider", "Status", "Entries", "Cached at", "Error"],
                                [(p.provider, self._pill(p.status, {"live": "ok", "cached": "partial"}.get(p.status, "failed")),
                                  p.entries, p.cached_at, p.error) for p in d.providers])
        return (f"<p>{len(d.hostnames)} in-scope names from {d.certificates_seen} certificate entries "
                f"({self._code(d.query)}); {live} resolve now; {d.verified_count} verified"
                f"{' (DNS + HTTPS/TLS)' if d.http_checked else ' (DNS)'}; {d.out_of_scope_dropped} out-of-scope names dropped.</p>"
                + "<h3>CT providers</h3>" + providers
                + self._table(["Hostname", "State", "DNS", "Addresses", "Private", "HTTPS", "TLS", "Sources",
                               "First cert", "Last expiry", "Certs", "Issuers"], rows)
                + self._note(d.note))

    def _dnssec(self) -> str:
        '''
        Render DNSSEC status.
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.dnssec):
            return msg
        d = self.report.dnssec.data
        kind = {"signed_validated": "ok", "signed_unvalidated": "partial", "unsigned": "skipped"}.get(d.status.value, "failed")
        return self._kv([
            ("Zone", self._code(d.zone)), ("Status", self._pill(d.status.value, kind)),
            ("DS", f"{d.ds_status} ({len(d.ds_records)})"), ("DNSKEY", f"{d.dnskey_status} ({d.dnskey_count})"),
            ("Key algorithms", d.key_algorithms), ("DS digest types", d.ds_digest_types),
            ("DS records", d.ds_records), ("Resolver AD flag", d.resolver_authenticated),
        ]) + self._note(d.note)

    def _resources(self) -> str:
        '''
        Render robots.txt, sitemaps, security.txt, manifest, favicon and humans.txt.
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.resources):
            return msg
        d = self.report.resources.data

        def state(res) -> Safe:
            if res.present:
                return self._pill("present", "ok")
            if res.soft_404:
                return self._pill("soft 404", "skipped")
            return self._pill(res.error or f"absent (HTTP {res.status_code})", "skipped")

        items = [("robots.txt", d.robots), ("security.txt", d.security_txt), ("manifest", d.manifest),
                 ("favicon", d.favicon), ("humans.txt", d.humans), *((f"sitemap ({s.source})", s) for s in d.sitemaps)]
        out = self._table(["Resource", "URL", "State", "Type", "Size", "SHA-256"],
                          [(name, r.url, state(r), r.content_type, r.size, self._code(r.sha256) if r.sha256 else None)
                           for name, r in items if r is not None])
        if d.robots and d.robots.present:
            out += "<h3>robots.txt</h3>" + self._kv([
                ("User agents", d.robots.user_agents), ("Disallow (*)", d.robots.disallow),
                ("Allow (*)", d.robots.allow), ("Crawl-delay", d.robots.crawl_delay), ("Sitemaps", d.robots.sitemaps)])
        if d.security_txt and d.security_txt.present:
            st = d.security_txt
            out += "<h3>security.txt</h3>" + self._kv([
                ("Contact", st.contacts), ("Expires", st.expires), ("Expired", st.expired), ("PGP signed", st.signed),
                *((k, v) for k, v in st.fields.items() if k not in ("contact", "expires"))])
        if d.manifest and d.manifest.present:
            m = d.manifest
            out += "<h3>Web app manifest</h3>" + self._kv([
                ("Name", m.name), ("Short name", m.short_name), ("Start URL", m.start_url), ("Scope", m.scope),
                ("Display", m.display), ("Theme color", m.theme_color), ("Icons", m.icon_count)])
        urls = d.sitemap_urls()
        if urls:
            out += f"<h3>Sitemap URLs ({len(urls)})</h3><ul>" + "".join(f"<li>{self._code(u)}</li>" for u in urls[:200]) + "</ul>"
        if d.humans and d.humans.present:
            out += "<h3>humans.txt (excerpt)</h3>" + f"<pre>{escape(chr(10).join(d.humans.excerpt))}</pre>"
        return out

    def _crawl(self) -> str:
        '''
        Render crawled pages, forms and unfetched discovered URLs.
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.crawler):
            return msg
        d = self.report.crawler.data
        out = (f"<p>{len(d.pages)} page(s) fetched (depth ≤ {d.max_depth}, limit {d.max_pages}"
               f"{', limit reached' if d.page_limit_reached else ''}); robots.txt "
               f"{'respected' if d.robots_respected else 'ignored'}; delay {d.crawl_delay}s.</p>")
        out += self._table(["URL", "From", "Depth", "Status", "Title", "Links", "Query params", "Missing security headers", "Error"],
                           [(p.url, p.source_url, p.depth, p.status_code, p.title, p.links_found, p.query_params,
                             [k for k, v in p.security_headers.items() if v is None], p.error) for p in d.pages])
        if d.forms:
            out += "<h3>Forms</h3>" + self._note("Inspected only; never submitted. Field values are not read.") + self._table(
                ["Page", "Method", "Action", "Inputs", "Password field"],
                [(f.page_url, f.method.upper(), f.action, f.input_names, f.has_password_field) for f in d.forms])
        if d.discovered:
            out += f"<details><summary>Discovered but not fetched ({len(d.discovered)})</summary>" + self._table(
                ["URL", "From", "Reason"], [(u.url, u.source_url, u.reason) for u in d.discovered]) + "</details>"
        return out

    def _assets(self) -> str:
        '''
        Render static JS/CSS asset analysis.
        Returns:
            str: Section body.
        '''
        if msg := self._unavailable(self.report.javascript):
            return msg
        d = self.report.javascript.data
        map_kind = {"public": "failed", "not_public": "ok", "inline": "partial"}
        out = (f"<p>{len(d.assets)} asset(s) analyzed, {d.total_bytes:,} bytes read; {len(d.skipped)} skipped. "
               f"Allowed external asset hosts: {escape(', '.join(d.allowed_external_hosts) or 'none')}.</p>")
        sri_kind = {"verified": "ok", "mismatch": "failed", "absent": "skipped"}
        out += self._table(["Asset", "Kind", "Status", "Size", "SHA-256", "Libraries", "Integrity", "Source map"],
                           [(a.url, a.kind, a.error or a.status_code, a.size,
                             self._code(a.sha256[:16]) if a.sha256 else None,
                             [f"{h.name} {h.version or ''} ({h.confidence.value})".replace("  ", " ") for h in a.libraries],
                             Safe(f"{self._pill(a.integrity_status, sri_kind.get(a.integrity_status, 'partial'))}"
                                  + (f" {escape(a.integrity_algorithm)}" if a.integrity_algorithm else ""))
                             if a.integrity_status else None,
                             Safe(f"{self._pill(a.source_map_status, map_kind.get(a.source_map_status, 'skipped'))} "
                                  + (f"<b>{a.source_map_source_count} sources</b> " if a.source_map_source_count else "")
                                  + f"{escape(a.source_map_url or '')}") if a.source_map_status else None)
                            for a in d.assets])
        exposed = [a for a in d.assets if a.source_map_sources]
        if exposed:
            total = sum(a.source_map_source_count for a in exposed)
            out += f"<h3>Original source files exposed by public source maps ({total})</h3>"
            for a in exposed:
                out += (f"<details><summary>{escape(a.source_map_url or a.url)} "
                        f"({a.source_map_source_count})</summary><ul>"
                        + "".join(f"<li>{self._code(s)}</li>" for s in a.source_map_sources) + "</ul></details>")
        if d.service_hosts:
            out += "<h3>Service hosts referenced in bundles</h3>" + self._table(
                ["Host", "Referenced by"], [(self._code(h), refs) for h, refs in d.service_hosts.items()])
        secrets = [(a, s) for a in d.assets for s in a.secrets]
        if secrets:
            out += (f"<h3>Suspected credentials ({len(secrets)})</h3>"
                    + self._note("Values are redacted (fingerprint only); detection is heuristic. "
                                 "Confirm each and rotate if real. Public keys are excluded.")
                    + self._table(["Type", "Severity", "Context", "Fingerprint", "Asset"],
                                  [(self._code(s.type), self._pill(s.severity, "failed" if s.severity == "high" else "partial"),
                                    s.context_key, self._code(s.redacted), a.url) for a, s in secrets]))
        configs = [(a, c) for a in d.assets for c in a.client_configs]
        if configs:
            out += "<h3>Public client configuration</h3>" + self._note(
                "These values ship in the browser by design. Confirm server-side rules do not rely on them staying secret.")
            for a, c in configs:
                out += (f"<h4>{escape(c.provider)} <span class='muted'>{escape(a.url)}</span></h4>"
                        + self._kv([(f.key, Safe('<span class="muted">(redacted)</span>') if f.sensitive else f.value)
                                    for f in c.fields]))
        endpoints = d.endpoints()
        if endpoints:
            out += f"<h3>API endpoints referenced ({len(endpoints)})</h3>" + self._note("Query values redacted.") + self._table(
                ["Endpoint", "Host", "Method", "Same-site"],
                [(self._code(e.value), e.host, e.method, e.same_site) for e in endpoints[:300]])
        if d.skipped:
            out += f"<details><summary>Skipped assets ({len(d.skipped)})</summary>" + self._table(
                ["Asset", "From", "Reason"], [(s.url, s.source_page, s.reason) for s in d.skipped]) + "</details>"
        return out + self._note(d.note)

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
            return f'<p class="muted">No cookies set by {d.responses_inspected} inspected response(s).</p>'
        return self._table(["Name", "Secure", "HttpOnly", "SameSite", "Domain", "Path", "Persistent", "Prefix",
                            "Value length", "Set by"],
                           [(self._code(c.name), c.secure, c.http_only, c.same_site, c.domain, c.path, c.persistent,
                             f"{c.prefix} ({'valid' if c.prefix_valid else 'invalid'})" if c.prefix else None,
                             c.value_length, c.source_url) for c in d.cookies]) + self._note(d.note)

    def _changes(self) -> str:
        '''
        Render the comparison with the previous stored scan, if any.
        Returns:
            str: Section body.
        '''
        c = self.report.comparison
        if c is None:
            return '<p class="muted">No previous scan of this target was stored; nothing to compare.</p>'
        kinds = {"added": "ok", "removed": "failed", "modified": "partial", "unknown": "skipped", "unchanged": "skipped"}
        cards = "".join(f'<div class="card"><div class="num">{v}</div><div class="label">{escape(k)}</div></div>'
                        for k, v in c.counts.items())
        rows = [(self._pill(ch.kind.value, kinds[ch.kind.value]), ch.type, ch.target, ch.key,
                 self._code(json.dumps(ch.previous, ensure_ascii=False)) if ch.previous is not None else None,
                 self._code(json.dumps(ch.current, ensure_ascii=False)) if ch.current is not None else None, ch.reason)
                for ch in c.changes]
        return (f"<p>Compared with {self._code(c.previous.scan_id)} ({c.previous.started_at:%Y-%m-%d %H:%M:%S} UTC).</p>"
                f'<div class="cards">{cards}</div>'
                + self._table(["Change", "Type", "Target", "Key", "Previous", "Current", "Reason"], rows)
                + self._note(c.note))

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
        out = self._table(["Provider", "Category", "Domains", "Sources", "Confidence", "Evidence"],
                          [(Safe(f"<strong>{escape(s.provider)}</strong>"), s.category, s.domains, s.sources,
                            self._pill(s.confidence.value, s.confidence.value), s.evidence) for s in known])
        if unknown:
            out += "<h3>Unrecognized external domains</h3>" + self._table(
                ["Domain group", "Hosts", "Sources", "Confidence", "Evidence"],
                [(s.provider, s.domains, s.sources, self._pill(s.confidence.value, s.confidence.value), s.evidence)
                 for s in unknown])
        return out

    def _infrastructure(self) -> str:
        '''
        Render inferred infrastructure providers.
        Returns:
            str: Section body.
        '''
        return self._table(["Provider", "Category", "Role", "Subjects", "Evidence", "Source", "Confidence", "Note"],
                           [(Safe(f"<strong>{escape(o.provider)}</strong>"), o.category, o.role, o.subjects,
                             o.evidence, o.source, self._pill(o.confidence.value, o.confidence.value), o.note)
                            for o in self.report.analysis.infrastructure])

    def _errors(self) -> str:
        '''
        Render collection errors and limitations.
        Returns:
            str: Section body.
        '''
        r = self.report
        out = (self._table(["Module", "Target", "Type", "Message", "Time"],
                           [(e.module, e.target, e.error_type, e.message, e.timestamp) for e in r.errors])
               if r.errors else '<p class="muted">No collection errors.</p>')
        return out + "<h3>Limitations</h3><ul>" + "".join(f"<li>{escape(x)}</li>" for x in r.limitations) + "</ul>"

    def _raw(self) -> str:
        '''
        Render every module's complete result as formatted JSON.
        Returns:
            str: Section body.
        '''
        out = [self._note("Complete collected data for each module, identical to raw/<module>.json.")]
        for name, result in self.report.module_results().items():
            payload = json.dumps(result.model_dump(mode="json"), indent=2, ensure_ascii=False)
            out.append(f"<details><summary>{self._pill(result.status.value, result.status.value)} "
                       f"{escape(name)} <span class=\"muted\">({len(payload):,} bytes)</span></summary>"
                       f"<pre>{escape(payload)}</pre></details>")
        analysis = json.dumps(self.report.analysis.model_dump(mode="json"), indent=2, ensure_ascii=False)
        out.append(f"<details><summary>analysis</summary><pre>{escape(analysis)}</pre></details>")
        return "".join(out)

    @staticmethod
    def _sources() -> str:
        '''
        Render the list of data sources and references.
        Returns:
            str: Section body.
        '''
        items = [
            "DNS: system-configured recursive resolver (dnspython)",
            "ASN: Team Cymru IP-to-ASN mapping via DNS (origin.asn.cymru.com)",
            "IP allocation: RDAP via rdap.org bootstrap → Regional Internet Registries",
            "Domain registration: RDAP via IANA bootstrap, WHOIS (port 43) fallback",
            "Subdomains: Certificate Transparency search at crt.sh",
            "HTML, technology and third-party analysis: derived from the fetched landing page and headers",
            "RFC 7208 (SPF), RFC 7489 (DMARC), RFC 6797 (HSTS), RFC 8659 (CAA), RFC 8996 (TLS 1.0/1.1 deprecation)",
        ]
        return "<ul>" + "".join(f"<li>{escape(i)}</li>" for i in items) + "</ul>"