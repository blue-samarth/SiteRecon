'''
Report writers for an ``ActiveReport`` (JSON, Markdown, HTML).

Kept visually distinct from the passive report — every rendering leads with an ACTIVE TESTING banner
so results are never mistaken for passive recon. Values coming from the target are escaped; the
request log shows query-redacted URLs only.
'''

from __future__ import annotations

from collections.abc import Iterable
from html import escape
from pathlib import Path
from typing import Any

from recon.active.models import ActiveReport
from recon.models import Finding, ModuleStatus, Severity
from recon.reporting.html_theme import CSS

_SEVERITY_ICON: dict[Severity, str] = {
    Severity.CRITICAL: "🟥", Severity.HIGH: "🟧", Severity.MEDIUM: "🟨",
    Severity.LOW: "🟦", Severity.INFORMATIONAL: "⬜",
}
_STATUS_ICON: dict[ModuleStatus, str] = {
    ModuleStatus.SUCCESS: "✅", ModuleStatus.PARTIAL: "⚠️", ModuleStatus.FAILED: "❌", ModuleStatus.SKIPPED: "⬚",
}


class ActiveJsonReportWriter:
    '''
    Writes active.json.
    '''

    def __init__(self, report: ActiveReport) -> None:
        '''
        Create the writer.
        Parameters:
            report (ActiveReport): The report to render.
        '''
        self.report = report

    def write(self, directory: Path) -> list[Path]:
        '''
        Write active.json.
        Parameters:
            directory (Path): Directory to write into; created if missing.
        Returns:
            list[Path]: Path of the file written.
        Raises:
            OSError: If the directory cannot be written.
        '''
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "active.json"
        path.write_text(self.report.model_dump_json(indent=2), encoding="utf-8")
        return [path]


class ActiveMarkdownReportWriter:
    '''
    Writes active.md.
    '''

    def __init__(self, report: ActiveReport) -> None:
        '''
        Create the writer.
        Parameters:
            report (ActiveReport): The report to render.
        '''
        self.report = report

    def write(self, directory: Path) -> list[Path]:
        '''
        Render Markdown and write active.md.
        Parameters:
            directory (Path): Directory to write into; created if missing.
        Returns:
            list[Path]: Path of the file written.
        Raises:
            OSError: If the directory cannot be written.
        '''
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "active.md"
        path.write_text(self.render(), encoding="utf-8")
        return [path]

    def render(self) -> str:
        '''
        Render the full active report as Markdown.
        Returns:
            str: Markdown text.
        '''
        r = self.report
        out = [f"# Active Testing Report: `{r.target.hostname}`", "",
               f"> ⚠️ **{r.notice}**", "",
               "## 1. Authorization", "", self._auth(), "",
               "## 2. Checks Run", "", self._checks(), "",
               "## 3. Findings", "", self._findings(), "",
               "## 4. Request Audit Log", "", self._log(), ""]
        return "\n".join(out)

    def _auth(self) -> str:
        '''
        Render the authorization summary table.
        Returns:
            str: Markdown.
        '''
        a = self.report.authorization
        rows = [("Target", a.get("target")), ("Authorized by", a.get("authorized_by")),
                ("Authorized on", a.get("authorized_on")),
                ("Window", f"{a['window']['start']} .. {a['window']['end']}"),
                ("Within window", "yes" if self.report.window_ok else "**NO — outside authorized window**"),
                ("Scope hosts", ", ".join(a.get("scope_hosts", [])) or "—"),
                ("TLS-authorized hosts", ", ".join(a.get("tls_authorized_hosts", [])) or "—"),
                ("Checks enabled", ", ".join(a.get("checks_enabled", [])) or "—"),
                ("Rate limit (rps)", a.get("rate_limit_rps")), ("Request budget", a.get("max_requests")),
                ("Requests made", f"{self.report.requests_made} / {self.report.request_budget}")]
        return _table(["Field", "Value"], rows)

    def _checks(self) -> str:
        '''
        Render the per-check status table.
        Returns:
            str: Markdown.
        '''
        rows = [(f"{_STATUS_ICON[c.status]} {c.status.value}", c.check_id, c.requests_made, len(c.findings),
                 c.skipped_reason or "") for c in self.report.checks]
        return _table(["Status", "Check", "Requests", "Findings", "Skip reason"], rows) if rows else "_No checks enabled._"

    def _findings(self) -> str:
        '''
        Render findings grouped most-severe-first.
        Returns:
            str: Markdown.
        '''
        findings = self.report.findings()
        if not findings:
            return "_No findings._"
        out = [_table(["", "Severity", "Title", "Subject"],
                      [(_SEVERITY_ICON[f.severity], f.severity.value, f.title, f.subject) for f in findings])]
        for f in findings:
            out += ["", f"#### {_SEVERITY_ICON[f.severity]} {f.title} — `{f.subject}`", "", f.description, "",
                    f"- **ID:** `{f.id}`  ", f"- **Severity / confidence:** {f.severity.value} / {f.confidence.value}  ",
                    f"- **Source:** {f.source}  "]
            if f.recommendation:
                out.append(f"- **Recommendation:** {f.recommendation}  ")
            if f.limitations:
                out.append(f"- **Limitations:** {f.limitations}  ")
            out.append("- **Evidence:**")
            out += [f"  - `{_cell(e)}`" for e in f.evidence]
        return "\n".join(out)

    def _log(self) -> str:
        '''
        Render the request audit log.
        Returns:
            str: Markdown.
        '''
        if not self.report.request_log:
            return f"_No requests were made ({self.report.requests_made} / {self.report.request_budget})._"
        rows = [(e.check_id, e.method, e.url, e.status, e.note or "") for e in self.report.request_log]
        return (f"Total requests: **{self.report.requests_made}** / {self.report.request_budget} budget.\n\n"
                + _table(["Check", "Method", "URL", "Status", "Note"], rows))


class ActiveHtmlReportWriter:
    '''
    Writes a self-contained active.html.
    '''

    CSP: str = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"

    def __init__(self, report: ActiveReport) -> None:
        '''
        Create the writer.
        Parameters:
            report (ActiveReport): The report to render.
        '''
        self.report = report

    def write(self, directory: Path) -> list[Path]:
        '''
        Render HTML and write active.html.
        Parameters:
            directory (Path): Directory to write into; created if missing.
        Returns:
            list[Path]: Path of the file written.
        Raises:
            OSError: If the directory cannot be written.
        '''
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "active.html"
        path.write_text(self.render(), encoding="utf-8")
        return [path]

    def render(self) -> str:
        '''
        Render the self-contained HTML page.
        Returns:
            str: HTML document.
        '''
        r = self.report
        host = escape(r.target.hostname)
        body = (f'<div class="banner">⚠️ {escape(r.notice)}</div>'
                f"<header><h1>Active Testing <code>{host}</code></h1>"
                f'<p class="muted">{escape(r.tool["name"])} {escape(r.tool["version"])} · '
                f'{r.started_at:%Y-%m-%d %H:%M:%S} UTC · {r.requests_made}/{r.request_budget} requests</p></header>'
                '<main class="active-wrap">'
                f'<section><h2>Authorization</h2>{self._auth()}</section>'
                f'<section><h2>Checks Run</h2>{self._checks()}</section>'
                f'<section><h2>Findings</h2>{self._findings()}</section>'
                f'<section><h2>Request Audit Log</h2>{self._log()}</section>'
                "</main>")
        extra = (".banner{background:var(--bad);color:#fff;padding:10px 24px;font-weight:600;text-align:center}"
                 ".win-bad{color:var(--bad);font-weight:700}"
                 ".active-wrap{max-width:1360px;margin:0 auto;padding:8px 40px 96px}"
                 "@media (max-width:900px){.active-wrap{padding:8px 16px 48px}}")
        return ("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
                f'<meta http-equiv="Content-Security-Policy" content="{self.CSP}">'
                '<meta name="viewport" content="width=device-width, initial-scale=1">'
                f"<title>Active testing: {host}</title><style>{CSS}{extra}</style></head><body>{body}</body></html>\n")

    def _auth(self) -> str:
        '''
        Render the authorization summary.
        Returns:
            str: HTML.
        '''
        a = self.report.authorization
        within = ('<span class="yes">yes</span>' if self.report.window_ok
                  else '<span class="win-bad">NO — outside authorized window</span>')
        return _kv([("Target", a.get("target")), ("Authorized by", a.get("authorized_by")),
                    ("Authorized on", a.get("authorized_on")),
                    ("Window", f"{a['window']['start']} .. {a['window']['end']}"),
                    ("Within window", _safe(within)), ("Scope hosts", a.get("scope_hosts")),
                    ("TLS-authorized hosts", a.get("tls_authorized_hosts")),
                    ("Checks enabled", a.get("checks_enabled")),
                    ("Rate limit (rps)", a.get("rate_limit_rps")),
                    ("Requests made", f"{self.report.requests_made} / {self.report.request_budget}")])

    def _checks(self) -> str:
        '''
        Render the checks table.
        Returns:
            str: HTML.
        '''
        rows = [(f"{_STATUS_ICON[c.status]} {c.status.value}", c.check_id, c.requests_made, len(c.findings),
                 c.skipped_reason) for c in self.report.checks]
        return _html_table(["Status", "Check", "Requests", "Findings", "Skip reason"], rows)

    def _findings(self) -> str:
        '''
        Render findings as cards.
        Returns:
            str: HTML.
        '''
        findings = self.report.findings()
        if not findings:
            return '<p class="muted">No findings.</p>'
        return "".join(self._finding_card(f) for f in findings)

    def _finding_card(self, f: Finding) -> str:
        '''
        Render one finding.
        Parameters:
            f (Finding): The finding.
        Returns:
            str: HTML.
        '''
        evidence = "".join(f"<li><code>{escape(e)}</code></li>" for e in f.evidence) or '<li class="muted">—</li>'
        return (f'<details class="finding" open><summary>'
                f'<span class="pill {f.severity.value}">{_SEVERITY_ICON[f.severity]} {escape(f.severity.value)}</span> '
                f'<b>{escape(f.title)}</b> <span class="muted">{escape(f.subject)}</span></summary>'
                f"<p>{escape(f.description)}</p>"
                + _kv([("ID", _code(f.id)), ("Confidence", f.confidence.value), ("Source", f.source),
                       ("Recommendation", f.recommendation), ("Limitations", f.limitations)])
                + f"<h4>Evidence</h4><ul>{evidence}</ul></details>")

    def _log(self) -> str:
        '''
        Render the request audit log.
        Returns:
            str: HTML.
        '''
        if not self.report.request_log:
            return f'<p class="muted">No requests ({self.report.requests_made}/{self.report.request_budget}).</p>'
        rows = [(e.check_id, e.method, _code(e.url), e.status, e.note) for e in self.report.request_log]
        return (f"<p>Total requests: <b>{self.report.requests_made}</b> / {self.report.request_budget} budget.</p>"
                + _html_table(["Check", "Method", "URL", "Status", "Note"], rows))


# --------------------------------------------------------------------------- shared helpers

class _Safe(str):
    '''
    Marks an already-escaped HTML fragment.
    '''


def _safe(value: str) -> _Safe:
    '''
    Wrap pre-escaped HTML so helpers do not escape it again.
    Parameters:
        value (str): Already-escaped HTML.
    Returns:
        _Safe: Marked value.
    '''
    return _Safe(value)


def _code(text: Any) -> _Safe:
    '''
    Render a value as inline code.
    Parameters:
        text (Any): Value.
    Returns:
        _Safe: HTML.
    '''
    return _Safe(f"<code>{escape(str(text))}</code>")


def _he(value: Any) -> str:
    '''
    Escape a value for an HTML cell.
    Parameters:
        value (Any): Value to display.
    Returns:
        str: Safe HTML ('—' for empty).
    '''
    if isinstance(value, _Safe):
        return value
    if value is None or value == "" or value == []:
        return '<span class="muted">—</span>'
    if isinstance(value, (list, tuple)):
        return "<br>".join(_he(v) for v in value)
    return escape(str(value))


def _kv(pairs: Iterable[tuple[str, Any]]) -> str:
    '''
    Render a two-column field/value table.
    Parameters:
        pairs (Iterable[tuple[str, Any]]): (label, value) pairs.
    Returns:
        str: HTML.
    '''
    body = "".join(f"<tr><th>{escape(k)}</th><td>{_he(v)}</td></tr>" for k, v in pairs)
    return f'<div class="scroll"><table class="kv"><tbody>{body}</tbody></table></div>'


def _html_table(headers: list[str], rows: Iterable[Iterable[Any]]) -> str:
    '''
    Render a data table.
    Parameters:
        headers (list[str]): Column headers.
        rows (Iterable[Iterable[Any]]): Row values.
    Returns:
        str: HTML, or an empty-state note.
    '''
    rows = list(rows)
    if not rows:
        return '<p class="muted">No data.</p>'
    head = "".join(f"<th>{escape(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{_he(c)}</td>" for c in row) + "</tr>" for row in rows)
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _cell(value: Any) -> str:
    '''
    Format a Markdown table cell (escape pipes/newlines).
    Parameters:
        value (Any): Cell value.
    Returns:
        str: Escaped text.
    '''
    if value is None or value == "":
        return "—"
    return str(value).replace("|", "\\|").replace("\n", " ")


def _table(headers: list[str], rows: Iterable[Iterable[Any]]) -> str:
    '''
    Render a Markdown table.
    Parameters:
        headers (list[str]): Column headers.
        rows (Iterable[Iterable[Any]]): Row values.
    Returns:
        str: Table text, or an empty-state note.
    '''
    rows = list(rows)
    if not rows:
        return "_No data._"
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)
