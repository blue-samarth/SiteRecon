'''
Visual theme for the self-contained HTML report.

System fonts only (the CSP blocks external resources), no JavaScript.
'''

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from html import escape
from typing import Any

NAV_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Overview", ("summary", "target", "findings", "changes")),
    ("Network", ("dns", "dnssec", "network", "tls", "whois")),
    ("Web", ("http", "resources", "technology", "html", "crawl", "assets", "cookies")),
    ("Discovery", ("subdomains", "third-party", "infrastructure")),
    ("Reference", ("errors", "raw", "sources")),
)


def nav_html(sections: Iterable[tuple[str, str]]) -> str:
    '''
    Render the grouped side navigation.
    Parameters:
        sections (Iterable[tuple[str, str]]): (section id, title) pairs.
    Returns:
        str: Safe HTML.
    '''
    titles = dict(sections)
    out = []
    for label, ids in NAV_GROUPS:
        links = "".join(f'<a href="#{i}">{escape(titles[i])}</a>' for i in ids if i in titles)
        out.append(f'<div class="group"><p>{escape(label)}</p>{links}</div>')
    return "".join(out)


def header_html(host: str, tool: str, version: str, started: datetime, duration_s: float) -> str:
    '''
    Render the page header: hostname as the title plus run metadata.
    Parameters:
        host (str): Normalized target hostname.
        tool (str): Tool name.
        version (str): Tool version.
        started (datetime): Scan start time (UTC).
        duration_s (float): Scan duration in seconds.
    Returns:
        str: Safe HTML.
    '''
    return (
        f'<header><h1>{escape(host)}</h1>'
        '<p class="sub">Reconnaissance report. Passive collection from an authorized target.</p>'
        '<dl class="meta">'
        f'<div><dt>Scanned</dt><dd>{started:%Y-%m-%d %H:%M:%S} UTC</dd></div>'
        f'<div><dt>Duration</dt><dd>{duration_s:.1f}s</dd></div>'
        f'<div><dt>Tool</dt><dd>{escape(tool)} {escape(version)}</dd></div>'
        '</dl></header>'
    )


def severity_bar(counts: Mapping[str, int], order: Iterable[Any]) -> str:
    '''
    Render the proportional severity bar with a count legend.
    Parameters:
        counts (Mapping[str, int]): Severity value to count.
        order (Iterable[Severity]): Severities from most to least serious.
    Returns:
        str: Safe HTML.
    '''
    order = list(order)
    total = sum(counts.get(s.value, 0) for s in order)
    if total:
        segs = "".join(f'<span class="seg {s.value}" style="flex:{counts[s.value]}"></span>'
                       for s in order if counts.get(s.value, 0))
        label = ", ".join(f"{counts.get(s.value, 0)} {s.value}" for s in order)
        bar = f'<div class="sevbar" role="img" aria-label="Findings by severity: {escape(label)}">{segs}</div>'
    else:
        bar = '<div class="sevbar empty" role="img" aria-label="No findings"></div>'
    legend = "".join(
        f'<li class="{s.value}{"" if counts.get(s.value, 0) else " zero"}">'
        f'<b>{counts.get(s.value, 0)}</b><span>{escape(s.value)}</span></li>' for s in order)
    return f'<div class="sev">{bar}<ul class="legend">{legend}</ul></div>'


CSS = """
:root{color-scheme:light dark;
--bg:#eef1ef;--surface:#fbfcfb;--sunk:#e4e9e6;--text:#16211f;--muted:#5b6a66;--line:#d6ddd9;--accent:#0f6b62;
--crit:#b3261e;--high:#c2490f;--med:#946c00;--low:#2468a8;--info:#66736f;--ok:#237a43;--bad:#b3261e;--warn:#946c00;
--serif:"Iowan Old Style","Palatino Linotype",Palatino,Charter,Georgia,serif;
--sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;
--mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#0c1211;--surface:#121a18;--sunk:#0a0f0e;--text:#e3ebe8;
--muted:#8fa09b;--line:#223230;--accent:#5fd3c0;--crit:#ff7b72;--high:#ffa066;--med:#e7c04a;--low:#79b8ff;
--info:#8fa09b;--ok:#6fd48f;--bad:#ff7b72;--warn:#e7c04a}}
*{box-sizing:border-box}
html{scroll-padding-top:20px}
@media (prefers-reduced-motion:no-preference){html{scroll-behavior:smooth}}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 var(--sans);-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-underline-offset:2px}
a:focus-visible,summary:focus-visible,.filter input:focus-visible+label{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}

header{max-width:1360px;margin:0 auto;padding:64px 40px 8px}
h1{margin:0;font:400 clamp(34px,6vw,60px)/1.05 var(--serif);letter-spacing:-.02em;overflow-wrap:anywhere}
.sub{margin:14px 0 0;color:var(--muted);font-size:16px}
.meta{display:flex;flex-wrap:wrap;gap:12px 40px;margin:28px 0 0;padding:0}
.meta div{display:flex;flex-direction:column;gap:2px}
.meta dt{font-size:12.5px;color:var(--muted)}.meta dd{margin:0;font-size:14px}

.layout{max-width:1360px;margin:0 auto;padding:24px 40px 96px;display:grid;grid-template-columns:210px minmax(0,1fr);gap:56px;align-items:start}
nav{position:sticky;top:24px;max-height:calc(100vh - 48px);overflow:auto;padding-right:4px}
.group p{margin:22px 0 4px;padding:0 10px;font-size:12.5px;font-weight:600;color:var(--muted)}
.group:first-child p{margin-top:0}
nav a{display:block;padding:5px 10px;border-radius:6px;color:var(--text);opacity:.78;text-decoration:none;font-size:14px}
nav a:hover{background:var(--sunk);opacity:1}
main{min-width:0}
section{padding:44px 0 40px;border-top:1px solid var(--line)}
section:first-child{border-top:0;padding-top:12px}
h2{margin:0 0 20px;font:500 28px/1.2 var(--serif);letter-spacing:-.01em}
h3{margin:32px 0 10px;font-size:15px;font-weight:600}
h4{margin:20px 0 8px;font-size:13px;font-weight:600;color:var(--muted)}
main p{max-width:80ch}

.scroll{overflow-x:auto;background:var(--surface);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{text-align:left;vertical-align:top;padding:9px 14px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}
tbody tr:last-child>*{border-bottom:0}
tbody tr:hover>td{background:color-mix(in srgb,var(--sunk) 45%,transparent)}
thead th{background:color-mix(in srgb,var(--sunk) 55%,var(--surface));color:var(--muted);font-size:12.5px;font-weight:600;white-space:nowrap}
table.kv th{width:210px;color:var(--muted);font-weight:500;white-space:normal}
table.kv tr:hover>td{background:none}

code,pre{font:12.5px/1.5 var(--mono)}
code{background:var(--sunk);padding:1px 6px;border-radius:4px;overflow-wrap:anywhere}
pre{background:var(--sunk);border:1px solid var(--line);padding:14px 16px;border-radius:8px;overflow:auto;max-height:520px;white-space:pre-wrap;overflow-wrap:anywhere}
pre code,td code{background:none;padding:0}
.muted{color:var(--muted)}.yes{color:var(--ok);font-weight:600}.no{color:var(--bad);font-weight:600}.bad{color:var(--bad)}
.note{color:var(--muted);font-size:13px;border-left:2px solid var(--accent);padding:2px 0 2px 12px;margin:14px 0}
.notice{padding:12px 14px;border-radius:8px;background:var(--sunk)}
.notice.bad{background:color-mix(in srgb,var(--bad) 10%,var(--surface))}

.pill{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12px;font-weight:600;line-height:1.6;
background:color-mix(in srgb,currentColor 13%,transparent);white-space:nowrap}
@supports not (color:color-mix(in srgb,red,blue)){.pill{border:1px solid currentColor}}
.critical{color:var(--crit)}.high{color:var(--high)}.medium{color:var(--med)}.low{color:var(--low)}
.informational{color:var(--info)}.ok,.success{color:var(--ok)}.partial{color:var(--warn)}.failed{color:var(--bad)}
.skipped{color:var(--muted)}

.sev{margin:4px 0 28px}
.sevbar{display:flex;gap:3px;height:16px;border-radius:8px;overflow:hidden}
.sevbar.empty{background:var(--line)}
.seg{background:currentColor;min-width:12px}
.legend{display:flex;flex-wrap:wrap;gap:12px 40px;list-style:none;margin:18px 0 0;padding:0}
.legend li{display:flex;flex-direction:column}
.legend b{font:400 38px/1 var(--serif)}
.legend span{margin-top:4px;color:var(--muted);font-size:13px;text-transform:capitalize}
.legend li.zero{opacity:.4}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:12px;margin-bottom:18px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card .num{font:400 30px/1.1 var(--serif)}.card .label{font-size:13px;color:var(--muted);text-transform:capitalize}

details{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:12px 18px;margin:10px 0}
details details{background:var(--bg)}
summary{cursor:pointer;font-weight:500;list-style:none}
summary::-webkit-details-marker{display:none}
summary::before{content:"";display:inline-block;width:6px;height:6px;margin:0 12px 2px 2px;border-right:2px solid var(--muted);
border-bottom:2px solid var(--muted);transform:rotate(-45deg);transition:transform .15s}
details[open]>summary::before{transform:rotate(45deg)}
details[open]>summary{margin-bottom:12px}
@media (prefers-reduced-motion:reduce){summary::before{transition:none}}
.finding{border-left:4px solid var(--info)}
.finding[data-sev=critical]{border-left-color:var(--crit)}.finding[data-sev=high]{border-left-color:var(--high)}
.finding[data-sev=medium]{border-left-color:var(--med)}.finding[data-sev=low]{border-left-color:var(--low)}
.finding .title{font-weight:600}.finding .subject{font-size:13px;margin-left:6px}
.filter{display:flex;flex-wrap:wrap;gap:6px;margin:14px 0 10px}.filter input{position:absolute;opacity:0;pointer-events:none}
.filter label{padding:3px 12px;border:1px solid var(--line);border-radius:999px;cursor:pointer;font-size:13px;text-transform:capitalize;background:var(--surface)}
.filter input:checked+label{background:var(--text);border-color:var(--text);color:var(--bg)}
.findings:has(#sev-critical:checked) .finding:not([data-sev=critical]),
.findings:has(#sev-high:checked) .finding:not([data-sev=high]),
.findings:has(#sev-medium:checked) .finding:not([data-sev=medium]),
.findings:has(#sev-low:checked) .finding:not([data-sev=low]),
.findings:has(#sev-informational:checked) .finding:not([data-sev=informational]){display:none}
.chips{display:flex;flex-wrap:wrap;gap:6px}.chips span{background:var(--surface);border:1px solid var(--line);
border-radius:999px;padding:2px 11px;font-size:13px}

@media (max-width:900px){
header{padding:40px 20px 0}.layout{grid-template-columns:1fr;gap:8px;padding:16px 20px 64px}
nav{position:static;max-height:none;display:flex;gap:4px;overflow-x:auto;padding-bottom:8px;border-bottom:1px solid var(--line)}
.group{display:contents}.group p{display:none}nav a{white-space:nowrap}
section{padding:32px 0 28px}table.kv th{width:auto}.legend{gap:12px 28px}}
@media print{nav{display:none}.layout{display:block;padding:0}body{background:#fff}
section,details,.scroll{break-inside:avoid}}
"""