'''
Command-line interface and terminal presentation.
'''

from __future__ import annotations

import asyncio
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, ClassVar

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from recon.active import (
    ActiveOrchestrator,
    ActiveReport,
    AuthorizationError,
    AuthorizationFile,
    load_authorization,
)
from recon.active.inventory import Inventory, build_inventory, read_inventory, write_inventory
from recon.analysis import ScanComparator
from recon.config import ALL_MODULES, Config, OutputFormat
from recon.models import ChangeKind, ComparisonResult, ModuleStatus, ReconReport, Severity
from recon.orchestrator import ScanHistory, ScanOrchestrator
from recon.reporting import (
    ActiveHtmlReportWriter,
    ActiveJsonReportWriter,
    ActiveMarkdownReportWriter,
    ComparisonReportWriter,
    HtmlReportWriter,
    JsonReportWriter,
    MarkdownReportWriter,
    ReportWriter,
)
from recon.storage import JsonScanStore
from recon.utils import InvalidTargetError, normalize_target, redact_url, setup_logging

app: typer.Typer = typer.Typer(add_completion=False, no_args_is_help=True, rich_markup_mode="rich")
console: Console = Console()

SUBCOMMANDS: frozenset[str] = frozenset({"scan", "history", "compare", "active"})


@contextmanager
def _progress_bar(description: str, total: int) -> Iterator[tuple[Callable[[str], None], Callable[[str], None]]]:
    '''
    Show a determinate progress bar and yield (advance, set_item) callbacks.

    So nobody stares at a blank screen, both passive and active runs drive this bar as each unit of
    work completes. ``advance(item)`` moves the bar one step and shows the finished item beside it;
    ``set_item(item)`` only updates the label (e.g. the step currently running), without advancing.
    Parameters:
        description (str): The fixed label at the left of the bar (e.g. 'Passive recon').
        total (int): Total number of steps the bar represents.
    Returns:
        Iterator[tuple[Callable[[str], None], Callable[[str], None]]]: Context manager yielding
            (advance, set_item). Call advance once per step.
    '''
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn("[dim]{task.fields[item]}[/dim]"),
        TimeElapsedColumn(),
        console=console,
    )
    with progress:
        task = progress.add_task(description, total=total, item="")

        def advance(item: str = "") -> None:
            progress.update(task, advance=1, item=item)

        def set_item(item: str = "") -> None:
            progress.update(task, item=item)

        yield advance, set_item


@app.command(help="Passive reconnaissance of a domain you own or are authorized to assess.")
def scan(
    domain: Annotated[str, typer.Argument(help="Target domain or URL (must be authorized).")],
    output_format: Annotated[OutputFormat, typer.Option(
        "--format", "-f", help="Report format: json, markdown, html, both (json+markdown) or all.")] = OutputFormat.ALL,
    output: Annotated[Path, typer.Option("--output", "-o", help="Report directory.")] = Path("reports"),
    modules: Annotated[str | None, typer.Option(
        "--modules", "-m", help=f"Comma-separated modules to run (default: all). Choices: {', '.join(ALL_MODULES)}.")] = None,
    timeout: Annotated[float, typer.Option(min=1, max=120, help="Per-request timeout (s).")] = 10.0,
    retries: Annotated[int, typer.Option(min=0, max=5, help="Retries for transient failures.")] = 2,
    concurrency: Annotated[int, typer.Option(min=1, max=50, help="Maximum concurrent requests.")] = 10,
    subdomains: Annotated[bool, typer.Option("--subdomains/--no-subdomains", help="CT subdomain discovery.")] = True,
    probe_subdomains: Annotated[bool, typer.Option(
        "--probe-subdomains", help="Also check HTTPS and TLS on each discovered subdomain that resolves.")] = False,
    max_subdomains: Annotated[int, typer.Option(min=0, max=1000, help="Max CT names to verify.")] = 100,
    whois: Annotated[bool, typer.Option("--whois/--no-whois", help="Domain registration lookup.")] = True,
    crawl: Annotated[bool, typer.Option("--crawl", help="Crawl in-scope pages linked from the site.")] = False,
    depth: Annotated[int, typer.Option(min=0, max=5, help="Crawl depth from the start page.")] = 1,
    max_pages: Annotated[int, typer.Option(min=1, max=500, help="Maximum pages to crawl.")] = 25,
    crawl_delay: Annotated[float, typer.Option(min=0, max=10, help="Delay between crawl requests (s).")] = 0.25,
    ignore_robots: Annotated[bool, typer.Option(
        "--ignore-robots", help="Crawl paths disallowed by robots.txt (only with explicit authorization).")] = False,
    max_assets: Annotated[int, typer.Option(min=0, max=200, help="Maximum JS/CSS assets to download and analyze.")] = 30,
    asset_host: Annotated[list[str] | None, typer.Option(
        "--asset-host", help="External host allowed for asset downloads (repeatable; e.g. a CDN you operate).")] = None,
    history: Annotated[bool, typer.Option("--history/--no-history", help="Store the scan and compare with the previous one.")] = True,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Detailed execution logs.")] = False,
    allow_private_networks: Annotated[bool, typer.Option(
        "--allow-private-networks",
        help="Permit requests to private/loopback addresses (authorized internal assessments only).")] = False,
) -> None:
    '''
    Passive reconnaissance of a domain you own or are authorized to assess.
    Parameters:
        domain (str): Target domain or URL.
        output_format (OutputFormat): Report format (json, markdown, html, both or all).
        output (Path): Base report directory; reports go to <output>/<hostname>/.
        modules (str | None): Comma-separated module names, or None for all.
        timeout (float): Per-request timeout in seconds.
        retries (int): Retries for transient failures.
        concurrency (int): Maximum concurrent requests.
        subdomains (bool): Run Certificate Transparency subdomain discovery.
        probe_subdomains (bool): Check HTTPS and TLS on discovered names that resolve publicly.
        max_subdomains (int): Maximum discovered names to verify.
        whois (bool): Run the domain registration lookup.
        crawl (bool): Crawl in-scope pages.
        depth (int): Crawl depth.
        max_pages (int): Maximum pages to crawl.
        crawl_delay (float): Delay between crawl requests in seconds.
        ignore_robots (bool): Crawl paths disallowed by robots.txt.
        max_assets (int): Maximum JS/CSS assets to download.
        asset_host (list[str] | None): External hosts allowed for asset downloads.
        history (bool): Store the scan and compare with the previous scan.
        verbose (bool): Enable detailed execution logs.
        allow_private_networks (bool): Permit requests to private/loopback addresses.
    Raises:
        typer.Exit: Code 2 for invalid input, 1 when every module that ran failed.
    '''
    setup_logging(verbose)
    try:
        hostname = normalize_target(domain)
    except InvalidTargetError as exc:
        console.print(f"[red]Invalid target:[/red] {exc}")
        raise typer.Exit(2) from exc
    selected = _parse_modules(modules)
    try:
        asset_hosts = tuple(normalize_target(h) for h in asset_host or [])
    except InvalidTargetError as exc:
        console.print(f"[red]Invalid --asset-host:[/red] {exc}")
        raise typer.Exit(2) from exc

    config = Config(
        target_input=domain, hostname=hostname, output_dir=output, output_format=output_format,
        timeout=timeout, retries=retries, concurrency=concurrency, subdomains=subdomains, verbose=verbose,
        allow_private_networks=allow_private_networks, probe_subdomains=probe_subdomains,
        max_subdomains=max_subdomains, whois=whois, modules=selected, crawl=crawl, crawl_depth=depth,
        max_pages=max_pages, crawl_delay=crawl_delay, respect_robots=not ignore_robots, history=history,
        max_assets=max_assets, asset_hosts=asset_hosts,
    )
    console.print(f"[bold]Scanning[/bold] {hostname} [dim](passive; authorized targets only)[/dim]")
    with _progress_bar("Passive recon", ScanOrchestrator.MODULE_COUNT) as (advance, _set):
        report = asyncio.run(ScanOrchestrator(config).run(progress=advance))

    directory = output / hostname
    written: list[Path] = []
    if config.history:
        written.append(Path(ScanHistory(JsonScanStore(output)).record(report)))
        if report.comparison:
            written += ComparisonReportWriter(report.comparison).write(directory)

    writers: list[ReportWriter] = []
    if config.wants_json:
        writers.append(JsonReportWriter(report))
    if config.wants_markdown:
        writers.append(MarkdownReportWriter(report))
    if config.wants_html:
        writers.append(HtmlReportWriter(report))
    written = [path for writer in writers for path in writer.write(directory)] + written

    TerminalSummary(console).print(report)
    console.print("\n[bold]Reports[/bold]")
    for path in written:
        console.print(f"  {path}")

    ran = [m for m in report.module_results().values() if m.status is not ModuleStatus.SKIPPED]
    if ran and all(m.status is ModuleStatus.FAILED for m in ran):
        raise typer.Exit(1)


@app.command(name="history", help="List stored scans of a target.")
def history_cmd(
    domain: Annotated[str, typer.Argument(help="Target domain or URL.")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Report directory.")] = Path("reports"),
) -> None:
    '''
    List stored scans of a target, oldest first.
    Parameters:
        domain (str): Target domain or URL.
        output (Path): Report directory containing the history.
    Raises:
        typer.Exit: Code 2 for invalid input.
    '''
    try:
        hostname = normalize_target(domain)
    except InvalidTargetError as exc:
        console.print(f"[red]Invalid target:[/red] {exc}")
        raise typer.Exit(2) from exc
    refs = JsonScanStore(output).list(hostname)
    if not refs:
        console.print(f"No stored scans for {hostname} in {output}.")
        return
    table = Table(title=f"Scans of {hostname}", title_justify="left")
    table.add_column("Scan ID")
    table.add_column("Started (UTC)")
    for ref in refs:
        table.add_row(ref.scan_id, f"{ref.started_at:%Y-%m-%d %H:%M:%S}")
    console.print(table)


@app.command(name="compare", help="Compare two stored scans (or the latest two of --target).")
def compare_cmd(
    previous: Annotated[str | None, typer.Argument(help="Previous scan ID.")] = None,
    current: Annotated[str | None, typer.Argument(help="Current scan ID.")] = None,
    target: Annotated[str | None, typer.Option("--target", "-t", help="Compare the two latest scans of this target.")] = None,
    output: Annotated[Path, typer.Option("--output", "-o", help="Report directory.")] = Path("reports"),
) -> None:
    '''
    Compare two stored scans and write changes.json / changes.md.
    Parameters:
        previous (str | None): Previous scan ID.
        current (str | None): Current scan ID.
        target (str | None): Target whose two latest scans are compared (instead of IDs).
        output (Path): Report directory containing the history.
    Raises:
        typer.Exit: Code 2 for invalid arguments or unknown scans.
    '''
    store = JsonScanStore(output)
    try:
        if target:
            refs = store.list(normalize_target(target))
            if len(refs) < 2:
                console.print(f"[red]Need at least two stored scans of {target}; found {len(refs)}.[/red]")
                raise typer.Exit(2)
            previous, current = refs[-2].scan_id, refs[-1].scan_id
        if not (previous and current):
            console.print("[red]Give two scan IDs, or --target <domain>.[/red]")
            raise typer.Exit(2)
        result = ScanComparator.compare(store.load(previous), store.load(current))
    except (KeyError, ValueError, InvalidTargetError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    paths = ComparisonReportWriter(result).write(output / result.current.hostname / "comparisons" /
                                                f"{result.previous.scan_id}__{result.current.scan_id}")
    TerminalSummary(console).print_comparison(result, detailed=True)
    console.print("\n[bold]Reports[/bold]")
    for path in paths:
        console.print(f"  {path}")


@app.command(name="active", help="Authorized active testing of a domain (requires an authorization file).")
def active_cmd(
    domain: Annotated[str, typer.Argument(help="Target domain (must match the authorization file's target).")],
    authorization: Annotated[Path, typer.Option("--authorization", "-A",
                                                help="Path to the operator-authored authorization file (YAML/JSON).")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Report directory.")] = Path("reports"),
    output_format: Annotated[OutputFormat, typer.Option("--format", "-f", help="Report format.")] = OutputFormat.ALL,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Resolve and print what would run; make no requests.")] = False,
    passive: Annotated[bool, typer.Option("--passive/--no-passive",
                                          help="Run a passive recon scan first to build an inventory.")] = True,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Detailed execution logs.")] = False,
    now: Annotated[str | None, typer.Option("--now", hidden=True, help="Reference time (ISO 8601) for the window check.")] = None,
) -> None:
    '''
    Run authorized active checks against a domain.
    Parameters:
        domain (str): Target domain; must match the authorization file's target.
        authorization (Path): Path to the authorization file.
        output (Path): Base report directory.
        output_format (OutputFormat): Report format.
        dry_run (bool): Resolve the plan and print it without making any requests.
        passive (bool): Run a passive recon scan first (for inventory and endpoint cross-check).
        verbose (bool): Enable detailed logs.
        now (str | None): Reference time (ISO 8601) for the window check; defaults to the current UTC time.
    Raises:
        typer.Exit: Code 2 for invalid input, a target mismatch, an invalid/expired authorization, or
            (without --dry-run) being outside the authorized window.
    '''
    setup_logging(verbose)
    try:
        moment = datetime.fromisoformat(now) if now else datetime.now(UTC)
    except ValueError as exc:
        console.print(f"[red]Invalid --now:[/red] {exc}")
        raise typer.Exit(2) from exc
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    try:
        hostname = normalize_target(domain)
    except InvalidTargetError as exc:
        console.print(f"[red]Invalid target:[/red] {exc}")
        raise typer.Exit(2) from exc
    try:
        auth = load_authorization(authorization)
    except AuthorizationError as exc:
        console.print(f"[red]Authorization error:[/red] {exc}")
        raise typer.Exit(2) from exc
    try:
        auth_host = normalize_target(auth.target)
    except InvalidTargetError as exc:
        console.print(f"[red]Authorization target is not a valid domain:[/red] {exc}")
        raise typer.Exit(2) from exc
    if auth_host != hostname:
        console.print(f"[red]Target mismatch:[/red] command target '{hostname}' does not match "
                      f"authorization target '{auth_host}'. Refusing to run.")
        raise typer.Exit(2)

    orchestrator = ActiveOrchestrator(auth, now=moment)
    if dry_run:
        _print_active_plan(orchestrator, auth, moment)
        return
    try:
        auth.validate_window(moment)
    except AuthorizationError as exc:
        console.print(f"[red]Refusing to run:[/red] {exc}")
        raise typer.Exit(2) from exc

    console.print(f"[bold red]ACTIVE testing[/bold red] {hostname} "
                  f"[dim](authorized; may affect the target)[/dim]")

    active_dir = output / hostname / "active"
    inventory: Inventory | None = None
    if passive:
        console.print("\n[bold]Step 1 — passive recon[/bold] [dim](building inventory)[/dim]")
        pconfig = Config(target_input=domain, hostname=hostname, output_dir=output, output_format=output_format,
                         crawl=True, history=False, verbose=verbose)
        with _progress_bar("Passive recon", ScanOrchestrator.MODULE_COUNT) as (advance, _set):
            passive_report = asyncio.run(ScanOrchestrator(pconfig).run(progress=advance))
        p_writers: list[ReportWriter] = [JsonReportWriter(passive_report)]
        if pconfig.wants_markdown:
            p_writers.append(MarkdownReportWriter(passive_report))
        if pconfig.wants_html:
            p_writers.append(HtmlReportWriter(passive_report))
        for w in p_writers:
            w.write(output / hostname)
        TerminalSummary(console).print(passive_report)
        inventory = build_inventory(passive_report)
        inv_path = write_inventory(inventory, active_dir)
        inventory = read_inventory(active_dir) or inventory
        console.print(f"  [green]Inventory[/green] {inventory.summary()} [dim]→ {inv_path}[/dim]")
    else:
        inventory = read_inventory(active_dir)
        if inventory is not None:
            console.print(f"  [dim]Loaded inventory from a prior passive scan ({inventory.summary()}).[/dim]")
        else:
            console.print("  [yellow]No saved inventory found[/yellow] "
                          "[dim](run without --no-passive to build one); skipping endpoint cross-check.[/dim]")

    if inventory is not None:
        _warn_uninventoried(auth, inventory)

    console.print("\n[bold]Step 2 — active checks[/bold]")
    checks = auth.checks_enabled
    if checks:
        with _progress_bar("Active checks", len(checks)) as (advance, set_item):
            def on_progress(event: str, check_id: str, detail: str) -> None:
                if event == "start":
                    set_item(f"{check_id}…")
                else:
                    advance(check_id)
                    console.print(f"  [dim]{check_id}: {detail}[/dim]")

            report = asyncio.run(orchestrator.run(progress=on_progress))
    else:
        report = asyncio.run(orchestrator.run())

    directory = output / hostname / "active"
    writers = [ActiveJsonReportWriter(report)]
    if output_format in (OutputFormat.MARKDOWN, OutputFormat.BOTH, OutputFormat.ALL):
        writers.append(ActiveMarkdownReportWriter(report))
    if output_format in (OutputFormat.HTML, OutputFormat.ALL):
        writers.append(ActiveHtmlReportWriter(report))
    written = [p for w in writers for p in w.write(directory)]

    TerminalSummary(console).print_active(report)
    console.print("\n[bold]Reports[/bold]")
    for path in written:
        console.print(f"  {path}")
    if report.checks and all(c.status is ModuleStatus.FAILED for c in report.checks):
        raise typer.Exit(1)


def _warn_uninventoried(auth: AuthorizationFile, inventory: Inventory) -> None:
    '''
    Warn when an authorized active target is absent from the persisted passive inventory.

    The active checks only ever touch operator-listed endpoints, but surfacing which of those the passive
    recon did not discover makes "testing a path the scan never saw" visible instead of silent.
    Parameters:
        auth (AuthorizationFile): The authorization (its endpoint lists).
        inventory (Inventory): The inventory read back from the passive step's inventory.json.
    '''
    from urllib.parse import urlsplit

    discovered = inventory.url_keys()
    hosts = inventory.known_hosts()

    def key(url: str) -> str:
        parts = urlsplit(url)
        return f"{(parts.hostname or '').lower()}{parts.path.rstrip('/') or '/'}"

    warnings: list[str] = []
    endpoints = ([t.url for t in auth.function_urls] + [t.url for t in auth.ip_trust_endpoints]
                 + [t.url for t in auth.email_endpoints])
    for url in endpoints:
        if (urlsplit(url).path.rstrip("/") or "/") != "/" and key(url) not in discovered:
            warnings.append(f"{redact_url(url)} — path not seen in the passive crawl/sitemap")
    if auth.supabase and auth.supabase.host.lower() not in hosts:
        warnings.append(f"{auth.supabase.host} — Supabase host not seen in the passive inventory")
    if warnings:
        console.print("[yellow]Note — authorized active targets the passive scan did not discover "
                      "(operator-listed, tested anyway):[/yellow]")
        for w in warnings:
            console.print(f"  [yellow]•[/yellow] {w}")


def _print_active_plan(orchestrator: ActiveOrchestrator, auth: AuthorizationFile, moment: datetime) -> None:
    '''
    Print the resolved active plan for --dry-run (no network I/O).
    Parameters:
        orchestrator (ActiveOrchestrator): The orchestrator (used to resolve the plan).
        auth (AuthorizationFile): The authorization.
        moment (datetime): Current time for the window check.
    '''
    opts = orchestrator.options_echo()
    within = auth.window.contains(moment)
    console.print(f"[bold]Active plan (dry run)[/bold] for {opts['target']}")
    console.print(f"  Window: {opts['window']['start']} .. {opts['window']['end']} — "
                  + ("[green]within window[/green]" if within else "[red]OUTSIDE window (would refuse to run)[/red]"))
    console.print(f"  Scope hosts: {', '.join(opts['scope_hosts']) or '(none)'}")
    console.print(f"  Rate limit: {opts['rate_limit_rps']} rps · budget {opts['max_requests']} "
                  f"(per check {opts['max_requests_per_check']})")
    table = Table(title="Checks", title_justify="left")
    for col in ("Check", "Would run?", "Reason"):
        table.add_column(col)
    for check_id, reason in orchestrator.plan():
        verdict = "[green]run[/green]" if reason is None else "[yellow]skip[/yellow]"
        table.add_row(check_id, verdict, reason or "")
    if not auth.checks_enabled:
        console.print("  [dim]No checks enabled in the authorization (checks_enabled is empty).[/dim]")
    console.print(table)
    console.print("[dim]No requests were made (dry run).[/dim]")


def _parse_modules(value: str | None) -> frozenset[str]:
    '''
    Parse and validate --modules.
    Parameters:
        value (str | None): Comma-separated module names, or None for all.
    Returns:
        frozenset[str]: Selected modules.
    Raises:
        typer.BadParameter: If an unknown module is named.
    '''
    if not value:
        return frozenset(ALL_MODULES)
    names = {v.strip().lower().replace("-", "_") for v in value.split(",") if v.strip()}
    unknown = sorted(names - set(ALL_MODULES))
    if unknown:
        raise typer.BadParameter(f"unknown module(s): {', '.join(unknown)}; choose from {', '.join(ALL_MODULES)}",
                                 param_hint="--modules")
    return frozenset(names)


class TerminalSummary:
    '''
    Prints module status, infrastructure, technologies and findings tables to a Rich console.
    '''

    STATUS_STYLE: ClassVar[dict[ModuleStatus, str]] = {
        ModuleStatus.SUCCESS: "green", ModuleStatus.PARTIAL: "yellow",
        ModuleStatus.FAILED: "red", ModuleStatus.SKIPPED: "dim",
    }
    SEVERITY_STYLE: ClassVar[dict[Severity, str]] = {
        Severity.CRITICAL: "bold red", Severity.HIGH: "red", Severity.MEDIUM: "yellow",
        Severity.LOW: "cyan", Severity.INFORMATIONAL: "dim",
    }

    def __init__(self, console: Console) -> None:
        '''
        Create a summary printer.
        Parameters:
            console (Console): Console to print to.
        '''
        self.console = console

    def print(self, report: ReconReport) -> None:
        '''
        Print every summary section for a report.
        Parameters:
            report (ReconReport): The completed reconnaissance report.
        '''
        self._modules(report)
        self._infrastructure(report)
        self._technologies(report)
        self._counts(report)
        self._findings(report)
        if report.comparison:
            self.print_comparison(report.comparison)

    def _modules(self, report: ReconReport) -> None:
        '''
        Print the module status table.
        Parameters:
            report (ReconReport): The completed reconnaissance report.
        '''
        table = Table(title="Modules", title_justify="left")
        for col in ("Module", "Status", "Duration", "Errors"):
            table.add_column(col)
        for name, res in report.module_results().items():
            style = self.STATUS_STYLE[res.status]
            table.add_row(name, f"[{style}]{res.status.value}[/{style}]",
                          f"{res.duration_ms:.0f} ms", str(len(res.errors)))
        self.console.print(table)

    def _infrastructure(self, report: ReconReport) -> None:
        '''
        Print inferred infrastructure providers, if any.
        Parameters:
            report (ReconReport): The completed reconnaissance report.
        '''
        if not report.analysis.infrastructure:
            return
        table = Table(title="Infrastructure", title_justify="left")
        for col in ("Provider", "Role", "Confidence"):
            table.add_column(col)
        for o in report.analysis.infrastructure:
            table.add_row(o.provider, o.role, o.confidence.value)
        self.console.print(table)

    def _technologies(self, report: ReconReport) -> None:
        '''
        Print detected technologies, if any.
        Parameters:
            report (ReconReport): The completed reconnaissance report.
        '''
        tech = report.technology.data
        if not (tech and tech.technologies):
            return
        table = Table(title="Technologies", title_justify="left")
        for col in ("Technology", "Category", "Version", "Status"):
            table.add_column(col)
        for item in tech.technologies:
            table.add_row(item.name, item.category, item.version or "", item.status.value)
        self.console.print(table)

    def _counts(self, report: ReconReport) -> None:
        '''
        Print one-line subdomain and third-party summaries.
        Parameters:
            report (ReconReport): The completed reconnaissance report.
        '''
        subs = report.subdomains.data
        if subs:
            live = sum(1 for h in subs.hostnames if h.resolves)
            self.console.print(f"[bold]Subdomains:[/bold] {len(subs.hostnames)} names in CT logs, "
                               f"{live} currently resolve ({subs.verified_count} checked)")
        crawl = report.crawler.data
        if crawl:
            self.console.print(f"[bold]Crawl:[/bold] {len(crawl.pages)} page(s) fetched, "
                               f"{len(crawl.discovered)} more discovered, {len(crawl.forms)} form(s)")
        cookies = report.cookies.data
        if cookies and cookies.cookies:
            self.console.print(f"[bold]Cookies:[/bold] {len(cookies.cookies)} (attributes only; values never stored)")
        assets = report.javascript.data
        if assets:
            maps = sum(1 for a in assets.assets if a.source_map_status == "public")
            exposed = sum(a.source_map_source_count for a in assets.assets)
            self.console.print(f"[bold]Assets:[/bold] {len(assets.assets)} analyzed ({assets.total_bytes:,} bytes), "
                               f"{assets.endpoint_count} endpoint(s), {len(assets.service_hosts)} host(s), "
                               f"{maps} public source map(s)"
                               + (f" exposing {exposed} source file(s)" if exposed else "")
                               + (f", SRI {assets.integrity_verified} verified" if assets.integrity_verified else "")
                               + (f"/{assets.integrity_mismatched} mismatched" if assets.integrity_mismatched else ""))
            if assets.secret_count:
                self.console.print(f"[bold red]Possible credentials in client code:[/bold red] "
                                   f"{assets.secret_count} (redacted; confirm and rotate)")
        dnssec = report.dnssec.data
        if dnssec:
            self.console.print(f"[bold]DNSSEC:[/bold] {dnssec.status.value}")
        tp = report.third_party.data
        if tp:
            known = [s.provider for s in tp.services if s.known]
            self.console.print(f"[bold]Third-party services:[/bold] {', '.join(known) or 'none recognized'}")

    def _findings(self, report: ReconReport) -> None:
        '''
        Print the findings table.
        Parameters:
            report (ReconReport): The completed reconnaissance report.
        '''
        table = Table(title=f"Findings ({len(report.analysis.findings)})", title_justify="left")
        for col in ("Severity", "Title", "Subject"):
            table.add_column(col)
        for f in report.analysis.findings:
            style = self.SEVERITY_STYLE[f.severity]
            table.add_row(f"[{style}]{f.severity.value}[/{style}]", f.title, f.subject)
        self.console.print(table)


    def print_comparison(self, result: ComparisonResult, detailed: bool = False) -> None:
        '''
        Print a summary of changes since a previous scan.
        Parameters:
            result (ComparisonResult): The comparison.
            detailed (bool): Also list each change.
        '''
        counts = ", ".join(f"{result.counts.get(k.value, 0)} {k.value}" for k in ChangeKind)
        self.console.print(f"[bold]Changes since {result.previous.scan_id}:[/bold] {counts}")
        if not detailed:
            return
        table = Table(title="Changes", title_justify="left")
        for col in ("Kind", "Type", "Target", "Key"):
            table.add_column(col)
        for ch in result.changes[:200]:
            table.add_row(ch.kind.value, ch.type, ch.target, ch.key)
        self.console.print(table)

    def print_active(self, report: ActiveReport) -> None:
        '''
        Print a summary of an active-testing run.
        Parameters:
            report (ActiveReport): The active report.
        '''
        checks = Table(title="Active checks", title_justify="left")
        for col in ("Check", "Status", "Requests", "Findings", "Skip reason"):
            checks.add_column(col)
        style = {ModuleStatus.SUCCESS: "green", ModuleStatus.PARTIAL: "yellow",
                 ModuleStatus.FAILED: "red", ModuleStatus.SKIPPED: "dim"}
        for c in report.checks:
            checks.add_row(c.check_id, f"[{style[c.status]}]{c.status.value}[/{style[c.status]}]",
                           str(c.requests_made), str(len(c.findings)), (c.skipped_reason or "")[:50])
        self.console.print(checks)
        self.console.print(f"[bold]Requests made:[/bold] {report.requests_made} / {report.request_budget} budget")
        findings = report.findings()
        if findings:
            table = Table(title=f"Findings ({len(findings)})", title_justify="left")
            for col in ("Severity", "Title", "Subject"):
                table.add_column(col)
            sev = {Severity.CRITICAL: "bold red", Severity.HIGH: "red", Severity.MEDIUM: "yellow",
                   Severity.LOW: "cyan", Severity.INFORMATIONAL: "dim"}
            for f in findings:
                table.add_row(f"[{sev[f.severity]}]{f.severity.value}[/{sev[f.severity]}]", f.title, f.subject)
            self.console.print(table)


def run() -> None:
    '''
    Console-script entry point. A bare domain (``siterecon example.com``) is treated as ``scan``.
    '''
    args = sys.argv[1:]
    if args and args[0] not in SUBCOMMANDS and not args[0].startswith("-"):
        sys.argv.insert(1, "scan")
    app()
