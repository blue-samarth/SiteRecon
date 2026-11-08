import datetime as dt
from io import StringIO

from rich.console import Console

import recon.cli as cli
from recon.active.authorization import ActiveScope, AuthorizationFile, FunctionUrlTarget, IpTrustTarget, TimeWindow
from recon.active.inventory import build_inventory
from recon.models import CrawlData, CrawledPage, ResourcesData, SitemapInfo
from tests.test_history import mr, report as make_report

WINDOW = TimeWindow(start=dt.datetime(2026, 11, 10, tzinfo=dt.UTC), end=dt.datetime(2026, 11, 30, tzinfo=dt.UTC))


def auth(**kw):
    base = dict(target="example.com", authorized_by="op", authorized_on="2026-11-08", window=WINDOW,
                scope=ActiveScope(hosts=["example.com"]))
    base.update(kw)
    return AuthorizationFile(**base)


def passive_report_with(pages, sitemap_urls):
    r = make_report("20260101T000000Z-aaaaaa", dns=None)
    r.crawler = mr("crawler", CrawlData(
        max_depth=1, max_pages=25, robots_respected=True, crawl_delay=0.0,
        pages=[CrawledPage(url=u, depth=0, status_code=200, final_url=u) for u in pages]))
    r.resources = mr("resources", ResourcesData(
        origin="https://example.com",
        sitemaps=[SitemapInfo(url="https://example.com/sitemap.xml", present=True, urls=list(sitemap_urls))]))
    return r


def capture_warn(auth_obj, report):
    buf = StringIO()
    saved = cli.console
    cli.console = Console(file=buf, width=120, no_color=True)
    try:
        cli._warn_uninventoried(auth_obj, build_inventory(report))
    finally:
        cli.console = saved
    return buf.getvalue()


def test_warns_only_for_endpoints_not_in_passive_inventory():
    report = passive_report_with(
        pages=["https://example.com/", "https://example.com/dashboard"],
        sitemap_urls=["https://example.com/pricing"])
    a = auth(ip_trust_endpoints=[
        IpTrustTarget(url="https://example.com/dashboard"),   # discovered by crawl → no warning
        IpTrustTarget(url="https://example.com/pricing"),     # discovered in sitemap → no warning
        IpTrustTarget(url="https://example.com/admin"),       # NOT discovered → warn
    ], function_urls=[FunctionUrlTarget(url="https://example.com/api/secret")])  # NOT discovered → warn
    out = capture_warn(a, report)
    assert "/admin" in out and "/api/secret" in out
    assert "/dashboard" not in out and "/pricing" not in out
    assert "did not discover" in out


def test_no_warning_when_everything_inventoried():
    report = passive_report_with(pages=["https://example.com/", "https://example.com/admin"], sitemap_urls=[])
    a = auth(ip_trust_endpoints=[IpTrustTarget(url="https://example.com/admin")])
    assert capture_warn(a, report).strip() == ""


def test_root_path_endpoints_are_not_warned():
    report = passive_report_with(pages=["https://example.com/"], sitemap_urls=[])
    a = auth(function_urls=[FunctionUrlTarget(url="https://example.com/")])   # root, always "discovered"
    assert capture_warn(a, report).strip() == ""


def test_no_passive_flag_skips_the_scan(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    text = """
target: example.com
authorized_by: op
authorized_on: "2026-11-08"
window: {start: "2026-11-10T00:00:00Z", end: "2026-11-30T23:59:59Z"}
scope: {hosts: [example.com]}
checks_enabled: []
"""
    (tmp_path / "a.yaml").write_text(text)

    def boom(self):  # pragma: no cover - must not run under --no-passive
        raise AssertionError("passive scan must not run with --no-passive")

    monkeypatch.setattr("recon.cli.ScanOrchestrator.run", boom)
    res = CliRunner().invoke(cli.app, ["active", "example.com", "-A", str(tmp_path / "a.yaml"),
                                       "-o", str(tmp_path / "out"), "--no-passive", "--now", "2026-11-10T03:00:00Z"])
    assert res.exit_code == 0, res.output
    assert "Step 2 — active checks" in res.output and "Step 1" not in res.output


def test_passive_default_runs_scan(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    text = """
target: example.com
authorized_by: op
authorized_on: "2026-11-08"
window: {start: "2026-11-10T00:00:00Z", end: "2026-11-30T23:59:59Z"}
scope: {hosts: [example.com]}
checks_enabled: []
"""
    (tmp_path / "a.yaml").write_text(text)
    stub = passive_report_with(pages=["https://example.com/"], sitemap_urls=[])

    async def fake_run(self, progress=None):
        return stub

    monkeypatch.setattr("recon.cli.ScanOrchestrator.run", fake_run)
    res = CliRunner().invoke(cli.app, ["active", "example.com", "-A", str(tmp_path / "a.yaml"),
                                       "-o", str(tmp_path / "out"), "--now", "2026-11-10T03:00:00Z"])
    assert res.exit_code == 0, res.output
    assert "Step 1 — passive recon" in res.output and "Step 2 — active checks" in res.output
    # passive reports were written alongside the active ones
    assert (tmp_path / "out" / "example.com" / "report.json").exists()
    assert (tmp_path / "out" / "example.com" / "active" / "active.json").exists()
    # the passive step persisted the inventory the active step reads from
    assert (tmp_path / "out" / "example.com" / "active" / "inventory.json").exists()


def test_inventory_round_trips_through_a_file(tmp_path):
    from recon.active.inventory import read_inventory, write_inventory

    report = passive_report_with(
        pages=["https://example.com/", "https://example.com/app"],
        sitemap_urls=["https://example.com/pricing"])
    inv = build_inventory(report)
    path = write_inventory(inv, tmp_path)
    assert path == tmp_path / "inventory.json"

    loaded = read_inventory(tmp_path)
    assert loaded is not None
    assert loaded.hostname == "example.com"
    assert "example.com/app" in loaded.url_keys()
    assert "example.com/pricing" in loaded.url_keys()


def test_read_inventory_missing_returns_none(tmp_path):
    from recon.active.inventory import read_inventory

    assert read_inventory(tmp_path) is None


def test_no_passive_reads_prior_inventory_file(tmp_path):
    from typer.testing import CliRunner

    from recon.active.inventory import build_inventory as bi, write_inventory

    # A prior passive run left an inventory that does NOT contain /admin.
    write_inventory(bi(passive_report_with(pages=["https://example.com/"], sitemap_urls=[])),
                    tmp_path / "out" / "example.com" / "active")

    text = """
target: example.com
authorized_by: op
authorized_on: "2026-11-08"
window: {start: "2026-11-10T00:00:00Z", end: "2026-11-30T23:59:59Z"}
scope: {hosts: [example.com]}
checks_enabled: []
ip_trust_endpoints:
  - url: "https://example.com/admin"
"""
    (tmp_path / "a.yaml").write_text(text)
    res = CliRunner().invoke(cli.app, ["active", "example.com", "-A", str(tmp_path / "a.yaml"),
                                       "-o", str(tmp_path / "out"), "--no-passive", "--now", "2026-11-10T03:00:00Z"])
    assert res.exit_code == 0, res.output
    assert "Loaded inventory from a prior passive scan" in res.output
    assert "/admin" in res.output  # cross-check ran against the file and flagged the undiscovered path
