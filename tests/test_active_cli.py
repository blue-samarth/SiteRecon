import datetime as dt
import json

from typer.testing import CliRunner

from recon.cli import app

runner = CliRunner()
INSIDE = dt.datetime(2026, 11, 10, 3, 0, tzinfo=dt.UTC)
OUTSIDE = dt.datetime(2026, 11, 11, 3, 0, tzinfo=dt.UTC)

AUTH = """
target: jobbie.io
authorized_by: "Op / Security"
authorized_on: "2026-11-08"
window:
  start: "2026-11-10T00:00:00Z"
  end: "2026-11-10T06:00:00Z"
scope:
  hosts: [sb.jobbie.test]
  tls_authorized_hosts: [sb.jobbie.test]
checks_enabled: [supabase_rls, tls_protocol_enum, function_url_reachability]
supabase:
  host: sb.jobbie.test
  anon_key: "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.sig"
  tables: [profiles]
"""


def write_auth(tmp_path, text=AUTH, name="auth.yaml"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def invoke(args, now=None):
    # inject the reference clock via the hidden --now option (Typer passes it through)
    return runner.invoke(app, [*args, "--now", (now or INSIDE).isoformat()])


def test_dry_run_prints_plan_and_makes_no_requests(tmp_path, monkeypatch):
    # fail loudly if anything tries real network in a dry run
    import recon.active.orchestrator as orch

    async def forbidden(self):  # pragma: no cover
        raise AssertionError("dry-run must not call run()")

    monkeypatch.setattr(orch.ActiveOrchestrator, "run", forbidden)
    res = invoke(["active", "jobbie.io", "-A", str(write_auth(tmp_path)), "--dry-run"])
    assert res.exit_code == 0, res.output
    assert "dry run" in res.output and "within window" in res.output
    assert "supabase_rls" in res.output and "tls_protocol_enum" in res.output
    assert "function_url_reachability" in res.output and "skip" in res.output   # no function_urls listed
    assert "No requests were made" in res.output


def test_dry_run_outside_window_still_runs_but_warns(tmp_path):
    res = invoke(["active", "jobbie.io", "-A", str(write_auth(tmp_path)), "--dry-run"], now=OUTSIDE)
    assert res.exit_code == 0 and "OUTSIDE" in res.output and "would refuse to run" in res.output.replace("\n", " ")


def test_target_mismatch_is_refused(tmp_path):
    res = invoke(["active", "other.com", "-A", str(write_auth(tmp_path)), "--dry-run"])
    assert res.exit_code == 2 and "mismatch" in res.output.lower()


def test_expired_window_refuses_real_run(tmp_path):
    res = invoke(["active", "jobbie.io", "-A", str(write_auth(tmp_path))], now=OUTSIDE)
    assert res.exit_code == 2 and "outside the authorized window" in res.output


def test_missing_authorization_file_exits_2(tmp_path):
    res = invoke(["active", "jobbie.io", "-A", str(tmp_path / "nope.yaml"), "--dry-run"])
    assert res.exit_code == 2 and "Authorization error" in res.output


def test_malformed_authorization_exits_2(tmp_path):
    res = invoke(["active", "jobbie.io", "-A", str(write_auth(tmp_path, "not: [a, mapping")), "--dry-run"])
    assert res.exit_code == 2


def test_empty_checks_produces_valid_reports(tmp_path):
    text = AUTH.replace("checks_enabled: [supabase_rls, tls_protocol_enum, function_url_reachability]",
                        "checks_enabled: []")
    out = tmp_path / "reports"
    res = invoke(["active", "jobbie.io", "-A", str(write_auth(tmp_path, text)), "-o", str(out), "--no-passive"])
    assert res.exit_code == 0, res.output
    active_dir = out / "jobbie.io" / "active"
    assert {p.name for p in active_dir.iterdir()} == {"active.json", "active.md", "active.html"}
    doc = json.loads((active_dir / "active.json").read_text())
    assert doc["checks"] == [] and doc["requests_made"] == 0 and doc["window_ok"] is True
    assert "eyJyb2xlIjoiYW5vbiJ9" not in (active_dir / "active.json").read_text()   # anon key redacted
    assert "ACTIVE TESTING" in (active_dir / "active.md").read_text()


def test_json_only_format(tmp_path):
    text = AUTH.replace("checks_enabled: [supabase_rls, tls_protocol_enum, function_url_reachability]",
                        "checks_enabled: []")
    out = tmp_path / "reports"
    res = invoke(["active", "jobbie.io", "-A", str(write_auth(tmp_path, text)), "-o", str(out), "-f", "json", "--no-passive"])
    assert res.exit_code == 0
    assert {p.name for p in (out / "jobbie.io" / "active").iterdir()} == {"active.json"}
