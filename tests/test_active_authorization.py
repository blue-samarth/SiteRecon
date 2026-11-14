import base64
import datetime as dt
import json

import pytest
from pydantic import ValidationError

from recon.active import AuthorizationError, load_authorization, redact_authorization
from recon.active.authorization import AuthorizationFile

NOW = dt.datetime(2026, 11, 10, 3, 0, tzinfo=dt.UTC)

VALID = """
target: jobbie.io
authorized_by: "Jane Operator / Security"
authorized_on: "2026-11-08"
window:
  start: "2026-11-10T00:00:00Z"
  end: "2026-11-10T06:00:00Z"
scope:
  hosts:
    - muvsftgwvzuttktqtkmc.supabase.co
    - abc.lambda-url.ap-south-1.on.aws
  tls_authorized_hosts:
    - muvsftgwvzuttktqtkmc.supabase.co
checks_enabled: [tls_protocol_enum]
rate_limit_rps: 1.0
max_requests: 50
supabase:
  host: muvsftgwvzuttktqtkmc.supabase.co
  anon_key: "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.sig"
  tables: [profiles, items]
"""


def jwt(role):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'HS256'})}.{enc({'role': role})}.signature"


def write(tmp_path, text, name="auth.yaml"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_loads_valid_yaml(tmp_path):
    auth = load_authorization(write(tmp_path, VALID))
    assert auth.target == "jobbie.io" and auth.checks_enabled == ["tls_protocol_enum"]
    assert auth.scope.allows("muvsftgwvzuttktqtkmc.supabase.co")
    assert auth.scope.allows("ABC.lambda-url.ap-south-1.on.aws")
    assert not auth.scope.allows("other.com")
    assert auth.scope.tls_authorized("muvsftgwvzuttktqtkmc.supabase.co")
    assert not auth.scope.tls_authorized("abc.lambda-url.ap-south-1.on.aws")   # not in tls_authorized_hosts


def test_loads_json_too(tmp_path):
    data = {"target": "x.io", "authorized_by": "a", "authorized_on": "2026-01-01",
            "window": {"start": "2026-11-10T00:00:00Z", "end": "2026-11-10T06:00:00Z"},
            "scope": {"hosts": ["a.io"]}}
    auth = load_authorization(write(tmp_path, json.dumps(data), "auth.json"))
    assert auth.target == "x.io" and auth.scope.allows("a.io")


def test_window_validation(tmp_path):
    auth = load_authorization(write(tmp_path, VALID))
    auth.validate_window(NOW)   # inside → no error
    with pytest.raises(AuthorizationError, match="outside the authorized window"):
        auth.validate_window(NOW + dt.timedelta(days=1))
    assert auth.window.contains(NOW) and not auth.window.contains(NOW - dt.timedelta(hours=4))


def test_subdomains_are_not_implicitly_in_scope(tmp_path):
    auth = load_authorization(write(tmp_path, VALID))
    assert not auth.scope.allows("evil.muvsftgwvzuttktqtkmc.supabase.co")   # exact match only


def test_exclude_hosts_carve_out(tmp_path):
    text = VALID.replace("tls_authorized_hosts:", "exclude_hosts:\n    - abc.lambda-url.ap-south-1.on.aws\n  tls_authorized_hosts:")
    auth = load_authorization(write(tmp_path, text))
    assert not auth.scope.allows("abc.lambda-url.ap-south-1.on.aws")


def test_service_role_key_is_rejected(tmp_path):
    text = VALID.replace('eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.sig', jwt("service_role"))
    with pytest.raises(AuthorizationError, match="service_role"):
        load_authorization(write(tmp_path, text))


def test_missing_required_field_is_specific(tmp_path):
    with pytest.raises(AuthorizationError, match="authorized_by"):
        load_authorization(write(tmp_path, VALID.replace('authorized_by: "Jane Operator / Security"', "")))


def test_malformed_file_rejected(tmp_path):
    with pytest.raises(AuthorizationError, match="mapping|YAML|invalid"):
        load_authorization(write(tmp_path, "just a string"))


def test_missing_file_rejected(tmp_path):
    with pytest.raises(AuthorizationError, match="cannot read"):
        load_authorization(tmp_path / "nope.yaml")


def test_invalid_utf8_rejected(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_bytes(b"target: \xff\xfe not utf-8")
    with pytest.raises(AuthorizationError, match="UTF-8"):
        load_authorization(path)


def test_authorized_on_parses_to_a_date(tmp_path):
    auth = load_authorization(write(tmp_path, VALID))
    assert auth.authorized_on == dt.date(2026, 11, 8)
    assert redact_authorization(auth)["authorized_on"] == "2026-11-08"


def test_enabled_checks_require_scope_hosts(tmp_path):
    text = """
target: x.io
authorized_by: a
authorized_on: "2026-01-01"
window: {start: "2026-11-10T00:00:00Z", end: "2026-11-10T06:00:00Z"}
scope: {hosts: []}
checks_enabled: [tls_protocol_enum]
"""
    with pytest.raises(AuthorizationError, match="scope.hosts is empty"):
        load_authorization(write(tmp_path, text))


def _base(**over):
    data = {"target": "x.io", "authorized_by": "a", "authorized_on": "2026-01-01",
            "window": {"start": "2026-11-10T00:00:00Z", "end": "2026-11-10T06:00:00Z"},
            "scope": {"hosts": ["a.io"]}}
    data.update(over)
    return data


def test_out_of_range_limits_are_rejected():
    for field, bad in (("rate_limit_rps", 999), ("rate_limit_rps", 0.0),
                       ("max_requests", 999999), ("max_requests", 0),
                       ("max_requests_per_check", 999999), ("max_requests_per_check", 0)):
        with pytest.raises(ValidationError, match=field):
            AuthorizationFile.model_validate(_base(**{field: bad}))


def test_non_finite_rate_is_rejected():
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValidationError, match="finite"):
            AuthorizationFile.model_validate(_base(rate_limit_rps=bad))


def test_in_range_limits_are_accepted():
    auth = AuthorizationFile.model_validate(_base(rate_limit_rps=10.0, max_requests=1000,
                                                  max_requests_per_check=1000,
                                                  email_endpoints=[{"url": "https://a.io/x", "burst": 500}]))
    assert auth.rate_limit_rps == 10.0 and auth.max_requests == 1000 and auth.max_requests_per_check == 1000
    assert auth.email_endpoints[0].burst == 10   # burst is still clamped, not rejected


def test_bad_url_and_method_are_rejected():
    with pytest.raises(ValidationError, match="http"):
        AuthorizationFile.model_validate(_base(function_urls=[{"url": "ftp://a.io/x"}]))
    with pytest.raises(ValidationError, match="http"):
        AuthorizationFile.model_validate(_base(ip_trust_endpoints=[{"url": "/relative/path"}]))
    with pytest.raises(ValidationError, match="host"):
        AuthorizationFile.model_validate(_base(function_urls=[{"url": "https://"}]))
    with pytest.raises(ValidationError, match="method"):
        AuthorizationFile.model_validate(_base(function_urls=[{"url": "https://a.io/x", "method": "TRACE"}]))


def test_secret_format_key_is_rejected():
    with pytest.raises(ValidationError, match="secret"):
        AuthorizationFile.model_validate(_base(supabase={"host": "a.io", "anon_key": "sb_secret_abc123"}))


def test_redaction_hides_anon_key(tmp_path):
    auth = load_authorization(write(tmp_path, VALID))
    summary = redact_authorization(auth)
    backend = summary["backends"][0]                          # legacy supabase block folded into backends
    assert backend["kind"] == "supabase" and backend["host"] == "muvsftgwvzuttktqtkmc.supabase.co"
    assert "sha256:" in backend["credential"] and backend["resources"] == ["profiles", "items"]
    assert "eyJyb2xlIjoiYW5vbiJ9" not in json.dumps(summary)   # key material not present
    assert summary["scope_hosts"] and summary["checks_enabled"] == ["tls_protocol_enum"]


def test_legacy_supabase_block_folds_into_backends(tmp_path):
    auth = load_authorization(write(tmp_path, VALID))
    assert [b.kind for b in auth.backends] == ["supabase"]
    assert auth.backends[0].host == "muvsftgwvzuttktqtkmc.supabase.co"
    assert auth.backends[0].resources == ["profiles", "items"]


def test_supabase_rls_check_id_is_migrated(tmp_path):
    text = VALID.replace("checks_enabled: [tls_protocol_enum]", "checks_enabled: [supabase_rls, tls_protocol_enum]")
    auth = load_authorization(write(tmp_path, text))
    assert auth.checks_enabled == ["backend_read_access", "tls_protocol_enum"]


def test_new_backends_reject_privileged_credentials():
    rest = {"kind": "rest_generic", "base_url": "https://a.io", "credential_header": "X-Api-Key",
            "credential": "sk_live_" + "a" * 24, "resources": [{"path": "/x", "success_if": {"status": 200}}]}
    with pytest.raises(ValidationError, match="private-credential pattern"):
        AuthorizationFile.model_validate(_base(backends=[rest]))


def test_rest_resource_requires_a_match_condition():
    rest = {"kind": "rest_generic", "base_url": "https://a.io",
            "resources": [{"path": "/x", "success_if": {}}]}
    with pytest.raises(ValidationError, match="status.*body_contains|match spec"):
        AuthorizationFile.model_validate(_base(backends=[rest]))


def test_unknown_backend_kind_is_rejected():
    with pytest.raises(ValidationError):
        AuthorizationFile.model_validate(_base(backends=[{"kind": "mongo", "host": "a.io"}]))
