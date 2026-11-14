from __future__ import annotations

import base64
import binascii
import json
import math
import re
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Annotated, Any, Literal, Union
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from recon.active.credentials import reject_privileged_credential
from recon.utils import redact_secret, redact_url

_HTTP_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
_B64URL: re.Pattern[str] = re.compile(r"^[A-Za-z0-9_-]+$")


class AuthorizationError(Exception):
    '''
    Raised when an authorization file is missing, malformed, out of its window, or otherwise invalid.
    '''


class TimeWindow(BaseModel):
    '''
    The wall-clock window during which active testing is authorized.
    '''
    start: datetime
    end: datetime

    @field_validator("start", "end")
    @classmethod
    def _aware(cls, value: datetime) -> datetime: return value if value.tzinfo else value.replace(tzinfo=UTC)

    def contains(self, now: datetime) -> bool: return self.start <= now <= self.end


class FunctionUrlTarget(BaseModel):
    '''
    A function/edge URL to probe for reachability and auth posture.
    '''
    url: str
    method: str = "OPTIONS"
    state_changing: bool = False

    @field_validator("url")
    @classmethod
    def _check_url(cls, value: str) -> str: return _validated_url(value)

    @field_validator("method")
    @classmethod
    def _check_method(cls, value: str) -> str: return _validated_method(value)


class IpTrustTarget(BaseModel):
    '''
    An endpoint to test for trust of client-supplied IP headers (X-Forwarded-For, etc.).
    '''
    url: str
    method: str = "GET"
    access_control: bool = False

    @field_validator("url")
    @classmethod
    def _check_url(cls, value: str) -> str: return _validated_url(value)

    @field_validator("method")
    @classmethod
    def _check_method(cls, value: str) -> str: return _validated_method(value)


class EmailEndpointTarget(BaseModel):
    '''
    An email/notification endpoint explicitly opted in for rate-limit probing.
    '''
    url: str
    method: str = "POST"
    burst: int = 5
    test_payload: str | None = None
    confirmed_no_real_delivery: bool = False

    @field_validator("url")
    @classmethod
    def _check_url(cls, value: str) -> str: return _validated_url(value)

    @field_validator("method")
    @classmethod
    def _check_method(cls, value: str) -> str: return _validated_method(value)

    @field_validator("burst")
    @classmethod
    def _cap_burst(cls, value: int) -> int: return max(1, min(value, 10))


class SupabaseTarget(BaseModel):
    '''
    A Supabase project to check for row-level-security enforcement using its public anon key only.
    '''
    host: str
    anon_key: str
    tables: list[str] = Field(default_factory=list)

    @field_validator("anon_key")
    @classmethod
    def _reject_private_key(cls, value: str) -> str:
        '''
        Refuse a private key, leaving only the public anon/publishable key through.

        Two private shapes are rejected: a new-format secret key (sb_secret_…), and a classic JWT whose
        decoded payload claims a privileged role (service_role). This is a structural guard, not proof:
        the JWT signature is NOT verified (that would need the project's secret), and a value that is
        neither a known secret prefix nor a decodable service_role JWT is permitted — public anon and
        publishable keys are the expected, safe input and are not always JWTs.
        Parameters:
            value (str): The supplied key.
        Returns:
            str: The key, if it shows no private-key signal.
        Raises:
            ValueError: If the key is a secret-format key or a service_role JWT.
        '''
        if value.strip().startswith("sb_secret_"): raise ValueError("key looks like a Supabase secret key; only the public anon/publishable key is permitted")
        if "service_role" in _jwt_role_hint(value): raise ValueError("anon_key looks like a service_role key; only the public anon key is permitted")
        return value


def _guarded_credential(value: str | None) -> str | None:
    '''
    Reject a credential that is too privileged to probe with, for use as a pydantic field validator.
    Parameters:
        value (str | None): The supplied credential.
    Returns:
        str | None: The credential, unchanged, if it is safe to test with.
    Raises:
        ValueError: If the credential matches a private/server-side secret shape.
    '''
    reason: str | None = reject_privileged_credential(value)
    if reason is not None:
        raise ValueError(f"credential {reason}")
    return value


class MatchSpec(BaseModel):
    '''
    An operator-supplied description of what a success or denial looks like for a generic backend.
    '''
    status: int | list[int] | None = None
    body_contains: str | None = None

    @model_validator(mode="after")
    def _require_a_condition(self) -> MatchSpec:
        '''
        Require at least one condition so a spec can never match everything by accident.
        Returns:
            MatchSpec: The validated spec.
        Raises:
            ValueError: If neither a status nor a body substring is given.
        '''
        if self.status is None and self.body_contains is None:
            raise ValueError("a match spec needs at least one of 'status' or 'body_contains'")
        return self

    def statuses(self) -> set[int]:
        '''
        The status codes this spec accepts (empty set means "any status").
        Returns:
            set[int]: Accepted status codes.
        '''
        if self.status is None:
            return set()
        return {self.status} if isinstance(self.status, int) else set(self.status)


class RestResource(BaseModel):
    '''
    One read-only resource on a generic REST backend, with the operator's success/denied definitions.
    '''
    path: str
    method: str = "GET"
    success_if: MatchSpec
    denied_if: MatchSpec | None = None

    @field_validator("method")
    @classmethod
    def _check_method(cls, value: str) -> str: return _validated_method(value)


class GraphQLResource(BaseModel):
    '''
    One minimal, read-only query on a generic GraphQL backend.
    '''
    name: str
    query: str
    variables: dict[str, Any] = Field(default_factory=dict)


class SupabaseBackend(BaseModel):
    '''
    A Supabase project tested with its public anon/publishable key only.
    '''
    kind: Literal["supabase"] = "supabase"
    host: str
    credential: str
    resources: list[str] = Field(default_factory=list)

    @field_validator("credential")
    @classmethod
    def _guard(cls, value: str) -> str:
        _guarded_credential(value)
        return value


class FirebaseBackend(BaseModel):
    '''
    A Firebase project: a Firestore collection or a Realtime Database path, tested with no auth or a
    public API key.
    '''
    kind: Literal["firebase"] = "firebase"
    project_id: str
    database: Literal["firestore", "realtime_db"] = "firestore"
    credential: str | None = None
    resources: list[str] = Field(default_factory=list)

    @field_validator("credential")
    @classmethod
    def _guard(cls, value: str | None) -> str | None: return _guarded_credential(value)


class HasuraBackend(BaseModel):
    '''
    A Hasura GraphQL endpoint, queried under the anonymous role (or an operator-named role).
    '''
    kind: Literal["hasura"] = "hasura"
    host: str
    role: str = "anonymous"
    credential: str | None = None
    resources: list[str] = Field(default_factory=list)

    @field_validator("credential")
    @classmethod
    def _guard(cls, value: str | None) -> str | None: return _guarded_credential(value)


class PocketBaseBackend(BaseModel):
    '''
    A PocketBase instance; one collection's list endpoint per resource.
    '''
    kind: Literal["pocketbase"] = "pocketbase"
    base_url: str
    credential: str | None = None
    resources: list[str] = Field(default_factory=list)

    @field_validator("base_url")
    @classmethod
    def _check_url(cls, value: str) -> str: return _validated_url(value)

    @field_validator("credential")
    @classmethod
    def _guard(cls, value: str | None) -> str | None: return _guarded_credential(value)


class RestGenericBackend(BaseModel):
    '''
    A bare REST API with a public, client-shipped key. The operator names the key header/param and, per
    resource, what an open vs denied response looks like.
    '''
    kind: Literal["rest_generic"] = "rest_generic"
    base_url: str
    credential_header: str | None = None
    credential_param: str | None = None
    credential: str | None = None
    resources: list[RestResource] = Field(default_factory=list)

    @field_validator("base_url")
    @classmethod
    def _check_url(cls, value: str) -> str: return _validated_url(value)

    @field_validator("credential")
    @classmethod
    def _guard(cls, value: str | None) -> str | None: return _guarded_credential(value)


class GraphQLGenericBackend(BaseModel):
    '''
    A bare GraphQL endpoint with an operator-supplied minimal query per resource.
    '''
    kind: Literal["graphql_generic"] = "graphql_generic"
    url: str
    credential_header: str | None = None
    credential: str | None = None
    resources: list[GraphQLResource] = Field(default_factory=list)

    @field_validator("url")
    @classmethod
    def _check_url(cls, value: str) -> str: return _validated_url(value)

    @field_validator("credential")
    @classmethod
    def _guard(cls, value: str | None) -> str | None: return _guarded_credential(value)


Backend = Annotated[
    Union[SupabaseBackend, FirebaseBackend, HasuraBackend, PocketBaseBackend,
          RestGenericBackend, GraphQLGenericBackend],
    Field(discriminator="kind"),
]


class AutoDiscover(BaseModel):
    '''
    Authorizes automated discover-and-test: a committed, standing assertion that the operator owns the
    listed registrable domains, so each run may passively discover first-party assets under them and
    actively test them without a per-run human step.
    '''
    authorized_domains: list[str] = Field(default_factory=list)
    checks: list[str] = Field(default_factory=list)

    @field_validator("authorized_domains")
    @classmethod
    def _require_domains(cls, value: list[str]) -> list[str]:
        '''
        Require at least one authorized domain, so auto-discovery always has an ownership boundary.
        Parameters:
            value (list[str]): The configured domains.
        Returns:
            list[str]: The domains, lowercased and trimmed.
        Raises:
            ValueError: If no domain is given.
        '''
        cleaned = [d.strip().lower().rstrip(".") for d in value if d.strip()]
        if not cleaned:
            raise ValueError("auto_discover.authorized_domains must list at least one domain you own")
        return cleaned


class ExternalIntelligence(BaseModel):
    '''
    Authorizes the external-intelligence phase: querying third-party providers (Wayback, Shodan InternetDB)
    about the target. These providers contact their own hosts, not the target's scope, and doing so
    discloses the target to them — hence it is gated by this authorization like any other active capability.
    '''
    providers: list[str] = Field(default_factory=list)


class ActiveScope(BaseModel):
    '''
    The hosts active checks may contact. Authored by hand; never inferred from a passive scan.
    '''
    hosts: list[str] = Field(default_factory=list)
    exclude_hosts: list[str] = Field(default_factory=list)
    tls_authorized_hosts: list[str] = Field(default_factory=list)

    def normalized_hosts(self) -> set[str]:
        '''
        In-scope hosts minus exclusions, lowercased.
        '''
        excluded: set[str] = {h.strip().lower().rstrip(".") for h in self.exclude_hosts}
        return {h.strip().lower().rstrip(".") for h in self.hosts if h.strip()} - excluded

    def allows(self, host: str | None) -> bool:
        '''
        Whether a host is in the active scope (exact match only — no implicit subdomains).
        Parameters:
            host (str | None): Hostname to test.
        Returns:
            bool: True if explicitly listed and not excluded.
        '''
        if not host: return False
        return host.strip().lower().rstrip(".") in self.normalized_hosts()

    def tls_authorized(self, host: str) -> bool:
        '''
        Whether a host carries the extra per-host opt-in required for TLS protocol enumeration.
        Parameters:
            host (str): Hostname to test.
        Returns:
            bool: True if listed in tls_authorized_hosts and in scope.
        '''
        allowed = {h.strip().lower().rstrip(".") for h in self.tls_authorized_hosts}
        return self.allows(host) and host.strip().lower().rstrip(".") in allowed


class AuthorizationFile(BaseModel):
    '''
    A parsed, validated active-testing authorization.
    '''
    target: str
    authorized_by: str
    authorized_on: date
    window: TimeWindow
    scope: ActiveScope = Field(default_factory=ActiveScope)
    checks_enabled: list[str] = Field(default_factory=list)
    rate_limit_rps: float = 1.0
    max_requests: int = 100
    max_requests_per_check: int = 50
    backends: list[Backend] = Field(default_factory=list)
    auto_discover: AutoDiscover | None = None
    external_intelligence: ExternalIntelligence | None = None
    supabase: SupabaseTarget | None = None
    function_urls: list[FunctionUrlTarget] = Field(default_factory=list)
    email_endpoints: list[EmailEndpointTarget] = Field(default_factory=list)
    ip_trust_endpoints: list[IpTrustTarget] = Field(default_factory=list)

    @field_validator("rate_limit_rps")
    @classmethod
    def _cap_rps(cls, value: float) -> float: return value if math.isfinite(value) and 0.1 <= value <= 10.0 else (_ for _ in ()).throw(ValueError("rate_limit_rps must be a finite number between 0.1 and 10.0"))

    @field_validator("max_requests")
    @classmethod
    def _cap_budget(cls, value: int) -> int: return value if 1 <= value <= 1000 else (_ for _ in ()).throw(ValueError("max_requests must be between 1 and 1000"))

    @field_validator("max_requests_per_check")
    @classmethod
    def _cap_per_check(cls, value: int) -> int: return value if 1 <= value <= 1000 else (_ for _ in ()).throw(ValueError("max_requests_per_check must be between 1 and 1000"))

    @model_validator(mode="after")
    def _normalize_backends(self) -> AuthorizationFile:
        '''
        Fold a deprecated top-level ``supabase`` block into ``backends`` and migrate the old
        ``supabase_rls`` check id, so existing authorization files keep working against the reframed
        ``backend_read_access`` check without the operator editing anything.
        Returns:
            AuthorizationFile: The normalized authorization.
        '''
        if self.supabase is not None and not any(
                getattr(b, "kind", None) == "supabase" and getattr(b, "host", None) == self.supabase.host
                for b in self.backends):
            self.backends = [*self.backends, SupabaseBackend(
                host=self.supabase.host, credential=self.supabase.anon_key, resources=list(self.supabase.tables))]
        if "supabase_rls" in self.checks_enabled:
            self.checks_enabled = list(dict.fromkeys(
                "backend_read_access" if c == "supabase_rls" else c for c in self.checks_enabled))
        return self

    def validate_window(self, now: datetime) -> None:
        '''
        Ensure the current time is inside the authorized window.
        Parameters:
            now (datetime): Current time (aware).
        Raises:
            AuthorizationError: If outside the window.
        '''
        if self.window.start > self.window.end: raise AuthorizationError("authorization window start is after its end")

        if not self.window.contains(now):
            raise AuthorizationError(
                f"outside the authorized window ({self.window.start.isoformat()} .. "
                f"{self.window.end.isoformat()}); current time is {now.isoformat()}")


def _validated_url(url: str) -> str:
    '''
    Require an absolute http(s) URL with a hostname.
    Parameters:
        url (str): Candidate URL.
    Returns:
        str: The trimmed URL.
    Raises:
        ValueError: If the scheme is not http/https or the host is missing.
    '''
    trimmed: str = url.strip()
    parts = urlsplit(trimmed)
    if parts.scheme not in ("http", "https"): raise ValueError(f"url must be http(s): {url!r}")
    if not parts.hostname: raise ValueError(f"url has no host: {url!r}")
    return trimmed


def _validated_method(method: str) -> str:
    '''
    Normalize an HTTP method and restrict it to a known-safe set.
    Parameters:
        method (str): Candidate method.
    Returns:
        str: The upper-cased method.
    Raises:
        ValueError: If the method is not recognized.
    '''
    normalized: str = method.strip().upper()
    if normalized not in _HTTP_METHODS: raise ValueError(f"unsupported HTTP method: {method!r}")
    return normalized


def _jwt_role_hint(token: str) -> str:
    '''
    Read a JWT's 'role' claim for the service-role guard, with strict structural checks (no signature check).
    Parameters:
        token (str): Candidate key.
    Returns:
        str: The role string, or '' if the token is not a decodable three-segment JWT.
    '''
    parts: list[str] = token.strip().split(".")
    if len(parts) != 3 or not all(part and _B64URL.match(part) for part in parts): return ""

    try:
        payload: str = parts[1] + "=" * (-len(parts[1]) % 4)
        claims: Any = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, binascii.Error): return ""

    return str(claims.get("role", "")) if isinstance(claims, dict) else ""


def load_authorization(path: Path) -> AuthorizationFile:
    '''
    Load and validate an authorization file (YAML or JSON), raising a specific error on any problem.
    Parameters:
        path (Path): Path to the authorization file.
    Returns:
        AuthorizationFile: The validated authorization.
    Raises:
        AuthorizationError: If the file is missing, not UTF-8, unparseable, or fails validation.
    '''
    try:
        text: str = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise AuthorizationError(f"authorization file {path} is not valid UTF-8: {exc}") from exc
    except OSError as exc:
        raise AuthorizationError(f"cannot read authorization file {path}: {exc}") from exc
    try:
        data: Any = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise AuthorizationError(f"authorization file is not valid YAML/JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise AuthorizationError("authorization file must be a mapping of fields")
    try:
        auth = AuthorizationFile.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors())
        raise AuthorizationError(f"authorization file is invalid: {problems}") from exc
    if not auth.scope.normalized_hosts() and auth.checks_enabled:
        raise AuthorizationError("checks are enabled but scope.hosts is empty")

    return auth


def _redact_backend(backend: Backend) -> dict[str, Any]:
    '''
    A report-safe summary of one backend entry: its kind, where it points, and its resources, with any
    credential replaced by a non-reversible descriptor.
    Parameters:
        backend (Backend): The backend entry.
    Returns:
        dict[str, Any]: JSON-serializable summary with the credential redacted.
    '''
    out: dict[str, Any] = {"kind": backend.kind}
    if isinstance(backend, SupabaseBackend):
        out["host"] = backend.host
        out["resources"] = list(backend.resources)
    elif isinstance(backend, FirebaseBackend):
        out["project_id"] = backend.project_id
        out["database"] = backend.database
        out["resources"] = list(backend.resources)
    elif isinstance(backend, HasuraBackend):
        out["host"] = backend.host
        out["role"] = backend.role
        out["resources"] = list(backend.resources)
    elif isinstance(backend, PocketBaseBackend):
        out["base_url"] = redact_url(backend.base_url)
        out["resources"] = list(backend.resources)
    elif isinstance(backend, RestGenericBackend):
        out["base_url"] = redact_url(backend.base_url)
        out["credential_header"] = backend.credential_header
        out["credential_param"] = backend.credential_param
        out["resources"] = [f"{r.method} {r.path}" for r in backend.resources]
    elif isinstance(backend, GraphQLGenericBackend):
        out["url"] = redact_url(backend.url)
        out["credential_header"] = backend.credential_header
        out["resources"] = [r.name for r in backend.resources]
    credential: str | None = getattr(backend, "credential", None)
    if credential is not None:
        out["credential"] = redact_secret(credential)
    return out


def redact_authorization(auth: AuthorizationFile) -> dict[str, Any]:
    '''
    A report-safe view of an authorization: identity, scope and window, with any key material redacted.
    Parameters:
        auth (AuthorizationFile): The authorization.
    Returns:
        dict[str, Any]: JSON-serializable summary with secrets redacted.
    '''
    summary: dict[str, Any] = {
        "target": auth.target,
        "authorized_by": auth.authorized_by,
        "authorized_on": auth.authorized_on.isoformat(),
        "window": {"start": auth.window.start.isoformat(), "end": auth.window.end.isoformat()},
        "scope_hosts": sorted(auth.scope.normalized_hosts()),
        "tls_authorized_hosts": sorted({h.strip().lower().rstrip(".") for h in auth.scope.tls_authorized_hosts} & auth.scope.normalized_hosts()),
        "checks_enabled": list(auth.checks_enabled),
        "rate_limit_rps": auth.rate_limit_rps,
        "max_requests": auth.max_requests,
    }
    if auth.backends:
        summary["backends"] = [_redact_backend(b) for b in auth.backends]

    if auth.auto_discover is not None:
        summary["auto_discover"] = {"authorized_domains": list(auth.auto_discover.authorized_domains),
                                    "checks": list(auth.auto_discover.checks)}

    if auth.external_intelligence is not None:
        summary["external_intelligence"] = {"providers": list(auth.external_intelligence.providers)}

    if auth.function_urls:
        summary["function_urls"] = [{"url": redact_url(t.url), "method": t.method, "state_changing": t.state_changing} for t in auth.function_urls]

    if auth.email_endpoints:
        summary["email_endpoints"] = [{"url": redact_url(t.url), "method": t.method, "burst": t.burst, "confirmed_no_real_delivery": t.confirmed_no_real_delivery} for t in auth.email_endpoints]

    if auth.ip_trust_endpoints:
        summary["ip_trust_endpoints"] = [{"url": redact_url(t.url), "method": t.method, "access_control": t.access_control} for t in auth.ip_trust_endpoints]

    return summary
