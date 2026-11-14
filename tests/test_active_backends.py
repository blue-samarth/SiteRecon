import datetime as dt
import json

import httpx
import pytest
import respx

from recon.active import ActiveContext, AuthorizationFile
from recon.active.adapters import Outcome, build_adapter
from recon.active.authorization import ActiveScope, SupabaseBackend, TimeWindow
from recon.active.checks import BackendReadAccessCheck
from recon.active.credentials import reject_privileged_credential
from recon.utils.http_client import SafeHttpClient
from recon.utils.scope import Scope
from tests.conftest import public_resolve

WINDOW = TimeWindow(start=dt.datetime(2026, 11, 10, 0, 0, tzinfo=dt.UTC),
                    end=dt.datetime(2026, 11, 10, 6, 0, tzinfo=dt.UTC))


def auth(hosts, backends):
    return AuthorizationFile(target="app.test", authorized_by="op", authorized_on="2026-11-08", window=WINDOW,
                             scope=ActiveScope(hosts=hosts), rate_limit_rps=5.0, max_requests=100, backends=backends)


def context(a):
    client = SafeHttpClient(Scope(hosts=sorted(a.scope.normalized_hosts())), user_agent="t", retries=0,
                            resolve=public_resolve, max_redirects=0)

    async def _sleep(_):
        return None

    return ActiveContext(a, client, clock=lambda: 0.0, sleep=_sleep), client


async def run_check(a):
    ctx, client = context(a)
    async with client:
        return await BackendReadAccessCheck().run(ctx)


# ------------------------------------------------------------------ firebase

async def test_firebase_firestore_open_vs_denied():
    a = auth(["firestore.googleapis.com"], [{"kind": "firebase", "project_id": "p", "database": "firestore",
                                             "resources": ["users", "secrets"]}])
    with respx.mock:
        respx.get(url__startswith="https://firestore.googleapis.com/v1/projects/p/databases/(default)/documents/users").mock(
            return_value=httpx.Response(200, json={"documents": [{"name": "x"}]}))
        respx.get(url__startswith="https://firestore.googleapis.com/v1/projects/p/databases/(default)/documents/secrets").mock(
            return_value=httpx.Response(403, json={"error": {"status": "PERMISSION_DENIED"}}))
        result = await run_check(a)
    ids = {f.id for f in result.findings}
    assert ids == {"active.backend_read_access_open:firebase:firestore.googleapis.com/users"}
    assert result.requests_made == 2


async def test_firebase_realtime_db_null_is_open():
    a = auth(["p.firebaseio.com"], [{"kind": "firebase", "project_id": "p", "database": "realtime_db",
                                     "resources": ["orders"]}])
    with respx.mock:
        respx.get(url__startswith="https://p.firebaseio.com/orders.json").mock(
            return_value=httpx.Response(200, content=b"null"))
        result = await run_check(a)
    assert [f.id for f in result.findings] == ["active.backend_read_access_open:firebase:p.firebaseio.com/orders"]


# ------------------------------------------------------------------ hasura

async def test_hasura_open_and_permission_error():
    a = auth(["gql.test"], [{"kind": "hasura", "host": "gql.test", "resources": ["users", "billing"]}])
    with respx.mock:
        route = respx.post("https://gql.test/v1/graphql")
        route.side_effect = [
            httpx.Response(200, json={"data": {"users": [{"__typename": "users"}]}}),
            httpx.Response(200, json={"errors": [{"message": "field \"billing\" not found in type: 'query_root'"}]}),
        ]
        result = await run_check(a)
    assert [f.id for f in result.findings] == ["active.backend_read_access_open:hasura:gql.test/users"]
    assert route.calls[0].request.headers["x-hasura-role"] == "anonymous"
    body = json.loads(route.calls[0].request.content)
    assert body["query"] == "query { users(limit: 1) { __typename } }"


# ------------------------------------------------------------------ pocketbase

async def test_pocketbase_open_vs_denied():
    a = auth(["pb.test"], [{"kind": "pocketbase", "base_url": "https://pb.test", "resources": ["posts", "admins"]}])
    with respx.mock:
        respx.get(url__startswith="https://pb.test/api/collections/posts/records").mock(
            return_value=httpx.Response(200, json={"items": [{"id": "1"}], "totalItems": 1}))
        respx.get(url__startswith="https://pb.test/api/collections/admins/records").mock(
            return_value=httpx.Response(403, json={"code": 403, "message": "Only admins can access."}))
        result = await run_check(a)
    assert [f.id for f in result.findings] == ["active.backend_read_access_open:pocketbase:pb.test/posts"]


# ------------------------------------------------------------------ generic REST

async def test_rest_generic_uses_operator_success_and_denied_specs():
    backend = {"kind": "rest_generic", "base_url": "https://api.test", "credential_header": "X-Api-Key",
               "credential": "pk_live_public123", "resources": [
                   {"path": "/v1/users?limit=1", "success_if": {"status": 200, "body_contains": "email"},
                    "denied_if": {"status": [401, 403]}},
                   {"path": "/v1/admin", "success_if": {"status": 200}, "denied_if": {"status": [401, 403]}}]}
    a = auth(["api.test"], [backend])
    with respx.mock:
        users = respx.get(url__startswith="https://api.test/v1/users").mock(
            return_value=httpx.Response(200, content=b'[{"email":"a@b.com"}]'))
        respx.get(url__startswith="https://api.test/v1/admin").mock(return_value=httpx.Response(401))
        result = await run_check(a)
    assert [f.id for f in result.findings] == ["active.backend_read_access_open:rest_generic:api.test/GET /v1/users?limit=1"]
    assert users.calls[0].request.headers["X-Api-Key"] == "pk_live_public123"   # operator-named key header is sent


async def test_rest_generic_no_finding_when_neither_spec_matches():
    backend = {"kind": "rest_generic", "base_url": "https://api.test", "resources": [
        {"path": "/x", "success_if": {"status": 200}, "denied_if": {"status": [403]}}]}
    a = auth(["api.test"], [backend])
    with respx.mock:
        respx.get(url__startswith="https://api.test/x").mock(return_value=httpx.Response(500))
        result = await run_check(a)
    assert result.findings == []   # 500 matched neither success_if nor denied_if → inconclusive


async def test_rest_generic_credential_param_is_redacted_in_evidence():
    backend = {"kind": "rest_generic", "base_url": "https://api.test", "credential_param": "apikey",
               "credential": "pk_live_public123", "resources": [
                   {"path": "/data", "success_if": {"status": 200}}]}
    a = auth(["api.test"], [backend])
    with respx.mock:
        respx.get(url__startswith="https://api.test/data").mock(return_value=httpx.Response(200, content=b"{}"))
        result = await run_check(a)
    assert result.findings and "pk_live_public123" not in result.model_dump_json()


# ------------------------------------------------------------------ generic GraphQL

async def test_graphql_generic_open_and_errors():
    backend = {"kind": "graphql_generic", "url": "https://g.test/graphql", "resources": [
        {"name": "me", "query": "query { me { id } }"},
        {"name": "admins", "query": "query { admins { id } }"}]}
    a = auth(["g.test"], [backend])
    with respx.mock:
        route = respx.post("https://g.test/graphql")
        route.side_effect = [
            httpx.Response(200, json={"data": {"me": {"id": "1"}}}),
            httpx.Response(200, json={"data": None, "errors": [{"message": "access denied"}]}),
        ]
        result = await run_check(a)
    assert [f.id for f in result.findings] == ["active.backend_read_access_open:graphql_generic:g.test/me"]


# ------------------------------------------------------------------ guards & scope

def test_privileged_credential_guard_recognizes_server_secrets():
    assert reject_privileged_credential(None) is None
    assert reject_privileged_credential("pk_live_public") is None                 # public key is fine
    assert "secret key" in reject_privileged_credential("sb_secret_abc")
    assert "service-account" in reject_privileged_credential('{"type": "service_account", "x": 1}')
    assert "service-account" in reject_privileged_credential("-----BEGIN PRIVATE KEY-----\nabc")
    assert "stripe" in (reject_privileged_credential("sk_live_" + "a" * 24) or "")


async def test_check_refuses_privileged_credential_at_runtime():
    # model_construct bypasses field validation, so run() must still refuse to send the probe
    bad = SupabaseBackend.model_construct(kind="supabase", host="sb.test", credential="sb_secret_leak", resources=["t"])
    a = auth(["sb.test"], [])
    object.__setattr__(a, "backends", [bad])
    ctx, client = context(a)
    with respx.mock:
        route = respx.get(url__startswith="https://sb.test/rest/v1/t").mock(return_value=httpx.Response(200, content=b"[]"))
        async with client:
            result = await BackendReadAccessCheck().run(ctx)
    assert not route.called and result.findings == []
    assert any(e.error_type == "privileged_credential" for e in result.errors)


def test_build_adapter_rejects_unknown_kind():
    bad = SupabaseBackend.model_construct(kind="nosuchkind")
    with pytest.raises(ValueError, match="no adapter"):
        build_adapter(bad)


def test_adapter_outcomes_are_stable_enum():
    assert {o.value for o in Outcome} == {"open", "denied", "not_found", "error"}
