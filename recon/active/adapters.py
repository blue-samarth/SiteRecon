from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, ClassVar
from urllib.parse import urlencode, urlsplit

from recon.active.credentials import reject_privileged_credential
from recon.utils import RawResponse

if TYPE_CHECKING:
    from recon.active.authorization import (
        Backend,
        FirebaseBackend,
        GraphQLGenericBackend,
        GraphQLResource,
        HasuraBackend,
        PocketBaseBackend,
        RestGenericBackend,
        RestResource,
        SupabaseBackend,
    )


class Outcome(str, Enum):
    '''
    How an adapter read a single probe response.
    '''
    OPEN = "open"            # the resource was readable with the supplied public/client-side credential
    DENIED = "denied"        # the backend refused the read (RLS/rules/permissions working) — no finding
    NOT_FOUND = "not_found"  # the resource does not exist — no finding
    ERROR = "error"          # inconclusive (transport error, unexpected shape) — no finding


@dataclass(slots=True)
class ProbeRequest:
    '''
    One read-only request an adapter wants the shared context to send for one resource.
    '''
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    content: bytes | None = None
    note: str = ""


@dataclass(slots=True)
class ProbeOutcome:
    '''
    An adapter's reading of one probe response: the classification plus a short, report-safe detail string.
    '''
    outcome: Outcome
    detail: str = ""

    @property
    def is_open(self) -> bool: return self.outcome is Outcome.OPEN


class BackendAdapter(ABC):
    '''
    Base class for a backend adapter: builds one read-only probe per resource and interprets the response.

    An adapter instance is bound to one operator-authored backend entry, so it carries that entry's host,
    credential and resource list. ``build_probe`` and ``interpret`` both take the resource because the
    generic adapters need the operator's per-resource request shape and success/denied definition.
    '''

    kind: ClassVar[str]

    def __init__(self, backend: Backend) -> None:
        '''
        Bind the adapter to a backend configuration entry.
        Parameters:
            backend (Backend): The operator-authored backend entry.
        '''
        self.backend = backend

    @property
    @abstractmethod
    def host(self) -> str:
        '''
        The hostname the probes contact; must be in ``scope.hosts`` for the check to run.
        Returns:
            str: The hostname.
        '''

    @abstractmethod
    def resources(self) -> list[Any]:
        '''
        The resource descriptors to probe, de-duplicated and in order.
        Returns:
            list[Any]: Resource identifiers (a table/collection name, or a richer per-resource model).
        '''

    @abstractmethod
    def build_probe(self, resource: Any) -> ProbeRequest:
        '''
        Build the single read-only request for one resource.
        Parameters:
            resource (Any): One item from :meth:`resources`.
        Returns:
            ProbeRequest: The request to send.
        '''

    @abstractmethod
    def interpret(self, resource: Any, response: RawResponse) -> ProbeOutcome:
        '''
        Classify a probe response as open / denied / not_found / error.
        Parameters:
            resource (Any): The resource that was probed.
            response (RawResponse): The response received.
        Returns:
            ProbeOutcome: The classification and a short detail string.
        '''

    @abstractmethod
    def label(self, resource: Any) -> str:
        '''
        A short, human-readable name for a resource, used in the finding subject and evidence.
        Parameters:
            resource (Any): One item from :meth:`resources`.
        Returns:
            str: The label.
        '''

    def credential(self) -> str | None: return getattr(self.backend, "credential", None)
    def credential_guard(self) -> str | None: return reject_privileged_credential(self.credential())


def _loads(body: bytes | None) -> Any:
    '''
    Parse a JSON body, returning a sentinel-free None on any failure.
    Parameters:
        body (bytes | None): Response body.
    Returns:
        Any: The decoded value, or None if it is absent or not JSON.
    '''
    if not body: return None
    try:
        return json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None


def _text(body: bytes | None, limit: int = 2000) -> str: return body[:limit * 4].decode("utf-8", "replace")[:limit] if body else ""

def _dedupe(items: list[str]) -> list[str]: return list(dict.fromkeys(items))

def _first_graphql_error(data: Any) -> str:
    '''
    Extract the first GraphQL error message from a response for evidence, if present.
    Parameters:
        data (Any): Decoded response body.
    Returns:
        str: The first error message, or a generic label.
    '''
    if isinstance(data, dict):
        errors: list[dict]|None = data.get("errors")
        if isinstance(errors, list) and errors and isinstance(errors[0], dict):
            msg: str | None = errors[0].get("message")
            if isinstance(msg, str): return msg[:200]
    return "GraphQL errors present"




class SupabaseAdapter(BackendAdapter):
    '''
    Supabase (PostgREST). One ``select`` per table with the public anon key; rows (or an authorized empty
    array) mean row-level security is not restricting anonymous reads.
    '''

    kind: ClassVar[str] = "supabase"

    @property
    def host(self) -> str:
        backend: SupabaseBackend = self.backend
        return backend.host

    def resources(self) -> list[str]:
        backend: SupabaseBackend = self.backend
        return _dedupe(backend.resources)

    def label(self, resource: Any) -> str: return str(resource)

    def build_probe(self, resource: Any) -> ProbeRequest:
        '''
        Build a GET request to ``https://<host>/rest/v1/<table>?select=*&limit=1`` with the anon key
        Parameters:
            resource (Any): One item from :meth:`resources`.
        Returns:
            ProbeRequest: The request to send.
        '''
        backend: SupabaseBackend = self.backend
        key: str = backend.credential
        url: str = f"https://{backend.host}/rest/v1/{resource}?select=*&limit=1"
        headers: dict[str, str] = {"apikey": key, "Authorization": f"Bearer {key}", "Accept": "application/json"}
        return ProbeRequest("GET", url, headers, None, f"supabase read probe: {resource}")

    def interpret(self, resource: Any, response: RawResponse) -> ProbeOutcome:
        '''
        Classify a Supabase probe response as open / denied / not_found / error.
        Parameters:
            resource (Any): The resource that was probed.
            response (RawResponse): The response received.
        Returns:
            ProbeOutcome: The classification and a short detail string.
        '''
        status: int = response.status_code
        if status == 200:
            data: list | dict = _loads(response.body)
            if isinstance(data, list):
                return ProbeOutcome(Outcome.OPEN, f"HTTP 200, {len(data)} row(s) returned (anon select authorized)")
            return ProbeOutcome(Outcome.ERROR, "HTTP 200 but body was not a JSON array")
        if status in (401, 403):
            return ProbeOutcome(Outcome.DENIED, f"HTTP {status} (PostgREST refused the anon read)")
        if status == 404:
            return ProbeOutcome(Outcome.NOT_FOUND, "HTTP 404 (no such table/endpoint)")
        return ProbeOutcome(Outcome.ERROR, f"HTTP {status}")



class FirebaseAdapter(BackendAdapter):
    '''
    Firebase. Reads one Firestore collection (REST) or one Realtime Database path with no auth (or the
    supplied public API key); a 200 with data means the security rules allow the anonymous read.
    '''

    kind: ClassVar[str] = "firebase"

    @property
    def host(self) -> str:
        '''
        The host to use for the Firebase API.
        Returns:
            str: The host, either ``<project>.firebaseio.com`` for Realtime Database or ``firestore.googleapis.com`` for Firestore.
        '''
        backend: FirebaseBackend = self.backend
        if backend.database == "realtime_db":
            return f"{backend.project_id}.firebaseio.com"
        return "firestore.googleapis.com"

    def resources(self) -> list[str]:
        '''
        The list of paths (Realtime Database) or collections (Firestore) to probe.
        Returns:
            list[str]: The list of resources to probe.
        '''
        backend: FirebaseBackend = self.backend
        return _dedupe(backend.resources)

    def label(self, resource: Any) -> str: return str(resource)

    def build_probe(self, resource: Any) -> ProbeRequest:
        '''
        Build a probe request for the given resource.
        Parameters:
            resource (Any): One item from :meth:`resources`.
        Returns:
            ProbeRequest: The request to send.
        '''
        backend: FirebaseBackend = self.backend
        cred: str | None = backend.credential
        headers: dict[str, str] = {"Accept": "application/json"}
        if backend.database == "realtime_db":
            path: str = str(resource).strip("/")
            url: str = f"https://{backend.project_id}.firebaseio.com/{path}.json"

            if cred: url += "?" + urlencode({"auth": cred})
        else:
            collection: str = str(resource).strip("/")
            url = (f"https://firestore.googleapis.com/v1/projects/{backend.project_id}"
                   f"/databases/(default)/documents/{collection}")

            if cred: url += "?" + urlencode({"key": cred})
        return ProbeRequest("GET", url, headers, None, f"firebase {backend.database} read probe: {resource}")

    def interpret(self, resource: Any, response: RawResponse) -> ProbeOutcome:
        '''
        Interpret the response to a probe request.
        Parameters:
            resource (Any): One item from :meth:`resources`.
            response (RawResponse): The response from the probe.
        Returns:
            ProbeOutcome: The outcome of the probe.
        '''
        backend: FirebaseBackend = self.backend
        status: int = response.status_code
        text: str = _text(response.body)
        if "PERMISSION_DENIED" in text or "Permission denied" in text or status in (401, 403):
            return ProbeOutcome(Outcome.DENIED, f"HTTP {status} (rules denied the read)")
        if status == 200:
            data = _loads(response.body)
            if backend.database == "realtime_db":
                # 200 + null means the path is readable but empty; still an allowed anonymous read.
                detail = "null (readable, no data at path)" if data is None else "data returned"
                return ProbeOutcome(Outcome.OPEN, f"HTTP 200, {detail}")

            if isinstance(data, dict) and "documents" in data:
                docs: list | None = data.get("documents")
                count = len(docs) if isinstance(docs, list) else 0
                return ProbeOutcome(Outcome.OPEN, f"HTTP 200, {count} document(s) (rules allow anonymous read)")

            return ProbeOutcome(Outcome.OPEN, "HTTP 200 (rules allow anonymous read; empty collection)")
        
        if "NOT_FOUND" in text or status == 404:
            return ProbeOutcome(Outcome.NOT_FOUND, f"HTTP {status}")
        return ProbeOutcome(Outcome.ERROR, f"HTTP {status}")



class HasuraAdapter(BackendAdapter):
    '''
    Hasura (GraphQL). Sends a minimal ``{ <type>(limit: 1) { __typename } }`` query under the anonymous
    role; data for the type means the role can select it, a permission/field error means it cannot.
    '''

    kind: ClassVar[str] = "hasura"

    @property
    def host(self) -> str:
        backend: HasuraBackend = self.backend
        return backend.host

    def resources(self) -> list[str]:
        backend: HasuraBackend = self.backend
        return _dedupe(backend.resources)

    def label(self, resource: Any) -> str:
        return str(resource)

    def build_probe(self, resource: Any) -> ProbeRequest:
        backend: HasuraBackend = self.backend
        url: str = f"https://{backend.host}/v1/graphql"
        headers: dict[str, str] = {"Content-Type": "application/json", "x-hasura-role": backend.role}
        if backend.credential:
            headers["Authorization"] = f"Bearer {backend.credential}"
        query: str = "query { %s(limit: 1) { __typename } }" % resource
        content: bytes = json.dumps({"query": query}).encode("utf-8")
        return ProbeRequest("POST", url, headers, content, f"hasura read probe: {resource} (role {backend.role})")

    def interpret(self, resource: Any, response: RawResponse) -> ProbeOutcome:
        backend: HasuraBackend = self.backend
        status: int = response.status_code
        data = _loads(response.body)
        if status in (401, 403):
            return ProbeOutcome(Outcome.DENIED, f"HTTP {status}")
        if status == 200 and isinstance(data, dict):
            if data.get("errors"):
                return ProbeOutcome(Outcome.DENIED, f"HTTP 200, GraphQL error: {_first_graphql_error(data)}")
            payload = data.get("data")
            if isinstance(payload, dict) and resource in payload:
                rows = payload[resource]
                count = len(rows) if isinstance(rows, list) else "?"
                return ProbeOutcome(Outcome.OPEN,
                                    f"HTTP 200, {count} row(s) for '{resource}' (role {backend.role} can select)")
            return ProbeOutcome(Outcome.ERROR, "HTTP 200 but no data for the queried type")
        return ProbeOutcome(Outcome.ERROR, f"HTTP {status}")



class PocketBaseAdapter(BackendAdapter):
    '''
    PocketBase. Lists one record from a collection; a 200 with an ``items`` array means the collection's
    list rule allows anonymous access.
    '''

    kind: ClassVar[str] = "pocketbase"

    @property
    def host(self) -> str:
        backend: PocketBaseBackend = self.backend
        return urlsplit(backend.base_url).hostname or ""

    def resources(self) -> list[str]:
        backend: PocketBaseBackend = self.backend
        return _dedupe(backend.resources)

    def label(self, resource: Any) -> str:
        return str(resource)

    def build_probe(self, resource: Any) -> ProbeRequest:
        backend: PocketBaseBackend = self.backend
        base: str = backend.base_url.rstrip("/")
        url: str = f"{base}/api/collections/{resource}/records?perPage=1"
        headers: dict[str, str] = {"Accept": "application/json"}
        if backend.credential:
            headers["Authorization"] = backend.credential
        return ProbeRequest("GET", url, headers, None, f"pocketbase read probe: {resource}")

    def interpret(self, resource: Any, response: RawResponse) -> ProbeOutcome:
        status: int = response.status_code
        data = _loads(response.body)
        if status == 200 and isinstance(data, dict) and "items" in data:
            items = data.get("items")
            count = len(items) if isinstance(items, list) else "?"
            return ProbeOutcome(Outcome.OPEN, f"HTTP 200, {count} record(s) (list rule allows anonymous access)")
        if status in (400, 401, 403):
            return ProbeOutcome(Outcome.DENIED, f"HTTP {status} (list rule denied anonymous access)")
        if status == 404:
            return ProbeOutcome(Outcome.NOT_FOUND, "HTTP 404 (no such collection)")
        return ProbeOutcome(Outcome.ERROR, f"HTTP {status}")


# --------------------------------------------------------------------------- generic REST


class RestGenericAdapter(BackendAdapter):
    '''
    A bare REST API with a public key shipped to the client. There is no universal "open"/"denied"
    convention, so the operator supplies, per resource, the request shape and what a success/denied
    response looks like; the adapter only applies those rules.
    '''

    kind: ClassVar[str] = "rest_generic"

    @property
    def host(self) -> str:
        backend: RestGenericBackend = self.backend
        return urlsplit(backend.base_url).hostname or ""

    def resources(self) -> list[RestResource]:
        backend: RestGenericBackend = self.backend
        return list(backend.resources)

    def label(self, resource: Any) -> str:
        return f"{resource.method} {resource.path}"

    def build_probe(self, resource: Any) -> ProbeRequest:
        backend: RestGenericBackend = self.backend
        base: str = backend.base_url.rstrip("/")
        path: str = resource.path if resource.path.startswith("/") else "/" + resource.path
        url: str = base + path
        headers: dict[str, str] = {}
        if backend.credential and backend.credential_header:
            headers[backend.credential_header] = backend.credential
        if backend.credential and backend.credential_param:
            url += ("&" if "?" in url else "?") + urlencode({backend.credential_param: backend.credential})
        return ProbeRequest(resource.method, url, headers, None,
                            f"rest_generic read probe: {resource.method} {path}")

    def interpret(self, resource: Any, response: RawResponse) -> ProbeOutcome:
        status: int = response.status_code
        text: str = _text(response.body)
        # denied_if is checked first so an endpoint that matches both never reports a false "open".
        if resource.denied_if is not None and _match(resource.denied_if, status, text):
            return ProbeOutcome(Outcome.DENIED, f"HTTP {status} matched denied_if")
        if _match(resource.success_if, status, text):
            return ProbeOutcome(Outcome.OPEN, f"HTTP {status} matched success_if")
        return ProbeOutcome(Outcome.ERROR, f"HTTP {status} matched neither success_if nor denied_if")


def _match(spec: Any, status: int, text: str) -> bool:
    '''
    Whether a response matches an operator-supplied success/denied spec (status AND body, when both given).
    Parameters:
        spec (MatchSpec): The operator's match spec.
        status (int): Response status code.
        text (str): Decoded response body (bounded).
    Returns:
        bool: True if every stated condition holds.
    '''
    statuses = spec.statuses()
    if statuses and status not in statuses:
        return False
    if spec.body_contains is not None and spec.body_contains not in text:
        return False
    return True



class GraphQLGenericAdapter(BackendAdapter):
    '''
    A bare GraphQL endpoint. The operator supplies a minimal query (and optional variables) per resource,
    with or without the public key; data and no errors means the read succeeded unauthenticated.
    '''

    kind: ClassVar[str] = "graphql_generic"

    @property
    def host(self) -> str:
        backend: GraphQLGenericBackend = self.backend
        return urlsplit(backend.url).hostname or ""

    def resources(self) -> list[GraphQLResource]:
        backend: GraphQLGenericBackend = self.backend
        return list(backend.resources)

    def label(self, resource: Any) -> str:
        return str(resource.name)

    def build_probe(self, resource: Any) -> ProbeRequest:
        backend: GraphQLGenericBackend = self.backend
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if backend.credential and backend.credential_header:
            headers[backend.credential_header] = backend.credential
        content: bytes = json.dumps({"query": resource.query, "variables": resource.variables}).encode("utf-8")
        return ProbeRequest("POST", backend.url, headers, content, f"graphql_generic read probe: {resource.name}")

    def interpret(self, resource: Any, response: RawResponse) -> ProbeOutcome:
        status: int = response.status_code
        data = _loads(response.body)
        if status in (401, 403):
            return ProbeOutcome(Outcome.DENIED, f"HTTP {status}")
        if status == 200 and isinstance(data, dict):
            if data.get("errors"):
                return ProbeOutcome(Outcome.DENIED, f"HTTP 200, GraphQL error: {_first_graphql_error(data)}")
            if data.get("data") is not None:
                return ProbeOutcome(Outcome.OPEN, "HTTP 200, data returned with no errors")
            return ProbeOutcome(Outcome.ERROR, "HTTP 200 but no data and no errors")
        return ProbeOutcome(Outcome.ERROR, f"HTTP {status}")


_ADAPTERS: dict[str, type[BackendAdapter]] = {
    cls.kind: cls
    for cls in (SupabaseAdapter, FirebaseAdapter, HasuraAdapter, PocketBaseAdapter,
                RestGenericAdapter, GraphQLGenericAdapter)
}


def build_adapter(backend: Backend) -> BackendAdapter:
    '''
    Instantiate the adapter for a backend entry, dispatching on its ``kind``.
    Parameters:
        backend (Backend): A validated backend configuration entry.
    Returns:
        BackendAdapter: The adapter bound to that entry.
    Raises:
        ValueError: If no adapter is registered for the backend's kind.
    '''
    try:
        adapter_cls = _ADAPTERS[backend.kind]
    except KeyError as exc:
        raise ValueError(f"no adapter registered for backend kind {backend.kind!r}") from exc
    return adapter_cls(backend)
