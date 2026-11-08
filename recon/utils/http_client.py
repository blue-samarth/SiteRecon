'''
Scope-restricted HTTP client.

Every request (including each redirect hop) is checked before it is sent:
  * scheme must be http/https,
  * hostname must be inside the client's ``Scope``,
  * every address the hostname resolves to must be publicly routable
    (blocks localhost, private ranges, link-local / cloud metadata) unless
    private networks were explicitly allowed.

Redirects are followed manually so each hop is validated and recorded. Response
bodies are read up to a size cap. Only transient failures are retried.

Known limitation: the address check and httpx's own connection resolve the name
separately, so a DNS-rebinding attacker could in theory answer differently. This
is acceptable for a reconnaissance tool talking to an operator-chosen target.
'''

from __future__ import annotations

import asyncio
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from time import perf_counter
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from recon.utils.resolver import system_resolve
from recon.utils.scope import Scope, is_public_ip

Resolve = Callable[[str, int], Awaitable[list[str]]]

REDIRECT_STATUSES: set[int] = {301, 302, 303, 307, 308}
RETRY_STATUSES: set[int] = {429, 502, 503, 504}
_MAX_RETRY_AFTER: float = 5.0


class BlockedRequestError(Exception):
    '''
    Raised when a request is refused by scope or address-safety checks.
    '''
    def __init__(self, reason: str, detail: str) -> None:
        '''
        Create the error.
        Parameters:
            reason (str): Machine-readable reason (out_of_scope, blocked_address, ...).
            detail (str): Human-readable detail.
        '''
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


@dataclass(slots=True)
class RawResponse:
    '''
    A single HTTP response with a size-capped body.
    '''
    url: str
    status_code: int
    http_version: str
    headers: list[tuple[str, str]]
    body: bytes
    truncated: bool
    elapsed_ms: float

    def header(self, name: str) -> str | None:
        '''
        Return the first value of a header (case-insensitive).
        Parameters:
            name (str): Header name.
        Returns:
            str | None: Header value or None.
        '''
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return None


@dataclass(slots=True)
class FetchOutcome:
    '''
    Result of a redirect-following fetch: every response, the terminal one, and why it stopped.
    '''
    requested_url: str
    responses: list[RawResponse] = field(default_factory=list)
    final: RawResponse | None = None
    stopped_reason: str | None = None   # out_of_scope, blocked_address, redirect_loop, ...
    stopped_url: str | None = None      # URL that was not requested
    error: str | None = None
    error_type: str | None = None


class SafeHttpClient:
    '''
    HTTP client that enforces scope, blocks non-public destinations, caps bodies and retries transient failures.
    '''
    def __init__(
        self,
        scope: Scope,
        *,
        timeout: float = 10.0,
        retries: int = 2,
        user_agent: str,
        max_response_bytes: int = 5 * 1024 * 1024,
        max_redirects: int = 10,
        concurrency: int = 10,
        allow_private_networks: bool = False,
        extra_headers: dict[str, str] | None = None,
        resolve: Resolve = system_resolve,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        '''
        Create the client.
        Parameters:
            scope (Scope): Hostnames this client may contact.
            timeout (float): Per-operation timeout in seconds.
            retries (int): Number of retries for transient failures.
            user_agent (str): User-Agent header value.
            max_response_bytes (int): Body size cap per response.
            max_redirects (int): Maximum redirects to follow.
            concurrency (int): Maximum concurrent requests.
            allow_private_networks (bool): Permit connections to non-public addresses.
            extra_headers (dict[str, str] | None): Additional default headers.
            resolve (Resolve): Async hostname resolver (injectable for tests).
            transport (httpx.AsyncBaseTransport | None): Custom httpx transport (tests).
        '''
        self.scope = scope
        self.retries = retries
        self.max_response_bytes = max_response_bytes
        self.max_redirects = max_redirects
        self.allow_private_networks = allow_private_networks
        self._resolve = resolve
        self._sem = asyncio.Semaphore(concurrency)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=min(timeout, 10.0)),
            headers={"User-Agent": user_agent, **(extra_headers or {})},
            follow_redirects=False,
            http2=transport is None,
            transport=transport,
            limits=httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency),
        )

    async def __aenter__(self) -> SafeHttpClient:
        '''
        Enter the async context.
        Returns:
            SafeHttpClient: This client.
        '''
        return self

    async def __aexit__(self, *exc: Any) -> None:
        '''
        Close the client on context exit.
        Parameters:
            *exc (Any): Exception info (ignored).
        '''
        await self.aclose()

    async def aclose(self) -> None:
        '''
        Close the underlying connection pool.
        '''
        await self._client.aclose()

    async def check_destination(self, url: str) -> None:
        '''
        Validate scheme, scope and resolved addresses before a request is sent.
        Parameters:
            url (str): URL about to be requested.
        Raises:
            BlockedRequestError: If the URL is out of scope, unresolvable or resolves to a non-public address. OSError: If resolution fails.
        '''
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise BlockedRequestError("unsupported_scheme", url)
        host = parts.hostname
        if not self.scope.allows(host):
            raise BlockedRequestError("out_of_scope", f"{host} is outside the authorized scope")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        addresses = await self._resolve(host, port)
        if not addresses:
            raise BlockedRequestError("unresolvable", f"{host} did not resolve")
        if not self.allow_private_networks:
            blocked = [a for a in addresses if not is_public_ip(a)]
            if blocked:
                raise BlockedRequestError(
                    "blocked_address", f"{host} resolves to non-public address(es) {blocked}"
                )

    async def get(self, url: str) -> RawResponse:
        '''
        Single validated GET without redirect following, retrying transient failures.
        Parameters:
            url (str): URL to request.
        Returns:
            RawResponse: The response.
        Raises:
            BlockedRequestError: If the destination is refused. httpx.HTTPError: When retries are exhausted.
        '''
        await self.check_destination(url)
        attempt = 0
        while True:
            attempt += 1
            try:
                async with self._sem:
                    response = await self._get_once(url)
            except (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError) as exc:
                if attempt > self.retries or _is_certificate_error(exc):
                    raise
                await asyncio.sleep(0.5 * 2 ** (attempt - 1))
                continue
            if response.status_code in RETRY_STATUSES and attempt <= self.retries:
                await asyncio.sleep(_retry_delay(response, attempt))
                continue
            return response

    async def request(self, method: str, url: str, *, content: bytes | None = None,
                      headers: dict[str, str] | None = None) -> RawResponse:
        '''
        One validated request with an arbitrary method, no redirect following and no retries.

        Used by active checks, where every request must be counted exactly once and never silently
        repeated. The destination is scope- and address-checked before the request is sent.
        Parameters:
            method (str): HTTP method (GET, POST, OPTIONS, ...).
            url (str): URL to request.
            content (bytes | None): Optional request body.
            headers (dict[str, str] | None): Optional extra request headers.
        Returns:
            RawResponse: The response.
        Raises:
            BlockedRequestError: If the destination is refused.
            httpx.HTTPError: On transport failure.
        '''
        await self.check_destination(url)
        async with self._sem:
            return await self._once(method.upper(), url, content, headers)

    async def _get_once(self, url: str) -> RawResponse:
        '''
        Send one GET and read the body up to the size cap.
        Parameters:
            url (str): URL to request.
        Returns:
            RawResponse: The response.
        Raises:
            httpx.HTTPError: On transport failure.
        '''
        return await self._once("GET", url, None, None)

    async def _once(self, method: str, url: str, content: bytes | None,
                    headers: dict[str, str] | None) -> RawResponse:
        '''
        Send one request of any method and read the body up to the size cap.
        Parameters:
            method (str): HTTP method.
            url (str): URL to request.
            content (bytes | None): Optional request body.
            headers (dict[str, str] | None): Optional extra headers.
        Returns:
            RawResponse: The response.
        Raises:
            httpx.HTTPError: On transport failure.
        '''
        start = perf_counter()
        async with self._client.stream(method, url, content=content, headers=headers) as resp:
            body = bytearray()
            truncated = False
            async for chunk in resp.aiter_bytes():
                remaining = self.max_response_bytes - len(body)
                if len(chunk) > remaining:
                    body.extend(chunk[:remaining])
                    truncated = True
                    break
                body.extend(chunk)
            return RawResponse(
                url=str(resp.url),
                status_code=resp.status_code,
                http_version=resp.http_version,
                headers=list(resp.headers.multi_items()),
                body=bytes(body),
                truncated=truncated,
                elapsed_ms=round((perf_counter() - start) * 1000, 2),
            )

    async def fetch(self, url: str) -> FetchOutcome:
        '''
        GET with manual, scope-validated redirect following; never raises for request failures.
        Parameters:
            url (str): Starting URL.
        Returns:
            FetchOutcome: Every response, the terminal one, and why the chain stopped.
        '''
        outcome = FetchOutcome(requested_url=url)
        current = url
        visited: set[str] = set()
        for _ in range(self.max_redirects + 1):
            try:
                response = await self.get(current)
            except BlockedRequestError as exc:
                if not outcome.responses:
                    outcome.error, outcome.error_type = exc.detail, exc.reason
                else:
                    outcome.stopped_reason, outcome.stopped_url = exc.reason, current
                return outcome
            except httpx.HTTPError as exc:
                outcome.error = str(exc) or type(exc).__name__
                outcome.error_type = type(exc).__name__
                return outcome
            except OSError as exc:  # resolver failures (socket.gaierror)
                outcome.error = str(exc)
                outcome.error_type = "dns_resolution"
                return outcome

            outcome.responses.append(response)
            location = response.header("location")
            if response.status_code in REDIRECT_STATUSES and location:
                visited.add(current)
                current = urljoin(current, location)
                if current in visited:
                    outcome.stopped_reason, outcome.stopped_url = "redirect_loop", current
                    return outcome
                continue
            outcome.final = response
            return outcome

        outcome.stopped_reason, outcome.stopped_url = "too_many_redirects", current
        return outcome


def _is_certificate_error(exc: Exception) -> bool:
    '''
    Whether an exception was caused by certificate verification failure.
    Parameters:
        exc (Exception): Exception to inspect (cause chain included).
    Returns:
        bool: True for certificate errors.
    '''
    seen = exc
    while seen is not None:
        if isinstance(seen, ssl.SSLCertVerificationError):
            return True
        seen = seen.__cause__ or seen.__context__
    return "CERTIFICATE_VERIFY_FAILED" in str(exc)


def _retry_delay(response: RawResponse, attempt: int) -> float:
    '''
    Compute the retry delay, honoring a numeric Retry-After up to the cap.
    Parameters:
        response (RawResponse): Response that triggered the retry.
        attempt (int): 1-based attempt number.
    Returns:
        float: Seconds to wait.
    '''
    retry_after = response.header("retry-after")
    if retry_after and retry_after.strip().isdigit():
        return min(float(retry_after), _MAX_RETRY_AFTER)
    return min(0.5 * 2 ** (attempt - 1), _MAX_RETRY_AFTER)
