from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from time import monotonic

import httpx

from recon.active.authorization import AuthorizationFile
from recon.active.models import RequestLogEntry
from recon.utils import BlockedRequestError, RawResponse, SafeHttpClient, redact_url


class BudgetExceeded(Exception):
    '''
    Raised when a request would exceed the per-check or engagement-wide request budget.
    '''


class ActiveContext:
    '''
    Carries the authorization, a scope-bound client, the shared budget, and the rate limiter.
    '''

    def __init__(self, auth: AuthorizationFile, client: SafeHttpClient, *, clock: Callable[[], float] = monotonic, sleep: Callable[[float], Awaitable[None]] = asyncio.sleep, ) -> None:
        '''
        Create a context.
        Parameters:
            auth (AuthorizationFile): The authorization governing this run.
            client (SafeHttpClient): Client scoped to the authorization's hosts.
            clock (Callable[[], float]): Monotonic clock (injectable for tests).
            sleep (Callable[[float], Awaitable[None]]): Async sleep (injectable for tests).
        '''
        self.auth = auth
        self.client = client
        self.request_log: list[RequestLogEntry] = []
        self._clock = clock
        self._sleep = sleep
        self._total = 0
        self._per_check: dict[str, int] = {}
        self._lock = asyncio.Lock()
        self._min_interval = 1.0 / auth.rate_limit_rps if auth.rate_limit_rps > 0 else 0.0
        self._next_allowed = clock()

    @property
    def requests_made(self) -> int: return self._total

    def check_count(self, check_id: str) -> int: return self._per_check.get(check_id, 0)
    def log_probe(self, check_id: str, method: str, target: str, *, status: int | None = None, note: str | None = None) -> None: self.request_log.append(RequestLogEntry(check_id=check_id, method=method, url=target, status=status, note=note))
    async def reserve_handshake(self, check_id: str) -> None: await self._reserve(check_id)


    async def _reserve(self, check_id: str) -> None:
        '''
        Reserve one request against the budgets and the rate limiter, or refuse.
        Parameters:
            check_id (str): The check making the request.
        Raises:
            BudgetExceeded: If the run or per-check budget is exhausted.
        '''
        async with self._lock:
            if self._total >= self.auth.max_requests:
                raise BudgetExceeded(f"engagement request budget ({self.auth.max_requests}) exhausted")
            if self._per_check.get(check_id, 0) >= self.auth.max_requests_per_check:
                raise BudgetExceeded(f"per-check budget ({self.auth.max_requests_per_check}) exhausted for {check_id}")
            wait = self._next_allowed - self._clock()
            if wait > 0:
                await self._sleep(wait)
            self._next_allowed = self._clock() + self._min_interval
            self._total += 1
            self._per_check[check_id] = self._per_check.get(check_id, 0) + 1

    async def request(self, check_id: str, method: str, url: str, *, content: bytes | None = None,
                      headers: dict[str, str] | None = None, note: str | None = None) -> RawResponse | None:
        '''
        Make one budgeted, rate-limited, scope-checked request and log it.
        Parameters:
            check_id (str): The check making the request.
            method (str): HTTP method.
            url (str): Target URL (must be in the active scope).
            content (bytes | None): Optional request body.
            headers (dict[str, str] | None): Optional extra headers.
            note (str | None): Audit note.
        Returns:
            RawResponse | None: The response, or None if the request failed at the transport/scope layer
                (an entry is still logged with the failure note).
        Raises:
            BudgetExceeded: If the budget is exhausted (the request is not sent).
        '''
        await self._reserve(check_id)
        entry: RequestLogEntry = RequestLogEntry(check_id=check_id, method=method.upper(), url=redact_url(url), note=note)
        try:
            resp = await self.client.request(method, url, content=content, headers=headers)
        except BlockedRequestError as exc:
            entry.note = f"blocked: {exc.reason}"
            self.request_log.append(entry)
            return None
        except (httpx.HTTPError, OSError) as exc:
            entry.note = f"error: {type(exc).__name__}"
            self.request_log.append(entry)
            return None
        entry.status = resp.status_code
        self.request_log.append(entry)
        return resp

    def record_external(self, check_id: str, method: str, url: str, *, status: int | None = None, note: str | None = None) -> None:
        '''
        Record a request a check made through its *own* client (e.g. an external-intelligence provider call
        to a third-party host), counting it toward the engagement total so the audit log and the reported
        request count stay in lockstep.
        Parameters:
            check_id (str): The check that made the request.
            method (str): HTTP method.
            url (str): The requested URL (query values are redacted before logging).
            status (int | None): Response status, if any.
            note (str | None): Audit note.
        '''
        self._total += 1
        self._per_check[check_id] = self._per_check.get(check_id, 0) + 1
        self.request_log.append(RequestLogEntry(check_id=check_id, method=method.upper(), url=redact_url(url), status=status, note=note))
