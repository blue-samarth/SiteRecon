'''
Shared context for active checks: a scope-bound HTTP client, a central request budget and a central
rate limiter. Checks ask the context to make requests; the context — not the check — enforces the
engagement-wide budget and rate, so a buggy check can never exceed them.
'''

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

    def __init__(
        self,
        auth: AuthorizationFile,
        client: SafeHttpClient,
        *,
        clock: Callable[[], float] = monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
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
    def requests_made(self) -> int:
        '''
        Total requests made so far.
        Returns:
            int: Count of reserved requests.
        '''
        return self._total

    def check_count(self, check_id: str) -> int:
        '''
        Requests a given check has made.
        Parameters:
            check_id (str): The check identifier.
        Returns:
            int: Count for that check.
        '''
        return self._per_check.get(check_id, 0)

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
        entry = RequestLogEntry(check_id=check_id, method=method.upper(), url=redact_url(url), note=note)
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

    def log_probe(self, check_id: str, method: str, target: str, *, status: int | None = None,
                  note: str | None = None) -> None:
        '''
        Record a non-HTTP probe (e.g. a TLS handshake) in the audit log.

        Budget for these is reserved via reserve_handshake; this call only adds the audit entry, so the
        request log always has one row per reserved request.
        Parameters:
            check_id (str): The check that performed the probe.
            method (str): Short method label (e.g. 'TLS').
            target (str): What was probed (host:port); shown verbatim.
            status (int | None): Optional numeric status.
            note (str | None): Audit note (e.g. the version and outcome).
        '''
        self.request_log.append(RequestLogEntry(check_id=check_id, method=method, url=target, status=status, note=note))

    async def reserve_handshake(self, check_id: str) -> None:
        '''
        Reserve budget and apply the rate limit before a single non-HTTP probe (e.g. a TLS handshake).
        Parameters:
            check_id (str): The check performing the probe.
        Raises:
            BudgetExceeded: If the budget is exhausted.
        '''
        await self._reserve(check_id)
