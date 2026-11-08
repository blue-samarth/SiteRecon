'''
Active-testing orchestrator. Mirrors ``ScanOrchestrator``: loads the authorization, builds a
scope-bound rate-limited client and a central budget, runs only the enabled-and-ready checks in
isolation, and assembles an ``ActiveReport``. The budget/rate are enforced by the context, so the
orchestrator is the backstop even if a check misbehaves.
'''

from __future__ import annotations

import logging
from datetime import UTC, datetime
from time import perf_counter
from collections.abc import Callable
from typing import Any

from recon import TOOL_NAME, __version__
from recon.active.authorization import AuthorizationFile, redact_authorization
from recon.active.checks import REGISTRY, build_check
from recon.active.context import ActiveContext
from recon.active.models import ActiveCheckResult, ActiveReport
from recon.active.checks import TlsProtocolEnumCheck
from recon.models import CollectionError, ModuleStatus, TargetInfo
from recon.storage import ScanStore
from recon.utils import SafeHttpClient, Scope, get_logger


class ActiveOrchestrator:
    '''
    Runs the authorized active checks for one engagement and assembles the report.
    '''

    log: logging.Logger = get_logger("active")

    def __init__(self, auth: AuthorizationFile, *, timeout: float = 10.0, retries: int = 2,
                 client: SafeHttpClient | None = None, now: datetime | None = None) -> None:
        '''
        Create the orchestrator and its scope-bound client.
        Parameters:
            auth (AuthorizationFile): The validated authorization.
            timeout (float): Per-request timeout.
            retries (int): Retries for the client's own transient handling (active requests themselves
                are single-shot; this only affects connection setup).
            client (SafeHttpClient | None): Client override (tests).
            now (datetime | None): Reference time for the window check (tests).
        '''
        self.auth = auth
        self.timeout = timeout
        self.now = now
        # The active client's scope is the authorization's explicit hosts — never the passive target scope.
        self.scope = Scope(hosts=sorted(auth.scope.normalized_hosts()))
        self.client = client or SafeHttpClient(
            self.scope, timeout=timeout, retries=0, user_agent=self._user_agent(),
            allow_private_networks=False, max_response_bytes=256 * 1024, max_redirects=0)

    @staticmethod
    def _user_agent() -> str:
        '''
        A User-Agent that identifies active testing.
        Returns:
            str: The User-Agent string.
        '''
        return f"{TOOL_NAME}/{__version__} (authorized active testing)"

    def plan(self) -> list[tuple[str, str | None]]:
        '''
        Resolve which enabled checks would run and which would be skipped (no network I/O).
        Returns:
            list[tuple[str, str | None]]: (check_id, skip_reason) for each enabled check; reason None means it would run.
        '''
        resolved: list[tuple[str, str | None]] = []
        for check_id in self.auth.checks_enabled:
            if check_id not in REGISTRY:
                resolved.append((check_id, f"unknown check (not in registry: {', '.join(sorted(REGISTRY))})"))
                continue
            resolved.append((check_id, build_check(check_id).prerequisites(self.auth)))
        return resolved

    async def run(self, progress: Callable[[str, str, str], None] | None = None) -> ActiveReport:
        '''
        Run every enabled, ready check in isolation and assemble the report.
        Parameters:
            progress (Callable[[str, str, str], None] | None): Optional callback invoked as
                (event, check_id, detail): ("start", check_id, "") just before a check runs, and
                ("done", check_id, detail) when it finishes, for a live terminal progress bar.
        Returns:
            ActiveReport: Results, request log and budget accounting.
        '''
        def say(event: str, check_id: str, detail: str = "") -> None:
            if progress is not None:
                progress(event, check_id, detail)

        started = datetime.now(UTC)
        t0 = perf_counter()
        now = self.now or datetime.now(UTC)
        window_ok = self.auth.window.contains(now)

        results: list[ActiveCheckResult] = []
        async with self.client:
            ctx = ActiveContext(self.auth, self.client)
            for check_id in self.auth.checks_enabled:
                say("start", check_id)
                result = await self._run_one(check_id, ctx)
                detail = (f"skipped — {result.skipped_reason}" if result.status.value == "skipped"
                          else f"{result.status.value} · {result.requests_made} request(s) · "
                               f"{len(result.findings)} finding(s)")
                say("done", check_id, detail)
                results.append(result)
            request_log = list(ctx.request_log)
            requests_made = ctx.requests_made

        report = ActiveReport(
            scan_id=ScanStore.new_scan_id(started),
            tool={"name": TOOL_NAME, "version": __version__, "user_agent": self._user_agent()},
            authorization=redact_authorization(self.auth),
            target=TargetInfo(input=self.auth.target, hostname=self.auth.target,
                              scope=sorted(self.auth.scope.normalized_hosts())),
            window_ok=window_ok,
            checks=results, request_log=request_log, requests_made=requests_made,
            request_budget=self.auth.max_requests,
            started_at=started, finished_at=datetime.now(UTC),
            duration_ms=round((perf_counter() - t0) * 1000, 2))
        return report

    async def _run_one(self, check_id: str, ctx: ActiveContext) -> ActiveCheckResult:
        '''
        Run a single check, converting a missing registry entry, failed prerequisites or an exception
        into a SKIPPED/FAILED result so one check never aborts the run.
        Parameters:
            check_id (str): The check to run.
            ctx (ActiveContext): Shared context.
        Returns:
            ActiveCheckResult: The result.
        '''
        started = datetime.now(UTC)
        if check_id not in REGISTRY:
            return self._skip(check_id, started, f"unknown check; available: {', '.join(sorted(REGISTRY))}")
        check = build_check(check_id)
        if isinstance(check, TlsProtocolEnumCheck):
            check.timeout = self.timeout
        reason = check.prerequisites(self.auth)
        if reason is not None:
            return self._skip(check_id, started, reason)
        self.log.info("running active check %s", check_id)
        try:
            result = await check.run(ctx)
        except Exception as exc:  # noqa: BLE001 - isolation boundary
            self.log.warning("active check %s failed: %s", check_id, exc,
                             exc_info=self.log.isEnabledFor(logging.DEBUG))
            now = datetime.now(UTC)
            return ActiveCheckResult(
                check_id=check_id, status=ModuleStatus.FAILED, target=self.auth.target,
                description=check.description, requests_made=ctx.check_count(check_id),
                started_at=started, finished_at=now, duration_ms=round((now - started).total_seconds() * 1000, 2),
                errors=[CollectionError(module=check_id, error_type=type(exc).__name__, message=str(exc))])
        self.log.info("active check %s: %s (%d request(s), %d finding(s))", check_id, result.status.value,
                      result.requests_made, len(result.findings))
        return result

    def _skip(self, check_id: str, started: datetime, reason: str) -> ActiveCheckResult:
        '''
        Build a SKIPPED result with a clear reason.
        Parameters:
            check_id (str): The check.
            started (datetime): When evaluation began.
            reason (str): Why it was skipped.
        Returns:
            ActiveCheckResult: The skipped result.
        '''
        description = REGISTRY[check_id].description if check_id in REGISTRY else ""
        now = datetime.now(UTC)
        return ActiveCheckResult(check_id=check_id, status=ModuleStatus.SKIPPED, target=self.auth.target,
                                 description=description, skipped_reason=reason, started_at=started,
                                 finished_at=now, duration_ms=0.0)

    def options_echo(self) -> dict[str, Any]:
        '''
        A compact view of the run's governing limits, for a --dry-run printout.
        Returns:
            dict[str, Any]: Limits and scope.
        '''
        return {"target": self.auth.target, "scope_hosts": sorted(self.auth.scope.normalized_hosts()),
                "rate_limit_rps": self.auth.rate_limit_rps, "max_requests": self.auth.max_requests,
                "max_requests_per_check": self.auth.max_requests_per_check,
                "window": {"start": self.auth.window.start.isoformat(), "end": self.auth.window.end.isoformat()}}
