'''
External-intelligence runner: executes the enabled providers against one target, in isolation.

Builds a single HTTP client scoped to exactly the enabled providers' third-party hosts (never the target's
scope, and never private networks), runs each provider, and converts a missing input or any exception into
a skipped/failed provider so one provider never aborts the others or the scan. Returns the aggregated
observations, findings and errors for merging into the report.
'''

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime

from recon import TOOL_NAME, __version__
from recon.intel.base import IntelContext
from recon.intel.providers import KEYLESS, REGISTRY
from recon.models import CollectionError, Finding, Observation, utcnow
from recon.utils import SafeHttpClient, Scope, get_logger


@dataclass(slots=True)
class ProviderNote:
    '''
    One line of per-provider outcome for the run log / CLI.
    '''
    provider: str
    status: str          # ran | skipped | failed
    detail: str = ""


@dataclass(slots=True)
class IntelAggregate:
    '''
    Combined output of an external-intelligence run.
    '''
    observations: list[Observation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[CollectionError] = field(default_factory=list)
    notes: list[ProviderNote] = field(default_factory=list)


class IntelRunner:
    '''
    Runs the enabled external-intelligence providers for one target.
    '''

    log: logging.Logger = get_logger("intel")

    def __init__(self, *, timeout: float = 15.0, providers: Iterable[str] | None = None,
                 client: SafeHttpClient | None = None) -> None:
        '''
        Create the runner.
        Parameters:
            timeout (float): Per-request timeout for provider calls.
            providers (Iterable[str] | None): Provider ids to run; None runs all keyless providers.
            client (SafeHttpClient | None): Client override (tests); scope is otherwise built from the
                enabled providers' hosts.
        '''
        self.timeout = timeout
        self.providers = self.resolve(providers)
        self._client_override = client

    @staticmethod
    def resolve(providers: Iterable[str] | None) -> list[str]:
        '''
        Resolve requested provider ids to known ones, defaulting to every keyless provider.
        Parameters:
            providers (Iterable[str] | None): Requested ids, or None.
        Returns:
            list[str]: Known provider ids to run, in registry order.
        '''
        requested = set(providers) if providers is not None else set(KEYLESS)
        return [name for name in REGISTRY if name in requested]

    def _build_client(self) -> SafeHttpClient:
        '''
        Build an HTTP client scoped to exactly the enabled providers' hosts.
        Returns:
            SafeHttpClient: The scoped client.
        '''
        hosts = sorted({h for name in self.providers for h in REGISTRY[name].hosts})
        return SafeHttpClient(
            Scope(hosts=hosts), timeout=self.timeout, retries=1,
            user_agent=f"{TOOL_NAME}/{__version__} (external intelligence)",
            allow_private_networks=False, max_response_bytes=2 * 1024 * 1024, max_redirects=5)

    async def run(self, host: str, ips: list[str], *, now: datetime | None = None,
                  on_request: Callable[[str, str, int | None], None] | None = None) -> IntelAggregate:
        '''
        Run every enabled provider and aggregate the results.
        Parameters:
            host (str): Target hostname the intelligence is about.
            ips (list[str]): Resolved public IPs for IP-keyed providers.
            now (datetime | None): Timestamp for observations/findings (defaults to now).
            on_request (Callable[[str, str, int | None], None] | None): Audit hook invoked per provider
                request as (method, url, status); used to record intel traffic in the active audit log.
        Returns:
            IntelAggregate: Observations, findings, errors and per-provider notes.
        '''
        aggregate = IntelAggregate()
        if not self.providers:
            return aggregate
        client = self._client_override or self._build_client()
        timestamp = now or utcnow()
        async with client:
            ctx = IntelContext(host=host, ips=list(ips), client=client, timestamp=timestamp,
                               on_request=on_request)
            for name in self.providers:
                provider = REGISTRY[name]()
                reason = provider.unavailable(ctx)
                if reason is not None:
                    aggregate.notes.append(ProviderNote(name, "skipped", reason))
                    continue
                try:
                    self.log.info("running intelligence provider %s", name)
                    result = await provider.collect(ctx)
                except Exception as exc:  # noqa: BLE001 - isolation boundary
                    self.log.warning("intelligence provider %s failed: %s", name, exc,
                                     exc_info=self.log.isEnabledFor(logging.DEBUG))
                    aggregate.errors.append(
                        CollectionError(module=name, error_type=type(exc).__name__, message=str(exc)))
                    aggregate.notes.append(ProviderNote(name, "failed", str(exc)))
                    continue
                aggregate.observations.extend(result.observations)
                aggregate.findings.extend(result.findings)
                aggregate.errors.extend(result.errors)
                aggregate.notes.append(ProviderNote(
                    name, "partial" if result.errors else "ran",
                    f"{len(result.findings)} finding(s), {len(result.observations)} observation(s)"
                    + (f", {len(result.errors)} error(s)" if result.errors else "")))
        return aggregate
