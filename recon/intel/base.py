'''
Base abstractions for external-intelligence providers.

External intelligence is a distinct execution category: it queries third-party providers *about* the
target rather than probing the target itself. Every provider is pluggable and fail-soft — a missing key,
a missing input or a provider outage yields a skipped/failed provider, never a failed scan — and declares
whether it needs an API key, so the keyless providers run with no registration at all.

Everything a provider produces is an ordinary ``Observation``/``Finding`` so it flows through the existing
normalization, reporting and comparison pipeline. The helpers here stamp that output with external
provenance (``collection_method = external_api``, the provider name, and freshness/expiry) so externally
retrieved facts stay clearly distinguishable from directly-collected ones.
'''

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar

from recon.analysis import RECOMMENDATIONS, LIMITATIONS, ObservationBuilder
from recon.analysis.findings import lookup_text
from recon.models import (
    CollectionError,
    CollectionMethod,
    Confidence,
    Finding,
    Freshness,
    Observation,
    Severity,
)
from recon.utils import FetchOutcome, SafeHttpClient


@dataclass(slots=True)
class IntelContext:
    '''
    Inputs and shared client for one external-intelligence run.
    '''
    host: str                              # the target hostname the intelligence is about
    ips: list[str]                         # resolved public IPs (for IP-keyed providers)
    client: SafeHttpClient                 # scoped to the enabled providers' hosts
    timestamp: datetime                    # stamped on every observation/finding
    max_items: int = 50                    # cap on items a provider will enumerate
    # Optional audit hook, invoked (method, url, status) for every provider request; set when running
    # under the active command so third-party intelligence traffic appears in the engagement audit log.
    on_request: Callable[[str, str, int | None], None] | None = None

    async def fetch(self, url: str) -> FetchOutcome:
        '''
        GET a provider URL through the shared client, notifying the audit hook with the outcome.
        Parameters:
            url (str): The URL to fetch.
        Returns:
            FetchOutcome: The fetch result (never raises for request failures).
        '''
        outcome = await self.client.fetch(url)
        if self.on_request is not None:
            self.on_request("GET", url, outcome.final.status_code if outcome.final else None)
        return outcome


@dataclass(slots=True)
class IntelResult:
    '''
    What one provider produced: normalized observations, interpreted findings and any errors.
    '''
    observations: list[Observation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[CollectionError] = field(default_factory=list)


class IntelligenceProvider(ABC):
    '''
    Base class for an external-intelligence provider.
    '''

    name: ClassVar[str]                    # stable id, e.g. "wayback"
    label: ClassVar[str]                   # human provider name, e.g. "Wayback Machine"
    hosts: ClassVar[tuple[str, ...]]       # third-party hosts it contacts (used to scope the client)
    requires_key: ClassVar[bool] = False   # True if an API key/credential is needed

    def unavailable(self, ctx: IntelContext) -> str | None:
        '''
        Reason this provider cannot run given the inputs (e.g. no resolved IPs), or None if it can.
        Parameters:
            ctx (IntelContext): The run inputs.
        Returns:
            str | None: A human-readable skip reason, or None.
        '''
        return None

    @abstractmethod
    async def collect(self, ctx: IntelContext) -> IntelResult:
        '''
        Query the provider and return normalized observations and findings.
        Parameters:
            ctx (IntelContext): The run inputs and shared client.
        Returns:
            IntelResult: Observations, findings and errors.
        Raises:
            Exception: Any unexpected failure; the runner converts it into a failed provider.
        '''

    def error(self, target: str | None, error_type: str, message: str) -> CollectionError:
        '''
        Build a CollectionError attributed to this provider.
        Parameters:
            target (str | None): What the failed lookup was about.
            error_type (str): Machine-readable error type.
            message (str): Human-readable detail.
        Returns:
            CollectionError: The error record.
        '''
        return CollectionError(module=self.name, target=target, error_type=error_type, message=message)

    def observation(self, ctx: IntelContext, type_: str, target: str, key: str, value: Any, *,
                    confidence: Confidence = Confidence.MEDIUM, freshness: Freshness = Freshness.UNKNOWN,
                    observed_at: datetime | None = None, expires_at: datetime | None = None,
                    limitations: list[str] | None = None) -> Observation:
        '''
        Build an externally-sourced observation stamped with this provider's provenance.
        Parameters:
            ctx (IntelContext): The run context (supplies the timestamp).
            type_ (str): Observation type (e.g. 'intel.shodan.exposure').
            target (str): What the observation is about.
            key (str): Distinguishing key.
            value (Any): JSON-serializable value.
            confidence (Confidence): Confidence in the observation.
            freshness (Freshness): How current the value is (external data is often not FRESH).
            observed_at (datetime | None): When the fact was true at the source, if known.
            expires_at (datetime | None): When the provider's answer should be considered stale.
            limitations (list[str] | None): What this observation cannot establish.
        Returns:
            Observation: The provenance-stamped observation.
        '''
        return Observation(
            id=ObservationBuilder.make_id(type_, target, key), module=self.name, target=target, type=type_,
            key=key, value=value, source=self.label, collection_method=CollectionMethod.EXTERNAL_API,
            timestamp=ctx.timestamp, observed_at=observed_at, confidence=confidence, freshness=freshness,
            external_provider=self.label, expires_at=expires_at, limitations=limitations or [],
            status="success")

    def finding(self, ctx: IntelContext, code: str, subject: str, *, category: str, title: str,
                description: str, severity: Severity, confidence: Confidence, evidence: list[str],
                evidence_refs: list[str] | None = None) -> Finding:
        '''
        Build a finding, pulling recommendation and limitations from the central tables by code.
        Parameters:
            ctx (IntelContext): The run context (supplies the timestamp).
            code (str): Finding code, e.g. 'intel.exposed_ports'.
            subject (str): What the finding is about.
            category (str): Finding category.
            title (str): Short title.
            description (str): Explanation.
            severity (Severity): Severity.
            confidence (Confidence): Confidence in the finding.
            evidence (list[str]): Supporting evidence strings.
            evidence_refs (list[str] | None): Observation ids backing this finding.
        Returns:
            Finding: The finding.
        '''
        return Finding(
            id=f"{code}:{subject}", category=category, title=title, description=description, severity=severity,
            confidence=confidence, evidence=evidence, source=self.label, subject=subject, timestamp=ctx.timestamp,
            recommendation=lookup_text(RECOMMENDATIONS, code), limitations=lookup_text(LIMITATIONS, code),
            evidence_refs=list(evidence_refs or []))
