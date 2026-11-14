'''
Models shared by every collection module.
'''

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Generic, TypeVar

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    '''
    Return the current time as a timezone-aware UTC datetime.
    Returns:
        datetime: Current UTC time.
    '''
    return datetime.now(UTC)


class ModuleStatus(StrEnum):
    '''
    Outcome of a collection module run.
    '''
    SUCCESS = "success"    # every check completed
    PARTIAL = "partial"    # some checks failed or were incomplete
    FAILED = "failed"      # module raised; no usable data
    SKIPPED = "skipped"    # not run (disabled, not applicable, or not implemented)


class Severity(StrEnum):
    '''
    Finding severity, ordered from informational to critical.
    '''
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        '''
        Ordinal position used for sorting (informational=0).
        Returns:
            int: Rank of this severity.
        '''
        return list(Severity).index(self)


class Confidence(StrEnum):
    '''
    Confidence in an observation or detection: the strength of the evidence, not the reputation of the
    source. The three levels map to the common probable/possible vocabulary via :meth:`label`.
    '''
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        '''
        Ordinal position used for comparison (low=0).
        Returns:
            int: Rank of this confidence.
        '''
        return list(Confidence).index(self)

    @property
    def label(self) -> str:
        '''
        The evidence-strength word some reports prefer: confirmed / probable / possible.
        Returns:
            str: 'confirmed' (high), 'probable' (medium) or 'possible' (low).
        '''
        return {Confidence.HIGH: "confirmed", Confidence.MEDIUM: "probable", Confidence.LOW: "possible"}[self]


class Freshness(StrEnum):
    '''
    How current an observation is relative to when it was collected and any provider freshness window.

    Freshness is about the information, not the finding: a historical snapshot (e.g. a Wayback result or a
    cached provider answer) is HISTORICAL even when it is correctly and recently retrieved. It is kept
    deliberately distinct from confidence (evidence strength) and from a finding's lifecycle state.
    '''
    FRESH = "fresh"            # collected directly and recently; reflects the current state
    STALE = "stale"           # older than the configured freshness threshold
    HISTORICAL = "historical"  # represents a past state (archives, cached/indexed provider data)
    UNKNOWN = "unknown"       # freshness cannot be established (no timestamp or threshold)


class CollectionMethod(StrEnum):
    '''
    How an observation was obtained. Records the mechanism behind the ``source`` string so passive,
    external-provider and active-collected facts stay distinguishable in reports and correlation.

    The field that stores this is typed as ``str`` so a new collector can introduce a value without a
    model change; these are the conventional, known methods.
    '''
    DNS_QUERY = "dns_query"
    NETWORK_LOOKUP = "network_lookup"       # ASN / RDAP / PTR
    HTTP_REQUEST = "http_request"           # ordinary passive GET/HEAD
    TLS_HANDSHAKE = "tls_handshake"
    WHOIS_LOOKUP = "whois_lookup"
    CT_LOG = "ct_log"                       # Certificate Transparency
    STATIC_ANALYSIS = "static_analysis"     # parsing fetched HTML/JS, no extra traffic
    DERIVED = "derived"                     # inferred from other observations, not collected directly
    LOCAL_DATABASE = "local_database"       # looked up in a bundled/offline dataset (e.g. an IP geo DB)
    EXTERNAL_API = "external_api"           # third-party intelligence provider (Shodan, Safe Browsing, …)
    BROWSER_RENDER = "browser_render"       # real-browser (Playwright) execution
    PORT_CONNECT = "port_connect"           # active TCP connect probe
    TRACEROUTE = "traceroute"               # active network-path probe
    UNKNOWN = "unknown"


class FindingState(StrEnum):
    '''
    Lifecycle state of a finding: where it sits between first evidence and resolution/dismissal.

    Orthogonal to severity (how bad) and confidence (how strong the evidence). A fresh finding starts at
    SUSPECTED or CONFIRMED based on evidence strength; CORROBORATED, RESOLVED and FALSE_POSITIVE require
    cross-source correlation or history (produced by the analysis engine, not a single collector). A
    missing observation is never, by itself, evidence of RESOLVED.
    '''
    SUSPECTED = "suspected"          # initial evidence suggests a potential issue
    CORROBORATED = "corroborated"    # multiple independent observations support it
    CONFIRMED = "confirmed"          # evidence is sufficient to establish the issue
    FALSE_POSITIVE = "false_positive"  # reviewed and dismissed
    RESOLVED = "resolved"            # previously detected, no longer observed (requires prior evidence)
    UNKNOWN = "unknown"              # current evidence is insufficient to determine status

    @classmethod
    def from_confidence(cls, confidence: Confidence) -> FindingState:
        '''
        The starting lifecycle state for a newly generated finding, from its evidence strength.

        Weak (low-confidence) evidence starts SUSPECTED; medium/high evidence starts CONFIRMED. States
        that depend on multiple sources or history (CORROBORATED/RESOLVED/FALSE_POSITIVE) are only ever
        assigned by the analysis engine, never derived here.
        Parameters:
            confidence (Confidence): The finding's evidence-strength confidence.
        Returns:
            FindingState: SUSPECTED for low confidence, otherwise CONFIRMED.
        '''
        return cls.SUSPECTED if confidence is Confidence.LOW else cls.CONFIRMED


class CollectionError(BaseModel):
    '''
    An error or incomplete check recorded by a collection module.
    '''
    module: str
    target: str | None = None
    error_type: str
    message: str
    timestamp: datetime = Field(default_factory=utcnow)


T = TypeVar("T")


class ModuleResult(BaseModel, Generic[T]):
    '''
    Envelope for one module's output: status, timing, data and errors.
    '''
    module: str
    status: ModuleStatus
    started_at: datetime
    finished_at: datetime
    duration_ms: float
    data: T | None = None
    errors: list[CollectionError] = Field(default_factory=list)
    note: str | None = None

    @classmethod
    def skipped(cls, module: str, note: str) -> ModuleResult[T]:
        '''
        Build a SKIPPED result for a module that was not run.
        Parameters:
            module (str): Module name.
            note (str): Why the module was skipped.
        Returns:
            ModuleResult[T]: A result with no data.
        '''
        now = utcnow()
        return cls(
            module=module, status=ModuleStatus.SKIPPED,
            started_at=now, finished_at=now, duration_ms=0.0, note=note,
        )
