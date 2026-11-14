'''
Normalized observations and scan-comparison models.
'''

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from recon.models.common import CollectionMethod, Confidence, Freshness


class Observation(BaseModel):
    '''
    One normalized fact collected by a module; the unit used for findings references and comparisons.

    Carries its own provenance (how and where it was collected) and freshness so that passively collected,
    externally retrieved and actively probed facts stay distinguishable, and so a historical or stale value
    is never silently presented as the current state. New fields are optional with safe defaults, so
    observations stored by earlier versions still load.
    '''
    id: str                      # stable hash of (type, target, key)
    module: str
    target: str
    type: str                    # e.g. dns.record, tls.certificate, http.security_header
    key: str                     # distinguishes observations of the same type and target
    value: Any
    source: str                  # human-readable evidence source (e.g. "DNS TXT", "GET https://…")
    collection_method: str = CollectionMethod.UNKNOWN   # the mechanism behind `source` (see CollectionMethod)
    timestamp: datetime          # when SiteRecon collected it (collected_at)
    observed_at: datetime | None = None                 # when the fact was true at the source, if different
    confidence: Confidence = Confidence.HIGH            # strength of evidence, not reputation of source
    freshness: Freshness = Freshness.UNKNOWN            # how current the value is (see evaluate_freshness)
    external_provider: str | None = None                # third-party provider, if retrieved from one
    expires_at: datetime | None = None                  # when a provider's answer should be considered stale
    limitations: list[str] = Field(default_factory=list)  # what this observation cannot establish
    status: str                  # module status when collected (success, partial, ...)

    @property
    def collected_at(self) -> datetime:
        '''
        When SiteRecon collected this observation (an alias for ``timestamp``).
        Returns:
            datetime: The collection time.
        '''
        return self.timestamp

    def evaluate_freshness(self, now: datetime, stale_after: timedelta) -> Freshness:
        '''
        Classify how current this observation is, without mutating it.

        A value carried from a provider's archive/index (``external_provider`` set with an ``observed_at``
        meaningfully before collection) is HISTORICAL. Otherwise it is STALE once older than ``stale_after``
        (by ``expires_at`` when the provider gave one, else by ``collected_at``), FRESH when within the
        window, and UNKNOWN when there is no basis to decide.
        Parameters:
            now (datetime): The reference time to measure against (timezone-aware).
            stale_after (timedelta): Age at which a directly-collected value is considered stale.
        Returns:
            Freshness: The classification.
        '''
        if self.observed_at is not None and self.observed_at < self.timestamp - stale_after:
            return Freshness.HISTORICAL
        reference = self.expires_at or self.timestamp
        if self.expires_at is not None:
            return Freshness.STALE if now >= self.expires_at else Freshness.FRESH
        if reference.tzinfo is None or now.tzinfo is None:
            return Freshness.UNKNOWN
        return Freshness.STALE if now - reference > stale_after else Freshness.FRESH


class ChangeKind(StrEnum):
    '''
    Classification of a difference between two scans.
    '''
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"
    UNKNOWN = "unknown"          # comparison could not be completed (module missing or incomplete)


class Change(BaseModel):
    '''
    A difference (or non-difference) for one observation key.
    '''
    kind: ChangeKind
    type: str
    target: str
    key: str
    module: str
    previous: Any = None
    current: Any = None
    reason: str | None = None


class ScanRef(BaseModel):
    '''
    Identifies one stored scan.
    '''
    scan_id: str
    hostname: str
    started_at: datetime


class ComparisonResult(BaseModel):
    '''
    Differences between two scans of the same target.
    '''
    previous: ScanRef
    current: ScanRef
    counts: dict[str, int] = Field(default_factory=dict)
    changes: list[Change] = Field(default_factory=list)      # everything except unchanged
    unchanged_count: int = 0
    note: str = ("Data missing from either scan (failed, partial or skipped modules) is reported as "
                 "'unknown', never as removed.")
