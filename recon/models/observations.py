'''
Normalized observations and scan-comparison models.
'''

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from recon.models.common import Confidence


class Observation(BaseModel):
    '''
    One normalized fact collected by a module; the unit used for findings references and comparisons.
    '''
    id: str                      # stable hash of (type, target, key)
    module: str
    target: str
    type: str                    # e.g. dns.record, tls.certificate, http.security_header
    key: str                     # distinguishes observations of the same type and target
    value: Any
    source: str
    timestamp: datetime
    confidence: Confidence = Confidence.HIGH
    status: str                  # module status when collected (success, partial, ...)


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
