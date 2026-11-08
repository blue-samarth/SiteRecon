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
    Confidence in an observation or detection.
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
