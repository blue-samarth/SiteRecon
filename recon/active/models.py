'''
Active-testing report models.

Kept separate from the passive ``ReconReport`` so a passive report is never silently extended with
active fields, but reusing ``Finding``, ``ModuleStatus`` and ``CollectionError`` so the existing
report writers extend naturally.
'''

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from recon.models import CollectionError, Finding, ModuleStatus, TargetInfo

SCHEMA_VERSION: str = "0.1"


class RequestLogEntry(BaseModel):
    '''
    One request an active check made, for the post-hoc audit log.
    '''
    check_id: str
    method: str
    url: str                 # query values redacted
    status: int | None = None
    note: str | None = None


class ActiveCheckResult(BaseModel):
    '''
    The outcome of one active check.
    '''
    check_id: str
    status: ModuleStatus
    target: str
    description: str = ""
    findings: list[Finding] = Field(default_factory=list)
    requests_made: int = 0
    skipped_reason: str | None = None
    started_at: datetime
    finished_at: datetime
    duration_ms: float = 0.0
    errors: list[CollectionError] = Field(default_factory=list)


class ActiveReport(BaseModel):
    '''
    The result of an active-testing run: who authorized it, which checks ran, and what traffic was made.
    '''
    schema_version: str = SCHEMA_VERSION
    scan_id: str
    tool: dict[str, str]
    authorization: dict[str, Any]     # redacted summary, never the raw file (see redact_authorization)
    target: TargetInfo
    window_ok: bool
    checks: list[ActiveCheckResult] = Field(default_factory=list)
    request_log: list[RequestLogEntry] = Field(default_factory=list)
    requests_made: int = 0
    request_budget: int = 0
    started_at: datetime
    finished_at: datetime
    duration_ms: float = 0.0
    notice: str = ("ACTIVE TESTING — these results were produced by sending requests to the target and may "
                   "have affected it. Run only with documented authorization.")

    def findings(self) -> list[Finding]:
        '''
        All findings across every check, most severe first.
        Returns:
            list[Finding]: Flattened findings.
        '''
        flat = [f for c in self.checks for f in c.findings]
        return sorted(flat, key=lambda f: (-f.severity.rank, f.category, f.id))
