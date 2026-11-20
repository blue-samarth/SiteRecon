'''
Historical-URL models (web archives and URL indexes).

Everything here describes the *past*: a URL an archive holds, a parameter a link once carried, the stack
that served a path when it was crawled. These values are never presented as the target's current state —
each record keeps its own first/last-seen window and the module's data carries a standing note saying so.
'''

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from recon.models.common import Confidence


class HistoricalSourceResult(BaseModel):
    '''
    Outcome of querying one historical-URL source.
    '''
    source: str
    status: str                  # live, failed, skipped
    urls: int = 0                # in-scope URLs this source contributed
    error: str | None = None
    skip_reason: str | None = None


class HistoricalUrl(BaseModel):
    '''
    One archived URL. Query values are redacted; only the structure is kept.
    '''
    url: str                     # absolute URL, query values redacted
    path: str                    # path component only
    host: str
    sources: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    status_codes: list[int] = Field(default_factory=list)   # HTTP statuses the archive recorded
    mime: str | None = None
    parameters: list[str] = Field(default_factory=list)     # query parameter names seen on this path


class HistoricalParameter(BaseModel):
    '''
    A query parameter observed in archived URLs, with how it should be read.
    '''
    name: str
    category: str                # credential, redirect, file, identifier, other
    occurrences: int = 0
    paths: list[str] = Field(default_factory=list)   # sample of paths carrying it
    sources: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    note: str | None = None


class HistoricalTechHint(BaseModel):
    '''
    A technology the archived URLs suggest the site *used to* run.

    Deliberately separate from the ``technology`` module's detections: a hint from an archived path is
    evidence about the past and is never merged into the current technology inventory.
    '''
    name: str
    category: str
    confidence: Confidence
    occurrences: int = 0
    evidence: list[str] = Field(default_factory=list)       # sample of matching paths
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    note: str | None = None
    still_detected: bool | None = None   # True when the current technology scan also detected it


class HistoricalData(BaseModel):
    '''
    Historical URLs for a target, aggregated across archives and URL indexes.
    '''
    host: str
    sources: list[HistoricalSourceResult] = Field(default_factory=list)
    urls_seen: int = 0                   # in-scope URLs after deduplication
    out_of_scope_dropped: int = 0
    limit: int = 0                       # per-source URL cap that was applied
    truncated: bool = False              # a source returned as many rows as the cap allowed
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    hosts: list[str] = Field(default_factory=list)          # in-scope hostnames seen in archived URLs
    paths: list[str] = Field(default_factory=list)          # distinct paths (capped sample)
    urls: list[HistoricalUrl] = Field(default_factory=list)  # capped sample, newest activity first
    endpoints: list[str] = Field(default_factory=list)      # API-looking paths worth probing manually
    parameters: list[HistoricalParameter] = Field(default_factory=list)
    tech_hints: list[HistoricalTechHint] = Field(default_factory=list)
    sensitive_paths: list[str] = Field(default_factory=list)
    extensions: dict[str, int] = Field(default_factory=dict)  # file extension → count
    note: str = (
        "Archived URLs are historical: a URL here was fetchable when the archive crawled it, which does "
        "not mean it exists or is reachable now. Query values are redacted. Technology hints describe the "
        "stack that served a path at the time, not the current one."
    )
