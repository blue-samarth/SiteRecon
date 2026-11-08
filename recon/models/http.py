'''
HTTP / HTTPS observation models.
'''

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class HttpHop(BaseModel):
    '''
    One response in a redirect chain.
    '''
    url: str
    status_code: int
    location: str | None = None  # absolute redirect target, if this hop redirected
    elapsed_ms: float
    http_version: str | None = None


class SecurityHeader(BaseModel):
    '''
    Presence, raw value and parsed form of a security header.
    '''
    name: str
    present: bool
    value: str | None = None
    parsed: dict[str, Any] | list[str] | None = None


class HttpProbe(BaseModel):
    '''
    Result of fetching one URL, including its redirect chain and final response.
    '''
    requested_url: str
    success: bool
    hops: list[HttpHop] = Field(default_factory=list)
    redirect_count: int = 0
    final_url: str | None = None
    final_fetched: bool = False
    redirect_stopped_reason: str | None = None
    status_code: int | None = None
    http_version: str | None = None
    headers: dict[str, list[str]] = Field(default_factory=dict)
    server: str | None = None
    content_type: str | None = None
    content_length: int | None = None
    body_bytes: int | None = None
    body_truncated: bool = False
    response_time_ms: float | None = None
    total_time_ms: float | None = None
    redirects_to_https: bool | None = None
    security_headers: dict[str, SecurityHeader] = Field(default_factory=dict)
    cache_control: str | None = None
    cors: dict[str, str] = Field(default_factory=dict)
    error: str | None = None
    error_type: str | None = None
    # Kept in memory for later analysis modules; never serialized into reports.
    body: bytes = Field(default=b"", exclude=True, repr=False)
    set_cookies: list[str] = Field(default_factory=list, exclude=True, repr=False)  # raw; values never reported


class HttpData(BaseModel):
    '''
    All HTTP/HTTPS probes for the target.
    '''
    probes: list[HttpProbe] = Field(default_factory=list)
