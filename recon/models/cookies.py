'''
Cookie attribute models. Cookie values are never stored.
'''

from __future__ import annotations

from pydantic import BaseModel, Field


class CookieRecord(BaseModel):
    '''
    Security-relevant attributes of one Set-Cookie header (value omitted; only its length is kept).
    '''
    name: str
    source_url: str
    over_https: bool
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None
    domain: str | None = None
    path: str | None = None
    expires: str | None = None
    max_age: int | None = None
    persistent: bool = False
    prefix: str | None = None           # __Host- or __Secure-
    prefix_valid: bool | None = None
    value_length: int = 0
    attributes: list[str] = Field(default_factory=list)   # attribute names as sent


class CookieData(BaseModel):
    '''
    Cookies set by fetched pages, deduplicated by (name, domain, path).
    '''
    cookies: list[CookieRecord] = Field(default_factory=list)
    responses_inspected: int = 0
    note: str = "Cookie values are never recorded; only attributes and value length."
