'''
Website crawl models.
'''

from __future__ import annotations

from pydantic import BaseModel, Field


class FormRecord(BaseModel):
    '''
    A form found on a page. Forms are inspected only, never submitted; field values are not read.
    '''
    page_url: str
    action: str
    method: str
    input_names: list[str] = Field(default_factory=list)
    has_password_field: bool = False


class CrawledPage(BaseModel):
    '''
    One in-scope page fetched by the crawler.
    '''
    url: str
    source_url: str | None = None      # page that linked here (None for seeds)
    depth: int
    status_code: int | None = None
    final_url: str | None = None
    content_type: str | None = None
    title: str | None = None
    response_time_ms: float | None = None
    links_found: int = 0
    query_params: list[str] = Field(default_factory=list)
    security_headers: dict[str, str | None] = Field(default_factory=dict)
    cache_control: str | None = None
    cors: dict[str, str] = Field(default_factory=dict)
    resource_urls: list[str] = Field(default_factory=list)
    external_domains: list[str] = Field(default_factory=list)
    error: str | None = None
    # In-memory only (for cookie and technology analysis); never serialized.
    set_cookies: list[str] = Field(default_factory=list, exclude=True, repr=False)
    body: bytes = Field(default=b"", exclude=True, repr=False)


class DiscoveredUrl(BaseModel):
    '''
    An in-scope URL seen but not fetched (limits, robots rules or non-HTML type).
    '''
    url: str
    source_url: str | None = None
    reason: str


class CrawlData(BaseModel):
    '''
    Crawl results: fetched pages, discovered-but-unfetched URLs and forms.
    '''
    seeds: list[str] = Field(default_factory=list)
    max_depth: int
    max_pages: int
    robots_respected: bool
    crawl_delay: float
    pages: list[CrawledPage] = Field(default_factory=list)
    discovered: list[DiscoveredUrl] = Field(default_factory=list)
    forms: list[FormRecord] = Field(default_factory=list)
    page_limit_reached: bool = False
