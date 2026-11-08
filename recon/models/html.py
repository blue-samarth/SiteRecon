'''
HTML analysis models.
'''

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ResourceRef(BaseModel):
    '''
    A resource referenced by the page (script, stylesheet, image, ...).
    '''
    url: str
    kind: str  # script, stylesheet, preload, modulepreload, preconnect, icon, image, iframe, form
    host: str | None = None
    same_site: bool
    attributes: dict[str, str] = Field(default_factory=dict)


class HtmlData(BaseModel):
    '''
    Metadata and references extracted from the landing page.
    '''
    source_url: str
    content_type: str | None = None
    body_truncated: bool = False
    title: str | None = None
    meta_description: str | None = None
    canonical: str | None = None
    robots: str | None = None
    generator: str | None = None
    lang: str | None = None
    open_graph: dict[str, str] = Field(default_factory=dict)
    twitter: dict[str, str] = Field(default_factory=dict)
    favicons: list[str] = Field(default_factory=list)
    verification_tokens: dict[str, str] = Field(default_factory=dict)
    resources: list[ResourceRef] = Field(default_factory=list)
    external_domains: list[str] = Field(default_factory=list)
    json_ld: list[Any] = Field(default_factory=list)
    inline_script_count: int = 0
    comment_count: int = 0
    # Commented-out markup is inactive; URLs found there are kept apart from live resources.
    commented_urls: list[str] = Field(default_factory=list)
    parse_warnings: list[str] = Field(default_factory=list)
