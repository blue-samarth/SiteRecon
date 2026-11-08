'''
Standard public resource models (robots.txt, sitemaps, security.txt, manifest, favicon, humans.txt).
'''

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class FetchedResource(BaseModel):
    '''
    Outcome of fetching one well-known public resource.
    '''
    url: str
    present: bool = False
    status_code: int | None = None
    content_type: str | None = None
    size: int | None = None
    sha256: str | None = None
    soft_404: bool = False          # 200 response that is really an HTML error/fallback page
    error: str | None = None


class RobotsInfo(FetchedResource):
    '''
    Parsed robots.txt.
    '''
    sitemaps: list[str] = Field(default_factory=list)
    user_agents: list[str] = Field(default_factory=list)
    disallow: list[str] = Field(default_factory=list)   # rules for '*'
    allow: list[str] = Field(default_factory=list)
    crawl_delay: float | None = None


class SitemapInfo(FetchedResource):
    '''
    One parsed sitemap (urlset or sitemap index).
    '''
    source: str = "default"                # default, robots.txt, or parent sitemap URL
    kind: str | None = None                # urlset or sitemapindex
    url_count: int = 0
    urls: list[str] = Field(default_factory=list)       # in-scope URLs (capped)
    nested: list[str] = Field(default_factory=list)


class SecurityTxtInfo(FetchedResource):
    '''
    Parsed security.txt (RFC 9116).
    '''
    fields: dict[str, list[str]] = Field(default_factory=dict)
    contacts: list[str] = Field(default_factory=list)
    expires: datetime | None = None
    expired: bool | None = None
    signed: bool = False


class ManifestInfo(FetchedResource):
    '''
    Parsed web app manifest.
    '''
    name: str | None = None
    short_name: str | None = None
    start_url: str | None = None
    scope: str | None = None
    display: str | None = None
    theme_color: str | None = None
    icon_count: int = 0


class TextResourceInfo(FetchedResource):
    '''
    A small free-text resource such as humans.txt.
    '''
    excerpt: list[str] = Field(default_factory=list)


class ResourcesData(BaseModel):
    '''
    Standard public resources of the target origin.
    '''
    origin: str
    robots: RobotsInfo | None = None
    sitemaps: list[SitemapInfo] = Field(default_factory=list)
    security_txt: SecurityTxtInfo | None = None
    manifest: ManifestInfo | None = None
    favicon: FetchedResource | None = None
    humans: TextResourceInfo | None = None

    def sitemap_urls(self) -> list[str]:
        '''
        All in-scope page URLs listed across sitemaps.
        Returns:
            list[str]: Unique URLs in discovery order.
        '''
        return list(dict.fromkeys(u for s in self.sitemaps for u in s.urls))
