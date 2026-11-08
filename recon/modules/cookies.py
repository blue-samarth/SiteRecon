'''
Cookie attribute analysis of Set-Cookie headers from fetched pages. Cookie values are never kept.
'''

from __future__ import annotations

from typing import ClassVar
from urllib.parse import urlsplit

from recon.models import CollectionError, CookieData, CookieRecord, CrawlData, HttpData
from recon.modules.base import Collector


class CookieParser:
    '''
    Parses a Set-Cookie header into its security attributes, discarding the value.
    '''

    @staticmethod
    def parse(header: str, source_url: str) -> CookieRecord | None:
        '''
        Parse one Set-Cookie header.
        Parameters:
            header (str): Raw Set-Cookie value.
            source_url (str): URL of the response that set it.
        Returns:
            CookieRecord | None: Attributes (value length only), or None if the header has no name.
        '''
        first, *attrs = header.split(";")
        name, _, value = first.partition("=")
        name = name.strip()
        if not name:
            return None
        rec = CookieRecord(name=name, source_url=source_url, over_https=urlsplit(source_url).scheme == "https",
                           value_length=len(value.strip()))
        for attr in attrs:
            key, _, val = attr.strip().partition("=")
            k = key.strip().lower()
            if not k:
                continue
            rec.attributes.append(key.strip())
            if k == "secure":
                rec.secure = True
            elif k == "httponly":
                rec.http_only = True
            elif k == "samesite":
                rec.same_site = val.strip().capitalize() or None
            elif k == "domain":
                rec.domain = val.strip().lstrip(".").lower() or None
            elif k == "path":
                rec.path = val.strip() or None
            elif k == "expires":
                rec.expires = val.strip() or None
            elif k == "max-age":
                try:
                    rec.max_age = int(val.strip())
                except ValueError:
                    pass
        rec.persistent = rec.expires is not None or rec.max_age is not None
        if name.startswith("__Host-"):
            rec.prefix = "__Host-"
            rec.prefix_valid = rec.secure and rec.domain is None and rec.path == "/"
        elif name.startswith("__Secure-"):
            rec.prefix = "__Secure-"
            rec.prefix_valid = rec.secure
        return rec


class CookieCollector(Collector[CookieData]):
    '''
    Collects cookie attributes from the HTTP probes and crawled pages (no additional requests).
    '''

    name: ClassVar[str] = "cookies"

    def __init__(self, http: HttpData | None, crawl: CrawlData | None = None) -> None:
        '''
        Create the collector.
        Parameters:
            http (HttpData | None): HTTP probe results, or None.
            crawl (CrawlData | None): Crawl results, or None.
        '''
        self.http = http
        self.crawl = crawl

    async def collect(self) -> tuple[CookieData, list[CollectionError]]:
        '''
        Parse every Set-Cookie header seen, deduplicated by (name, domain, path).
        Returns:
            tuple[CookieData, list[CollectionError]]: Cookie attributes (this step never records errors).
        '''
        sources: list[tuple[str, list[str]]] = []
        for probe in self.http.probes if self.http else []:
            if probe.final_fetched and probe.final_url:
                sources.append((probe.final_url, probe.set_cookies))
        for page in self.crawl.pages if self.crawl else []:
            sources.append((page.final_url or page.url, page.set_cookies))

        seen: dict[tuple[str, str | None, str | None], CookieRecord] = {}
        for url, headers in sources:
            for header in headers:
                rec = CookieParser.parse(header, url)
                if rec is not None:
                    seen.setdefault((rec.name, rec.domain, rec.path), rec)
        return CookieData(cookies=sorted(seen.values(), key=lambda c: c.name.lower()),
                          responses_inspected=len(sources)), []
