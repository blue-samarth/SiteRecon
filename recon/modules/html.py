'''
HTML analysis of pages already fetched by the HTTP module (no additional requests).
'''

from __future__ import annotations

import json
import re
from typing import ClassVar
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup, Comment, Tag

from recon.models import CollectionError, HtmlData, HttpData, HttpProbe, ResourceRef
from recon.modules.base import Collector
from recon.utils import Scope, redact_url


class HtmlParser:
    '''
    Extracts metadata, resources and external domains from one HTML document.
    Commented-out markup is removed before extraction and its URLs are kept separately.
    '''

    MAX_RESOURCES: ClassVar[int] = 2000
    VERIFICATION_META: ClassVar[frozenset[str]] = frozenset({
        "google-site-verification", "facebook-domain-verification", "msvalidate.01",
        "yandex-verification", "p:domain_verify", "baidu-site-verification",
        "norton-safeweb-site-verification", "ahrefs-site-verification",
        "apple-domain-verification", "pinterest-site-verification", "bing-site-verification",
    })
    _URL_IN_TEXT: ClassVar[re.Pattern[str]] = re.compile(r"""(?:https?:)?//[a-z0-9.-]+\.[a-z]{2,}[^\s"'<>)]*""", re.I)
    _SKIP_SCHEMES: ClassVar[tuple[str, ...]] = ("data:", "javascript:", "blob:", "mailto:", "tel:", "about:", "#")
    _LINK_KINDS: ClassVar[dict[str, str]] = {
        "stylesheet": "stylesheet", "preload": "preload", "modulepreload": "modulepreload",
        "preconnect": "preconnect", "dns-prefetch": "preconnect", "prefetch": "prefetch",
        "manifest": "manifest",
    }

    def __init__(self, body: bytes, url: str, scope: Scope) -> None:
        '''
        Prepare a parser for one document.
        Parameters:
            body (bytes): Raw HTML bytes.
            url (str): URL of the document (base for relative links).
            scope (Scope): Scope used to label resources as same-site.
        '''
        self.url = url
        self.scope = scope
        self.soup = BeautifulSoup(body, "html.parser")
        self.data = HtmlData(source_url=url)
        self._resources: list[ResourceRef] = []

    def parse(self) -> HtmlData:
        '''
        Run every extraction step and return the page data.
        Returns:
            HtmlData: Parsed page data.
        '''
        self._extract_comments()
        self._extract_document()
        self._extract_meta()
        self._extract_links()
        self._extract_scripts()
        self._extract_media()
        self.data.resources = self._dedupe(self._resources)
        if len(self._resources) >= self.MAX_RESOURCES:
            self.data.parse_warnings.append(f"resource list capped at {self.MAX_RESOURCES}")
        self.data.external_domains = sorted({r.host for r in self.data.resources if r.host and not r.same_site})
        return self.data

    def _extract_comments(self) -> None:
        '''
        Record and remove HTML comments so inactive markup never counts as live metadata.
        '''
        comments = self.soup.find_all(string=lambda t: isinstance(t, Comment))
        self.data.comment_count = len(comments)
        found: list[str] = []
        for c in comments:
            found.extend(redact_url(u) for u in self._URL_IN_TEXT.findall(str(c)))
            c.extract()
        self.data.commented_urls = list(dict.fromkeys(found))[:200]

    def _extract_document(self) -> None:
        '''
        Extract the title and document language.
        '''
        if self.soup.title and self.soup.title.string:
            self.data.title = self.soup.title.string.strip()
        html_tag = self.soup.find("html")
        if isinstance(html_tag, Tag) and html_tag.get("lang"):
            self.data.lang = str(html_tag.get("lang"))

    def _extract_meta(self) -> None:
        '''
        Extract description, robots, generator, Open Graph, Twitter and verification meta tags.
        '''
        d = self.data
        for meta in self.soup.find_all("meta"):
            key = (meta.get("name") or meta.get("property") or "").strip().lower()
            content = (meta.get("content") or "").strip()
            if not key or not content:
                continue
            if key == "description":
                d.meta_description = content
            elif key == "robots":
                d.robots = content
            elif key == "generator":
                d.generator = content
            elif key.startswith("og:"):
                d.open_graph.setdefault(key, content)
            elif key.startswith("twitter:"):
                d.twitter.setdefault(key, content)
            elif key in self.VERIFICATION_META:
                d.verification_tokens[key] = content
        for key in ("og:image", "twitter:image"):
            self._add(d.open_graph.get(key) or d.twitter.get(key), "meta_image")

    def _extract_links(self) -> None:
        '''
        Extract canonical, favicons, stylesheets, preloads, preconnects and manifests from <link>.
        '''
        for link in self.soup.find_all("link", href=True):
            rels = [r.lower() for r in (link.get("rel") or [])]
            href = link.get("href")
            if "canonical" in rels:
                self.data.canonical = urljoin(self.url, href)
                continue
            if any("icon" in r for r in rels):
                if absolute := self._add(href, "icon"):
                    self.data.favicons.append(absolute)
                continue
            kind = next((self._LINK_KINDS[r] for r in rels if r in self._LINK_KINDS), None)
            if kind:
                self._add(href, kind, **{"as": link.get("as"), "crossorigin": self._flag(link, "crossorigin"),
                                         "integrity": (link.get("integrity") or "").strip() or None})

    def _extract_scripts(self) -> None:
        '''
        Extract external scripts, JSON-LD blocks and count inline scripts.
        '''
        for script in self.soup.find_all("script"):
            stype = (script.get("type") or "").lower()
            if script.get("src"):
                self._add(script.get("src"), "script", type=stype or None,
                          integrity=(script.get("integrity") or "").strip() or None,
                          crossorigin=self._flag(script, "crossorigin"),
                          loading="async" if script.has_attr("async") else ("defer" if script.has_attr("defer") else None))
            elif stype == "application/ld+json":
                try:
                    self.data.json_ld.append(json.loads(script.string or ""))
                except (json.JSONDecodeError, TypeError):
                    self.data.parse_warnings.append("unparseable JSON-LD block")
            else:
                self.data.inline_script_count += 1

    def _extract_media(self) -> None:
        '''
        Extract images, iframes and form actions.
        '''
        for img in self.soup.find_all(["img", "source"]):
            src = img.get("src") or (img.get("srcset") or "").split(",")[0].strip().split(" ")[0]
            self._add(src, "image")
        for frame in self.soup.find_all("iframe", src=True):
            self._add(frame.get("src"), "iframe")
        for form in self.soup.find_all("form", action=True):
            self._add(form.get("action"), "form", method=(form.get("method") or "get").lower())

    def _add(self, raw: str | None, kind: str, **attrs: str | None) -> str | None:
        '''
        Resolve, redact and record a referenced resource.
        Parameters:
            raw (str | None): Attribute value as written in the page.
            kind (str): Resource kind (script, stylesheet, image, ...).
            **attrs (str | None): Extra attributes to keep; None values are dropped.
        Returns:
            str | None: The absolute (redacted) URL, or None if skipped.
        '''
        if not raw or len(self._resources) >= self.MAX_RESOURCES:
            return None
        raw = raw.strip()
        if not raw or raw.lower().startswith(self._SKIP_SCHEMES):
            return None
        absolute = redact_url(urljoin(self.url, raw))
        host = (urlsplit(absolute).hostname or "").lower() or None
        self._resources.append(ResourceRef(
            url=absolute, kind=kind, host=host, same_site=self.scope.allows(host),
            attributes={k: v for k, v in attrs.items() if v},
        ))
        return absolute

    @staticmethod
    def _flag(tag: Tag, attr: str) -> str | None:
        '''
        Return an attribute's value, 'true' for a bare attribute, or None if absent.
        Parameters:
            tag (Tag): Element to inspect.
            attr (str): Attribute name.
        Returns:
            str | None: Attribute value or None.
        '''
        if not tag.has_attr(attr):
            return None
        return tag.get(attr) or "true"

    @staticmethod
    def _dedupe(resources: list[ResourceRef]) -> list[ResourceRef]:
        '''
        Remove duplicate (kind, url) resources, preserving order.
        Parameters:
            resources (list[ResourceRef]): Resources to deduplicate.
        Returns:
            list[ResourceRef]: Unique resources.
        '''
        seen: set[tuple[str, str]] = set()
        out = []
        for r in resources:
            key = (r.kind, r.url)
            if key not in seen:
                seen.add(key)
                out.append(r)
        return out


class HtmlCollector(Collector[HtmlData]):
    '''
    Parses the landing page already fetched by the HTTP module (no new requests).
    '''

    name: ClassVar[str] = "html"

    def __init__(self, hostname: str, http: HttpData | None) -> None:
        '''
        Create the collector.
        Parameters:
            hostname (str): Normalized target hostname.
            http (HttpData | None): HTTP probe results.
        '''
        self.hostname = hostname
        self.http = http

    @staticmethod
    def select_page(http: HttpData | None) -> HttpProbe | None:
        '''
        Pick the main HTML document: HTTPS first, then fewest redirects.
        Parameters:
            http (HttpData | None): HTTP probe results.
        Returns:
            HttpProbe | None: The chosen probe, or None if no HTML was fetched.
        '''
        if not http:
            return None
        candidates = [p for p in http.probes
                      if p.final_fetched and p.body and "html" in (p.content_type or "text/html").lower()]
        candidates.sort(key=lambda p: (not (p.final_url or "").startswith("https://"), p.redirect_count))
        return candidates[0] if candidates else None

    async def collect(self) -> tuple[HtmlData | None, list[CollectionError]]:
        '''
        Parse the selected landing page.
        Returns:
            tuple[HtmlData | None, list[CollectionError]]: Parsed HTML (or None) and a no_document error when nothing was available.
        '''
        page = self.select_page(self.http)
        if page is None:
            return None, [self.error(self.hostname, "no_document",
                                     "no in-scope HTML response was available to parse")]
        data = HtmlParser(page.body, page.final_url or page.requested_url, Scope.for_target(self.hostname)).parse()
        data.content_type = page.content_type
        data.body_truncated = page.body_truncated
        if page.body_truncated:
            data.parse_warnings.append("document exceeded the response size limit and was truncated")
        return data, []
