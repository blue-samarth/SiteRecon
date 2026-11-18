'''
Dynamic rendering: load the in-scope pages in a headless browser (Playwright/Chromium), run their
JavaScript, and capture the requests each running page makes plus the DOM/config it builds at runtime.

This is the one collector that executes pages rather than parsing them statically, so it surfaces the
runtime endpoints and client configuration that only exist after JavaScript runs (the SPA gap the static
asset analysis cannot see). Several pages (the crawl's in-scope routes) are rendered in one browser
session. It is opt-in (``--render``) and off by default.

Playwright is imported lazily, so the package is only required when rendering is actually requested; if it
or its browser binary is missing, the collector reports a clear error instead of failing the scan.
'''

from __future__ import annotations

import re
from typing import ClassVar
from urllib.parse import urlsplit

from recon.models import (
    ClientConfig,
    CollectionError,
    EndpointRef,
    RenderData,
    RenderedPage,
    RenderRequest,
)
from recon.modules.base import Collector
from recon.modules.javascript import ClientConfigExtractor, EndpointExtractor
from recon.utils import Scope, redact_url


class Renderer(Collector[RenderData]):
    '''
    Loads in-scope pages in a headless browser and records their runtime requests, API routes and config.
    '''

    name: ClassVar[str] = "render"
    # Resource types whose requests are real API traffic — always promoted to endpoints.
    API_TYPES: ClassVar[frozenset[str]] = frozenset({"xhr", "fetch", "websocket", "eventsource"})
    # DOM-referenced routes are kept as endpoints only when they look like an API (the focus), so the inventory
    # is not flooded with image/font/CDN URLs the extractor also finds in rendered markup.
    _API_HINT: ClassVar[re.Pattern[str]] = re.compile(
        r"/(?:api|rest|graphql|gql|v\d{1,2}|_next/data|\.netlify|\.vercel|oauth|auth|webhook|functions|rpc)s?\b",
        re.I)
    _ASSET_EXT: ClassVar[tuple[str, ...]] = (
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".avif", ".css", ".js", ".mjs",
        ".map", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm", ".mp3", ".pdf")
    MAX_REQUESTS: ClassVar[int] = 1000
    MAX_ENDPOINTS: ClassVar[int] = 300
    MAX_CONSOLE: ClassVar[int] = 50

    def __init__(self, urls: list[str], hostname: str, *, timeout: float = 30.0, max_pages: int = 10,
                 user_agent: str | None = None, retain_client_keys: bool = False) -> None:
        '''
        Create the renderer.
        Parameters:
            urls (list[str]): Page URLs to load (the target origin plus in-scope crawled routes).
            hostname (str): Normalized target hostname (used only to label same-site endpoints).
            timeout (float): Per-navigation / load-state timeout in seconds.
            max_pages (int): Maximum number of pages to render in the session.
            user_agent (str | None): User-agent to present; the browser default when None.
            retain_client_keys (bool): Keep public client keys (e.g. Supabase anon key) unredacted.
        '''
        self.urls = list(dict.fromkeys(u for u in urls if u))[:max_pages]
        self.hostname = hostname
        self.timeout = timeout
        self.user_agent = user_agent
        self.retain_client_keys = retain_client_keys

    async def collect(self) -> tuple[RenderData | None, list[CollectionError]]:
        '''
        Drive a headless browser through each page and capture what it does at runtime.
        Returns:
            tuple[RenderData | None, list[CollectionError]]: Aggregated render result (None with an error
                only if Playwright/the browser is unavailable), plus per-page load errors.
        '''
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return None, [self.error(self.urls[0] if self.urls else self.hostname, "playwright_missing",
                                     "playwright is not installed; run `uv add playwright` and "
                                     "`uv run playwright install chromium`")]

        requests: list[RenderRequest] = []
        statuses: dict[str, int] = {}
        console_errors: list[str] = []
        pages: list[RenderedPage] = []
        htmls: list[str] = []
        errors: list[CollectionError] = []

        def on_request(req: object) -> None:
            try:
                requests.append(RenderRequest(method=req.method, url=redact_url(req.url),   # type: ignore[attr-defined]
                                              resource_type=req.resource_type))              # type: ignore[attr-defined]
            except Exception:
                pass

        def on_response(resp: object) -> None:
            try:
                statuses[redact_url(resp.url)] = resp.status   # type: ignore[attr-defined]
            except Exception:
                pass

        def on_console(msg: object) -> None:
            try:
                if msg.type == "error":                        # type: ignore[attr-defined]
                    console_errors.append(str(msg.text)[:300])  # type: ignore[attr-defined]
            except Exception:
                pass

        timeout_ms = int(self.timeout * 1000)
        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                try:
                    kwargs: dict[str, object] = {"ignore_https_errors": True}
                    if self.user_agent:
                        kwargs["user_agent"] = self.user_agent
                    context = await browser.new_context(**kwargs)
                    context.on("request", on_request)    # request/response aggregate across every page
                    context.on("response", on_response)
                    for url in self.urls:
                        before = len(requests)
                        page = await context.new_page()
                        page.on("console", on_console)   # console is a page-level event, not context-level
                        try:
                            response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                            try:
                                await page.wait_for_load_state("networkidle", timeout=timeout_ms)
                            except Exception:
                                pass   # chatty/long-polling pages never go idle; keep what we captured
                            htmls.append(await page.content())
                            pages.append(RenderedPage(url=redact_url(page.url), title=(await page.title()) or None,
                                                      status_code=response.status if response else None,
                                                      request_count=len(requests) - before))
                        except Exception as exc:
                            pages.append(RenderedPage(url=redact_url(url), error=f"{type(exc).__name__}: {exc}"))
                            errors.append(self.error(url, "render_failed", f"{type(exc).__name__}: {exc}"))
                        finally:
                            await page.close()
                finally:
                    await browser.close()
        except Exception as exc:
            return None, [self.error(self.urls[0] if self.urls else self.hostname, "render_failed",
                                     f"{type(exc).__name__}: {exc}")]

        for req in requests:
            req.status = statuses.get(req.url)
        data = self._build(pages=pages, requests=requests, htmls=htmls, console_errors=console_errors,
                           hostname=self.hostname, retain=self.retain_client_keys)
        return data, errors

    @classmethod
    def _build(cls, *, pages: list[RenderedPage], requests: list[RenderRequest], htmls: list[str],
               console_errors: list[str], hostname: str, retain: bool) -> RenderData:
        '''
        Turn captured browser activity into a RenderData (pure; no browser involved, so it is unit-testable).

        Endpoints are the API routes the app actually called (xhr/fetch/websocket) plus API-ish routes found
        in each rendered DOM; non-API requests (images, scripts, fonts, pages) stay in the full ``requests``
        inventory and ``hosts_contacted`` but are not promoted to endpoints.
        Parameters:
            pages (list[RenderedPage]): Per-page summaries.
            requests (list[RenderRequest]): Every request the browser made (urls already redacted).
            htmls (list[str]): Fully-rendered DOM of each page.
            console_errors (list[str]): Captured console error texts.
            hostname (str): Target hostname (same-site labelling only).
            retain (bool): Keep public client keys unredacted.
        Returns:
            RenderData: The assembled render result.
        '''
        scope = Scope.for_target(hostname)
        endpoints: dict[str, EndpointRef] = {}
        for req in requests:
            if req.resource_type in cls.API_TYPES and req.url not in endpoints:
                host = urlsplit(req.url).hostname
                endpoints[req.url] = EndpointRef(value=req.url, host=host, method=req.method,
                                                 same_site=scope.allows(host))
        for html in htmls:
            for ref in EndpointExtractor.extract(html, hostname, scope):
                if ref.value in endpoints or cls._looks_malformed(ref.value) or not cls._is_api_route(ref.value):
                    continue   # focus endpoints on API routes; skip DOM-escaped junk and static assets
                endpoints[ref.value] = ref

        configs: list[ClientConfig] = []
        seen_cfg: set[tuple[str, tuple[str, ...]]] = set()
        source = pages[0].url if pages else hostname
        for html in htmls:
            for cfg in ClientConfigExtractor.extract(html, source, retain=retain):
                key = (cfg.provider, tuple(f.key for f in cfg.fields))
                if key not in seen_cfg:
                    seen_cfg.add(key)
                    configs.append(cfg)

        hosts = sorted({h for r in requests if (h := urlsplit(r.url).hostname)})
        total_bytes = sum(len(h.encode("utf-8", "replace")) for h in htmls)
        return RenderData(
            pages=pages, pages_rendered=sum(1 for p in pages if p.error is None), rendered_bytes=total_bytes,
            request_count=len(requests), requests=requests[: cls.MAX_REQUESTS], hosts_contacted=hosts,
            endpoints=list(endpoints.values())[: cls.MAX_ENDPOINTS], client_configs=configs,
            console_errors=console_errors[: cls.MAX_CONSOLE])

    @classmethod
    def _is_api_route(cls, value: str) -> bool:
        '''
        Whether a DOM-referenced URL/path looks like an API route (vs a static asset), so endpoints stay focused.
        Parameters:
            value (str): The candidate endpoint value.
        Returns:
            bool: True if it matches an API path hint and is not a static asset.
        '''
        path = urlsplit(value).path.lower()
        if any(path.endswith(ext) for ext in cls._ASSET_EXT):
            return False
        return bool(cls._API_HINT.search(path))

    @staticmethod
    def _looks_malformed(value: str) -> bool:
        '''
        Whether an endpoint value ran into HTML-escaped inline JSON in the rendered DOM and is not a real URL.
        Parameters:
            value (str): The candidate endpoint value.
        Returns:
            bool: True if it contains HTML entities or markup and should be dropped.
        '''
        return "&quot;" in value or "&#" in value or "&amp;quot" in value or "<" in value or ">" in value
