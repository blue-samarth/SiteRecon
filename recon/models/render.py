'''
Dynamic-rendering models: what a headless-browser load of one or more pages produced.

Unlike the static asset/JS analysis (which parses bundles without executing them), a render actually runs
each page's JavaScript in a real browser, so it captures the requests the running app makes and the DOM /
client configuration it builds at runtime — closing the SPA gap the static path cannot see. Several pages
(the crawl's in-scope routes) are rendered in one browser session and their results aggregated.
'''

from __future__ import annotations

from pydantic import BaseModel, Field

from recon.models.assets import ClientConfig, EndpointRef


class RenderRequest(BaseModel):
    '''
    One request a rendered page made, as observed by the browser.
    '''
    method: str
    url: str                    # query values redacted
    resource_type: str          # document, xhr, fetch, script, stylesheet, image, websocket, ...
    status: int | None = None   # response status, if one came back


class RenderedPage(BaseModel):
    '''
    Summary of one page that was loaded in the browser.
    '''
    url: str
    title: str | None = None
    status_code: int | None = None
    request_count: int = 0
    error: str | None = None    # set when this page failed to load (others still rendered)


class RenderData(BaseModel):
    '''
    The aggregate result of loading one or more pages in a headless browser and running their JavaScript.
    '''
    pages: list[RenderedPage] = Field(default_factory=list)
    pages_rendered: int = 0
    rendered_bytes: int = 0
    request_count: int = 0
    requests: list[RenderRequest] = Field(default_factory=list)       # full inventory across pages (every type)
    hosts_contacted: list[str] = Field(default_factory=list)
    endpoints: list[EndpointRef] = Field(default_factory=list)        # API routes only (xhr/fetch + API-ish DOM refs)
    client_configs: list[ClientConfig] = Field(default_factory=list)  # configs present in the rendered DOM
    console_errors: list[str] = Field(default_factory=list)
    note: str = ("Pages were loaded and their JavaScript executed in a headless browser. 'endpoints' are the "
                 "API routes the running application called or references at runtime (the SPA gap static "
                 "parsing misses); 'requests' is the full inventory of everything the browser fetched.")
