'''
HTTP / HTTPS response analysis: redirect chains, headers and security-header parsing.
'''

from __future__ import annotations

import asyncio
from typing import Any, ClassVar
from urllib.parse import urljoin, urlsplit

from recon.models import CollectionError, HttpData, HttpHop, HttpProbe, SecurityHeader
from recon.modules.base import Collector
from recon.utils import REDIRECT_STATUSES, FetchOutcome, RawResponse, SafeHttpClient, host_of


class SecurityHeaderParser:
    '''
    Parses security response headers into structured directives.
    '''

    HEADERS: ClassVar[tuple[str, ...]] = (
        "strict-transport-security",
        "content-security-policy",
        "content-security-policy-report-only",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
        "cross-origin-embedder-policy",
    )
    CORS_HEADERS: ClassVar[tuple[str, ...]] = (
        "access-control-allow-origin", "access-control-allow-credentials",
        "access-control-allow-methods", "access-control-allow-headers", "access-control-expose-headers",
    )
    _PARSERS: ClassVar[dict[str, str]] = {
        "strict-transport-security": "parse_hsts",
        "content-security-policy": "parse_csp",
        "content-security-policy-report-only": "parse_csp",
        "permissions-policy": "parse_permissions_policy",
        "referrer-policy": "parse_list",
        "x-content-type-options": "parse_list",
        "x-frame-options": "parse_list",
        "cross-origin-opener-policy": "parse_list",
        "cross-origin-resource-policy": "parse_list",
        "cross-origin-embedder-policy": "parse_list",
    }

    @classmethod
    def inspect(cls, name: str, values: list[str] | None) -> SecurityHeader:
        '''
        Record presence, joined value and parsed directives of a security header.
        Parameters:
            name (str): Lowercase header name.
            values (list[str] | None): All values received, or None if absent.
        Returns:
            SecurityHeader: The header observation.
        '''
        if not values:
            return SecurityHeader(name=name, present=False)
        value = ", ".join(values)
        parser = getattr(cls, cls._PARSERS[name]) if name in cls._PARSERS else None
        try:
            parsed = parser(value) if parser else None
        except ValueError:
            parsed = None
        return SecurityHeader(name=name, present=True, value=value, parsed=parsed)

    @classmethod
    def inspect_all(cls, headers: dict[str, list[str]]) -> dict[str, SecurityHeader]:
        '''
        Inspect every tracked security header in a response.
        Parameters:
            headers (dict[str, list[str]]): Lowercase header name to values.
        Returns:
            dict[str, SecurityHeader]: Observation per tracked header.
        '''
        return {name: cls.inspect(name, headers.get(name)) for name in cls.HEADERS}

    @classmethod
    def cors(cls, headers: dict[str, list[str]]) -> dict[str, str]:
        '''
        Collect CORS response headers present in a response.
        Parameters:
            headers (dict[str, list[str]]): Lowercase header name to values.
        Returns:
            dict[str, str]: Header name to joined value, for headers that were sent.
        '''
        return {h: ", ".join(headers[h]) for h in cls.CORS_HEADERS if headers.get(h)}

    @staticmethod
    def redact_set_cookie(value: str) -> str:
        '''
        Replace a Set-Cookie value with a placeholder, keeping the name and attributes.
        Parameters:
            value (str): Raw Set-Cookie header value.
        Returns:
            str: 'name=[REDACTED]; attributes...'.
        '''
        first, sep, rest = value.partition(";")
        name = first.split("=", 1)[0].strip()
        return f"{name}=[REDACTED]" + (sep + rest if sep else "")

    @staticmethod
    def parse_hsts(value: str) -> dict[str, Any]:
        '''
        Parse Strict-Transport-Security directives.
        Parameters:
            value (str): Raw header value.
        Returns:
            dict[str, Any]: Directives; max-age is int or None if invalid.
        '''
        out: dict[str, Any] = {}
        for directive in value.split(";"):
            directive = directive.strip()
            if not directive:
                continue
            key, _, raw = directive.partition("=")
            key = key.strip().lower()
            if key == "max-age":
                raw = raw.strip().strip('"')
                out["max-age"] = int(raw) if raw.isdigit() else None
            else:
                out[key] = True
        return out

    @staticmethod
    def parse_csp(value: str) -> dict[str, list[str]]:
        '''
        Parse Content-Security-Policy into directive → sources (multiple policies merged).
        Parameters:
            value (str): Raw header value.
        Returns:
            dict[str, list[str]]: Directive to source list.
        '''
        out: dict[str, list[str]] = {}
        # Multiple CSP headers are joined with ", "; each is enforced independently,
        # so the merged view is informational only.
        for policy in value.split(","):
            for directive in policy.split(";"):
                tokens = directive.split()
                if tokens:
                    out.setdefault(tokens[0].lower(), []).extend(tokens[1:])
        return out

    @staticmethod
    def parse_permissions_policy(value: str) -> dict[str, str]:
        '''
        Parse Permissions-Policy into feature → allowlist.
        Parameters:
            value (str): Raw header value.
        Returns:
            dict[str, str]: Feature to allowlist string.
        '''
        out: dict[str, str] = {}
        for item in value.split(","):
            feature, sep, allowlist = item.partition("=")
            if sep:
                out[feature.strip().lower()] = allowlist.strip()
        return out

    @staticmethod
    def parse_list(value: str) -> list[str]:
        '''
        Split a comma-separated header value into lowercase tokens.
        Parameters:
            value (str): Raw header value.
        Returns:
            list[str]: Tokens.
        '''
        return [v.strip().lower() for v in value.split(",") if v.strip()]

    @staticmethod
    def csp_hosts(parsed: dict[str, list[str]]) -> set[str]:
        '''
        Extract hostnames from parsed CSP sources, ignoring keywords and scheme-only sources.
        Parameters:
            parsed (dict[str, list[str]]): Parsed CSP (directive → sources).
        Returns:
            set[str]: Hostnames, with wildcards reduced to their base.
        '''
        hosts = set()
        for sources in parsed.values():
            for src in sources:
                if src.startswith("'") or src.endswith(":") or src in ("*", "data:", "blob:"):
                    continue
                candidate = src if "://" in src else "https://" + src
                host = host_of(candidate.replace("*.", "wildcard."))
                if host:
                    hosts.add(host.removeprefix("wildcard."))
        return hosts


class HttpCollector(Collector[HttpData]):
    '''
    Fetches the target over HTTP and HTTPS and records redirect chains and headers.
    '''

    name: ClassVar[str] = "http"

    def __init__(self, hostname: str, client: SafeHttpClient) -> None:
        '''
        Create the collector.
        Parameters:
            hostname (str): Normalized target hostname.
            client (SafeHttpClient): Scope-restricted HTTP client.
        '''
        self.hostname = hostname
        self.client = client

    @staticmethod
    def candidate_urls(hostname: str) -> list[str]:
        '''
        URLs to probe: http://, https:// and https://www. (unless the target already starts with www.).
        Parameters:
            hostname (str): Normalized target hostname.
        Returns:
            list[str]: URLs to request.
        '''
        urls = [f"http://{hostname}/", f"https://{hostname}/"]
        if not hostname.startswith("www."):
            urls.append(f"https://www.{hostname}/")
        return urls

    async def collect(self) -> tuple[HttpData, list[CollectionError]]:
        '''
        Fetch each candidate URL with scope-validated redirect following.
        Returns:
            tuple[HttpData, list[CollectionError]]: HTTP probes and errors for failed requests.
        '''
        outcomes = await asyncio.gather(*(self.client.fetch(u) for u in self.candidate_urls(self.hostname)))
        probes = [self.build_probe(o) for o in outcomes]
        errors = [self.error(p.requested_url, p.error_type or "error", p.error or "") for p in probes if p.error]
        return HttpData(probes=probes), errors

    @classmethod
    def build_probe(cls, outcome: FetchOutcome) -> HttpProbe:
        '''
        Convert a fetch outcome into an HttpProbe with hops, headers and security-header parsing.
        Parameters:
            outcome (FetchOutcome): Result of SafeHttpClient.fetch.
        Returns:
            HttpProbe: The probe.
        '''
        probe = HttpProbe(requested_url=outcome.requested_url, success=False,
                          error=outcome.error, error_type=outcome.error_type)
        responses = outcome.responses
        if not responses:
            return probe

        probe.hops = [cls._hop(r) for r in responses]
        probe.redirect_count = sum(1 for r in responses if r.status_code in REDIRECT_STATUSES)
        probe.total_time_ms = round(sum(r.elapsed_ms for r in responses), 2)
        probe.redirect_stopped_reason = outcome.stopped_reason
        probe.success = True

        final = outcome.final
        if final is None:
            # Chain stopped before a terminal response (e.g. redirect leaves scope).
            probe.final_url = outcome.stopped_url
            probe.final_fetched = False
            probe.status_code = responses[-1].status_code
        else:
            probe.final_url = final.url
            probe.final_fetched = True
            cls._apply_final(probe, final)

        if urlsplit(outcome.requested_url).scheme == "http":
            visited = [r.url for r in responses] + ([outcome.stopped_url] if outcome.stopped_url else [])
            probe.redirects_to_https = any(urlsplit(u).scheme == "https" for u in visited)
        return probe

    @staticmethod
    def _hop(r: RawResponse) -> HttpHop:
        '''
        Convert a raw response into a redirect-chain hop with an absolute Location.
        Parameters:
            r (RawResponse): Raw response.
        Returns:
            HttpHop: The hop.
        '''
        location = r.header("location") if r.status_code in REDIRECT_STATUSES else None
        if location:
            location = urljoin(r.url, location)
        return HttpHop(url=r.url, status_code=r.status_code, location=location,
                       elapsed_ms=r.elapsed_ms, http_version=r.http_version)

    @staticmethod
    def _apply_final(probe: HttpProbe, final: RawResponse) -> None:
        '''
        Copy final-response details (status, headers, body, security headers) onto the probe.
        Parameters:
            probe (HttpProbe): Probe to update in place.
            final (RawResponse): Terminal response of the chain.
        '''
        headers: dict[str, list[str]] = {}
        for key, value in final.headers:
            headers.setdefault(key.lower(), []).append(value)
        probe.set_cookies = headers.get("set-cookie", [])
        if probe.set_cookies:  # cookie values never reach reports
            headers["set-cookie"] = [SecurityHeaderParser.redact_set_cookie(v) for v in probe.set_cookies]
        probe.headers = headers
        probe.cache_control = final.header("cache-control")
        probe.cors = SecurityHeaderParser.cors(headers)
        probe.status_code = final.status_code
        probe.http_version = final.http_version
        probe.server = final.header("server")
        probe.content_type = final.header("content-type")
        length = final.header("content-length")
        probe.content_length = int(length) if length and length.strip().isdigit() else None
        probe.body_bytes = len(final.body)
        probe.body_truncated = final.truncated
        probe.response_time_ms = final.elapsed_ms
        probe.body = final.body
        probe.security_headers = SecurityHeaderParser.inspect_all(headers)
