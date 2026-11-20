'''
Coordinates collection → observations → analysis. Never generates presentation output itself.

Sequence:
  1. DNS
  2. network, HTTP, TLS, DNSSEC, registration, subdomains, historical URLs   (concurrent, bounded)
  3. HTML → public resources → crawler → JS/CSS assets         (crawler seeded with sitemap URLs)
  4. technology, cookies, third-party, SEO audit               (derived from collected data)
  5. observations → analysis engine
'''

from __future__ import annotations

import asyncio
import logging
from collections import Counter
from collections.abc import Awaitable, Callable
from contextlib import AsyncExitStack
from datetime import timedelta
from time import perf_counter
from typing import Any, ClassVar, TypeVar
from urllib.parse import urlsplit

from recon import TOOL_NAME, __version__
from recon.analysis import (
    SIGNATURES_VERSION,
    AnalysisEngine,
    ChangeAnalyzer,
    ObservationBuilder,
    RegressionAnalyzer,
    ScanComparator,
)
from recon.config import ALL_MODULES, Config
from recon.models import (
    AnalysisResult,
    AssetData,
    CollectionError,
    CrawlData,
    HttpData,
    ModuleResult,
    ModuleStatus,
    ReconReport,
    Severity,
    TargetInfo,
    ToolInfo,
    utcnow,
)
from recon.modules import (
    AssetCollector,
    Collector,
    CookieCollector,
    Crawler,
    CtCache,
    DnsCollector,
    DnssecCollector,
    HistoricalUrlCollector,
    HtmlCollector,
    HttpCollector,
    NetworkCollector,
    PassiveCache,
    Renderer,
    ResourcesCollector,
    SeoCollector,
    SubdomainCollector,
    TechnologyCollector,
    ThirdPartyCollector,
    TlsCollector,
    VulnerabilityScanner,
    WhoisCollector,
)
from recon.modules import historical as historical_sources
from recon.modules import subdomain_sources as passive_sources
from recon.storage import ScanStore
from recon.utils import DnsClient, GeoLocator, SafeHttpClient, Scope, get_logger

T = TypeVar("T")


class ScanOrchestrator:
    '''
    Runs the full pipeline for one target and assembles the ReconReport.
    Each collector runs in isolation: an exception becomes a FAILED module result, not a failed scan.
    '''

    LIMITATIONS: ClassVar[tuple[str, ...]] = (
        "JavaScript/CSS analysis is static and limited to in-scope assets (plus hosts allowed with "
        "--asset-host); assets are never executed. Endpoint paths and public client configuration are "
        "inventoried for review; suspected private credentials are reported by type and fingerprint only — "
        "raw secret values are never stored, and none are ever used.",
        "Technology detection relies on public markers; every detection carries its evidence and a grade "
        "(confirmed / probable / possible), and versions are reported only when a banner, generator tag or "
        "versioned asset path states one.",
        "Subresource Integrity is hash-verified for assets this scan downloaded; for assets that were not "
        "downloaded (off-scope third parties), only the presence of the attribute is reported.",
        "Subdomain discovery is never exhaustive. Certificate Transparency is always queried; passive "
        "datasets and archives are queried only when enabled with --subdomain-source, and each one "
        "discloses the target domain to that provider. A name absent from the report is not evidence it "
        "does not exist. Generated candidates (--permute-subdomains) are resolved in DNS only, capped, and "
        "reported solely when they resolve.",
        "Historical URLs (--historical) come from third-party web archives and URL indexes and describe the "
        "past: a URL there may no longer exist, query values are redacted, and technology hints derived "
        "from archived paths describe the stack that served them at the time, never the current one.",
        "The SEO audit (--seo) re-reads the pages this scan already fetched: it covers exactly those "
        "pages, judges the markup as served (JavaScript-rendered content counts only with --render), and "
        "reports what the site declares about indexing — not what any search engine has indexed. Its "
        "score is for tracking a site against its own history and predicts nothing about rankings.",
        "Managed-cloud resources are inventoried from references only. SiteRecon never requests a bucket, "
        "function or database endpoint, so it cannot establish whether any is reachable or publicly "
        "readable; confirming that requires an authorized active check.",
    )
    _RDAP_ACCEPT: ClassVar[dict[str, str]] = {"Accept": "application/rdap+json, application/json"}
    log: ClassVar[logging.Logger] = get_logger("orchestrator")

    def __init__(
        self,
        config: Config,
        *,
        dns_client: DnsClient | None = None,
        target_client: SafeHttpClient | None = None,
        rdap_client: SafeHttpClient | None = None,
        ct_client: SafeHttpClient | None = None,
        dnssec_client: DnsClient | None = None,
        passive_client: SafeHttpClient | None = None,
        historical_client: SafeHttpClient | None = None,
        tls_kwargs: dict[str, Any] | None = None,
        whois_kwargs: dict[str, Any] | None = None,
    ) -> None:
        '''
        Create an orchestrator and its clients.
        Parameters:
            config (Config): Runtime configuration.
            dns_client (DnsClient | None): DNS client override (tests).
            target_client (SafeHttpClient | None): Target-scoped HTTP client override (tests).
            rdap_client (SafeHttpClient | None): RDAP client override (tests).
            ct_client (SafeHttpClient | None): Certificate Transparency client override (tests).
            dnssec_client (DnsClient | None): Validating DNS client override (tests).
            passive_client (SafeHttpClient | None): Passive-subdomain-source client override (tests).
            historical_client (SafeHttpClient | None): Historical-URL-source client override (tests).
            tls_kwargs (dict[str, Any] | None): Extra keyword arguments for TlsCollector.
            whois_kwargs (dict[str, Any] | None): Extra keyword arguments for WhoisCollector.
        '''
        self.config = config
        self.scope = Scope.for_target(config.hostname)
        self._progress: Callable[[str], None] | None = None
        self.tls_kwargs = tls_kwargs or {}
        self.whois_kwargs = whois_kwargs or {}
        self._client_kwargs: dict[str, Any] = dict(
            timeout=config.timeout, retries=config.retries, user_agent=config.user_agent,
            max_response_bytes=config.max_response_bytes, max_redirects=config.max_redirects,
            concurrency=config.concurrency, allow_private_networks=config.allow_private_networks,
        )
        public_only = {**self._client_kwargs, "allow_private_networks": False}
        self.dns_client = dns_client or DnsClient(config.timeout, config.retries, config.concurrency)
        # Optional offline geolocation DB for city-level hosting estimates; None if not configured/available.
        self.geo_locator = GeoLocator.open(config.geoip_db)
        self.dnssec_client = dnssec_client
        self.target_client = target_client or SafeHttpClient(self.scope, **self._client_kwargs)
        self.rdap_client = rdap_client or SafeHttpClient(
            NetworkCollector.RDAP_SCOPE, **{**public_only, "max_response_bytes": 1024 * 1024},
            extra_headers=self._RDAP_ACCEPT,
        )
        self.ct_client = ct_client or SafeHttpClient(
            SubdomainCollector.CT_SCOPE,
            **{**public_only, "timeout": max(config.timeout * 3, 30.0), "retries": max(config.retries, 3),
               "max_response_bytes": 25 * 1024 * 1024, "concurrency": 2},
            extra_headers={"Accept": "application/json"},
        )
        # One client per third-party family, each allow-listed to exactly the provider hosts its sources
        # contact (never the target's scope, never private networks) — so a passive source cannot be
        # steered into requesting anything else.
        self.passive_sources = [passive_sources.REGISTRY[name]()
                                for name in passive_sources.resolve_sources(config.subdomain_sources)]
        self.passive_client = passive_client or self._source_client(
            passive_sources.scope_hosts([s.name for s in self.passive_sources]))
        self.historical_sources = [historical_sources.REGISTRY[name]()
                                   for name in historical_sources.resolve_sources(
                                       config.historical_sources or None)] if config.historical else []
        self.historical_client = historical_client or self._source_client(
            historical_sources.scope_hosts([s.name for s in self.historical_sources]))

    def _source_client(self, hosts: list[str]) -> SafeHttpClient | None:
        '''
        Build a client allow-listed to exactly these third-party source hosts.

        Returns None when no host is given, which is how "no source enabled" is represented: a collector
        with no client skips every source rather than falling back to a wider scope.
        Parameters:
            hosts (list[str]): Provider hostnames the client may contact.
        Returns:
            SafeHttpClient | None: The scoped client, or None when there is nothing to contact.
        '''
        if not hosts:
            return None
        cfg = self.config
        return SafeHttpClient(
            Scope(hosts=hosts),
            **{**self._client_kwargs, "allow_private_networks": False,
               "timeout": max(cfg.timeout * 2, 20.0), "retries": max(cfg.retries, 1),
               "max_response_bytes": 25 * 1024 * 1024, "concurrency": 2},
            extra_headers={"Accept": "application/json, text/html;q=0.9, */*;q=0.8"},
        )

    def rdap_client_factory(self, scope: Scope) -> SafeHttpClient:
        '''
        Build a public-only RDAP client for a registry discovered at run time.
        Parameters:
            scope (Scope): Hosts the new client may contact.
        Returns:
            SafeHttpClient: A new client (caller closes it).
        '''
        kwargs = {**self._client_kwargs, "allow_private_networks": False, "max_response_bytes": 2 * 1024 * 1024}
        return SafeHttpClient(scope, **kwargs, extra_headers=self._RDAP_ACCEPT)

    def _maybe(self, module: str, make: Any, reason: str | None = None) -> Awaitable[ModuleResult[Any]]:
        '''
        Run a collector if its module is enabled and its prerequisites are met, else return SKIPPED.
        Parameters:
            module (str): Module name.
            make (Any): Zero-argument callable building the Collector.
            reason (str | None): Prerequisite failure explaining a skip, if any.
        Returns:
            Awaitable[ModuleResult[Any]]: Awaitable producing the module result.
        '''
        if not self.config.enabled(module):
            return self._tracked(module, self._skipped(module, "not selected" if module not in self.config.modules else "disabled"))
        if reason:
            return self._tracked(module, self._skipped(module, reason))
        return self._tracked(module, self.run_collector(make()))

    async def _tracked(self, module: str, awaitable: Awaitable[ModuleResult[Any]]) -> ModuleResult[Any]:
        '''
        Await a module's result and report one unit of progress when it completes.
        Parameters:
            module (str): Module name, passed to the progress callback.
            awaitable (Awaitable[ModuleResult[Any]]): The module's result awaitable.
        Returns:
            ModuleResult[Any]: The awaited result, unchanged.
        '''
        result = await awaitable
        if self._progress is not None:
            self._progress(module)
        return result

    MODULE_COUNT: ClassVar[int] = len(ALL_MODULES)

    async def run(self, progress: Callable[[str], None] | None = None) -> ReconReport:
        '''
        Run the full pipeline and return the report (without history; see ScanHistory).
        Parameters:
            progress (Callable[[str], None] | None): Optional callback invoked with each module's name as
                that module finishes, for a terminal progress bar. Called MODULE_COUNT times in total.
        Returns:
            ReconReport: The complete report, including partial results.
        '''
        self._progress = progress
        cfg, host = self.config, self.config.hostname
        started = utcnow()
        t0 = perf_counter()

        asset_scope = Scope(roots=[host], hosts=cfg.asset_hosts)
        asset_client = SafeHttpClient(asset_scope, **{**self._client_kwargs, "max_response_bytes": cfg.max_asset_bytes,
                                                      "concurrency": 4})
        map_client = SafeHttpClient(asset_scope, **{**self._client_kwargs,
                                                    "max_response_bytes": cfg.max_source_map_bytes,
                                                    "concurrency": 4})

        async with AsyncExitStack() as stack:
            for client in (self.target_client, self.rdap_client, self.ct_client, asset_client, map_client,
                           self.passive_client, self.historical_client):
                if client is not None:
                    await stack.enter_async_context(client)
            dns_result = await self._maybe("dns", lambda: DnsCollector(host, self.dns_client, cfg.dkim_selectors))
            ips = dns_result.data.addresses() if dns_result.data else []

            def tls_probe(hostname: str):
                return TlsCollector(hostname, timeout=cfg.timeout, retries=cfg.retries,
                                    allow_private_networks=cfg.allow_private_networks, **self.tls_kwargs).probe(hostname)

            (network_result, http_result, tls_result, whois_result, subdomains_result,
             dnssec_result, historical_result) = await asyncio.gather(
                self._maybe("network", lambda: NetworkCollector(ips, self.dns_client, self.rdap_client,
                                                                self.geo_locator),
                            None if ips else "no A/AAAA addresses resolved"),
                self._maybe("http", lambda: HttpCollector(host, self.target_client)),
                self._maybe("tls", lambda: TlsCollector(host, timeout=cfg.timeout, retries=cfg.retries,
                                                        allow_private_networks=cfg.allow_private_networks,
                                                        **self.tls_kwargs)),
                self._maybe("whois", lambda: WhoisCollector(host, self.rdap_client_factory, timeout=cfg.timeout,
                                                            retries=cfg.retries, **self.whois_kwargs)),
                self._maybe("subdomains", lambda: SubdomainCollector(
                    host, self.ct_client, self.dns_client, verify_limit=cfg.max_subdomains,
                    http_client=self.target_client if cfg.probe_subdomains else None,
                    tls_probe=tls_probe if cfg.probe_subdomains else None,
                    cache=CtCache(cfg.cache_dir, timedelta(hours=cfg.ct_cache_ttl_hours)),
                    passive_client=self.passive_client, passive_sources=self.passive_sources,
                    passive_cache=PassiveCache(cfg.cache_dir, timedelta(hours=cfg.ct_cache_ttl_hours)),
                    permute=cfg.permute_subdomains, permutation_limit=cfg.max_permutations)),
                self._maybe("dnssec", lambda: DnssecCollector(host, self.dnssec_client, timeout=cfg.timeout,
                                                              retries=cfg.retries)),
                self._maybe("historical", lambda: HistoricalUrlCollector(
                    host, self.historical_client, sources=self.historical_sources,
                    limit=cfg.max_historical_urls),
                    None if self.historical_sources else "no historical sources enabled"),
            )

            http = http_result.data
            html_result = await self._maybe("html", lambda: HtmlCollector(host, http),
                                            None if http else "requires HTTP results")
            origin = self.origin(host, http)
            resources_result = await self._maybe(
                "resources", lambda: ResourcesCollector(host, self.target_client, origin, html_result.data))
            sitemap_urls = resources_result.data.sitemap_urls() if resources_result.data else []
            robots = resources_result.data.robots if resources_result.data else None
            crawler_result = await self._maybe("crawler", lambda: Crawler(
                host, self.target_client, [origin + "/", *sitemap_urls[: cfg.max_pages]],
                max_depth=cfg.crawl_depth, max_pages=cfg.max_pages, delay=cfg.crawl_delay,
                robots=robots, respect_robots=cfg.respect_robots))
            assets_result = await self._maybe("javascript", lambda: AssetCollector(
                host, asset_client, map_client, html=html_result.data, crawl=crawler_result.data,
                allowed_hosts=cfg.asset_hosts, max_assets=cfg.max_assets,
                max_total_bytes=cfg.max_assets_total_bytes, retain_client_keys=cfg.retain_client_keys),
                None if (html_result.data or crawler_result.data) else "requires HTML or crawl results")

        crawl = crawler_result.data
        assets = assets_result.data
        render_result = await self._maybe("render", lambda: Renderer(
            self._render_seeds(origin, crawl, cfg.render_max_pages), host, timeout=cfg.render_timeout,
            max_pages=cfg.render_max_pages, user_agent=cfg.user_agent,
            retain_client_keys=cfg.retain_client_keys))
        vulnscan_result = await self._run_vulnscan(cfg, assets)
        technology_result = await self._maybe("technology", lambda: TechnologyCollector(
            http, html_result.data, crawl=crawl, dns=dns_result.data, assets=assets))
        cookies_result = await self._maybe("cookies", lambda: CookieCollector(http, crawl),
                                           None if (http or crawl) else "requires HTTP or crawl results")
        third_party_result = await self._maybe("third_party", lambda: ThirdPartyCollector(
            host, dns=dns_result.data, http=http, html=html_result.data, tls=tls_result.data, crawl=crawl,
            assets=assets))
        seo_result = await self._maybe("seo", lambda: SeoCollector(
            host, origin, html=html_result.data, http=http, crawl=crawl, resources=resources_result.data),
            None if (http or crawl) else "requires HTTP or crawl results")
        if historical_result.data is not None and technology_result.data is not None:
            # Annotate (never merge): a hint the current scan also detects is a live technology, while one
            # only the archive saw is a lead about the past. The technology inventory itself is untouched.
            HistoricalUrlCollector.mark_current(
                historical_result.data, {t.name for t in technology_result.data.technologies})

        report = ReconReport(
            scan_id=ScanStore.new_scan_id(started),
            tool=ToolInfo(name=TOOL_NAME, version=__version__, user_agent=cfg.user_agent),
            target=TargetInfo(input=cfg.target_input, hostname=host, scope=self.scope.describe()),
            options=self.options(),
            started_at=started, finished_at=started, duration_ms=0,
            dns=dns_result, network=network_result, http=http_result, tls=tls_result, whois=whois_result,
            html=html_result, technology=technology_result, subdomains=subdomains_result,
            third_party=third_party_result, dnssec=dnssec_result, resources=resources_result,
            crawler=crawler_result, cookies=cookies_result, javascript=assets_result, render=render_result,
            vulnscan=vulnscan_result, historical=historical_result, seo=seo_result,
            analysis=AnalysisResult(),
            limitations=list(self.LIMITATIONS),
        )
        report.observations = ObservationBuilder(host, report.module_results()).build()
        report.analysis = AnalysisEngine(utcnow()).analyze(
            dns=dns_result.data, network=network_result.data, http=http, tls=tls_result.data, host=host,
            whois=whois_result.data, html=html_result.data, subdomains=subdomains_result.data,
            dnssec=dnssec_result.data, resources=resources_result.data, crawl=crawl,
            cookies=cookies_result.data, assets=assets, third_party=third_party_result.data,
            render=render_result.data, vulnerabilities=vulnscan_result.data,
            historical=historical_result.data, seo=seo_result.data, observations=report.observations,
        )
        report.errors = [e for m in report.module_results().values() for e in m.errors]
        report.finished_at = utcnow()
        report.duration_ms = round((perf_counter() - t0) * 1000, 2)
        if self.geo_locator is not None:
            self.geo_locator.close()
        return report

    def origin(self, host: str, http: HttpData | None) -> str:
        '''
        Choose the origin for resource fetching and crawling: the in-scope HTTPS final URL, else https://host.
        Parameters:
            host (str): Target hostname.
            http (HttpData | None): HTTP results.
        Returns:
            str: Origin such as 'https://example.com'.
        '''
        for probe in http.probes if http else []:
            if probe.final_fetched and probe.final_url:
                parts = urlsplit(probe.final_url)
                if parts.scheme == "https" and self.scope.allows(parts.hostname):
                    return f"https://{parts.netloc}"
        return f"https://{host}"

    async def _run_vulnscan(self, cfg: Config, assets: AssetData | None) -> ModuleResult[Any]:
        '''
        Run the OSV vulnerability lookup over the detected components, behind an api.osv.dev-scoped client.
        Parameters:
            cfg (Config): Runtime config (gates the module and supplies client settings).
            assets (AssetData | None): Static asset analysis carrying the detected libraries.
        Returns:
            ModuleResult[Any]: The vulnscan result (SKIPPED when the module is disabled).
        '''
        if not cfg.enabled("vulnscan"):
            return await self._maybe("vulnscan", lambda: None)   # not enabled → SKIPPED, lambda never called
        client = SafeHttpClient(Scope(hosts=["api.osv.dev"]),
                                **{**self._client_kwargs, "allow_private_networks": False})
        async with client:
            return await self._maybe("vulnscan", lambda: VulnerabilityScanner(assets, client))

    @staticmethod
    def _render_seeds(origin: str, crawl: CrawlData | None, limit: int) -> list[str]:
        '''
        Pages to render: the origin homepage plus distinct in-scope crawled routes (scheme://host/path, no
        query), so rendering spans the app's pages rather than only the landing page.
        Parameters:
            origin (str): The target origin, e.g. 'https://example.com'.
            crawl (CrawlData | None): Crawl results, if the crawler ran.
            limit (int): Maximum number of pages to render.
        Returns:
            list[str]: Distinct page URLs to render, origin first.
        '''
        seeds: list[str] = [origin + "/"]
        seen: set[str] = {urlsplit(seeds[0]).path or "/"}
        for page in crawl.pages if crawl else []:
            parts = urlsplit(page.url)
            path = parts.path or "/"
            if path in seen or not parts.netloc:
                continue
            seen.add(path)
            seeds.append(f"{parts.scheme}://{parts.netloc}{path}")
            if len(seeds) >= limit:
                break
        return seeds

    def options(self) -> dict[str, Any]:
        '''
        Record the options that shaped this scan.
        Returns:
            dict[str, Any]: Option name to value.
        '''
        c = self.config
        return {"timeout": c.timeout, "retries": c.retries, "modules": sorted(c.modules),
                "subdomains": c.subdomains, "probe_subdomains": c.probe_subdomains,
                "max_subdomains": c.max_subdomains, "whois": c.whois, "crawl": c.crawl,
                "crawl_depth": c.crawl_depth, "max_pages": c.max_pages, "crawl_delay": c.crawl_delay,
                "respect_robots": c.respect_robots, "concurrency": c.concurrency, "max_assets": c.max_assets,
                "asset_hosts": list(c.asset_hosts),
                "subdomain_sources": [s.name for s in self.passive_sources],
                "permute_subdomains": c.permute_subdomains, "max_permutations": c.max_permutations,
                "historical": c.historical, "max_historical_urls": c.max_historical_urls,
                "seo": c.seo,
                "historical_sources": [s.name for s in self.historical_sources],
                "format": c.output_format.value, "allow_private_networks": c.allow_private_networks,
                "signatures_version": SIGNATURES_VERSION,
                "geoip_db": str(c.geoip_db) if c.geoip_db else None}

    @classmethod
    async def run_collector(cls, collector: Collector[T]) -> ModuleResult[T]:
        '''
        Run one collector, converting any exception into a FAILED result so the scan continues.
        Parameters:
            collector (Collector[T]): The collection step to run.
        Returns:
            ModuleResult[T]: Result with status, timing, data and errors.
        '''
        name = collector.name
        started = utcnow()
        t0 = perf_counter()
        cls.log.info("running %s", name)
        try:
            data, errors = await collector.collect()
            if data is None:
                status = ModuleStatus.FAILED if errors else ModuleStatus.SKIPPED
            else:
                status = ModuleStatus.PARTIAL if errors else ModuleStatus.SUCCESS
        except Exception as exc:  # noqa: BLE001 - isolation boundary
            cls.log.warning("%s module failed: %s", name, exc, exc_info=cls.log.isEnabledFor(logging.DEBUG))
            data = None
            errors = [CollectionError(module=name, error_type=type(exc).__name__, message=str(exc))]
            status = ModuleStatus.FAILED
        duration = round((perf_counter() - t0) * 1000, 2)
        cls.log.info("%s finished: %s in %.0f ms (%d errors)", name, status, duration, len(errors))
        return ModuleResult(module=name, status=status, started_at=started, finished_at=utcnow(),
                            duration_ms=duration, data=data, errors=errors)

    @staticmethod
    async def _skipped(name: str, note: str) -> ModuleResult[Any]:
        '''
        Return a SKIPPED result (awaitable so it can be gathered with real modules).
        Parameters:
            name (str): Module name.
            note (str): Why it was skipped.
        Returns:
            ModuleResult[Any]: The skipped result.
        '''
        return ModuleResult.skipped(name, note)


class ScanHistory:
    '''
    Attaches the comparison with the previous stored scan and stores the new one.
    '''

    def __init__(self, store: ScanStore) -> None:
        '''
        Create the history helper.
        Parameters:
            store (ScanStore): Where scans are kept.
        '''
        self.store = store

    def record(self, report: ReconReport) -> str:
        '''
        Compare with the latest stored scan of the same target (if any), then save this scan.

        With no previous scan the report is saved as-is (first run); with one, its observation comparison,
        interpreted change findings and finding delta (new/persisting/resolved) are attached in place.
        Parameters:
            report (ReconReport): The new report; its comparison/finding_changes are set in place.
        Returns:
            str: Where the scan was stored.
        Raises:
            OSError: If the scan cannot be written.
        '''
        try:
            previous = self.store.latest(report.target.hostname, exclude=report.scan_id)
        except (KeyError, ValueError) as exc:
            ScanOrchestrator.log.warning("previous scan unreadable, skipping comparison: %s", exc)
            previous = None
        if previous is not None:
            report.comparison = ScanComparator.compare(previous, report)
            changes = ChangeAnalyzer.analyze(report.comparison, report.finished_at)
            if changes:  # merge named regressions into the findings before computing the delta
                report.analysis.findings = sorted([*report.analysis.findings, *changes],
                                                  key=lambda f: (-f.severity.rank, f.category, f.id))
                counts = Counter(f.severity.value for f in report.analysis.findings)
                report.analysis.severity_counts = {s.value: counts.get(s.value, 0) for s in Severity}
            report.finding_changes = RegressionAnalyzer.analyze(previous, report)
        return self.store.save(report)
