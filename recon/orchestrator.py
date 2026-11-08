'''
Coordinates collection → observations → analysis. Never generates presentation output itself.

Sequence:
  1. DNS
  2. network, HTTP, TLS, DNSSEC, registration, CT subdomains   (concurrent, bounded)
  3. HTML → public resources → crawler → JS/CSS assets         (crawler seeded with sitemap URLs)
  4. technology, cookies, third-party                          (derived from collected data)
  5. observations → analysis engine
'''

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import timedelta
from time import perf_counter
from typing import Any, ClassVar, TypeVar
from urllib.parse import urlsplit

from recon import TOOL_NAME, __version__
from recon.analysis import AnalysisEngine, ObservationBuilder, ScanComparator
from recon.config import ALL_MODULES, Config
from recon.models import (
    AnalysisResult,
    CollectionError,
    HttpData,
    ModuleResult,
    ModuleStatus,
    ReconReport,
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
    HtmlCollector,
    HttpCollector,
    NetworkCollector,
    ResourcesCollector,
    SubdomainCollector,
    TechnologyCollector,
    ThirdPartyCollector,
    TlsCollector,
    WhoisCollector,
)
from recon.storage import ScanStore
from recon.utils import DnsClient, SafeHttpClient, Scope, get_logger

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

        async with self.target_client, self.rdap_client, self.ct_client, asset_client, map_client:
            dns_result = await self._maybe("dns", lambda: DnsCollector(host, self.dns_client, cfg.dkim_selectors))
            ips = dns_result.data.addresses() if dns_result.data else []

            def tls_probe(hostname: str):
                return TlsCollector(hostname, timeout=cfg.timeout, retries=cfg.retries,
                                    allow_private_networks=cfg.allow_private_networks, **self.tls_kwargs).probe(hostname)

            (network_result, http_result, tls_result, whois_result, subdomains_result,
             dnssec_result) = await asyncio.gather(
                self._maybe("network", lambda: NetworkCollector(ips, self.dns_client, self.rdap_client),
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
                    cache=CtCache(cfg.cache_dir, timedelta(hours=cfg.ct_cache_ttl_hours)))),
                self._maybe("dnssec", lambda: DnssecCollector(host, self.dnssec_client, timeout=cfg.timeout,
                                                              retries=cfg.retries)),
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
                max_total_bytes=cfg.max_assets_total_bytes),
                None if (html_result.data or crawler_result.data) else "requires HTML or crawl results")

        crawl = crawler_result.data
        assets = assets_result.data
        technology_result = await self._maybe("technology", lambda: TechnologyCollector(
            http, html_result.data, crawl=crawl, dns=dns_result.data, assets=assets))
        cookies_result = await self._maybe("cookies", lambda: CookieCollector(http, crawl),
                                           None if (http or crawl) else "requires HTTP or crawl results")
        third_party_result = await self._maybe("third_party", lambda: ThirdPartyCollector(
            host, dns=dns_result.data, http=http, html=html_result.data, tls=tls_result.data, crawl=crawl,
            assets=assets))

        report = ReconReport(
            scan_id=ScanStore.new_scan_id(started),
            tool=ToolInfo(name=TOOL_NAME, version=__version__, user_agent=cfg.user_agent),
            target=TargetInfo(input=cfg.target_input, hostname=host, scope=self.scope.describe()),
            options=self.options(),
            started_at=started, finished_at=started, duration_ms=0,
            dns=dns_result, network=network_result, http=http_result, tls=tls_result, whois=whois_result,
            html=html_result, technology=technology_result, subdomains=subdomains_result,
            third_party=third_party_result, dnssec=dnssec_result, resources=resources_result,
            crawler=crawler_result, cookies=cookies_result, javascript=assets_result,
            analysis=AnalysisResult(),
            limitations=list(self.LIMITATIONS),
        )
        report.observations = ObservationBuilder(host, report.module_results()).build()
        report.analysis = AnalysisEngine(utcnow()).analyze(
            dns=dns_result.data, network=network_result.data, http=http, tls=tls_result.data,
            whois=whois_result.data, html=html_result.data, subdomains=subdomains_result.data,
            dnssec=dnssec_result.data, resources=resources_result.data, crawl=crawl,
            cookies=cookies_result.data, assets=assets, observations=report.observations,
        )
        report.errors = [e for m in report.module_results().values() for e in m.errors]
        report.finished_at = utcnow()
        report.duration_ms = round((perf_counter() - t0) * 1000, 2)
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
                "format": c.output_format.value, "allow_private_networks": c.allow_private_networks}

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
        Parameters:
            report (ReconReport): The new report; its comparison field is set in place.
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
        return self.store.save(report)
