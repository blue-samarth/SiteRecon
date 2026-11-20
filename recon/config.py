'''
Runtime configuration shared by every layer.
'''

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from recon import TOOL_NAME, __version__

DEFAULT_USER_AGENT: str = (
    f"{TOOL_NAME}/{__version__} (passive reconnaissance tool; authorized assessments only)"
)

# Every selectable module, in pipeline order.
ALL_MODULES: tuple[str, ...] = (
    "dns", "dnssec", "network", "http", "tls", "whois", "resources", "crawler", "html", "javascript",
    "technology", "cookies", "subdomains", "third_party", "render", "vulnscan", "historical", "seo",
)

# Common public DKIM selectors (providers and defaults). DKIM selectors cannot be
# enumerated, so absence across this list never proves DKIM is unconfigured.
DEFAULT_DKIM_SELECTORS: tuple[str, ...] = (
    "default", "dkim", "dkim1", "mail", "email", "smtp", "mx", "key1", "key2", "sig1",
    "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2", "s1024", "s2048",
    "mandrill", "mailjet", "mg", "smtpapi", "amazonses", "ses", "zoho", "zmail",
    "protonmail", "protonmail2", "protonmail3", "fm1", "fm2", "fm3", "hs1", "hs2",
    "cm", "pm", "everlytickey1", "mxvault", "turbo-smtp", "sendinblue", "brevo",
)


class OutputFormat(StrEnum):
    '''
    Report formats selectable with --format.
    '''
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    BOTH = "both"  # json + markdown
    ALL = "all"    # json + markdown + html


@dataclass(frozen=True, slots=True)
class Config:
    '''
    Immutable runtime configuration shared by every layer.
    '''
    target_input: str
    hostname: str
    output_dir: Path = Path("reports")
    output_format: OutputFormat = OutputFormat.ALL
    timeout: float = 10.0
    retries: int = 2
    verbose: bool = False
    allow_private_networks: bool = False
    modules: frozenset[str] = frozenset(ALL_MODULES)
    # subdomains
    subdomains: bool = True
    probe_subdomains: bool = False      # HTTPS + TLS availability check of discovered names
    max_subdomains: int = 100           # cap on verification of discovered names
    ct_cache_ttl_hours: float = 24.0    # reuse CT/passive results this fresh when a source fails
    # Non-CT passive discovery sources (OTX, urlscan, Common Crawl, Wayback, RapidDNS, HackerTarget,
    # Anubis, BufferOver). Empty means Certificate Transparency only: each extra source discloses the
    # target domain to another third party, so enabling them is the operator's explicit choice.
    subdomain_sources: tuple[str, ...] = ()
    # Controlled permutation: generate candidate names from the labels already discovered and keep only
    # those that resolve in DNS. Opt-in and hard-capped; see SubdomainPermuter for why it stays small.
    permute_subdomains: bool = False
    max_permutations: int = 200
    # historical URLs (web archives and URL indexes; discloses the target domain to those providers)
    historical: bool = False
    historical_sources: tuple[str, ...] = ()   # empty = every known source when the module is enabled
    max_historical_urls: int = 1000            # per-source cap on URLs requested
    # on-page SEO audit (derived from pages already fetched; sends no requests of its own, but a
    # site-wide audit needs more than one page, so --seo turns the crawler on unless told otherwise)
    seo: bool = False
    # registration
    whois: bool = True
    # crawling
    crawl: bool = False
    crawl_depth: int = 1
    max_pages: int = 25
    crawl_delay: float = 0.25           # seconds between crawl requests (robots Crawl-delay may raise it)
    respect_robots: bool = True
    # dynamic rendering (opt-in; executes the page's JavaScript in a headless browser)
    render: bool = False
    render_timeout: float = 30.0        # per-navigation / load-state timeout in seconds
    render_max_pages: int = 10          # how many in-scope pages (origin + crawled routes) to render
    check_vulns: bool = False           # look up detected component versions in OSV (discloses package@version)
    # frontend assets (static analysis; never executed)
    retain_client_keys: bool = False    # keep public client keys (e.g. Supabase anon key) unredacted; see --bypass-sec
    max_assets: int = 30
    max_asset_bytes: int = 2 * 1024 * 1024
    max_source_map_bytes: int = 8 * 1024 * 1024   # large enough to list a map's 'sources' array
    max_assets_total_bytes: int = 20 * 1024 * 1024
    asset_hosts: tuple[str, ...] = ()   # external hosts explicitly permitted for asset downloads
    # hosting location (optional offline geolocation DB; None = ASN/RDAP country estimate only)
    geoip_db: Path | None = None
    # history
    history: bool = True
    # limits
    concurrency: int = 10
    max_response_bytes: int = 5 * 1024 * 1024
    max_redirects: int = 10
    user_agent: str = DEFAULT_USER_AGENT
    dkim_selectors: tuple[str, ...] = field(default=DEFAULT_DKIM_SELECTORS)

    def enabled(self, module: str) -> bool:
        '''
        Whether a module is selected (and not disabled by its own flag).
        Parameters:
            module (str): Module name from ALL_MODULES.
        Returns:
            bool: True if the module should run.
        '''
        flags = {"subdomains": self.subdomains, "whois": self.whois, "crawler": self.crawl,
                 "render": self.render, "vulnscan": self.check_vulns, "historical": self.historical,
                 "seo": self.seo}
        return module in self.modules and flags.get(module, True)

    @property
    def cache_dir(self) -> Path:
        '''
        Directory for cached provider results (e.g. Certificate Transparency).
        Returns:
            Path: <output_dir>/.cache
        '''
        return self.output_dir / ".cache"

    @property
    def wants_json(self) -> bool:
        '''
        Whether a JSON report should be written.
        Returns:
            bool: True for json, both or all.
        '''
        return self.output_format in (OutputFormat.JSON, OutputFormat.BOTH, OutputFormat.ALL)

    @property
    def wants_markdown(self) -> bool:
        '''
        Whether a Markdown report should be written.
        Returns:
            bool: True for markdown, both or all.
        '''
        return self.output_format in (OutputFormat.MARKDOWN, OutputFormat.BOTH, OutputFormat.ALL)

    @property
    def wants_html(self) -> bool:
        '''
        Whether an HTML report should be written.
        Returns:
            bool: True for html or all.
        '''
        return self.output_format in (OutputFormat.HTML, OutputFormat.ALL)
