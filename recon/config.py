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
    "technology", "cookies", "subdomains", "third_party",
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
    max_subdomains: int = 100           # cap on verification of CT names
    ct_cache_ttl_hours: float = 24.0    # reuse CT results this fresh when providers fail
    # registration
    whois: bool = True
    # crawling
    crawl: bool = False
    crawl_depth: int = 1
    max_pages: int = 25
    crawl_delay: float = 0.25           # seconds between crawl requests (robots Crawl-delay may raise it)
    respect_robots: bool = True
    # frontend assets (static analysis; never executed)
    max_assets: int = 30
    max_asset_bytes: int = 2 * 1024 * 1024
    max_source_map_bytes: int = 8 * 1024 * 1024   # large enough to list a map's 'sources' array
    max_assets_total_bytes: int = 20 * 1024 * 1024
    asset_hosts: tuple[str, ...] = ()   # external hosts explicitly permitted for asset downloads
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
        flags = {"subdomains": self.subdomains, "whois": self.whois, "crawler": self.crawl}
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
