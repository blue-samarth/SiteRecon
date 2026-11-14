from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, ValidationError

if TYPE_CHECKING: from recon.models import ReconReport


class Inventory(BaseModel):
    '''
    What the passive scan discovered, in a form the active step can read back.
    '''
    hostname: str
    scan_id: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    sitemap_urls: list[str] = Field(default_factory=list)
    pages: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)

    def url_keys(self) -> set[str]: return {_key(u) for u in (*self.pages, *self.sitemap_urls, *self.endpoints)}
    def known_hosts(self) -> set[str]: return {h.lower().rstrip(".") for h in self.hosts if h}

    def summary(self) -> str:
        '''
        A one-line count summary for terminal output.
        '''
        return (f"{len(self.pages)} pages, {len(self.sitemap_urls)} sitemap URLs, "
                f"{len(self.endpoints)} endpoints, {len(self.hosts)} hosts")


def _key(url: str) -> str: parts = urlsplit(url); return f"{(parts.hostname or '').lower()}{parts.path.rstrip('/') or '/'}"

def build_inventory(report: ReconReport) -> Inventory:
    '''
    Extract the inventory from a passive ReconReport.
    Parameters:
        report (ReconReport): The completed passive scan.
    Returns:
        Inventory: Discovered sitemap URLs, pages, endpoints and hosts, deduplicated in discovery order.
    '''
    pages: list[str] = []
    endpoints: list[str] = []
    hosts: list[str] = [report.target.hostname]
    sitemap_urls: list[str] = []

    if report.crawler.data:
        for page in report.crawler.data.pages:
            pages.append(page.final_url or page.url)
        pages.extend(d.url for d in report.crawler.data.discovered)
    if report.resources.data:
        sitemap_urls.extend(report.resources.data.sitemap_urls())
    if report.javascript.data:
        endpoints.extend(e.value for e in report.javascript.data.endpoints())
        hosts.extend(report.javascript.data.service_hosts)
    if report.subdomains.data:
        hosts.extend(h.hostname for h in report.subdomains.data.hostnames)
    if report.third_party.data:
        hosts.extend(d for s in report.third_party.data.services for d in s.domains)

    return Inventory(
        hostname=report.target.hostname, scan_id=report.scan_id,
        sitemap_urls=list(dict.fromkeys(sitemap_urls)), pages=list(dict.fromkeys(pages)),
        endpoints=list(dict.fromkeys(endpoints)), hosts=list(dict.fromkeys(hosts)))


def write_inventory(inventory: Inventory, directory: Path) -> Path:
    '''
    Write the inventory to <directory>/inventory.json, creating the directory if needed.
    Parameters:
        inventory (Inventory): The inventory to persist.
        directory (Path): Directory to write into.
    Returns:
        Path: The path written.
    Raises:
        OSError: If the file cannot be written.
    '''
    directory.mkdir(parents=True, exist_ok=True)
    path: Path = directory / "inventory.json"
    path.write_text(inventory.model_dump_json(indent=2), encoding="utf-8")
    return path


def read_inventory(directory: Path) -> Inventory | None:
    '''
    Read <directory>/inventory.json if present and valid.
    Parameters:
        directory (Path): Directory holding inventory.json.
    Returns:
        Inventory | None: The inventory, or None if missing or unreadable.
    '''
    path: Path = directory / "inventory.json"
    if not path.is_file(): return None

    try:
        return Inventory.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError, ValueError): return None
