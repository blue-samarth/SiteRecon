'''
Keyless external-intelligence providers.

Both run with no account and no API key:
  * Wayback Machine (Internet Archive) — historical snapshots and archived URLs for the domain.
  * Shodan InternetDB — open ports, CVE candidates, CPEs and hostnames indexed for an IP.

Each discloses the target (its domain or IPs) to the provider, so external intelligence is opt-in. Results
are clearly marked as historical/indexed estimates, never as the target's current state.
'''

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any, ClassVar
from urllib.parse import quote, urlsplit

from recon.intel.base import IntelContext, IntelligenceProvider, IntelResult
from recon.models import Confidence, Freshness, Severity

S, C = Severity, Confidence

# Archived paths worth a second look if they were ever public (historical exposure, not current proof).
_SENSITIVE_PATH: re.Pattern[str] = re.compile(
    r"(\.(?:sql|bak|old|swp|zip|tar|gz|tgz|rar|7z|env|log|pem|key|p12|pfx|ini|conf|config|yml|yaml|json|bson|dump)"
    r"(?:$|[?#])|/(?:\.git|\.env|\.svn|backup|backups|dump|db|database|wp-config|config\.php|phpinfo|"
    r"id_rsa|credentials|secret)\b)", re.I)


class WaybackProvider(IntelligenceProvider):
    '''
    Internet Archive Wayback Machine: how long the domain has been archived and which historical URLs
    (especially sensitive-looking ones) the archive holds. Keyless.
    '''

    name: ClassVar[str] = "wayback"
    label: ClassVar[str] = "Wayback Machine"
    hosts: ClassVar[tuple[str, ...]] = ("web.archive.org", "archive.org")

    async def collect(self, ctx: IntelContext) -> IntelResult:
        '''
        Query the CDX API for the domain's archived URLs and summarize them.
        Parameters:
            ctx (IntelContext): The run context.
        Returns:
            IntelResult: History observation/finding, plus a sensitive-path finding if any are archived.
        '''
        result = IntelResult()
        url = (f"https://web.archive.org/cdx/search/cdx?url={quote(ctx.host)}&matchType=domain"
               f"&output=json&collapse=urlkey&fl=original,timestamp,statuscode&limit={ctx.max_items * 20}")
        outcome = await ctx.fetch(url)
        if outcome.final is None or outcome.final.status_code != 200:
            detail = outcome.error or (f"HTTP {outcome.final.status_code}" if outcome.final else "no response")
            result.errors.append(self.error(ctx.host, outcome.error_type or "request_failed", detail))
            return result
        rows = self._rows(outcome.final.body)
        if not rows:
            return result   # domain not archived — nothing to report, no finding

        originals = [r[0] for r in rows if r]
        stamps = sorted(r[1] for r in rows if len(r) > 1 and r[1].isdigit())
        first, last = self._fmt(stamps[0]) if stamps else None, self._fmt(stamps[-1]) if stamps else None
        last_dt = self._parse(stamps[-1]) if stamps else None
        history_obs = self.observation(
            ctx, "intel.wayback.history", ctx.host, "summary",
            {"snapshots": len(rows), "first": first, "last": last},
            freshness=Freshness.HISTORICAL, observed_at=last_dt,
            limitations=["Archived snapshots are historical and may no longer be accessible on the live site."])
        result.observations.append(history_obs)
        result.findings.append(self.finding(
            ctx, "intel.archived_history", ctx.host, category="intel", title="Site has Wayback Machine history",
            description=("The Internet Archive holds archived snapshots of this domain. Historical pages can "
                         "reveal old endpoints, stack details or content no longer linked; this is evidence of "
                         "the past, not of what is currently reachable."),
            severity=S.INFORMATIONAL, confidence=C.HIGH,
            evidence=[f"{len(rows)} archived URL(s) (capped)", f"earliest: {first}", f"latest: {last}"],
            evidence_refs=[history_obs.id]))

        sensitive = [u for u in originals if _SENSITIVE_PATH.search(urlsplit(u).path or u)]
        sensitive = list(dict.fromkeys(sensitive))[:15]
        if sensitive:
            result.findings.append(self.finding(
                ctx, "intel.archived_sensitive_path", ctx.host, category="intel",
                title="Sensitive-looking paths exist in the web archive",
                description=("The archive holds URLs whose names suggest backups, dumps, config or secret files "
                             "that were once publicly fetchable. This is historical evidence — confirm whether "
                             "each is still reachable, and rotate any credential that may have been exposed."),
                severity=S.LOW, confidence=C.MEDIUM, evidence=sensitive, evidence_refs=[history_obs.id]))
        return result

    @staticmethod
    def _rows(body: bytes) -> list[list[str]]:
        '''
        Parse the CDX JSON array, dropping the header row.
        Parameters:
            body (bytes): Response body.
        Returns:
            list[list[str]]: Data rows (each [original, timestamp, statuscode]).
        '''
        try:
            data = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            return []
        if not isinstance(data, list) or len(data) < 2:
            return []
        return [r for r in data[1:] if isinstance(r, list)]

    @staticmethod
    def _fmt(stamp: str) -> str:
        '''
        Format a CDX YYYYMMDDhhmmss timestamp as a readable date, or return it unchanged.
        Parameters:
            stamp (str): The 14-digit timestamp.
        Returns:
            str: ISO-ish date, or the original string.
        '''
        dt = WaybackProvider._parse(stamp)
        return dt.date().isoformat() if dt else stamp

    @staticmethod
    def _parse(stamp: str) -> datetime | None:
        '''
        Parse a CDX YYYYMMDDhhmmss timestamp into a datetime.
        Parameters:
            stamp (str): The 14-digit timestamp.
        Returns:
            datetime | None: Parsed datetime (UTC), or None.
        '''
        try:
            return datetime.strptime(stamp[:14], "%Y%m%d%H%M%S").replace(tzinfo=UTC)
        except (ValueError, TypeError):
            return None


class ShodanInternetDbProvider(IntelligenceProvider):
    '''
    Shodan's free, keyless InternetDB: the open ports, CVE candidates, CPEs and hostnames Shodan has
    indexed for each resolved IP.
    '''

    name: ClassVar[str] = "shodan_internetdb"
    label: ClassVar[str] = "Shodan InternetDB"
    hosts: ClassVar[tuple[str, ...]] = ("internetdb.shodan.io",)
    MAX_IPS: ClassVar[int] = 16

    def unavailable(self, ctx: IntelContext) -> str | None:
        '''
        Require at least one resolved public IP.
        Parameters:
            ctx (IntelContext): The run context.
        Returns:
            str | None: Skip reason, or None.
        '''
        return None if ctx.ips else "no resolved public IPs to query"

    async def collect(self, ctx: IntelContext) -> IntelResult:
        '''
        Look up each resolved public IP in InternetDB and record indexed exposure.
        Parameters:
            ctx (IntelContext): The run context.
        Returns:
            IntelResult: Exposure observations and findings (ports and CVE candidates) per IP.
        '''
        result = IntelResult()
        for ip in ctx.ips[: self.MAX_IPS]:
            outcome = await ctx.fetch(f"https://internetdb.shodan.io/{ip}")
            if outcome.final is None:
                result.errors.append(self.error(ip, outcome.error_type or "request_failed",
                                                 outcome.error or "no response"))
                continue
            if outcome.final.status_code == 404:
                continue   # no index entry for this IP — not an error
            if outcome.final.status_code != 200:
                result.errors.append(self.error(ip, "request_failed", f"HTTP {outcome.final.status_code}"))
                continue
            data = self._json(outcome.final.body)
            if data is None:
                result.errors.append(self.error(ip, "parse_error", "InternetDB body was not JSON"))
                continue
            self._record(ctx, ip, data, result)
        return result

    def _record(self, ctx: IntelContext, ip: str, data: dict[str, Any], result: IntelResult) -> None:
        '''
        Turn one InternetDB response into observations and findings.
        Parameters:
            ctx (IntelContext): The run context.
            ip (str): The IP looked up.
            data (dict[str, Any]): The InternetDB record.
            result (IntelResult): Accumulator for observations/findings.
        '''
        ports = sorted(data.get("ports") or [])
        vulns = sorted(data.get("vulns") or [])
        hostnames = sorted(data.get("hostnames") or [])
        cpes = sorted(data.get("cpes") or [])
        tags = sorted(data.get("tags") or [])
        if not any((ports, vulns, hostnames, cpes, tags)):
            return
        caveats = ["Shodan's index (refreshed roughly weekly); an indexed service does not prove current "
                   "exposure.",
                   "A shared IP may host unrelated domains, and indexed hostnames are not verified as the "
                   "target's."]
        obs = self.observation(
            ctx, "intel.shodan.exposure", ip, "indexed",
            {"ports": ports, "vulns": vulns, "hostnames": hostnames, "cpes": cpes, "tags": tags},
            confidence=C.MEDIUM, freshness=Freshness.UNKNOWN, limitations=caveats)
        result.observations.append(obs)
        if ports:
            result.findings.append(self.finding(
                ctx, "intel.exposed_ports", ip, category="intel", title=f"Indexed open ports on {ip}",
                description=("Shodan's InternetDB indexes these open ports for this IP. This is third-party "
                             "index data, not a live scan by SiteRecon — confirm current exposure, and note a "
                             "shared IP may serve unrelated hosts."),
                severity=S.INFORMATIONAL, confidence=C.MEDIUM,
                evidence=[f"ports: {ports}"] + ([f"hostnames: {hostnames[:5]}"] if hostnames else [])
                + ([f"tags: {tags}"] if tags else []), evidence_refs=[obs.id]))
        if vulns:
            result.findings.append(self.finding(
                ctx, "intel.indexed_vulnerability", ip, category="intel",
                title=f"Shodan associates {len(vulns)} CVE(s) with {ip}",
                description=("Shodan links these CVEs to software versions it detected on this IP. They are "
                             "candidates from version matching — frequently false positives, and possibly "
                             "stale — and must be verified against the actual deployed software, not treated "
                             "as confirmed vulnerabilities."),
                severity=S.LOW, confidence=C.LOW, evidence=[f"CVEs: {vulns[:20]}"] + (
                    [f"CPEs: {cpes[:5]}"] if cpes else []), evidence_refs=[obs.id]))

    @staticmethod
    def _json(body: bytes) -> dict[str, Any] | None:
        '''
        Parse a JSON object body, or None.
        Parameters:
            body (bytes): Response body.
        Returns:
            dict[str, Any] | None: The decoded object, or None.
        '''
        try:
            data = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            return None
        return data if isinstance(data, dict) else None


REGISTRY: dict[str, type[IntelligenceProvider]] = {
    WaybackProvider.name: WaybackProvider,
    ShodanInternetDbProvider.name: ShodanInternetDbProvider,
}

# Providers that run with no API key / no account (enabled by default when --intel is used).
KEYLESS: tuple[str, ...] = tuple(name for name, cls in REGISTRY.items() if not cls.requires_key)
