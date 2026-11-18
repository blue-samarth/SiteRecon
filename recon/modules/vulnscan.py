'''
Known-vulnerability scanning: match inventoried component versions against the OSV database (osv.dev).

The static asset analysis identifies JavaScript libraries and their versions; this turns that inventory
into findings. Only versioned components are queryable (OSV matches by version), and only the package name
and version are disclosed to the provider — never anything about the target. It is opt-in (``--check-vulns``).
'''

from __future__ import annotations

import json
from typing import ClassVar

import httpx

from recon.models import AssetData, CollectionError, VulnerabilityData, VulnerableComponent, VulnMatch
from recon.modules.base import Collector
from recon.utils import BlockedRequestError, SafeHttpClient

# Detected display name → npm package name, where they differ. Unknown names fall back to a lowercased slug.
_NPM_ALIASES: dict[str, str] = {
    "jquery": "jquery", "vue.js": "vue", "moment.js": "moment", "gsap": "gsap", "chart.js": "chart.js",
    "bootstrap": "bootstrap", "tailwind css": "tailwindcss", "font awesome": "@fortawesome/fontawesome-free",
    "react": "react", "angular": "@angular/core", "lodash": "lodash", "axios": "axios", "three.js": "three",
    "core-js": "core-js", "next.js": "next", "nuxt": "nuxt", "svelte": "svelte", "framer motion": "framer-motion",
    "redux toolkit": "@reduxjs/toolkit", "react router": "react-router", "socket.io": "socket.io-client",
}
# GHSA/OSV database_specific severity labels → the project's Severity values.
_LABEL_SEVERITY: dict[str, str] = {"critical": "critical", "high": "high", "moderate": "medium",
                                   "medium": "medium", "low": "low"}


def npm_name(display: str) -> str:
    '''
    Map a detected library display name to its npm package name.
    Parameters:
        display (str): Detected name, e.g. "Vue.js".
    Returns:
        str: npm package name, e.g. "vue".
    '''
    key = display.lower().strip()
    if key in _NPM_ALIASES:
        return _NPM_ALIASES[key]
    return key.replace(" ", "-").removesuffix(".js")


def severity_from_osv(vuln: dict) -> tuple[str, float | None]:
    '''
    Derive a severity label and (when available) a CVSS base score from an OSV vulnerability record.
    Parameters:
        vuln (dict): An OSV vulnerability record.
    Returns:
        tuple[str, float | None]: (severity value, CVSS base score or None).
    '''
    label = str((vuln.get("database_specific") or {}).get("severity") or "").lower()
    if label in _LABEL_SEVERITY:
        return _LABEL_SEVERITY[label], None
    for entry in vuln.get("severity") or []:
        score = str(entry.get("score") or "")
        try:
            value = float(score)   # some records give a numeric base score directly
        except ValueError:
            continue
        if value >= 9.0:
            return "critical", value
        if value >= 7.0:
            return "high", value
        if value >= 4.0:
            return "medium", value
        return "low", value
    return "medium", None   # advisory exists but no machine-readable severity → treat as medium


class VulnerabilityScanner(Collector[VulnerabilityData]):
    '''
    Looks up each inventoried, versioned JavaScript component in OSV and records matching advisories.
    '''

    name: ClassVar[str] = "vulnscan"
    ECOSYSTEM: ClassVar[str] = "npm"
    BATCH_URL: ClassVar[str] = "https://api.osv.dev/v1/querybatch"
    VULN_URL: ClassVar[str] = "https://api.osv.dev/v1/vulns/"
    MAX_COMPONENTS: ClassVar[int] = 50
    MAX_DETAILS: ClassVar[int] = 40

    def __init__(self, assets: AssetData | None, client: SafeHttpClient, *,
                 max_components: int = MAX_COMPONENTS, max_details: int = MAX_DETAILS) -> None:
        '''
        Create the scanner.
        Parameters:
            assets (AssetData | None): Static asset analysis carrying the detected libraries.
            client (SafeHttpClient): Client scoped to api.osv.dev.
            max_components (int): Cap on distinct components queried.
            max_details (int): Cap on advisory-detail fetches.
        '''
        self.client = client
        self.max_components = max_components
        self.max_details = max_details
        self.components = self._inventory(assets)[:max_components]

    @staticmethod
    def _inventory(assets: AssetData | None) -> list[VulnerableComponent]:
        '''
        Distinct versioned components from the asset analysis, as query stubs (no vulns yet).
        Parameters:
            assets (AssetData | None): Static asset analysis.
        Returns:
            list[VulnerableComponent]: One stub per distinct (package, version).
        '''
        out: dict[tuple[str, str], VulnerableComponent] = {}
        for asset in (assets.assets if assets else []):
            for lib in asset.libraries:
                if not lib.version:
                    continue   # OSV matches by version; unversioned detections are not queryable
                pkg = npm_name(lib.name)
                key = (pkg, lib.version)
                if key not in out:
                    out[key] = VulnerableComponent(name=lib.name, package=pkg, ecosystem="npm",
                                                   version=lib.version, source_asset=asset.url)
        return list(out.values())

    async def collect(self) -> tuple[VulnerabilityData | None, list[CollectionError]]:
        '''
        Batch-query OSV for the inventoried components, then fetch advisory details for the matches.
        Returns:
            tuple[VulnerabilityData | None, list[CollectionError]]: Vulnerable components and any errors.
        '''
        data = VulnerabilityData(ecosystem=self.ECOSYSTEM, components_checked=len(self.components))
        if not self.components:
            return data, []
        errors: list[CollectionError] = []
        try:
            ids_per_component = await self._query_batch()
        except (BlockedRequestError, httpx.HTTPError, OSError, ValueError) as exc:
            return data, [self.error("api.osv.dev", "osv_query_failed", f"{type(exc).__name__}: {exc}")]

        detail_cache: dict[str, VulnMatch] = {}
        fetched = 0
        for component, ids in zip(self.components, ids_per_component):
            if not ids:
                continue
            for vid in ids:
                if vid not in detail_cache:
                    if fetched >= self.max_details:
                        detail_cache[vid] = VulnMatch(id=vid)   # over the detail budget: record the id only
                    else:
                        fetched += 1
                        detail_cache[vid] = await self._fetch_detail(vid, errors)
                component.vulns.append(detail_cache[vid])
            if component.vulns:
                data.vulnerable.append(component)
        return data, errors

    async def _query_batch(self) -> list[list[str]]:
        '''
        POST the component list to the OSV batch endpoint and return advisory ids aligned to self.components.
        Returns:
            list[list[str]]: For each component (in order), its matching advisory ids.
        Raises:
            httpx.HTTPError | OSError | ValueError | BlockedRequestError: On transport or parse failure.
        '''
        queries = [{"version": c.version, "package": {"name": c.package, "ecosystem": c.ecosystem}}
                   for c in self.components]
        body = json.dumps({"queries": queries}).encode("utf-8")
        resp = await self.client.request("POST", self.BATCH_URL, content=body,
                                         headers={"content-type": "application/json"})
        results = json.loads(resp.body).get("results", [])
        out: list[list[str]] = []
        for i in range(len(self.components)):
            result = results[i] if i < len(results) else {}
            out.append([v["id"] for v in (result.get("vulns") or []) if v.get("id")])
        return out

    async def _fetch_detail(self, vid: str, errors: list[CollectionError]) -> VulnMatch:
        '''
        Fetch one advisory's details (summary, aliases, severity); fall back to the id alone on failure.
        Parameters:
            vid (str): Advisory id.
            errors (list[CollectionError]): Error accumulator.
        Returns:
            VulnMatch: The advisory, with whatever detail could be retrieved.
        '''
        try:
            resp = await self.client.get(self.VULN_URL + vid)
            vuln = json.loads(resp.body)
        except (BlockedRequestError, httpx.HTTPError, OSError, ValueError) as exc:
            errors.append(self.error(vid, "osv_detail_failed", f"{type(exc).__name__}: {exc}"))
            return VulnMatch(id=vid)
        sev, cvss = severity_from_osv(vuln)
        refs = [r.get("url") for r in (vuln.get("references") or []) if r.get("url")]
        advisory = next((r for r in refs if "advisor" in (r or "").lower() or "GHSA" in (r or "")), None)
        return VulnMatch(id=vid, aliases=[a for a in (vuln.get("aliases") or []) if a],
                         summary=(vuln.get("summary") or vuln.get("details") or None),
                         severity=sev, cvss=cvss, reference=advisory or (refs[0] if refs else None))
