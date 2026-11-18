'''
Known-vulnerability models: advisories affecting the specific component versions the scan inventoried.

The static asset analysis already identifies JavaScript libraries and their versions (e.g. jQuery 3.7.1).
This turns that inventory into findings by matching each versioned component against a vulnerability
database (OSV). Only the package name and version are ever sent to the database — never anything about the
target — and the data is third-party, so observations built from it carry external provenance.
'''

from __future__ import annotations

from pydantic import BaseModel, Field


class VulnMatch(BaseModel):
    '''
    One advisory affecting a component version.
    '''
    id: str                              # OSV / GHSA identifier
    aliases: list[str] = Field(default_factory=list)   # CVE ids and other aliases
    summary: str | None = None
    severity: str = "medium"             # mapped to the project's Severity values
    cvss: float | None = None            # CVSS base score when the advisory provides a numeric one
    reference: str | None = None         # a canonical advisory URL, if any


class VulnerableComponent(BaseModel):
    '''
    A detected component version with the advisories that affect it.
    '''
    name: str                            # as detected (e.g. "jQuery")
    package: str                         # package name queried (e.g. "jquery")
    ecosystem: str                       # OSV ecosystem (e.g. "npm")
    version: str
    source_asset: str | None = None      # asset the component was detected in
    vulns: list[VulnMatch] = Field(default_factory=list)


class VulnerabilityData(BaseModel):
    '''
    Result of checking the inventoried component versions against the vulnerability database.
    '''
    ecosystem: str = "npm"
    provider: str = "OSV (osv.dev)"
    components_checked: int = 0
    vulnerable: list[VulnerableComponent] = Field(default_factory=list)
    note: str = ("Each inventoried component version was looked up in the OSV database; only the package name "
                 "and version were disclosed to the provider. Matches reflect published advisories for the "
                 "version in use, not confirmation that the vulnerable code path is reachable.")
