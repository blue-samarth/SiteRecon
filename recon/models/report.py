'''
Top-level report schema and analysis output models.
'''

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, model_validator

from recon.models.common import CollectionError, Confidence, FindingState, ModuleResult, Severity  # noqa: F401
from recon.models.assets import AssetData
from recon.models.cookies import CookieData
from recon.models.crawl import CrawlData
from recon.models.dns import DnsData
from recon.models.dnssec import DnssecData
from recon.models.html import HtmlData
from recon.models.http import HttpData
from recon.models.network import NetworkData
from recon.models.observations import ComparisonResult, Observation
from recon.models.resources import ResourcesData
from recon.models.subdomains import SubdomainData
from recon.models.technology import TechnologyData
from recon.models.third_party import ThirdPartyData
from recon.models.tls import TlsData
from recon.models.whois import DomainRegistration

# 2.1 adds optional provenance/freshness fields to observations and a lifecycle `state` to findings; all
# are additive with safe defaults, so reports written by 2.0 still load.
SCHEMA_VERSION: str = "2.1"


class Finding(BaseModel):
    '''
    An interpreted, evidence-backed observation.

    ``state`` is the finding's lifecycle position (orthogonal to ``severity`` and ``confidence``). When a
    producer does not set it, it is derived from ``confidence`` on construction: low confidence starts
    SUSPECTED, otherwise CONFIRMED. CORROBORATED/RESOLVED/FALSE_POSITIVE are assigned only by the analysis
    engine from cross-source correlation or history. Reports written before 2.1 have no ``state`` and get
    the same derivation when loaded.
    '''
    id: str
    category: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    state: FindingState | None = None    # derived from confidence when unset (see _derive_state)
    evidence: list[str] = Field(default_factory=list)
    source: str
    subject: str
    timestamp: datetime
    recommendation: str | None = None
    limitations: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)   # Observation ids supporting this finding

    @model_validator(mode="after")
    def _derive_state(self) -> Finding:
        '''
        Fill a missing lifecycle state from the finding's confidence, so every finding has one.
        Returns:
            Finding: This finding, with ``state`` set.
        '''
        if self.state is None:
            self.state = FindingState.from_confidence(self.confidence)
        return self


class InfrastructureObservation(BaseModel):
    '''
    An inferred provider relationship (CDN, DNS, email, edge, allocation).
    '''
    provider: str
    category: str      # cdn, cloud, hosting, dns, email
    role: str          # ip_allocation, authoritative_dns, mail_exchange, http_edge
    subjects: list[str]
    evidence: list[str]
    source: str
    confidence: Confidence
    note: str | None = None


class AnalysisResult(BaseModel):
    '''
    Output of the analysis engine.
    '''
    findings: list[Finding] = Field(default_factory=list)
    infrastructure: list[InfrastructureObservation] = Field(default_factory=list)
    severity_counts: dict[str, int] = Field(default_factory=dict)


class ToolInfo(BaseModel):
    '''
    Tool identity recorded in the report.
    '''
    name: str
    version: str
    user_agent: str


class TargetInfo(BaseModel):
    '''
    The requested target and its authorized scope.
    '''
    input: str
    hostname: str
    scope: list[str]


def _skipped(module: str) -> Any:
    '''
    Default factory for module results that were not part of the scan.
    Parameters:
        module (str): Module name.
    Returns:
        Any: A zero-argument factory producing a SKIPPED ModuleResult.
    '''
    return lambda: ModuleResult.skipped(module, "not run")


class ReconReport(BaseModel):
    '''
    Top-level report: every module result, observations, analysis, errors and limitations.
    '''
    schema_version: str = SCHEMA_VERSION
    scan_id: str = ""
    tool: ToolInfo
    target: TargetInfo
    options: dict[str, Any]
    started_at: datetime
    finished_at: datetime
    duration_ms: float
    dns: ModuleResult[DnsData]
    network: ModuleResult[NetworkData]
    http: ModuleResult[HttpData]
    tls: ModuleResult[TlsData]
    whois: ModuleResult[DomainRegistration]
    html: ModuleResult[HtmlData]
    technology: ModuleResult[TechnologyData]
    subdomains: ModuleResult[SubdomainData]
    third_party: ModuleResult[ThirdPartyData]
    dnssec: ModuleResult[DnssecData] = Field(default_factory=_skipped("dnssec"))
    resources: ModuleResult[ResourcesData] = Field(default_factory=_skipped("resources"))
    crawler: ModuleResult[CrawlData] = Field(default_factory=_skipped("crawler"))
    cookies: ModuleResult[CookieData] = Field(default_factory=_skipped("cookies"))
    javascript: ModuleResult[AssetData] = Field(default_factory=_skipped("javascript"))
    observations: list[Observation] = Field(default_factory=list)
    analysis: AnalysisResult
    comparison: ComparisonResult | None = None    # changes since the previous stored scan, if any
    errors: list[CollectionError] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    def module_results(self) -> dict[str, ModuleResult]:
        '''
        Return all module results keyed by module name.
        Returns:
            dict[str, ModuleResult]: Module name to result, in pipeline order.
        '''
        return {
            "dns": self.dns, "dnssec": self.dnssec, "network": self.network, "http": self.http,
            "tls": self.tls, "whois": self.whois, "resources": self.resources, "crawler": self.crawler,
            "html": self.html, "javascript": self.javascript, "technology": self.technology, "cookies": self.cookies,
            "subdomains": self.subdomains, "third_party": self.third_party,
        }
