'''
Pydantic schemas shared by every layer (collection, analysis, reporting).

Import from this package rather than individual submodules, e.g.
``from recon.models import DnsData, ReconReport``. Submodules inside this package
import each other directly to avoid circular imports.
'''

from recon.models.assets import (
    AssetData,
    AssetRecord,
    ClientConfig,
    ClientConfigValue,
    EndpointRef,
    LibraryHit,
    SecretFinding,
    SkippedAsset,
)
from recon.models.common import (
    CollectionError,
    CollectionMethod,
    Confidence,
    FindingState,
    Freshness,
    ModuleResult,
    ModuleStatus,
    Severity,
    utcnow,
)
from recon.models.cookies import CookieData, CookieRecord
from recon.models.crawl import CrawlData, CrawledPage, DiscoveredUrl, FormRecord
from recon.models.dns import (
    CaaAnalysis,
    DkimSelectorResult,
    DmarcAnalysis,
    DnsData,
    DnsQueryResult,
    DnsQueryStatus,
    DnsRecord,
    EmailSecurity,
    SpfAnalysis,
    SpfRecord,
)
from recon.models.dnssec import DnssecData, DnssecStatus
from recon.models.html import HtmlData, ResourceRef
from recon.models.http import HttpData, HttpHop, HttpProbe, SecurityHeader
from recon.models.network import AsnInfo, GeoLocation, IpIntel, NetworkData, RdapNetwork
from recon.models.observations import ChangeKind, Change, ComparisonResult, Observation, ScanRef
from recon.models.resources import (
    FetchedResource,
    ManifestInfo,
    ResourcesData,
    RobotsInfo,
    SecurityTxtInfo,
    SitemapInfo,
    TextResourceInfo,
)
from recon.models.report import (
    SCHEMA_VERSION,
    AnalysisResult,
    Finding,
    InfrastructureObservation,
    ReconReport,
    TargetInfo,
    ToolInfo,
)
from recon.models.subdomains import CtEntry, HostState, ProviderResult, SubdomainData, SubdomainRecord
from recon.models.technology import DetectionStatus, TechEvidence, Technology, TechnologyData
from recon.models.third_party import ThirdPartyData, ThirdPartyService
from recon.models.tls import CertificateInfo, TlsData, TlsProbe
from recon.models.whois import DomainRegistration

__all__ = [
    # common
    "CollectionError", "CollectionMethod", "Confidence", "FindingState", "Freshness",
    "ModuleResult", "ModuleStatus", "Severity", "utcnow",
    # dns
    "DkimSelectorResult", "DmarcAnalysis", "DnsData", "DnsQueryResult", "DnsQueryStatus",
    "DnsRecord", "EmailSecurity", "SpfAnalysis", "SpfRecord",
    # html / http
    "HtmlData", "ResourceRef", "HttpData", "HttpHop", "HttpProbe", "SecurityHeader",
    # network
    "AsnInfo", "GeoLocation", "IpIntel", "NetworkData", "RdapNetwork",
    # report / analysis output
    "SCHEMA_VERSION", "AnalysisResult", "Finding", "InfrastructureObservation", "ReconReport",
    "TargetInfo", "ToolInfo",
    # subdomains / technology / third party / tls / whois
    "SubdomainData", "SubdomainRecord", "DetectionStatus", "TechEvidence", "Technology",
    "TechnologyData", "ThirdPartyData", "ThirdPartyService", "CertificateInfo", "TlsData",
    "TlsProbe", "DomainRegistration",
    # v0.2
    "CaaAnalysis", "CookieData", "CookieRecord", "CrawlData", "CrawledPage", "DiscoveredUrl", "FormRecord",
    "DnssecData", "DnssecStatus", "ChangeKind", "Change", "ComparisonResult", "Observation", "ScanRef",
    "FetchedResource", "ManifestInfo", "ResourcesData", "RobotsInfo", "SecurityTxtInfo", "SitemapInfo",
    "TextResourceInfo", "CtEntry", "HostState", "ProviderResult",
    "AssetData", "AssetRecord", "LibraryHit", "SkippedAsset", "EndpointRef", "ClientConfig",
    "ClientConfigValue", "SecretFinding",
]
