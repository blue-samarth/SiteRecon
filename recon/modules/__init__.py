'''
Collection layer: each collector gathers evidence and returns structured observations.

Every collector subclasses ``Collector`` and implements ``collect() -> (data, errors)``; none
produce findings or reports. Import from this package, e.g.
``from recon.modules import DnsCollector, HttpCollector``.
'''

from recon.modules.base import Collector
from recon.modules.cookies import CookieCollector, CookieParser
from recon.modules.crawler import Crawler, RobotsRules
from recon.modules.dns import DnsCollector
from recon.modules.dnssec import DnssecCollector
from recon.modules.html import HtmlCollector, HtmlParser
from recon.modules.http import HttpCollector, SecurityHeaderParser
from recon.modules.javascript import (
    BUNDLE_SIGNATURES,
    AssetCollector,
    BundleAnalyzer,
    BundleSignature,
    AssetRef,
    ClientConfigExtractor,
    EndpointExtractor,
    IntegrityVerifier,
    SecretScanner,
    SourceMapReader,
)
from recon.modules.network import NetworkCollector
from recon.modules.resources import (
    ResourcesCollector,
    RobotsParser,
    SecurityTxtParser,
    SitemapParser,
)
from recon.modules.subdomains import (
    CertSpotterProvider,
    CrtShProvider,
    CtCache,
    CtProvider,
    CtProviderError,
    SubdomainCollector,
)
from recon.modules.technology import FingerprintInputs, TechnologyCollector, TechnologyFingerprinter
from recon.modules.third_party import ServiceInventory, ThirdPartyCollector
from recon.modules.tls import CertificateParser, TlsCollector
from recon.modules.whois import RdapUnavailableError, WhoisClient, WhoisCollector, WhoisError, WhoisParser

__all__ = [
    # base
    "Collector",
    # collectors
    "DnsCollector", "NetworkCollector", "HttpCollector", "TlsCollector", "WhoisCollector",
    "HtmlCollector", "TechnologyCollector", "SubdomainCollector", "ThirdPartyCollector",
    # helpers used by collectors
    "HtmlParser", "SecurityHeaderParser", "FingerprintInputs", "TechnologyFingerprinter",
    "ServiceInventory", "CertificateParser", "RdapUnavailableError", "WhoisClient", "WhoisError",
    "WhoisParser",
    # v0.2
    "DnssecCollector", "ResourcesCollector", "Crawler", "CookieCollector",
    "CookieParser", "RobotsRules", "RobotsParser", "SecurityTxtParser", "SitemapParser",
    "CtProvider", "CtProviderError", "CrtShProvider", "CertSpotterProvider", "CtCache",
    "AssetCollector", "BundleAnalyzer", "BundleSignature", "BUNDLE_SIGNATURES",
    "EndpointExtractor", "ClientConfigExtractor", "SecretScanner", "IntegrityVerifier",
    "SourceMapReader", "AssetRef",
]
