'''
Analysis layer: turns collected observations into findings and provider inferences.

Nothing in this package performs network I/O. Import from this package, e.g.
``from recon.analysis import AnalysisEngine, TECH_SIGNATURES``.
'''

from recon.analysis.engine import (
    DOMAIN_EXPIRY_WARN_DAYS,
    HOLD_STATUSES,
    HSTS_RECOMMENDED_MAX_AGE,
    LEGACY_TLS,
    TLS_EXPIRY_URGENT_DAYS,
    TLS_EXPIRY_WARN_DAYS,
    AnalysisEngine,
    InfrastructureInference,
)
from recon.analysis.comparison import ScanComparator
from recon.analysis.findings import LIMITATIONS, RECOMMENDATIONS, FindingCollector
from recon.analysis.observations import ObservationBuilder
from recon.analysis.signatures import (
    DNS_PROVIDERS,
    HTTP_EDGE_PROVIDERS,
    MAIL_PROVIDERS,
    NETWORK_PROVIDERS,
    HeaderSignature,
    ProviderSignature,
)
from recon.analysis.tech_signatures import (
    CERTIFICATE_AUTHORITIES,
    SPF_SERVICES,
    TECH_SIGNATURES,
    THIRD_PARTY_DOMAINS,
    TXT_VERIFICATIONS,
    DomainService,
    TechSignature,
)

__all__ = [
    "AnalysisEngine", "InfrastructureInference", "FindingCollector", "ScanComparator", "ObservationBuilder",
    "RECOMMENDATIONS", "LIMITATIONS",
    "DOMAIN_EXPIRY_WARN_DAYS", "HOLD_STATUSES", "HSTS_RECOMMENDED_MAX_AGE", "LEGACY_TLS",
    "TLS_EXPIRY_URGENT_DAYS", "TLS_EXPIRY_WARN_DAYS",
    "DNS_PROVIDERS", "HTTP_EDGE_PROVIDERS", "MAIL_PROVIDERS", "NETWORK_PROVIDERS",
    "HeaderSignature", "ProviderSignature",
    "CERTIFICATE_AUTHORITIES", "SPF_SERVICES", "TECH_SIGNATURES", "THIRD_PARTY_DOMAINS",
    "TXT_VERIFICATIONS", "DomainService", "TechSignature",
]
