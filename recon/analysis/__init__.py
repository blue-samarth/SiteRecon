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
from recon.analysis.cloud_signatures import (
    CLOUD_SIGNATURES,
    CLOUD_SIGNATURES_VERSION,
    CloudMatch,
    CloudSignature,
    match_cloud,
)
from recon.analysis.comparison import ScanComparator
from recon.analysis.correlation import calibrate, correlate, recalc_states
from recon.analysis.regression import ChangeAnalyzer, RegressionAnalyzer
from recon.analysis.findings import LIMITATIONS, RECOMMENDATIONS, FindingCollector
from recon.analysis.historical_signatures import (
    HISTORICAL_SIGNATURES_VERSION,
    HISTORICAL_TECH_HINTS,
    PARAMETER_PATTERNS,
    SENSITIVE_PATH,
    ParameterSignature,
    TechHintSignature,
    classify_parameter,
    match_tech_hints,
)
from recon.analysis.observations import ObservationBuilder
from recon.analysis.seo_checks import (
    AREA_LABEL,
    AREAS,
    CHECKS_BY_ID,
    SEO_CHECKS,
    SEO_CHECKS_VERSION,
    CheckOutcome,
    SeoCheckSpec,
)
from recon.analysis.seo_grading import compute_seo_grade, run_checks
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
    SIGNATURES_VERSION,
    SPF_SERVICES,
    TECH_SIGNATURES,
    THIRD_PARTY_DOMAINS,
    TXT_VERIFICATIONS,
    DomainService,
    TechSignature,
)
from recon.analysis.trackers import (
    PRIVACY_SENSITIVE,
    TRACKER_SIGNATURES,
    TrackerCategory,
    TrackerSignature,
    classify_tracker,
)
from recon.analysis.waf import WAF_SIGNATURES, WafDetection, WafSignature, detect_wafs

__all__ = [
    "AnalysisEngine", "InfrastructureInference", "FindingCollector", "ScanComparator", "RegressionAnalyzer",
    "ChangeAnalyzer", "ObservationBuilder", "correlate", "calibrate", "recalc_states",
    "RECOMMENDATIONS", "LIMITATIONS",
    "DOMAIN_EXPIRY_WARN_DAYS", "HOLD_STATUSES", "HSTS_RECOMMENDED_MAX_AGE", "LEGACY_TLS",
    "TLS_EXPIRY_URGENT_DAYS", "TLS_EXPIRY_WARN_DAYS",
    "DNS_PROVIDERS", "HTTP_EDGE_PROVIDERS", "MAIL_PROVIDERS", "NETWORK_PROVIDERS",
    "HeaderSignature", "ProviderSignature",
    "CERTIFICATE_AUTHORITIES", "SPF_SERVICES", "TECH_SIGNATURES", "THIRD_PARTY_DOMAINS",
    "TXT_VERIFICATIONS", "DomainService", "TechSignature", "SIGNATURES_VERSION",
    "PRIVACY_SENSITIVE", "TRACKER_SIGNATURES", "TrackerCategory", "TrackerSignature", "classify_tracker",
    "WAF_SIGNATURES", "WafDetection", "WafSignature", "detect_wafs",
    # phase 1: cloud and historical signature sets
    "CLOUD_SIGNATURES", "CLOUD_SIGNATURES_VERSION", "CloudMatch", "CloudSignature", "match_cloud",
    "HISTORICAL_SIGNATURES_VERSION", "HISTORICAL_TECH_HINTS", "PARAMETER_PATTERNS", "SENSITIVE_PATH",
    "ParameterSignature", "TechHintSignature", "classify_parameter", "match_tech_hints",
    # seo audit
    "SEO_CHECKS", "SEO_CHECKS_VERSION", "CHECKS_BY_ID", "SeoCheckSpec", "CheckOutcome", "AREAS",
    "AREA_LABEL", "run_checks", "compute_seo_grade",
]
