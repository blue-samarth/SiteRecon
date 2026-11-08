'''
Shared helpers: input validation, scope and SSRF guards, DNS/HTTP clients, redaction, logging.

Import from this package, e.g. ``from recon.utils import SafeHttpClient, Scope``.
Submodules inside this package import each other directly to avoid circular imports.
'''

from recon.utils.domains import (
    host_of,
    matches_suffix,
    normalize_discovered,
    public_suffix,
    registrable_domain,
)
from recon.utils.psl import PublicSuffixList
from recon.utils.http_client import (
    REDIRECT_STATUSES,
    RETRY_STATUSES,
    BlockedRequestError,
    FetchOutcome,
    RawResponse,
    Resolve,
    SafeHttpClient,
)
from recon.utils.logger import LOGGER_NAME, get_logger, setup_logging
from recon.utils.redact import REDACTED, redact_secret, redact_url
from recon.utils.resolver import DnsClient, format_rdata, system_resolve
from recon.utils.scope import Scope, is_public_ip
from recon.utils.validators import InvalidTargetError, normalize_target, validate_hostname

__all__ = [
    "host_of", "matches_suffix", "normalize_discovered", "registrable_domain", "public_suffix",
    "PublicSuffixList",
    "REDIRECT_STATUSES", "RETRY_STATUSES", "BlockedRequestError", "FetchOutcome", "RawResponse",
    "Resolve", "SafeHttpClient",
    "LOGGER_NAME", "get_logger", "setup_logging",
    "REDACTED", "redact_url", "redact_secret",
    "DnsClient", "format_rdata", "system_resolve",
    "Scope", "is_public_ip",
    "InvalidTargetError", "normalize_target", "validate_hostname",
]
