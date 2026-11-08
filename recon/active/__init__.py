'''
Active testing: authorized checks that send more than passive probes, gated behind an
operator-authored authorization file. Import from this package, e.g.
``from recon.active import ActiveOrchestrator, load_authorization``.
'''

from recon.active.authorization import (
    ActiveScope,
    AuthorizationError,
    AuthorizationFile,
    load_authorization,
    redact_authorization,
)
from recon.active.checks import REGISTRY, ActiveCheck, ClientIpHeaderTrustCheck, build_check
from recon.active.context import ActiveContext, BudgetExceeded
from recon.active.models import ActiveCheckResult, ActiveReport, RequestLogEntry
from recon.active.orchestrator import ActiveOrchestrator

__all__ = [
    "ActiveScope", "AuthorizationError", "AuthorizationFile", "load_authorization", "redact_authorization",
    "REGISTRY", "ActiveCheck", "ClientIpHeaderTrustCheck", "build_check", "ActiveContext", "BudgetExceeded",
    "ActiveCheckResult", "ActiveReport", "RequestLogEntry", "ActiveOrchestrator",
]
