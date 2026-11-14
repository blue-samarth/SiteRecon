'''
External intelligence: query third-party providers *about* a target (never probing the target itself),
through pluggable, fail-soft providers whose output flows through the normal observation/finding pipeline.

The two providers here are keyless (no account, no API key): the Wayback Machine and Shodan InternetDB.
Import from this package, e.g. ``from recon.intel import IntelRunner``.
'''

from recon.intel.base import IntelContext, IntelligenceProvider, IntelResult
from recon.intel.providers import KEYLESS, REGISTRY, ShodanInternetDbProvider, WaybackProvider
from recon.intel.runner import IntelAggregate, IntelRunner, ProviderNote

__all__ = [
    "IntelContext", "IntelligenceProvider", "IntelResult",
    "KEYLESS", "REGISTRY", "WaybackProvider", "ShodanInternetDbProvider",
    "IntelAggregate", "IntelRunner", "ProviderNote",
]
