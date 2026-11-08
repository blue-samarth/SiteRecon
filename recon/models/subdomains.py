'''
Certificate Transparency subdomain models.
'''

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class HostState(StrEnum):
    '''
    What is known about a discovered hostname today.
    '''
    HISTORICAL = "historical"   # seen in certificates; does not resolve now
    RESOLVING = "resolving"     # resolves in DNS
    REACHABLE = "reachable"     # resolves and answered over HTTPS or TLS
    UNVERIFIED = "unverified"   # not checked, or the check was inconclusive


class CtEntry(BaseModel):
    '''
    One certificate as reported by a CT provider, normalized across providers.
    '''
    provider: str
    cert_id: str | None = None
    names: list[str] = Field(default_factory=list)
    issuer: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None


class ProviderResult(BaseModel):
    '''
    Outcome of querying one CT provider.
    '''
    provider: str
    status: str                 # live, cached, failed
    entries: int = 0
    error: str | None = None
    cached_at: datetime | None = None


class SubdomainRecord(BaseModel):
    '''
    A hostname seen in Certificate Transparency, with optional verification results.
    '''
    hostname: str
    wildcard: bool = False          # seen only as "*.hostname"
    sources: list[str] = Field(default_factory=list)
    certificate_count: int = 0
    first_seen: datetime | None = None   # earliest not_before
    last_seen: datetime | None = None    # latest not_after
    issuers: list[str] = Field(default_factory=list)
    cert_ids: list[str] = Field(default_factory=list)  # sample of provider certificate IDs
    state: HostState = HostState.UNVERIFIED
    # Verification (only if performed)
    verified: bool = False
    resolves: bool | None = None
    dns_status: str | None = None
    addresses: list[str] = Field(default_factory=list)
    private_addresses: list[str] = Field(default_factory=list)
    http_status: int | None = None
    http_location: str | None = None
    http_error: str | None = None
    tls_ok: bool | None = None
    tls_hostname_match: bool | None = None
    tls_error: str | None = None


class SubdomainData(BaseModel):
    '''
    Certificate Transparency discovery results.
    '''
    query: str
    providers: list[ProviderResult] = Field(default_factory=list)
    certificates_seen: int = 0
    hostnames: list[SubdomainRecord] = Field(default_factory=list)
    out_of_scope_dropped: int = 0
    verification_limit: int
    verified_count: int = 0
    http_checked: bool = False
    note: str = (
        "Names come from historical certificates. Presence in a certificate does not prove "
        "that a host exists or is active today; 'state' records what was verified."
    )
