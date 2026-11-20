'''
Subdomain-discovery models: Certificate Transparency, passive sources and controlled permutation.
'''

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class HostState(StrEnum):
    '''
    What is known about a discovered hostname today.
    '''
    HISTORICAL = "historical"   # seen in certificates or archives; does not resolve now
    RESOLVING = "resolving"     # resolves in DNS
    REACHABLE = "reachable"     # resolves and answered over HTTPS or TLS
    UNVERIFIED = "unverified"   # not checked, or the check was inconclusive


class SourceKind(StrEnum):
    '''
    How a discovery source learns about a hostname, which is what its evidence is worth.
    '''
    CT = "ct"                       # Certificate Transparency log search (a certificate named the host)
    PASSIVE_DNS = "passive_dns"     # a passive-DNS dataset observed the name resolving
    URL_INDEX = "url_index"         # a crawl/archive index holds a URL on that host
    SCRAPE = "scrape"               # an HTML listing page was parsed (weakest; format can change)
    PERMUTATION = "permutation"     # generated locally from known names, then confirmed in DNS


class PassiveEntry(BaseModel):
    '''
    One hostname as reported by a non-CT passive source, normalized across sources.
    '''
    source: str
    hostname: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    address: str | None = None      # the address the source saw, when it reports one (never contacted)
    detail: str | None = None       # short source-specific note (e.g. the record type it saw)


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
    Outcome of querying one discovery source (a CT provider or a passive source).
    '''
    provider: str
    status: str                 # live, cached, failed, skipped
    entries: int = 0
    error: str | None = None
    cached_at: datetime | None = None
    kind: str = SourceKind.CT   # which family the source belongs to (see SourceKind)
    names: int = 0              # in-scope names this source contributed
    skip_reason: str | None = None   # why a source did not run (e.g. missing API key)


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
    # Subdomain-takeover assessment (only when verification ran)
    cname: str | None = None                 # CNAME target, if the name is a CNAME
    takeover_provider: str | None = None     # takeover-prone provider the CNAME points at, if any
    takeover_vulnerable: bool = False        # confirmed unclaimed (fingerprint) or dangling (target gone)
    takeover_detail: str | None = None       # human-readable explanation of the assessment


class PermutationStats(BaseModel):
    '''
    What the controlled permutation pass generated and confirmed.

    Permutation is the one discovery path that is not purely passive: it builds candidate names from the
    labels already discovered plus a small fixed wordlist and resolves them in DNS (A/AAAA only, no HTTP).
    It is opt-in, hard-capped, scope-checked, and only names that actually resolve are kept — a candidate
    that does not resolve is discarded rather than recorded, so the inventory never fills with guesses.
    '''
    enabled: bool = False
    generated: int = 0          # distinct in-scope candidates built
    tested: int = 0             # candidates actually resolved (bounded by `limit`)
    resolved: int = 0           # candidates that resolve and were added to the inventory
    limit: int = 0
    wordlist_size: int = 0
    truncated: bool = False     # more candidates were generated than the limit allowed
    note: str = (
        "Candidate names are generated from already-discovered labels and a small fixed wordlist, then "
        "resolved in DNS only. Nothing is fetched over HTTP, the count is hard-capped, every candidate is "
        "scope-checked, and only names that resolve are reported."
    )


class SubdomainData(BaseModel):
    '''
    Subdomain discovery results: Certificate Transparency, passive sources and optional permutation.
    '''
    query: str
    providers: list[ProviderResult] = Field(default_factory=list)   # CT providers
    sources: list[ProviderResult] = Field(default_factory=list)     # non-CT passive sources
    certificates_seen: int = 0
    passive_entries_seen: int = 0
    hostnames: list[SubdomainRecord] = Field(default_factory=list)
    out_of_scope_dropped: int = 0
    verification_limit: int
    verified_count: int = 0
    http_checked: bool = False
    permutation: PermutationStats = Field(default_factory=PermutationStats)
    note: str = (
        "Names come from historical certificates, passive datasets and (when enabled) locally generated "
        "candidates confirmed in DNS. Presence in a certificate or dataset does not prove that a host "
        "exists or is active today; 'state' records what was verified."
    )

    def by_source_kind(self) -> dict[str, int]:
        '''
        Count discovered names per source family, so report readers can see what each kind contributed.
        Returns:
            dict[str, int]: Source name → number of discovered hostnames crediting it.
        '''
        counts: dict[str, int] = {}
        for record in self.hostnames:
            for source in record.sources:
                counts[source] = counts.get(source, 0) + 1
        return dict(sorted(counts.items()))
