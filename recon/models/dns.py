'''
DNS observation models.
'''

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class DnsQueryStatus(StrEnum):
    '''
    Classified outcome of a DNS query.
    '''
    NOERROR = "NOERROR"
    NXDOMAIN = "NXDOMAIN"   # name does not exist
    NODATA = "NODATA"       # name exists, no records of this type
    SERVFAIL = "SERVFAIL"   # no nameserver could answer
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"

    @property
    def is_definitive(self) -> bool:
        '''
        Whether the resolver gave an authoritative answer (positive or negative).
        Returns:
            bool: True for NOERROR, NXDOMAIN and NODATA.
        '''
        return self in (DnsQueryStatus.NOERROR, DnsQueryStatus.NXDOMAIN, DnsQueryStatus.NODATA)


class DnsRecord(BaseModel):
    '''
    A single resource record value with its TTL.
    '''
    value: str
    ttl: int | None = None


class DnsQueryResult(BaseModel):
    '''
    Result of one DNS query, including status, records and timing.
    '''
    name: str
    record_type: str
    status: DnsQueryStatus
    records: list[DnsRecord] = Field(default_factory=list)
    response_time_ms: float
    attempts: int = 1
    error: str | None = None
    authenticated: bool | None = None   # resolver AD flag (meaningful only when DNSSEC validation was requested)

    @property
    def values(self) -> list[str]:
        '''
        Return the record values as plain strings.
        Returns:
            list[str]: Record values in answer order.
        '''
        return [r.value for r in self.records]


class SpfRecord(BaseModel):
    '''
    A parsed SPF (v=spf1) record.
    '''
    raw: str
    mechanisms: list[str]
    includes: list[str]
    redirect: str | None = None
    all_qualifier: str | None = None  # "+", "-", "~", "?" or None when no "all" term
    parse_errors: list[str] = Field(default_factory=list)   # unknown or malformed terms
    uses_ptr: bool = False                                  # 'ptr' is deprecated (RFC 7208 §5.5)


class SpfAnalysis(BaseModel):
    '''
    SPF records found at the domain.
    '''
    lookup_status: DnsQueryStatus
    records: list[SpfRecord] = Field(default_factory=list)
    lookup_count: int | None = None          # DNS-querying terms, followed through include/redirect
    void_lookups: int | None = None          # includes/redirects that resolved to nothing
    lookup_limit_exceeded: bool | None = None
    evaluation_errors: list[str] = Field(default_factory=list)
    lookup_tree: list[str] = Field(default_factory=list)   # e.g. "include:_spf.google.com (+3)"


class DmarcAnalysis(BaseModel):
    '''
    Parsed DMARC policy from _dmarc.<domain>.
    '''
    name: str
    lookup_status: DnsQueryStatus
    raw_records: list[str] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)
    policy: str | None = None
    subdomain_policy: str | None = None
    pct: int | None = None
    adkim: str | None = None    # DKIM alignment: r (relaxed, default) or s (strict)
    aspf: str | None = None     # SPF alignment: r (relaxed, default) or s (strict)
    fo: str | None = None
    rua: list[str] = Field(default_factory=list)
    ruf: list[str] = Field(default_factory=list)


class DkimSelectorResult(BaseModel):
    '''
    A DKIM record found for a predefined selector.
    '''
    selector: str
    name: str
    status: DnsQueryStatus
    record: str | None = None
    key_type: str | None = None
    key_bits: int | None = None
    revoked: bool = False       # empty p= tag
    tags: dict[str, str] = Field(default_factory=dict)   # tags other than the key itself


class CaaAnalysis(BaseModel):
    '''
    CAA policy in effect for the hostname, found by climbing parent names (RFC 8659 §3).
    '''
    effective_name: str | None = None        # name whose CAA set applies
    records: list[str] = Field(default_factory=list)
    inherited: bool = False                  # policy comes from a parent name
    checked: dict[str, str] = Field(default_factory=dict)  # name → lookup status
    complete: bool = True                    # False if an inconclusive lookup interrupted the climb


class EmailSecurity(BaseModel):
    '''
    SPF, DMARC and DKIM observations.
    '''
    spf: SpfAnalysis
    dmarc: DmarcAnalysis
    dkim_selectors_checked: list[str]
    dkim_found: list[DkimSelectorResult] = Field(default_factory=list)
    dkim_note: str = (
        "DKIM selectors cannot be enumerated; only a small predefined list was checked. "
        "Absence here does not mean DKIM is not configured."
    )


class DnsData(BaseModel):
    '''
    All DNS observations for the target hostname.
    '''
    hostname: str
    queries: dict[str, DnsQueryResult]
    email: EmailSecurity
    caa: CaaAnalysis = Field(default_factory=CaaAnalysis)

    def addresses(self) -> list[str]:
        '''
        Return unique A and AAAA values.
        Returns:
            list[str]: IPv4 then IPv6 addresses, deduplicated.
        '''
        out: list[str] = []
        for rtype in ("A", "AAAA"):
            q = self.queries.get(rtype)
            if q:
                out.extend(q.values)
        return list(dict.fromkeys(out))
