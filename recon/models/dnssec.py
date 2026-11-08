'''
DNSSEC models.
'''

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class DnssecStatus(StrEnum):
    '''
    DNSSEC state derived from DS, DNSKEY and resolver validation together (never from one record alone).
    '''
    SIGNED_VALIDATED = "signed_validated"       # DS + DNSKEY, and the resolver set AD
    SIGNED_UNVALIDATED = "signed_unvalidated"   # DS + DNSKEY, but the resolver did not confirm validation
    UNSIGNED = "unsigned"                       # no DS and no DNSKEY (definitive answers)
    ISLAND = "island"                           # DNSKEY without DS: signed but no chain of trust
    BROKEN = "broken"                           # DS without DNSKEY: validating resolvers will fail
    UNKNOWN = "unknown"                         # a lookup was inconclusive


class DnssecData(BaseModel):
    '''
    DNSSEC observations for the zone.
    '''
    zone: str
    status: DnssecStatus
    ds_status: str
    dnskey_status: str
    ds_records: list[str] = Field(default_factory=list)
    dnskey_count: int = 0
    key_algorithms: list[str] = Field(default_factory=list)
    ds_digest_types: list[str] = Field(default_factory=list)
    resolver_authenticated: bool | None = None
    note: str = ("Validation status comes from the configured recursive resolver's AD flag; a resolver "
                 "that does not validate reports signed zones as 'signed_unvalidated'.")
