'''
Network / IP intelligence models.
'''

from __future__ import annotations

from pydantic import BaseModel, Field

from recon.models.dns import DnsQueryStatus


class AsnInfo(BaseModel):
    '''
    Origin ASN and prefix for an IP (Team Cymru).
    '''
    asn: int
    prefix: str | None = None
    country: str | None = None
    registry: str | None = None
    allocated: str | None = None
    name: str | None = None
    source: str = "Team Cymru IP-to-ASN (DNS)"


class RdapNetwork(BaseModel):
    '''
    IP allocation data from RDAP.
    '''
    handle: str | None = None
    name: str | None = None
    type: str | None = None
    start_address: str | None = None
    end_address: str | None = None
    cidrs: list[str] = Field(default_factory=list)
    country: str | None = None
    organizations: list[str] = Field(default_factory=list)
    source_url: str | None = None


class IpIntel(BaseModel):
    '''
    PTR, ASN and RDAP intelligence for one IP address.
    '''
    ip: str
    version: int
    is_public: bool
    ptr: list[str] = Field(default_factory=list)
    ptr_status: DnsQueryStatus | None = None
    asn: AsnInfo | None = None
    rdap: RdapNetwork | None = None
    note: str = (
        "ASN/RDAP data describe who the address space is allocated to (often a CDN or "
        "cloud edge), not necessarily the website's origin server."
    )


class NetworkData(BaseModel):
    '''
    Intelligence for every unique resolved IP.
    '''
    ips: list[IpIntel] = Field(default_factory=list)
