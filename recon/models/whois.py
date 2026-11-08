'''
Domain registration (RDAP / WHOIS) models.
'''

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class DomainRegistration(BaseModel):
    '''
    Registrar, lifecycle dates, status, nameservers and DNSSEC for the domain.
    '''
    domain: str
    source: str  # "rdap" or "whois"
    source_url: str | None = None
    registrar: str | None = None
    registrar_iana_id: str | None = None
    created: datetime | None = None
    updated: datetime | None = None
    expires: datetime | None = None
    days_until_expiry: int | None = None
    status: list[str] = Field(default_factory=list)
    nameservers: list[str] = Field(default_factory=list)
    dnssec: bool | None = None
    note: str = "Registrant contact details are intentionally not collected."
