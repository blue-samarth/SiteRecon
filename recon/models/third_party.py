'''
Third-party integration models.
'''

from __future__ import annotations

from pydantic import BaseModel, Field

from recon.models.common import Confidence


class ThirdPartyService(BaseModel):
    '''
    An external service the site depends on, with evidence.
    '''
    provider: str
    category: str  # hosting, dns, email, analytics, authentication, backend, storage, media,
                   # cdn, monitoring, payment, certificate_authority, other
    domains: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    confidence: Confidence
    known: bool = True  # False when only an unrecognized external domain was seen


class ThirdPartyData(BaseModel):
    '''
    Inventory of third-party services.
    '''
    services: list[ThirdPartyService] = Field(default_factory=list)
