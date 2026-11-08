'''
Technology fingerprinting models.
'''

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from recon.models.common import Confidence


class DetectionStatus(StrEnum):
    '''
    Whether a technology detection is confirmed or probable.
    '''
    CONFIRMED = "confirmed"  # strong evidence (header/generator) or several independent sources
    PROBABLE = "probable"    # a single medium-strength signal
    POSSIBLE = "possible"    # only weak signals: CSP allow-list, DNS hint, or implied by another technology


class TechEvidence(BaseModel):
    '''
    One piece of evidence supporting a detection.
    '''
    source: str  # header, meta_generator, resource_url, html, domain, csp, dns, implied
    detail: str
    confidence: Confidence


class Technology(BaseModel):
    '''
    A detected technology with its evidence.
    '''
    name: str
    category: str
    status: DetectionStatus
    confidence: Confidence
    version: str | None = None
    evidence: list[TechEvidence] = Field(default_factory=list)


class TechnologyData(BaseModel):
    '''
    All technology detections.
    '''
    technologies: list[Technology] = Field(default_factory=list)
    signatures_checked: int = 0
    inputs: list[str] = Field(default_factory=list)
