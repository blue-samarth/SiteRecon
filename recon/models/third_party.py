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


class CloudResource(BaseModel):
    '''
    A managed-cloud endpoint the site references: a storage bucket, serverless function, managed database,
    edge worker or hosting target.

    This is an inventory entry, not a vulnerability. It records that the application *references* the
    resource (from a page, a bundle, a CNAME or a CSP allow-list) — SiteRecon never requests the resource,
    so it cannot and does not claim the bucket is listable or the function is unauthenticated.
    '''
    provider: str               # Amazon S3, Azure Blob Storage, Cloudflare Workers, ...
    kind: str                   # object_storage, serverless_function, managed_database, edge_worker,
                                # hosting, auth, search, container
    identifier: str             # bucket / project / function / account identifier, as referenced
    host: str
    region: str | None = None
    sources: list[str] = Field(default_factory=list)   # html:script, bundle, bundle:endpoint, dns:cname, csp, crawl
    evidence: list[str] = Field(default_factory=list)
    url_sample: str | None = None      # one referencing URL, query-redacted
    confidence: Confidence
    public_by_default: bool = False    # the resource class is commonly world-readable when misconfigured
    note: str | None = None


class ThirdPartyData(BaseModel):
    '''
    Inventory of third-party services and managed-cloud resources.
    '''
    services: list[ThirdPartyService] = Field(default_factory=list)
    cloud_resources: list[CloudResource] = Field(default_factory=list)
    cloud_note: str = (
        "Cloud resources are listed because the site references them. They were never requested: whether a "
        "bucket is publicly listable, or a function endpoint accepts unauthenticated calls, requires an "
        "authorized active check (see `siterecon active`)."
    )
