'''
Frontend asset (JavaScript / CSS bundle) models. Bundle contents are never stored.
'''

from __future__ import annotations

from pydantic import BaseModel, Field

from recon.models.common import Confidence


class LibraryHit(BaseModel):
    '''
    A library or framework marker found in a bundle.
    '''
    name: str
    category: str
    version: str | None = None
    confidence: Confidence
    evidence: str               # which marker matched (never surrounding code)


class EndpointRef(BaseModel):
    '''
    An API path or URL referenced in a bundle. Query values are redacted; this is an inventory of
    reachable routes, not a guarantee any is called.
    '''
    value: str                  # absolute URL or root-relative path, query-redacted
    host: str | None = None     # None for same-origin relative paths
    method: str | None = None   # only when a literal method sits next to the path
    same_site: bool = False


class ClientConfigValue(BaseModel):
    '''
    One field of a public client configuration block.
    '''
    key: str
    value: str                  # redacted when the field looks secret (see ClientConfig.note)
    sensitive: bool = False     # True if the value was redacted


class ClientConfig(BaseModel):
    '''
    A public, client-side configuration block (e.g. Firebase, Supabase). These are designed to ship in
    the browser; structural identifiers are shown, key/token fields are redacted.
    '''
    provider: str
    kind: str                   # firebase, supabase, generic
    source_asset: str
    fields: list[ClientConfigValue] = Field(default_factory=list)
    note: str = ("Public client configuration is meant to ship in the browser. Identifier fields are shown; "
                 "key and token fields are redacted. Public keys are not secrets but can enable abuse if "
                 "server-side rules (e.g. database row-level security) are weak.")


class SecretFinding(BaseModel):
    '''
    A value that matches a private-credential pattern. The raw value is never stored: only its type,
    location and a non-reversible fingerprint are kept, so an operator can locate and rotate it.
    '''
    type: str                   # aws_access_key_id, stripe_secret_key, private_key, generic_secret, ...
    source_asset: str
    context_key: str | None = None   # the variable/JSON key it was assigned to, if any
    redacted: str                    # fingerprint from redact_secret(); never the raw value
    severity: str                    # high, medium (informational handled as a finding elsewhere)
    note: str = "Detection is heuristic; confirm before acting. The raw value is never stored or used."


class AssetRecord(BaseModel):
    '''
    One downloaded (or skipped) frontend asset.
    '''
    url: str
    kind: str                   # script or stylesheet
    source_page: str | None = None
    status_code: int | None = None
    content_type: str | None = None
    size: int | None = None
    truncated: bool = False
    sha256: str | None = None
    libraries: list[LibraryHit] = Field(default_factory=list)
    service_hosts: list[str] = Field(default_factory=list)
    endpoints: list[EndpointRef] = Field(default_factory=list)
    client_configs: list[ClientConfig] = Field(default_factory=list)
    secrets: list[SecretFinding] = Field(default_factory=list)
    source_map_url: str | None = None
    source_map_status: str | None = None   # public, not_public, inline, out_of_scope, unchecked, error
    source_map_source_count: int = 0       # original files listed by a public map
    source_map_sources: list[str] = Field(default_factory=list)   # sample of original paths (never their contents)
    integrity_declared: str | None = None  # the page's integrity= attribute for this asset
    integrity_status: str | None = None    # verified, mismatch, unverifiable, absent, unsupported_algorithm
    integrity_algorithm: str | None = None
    error: str | None = None


class SkippedAsset(BaseModel):
    '''
    An asset that was referenced but not downloaded.
    '''
    url: str
    source_page: str | None = None
    reason: str                 # out_of_scope, asset_limit, byte_limit


class AssetData(BaseModel):
    '''
    Static analysis of frontend assets.
    '''
    assets: list[AssetRecord] = Field(default_factory=list)
    skipped: list[SkippedAsset] = Field(default_factory=list)
    total_bytes: int = 0
    allowed_external_hosts: list[str] = Field(default_factory=list)
    service_hosts: dict[str, list[str]] = Field(default_factory=dict)   # host → assets referencing it (sample)
    endpoint_count: int = 0
    secret_count: int = 0
    integrity_verified: int = 0
    integrity_mismatched: int = 0
    note: str = ("Assets were downloaded and scanned as text; they were never executed. Endpoint paths and "
                 "public client configuration are inventoried for review. Suspected private credentials are "
                 "reported by type and fingerprint only — raw values are never stored, and none are ever used.")

    def endpoints(self) -> list[EndpointRef]:
        '''
        Every endpoint reference across all assets, deduplicated by value.
        Returns:
            list[EndpointRef]: Unique endpoint references in discovery order.
        '''
        seen: dict[str, EndpointRef] = {}
        for asset in self.assets:
            for ref in asset.endpoints:
                seen.setdefault(ref.value, ref)
        return list(seen.values())
