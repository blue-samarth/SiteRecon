'''
TLS certificate observation models.
'''

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class CertificateInfo(BaseModel):
    '''
    Fields extracted from the presented leaf certificate.
    '''
    subject: str
    subject_cn: str | None = None
    issuer: str
    issuer_cn: str | None = None
    issuer_org: str | None = None
    serial_number: str
    version: str
    san_dns: list[str] = Field(default_factory=list)
    san_ip: list[str] = Field(default_factory=list)
    not_before: datetime
    not_after: datetime
    signature_algorithm: str
    signature_hash: str | None = None
    public_key_algorithm: str
    public_key_size: int | None = None
    public_key_curve: str | None = None
    fingerprint_sha256: str
    self_issued: bool
    sct_count: int = 0          # embedded Signed Certificate Timestamps (CT proof baked into the cert)


class TlsProbe(BaseModel):
    '''
    Result of a TLS handshake against one hostname.
    '''
    hostname: str
    port: int = 443
    ip: str | None = None
    success: bool
    tls_version: str | None = None
    cipher: str | None = None
    forward_secret: bool | None = None    # negotiated cipher provides forward secrecy (ECDHE/DHE, or TLS 1.3)
    alpn: str | None = None               # ALPN protocol negotiated (h2 / http/1.1)
    chain_length: int | None = None       # certificates the server sent (leaf + intermediates)
    chain_complete: bool | None = None    # server sent at least one intermediate (not just the leaf)
    verified: bool | None = None
    verification_error: str | None = None
    hostname_match: bool | None = None
    currently_valid: bool | None = None
    days_remaining: int | None = None
    certificate: CertificateInfo | None = None
    error: str | None = None
    error_type: str | None = None


class TlsData(BaseModel):
    '''
    All TLS probes for the target.
    '''
    probes: list[TlsProbe] = Field(default_factory=list)
