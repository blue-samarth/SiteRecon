'''
TLS certificate inspection over non-blocking asyncio connections (``ssl`` + ``cryptography`` for parsing).
'''

from __future__ import annotations

import asyncio
import contextlib
import ssl
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import ClassVar, TypeVar

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from recon.models import CertificateInfo, CollectionError, TlsData, TlsProbe
from recon.modules.base import Collector
from recon.utils import Resolve, is_public_ip, system_resolve

_R = TypeVar("_R")


class CertificateParser:
    '''
    Extracts report fields from DER certificates and performs RFC 6125 hostname matching.
    '''

    @classmethod
    def parse(cls, der: bytes) -> CertificateInfo:
        '''
        Parse a DER certificate into report fields.
        Parameters:
            der (bytes): DER-encoded certificate.
        Returns:
            CertificateInfo: Extracted fields.
        Raises:
            ValueError: If the bytes are not a valid certificate.
        '''
        cert = x509.load_der_x509_certificate(der)
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            san_dns = [n.lower() for n in san.get_values_for_type(x509.DNSName)]
            san_ip = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
        except x509.ExtensionNotFound:
            san_dns, san_ip = [], []

        key_alg, key_size, curve = cls._public_key_details(cert)
        oid = cert.signature_algorithm_oid
        return CertificateInfo(
            subject=cert.subject.rfc4514_string(),
            subject_cn=cls._attr(cert.subject, NameOID.COMMON_NAME),
            issuer=cert.issuer.rfc4514_string(),
            issuer_cn=cls._attr(cert.issuer, NameOID.COMMON_NAME),
            issuer_org=cls._attr(cert.issuer, NameOID.ORGANIZATION_NAME),
            serial_number=format(cert.serial_number, "X"),
            version=cert.version.name,
            san_dns=san_dns,
            san_ip=san_ip,
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            signature_algorithm=getattr(oid, "_name", None) or oid.dotted_string,
            signature_hash=cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None,
            public_key_algorithm=key_alg,
            public_key_size=key_size,
            public_key_curve=curve,
            fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(":").upper(),
            self_issued=cert.subject == cert.issuer,
        )

    @staticmethod
    def _public_key_details(cert: x509.Certificate) -> tuple[str, int | None, str | None]:
        '''
        Describe the certificate's public key.
        Parameters:
            cert (x509.Certificate): Parsed certificate.
        Returns:
            tuple[str, int | None, str | None]: Algorithm name, key size in bits, and curve name (EC only).
        '''
        key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            return "RSA", key.key_size, None
        if isinstance(key, ec.EllipticCurvePublicKey):
            return "EC", key.curve.key_size, key.curve.name
        if isinstance(key, ed25519.Ed25519PublicKey):
            return "Ed25519", 256, None
        if isinstance(key, ed448.Ed448PublicKey):
            return "Ed448", 456, None
        if isinstance(key, dsa.DSAPublicKey):
            return "DSA", key.key_size, None
        return type(key).__name__, None, None

    @staticmethod
    def _attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
        '''
        Return the first value of a name attribute.
        Parameters:
            name (x509.Name): X.509 name.
            oid (x509.ObjectIdentifier): Attribute OID.
        Returns:
            str | None: Attribute value or None.
        '''
        values = name.get_attributes_for_oid(oid)
        return str(values[0].value) if values else None

    @staticmethod
    def hostname_matches(hostname: str, san_dns: list[str]) -> bool:
        '''
        RFC 6125 matching against SAN dNSNames (wildcard only as the whole left-most label).
        Parameters:
            hostname (str): Hostname that was requested.
            san_dns (list[str]): SAN DNS names from the certificate.
        Returns:
            bool: True if any SAN matches.
        '''
        host = hostname.lower().rstrip(".")
        for pattern in san_dns:
            pattern = pattern.lower().rstrip(".")
            if pattern == host:
                return True
            if pattern.startswith("*."):
                suffix = pattern[2:]
                head, _, rest = host.partition(".")
                if head and rest == suffix and suffix.count(".") >= 1:
                    return True
        return False


class TlsCollector(Collector[TlsData]):
    '''
    Inspects the TLS certificate presented by the target and its www. variant.
    '''

    name: ClassVar[str] = "tls"

    def __init__(
        self,
        hostname: str,
        *,
        timeout: float,
        retries: int,
        allow_private_networks: bool = False,
        resolve: Resolve = system_resolve,
        now: datetime | None = None,
    ) -> None:
        '''
        Create the collector.
        Parameters:
            hostname (str): Normalized target hostname.
            timeout (float): Per-operation timeout in seconds.
            retries (int): Number of retries for transient failures.
            allow_private_networks (bool): Permit connections to non-public addresses.
            resolve (Resolve): Async hostname resolver (injectable for tests).
            now (datetime | None): Reference time for validity calculations; defaults to the current UTC time.
        '''
        self.hostname = hostname
        self.timeout = timeout
        self.retries = retries
        self.allow_private_networks = allow_private_networks
        self.resolve = resolve
        self.now = now

    @staticmethod
    def candidate_hosts(hostname: str) -> list[str]:
        '''
        Hostnames to inspect: the target and its www. variant.
        Parameters:
            hostname (str): Normalized target hostname.
        Returns:
            list[str]: Hostnames to probe.
        '''
        return [hostname] if hostname.startswith("www.") else [hostname, f"www.{hostname}"]

    async def collect(self) -> tuple[TlsData, list[CollectionError]]:
        '''
        Inspect the TLS certificate of each candidate host concurrently.
        Returns:
            tuple[TlsData, list[CollectionError]]: TLS probes and errors for failed handshakes.
        '''
        probes = await asyncio.gather(*(self.probe(h) for h in self.candidate_hosts(self.hostname)))
        errors = [self.error(f"{p.hostname}:{p.port}", p.error_type or "error", p.error or "")
                  for p in probes if p.error]
        return TlsData(probes=list(probes)), errors

    async def probe(self, hostname: str, port: int = 443) -> TlsProbe:
        '''
        Handshake with a vetted address, verify the chain, then re-fetch unverified if needed to inspect the certificate.
        Parameters:
            hostname (str): Hostname to connect to (SNI and verification name).
            port (int): TCP port.
        Returns:
            TlsProbe: The probe result.
        '''
        probe = TlsProbe(hostname=hostname, port=port, success=False)
        try:
            addresses = await self.resolve(hostname, port)
        except OSError as exc:
            probe.error, probe.error_type = str(exc), "dns_resolution"
            return probe
        allowed = [a for a in addresses if self.allow_private_networks or is_public_ip(a)]
        if not allowed:
            probe.error = f"{hostname} resolves only to non-public addresses {addresses}"
            probe.error_type = "blocked_address"
            return probe
        ip = probe.ip = allowed[0]  # connect to the vetted address, not a fresh resolution

        try:
            der, version, cipher = await self._with_retries(
                lambda: self._handshake(ip, hostname, port, verify=True))
            probe.verified = True
        except ssl.SSLCertVerificationError as exc:
            probe.verified = False
            probe.verification_error = exc.verify_message or str(exc)
            try:
                der, version, cipher = await self._with_retries(
                    lambda: self._handshake(ip, hostname, port, verify=False))
            except (ssl.SSLError, OSError) as inner:
                probe.error, probe.error_type = str(inner), type(inner).__name__
                return probe
        except (ssl.SSLError, OSError) as exc:
            probe.error, probe.error_type = str(exc) or type(exc).__name__, type(exc).__name__
            return probe

        probe.success = True
        probe.tls_version, probe.cipher = version, cipher
        cert = CertificateParser.parse(der)
        probe.certificate = cert
        current = self.now or datetime.now(UTC)
        probe.currently_valid = cert.not_before <= current <= cert.not_after
        probe.days_remaining = (cert.not_after - current).days
        probe.hostname_match = CertificateParser.hostname_matches(hostname, cert.san_dns)
        return probe

    async def _with_retries(self, fn: Callable[[], Awaitable[_R]]) -> _R:
        '''
        Await a coroutine factory, retrying timeouts and connection resets/refusals with backoff.
        Parameters:
            fn (Callable[[], Awaitable[_R]]): Zero-argument callable returning a fresh coroutine per attempt.
        Returns:
            _R: The coroutine's result.
        Raises:
            TimeoutError | ConnectionResetError | ConnectionRefusedError: When retries are exhausted.
        '''
        attempt = 0
        while True:
            attempt += 1
            try:
                return await fn()
            except (TimeoutError, ConnectionResetError, ConnectionRefusedError):
                if attempt > self.retries:
                    raise
                await asyncio.sleep(0.5 * 2 ** (attempt - 1))

    async def _handshake(self, ip: str, hostname: str, port: int, verify: bool) -> tuple[bytes, str | None, str | None]:
        '''
        Perform one non-blocking TLS handshake and return the leaf certificate and session details.
        Parameters:
            ip (str): Address to connect to.
            hostname (str): SNI / verification hostname.
            port (int): TCP port.
            verify (bool): Verify the chain and hostname.
        Returns:
            tuple[bytes, str | None, str | None]: DER certificate, TLS version and cipher name.
        Raises:
            ssl.SSLError | OSError: On handshake or connection failure.
            TimeoutError: If connecting or the handshake exceeds the timeout.
        '''
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=hostname,
                                    ssl_handshake_timeout=self.timeout),
            timeout=self.timeout,
        )
        try:
            tls: ssl.SSLObject = writer.get_extra_info("ssl_object")
            der = tls.getpeercert(binary_form=True)
            if der is None:
                raise ssl.SSLError("server presented no certificate")
            cipher = tls.cipher()
            return der, tls.version(), cipher[0] if cipher else None
        finally:
            writer.close()
            with contextlib.suppress(OSError, ssl.SSLError, TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), timeout=2)
