from __future__ import annotations

import datetime as dt
import ipaddress

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

PUBLIC_IP = "93.184.216.34"


def make_cert(
    cn: str = "example.com",
    sans: tuple[str, ...] = ("example.com", "*.example.com"),
    not_before: dt.datetime | None = None,
    not_after: dt.datetime | None = None,
):
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(0xABCDEF)
        .not_valid_before(not_before or now - dt.timedelta(days=1))
        .not_valid_after(not_after or now + dt.timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName(
            [x509.DNSName(s) for s in sans] + [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
        ), critical=False)
    )
    cert = builder.sign(key, hashes.SHA256())
    return cert, key


@pytest.fixture
def cert_files(tmp_path):
    cert, key = make_cert(cn="localhost.test", sans=("localhost.test",))
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path


async def public_resolve(host: str, port: int) -> list[str]:
    return [PUBLIC_IP]
