import datetime as dt
import socket
import ssl
import threading

import pytest
from cryptography.hazmat.primitives import serialization

from recon.modules import CertificateParser, TlsCollector


async def probe_tls(hostname, port, **kwargs):
    return await TlsCollector(hostname, **kwargs).probe(hostname, port)
from tests.conftest import make_cert


def test_parse_certificate_fields():
    cert, _ = make_cert()
    info = CertificateParser.parse(cert.public_bytes(serialization.Encoding.DER))
    assert info.subject_cn == "example.com"
    assert info.issuer_org == "Test Org"
    assert info.serial_number == "ABCDEF"
    assert info.san_dns == ["example.com", "*.example.com"]
    assert info.san_ip == ["127.0.0.1"]
    assert info.public_key_algorithm == "EC" and info.public_key_size == 256
    assert info.public_key_curve == "secp256r1"
    assert info.signature_hash == "sha256"
    assert info.self_issued is True


@pytest.mark.parametrize("host, sans, ok", [
    ("example.com", ["example.com"], True),
    ("www.example.com", ["*.example.com"], True),
    ("a.b.example.com", ["*.example.com"], False),   # wildcard covers one label only
    ("example.com", ["*.example.com"], False),
    ("WWW.Example.COM.", ["www.example.com"], True),
    ("example.com", ["*.com"], False),               # no wildcard on public suffix-like names
    ("example.com", [], False),
])
def test_hostname_matches(host, sans, ok):
    assert CertificateParser.hostname_matches(host, sans) is ok


@pytest.fixture
def tls_server(cert_files):
    """Minimal local TLS server presenting a self-signed cert for localhost.test."""
    cert_path, key_path = cert_files
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    srv = socket.create_server(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except TimeoutError:
                continue
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1)
            except (ssl.SSLError, OSError):
                pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield port
    stop.set()
    t.join(timeout=2)
    srv.close()


async def _loopback(host, port):
    return ["127.0.0.1"]


async def test_probe_self_signed_records_verification_failure(tls_server):
    probe = await probe_tls("localhost.test", tls_server, timeout=3, retries=0,
                            allow_private_networks=True, resolve=_loopback)
    assert probe.success, probe.error
    assert probe.verified is False
    assert "self" in (probe.verification_error or "").lower()
    assert probe.hostname_match is True
    assert probe.certificate.subject_cn == "localhost.test"
    assert probe.tls_version in ("TLSv1.2", "TLSv1.3")
    assert probe.currently_valid is True and 85 <= probe.days_remaining <= 90


async def test_probe_hostname_mismatch(tls_server):
    probe = await probe_tls("other.test", tls_server, timeout=3, retries=0,
                            allow_private_networks=True, resolve=_loopback)
    assert probe.success and probe.hostname_match is False and probe.verified is False


async def test_probe_expiry_math_uses_injected_clock(tls_server):
    future = dt.datetime.now(dt.UTC) + dt.timedelta(days=200)
    probe = await probe_tls("localhost.test", tls_server, timeout=3, retries=0,
                            allow_private_networks=True, resolve=_loopback, now=future)
    assert probe.currently_valid is False and probe.days_remaining < 0


async def test_probe_private_address_blocked_by_default():
    probe = await probe_tls("localhost.test", 443, timeout=1, retries=0, resolve=_loopback)
    assert not probe.success and probe.error_type == "blocked_address"


async def test_probe_connection_refused():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listening now
    probe = await probe_tls("localhost.test", port, timeout=1, retries=0,
                            allow_private_networks=True, resolve=_loopback)
    assert not probe.success and probe.error_type == "ConnectionRefusedError"
