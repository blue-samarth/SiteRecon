import pytest

from recon.utils.scope import Scope, is_public_ip
from recon.utils.validators import InvalidTargetError, normalize_target


@pytest.mark.parametrize("raw, expected", [
    ("example.io", "example.io"),
    ("EXAMPLE.IO", "example.io"),
    ("  example.io.  ", "example.io"),
    ("https://example.io/path?q=1#frag", "example.io"),
    ("http://user:pw@www.example.io:8080/x", "www.example.io"),
    ("example.io/some/path", "example.io"),
    ("bücher.de", "xn--bcher-kva.de"),
    ("xn--bcher-kva.de", "xn--bcher-kva.de"),
])
def test_normalize_valid(raw, expected):
    assert normalize_target(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "   ", "localhost", "192.168.1.1", "http://[::1]/", "ftp://example.com",
    "exa mple.com", "-bad.com", "bad-.com", "under_score.com", "example.123",
    "a" * 64 + ".com", ".".join(["a" * 60] * 5),
])
def test_normalize_invalid(raw):
    with pytest.raises(InvalidTargetError):
        normalize_target(raw)


def test_scope_allows_root_and_subdomains_only():
    scope = Scope.for_target("example.io")
    assert scope.allows("example.io")
    assert scope.allows("www.example.io")
    assert scope.allows("A.B.EXAMPLE.IO.")
    assert not scope.allows("evil-example.io")
    assert not scope.allows("example.io.evil.com")
    assert not scope.allows(None)


def test_scope_exact_hosts():
    scope = Scope(hosts=["rdap.org"])
    assert scope.allows("rdap.org")
    assert not scope.allows("x.rdap.org")


@pytest.mark.parametrize("ip, public", [
    ("93.184.216.34", True),
    ("2606:4700::6810:84e5", True),
    ("127.0.0.1", False),
    ("10.0.0.5", False),
    ("172.16.3.4", False),
    ("192.168.0.1", False),
    ("100.64.0.1", False),         # CGNAT
    ("169.254.169.254", False),    # cloud metadata
    ("::1", False),
    ("fe80::1%en0", False),
    ("fd00:ec2::254", False),      # AWS IPv6 metadata (ULA)
    ("::ffff:127.0.0.1", False),   # IPv4-mapped loopback
    ("224.0.0.1", False),
    ("0.0.0.0", False),
    ("not-an-ip", False),
])
def test_is_public_ip(ip, public):
    assert is_public_ip(ip) is public
