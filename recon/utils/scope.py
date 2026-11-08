'''
Authorization scope and destination-safety checks (SSRF protection).
'''

from __future__ import annotations

import ipaddress
from collections.abc import Iterable


class Scope:
    '''
    Hostnames a client may contact: roots permit subdomains, hosts permit exact matches only.
    '''

    def __init__(self, roots: Iterable[str] = (), hosts: Iterable[str] = ()) -> None:
        '''
        Create a scope.
        Parameters:
            roots (Iterable[str]): Domains permitted together with all subdomains.
            hosts (Iterable[str]): Hostnames permitted exactly.
        '''
        self.roots = frozenset(_clean(r) for r in roots)
        self.hosts = frozenset(_clean(h) for h in hosts)

    @classmethod
    def for_target(cls, hostname: str) -> Scope:
        '''
        Scope covering a target and its subdomains.
        Parameters:
            hostname (str): Normalized target hostname.
        Returns:
            Scope: The scope.
        '''
        return cls(roots=[hostname])

    def allows(self, host: str | None) -> bool:
        '''
        Whether a hostname is inside the scope.
        Parameters:
            host (str | None): Hostname to test.
        Returns:
            bool: True if permitted.
        '''
        if not host:
            return False
        host = _clean(host)
        if host in self.hosts:
            return True
        return any(host == root or host.endswith("." + root) for root in self.roots)

    def describe(self) -> list[str]:
        '''
        Human-readable list of permitted patterns.
        Returns:
            list[str]: Sorted patterns.
        '''
        return sorted([f"*.{r}" for r in self.roots] + list(self.roots) + list(self.hosts))


def _clean(host: str) -> str:
    '''
    Normalize a hostname for comparison.
    Parameters:
        host (str): Hostname.
    Returns:
        str: Lowercase hostname without trailing dot.
    '''
    return host.strip().lower().rstrip(".")


def is_public_ip(ip: str) -> bool:
    '''
    True only for globally routable unicast addresses (blocks loopback, private, link-local/metadata, ULA, multicast).
    Parameters:
        ip (str): Address string (zone IDs allowed).
    Returns:
        bool: Whether the address is public.
    '''
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast
