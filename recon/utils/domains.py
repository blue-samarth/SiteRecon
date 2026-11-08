'''
Hostname helpers that do not need network access.
'''

from __future__ import annotations

from urllib.parse import urlsplit

from recon.utils.psl import PublicSuffixList
from recon.utils.psl import registrable_domain as _psl_registrable_domain


def registrable_domain(host: str, include_private: bool = False) -> str:
    '''
    Exact eTLD+1 using the bundled Public Suffix List (e.g. www.shop.example.co.uk → example.co.uk).
    Parameters:
        host (str): Hostname.
        include_private (bool): Also apply the PSL private section (e.g. treat 'github.io' as a suffix).
            Off by default so the result is the name registered with a registry, as RDAP/WHOIS expect.
    Returns:
        str: Registrable domain, or the host itself when it is a public suffix.
    '''
    return _psl_registrable_domain(host, include_private)


def public_suffix(host: str, include_private: bool = False) -> str | None:
    '''
    The public suffix of a hostname, per the bundled Public Suffix List.
    Parameters:
        host (str): Hostname.
        include_private (bool): Also apply the PSL private section.
    Returns:
        str | None: The public suffix, or None for an empty host.
    '''
    return PublicSuffixList.load(include_private).public_suffix(host)


def host_of(url: str) -> str | None:
    '''
    Return the lowercase hostname of a URL.
    Parameters:
        url (str): URL to parse.
    Returns:
        str | None: Hostname, or None if absent or unparseable.
    '''
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.lower().rstrip(".") if host else None


def matches_suffix(host: str, suffix: str) -> bool:
    '''
    Whether host equals suffix or is a subdomain of it.
    Parameters:
        host (str): Hostname to test.
        suffix (str): Domain suffix.
    Returns:
        bool: True on a label-boundary match.
    '''
    host, suffix = host.lower().rstrip("."), suffix.lower().rstrip(".")
    return host == suffix or host.endswith("." + suffix)


def normalize_discovered(name: str) -> tuple[str, bool] | None:
    '''
    Normalize a hostname found in external data.
    Parameters:
        name (str): Raw name, possibly '*.'-prefixed.
    Returns:
        tuple[str, bool] | None: (hostname, was_wildcard), or None if the name is not a usable hostname.
    '''
    name = name.strip().lower().rstrip(".")
    wildcard = name.startswith("*.")
    if wildcard:
        name = name[2:]
    if not name or " " in name or "@" in name or "*" in name or "." not in name:
        return None
    try:
        name = name.encode("idna").decode("ascii") if not name.isascii() else name
    except UnicodeError:
        return None
    return name, wildcard
