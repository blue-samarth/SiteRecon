'''
Target normalization and hostname validation.
'''

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

import idna

_LABEL: re.Pattern[str] = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class InvalidTargetError(ValueError):
    '''
    Raised when user input cannot be turned into a valid hostname.
    '''


def normalize_target(raw: str) -> str:
    '''
    Turn a domain or URL into a lowercase ASCII (punycode) hostname; IP literals are rejected.
    Parameters:
        raw (str): User-supplied domain or URL.
    Returns:
        str: Normalized hostname.
    Raises:
        InvalidTargetError: If the input is not a valid domain.
    '''
    candidate = (raw or "").strip()
    if not candidate:
        raise InvalidTargetError("target is empty")
    if "://" not in candidate:
        candidate = "//" + candidate

    try:
        parts = urlsplit(candidate)
    except ValueError as exc:
        raise InvalidTargetError(f"could not parse target: {exc}") from exc

    if parts.scheme and parts.scheme not in ("http", "https"):
        raise InvalidTargetError(f"unsupported scheme {parts.scheme!r}; use a domain or http(s) URL")

    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise InvalidTargetError("no hostname found in target")
    if _is_ip_literal(host):
        raise InvalidTargetError("IP addresses are not accepted; provide a domain name")

    try:
        ascii_host = idna.encode(host, uts46=True).decode("ascii")
    except idna.IDNAError as exc:
        raise InvalidTargetError(f"invalid hostname {host!r}: {exc}") from exc

    validate_hostname(ascii_host)
    return ascii_host


def validate_hostname(host: str) -> None:
    '''
    Validate hostname length and label syntax.
    Parameters:
        host (str): ASCII hostname.
    Raises:
        InvalidTargetError: If the hostname is invalid.
    '''
    if len(host) > 253:
        raise InvalidTargetError("hostname exceeds 253 characters")
    labels = host.split(".")
    if len(labels) < 2:
        raise InvalidTargetError(f"{host!r} is not a fully qualified domain name")
    for label in labels:
        if not _LABEL.match(label):
            raise InvalidTargetError(f"invalid hostname label {label!r} in {host!r}")
    if labels[-1].isdigit():
        raise InvalidTargetError(f"top-level label of {host!r} cannot be numeric")


def _is_ip_literal(host: str) -> bool:
    '''
    Whether the string is an IP address.
    Parameters:
        host (str): Candidate string.
    Returns:
        bool: True for IP literals.
    '''
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True
