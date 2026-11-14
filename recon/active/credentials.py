from __future__ import annotations

import base64
import binascii
import json
import re

_B64URL: re.Pattern[str] = re.compile(r"^[A-Za-z0-9_-]+$")
_PRIVILEGED_JWT_ROLES: frozenset[str] = frozenset({"service_role"})


def reject_privileged_credential(credential: str | None) -> str | None:
    '''
    Decide whether a credential looks too privileged to be used in a read-access probe.

    A missing credential is fine (the open/unauthenticated case is a legitimate thing to test). A public
    anon/publishable key is fine. Anything that matches a known private-credential shape is refused.
    Parameters:
        credential (str | None): The credential an adapter would send.
    Returns:
        str | None: A human-readable reason it must not be used, or None if it is safe to test with.
    '''
    if not credential:
        return None
    value: str = credential.strip()
    if value.startswith("sb_secret_"):
        return "looks like a Supabase secret key (sb_secret_…); only a public/anon credential may be tested"
    if _looks_like_service_account(value):
        return "looks like a service-account JSON or private key block; only a public/anon credential may be tested"
    role: str = _jwt_role(value)
    if role in _PRIVILEGED_JWT_ROLES:
        return f"is a JWT with the privileged role '{role}'; only a public/anon credential may be tested"
    hit: str | None = _secret_scanner_hit(value)
    if hit is not None:
        return f"matches a known private-credential pattern ({hit}); only a public/anon credential may be tested"
    return None


def _looks_like_service_account(value: str) -> bool:
    '''
    Whether a value looks like a Google/Firebase service-account JSON or an embedded private key.
    Parameters:
        value (str): Candidate credential.
    Returns:
        bool: True if it carries service-account / private-key markers.
    '''
    lowered: str = value.lower()
    if '"type"' in lowered and "service_account" in lowered:
        return True
    if '"private_key"' in lowered:
        return True
    return "-----begin" in lowered and "private key-----" in lowered


def _jwt_role(token: str) -> str:
    '''
    Read a JWT's 'role' claim with strict structural checks and no signature verification.

    Mirrors the Supabase anon-key guard: a short or absent signature does not make a service_role token
    safe, so the signature length is not checked (unlike a pattern scan). Returns '' for a non-JWT value.
    Parameters:
        token (str): Candidate credential.
    Returns:
        str: The role claim, or '' if the token is not a decodable three-segment JWT.
    '''
    parts: list[str] = token.split(".")
    if len(parts) != 3 or not all(part and _B64URL.match(part) for part in parts):
        return ""
    try:
        payload: str = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, binascii.Error):
        return ""
    return str(claims.get("role", "")) if isinstance(claims, dict) else ""


def _secret_scanner_hit(value: str) -> str | None:
    '''
    Ask the passive SecretScanner whether a bare value matches a private-credential pattern.

    SecretScanner already excludes public-by-design values (pk_live_, anon JWTs, analytics ids) and maps a
    service_role JWT to a private type, so reusing it keeps one definition of "private credential".
    Parameters:
        value (str): Candidate credential.
    Returns:
        str | None: The matched credential type (e.g. 'stripe_secret_key'), or None.
    '''
    try:
        from recon.modules.javascript import SecretScanner
    except Exception:
        return None
    try:
        hits = SecretScanner.scan(value, "credential")
    except Exception:
        return None
    return hits[0].type if hits else None
