'''
Redaction of potentially sensitive values before they reach reports.
'''

from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED: str = "[REDACTED]"
_SENSITIVE_PARAM: re.Pattern[str] = re.compile(
    r"(token|key|secret|signature|sig|password|passwd|pwd|auth|session|credential|"
    r"expires|policy|code|jwt|bearer|apikey|access|refresh|x-amz-|x-goog-)",
    re.I,
)


def redact_url(url: str) -> str:
    '''
    Drop userinfo and replace values of sensitive-looking query parameters.
    Parameters:
        url (str): URL to redact.
    Returns:
        str: The redacted URL (unchanged if unparseable).
    '''
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    netloc = parts.hostname or ""
    if parts.port:
        netloc += f":{parts.port}"
    if not parts.query:
        return urlunsplit((parts.scheme, netloc, parts.path, "", ""))
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    cleaned = [(k, REDACTED if _SENSITIVE_PARAM.search(k) else v) for k, v in pairs]
    return urlunsplit((parts.scheme, netloc, parts.path, urlencode(cleaned, safe="[]"), ""))


def redact_secret(value: str, keep_prefix: int = 4) -> str:
    '''
    Replace a suspected secret with a non-reversible descriptor so the raw value never reaches a report.
    Parameters:
        value (str): The suspected secret value.
        keep_prefix (int): How many leading characters to keep as a hint (0 to keep none).
    Returns:
        str: e.g. 'sk_l…[REDACTED 32 chars sha256:1a2b3c4d]'. Short values keep no prefix.
    '''
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:8]
    prefix = value[:keep_prefix] if keep_prefix and len(value) > keep_prefix * 2 else ""
    hint = f"{prefix}…" if prefix else ""
    return f"{hint}[REDACTED {len(value)} chars sha256:{digest}]"
