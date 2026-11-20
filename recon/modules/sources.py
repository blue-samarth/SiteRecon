'''
Shared plumbing for third-party discovery sources (CT logs, passive-DNS datasets, URL indexes).

Every source is a read-only GET against one allow-listed provider host, routed through the scope-restricted
client, and every failure mode — HTTP error, truncated body, unexpected shape — becomes a ``SourceError``
so one provider outage degrades coverage instead of failing the module. A source that needs a credential
declares it and is skipped with a clear reason rather than half-running.

Using any of these discloses the target domain to that provider, which is why the non-CT sources are
opt-in; see ``docs/passive-discovery.md``.
'''

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from typing import Any

from recon.utils import SafeHttpClient

# Response bodies larger than this are refused rather than parsed, so a provider cannot blow up memory.
MAX_SOURCE_BYTES: int = 25 * 1024 * 1024


class SourceError(Exception):
    '''
    Raised when a discovery source cannot return complete, usable results.
    '''


async def fetch_text(client: SafeHttpClient, url: str, *, headers: dict[str, str] | None = None) -> str:
    '''
    GET a URL and return its body as text, rejecting failures and truncated bodies.
    Parameters:
        client (SafeHttpClient): Client scoped to the provider host.
        url (str): URL to fetch.
        headers (dict[str, str] | None): Extra request headers (e.g. an Accept or API-key header).
    Returns:
        str: Decoded body.
    Raises:
        SourceError: On HTTP failure, truncation or a blocked destination.
    '''
    if headers:
        response = await client.request("GET", url, headers=headers)
        if response.status_code != 200:
            raise SourceError(f"HTTP {response.status_code}")
        if response.truncated:
            raise SourceError("response exceeded the size limit; results would be incomplete")
        return response.body.decode("utf-8", "replace")
    outcome = await client.fetch(url)
    resp = outcome.final
    if resp is None or resp.status_code != 200:
        status = resp.status_code if resp else None
        raise SourceError(outcome.error or outcome.stopped_reason or f"HTTP {status}")
    if resp.truncated:
        raise SourceError("response exceeded the size limit; results would be incomplete")
    return resp.body.decode("utf-8", "replace")


async def fetch_json(client: SafeHttpClient, url: str, *, headers: dict[str, str] | None = None) -> Any:
    '''
    GET a URL and decode a JSON document.
    Parameters:
        client (SafeHttpClient): Client scoped to the provider host.
        url (str): URL to fetch.
        headers (dict[str, str] | None): Extra request headers.
    Returns:
        Any: Decoded JSON.
    Raises:
        SourceError: On HTTP failure, truncation or invalid JSON.
    '''
    text = await fetch_text(client, url, headers=headers)
    try:
        return json.loads(text or "null")
    except json.JSONDecodeError as exc:
        raise SourceError(f"invalid JSON: {exc}") from exc


async def fetch_json_lines(client: SafeHttpClient, url: str, *,
                           headers: dict[str, str] | None = None) -> list[dict[str, Any]]:
    '''
    GET a newline-delimited JSON document (the CDX index format) and decode each object.

    Unparseable lines are skipped rather than failing the source: a CDX response can end mid-line when a
    provider truncates it, and the complete rows before that point are still usable.
    Parameters:
        client (SafeHttpClient): Client scoped to the provider host.
        url (str): URL to fetch.
        headers (dict[str, str] | None): Extra request headers.
    Returns:
        list[dict[str, Any]]: Decoded objects, in order.
    Raises:
        SourceError: On HTTP failure or truncation.
    '''
    text = await fetch_text(client, url, headers=headers)
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def parse_timestamp(value: Any) -> datetime | None:
    '''
    Parse a timestamp from provider data: ISO 8601, a CDX ``YYYYMMDDhhmmss`` stamp, or a unix epoch.

    Assumes UTC when no offset is present, so timestamps from different providers stay comparable.
    Parameters:
        value (Any): Raw timestamp value.
    Returns:
        datetime | None: The datetime in UTC, or None if unparseable.
    '''
    if value is None or value == "":
        return None
    text = str(value).strip()
    if text.isdigit():
        if len(text) == 14:                     # CDX: YYYYMMDDhhmmss
            try:
                return datetime.strptime(text, "%Y%m%d%H%M%S").replace(tzinfo=UTC)
            except ValueError:
                return None
        if len(text) == 8:                      # YYYYMMDD
            try:
                return datetime.strptime(text, "%Y%m%d").replace(tzinfo=UTC)
            except ValueError:
                return None
        if 9 <= len(text) <= 13:                # unix epoch (seconds or milliseconds)
            try:
                seconds = int(text) / (1000 if len(text) > 10 else 1)
                return datetime.fromtimestamp(seconds, UTC)
            except (ValueError, OSError, OverflowError):
                return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def credential(env_var: str) -> str | None:
    '''
    Read a provider credential from the environment, treating blank as absent.

    Credentials are only ever read here and sent as a request header to the provider that issued them;
    they are never logged, stored in a report, or included in an error message.
    Parameters:
        env_var (str): Environment variable name, e.g. 'SITERECON_BUFFEROVER_KEY'.
    Returns:
        str | None: The credential, or None when it is unset or empty.
    '''
    value = (os.environ.get(env_var) or "").strip()
    return value or None
