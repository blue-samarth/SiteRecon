#!/usr/bin/env python3
'''
Refresh the bundled HSTS preload snapshot from Chromium's source list.

The browser preload list is the authoritative answer to "is this domain preloaded", and it is a public
file — so SiteRecon answers the question offline from a bundled snapshot instead of asking a third party,
the same way it answers registrable-domain questions from the bundled Public Suffix List.

Chromium ships the list as ~10 MB of JSON-with-comments carrying fields SiteRecon does not need (policy
bucket, pinsets, expect-CT remnants). This reduces it to the two facts a membership test requires — the
name, and whether the entry covers subdomains — and writes them as a sorted, gzipped text file of roughly
600 KB.

Usage:
    python scripts/refresh_hsts_preload.py                      # download and write the snapshot
    python scripts/refresh_hsts_preload.py --from local.json    # transform an already-downloaded copy
    python scripts/refresh_hsts_preload.py --check              # report drift without writing

Format of recon/data/hsts_preload.txt.gz:
    # comment lines carry provenance (source, retrieval date, entry count)
    example.com        a name whose entry also covers its subdomains
    !example.org       a name preloaded exactly, subdomains not covered

Standard library only: this runs in CI or on a maintainer's machine, not inside a scan.
'''

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import json
import re
import sys
import urllib.request
from pathlib import Path

SOURCE_URL: str = ("https://raw.githubusercontent.com/chromium/chromium/main/net/http/"
                   "transport_security_state_static.json")
OUTPUT: Path = Path(__file__).resolve().parent.parent / "recon" / "data" / "hsts_preload.txt.gz"
# The file is JSON with // line comments, which json.loads rejects.
_COMMENT: re.Pattern[str] = re.compile(r"^\s*//.*$", re.MULTILINE)
# A sanity floor: the real list has ~95k entries, so anything far below that means a truncated download
# or an upstream format change, and must not silently replace a good snapshot.
MIN_ENTRIES: int = 50_000


def fetch(url: str) -> str:
    '''
    Download the Chromium list.
    Parameters:
        url (str): Source URL.
    Returns:
        str: Raw file contents.
    Raises:
        OSError: If the download fails.
    '''
    with urllib.request.urlopen(url, timeout=120) as response:
        return response.read().decode("utf-8")


def extract(raw: str) -> list[str]:
    '''
    Reduce the Chromium list to the lines SiteRecon stores.

    Only ``force-https`` entries are kept: those are the ones a browser upgrades. An entry that does not
    cover subdomains is prefixed with '!', mirroring the Public Suffix List's exception marker.
    Parameters:
        raw (str): Raw contents of transport_security_state_static.json.
    Returns:
        list[str]: Sorted lines, one per preloaded name.
    Raises:
        ValueError: If the file cannot be parsed or holds implausibly few entries.
        TypeError: If the upstream format no longer has an 'entries' list.
    '''
    try:
        data = json.loads(_COMMENT.sub("", raw))
    except json.JSONDecodeError as exc:
        raise ValueError(f"source is not parseable as JSON-with-comments: {exc}") from exc
    entries = data.get("entries")
    if not isinstance(entries, list):
        raise TypeError("source has no 'entries' list; the upstream format has changed")

    lines: set[str] = set()
    for entry in entries:
        name = str(entry.get("name", "")).strip().lower().strip(".")
        if not name or entry.get("mode") != "force-https":
            continue
        lines.add(name if entry.get("include_subdomains") else f"!{name}")
    if len(lines) < MIN_ENTRIES:
        raise ValueError(f"only {len(lines)} usable entries (expected at least {MIN_ENTRIES}); "
                         "refusing to replace the snapshot")
    return sorted(lines)


def render(lines: list[str], source: str, today: dt.date) -> bytes:
    '''
    Build the gzipped snapshot, provenance header included.
    Parameters:
        lines (list[str]): Extracted name lines.
        source (str): Source URL to record.
        today (dt.date): Retrieval date to record.
    Returns:
        bytes: Gzipped file contents.
    '''
    exact = sum(1 for line in lines if line.startswith("!"))
    header = [
        "# HSTS preload list, reduced to name + subdomain coverage.",
        f"# source: {source}",
        f"# retrieved: {today.isoformat()}",
        f"# entries: {len(lines)} ({len(lines) - exact} covering subdomains, {exact} exact-only)",
        "# a leading '!' means the entry does NOT cover subdomains.",
    ]
    body = "\n".join([*header, *lines]) + "\n"
    # mtime=0 keeps the output byte-identical for identical input, so a no-op refresh is a no-op commit.
    return gzip.compress(body.encode("utf-8"), compresslevel=9, mtime=0)


def main(argv: list[str] | None = None) -> int:
    '''
    Entry point.
    Parameters:
        argv (list[str] | None): Command-line arguments.
    Returns:
        int: Process exit code (0 unchanged/written, 1 drift found with --check, 2 on failure).
    '''
    parser = argparse.ArgumentParser(description="Refresh the bundled HSTS preload snapshot.")
    parser.add_argument("--from", dest="local", type=Path, help="transform this local JSON copy instead")
    parser.add_argument("--check", action="store_true", help="report whether the snapshot is stale; write nothing")
    parser.add_argument("--output", type=Path, default=OUTPUT, help=f"output path (default: {OUTPUT})")
    args = parser.parse_args(argv)

    try:
        raw = args.local.read_text(encoding="utf-8") if args.local else fetch(SOURCE_URL)
        lines = extract(raw)
    except (OSError, TypeError, ValueError) as exc:
        print(f"refresh failed: {exc}", file=sys.stderr)
        return 2

    rendered = render(lines, str(args.local) if args.local else SOURCE_URL, dt.date.today())
    previous = args.output.read_bytes() if args.output.exists() else b""
    if args.check:
        before = _names(previous)
        after = _names(rendered)
        if before == after:
            print(f"up to date: {len(after)} entries")
            return 0
        print(f"stale: {len(after - before)} added, {len(before - after)} removed "
              f"({len(before)} -> {len(after)} entries)")
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(rendered)
    print(f"wrote {args.output} — {len(lines)} entries, {len(rendered):,} bytes")
    return 0


def _names(blob: bytes) -> set[str]:
    '''
    The name lines inside a rendered snapshot, for drift comparison.
    Parameters:
        blob (bytes): Gzipped snapshot (empty when absent).
    Returns:
        set[str]: Name lines, comments excluded.
    '''
    if not blob:
        return set()
    text = gzip.decompress(blob).decode("utf-8")
    return {line for line in text.splitlines() if line and not line.startswith("#")}


if __name__ == "__main__":
    raise SystemExit(main())
