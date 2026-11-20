'''
HSTS preload list membership, answered offline from a bundled snapshot.

Whether a domain is in the browsers' HSTS preload list is a fact about a public file, not about the site,
so SiteRecon answers it from a vendored snapshot rather than asking a third party — the same reasoning
that puts the Public Suffix List in ``recon/data``. The alternative, querying hstspreload.org at scan
time, would disclose the target to Google for a question that needs no network at all.

Membership is not the same as eligibility, and the distinction matters in both directions:

* A domain can be **preloaded while its current header no longer qualifies** — once submitted, a browser
  upgrades requests regardless of what the site sends today, and removal takes months to reach users.
  That combination is worth reporting: the protection is real but undocumented by the site itself.
* A domain can be **eligible but absent**, which is the common case and simply means nobody submitted it.

The snapshot is a point-in-time copy, so a very recent submission can be absent from it. That limitation
travels with every finding rather than being smoothed over, and ``snapshot_date`` is recorded so a stale
bundle is visible in the report.
'''

from __future__ import annotations

import datetime as dt
import gzip
import threading
from dataclasses import dataclass
from pathlib import Path

DATA_FILE: Path = Path(__file__).resolve().parent.parent / "data" / "hsts_preload.txt.gz"
# Minimum plausible entry count; a snapshot far below this is truncated or corrupt and is refused rather
# than answered from, because a silently tiny list would report every domain as "not preloaded".
MIN_ENTRIES: int = 50_000


@dataclass(frozen=True, slots=True)
class PreloadStatus:
    '''
    The outcome of a preload-list lookup for one hostname.
    '''
    preloaded: bool
    matched_name: str | None = None      # the list entry that covered the hostname
    via_subdomains: bool = False         # True when an ancestor entry covered it, not an exact match
    snapshot_date: str | None = None     # retrieval date of the bundled snapshot
    entries: int = 0                     # entries in the snapshot the answer came from


@dataclass(slots=True)
class PreloadRules:
    '''
    Parsed preload snapshot: names covering their subdomains, and names preloaded exactly.
    '''
    with_subdomains: frozenset[str] = frozenset()
    exact_only: frozenset[str] = frozenset()
    snapshot_date: str | None = None

    def __len__(self) -> int:
        '''
        Total number of entries.
        Returns:
            int: Entries across both sets.
        '''
        return len(self.with_subdomains) + len(self.exact_only)


class HstsPreloadList:
    '''
    Matches hostnames against the bundled HSTS preload snapshot.
    '''

    _lock: threading.Lock = threading.Lock()
    _cache: dict[Path, HstsPreloadList] = {}

    def __init__(self, rules: PreloadRules) -> None:
        '''
        Create a matcher from parsed rules.
        Parameters:
            rules (PreloadRules): Parsed snapshot.
        '''
        self.rules = rules

    @classmethod
    def load(cls, path: Path | None = None) -> HstsPreloadList:
        '''
        Load (and cache) the bundled snapshot.
        Parameters:
            path (Path | None): Override the data file (tests).
        Returns:
            HstsPreloadList: Cached matcher.
        Raises:
            OSError: If the data file cannot be read.
            ValueError: If the snapshot holds implausibly few entries.
        '''
        target = (path or DATA_FILE).resolve()
        with cls._lock:
            if target not in cls._cache:
                cls._cache[target] = cls(cls.parse(gzip.decompress(target.read_bytes()).decode("utf-8")))
            return cls._cache[target]

    @staticmethod
    def parse(text: str) -> PreloadRules:
        '''
        Parse a snapshot: comment lines carry provenance, '!' marks an entry that excludes subdomains.
        Parameters:
            text (str): Decompressed snapshot contents.
        Returns:
            PreloadRules: Parsed rules.
        Raises:
            ValueError: If the snapshot holds implausibly few entries.
        '''
        covering: set[str] = set()
        exact: set[str] = set()
        snapshot_date: str | None = None
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                if line.startswith("# retrieved:"):
                    snapshot_date = line.split(":", 1)[1].strip() or None
                continue
            if line.startswith("!"):
                exact.add(line[1:])
            else:
                covering.add(line)
        rules = PreloadRules(frozenset(covering), frozenset(exact), snapshot_date)
        if len(rules) < MIN_ENTRIES:
            raise ValueError(f"HSTS preload snapshot holds only {len(rules)} entries "
                             f"(expected at least {MIN_ENTRIES}); refusing to answer from it")
        return rules

    def lookup(self, hostname: str) -> PreloadStatus:
        '''
        Whether a hostname is covered by the preload list.

        An exact entry wins over an ancestor, and the most specific ancestor wins over a broader one, so a
        name covered by both its own entry and a preloaded parent reports its own. Entries marked
        exact-only never cover descendants.
        Parameters:
            hostname (str): Hostname to test (case and trailing dot are ignored).
        Returns:
            PreloadStatus: The result, including which entry matched and how.
        '''
        name = hostname.strip().lower().strip(".")
        base = PreloadStatus(preloaded=False, snapshot_date=self.rules.snapshot_date,
                             entries=len(self.rules))
        if not name:
            return base
        if name in self.rules.exact_only or name in self.rules.with_subdomains:
            return PreloadStatus(True, name, False, self.rules.snapshot_date, len(self.rules))
        labels = name.split(".")
        for cut in range(1, len(labels)):                      # nearest ancestor first
            ancestor = ".".join(labels[cut:])
            if ancestor in self.rules.with_subdomains:
                return PreloadStatus(True, ancestor, True, self.rules.snapshot_date, len(self.rules))
        return base

    @property
    def stale_after_days(self) -> int | None:
        '''
        Age of the bundled snapshot in days, when it records a retrieval date.
        Returns:
            int | None: Days since the snapshot was taken, or None if undated.
        '''
        if not self.rules.snapshot_date:
            return None
        try:
            taken = dt.date.fromisoformat(self.rules.snapshot_date)
        except ValueError:
            return None
        return (dt.date.today() - taken).days


def preload_status(hostname: str, path: Path | None = None) -> PreloadStatus | None:
    '''
    Look up a hostname in the bundled HSTS preload snapshot.

    Returns None when the snapshot is missing or unusable, so a scan on an installation without the data
    file reports "not checked" rather than "not preloaded" — absence of data must never read as absence
    of protection.
    Parameters:
        hostname (str): Hostname to test.
        path (Path | None): Override the data file (tests).
    Returns:
        PreloadStatus | None: The lookup result, or None when no snapshot is available.
    '''
    try:
        return HstsPreloadList.load(path).lookup(hostname)
    except (OSError, ValueError, gzip.BadGzipFile):
        return None
