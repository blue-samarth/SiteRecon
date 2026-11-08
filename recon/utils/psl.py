'''
Public Suffix List lookups.

Implements the publicsuffix.org matching algorithm against a bundled snapshot of the list, so
registrable-domain ('eTLD+1') calculation is exact and works offline. ICANN rules are used by
default: that makes the registrable domain the name actually registered with a registry, which is
what RDAP and WHOIS expect. The private section (e.g. 'github.io', 'vercel.app') can be enabled
when the goal is grouping delegated namespaces rather than finding the registrant.
'''

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import idna

DATA_FILE: Path = Path(__file__).resolve().parent.parent / "data" / "public_suffix_list.dat"
ICANN_BEGIN: str = "===BEGIN ICANN DOMAINS==="
ICANN_END: str = "===END ICANN DOMAINS==="


@dataclass(slots=True)
class PslRules:
    '''
    Parsed Public Suffix List rules.
    '''
    exact: set[str] = field(default_factory=set)       # 'com', 'co.uk'
    wildcard: set[str] = field(default_factory=set)    # '*.ck' stored as 'ck'
    exception: set[str] = field(default_factory=set)   # '!www.ck' stored as 'www.ck'

    def __len__(self) -> int:
        '''
        Total number of rules.
        Returns:
            int: Count of exact, wildcard and exception rules.
        '''
        return len(self.exact) + len(self.wildcard) + len(self.exception)


class PublicSuffixList:
    '''
    Matches hostnames against the Public Suffix List.
    '''

    _lock: threading.Lock = threading.Lock()
    _cache: dict[bool, PublicSuffixList] = {}

    def __init__(self, rules: PslRules) -> None:
        '''
        Create a matcher from parsed rules.
        Parameters:
            rules (PslRules): Parsed rule sets.
        '''
        self.rules = rules

    @classmethod
    def load(cls, include_private: bool = False, path: Path | None = None) -> PublicSuffixList:
        '''
        Load (and cache) the bundled list.
        Parameters:
            include_private (bool): Also apply the PRIVATE section (delegated namespaces).
            path (Path | None): Override the data file (tests).
        Returns:
            PublicSuffixList: Cached matcher.
        Raises:
            OSError: If the data file cannot be read.
        '''
        if path is not None:
            return cls(cls.parse(path.read_text(encoding="utf-8"), include_private))
        with cls._lock:
            if include_private not in cls._cache:
                text = DATA_FILE.read_text(encoding="utf-8")
                cls._cache[include_private] = cls(cls.parse(text, include_private))
            return cls._cache[include_private]

    @staticmethod
    def parse(text: str, include_private: bool = False) -> PslRules:
        '''
        Parse list text into rule sets, converting internationalized rules to punycode.
        Parameters:
            text (str): Contents of public_suffix_list.dat.
            include_private (bool): Include rules after the ICANN section.
        Returns:
            PslRules: Parsed rules.
        '''
        rules = PslRules()
        in_icann = False
        seen_icann_marker = False
        for raw in text.splitlines():
            line = raw.strip()
            if line.startswith("//"):
                if ICANN_BEGIN in line:
                    in_icann, seen_icann_marker = True, True
                elif ICANN_END in line:
                    in_icann = False
                continue
            if not line:
                continue
            # Before any marker treat rules as ICANN; after the ICANN section they are private.
            if seen_icann_marker and not in_icann and not include_private:
                continue
            rule = line.split()[0]
            exception = rule.startswith("!")
            rule = rule.removeprefix("!")
            normalized = PublicSuffixList._to_ascii(rule)
            if normalized is None:
                continue
            if exception:
                rules.exception.add(normalized)
            elif normalized.startswith("*."):
                rules.wildcard.add(normalized[2:])
            else:
                rules.exact.add(normalized)
        return rules

    @staticmethod
    def _to_ascii(rule: str) -> str | None:
        '''
        Convert a rule to lowercase punycode so it matches IDNA-encoded hostnames.
        Parameters:
            rule (str): Rule text, possibly containing non-ASCII labels.
        Returns:
            str | None: ASCII rule, or None if a label cannot be encoded.
        '''
        rule = rule.lower().strip(".")
        if rule.isascii():
            return rule or None
        labels = []
        for label in rule.split("."):
            if label == "*":
                labels.append(label)
                continue
            try:
                labels.append(idna.encode(label, uts46=True).decode("ascii") if not label.isascii() else label)
            except idna.IDNAError:
                return None
        return ".".join(labels)

    def public_suffix(self, host: str) -> str | None:
        '''
        The public suffix of a hostname (the part under which names are registered).
        Parameters:
            host (str): Hostname (punycode/ASCII, any case).
        Returns:
            str | None: The public suffix, or None for an empty host.
        '''
        labels = [part for part in host.lower().strip(".").split(".") if part]
        if not labels:
            return None
        best = 0
        for i in range(len(labels)):
            candidate = ".".join(labels[i:])
            if candidate in self.rules.exception:
                return ".".join(labels[i + 1:])        # exceptions outrank every other rule
            if candidate in self.rules.exact:
                best = max(best, len(labels) - i)
            elif i + 1 < len(labels) and ".".join(labels[i + 1:]) in self.rules.wildcard:
                best = max(best, len(labels) - i)
        return ".".join(labels[len(labels) - best:]) if best else labels[-1]   # default rule is '*'

    def registrable_domain(self, host: str) -> str | None:
        '''
        The registrable domain ('eTLD+1'): the public suffix plus one more label.
        Parameters:
            host (str): Hostname (punycode/ASCII, any case).
        Returns:
            str | None: The registrable domain, or None if the host is itself a public suffix.
        '''
        labels = [part for part in host.lower().strip(".").split(".") if part]
        suffix = self.public_suffix(host)
        if suffix is None:
            return None
        suffix_labels = suffix.split(".")
        if len(labels) <= len(suffix_labels):
            return None                                 # host is a public suffix, not registrable
        return ".".join(labels[len(labels) - len(suffix_labels) - 1:])


@lru_cache(maxsize=4096)
def registrable_domain(host: str, include_private: bool = False) -> str:
    '''
    Registrable domain via the Public Suffix List, falling back to the host itself when it is a
    public suffix (or when the bundled list cannot be read).
    Parameters:
        host (str): Hostname.
        include_private (bool): Apply the PRIVATE section as well as ICANN rules.
    Returns:
        str: Registrable domain, or the normalized host when none applies.
    '''
    cleaned = host.lower().strip(".")
    try:
        result = PublicSuffixList.load(include_private).registrable_domain(cleaned)
    except OSError:
        labels = cleaned.split(".")
        return ".".join(labels[-2:]) if len(labels) > 2 else cleaned
    return result or cleaned
