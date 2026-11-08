'''
DNS reconnaissance: record collection, SPF evaluation (with lookup counting), DMARC and DKIM
parsing, and CAA policy discovery including inherited parent policies.
'''

from __future__ import annotations

import asyncio
import base64
import binascii
import re
from typing import ClassVar

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

from recon.models import (
    CaaAnalysis,
    CollectionError,
    DkimSelectorResult,
    DmarcAnalysis,
    DnsData,
    DnsQueryResult,
    DnsQueryStatus,
    EmailSecurity,
    SpfAnalysis,
    SpfRecord,
)
from recon.modules.base import Collector
from recon.utils import DnsClient, registrable_domain


class DnsCollector(Collector[DnsData]):
    '''
    Queries every record type, DMARC and predefined DKIM selectors for the target, then evaluates
    SPF lookups and the effective CAA policy.
    '''

    name: ClassVar[str] = "dns"
    RECORD_TYPES: ClassVar[tuple[str, ...]] = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "CNAME")
    SPF_LOOKUP_LIMIT: ClassVar[int] = 10   # RFC 7208 §4.6.4
    SPF_VOID_LIMIT: ClassVar[int] = 2
    SPF_MECHANISMS: ClassVar[frozenset[str]] = frozenset({"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"})
    _SPF_NEEDS_ARG: ClassVar[frozenset[str]] = frozenset({"include", "ip4", "ip6", "exists"})

    def __init__(self, hostname: str, client: DnsClient, dkim_selectors: tuple[str, ...] = ()) -> None:
        '''
        Create the collector.
        Parameters:
            hostname (str): Normalized target hostname.
            client (DnsClient): DNS client used for queries.
            dkim_selectors (tuple[str, ...]): DKIM selectors to probe.
        '''
        self.hostname = hostname
        self.client = client
        self.dkim_selectors = dkim_selectors

    async def collect(self) -> tuple[DnsData, list[CollectionError]]:
        '''
        Query every record type, DMARC and DKIM selectors concurrently, then evaluate SPF and CAA.
        Returns:
            tuple[DnsData, list[CollectionError]]: DNS observations and errors for inconclusive queries (timeouts, SERVFAIL).
        '''
        host = self.hostname
        jobs: dict[str, asyncio.Task[DnsQueryResult]] = {}
        async with asyncio.TaskGroup() as tg:
            for rtype in self.RECORD_TYPES:
                jobs[rtype] = tg.create_task(self.client.query(host, rtype))
            jobs["DMARC"] = tg.create_task(self.client.query(f"_dmarc.{host}", "TXT"))
            if not host.startswith("www."):
                jobs["CNAME(www)"] = tg.create_task(self.client.query(f"www.{host}", "CNAME"))
            dkim_jobs = {sel: tg.create_task(self.client.query(f"{sel}._domainkey.{host}", "TXT"))
                         for sel in self.dkim_selectors}

        queries: dict[str, DnsQueryResult] = {key: job.result() for key, job in jobs.items()}
        dkim_results: dict[str, DnsQueryResult] = {sel: job.result() for sel, job in dkim_jobs.items()}

        spf = self.parse_spf(queries["TXT"])
        caa = await self._climb_caa(queries["CAA"])
        await self._evaluate_spf(spf)

        errors: list[CollectionError] = [
            self.error(f"{q.name} {q.record_type}", q.status.value, q.error or q.status.value)
            for q in [*queries.values(), *dkim_results.values()]
            if not q.status.is_definitive
        ]
        email = EmailSecurity(
            spf=spf,
            dmarc=self.parse_dmarc(queries["DMARC"]),
            dkim_selectors_checked=list(self.dkim_selectors),
            dkim_found=[self.parse_dkim(sel, q) for sel, q in dkim_results.items() if self._first_dkim(q)],
        )
        return DnsData(hostname=host, queries=queries, email=email, caa=caa), errors

    # ------------------------------------------------------------------ SPF

    @classmethod
    def parse_spf(cls, txt: DnsQueryResult) -> SpfAnalysis:
        '''
        Extract and parse SPF records from a TXT query.
        Parameters:
            txt (DnsQueryResult): TXT query result for the domain.
        Returns:
            SpfAnalysis: SPF records found, with the lookup status.
        '''
        records = [cls.parse_spf_record(v) for v in txt.values if v.strip().lower().startswith("v=spf1")]
        # "v=spf1x" is not SPF; require the version token to stand alone.
        records = [r for r in records if r.raw.split()[0].lower() == "v=spf1"]
        return SpfAnalysis(lookup_status=txt.status, records=records)

    @classmethod
    def parse_spf_record(cls, raw: str) -> SpfRecord:
        '''
        Parse one SPF record into mechanisms, includes, redirect, 'all' qualifier and parse errors.
        Parameters:
            raw (str): Raw record text starting with 'v=spf1'.
        Returns:
            SpfRecord: The parsed record.
        '''
        terms = raw.split()[1:]
        includes: list[str] = []
        errors: list[str] = []
        redirect: str | None = None
        all_qualifier: str | None = None
        uses_ptr = False
        for term in terms:
            lowered = term.lower()
            qualifier, body = (lowered[0], lowered[1:]) if lowered[:1] in "+-~?" else ("+", lowered)
            name = re.split(r"[:/=]", body, maxsplit=1)[0]
            if "=" in body and name not in cls.SPF_MECHANISMS:  # modifier
                if name == "redirect":
                    redirect = body.split("=", 1)[1]
                elif not re.fullmatch(r"[a-z][a-z0-9_.-]*", name):
                    errors.append(f"malformed modifier {term!r}")
                continue
            if name not in cls.SPF_MECHANISMS:
                errors.append(f"unknown mechanism {term!r}")
                continue
            if name in cls._SPF_NEEDS_ARG and not body.partition(":")[2]:
                errors.append(f"{name} without argument {term!r}")
                continue
            if name == "all":
                all_qualifier = qualifier
            elif name == "include":
                includes.append(body.split(":", 1)[1])
            elif name == "ptr":
                uses_ptr = True
        return SpfRecord(raw=raw, mechanisms=terms, includes=includes, redirect=redirect,
                         all_qualifier=all_qualifier, parse_errors=errors, uses_ptr=uses_ptr)

    async def _evaluate_spf(self, spf: SpfAnalysis) -> None:
        '''
        Count DNS-querying SPF terms through include/redirect chains (RFC 7208 §4.6.4).
        Evaluation is skipped unless exactly one SPF record exists (otherwise SPF is a permerror anyway).
        Parameters:
            spf (SpfAnalysis): Analysis to update in place.
        '''
        if len(spf.records) != 1:
            return
        state = {"count": 0, "void": 0}
        await self._walk_spf(spf.records[0], 0, state, spf, {self.hostname})
        spf.lookup_count = state["count"]
        spf.void_lookups = state["void"]
        spf.lookup_limit_exceeded = state["count"] > self.SPF_LOOKUP_LIMIT or state["void"] > self.SPF_VOID_LIMIT

    async def _walk_spf(self, record: SpfRecord, depth: int, state: dict[str, int],
                        spf: SpfAnalysis, seen: set[str]) -> None:
        '''
        Recursively count lookups for one record, recording a readable lookup tree.
        Parameters:
            record (SpfRecord): Record being evaluated.
            depth (int): Include/redirect nesting depth.
            state (dict[str, int]): Running 'count' and 'void' totals, updated in place.
            spf (SpfAnalysis): Analysis receiving the tree and evaluation errors.
            seen (set[str]): Domains already on this include path (loop protection).
        '''
        indent = "  " * depth
        for term in record.mechanisms:
            body = term.lstrip("+-~?").lower()
            name = re.split(r"[:/=]", body, maxsplit=1)[0]
            if name in ("a", "mx", "ptr", "exists"):
                state["count"] += 1
                continue
            if name not in ("include", "redirect"):
                continue
            state["count"] += 1
            target = body.split(":" if name == "include" else "=", 1)[1] if (":" in body or "=" in body) else ""
            if not target or "%" in target:
                spf.evaluation_errors.append(f"cannot follow {term!r} (macro or empty target)")
                continue
            if target in seen:
                spf.evaluation_errors.append(f"include loop via {target}")
                continue
            if depth >= self.SPF_LOOKUP_LIMIT or state["count"] > self.SPF_LOOKUP_LIMIT:
                spf.evaluation_errors.append("lookup limit exceeded; evaluation stopped")
                return
            q = await self.client.query(target, "TXT")
            if not q.status.is_definitive:
                spf.evaluation_errors.append(f"{target}: lookup {q.status.value}")
                continue
            sub = [v for v in q.values if v.strip().lower() == "v=spf1" or v.strip().lower().startswith("v=spf1 ")]
            if not sub:
                state["void"] += 1
                spf.lookup_tree.append(f"{indent}{name}:{target} (no SPF record — void lookup)")
                continue
            before = state["count"]
            slot = len(spf.lookup_tree)
            spf.lookup_tree.append("")
            await self._walk_spf(self.parse_spf_record(sub[0]), depth + 1, state, spf, seen | {target})
            spf.lookup_tree[slot] = f"{indent}{name}:{target} (+{state['count'] - before} nested)"

    # ------------------------------------------------------------------ DMARC / DKIM

    @classmethod
    def parse_dmarc(cls, txt: DnsQueryResult) -> DmarcAnalysis:
        '''
        Parse the DMARC record; tags are parsed only when exactly one record exists.
        Parameters:
            txt (DnsQueryResult): TXT query result for _dmarc.<domain>.
        Returns:
            DmarcAnalysis: The DMARC analysis.
        '''
        raws = [v for v in txt.values if v.strip().lower().startswith("v=dmarc1")]
        result = DmarcAnalysis(name=txt.name, lookup_status=txt.status, raw_records=raws)
        if len(raws) != 1:
            return result  # zero or several records: receivers ignore DMARC (RFC 7489 §6.6.3)
        tags = cls._tags(raws[0])
        result.tags = tags
        result.policy = tags.get("p", "").lower() or None
        result.subdomain_policy = tags.get("sp", "").lower() or None
        pct = tags.get("pct")
        result.pct = int(pct) if pct and pct.isdigit() else None
        result.adkim = tags.get("adkim", "").lower() or None
        result.aspf = tags.get("aspf", "").lower() or None
        result.fo = tags.get("fo") or None
        result.rua = cls._split_uris(tags.get("rua"))
        result.ruf = cls._split_uris(tags.get("ruf"))
        return result

    @classmethod
    def parse_dkim(cls, selector: str, q: DnsQueryResult) -> DkimSelectorResult:
        '''
        Parse a DKIM key record: key type, key size and revocation (empty p=).
        Parameters:
            selector (str): Selector that was queried.
            q (DnsQueryResult): TXT query result for <selector>._domainkey.<domain>.
        Returns:
            DkimSelectorResult: Parsed selector result.
        '''
        record = cls._first_dkim(q) or ""
        tags = cls._tags(record)
        key_b64 = re.sub(r"\s+", "", tags.pop("p", ""))
        key_type = tags.get("k", "rsa").lower()
        result = DkimSelectorResult(selector=selector, name=q.name, status=q.status, record=record,
                                    key_type=key_type, revoked=key_b64 == "", tags=tags)
        if key_b64:
            try:
                raw = base64.b64decode(key_b64, validate=False)
                if key_type == "ed25519":
                    result.key_bits = 256 if len(raw) == 32 else None
                else:
                    key = load_der_public_key(raw)
                    result.key_bits = key.key_size if isinstance(key, rsa.RSAPublicKey) else None
            except (ValueError, binascii.Error, TypeError):
                result.key_bits = None
        return result

    @staticmethod
    def _tags(record: str) -> dict[str, str]:
        '''
        Split a 'k=v; k=v' tag list (DMARC, DKIM).
        Parameters:
            record (str): Raw record.
        Returns:
            dict[str, str]: Lowercase tag name to stripped value.
        '''
        tags: dict[str, str] = {}
        for part in record.split(";"):
            if "=" in part:
                key, value = part.split("=", 1)
                tags[key.strip().lower()] = value.strip()
        return tags

    @staticmethod
    def _split_uris(value: str | None) -> list[str]:
        '''
        Split a comma-separated DMARC URI list.
        Parameters:
            value (str | None): Raw rua/ruf tag value.
        Returns:
            list[str]: Individual URIs.
        '''
        return [u.strip() for u in value.split(",") if u.strip()] if value else []

    @staticmethod
    def _first_dkim(q: DnsQueryResult) -> str | None:
        '''
        Return the first value that looks like a DKIM key record.
        Parameters:
            q (DnsQueryResult): TXT query result for a selector.
        Returns:
            str | None: The record, or None.
        '''
        if q.status is not DnsQueryStatus.NOERROR:
            return None
        for value in q.values:
            lowered = value.lower().replace(" ", "")
            if "v=dkim1" in lowered or "p=" in lowered:
                return value
        return None

    # ------------------------------------------------------------------ CAA

    async def _climb_caa(self, host_q: DnsQueryResult) -> CaaAnalysis:
        '''
        Find the CAA set in effect: the hostname's own, else the closest parent's (up to the registrable domain).
        Parameters:
            host_q (DnsQueryResult): CAA query result for the hostname itself.
        Returns:
            CaaAnalysis: Effective policy, whether it is inherited, and every name checked.
        '''
        result = CaaAnalysis(checked={self.hostname: host_q.status.value})
        if host_q.status is DnsQueryStatus.NOERROR and host_q.values:
            result.effective_name, result.records = self.hostname, host_q.values
            return result
        if not host_q.status.is_definitive:
            result.complete = False
            return result
        labels = self.hostname.split(".")
        stop = registrable_domain(self.hostname)
        parents = [".".join(labels[i:]) for i in range(1, len(labels))]
        for name in parents[: parents.index(stop) + 1] if stop in parents else []:
            q = await self.client.query(name, "CAA")
            result.checked[name] = q.status.value
            if q.status is DnsQueryStatus.NOERROR and q.values:
                result.effective_name, result.records, result.inherited = name, q.values, True
                break
            if not q.status.is_definitive:
                result.complete = False
                break
        return result
