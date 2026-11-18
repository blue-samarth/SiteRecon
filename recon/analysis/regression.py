from __future__ import annotations

from datetime import datetime
from typing import Any

from recon.analysis.findings import LIMITATIONS, RECOMMENDATIONS, _CATEGORY_MODULES, lookup_text
from recon.models import (
    Change,
    ChangeKind,
    ComparisonResult,
    Confidence,
    DnssecStatus,
    Finding,
    FindingDelta,
    FindingState,
    ModuleStatus,
    ReconReport,
    Severity,
)

_RAN_OK: tuple[ModuleStatus, ...] = (ModuleStatus.SUCCESS, ModuleStatus.PARTIAL)
S, C = Severity, Confidence

# TLS/SSL version ordering, so a MODIFIED tls.protocol can be read as an upgrade or a downgrade.
_TLS_RANK: dict[str, int] = {"SSLv2": 0, "SSLv3": 1, "TLSv1": 2, "TLSv1.0": 2, "TLSv1.1": 3, "TLSv1.2": 4,
                             "TLSv1.3": 5}
# Security headers whose removal is a meaningful regression (others are flagged at low severity).
_IMPORTANT_HEADERS: frozenset[str] = frozenset({"strict-transport-security", "content-security-policy"})
# DNSSEC statuses that mean the zone is signed; a move from any of these to UNSIGNED is DNSSEC being turned off.
_DNSSEC_SIGNED: frozenset[str] = frozenset({DnssecStatus.SIGNED_VALIDATED.value,
                                            DnssecStatus.SIGNED_UNVALIDATED.value})
# Change kinds a drop can present as: a key that vanished (REMOVED) or whose value went to absent (MODIFIED).
# The observation builder records absent headers/CAA with an empty value on every probe, so a dropped value
# is usually MODIFIED, not REMOVED — matching on the kind alone misses it.
_DROP_KINDS: tuple[ChangeKind, ...] = (ChangeKind.MODIFIED, ChangeKind.REMOVED)


class ChangeAnalyzer:
    '''
    Interprets the observation-level comparison into explicit before/after regression findings.

    Where RegressionAnalyzer tracks whole findings appearing and disappearing, this reads individual
    observation changes and names the security-relevant transitions — a removed security header, a weakened
    cookie, a TLS downgrade, DNSSEC turned off — with the previous and current values in the evidence. These
    are transient (they fire on the scan where the change happened), category ``regression``, and are added
    to the findings list so they show in the report and can gate CI.
    '''

    @classmethod
    def analyze(cls, comparison: ComparisonResult, timestamp: datetime) -> list[Finding]:
        '''
        Produce regression findings for the security-relevant changes in a comparison.
        Parameters:
            comparison (ComparisonResult): The observation-level diff vs the previous scan.
            timestamp (datetime): Timestamp to stamp on the findings.
        Returns:
            list[Finding]: Interpreted change findings (possibly empty).
        '''
        out: list[Finding] = []
        for change in comparison.changes:
            finding = cls._interpret(change, timestamp)
            if finding is not None:
                out.append(finding)
        return out

    @classmethod
    def _interpret(cls, change: Change, timestamp: datetime) -> Finding | None:
        '''
        Turn one observation change into a regression finding, or None if it is not security-relevant.
        Parameters:
            change (Change): One observation change.
            timestamp (datetime): Timestamp for the finding.
        Returns:
            Finding | None: The interpreted finding, or None.
        '''
        handler = {
            "http.security_header": cls._security_header,
            "cookie": cls._cookie,
            "tls.protocol": cls._tls,
            "dnssec.status": cls._dnssec,
            "dns.caa_effective": cls._caa,
            "subdomain": cls._subdomain,
        }.get(change.type)
        return handler(change, timestamp) if handler else None

    @classmethod
    def _finding(cls, code: str, change: Change, *, title: str, description: str, severity: Severity,
                 timestamp: datetime, evidence: list[str], confidence: Confidence = C.HIGH) -> Finding:
        '''
        Build a regression finding with recommendation/limitations from the central tables.
        '''
        subject = f"{change.target}:{change.key}" if change.key else change.target
        return Finding(
            id=f"{code}:{subject}", category="regression", title=title, description=description,
            severity=severity, confidence=confidence, evidence=evidence,
            source="change since the previous scan", subject=change.target, timestamp=timestamp,
            recommendation=lookup_text(RECOMMENDATIONS, code), limitations=lookup_text(LIMITATIONS, code))

    @classmethod
    def _security_header(cls, change: Change, timestamp: datetime) -> Finding | None:
        # A header the builder records on every probe (value None when absent) drops as MODIFIED, not REMOVED;
        # fire on present-then-absent regardless of which kind the comparator assigned.
        if change.kind not in _DROP_KINDS or change.previous is None or change.current is not None:
            return None
        important = change.key in _IMPORTANT_HEADERS
        return cls._finding(
            "regression.security_header_removed", change, timestamp=timestamp,
            title=f"Security header removed: {change.key}",
            description=f"The '{change.key}' response header was present in the previous scan and is now "
                        "absent. A security header that disappears is a posture regression; confirm it was "
                        "removed intentionally.",
            severity=S.MEDIUM if important else S.LOW,
            evidence=[f"{change.key}: present → absent", f"was: {change.previous!r}"])

    @classmethod
    def _cookie(cls, change: Change, timestamp: datetime) -> Finding | None:
        if change.kind is not ChangeKind.MODIFIED:
            return None
        prev, cur = change.previous or {}, change.current or {}
        dropped = [a for a in ("secure", "http_only") if _truthy(prev, a) and not _truthy(cur, a)]
        if not dropped:
            return None
        return cls._finding(
            "regression.cookie_weakened", change, timestamp=timestamp,
            title="Cookie security attribute dropped",
            description=f"A cookie lost the {', '.join(dropped)} attribute(s) it had in the previous scan, "
                        "weakening its protection.",
            severity=S.MEDIUM, evidence=[f"dropped: {', '.join(dropped)}", f"was: {prev}", f"now: {cur}"])

    @classmethod
    def _tls(cls, change: Change, timestamp: datetime) -> Finding | None:
        if change.kind is not ChangeKind.MODIFIED:
            return None
        prev_rank = _TLS_RANK.get(str(change.previous), -1)
        cur_rank = _TLS_RANK.get(str(change.current), -1)
        if prev_rank < 0 or cur_rank < 0 or cur_rank >= prev_rank:
            return None   # only a genuine downgrade is a regression
        return cls._finding(
            "regression.tls_downgrade", change, timestamp=timestamp, title="Negotiated TLS version downgraded",
            description=f"The negotiated TLS version dropped from {change.previous} to {change.current} since "
                        "the previous scan. A lower version is weaker; confirm this was intended.",
            severity=S.MEDIUM, evidence=[f"{change.previous} → {change.current}"])

    @classmethod
    def _dnssec(cls, change: Change, timestamp: datetime) -> Finding | None:
        # Values are DnssecStatus members (signed_validated / signed_unvalidated / unsigned / …), not
        # "signed"/"unsigned"; a signed zone going UNSIGNED is DNSSEC being turned off.
        if change.kind is not ChangeKind.MODIFIED or str(change.previous) not in _DNSSEC_SIGNED \
                or str(change.current) != DnssecStatus.UNSIGNED.value:
            return None
        return cls._finding(
            "regression.dnssec_disabled", change, timestamp=timestamp, title="DNSSEC no longer signed",
            description=f"The zone was '{change.previous}' in the previous scan and is now "
                        f"'{change.current}'. DNSSEC appears to have been turned off.",
            severity=S.MEDIUM, evidence=[f"{change.previous} → {change.current}"])

    @classmethod
    def _caa(cls, change: Change, timestamp: datetime) -> Finding | None:
        # dns.caa_effective is recorded whenever the lookup completed (records: [] when none), so dropping a
        # CAA policy is a MODIFIED value with emptied records, not a REMOVED key. Fire on records → empty.
        if change.kind not in _DROP_KINDS or not _caa_records(change.previous) or _caa_records(change.current):
            return None
        return cls._finding(
            "regression.caa_removed", change, timestamp=timestamp, title="CAA policy removed",
            description="A CAA policy that was in effect in the previous scan is now absent, widening which "
                        "certificate authorities may issue for the domain.",
            severity=S.LOW, evidence=["CAA policy: present → absent", f"was: {_caa_records(change.previous)}"])

    @classmethod
    def _subdomain(cls, change: Change, timestamp: datetime) -> Finding | None:
        if change.kind is not ChangeKind.ADDED:
            return None
        return cls._finding(
            "regression.new_subdomain", change, timestamp=timestamp, confidence=C.MEDIUM,
            title=f"New subdomain since the previous scan: {change.key}",
            description="A hostname not seen in the previous scan appeared. New names grow the attack "
                        "surface; confirm it is intended and inventoried.",
            severity=S.INFORMATIONAL, evidence=[f"new: {change.key}"])


def _truthy(value: Any, key: str) -> bool:
    '''
    Read a boolean-ish field from a possibly-non-dict observation value.
    Parameters:
        value (Any): The observation value (expected dict).
        key (str): Field name.
    Returns:
        bool: The field's truthiness, or False if absent/not a dict.
    '''
    return bool(value.get(key)) if isinstance(value, dict) else False


def _caa_records(value: Any) -> list[str]:
    '''
    Read the CAA records list out of a dns.caa_effective observation value.
    Parameters:
        value (Any): The observation value (expected dict with a 'records' list), or None.
    Returns:
        list[str]: The records, or [] when absent / not a dict.
    '''
    records = value.get("records") if isinstance(value, dict) else None
    return records if isinstance(records, list) else []


class RegressionAnalyzer:
    '''
    Compares the findings of two scans and classifies the lifecycle of each.
    '''

    @classmethod
    def analyze(cls, previous: ReconReport, current: ReconReport) -> FindingDelta:
        '''
        Classify findings as new / persisting / resolved and update the current findings' states in place.

        Persisting findings are promoted to CORROBORATED (reproduced across scans); a new finding backed by
        more than one module's observations is likewise CORROBORATED. Resolved findings are returned with
        state RESOLVED, only when their producing module(s) ran this time.
        Parameters:
            previous (ReconReport): The earlier scan.
            current (ReconReport): The later scan; its findings' lifecycle states are updated.
        Returns:
            FindingDelta: New and persisting finding ids, and the resolved findings.
        Raises:
            ValueError: If the scans are of different targets.
        '''
        if previous.target.hostname != current.target.hostname:
            raise ValueError(f"cannot compare scans of different targets: "
                             f"{previous.target.hostname} vs {current.target.hostname}")
        prev = {f.id: f for f in previous.analysis.findings}
        current_ids = {f.id for f in current.analysis.findings}
        status = {name: m.status for name, m in current.module_results().items()}
        obs_module = {o.id: o.module for o in current.observations}

        new: list[str] = []
        persisting: list[str] = []
        for finding in current.analysis.findings:
            if finding.id in prev:
                persisting.append(finding.id)
                if finding.state in (FindingState.SUSPECTED, FindingState.CONFIRMED):
                    finding.state = FindingState.CORROBORATED   # reproduced in two scans
            else:
                new.append(finding.id)
                if finding.state is FindingState.CONFIRMED and cls._multi_source(finding, obs_module):
                    finding.state = FindingState.CORROBORATED

        resolved = [f.model_copy(update={"state": FindingState.RESOLVED})
                    for fid, f in prev.items() if fid not in current_ids and cls._producible(f, status)]

        return FindingDelta(
            previous_scan_id=previous.scan_id, new=sorted(new), persisting=sorted(persisting),
            resolved=sorted(resolved, key=lambda f: (-f.severity.rank, f.category, f.id)))

    @staticmethod
    def _producible(finding: Finding, status: dict[str, ModuleStatus]) -> bool:
        '''
        Whether the module(s) behind a finding's category ran this scan, so its absence is a real resolution.
        Parameters:
            finding (Finding): The finding from the previous scan.
            status (dict[str, ModuleStatus]): Current module statuses.
        Returns:
            bool: True if at least one producing module ran (success/partial); False for unknown provenance.
        '''
        modules = _CATEGORY_MODULES.get(finding.category)
        if not modules:
            return False   # e.g. active/intel categories have no passive module; never claim them resolved here
        return any(status.get(m) in _RAN_OK for m in modules)

    @staticmethod
    def _multi_source(finding: Finding, obs_module: dict[str, str]) -> bool:
        '''
        Whether a finding is backed by observations from at least two distinct modules.
        Parameters:
            finding (Finding): The finding.
            obs_module (dict[str, str]): Observation id to producing module.
        Returns:
            bool: True if the finding's evidence spans two or more modules.
        '''
        modules = {obs_module.get(ref) for ref in finding.evidence_refs}
        modules.discard(None)
        return len(modules) >= 2
