'''
Cross-module correlation and confidence calibration: two small in-place passes over the final findings.

``correlate`` collapses findings that describe the same issue on the same subject but were surfaced by
more than one module into a single finding, merging their evidence. ``calibrate`` adjusts confidence from
the evidence: a finding backed only by stale or historical external-provider data is weakened, because
such data is less certain than a live observation.
'''

from __future__ import annotations

from recon.models import Confidence, Finding, Freshness, Observation

_STALE: frozenset[Freshness] = frozenset({Freshness.STALE, Freshness.HISTORICAL})
_LOWER: dict[Confidence, Confidence] = {Confidence.HIGH: Confidence.MEDIUM, Confidence.MEDIUM: Confidence.LOW}


def correlate(findings: list[Finding]) -> list[Finding]:
    '''
    Merge findings that are the same issue (same subject and title) into one, unioning their evidence.

    Findings are already de-duplicated by code and subject upstream; this collapses the remaining case —
    the same issue reported under different codes by different modules — keeping the strongest severity and
    confidence.
    Parameters:
        findings (list[Finding]): Findings in priority order.
    Returns:
        list[Finding]: Findings with same-issue duplicates merged, order preserved.
    '''
    merged: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        key = (finding.subject, finding.title.strip().lower())
        keep = merged.get(key)
        if keep is None:
            merged[key] = finding
            continue
        if finding.severity.rank > keep.severity.rank:
            keep.severity = finding.severity
        if finding.confidence.rank > keep.confidence.rank:
            keep.confidence = finding.confidence
        keep.evidence = list(dict.fromkeys([*keep.evidence, *finding.evidence]))[:20]
        keep.evidence_refs = list(dict.fromkeys([*keep.evidence_refs, *finding.evidence_refs]))[:10]
    return list(merged.values())


def calibrate(findings: list[Finding], observations: list[Observation]) -> None:
    '''
    Lower a finding's confidence when all its evidence is stale or historical external-provider data.
    Parameters:
        findings (list[Finding]): Findings to calibrate in place.
        observations (list[Observation]): Observations the findings may reference.
    '''
    by_id = {o.id: o for o in observations}
    for finding in findings:
        refs = [by_id[r] for r in finding.evidence_refs if r in by_id]
        if refs and finding.confidence in _LOWER \
                and all(o.external_provider and o.freshness in _STALE for o in refs):
            finding.confidence = _LOWER[finding.confidence]
