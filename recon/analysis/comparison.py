from __future__ import annotations

from collections import Counter

from recon.models import (
    Change,
    ChangeKind,
    ComparisonResult,
    ModuleStatus,
    Observation,
    ReconReport,
    ScanRef,
)


class ScanComparator:
    '''
    Produces a ComparisonResult from two ReconReports.
    '''

    @classmethod
    def compare(cls, previous: ReconReport, current: ReconReport) -> ComparisonResult:
        '''
        Compare every observation key across two scans.
        Parameters:
            previous (ReconReport): Earlier scan.
            current (ReconReport): Later scan.
        Returns:
            ComparisonResult: Classified changes and per-kind counts.
        Raises:
            ValueError: If the scans are of different targets.
        '''
        if previous.target.hostname != current.target.hostname:
            raise ValueError(f"cannot compare scans of different targets: "
                             f"{previous.target.hostname} vs {current.target.hostname}")
        prev = cls._index(previous.observations)
        cur = cls._index(current.observations)
        prev_status = {name: m.status for name, m in previous.module_results().items()}
        cur_status = {name: m.status for name, m in current.module_results().items()}

        changes: list[Change] = []
        counts: Counter[str] = Counter()
        for key in sorted(prev.keys() | cur.keys()):
            p, c = prev.get(key), cur.get(key)
            module = (p or c).module
            change = Change(type=key[0], target=key[1], key=key[2], module=module,
                            previous=p.value if p else None, current=c.value if c else None,
                            kind=ChangeKind.UNCHANGED)
            if p and c:
                change.kind = ChangeKind.UNCHANGED if p.value == c.value else ChangeKind.MODIFIED
            elif c:
                ps = prev_status.get(module)
                change.kind = ChangeKind.ADDED if ps is ModuleStatus.SUCCESS else ChangeKind.UNKNOWN
                if change.kind is ChangeKind.UNKNOWN:
                    change.reason = f"'{module}' was {ps.value if ps else 'absent'} in the previous scan"
            else:
                cs = cur_status.get(module)
                change.kind = ChangeKind.REMOVED if cs is ModuleStatus.SUCCESS else ChangeKind.UNKNOWN
                if change.kind is ChangeKind.UNKNOWN:
                    change.reason = f"'{module}' was {cs.value if cs else 'absent'} in the current scan"
            counts[change.kind.value] += 1
            if change.kind is not ChangeKind.UNCHANGED:
                changes.append(change)

        return ComparisonResult(
            previous=ScanRef(scan_id=previous.scan_id, hostname=previous.target.hostname,
                             started_at=previous.started_at),
            current=ScanRef(scan_id=current.scan_id, hostname=current.target.hostname,
                            started_at=current.started_at),
            counts={k.value: counts.get(k.value, 0) for k in ChangeKind},
            changes=changes,
            unchanged_count=counts.get(ChangeKind.UNCHANGED.value, 0),
        )

    @staticmethod
    def _index(observations: list[Observation]) -> dict[tuple[str, str, str], Observation]: return {(o.type, o.target, o.key): o for o in observations}
