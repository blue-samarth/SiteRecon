'''
JSON file scan store: <root>/<hostname>/history/<scan_id>.json
'''

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError

from recon.models import ReconReport, ScanRef
from recon.storage.base import ScanStore
from recon.utils import validate_hostname


class JsonScanStore(ScanStore):
    '''
    Stores each scan as one JSON file per target.
    '''

    def __init__(self, root: Path) -> None:
        '''
        Create a store.
        Parameters:
            root (Path): Base directory (normally the report output directory).
        '''
        self.root = root

    def _dir(self, hostname: str) -> Path:
        '''
        History directory for a target.
        Parameters:
            hostname (str): Target hostname (validated, so it cannot escape the root).
        Returns:
            Path: <root>/<hostname>/history
        Raises:
            InvalidTargetError: If the hostname is malformed.
        '''
        validate_hostname(hostname)
        return self.root / hostname / "history"

    def save(self, report: ReconReport) -> str:
        '''
        Write the report as <scan_id>.json.
        Parameters:
            report (ReconReport): Report with a scan_id.
        Returns:
            str: Path of the stored file.
        Raises:
            ValueError: If the report has no valid scan_id.
            OSError: If the file cannot be written.
        '''
        scan_id = self.validate_scan_id(report.scan_id)
        directory = self._dir(report.target.hostname)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{scan_id}.json"
        path.write_text(report.model_dump_json(), encoding="utf-8")
        return str(path)

    def list(self, hostname: str) -> list[ScanRef]:
        '''
        List stored scans of a target, oldest first (unreadable files are skipped).
        Parameters:
            hostname (str): Target hostname.
        Returns:
            list[ScanRef]: Stored scans.
        '''
        directory = self._dir(hostname)
        refs: list[ScanRef] = []
        for path in sorted(directory.glob("*.json")) if directory.is_dir() else []:
            if not self.SCAN_ID.match(path.stem):
                continue
            try:
                head = json.loads(path.read_text(encoding="utf-8"))
                refs.append(ScanRef(scan_id=path.stem, hostname=head["target"]["hostname"],
                                    started_at=datetime.fromisoformat(head["started_at"])))
            except (OSError, ValueError, KeyError, TypeError):
                continue
        return sorted(refs, key=lambda r: (r.started_at, r.scan_id))

    def load(self, scan_id: str) -> ReconReport:
        '''
        Load a report by id from any target's history.
        Parameters:
            scan_id (str): Scan identifier.
        Returns:
            ReconReport: The report.
        Raises:
            KeyError: If no such scan exists or it cannot be parsed.
            ValueError: If the id is malformed.
        '''
        self.validate_scan_id(scan_id)
        for path in self.root.glob(f"*/history/{scan_id}.json"):
            try:
                return ReconReport.model_validate_json(path.read_text(encoding="utf-8"))
            except (OSError, ValidationError) as exc:
                raise KeyError(f"scan {scan_id} could not be read: {exc}") from exc
        raise KeyError(f"no stored scan {scan_id}")
