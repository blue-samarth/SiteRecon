'''
Scan history storage interface.
'''

from __future__ import annotations

import re
import secrets
from abc import ABC, abstractmethod
from datetime import datetime
from typing import ClassVar

from recon.models import ReconReport, ScanRef


class ScanStore(ABC):
    '''
    Persists complete reports so scans of a target can be listed and compared.
    '''

    SCAN_ID: ClassVar[re.Pattern[str]] = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{6}$")

    @classmethod
    def new_scan_id(cls, started_at: datetime) -> str:
        '''
        Generate a sortable, unique scan identifier.
        Parameters:
            started_at (datetime): Scan start time (UTC).
        Returns:
            str: e.g. '20261107T130452Z-3fa9c1'.
        '''
        return f"{started_at:%Y%m%dT%H%M%SZ}-{secrets.token_hex(3)}"

    @classmethod
    def validate_scan_id(cls, scan_id: str) -> str:
        '''
        Reject anything that is not a well-formed scan id (prevents path traversal).
        Parameters:
            scan_id (str): Candidate id.
        Returns:
            str: The id, unchanged.
        Raises:
            ValueError: If the id is malformed.
        '''
        if not cls.SCAN_ID.match(scan_id):
            raise ValueError(f"invalid scan id {scan_id!r}")
        return scan_id

    @abstractmethod
    def save(self, report: ReconReport) -> str:
        '''
        Store a report.
        Parameters:
            report (ReconReport): Report with a scan_id.
        Returns:
            str: Where it was stored.
        Raises:
            ValueError: If the report has no valid scan_id.
        '''

    @abstractmethod
    def list(self, hostname: str) -> list[ScanRef]:
        '''
        List stored scans of a target, oldest first.
        Parameters:
            hostname (str): Target hostname.
        Returns:
            list[ScanRef]: Stored scans.
        '''

    @abstractmethod
    def load(self, scan_id: str) -> ReconReport:
        '''
        Load a stored report by id.
        Parameters:
            scan_id (str): Scan identifier.
        Returns:
            ReconReport: The report.
        Raises:
            KeyError: If no such scan exists.
            ValueError: If the id is malformed.
        '''

    def latest(self, hostname: str, exclude: str | None = None) -> ReconReport | None:
        '''
        Load the most recent stored scan of a target.
        Parameters:
            hostname (str): Target hostname.
            exclude (str | None): Scan id to ignore (e.g. the current scan).
        Returns:
            ReconReport | None: The latest report, or None if there is none.
        '''
        refs = [r for r in self.list(hostname) if r.scan_id != exclude]
        return self.load(refs[-1].scan_id) if refs else None
