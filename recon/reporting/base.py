'''
Base class shared by report writers.
'''

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from recon.models import ReconReport


class ReportWriter(ABC):
    '''
    Renders a ReconReport to one or more files in a directory.
    '''

    def __init__(self, report: ReconReport) -> None:
        '''
        Create a writer for a report.
        Parameters:
            report (ReconReport): The completed reconnaissance report.
        '''
        self.report = report

    @abstractmethod
    def write(self, directory: Path) -> list[Path]:
        '''
        Write the report files.
        Parameters:
            directory (Path): Directory to write into; created if missing.
        Returns:
            list[Path]: Paths of the files written.
        Raises:
            OSError: If the directory cannot be written.
        '''
