'''
JSON report writer: full report plus one raw file per collection module.
'''

from __future__ import annotations

from pathlib import Path

from recon.reporting.base import ReportWriter


class JsonReportWriter(ReportWriter):
    '''
    Writes report.json and one raw/<module>.json file per module.
    '''

    def write(self, directory: Path) -> list[Path]:
        '''
        Write report.json and one raw/<module>.json file per module.
        Parameters:
            directory (Path): Directory to write into; created if missing.
        Returns:
            list[Path]: Paths of the files written.
        Raises:
            OSError: If the directory cannot be written.
        '''
        directory.mkdir(parents=True, exist_ok=True)
        raw_dir = directory / "raw"
        raw_dir.mkdir(exist_ok=True)

        main = directory / "report.json"
        main.write_text(self.report.model_dump_json(indent=2), encoding="utf-8")
        written = [main]
        for name, result in self.report.module_results().items():
            path = raw_dir / f"{name}.json"
            path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
            written.append(path)
        return written
