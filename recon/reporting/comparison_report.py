'''
Comparison report: differences between two scans as JSON and Markdown.
'''

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

from recon.models import ChangeKind, ComparisonResult


class ComparisonReportWriter:
    '''
    Writes changes.json and changes.md for a ComparisonResult.
    '''

    ORDER: ClassVar[tuple[ChangeKind, ...]] = (ChangeKind.ADDED, ChangeKind.REMOVED, ChangeKind.MODIFIED,
                                               ChangeKind.UNKNOWN)

    def __init__(self, comparison: ComparisonResult) -> None:
        '''
        Create a writer.
        Parameters:
            comparison (ComparisonResult): The comparison to render.
        '''
        self.comparison = comparison

    def write(self, directory: Path) -> list[Path]:
        '''
        Write changes.json and changes.md.
        Parameters:
            directory (Path): Directory to write into; created if missing.
        Returns:
            list[Path]: Paths of the files written.
        Raises:
            OSError: If the directory cannot be written.
        '''
        directory.mkdir(parents=True, exist_ok=True)
        json_path, md_path = directory / "changes.json", directory / "changes.md"
        json_path.write_text(self.comparison.model_dump_json(indent=2), encoding="utf-8")
        md_path.write_text(self.render(), encoding="utf-8")
        return [json_path, md_path]

    def render(self) -> str:
        '''
        Render the comparison as Markdown, grouped by change kind.
        Returns:
            str: Markdown text.
        '''
        c = self.comparison
        out = [
            f"# Changes for `{c.current.hostname}`", "",
            f"- **Previous scan:** `{c.previous.scan_id}` ({c.previous.started_at:%Y-%m-%d %H:%M:%S} UTC)",
            f"- **Current scan:** `{c.current.scan_id}` ({c.current.started_at:%Y-%m-%d %H:%M:%S} UTC)",
            "- **Summary:** " + ", ".join(f"{c.counts.get(k.value, 0)} {k.value}" for k in (*self.ORDER, ChangeKind.UNCHANGED)),
            "", f"> {c.note}", "",
        ]
        if not c.changes:
            out.append("_No changes detected._")
        for kind in self.ORDER:
            items = [ch for ch in c.changes if ch.kind is kind]
            if not items:
                continue
            out += [f"## {kind.value.capitalize()} ({len(items)})", "",
                    "| Type | Target | Key | Previous | Current |" + (" Reason |" if kind is ChangeKind.UNKNOWN else ""),
                    "|---|---|---|---|---|" + ("---|" if kind is ChangeKind.UNKNOWN else "")]
            for ch in items:
                row = [ch.type, ch.target, ch.key, self._fmt(ch.previous), self._fmt(ch.current)]
                if kind is ChangeKind.UNKNOWN:
                    row.append(ch.reason or "")
                out.append("| " + " | ".join(self._cell(v) for v in row) + " |")
            out.append("")
        return "\n".join(out) + "\n"

    @staticmethod
    def _fmt(value: Any) -> str:
        '''
        Format an observation value compactly.
        Parameters:
            value (Any): Observation value.
        Returns:
            str: Display text ('—' for None).
        '''
        if value is None:
            return "—"
        if isinstance(value, str):
            return value
        return json.dumps(value, ensure_ascii=False, sort_keys=True)

    @staticmethod
    def _cell(value: str) -> str:
        '''
        Escape a Markdown table cell and cap its length.
        Parameters:
            value (str): Cell text.
        Returns:
            str: Escaped text.
        '''
        text = value.replace("|", "\\|").replace("\n", " ")
        return text if len(text) <= 160 else text[:157] + "…"
