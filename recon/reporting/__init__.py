'''
Presentation layer: renders a ``ReconReport`` as JSON, Markdown and HTML files.

Import from this package, e.g. ``from recon.reporting import JsonReportWriter``.
'''

from recon.reporting.active_report import (
    ActiveHtmlReportWriter,
    ActiveJsonReportWriter,
    ActiveMarkdownReportWriter,
)
from recon.reporting.base import ReportWriter
from recon.reporting.comparison_report import ComparisonReportWriter
from recon.reporting.html_report import HtmlReportWriter
from recon.reporting.json_report import JsonReportWriter
from recon.reporting.markdown_report import MarkdownReportWriter

__all__ = ["ReportWriter", "JsonReportWriter", "MarkdownReportWriter", "HtmlReportWriter", "ComparisonReportWriter",
           "ActiveJsonReportWriter", "ActiveMarkdownReportWriter", "ActiveHtmlReportWriter"]
