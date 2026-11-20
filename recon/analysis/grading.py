'''
Observatory-style A–F security grading.

The severity histogram says how many issues exist but not how a site compares or how it trends. This scores
each posture area (TLS, HTTP headers, DNS/email, exposure) out of 100 by deducting per finding by severity,
maps the score to a letter grade, and combines the areas into one overall grade — a single comparable number
that moves across scans as posture changes.
'''

from __future__ import annotations

from recon.models import Finding, SecurityGrade, Severity
from recon.models.report import AreaGrade

# Points deducted per grade-affecting finding, by severity. Informational findings never lower a grade.
_PENALTY: dict[Severity, int] = {Severity.CRITICAL: 50, Severity.HIGH: 25, Severity.MEDIUM: 10, Severity.LOW: 4,
                                 Severity.INFORMATIONAL: 0}
# Categories graded elsewhere, excluded from the security grade entirely. SEO and social-preview
# findings are content-quality signals: a missing meta description is not a weaker security posture, and
# letting a site-wide SEO audit deduct from "exposure" would make the security number move for reasons
# that have nothing to do with security. They get their own score (see recon.analysis.seo_grading).
_UNGRADED: frozenset[str] = frozenset({"seo", "social"})
# Finding category → posture area. Categories not listed fall under "exposure".
_AREA: dict[str, str] = {
    "tls": "tls",
    "http": "headers", "waf": "headers",
    "dns": "dns_email", "email": "dns_email", "dnssec": "dns_email",
}
_AREAS: tuple[str, ...] = ("tls", "headers", "dns_email", "exposure")
_AREA_LABEL: dict[str, str] = {"tls": "TLS", "headers": "HTTP headers", "dns_email": "DNS & email",
                               "exposure": "Exposure & components"}
# Score thresholds → letter grade (Mozilla Observatory style).
_GRADE_BANDS: tuple[tuple[int, str], ...] = (
    (95, "A+"), (90, "A"), (85, "A-"), (80, "B+"), (75, "B"), (70, "B-"),
    (65, "C+"), (60, "C"), (55, "C-"), (50, "D+"), (45, "D"), (40, "D-"), (0, "F"))


def letter(score: int) -> str:
    '''
    Map a 0–100 score to a letter grade.
    Parameters:
        score (int): The clamped score.
    Returns:
        str: Letter grade (A+ … F).
    '''
    return next(grade for threshold, grade in _GRADE_BANDS if score >= threshold)


def compute_grade(findings: list[Finding]) -> SecurityGrade:
    '''
    Grade the posture from the finalized findings: per-area scores and one overall grade.

    Findings in the categories graded separately (SEO, social previews) are skipped, so this number
    reflects security posture only.
    Parameters:
        findings (list[Finding]): The report's findings.
    Returns:
        SecurityGrade: Overall score/grade plus a per-area breakdown.
    '''
    penalties: dict[str, int] = {a: 0 for a in _AREAS}
    counts: dict[str, int] = {a: 0 for a in _AREAS}
    for finding in findings:
        if finding.category in _UNGRADED:
            continue
        area = _AREA.get(finding.category, "exposure")
        deduction = _PENALTY.get(finding.severity, 0)
        if deduction:
            penalties[area] += deduction
            counts[area] += 1

    areas: list[AreaGrade] = []
    for area in _AREAS:
        score = max(0, 100 - penalties[area])
        areas.append(AreaGrade(area=area, label=_AREA_LABEL[area], score=score, grade=letter(score),
                               findings=counts[area], penalty=penalties[area]))
    overall = round(sum(a.score for a in areas) / len(areas))
    return SecurityGrade(score=overall, grade=letter(overall), areas=areas)
