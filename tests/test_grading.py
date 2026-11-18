import datetime as dt

from recon.analysis.grading import compute_grade, letter
from recon.models import Finding, Severity
from recon.models.common import Confidence

T0 = dt.datetime(2026, 11, 18, tzinfo=dt.UTC)


def finding(category, severity):
    return Finding(id=f"{category}.x:{severity.value}", category=category, title="t", description="d",
                   severity=severity, confidence=Confidence.HIGH, source="s", subject="sub", timestamp=T0)


def test_letter_bands():
    assert letter(100) == "A+" and letter(90) == "A" and letter(72) == "B-"
    assert letter(60) == "C" and letter(39) == "F"


def test_clean_site_scores_top_grade():
    g = compute_grade([])
    assert g.grade == "A+" and g.score == 100
    assert {a.area for a in g.areas} == {"tls", "headers", "dns_email", "exposure"}


def test_findings_lower_the_relevant_area_and_overall():
    g = compute_grade([finding("tls", Severity.HIGH),          # -25 → tls 75
                       finding("http", Severity.MEDIUM),       # -10 → headers 90
                       finding("vuln", Severity.CRITICAL)])    # -50 → exposure 50
    by = {a.area: a for a in g.areas}
    assert by["tls"].score == 75 and by["tls"].grade == "B"
    assert by["headers"].score == 90
    assert by["exposure"].score == 50 and by["exposure"].grade == "D+"
    assert by["dns_email"].score == 100
    # overall = mean(75, 90, 50, 100) = 78.75 → 79 → B (80 would be B+)
    assert g.score == 79 and g.grade == "B"


def test_informational_findings_do_not_affect_the_grade():
    g = compute_grade([finding("tls", Severity.INFORMATIONAL), finding("dns", Severity.INFORMATIONAL)])
    assert g.score == 100 and g.grade == "A+"


def test_area_penalty_floors_at_zero():
    g = compute_grade([finding("tls", Severity.CRITICAL)] * 5)   # -250, floored
    assert next(a for a in g.areas if a.area == "tls").score == 0
