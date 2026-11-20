'''
Runs the SEO check table and turns the result into an A–F health score.

The score exists for the same reason the security grade does: a list of thirty observations says what is
wrong but not whether the site is getting better. It is deliberately a separate number — SEO hygiene and
security posture are different properties, and averaging them would describe neither.

How a score is reached, in full:
  * every check is evaluated and keeps its own denominator (how many pages it could look at);
  * a failing check deducts ``weight x (failing pages / evaluated pages)`` from its area, so a template
    bug across the whole site costs the full weight and one odd page costs a fraction of it;
  * an area starts at 100, subtracts its deductions and is floored at 0;
  * the overall score is the mean of the areas that had at least one evaluable check — an area with no
    evidence is left out of the average rather than counted as perfect.

That last rule is what keeps a one-page run honest: without ``--crawl`` the crawlability checks mostly
cannot be evaluated, so they neither pass nor fail, and the report says which ones were skipped.
'''

from __future__ import annotations

from recon.analysis.grading import letter
from recon.analysis.seo_checks import AREA_LABEL, AREAS, SEO_CHECKS, SEO_CHECKS_VERSION
from recon.models import AreaGrade, SeoCheck, SeoData, SeoGrade


def run_checks(seo: SeoData) -> list[SeoCheck]:
    '''
    Evaluate every SEO check against the collected evidence.

    A check whose inputs are missing is returned with status ``not_checked`` and a note saying why, so the
    report can distinguish "this is fine" from "this was never looked at".
    Parameters:
        seo (SeoData): SEO evidence from the seo module.
    Returns:
        list[SeoCheck]: One row per check, in table order.
    '''
    rows: list[SeoCheck] = []
    for spec in SEO_CHECKS:
        outcome = spec.evaluate(seo)
        if not outcome.checked:
            rows.append(SeoCheck(id=spec.id, label=spec.label, area=spec.area, status="not_checked",
                                 scope=spec.scope, weight=spec.weight, note=outcome.note))
            continue
        penalty = round(spec.weight * outcome.share) if outcome.affected else 0
        rows.append(SeoCheck(
            id=spec.id, label=spec.label, area=spec.area, scope=spec.scope,
            status="fail" if outcome.affected else "pass",
            affected=outcome.affected, checked=outcome.checked, weight=spec.weight, penalty=penalty,
            samples=outcome.samples[:10], detail=outcome.detail))
    return rows


def compute_seo_grade(seo: SeoData, checks: list[SeoCheck]) -> SeoGrade | None:
    '''
    Score each area from its checks' deductions and combine them into one SEO grade.
    Parameters:
        seo (SeoData): SEO evidence (for the page count recorded on the grade).
        checks (list[SeoCheck]): Evaluated checks from :func:`run_checks`.

    Returns:
        SeoGrade | None: The grade, or None when no check could be evaluated at all.
    '''
    areas: list[AreaGrade] = []
    for area in AREAS:
        evaluated = [c for c in checks if c.area == area and c.status != "not_checked"]
        if not evaluated:
            continue
        penalty = sum(c.penalty for c in evaluated)
        score = max(0, min(100, 100 - penalty))
        areas.append(AreaGrade(area=area, label=AREA_LABEL[area], score=score, grade=letter(score),
                               findings=sum(1 for c in evaluated if c.status == "fail"), penalty=penalty))
    if not areas:
        return None
    overall = round(sum(a.score for a in areas) / len(areas))
    return SeoGrade(score=overall, grade=letter(overall), areas=areas, checks=checks,
                    pages_analyzed=seo.pages_analyzed, checks_version=SEO_CHECKS_VERSION)
