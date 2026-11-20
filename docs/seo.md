# SEO audit (`--seo`)

`--seo` runs an on-page SEO audit over the pages a scan already fetched: 39 checks across indexability,
metadata, content, crawlability and delivery, each scored with its own denominator, combined into an A–F
grade per area and one overall grade.

```bash
siterecon scan example.com --seo                                # audits the site (turns the crawler on)
siterecon scan example.com --seo --depth 3 --max-pages 100      # wider coverage
siterecon scan example.com --seo --no-crawl                     # landing page only
siterecon scan example.com --seo --modules html,http,resources,crawler,seo
```

## What it is, and what it is not

The audit re-reads the response bodies the `http` and `crawler` modules retained. It **sends no requests
of its own**, contacts **no third party**, and asks **no search engine** anything. That shapes what it can
honestly tell you:

| It answers | It cannot answer |
|---|---|
| Does this page *declare* itself indexable (robots meta, `X-Robots-Tag`, robots.txt, canonical)? | Is this page actually in a search index? |
| Do these pages have unique titles, descriptions and H1s? | Will a given title rank better than another? |
| Does the sitemap agree with robots.txt and with the pages that exist? | What a search engine's own crawl found. |
| How long did the server take to produce each page? | Core Web Vitals, or anything a real user experiences. |
| How many words of copy does the served HTML contain? | Text a client-side framework renders later (unless `--render` ran). |
| Which pages have no inbound link *from the pages that were crawled*? | Whether an uncrawled page links to them. |

The SEO grade exists to track a site against **its own history**, the way the security grade does. It is
not a ranking prediction and does not claim to be one; the note on every rendered grade says so.

## Coverage, and why `--seo` crawls

Every site-wide check — duplicate titles, orphan pages, sitemap coverage, broken internal links — needs
more than one page to compare. So `--seo` turns the crawler on and says so on stdout, because that is
extra requests to the target. `--crawl` and `--no-crawl` always win over the implication:

| Invocation | Pages audited |
|---|---|
| `--seo` | landing page + crawl (depth 1, 25 pages by default) |
| `--seo --crawl --depth 3 --max-pages 100` | landing page + a wider crawl |
| `--seo --no-crawl` | landing page only; every site-wide check reports `not_checked` |

Coverage is reported as a finding, never left implicit:

- `seo.coverage_single_page` — only one page was available, so the site-wide checks were skipped (not
  passed). Severity informational; the recommendation is to re-run with `--crawl`.
- `seo.coverage_truncated` — the crawl stopped at its page limit, so every count describes the analyzed
  pages, not the site.

A thin audit therefore reads as a thin audit. It never reads as a clean one.

## Per-page evidence

`report.seo.data.pages[]` holds one `PageSeo` record per analyzed page:

| Group | Fields |
|---|---|
| Response | `url`, `final_url`, `status_code`, `depth`, `content_type`, `html_bytes`, `response_time_ms`, `truncated` |
| Indexability | `indexable`, `index_blockers` (`noindex_meta` / `x_robots_tag` / `robots_txt`), `robots_meta`, `x_robots_tag`, `nofollow`, `canonical`, `canonical_self`, `canonical_offsite` |
| Metadata | `title`, `title_length`, `meta_description`, `description_length`, `lang`, `hreflang`, `viewport`, `open_graph_present`, `open_graph_missing`, `twitter_card` |
| Content | `h1`, `heading_counts`, `heading_skips`, `word_count`, `images`, `images_missing_alt` |
| Links | `internal_links`, `external_links`, `nofollow_links`, `inbound_internal_links` |
| Structured data | `structured_data_types`, `structured_data_errors`, `in_sitemap` |

Two details worth knowing:

- **`alt=""` is correct markup**, not a missing alt. Only an image with no `alt` attribute at all counts
  toward `images_missing_alt`.
- **Word counts exclude script, style, `noscript`, `template`, `svg` and `iframe` content**, and are taken
  from the HTML as served. A client-rendered page looks thin here because it *is* thin on arrival; run
  `--render` if you need the post-JavaScript view.

Site-wide aggregates sit alongside: `duplicates` (title / description / H1 groups, computed over
indexable pages only — two blocked URLs sharing a title compete for nothing), `orphan_pages`,
`broken_links`, `redirects`, `sitemap`, `host_canonical`, `structured_data`, `languages`, `compression`,
`http_version`, `median_response_ms`, `slowest_response_ms`, `total_html_bytes`.

## The checks

Every judgement lives in one table, `recon/analysis/seo_checks.py`. A check declares its area, weight,
severity and how to evaluate it; the same entry produces both the finding and the score deduction.

A check has three possible outcomes:

- **`pass`** — it was evaluated and nothing failed.
- **`fail`** — `affected` of `checked` items failed. One finding, `seo.<id>`, is emitted.
- **`not_checked`** — there was no evidence to evaluate. **No finding, no deduction, and the area is left
  out of the average** rather than credited as perfect. The report prints the reason.

Five checks deliberately skip the landing page — `titles_missing`, `descriptions_missing`,
`canonical_offsite_pages`, `pages_blocked_from_indexing` and `social_metadata_missing` — because the
landing page already has its own dedicated finding (`seo.title_missing`, `seo.noindex`, `og.missing`, …).
A single-page site is never told about the same missing title twice.

#### Indexability & canonicalization

| Check (`seo.<id>`) | Scope | Weight | Severity | Fails when |
|---|---|---|---|---|
| `pages_blocked_from_indexing` | page | 30 | low | A page is blocked by robots meta, `X-Robots-Tag` or robots.txt |
| `robots_blocked_pages` | site | 20 | low | robots.txt disallows URLs the site publishes |
| `canonical_missing` | page | 20 | informational | An indexable page declares no `rel=canonical` |
| `canonical_not_self` | page | 10 | informational | The canonical names another URL on the same site |
| `canonical_offsite_pages` | page | 15 | low | The canonical names another registrable domain |
| `sitemap_noindex_conflict` | site | 15 | low | A sitemap URL is blocked from indexing |
| `host_not_canonicalized` | site | 20 | low | Apex and `www` both serve the page without redirecting |
| `no_https_canonicalization` | site | 10 | low | `http://` does not reach `https://` |

#### Titles & metadata

| Check (`seo.<id>`) | Scope | Weight | Severity | Fails when |
|---|---|---|---|---|
| `titles_missing` | page | 25 | low | A page has no `<title>` |
| `title_length` | page | 10 | informational | Title is under 20 or over 60 characters |
| `duplicate_titles` | page | 20 | low | Indexable pages share a title |
| `descriptions_missing` | page | 20 | informational | A page has no meta description |
| `description_length` | page | 8 | informational | Description is under 70 or over 160 characters |
| `duplicate_descriptions` | page | 15 | informational | Indexable pages share a description |
| `viewport_missing` | page | 15 | low | A page declares no mobile viewport |
| `lang_missing` | page | 10 | informational | `<html>` has no `lang` attribute |
| `hreflang_invalid` | page | 10 | low | An `hreflang` value is not a valid language tag |
| `social_metadata_missing` | page | 10 | informational | A page carries no `og:*` tags |

#### Content & structure

| Check (`seo.<id>`) | Scope | Weight | Severity | Fails when |
|---|---|---|---|---|
| `h1_missing` | page | 20 | low | A page has no H1 |
| `h1_multiple` | page | 10 | informational | A page has more than one H1 |
| `heading_hierarchy` | page | 8 | informational | Heading levels are skipped (H2 → H4) |
| `duplicate_h1` | page | 10 | informational | Indexable pages share an H1 |
| `thin_content` | page | 15 | informational | Under 150 words of visible copy |
| `images_missing_alt` | page | 15 | low | An image has no `alt` attribute |
| `structured_data_missing` | site | 12 | informational | No JSON-LD or microdata on any analyzed page |
| `structured_data_invalid` | page | 10 | low | A JSON-LD block is not valid JSON |

#### Crawlability & internal links

| Check (`seo.<id>`) | Scope | Weight | Severity | Fails when |
|---|---|---|---|---|
| `robots_txt_missing` | site | 15 | informational | The origin serves no robots.txt |
| `sitemap_missing` | site | 25 | low | No sitemap at the conventional paths or in robots.txt |
| `sitemap_not_declared` | site | 10 | informational | A sitemap exists but robots.txt has no `Sitemap:` line |
| `sitemap_coverage_gap` | page | 15 | informational | An indexable analyzed page is in no sitemap |
| `sitemap_errors` | site | 20 | low | A sitemap URL answered with an error |
| `orphan_pages` | page | 15 | informational | No analyzed page links to this page |
| `broken_internal_links` | site | 25 | low | An internal link points at a 4xx/5xx URL |
| `internal_redirects` | site | 10 | informational | An internal link points at a redirecting URL |
| `deep_pages` | page | 8 | informational | A page was first reached 4+ clicks from home |

#### Delivery

| Check (`seo.<id>`) | Scope | Weight | Severity | Fails when |
|---|---|---|---|---|
| `no_compression` | site | 25 | low | The landing HTML has no `Content-Encoding` |
| `slow_pages` | page | 25 | informational | The server took over 1500 ms to respond |
| `heavy_html` | page | 20 | informational | A document exceeds 300 KB of markup alone |
| `legacy_http_version` | site | 15 | informational | The landing page was served over HTTP/1.1 |

Thresholds (`TITLE_MIN_CHARS`, `DESC_MAX_CHARS`, `THIN_CONTENT_WORDS`, `SLOW_RESPONSE_MS`,
`HEAVY_HTML_BYTES`, `DEEP_PAGE_DEPTH`) are the common published guidance, not rules SiteRecon can verify.
A failing check means *this differs from the usual guidance* — which is why most are informational or low
severity. `SEO_CHECKS_VERSION` is a calendar version recorded on every grade, so a score that moves
because the rule set changed can be told apart from a score that moves because the site did.

## Scoring

```
deduction per failing check = weight × (failing items / evaluated items)
area score                  = max(0, 100 − Σ deductions in that area)
overall score               = mean of the areas that had at least one evaluable check
letter grade                = the same A+…F bands as the security grade
```

Proportionality is the point: one odd page out of forty is a fraction of the weight, while the same
problem on every page is the full weight. An area with nothing to evaluate is **excluded from the
average**, never scored 100.

SEO findings are in the categories `seo` and `social`, which `recon/analysis/grading.py` excludes from the
**security** grade entirely. A missing meta description is not a weaker security posture, and the two
numbers stay independent in both directions. `report.analysis.seo` holds the SEO grade;
`report.analysis.grade` holds the security grade.

## Findings, observations and the diff

**Findings** are emitted one per failing check, subject = the hostname, code `seo.<check id>`, with the
affected/evaluated counts, a detail line and up to eight example pages as evidence. Each carries a
recommendation and a limitation from the central tables in `recon/analysis/findings.py`, like every other
finding in the tool. The four landing-page-only codes that predate this module (`seo.title_missing`,
`seo.meta_description_missing`, `seo.noindex`, `seo.canonical_offsite`) still fire for the landing page and
keep their narrower limitation text.

**Observations** feed the scan-to-scan diff. Site-level records cover the page count, indexable count,
coverage, compression, HTTP version, languages, structured-data types, duplicate-group counts, sitemap
facts and the serving hosts. Per-page records (capped at 50 pages) cover `indexable`, `index_blockers`,
`title`, `description`, `canonical` and `h1` — so a diff surfaces exactly the regressions worth an alert:

```text
modified   seo.page   https://example.com/        title        'Acme Widgets: fasteners…' -> 'Acme Widgets'
modified   seo.page   https://example.com/pricing indexable    'True' -> 'False'
removed    seo.duplicates  example.com            title        '3' -> None
```

Volatile measurements — word counts, response times, byte sizes — are deliberately **not** observed. They
change on every content edit and would bury the structural changes in noise. They are still in the
report, just not in the diff.

As with every module, a change is only `added`/`removed` when the `seo` module succeeded in both scans;
otherwise it is `unknown`, so a skipped audit never looks like a site that lost its titles.

## In the reports

- **Markdown / HTML**: an `SEO Audit` section with the grade and per-area table, the full check list
  (including every `not_checked` row and its reason), the per-page table, duplicate groups, the
  robots/sitemap comparison, internal-link problems, structured-data inventory, host canonicalization and
  delivery summary.
- **Executive summary**: the SEO grade appears beside the security grade, labelled as scored separately.
- **Terminal**: the grade, the per-area breakdown, the failing checks worst-first, and the number of
  checks that had no evidence.
- **JSON**: `report.seo` (evidence) and `report.analysis.seo` (checks, areas, grade); `raw/seo.json` holds
  the module result on its own.

## Adding a check

Append a `SeoCheckSpec` to `SEO_CHECKS` in `recon/analysis/seo_checks.py` and a recommendation to
`RECOMMENDATIONS` in `recon/analysis/findings.py` under `seo.<id>`. Nothing else needs changing: the
finding, the score deduction, the report rows and the terminal summary all come from the table. Use
`page_rule(...)` for a per-page predicate (it handles eligibility, indexable-only filtering and the
landing-page exclusion) or `site_rule(...)` for a site-level evaluator, and return `CheckOutcome(note=…)`
with no `checked` whenever the evidence is missing — that is what makes the difference between "fine" and
"never looked at". `tests/test_seo.py` asserts that every check in the table has a recommendation, so a
new entry without one fails the suite.
