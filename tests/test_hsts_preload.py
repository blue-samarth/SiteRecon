from __future__ import annotations

import gzip

import pytest

from recon.models import HttpData, HttpProbe, ModuleResult, ModuleStatus
from recon.modules import HttpCollector
from recon.utils.hsts import DATA_FILE, HstsPreloadList, preload_status

# A snapshot small enough to read, padded past the sanity floor so the loader accepts it.
HEADER = ("# HSTS preload list, reduced to name + subdomain coverage.\n"
          "# source: https://example.invalid/list.json\n"
          "# retrieved: 2026-11-20\n"
          "# entries: 6\n"
          "# a leading '!' means the entry does NOT cover subdomains.\n")
NAMES = ["dev", "github.com", "paypal.com", "!aclu.org", "!www.bbc.co.uk"]


def snapshot(tmp_path, names=None, header=HEADER, pad=True):
    '''Write a gzipped snapshot and return its path.'''
    body = list(names if names is not None else NAMES)
    if pad:
        body += [f"pad{i}.example" for i in range(50_000)]
    path = tmp_path / "hsts_preload.txt.gz"
    path.write_bytes(gzip.compress((header + "\n".join(body) + "\n").encode()))
    HstsPreloadList._cache.clear()
    return path


# ------------------------------------------------------------------ parsing

def test_the_bundled_snapshot_loads_and_is_plausibly_complete():
    assert DATA_FILE.exists(), "the HSTS preload snapshot must ship with the package"
    rules = HstsPreloadList.load().rules
    assert len(rules) > 50_000
    assert rules.snapshot_date and len(rules.snapshot_date) == 10      # ISO date from the header


def test_comment_lines_carry_provenance_and_are_not_treated_as_names(tmp_path):
    rules = HstsPreloadList.load(snapshot(tmp_path)).rules
    assert rules.snapshot_date == "2026-11-20"
    assert not any(n.startswith("#") for n in rules.with_subdomains | rules.exact_only)


def test_a_truncated_snapshot_is_refused_rather_than_answered_from(tmp_path):
    # Silently answering from a tiny list would report every domain as "not preloaded".
    with pytest.raises(ValueError, match="refusing to answer"):
        HstsPreloadList.load(snapshot(tmp_path, pad=False))


def test_an_unreadable_snapshot_yields_no_answer_instead_of_a_false_negative(tmp_path):
    missing = tmp_path / "absent.txt.gz"
    assert preload_status("github.com", missing) is None
    corrupt = tmp_path / "corrupt.txt.gz"
    corrupt.write_bytes(b"not gzip at all")
    HstsPreloadList._cache.clear()
    assert preload_status("github.com", corrupt) is None


# ------------------------------------------------------------------ matching

def test_an_exact_entry_matches(tmp_path):
    status = preload_status("github.com", snapshot(tmp_path))
    assert status.preloaded and status.matched_name == "github.com" and not status.via_subdomains


def test_an_entry_covering_subdomains_matches_descendants(tmp_path):
    path = snapshot(tmp_path)
    status = preload_status("api.github.com", path)
    assert status.preloaded and status.matched_name == "github.com" and status.via_subdomains
    deep = preload_status("a.b.c.github.com", path)
    assert deep.preloaded and deep.matched_name == "github.com"


def test_an_exact_only_entry_does_not_cover_descendants(tmp_path):
    path = snapshot(tmp_path)
    assert preload_status("aclu.org", path).preloaded is True
    assert preload_status("sub.aclu.org", path).preloaded is False      # '!aclu.org' is exact-only


def test_a_whole_preloaded_tld_covers_everything_under_it(tmp_path):
    status = preload_status("anything.dev", snapshot(tmp_path))
    assert status.preloaded and status.matched_name == "dev" and status.via_subdomains


def test_the_nearest_ancestor_wins(tmp_path):
    path = snapshot(tmp_path, names=["example.com", "shop.example.com", *NAMES])
    assert preload_status("a.shop.example.com", path).matched_name == "shop.example.com"


def test_an_unlisted_name_is_reported_as_absent_with_the_snapshot_recorded(tmp_path):
    status = preload_status("nothing-here.example", snapshot(tmp_path))
    assert status.preloaded is False and status.matched_name is None
    assert status.snapshot_date == "2026-11-20" and status.entries > 50_000


@pytest.mark.parametrize("given", ["GitHub.COM", "github.com.", " github.com ", "GITHUB.com."])
def test_lookups_ignore_case_and_a_trailing_dot(tmp_path, given):
    assert preload_status(given, snapshot(tmp_path)).preloaded is True


def test_an_empty_hostname_is_not_preloaded(tmp_path):
    assert preload_status("", snapshot(tmp_path)).preloaded is False


# ------------------------------------------------------------------ real list spot checks

@pytest.mark.parametrize("host,expected", [
    ("github.com", True), ("api.github.com", True),          # listed, covers subdomains
    ("anything.dev", True),                                  # the whole .dev TLD is preloaded
    ("example.com", False),                                  # reserved, never submitted
])
def test_spot_checks_against_the_bundled_list(host, expected):
    assert preload_status(host).preloaded is expected


# ------------------------------------------------------------------ collector and observations

def test_the_collector_records_the_lookup_without_making_a_request():
    status = HttpCollector.preload_status("github.com")
    assert status.checked and status.preloaded and status.entries > 50_000
    assert status.snapshot_date and status.hostname == "github.com"


def test_the_collector_reports_not_checked_when_no_snapshot_is_available(monkeypatch, tmp_path):
    monkeypatch.setattr("recon.modules.http.lookup_preload", lambda host: None)
    status = HttpCollector.preload_status("github.com")
    assert status.checked is False and status.preloaded is False
    assert "refresh" in (status.note or "")


def test_membership_becomes_an_observation_so_a_delisting_shows_up_in_the_diff():
    import datetime as dt

    from recon.analysis import ObservationBuilder
    from recon.models import CollectionMethod

    t0 = dt.datetime(2026, 11, 20, tzinfo=dt.UTC)
    data = HttpData(probes=[HttpProbe(requested_url="https://github.com/", success=True)],
                    hsts_preload=HttpCollector.preload_status("github.com"))
    r = ModuleResult(module="http", status=ModuleStatus.SUCCESS, started_at=t0, finished_at=t0,
                     duration_ms=1.0, data=data)
    obs = {(o.type, o.key): o for o in ObservationBuilder("github.com", {"http": r}).build()}
    listed = obs[("hsts.preload", "listed")]
    assert listed.value is True
    assert listed.collection_method == CollectionMethod.LOCAL_DATABASE   # a bundled lookup, not a request
    assert listed.limitations and "snapshot" in listed.limitations[0]
    assert obs[("hsts.preload", "entry")].value == {"name": "github.com", "covers_subdomains": False}


def test_an_unchecked_lookup_records_no_observation_at_all():
    import datetime as dt

    from recon.analysis import ObservationBuilder
    from recon.models import HstsPreload

    t0 = dt.datetime(2026, 11, 20, tzinfo=dt.UTC)
    data = HttpData(probes=[HttpProbe(requested_url="https://x.test/", success=True)],
                    hsts_preload=HstsPreload(checked=False, hostname="x.test", note="no snapshot"))
    r = ModuleResult(module="http", status=ModuleStatus.SUCCESS, started_at=t0, finished_at=t0,
                     duration_ms=1.0, data=data)
    types = {o.type for o in ObservationBuilder("x.test", {"http": r}).build()}
    assert "hsts.preload" not in types      # absent data must not read as "not listed"
