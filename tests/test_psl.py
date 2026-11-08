import pytest

from recon.utils import PublicSuffixList, public_suffix, registrable_domain


@pytest.mark.parametrize("host, suffix, etld1", [
    # plain
    ("jobbie.io", "io", "jobbie.io"),
    ("a.b.example.com", "com", "example.com"),
    # multi-label ICANN suffixes the old approximation got right
    ("www.shop.example.co.uk", "co.uk", "example.co.uk"),
    # ones the old approximation got WRONG
    ("example.pvt.k12.ma.us", "pvt.k12.ma.us", "example.pvt.k12.ma.us"),
    ("site.books.kobe.jp", "books.kobe.jp", "site.books.kobe.jp"),
    ("foo.bar.sch.uk", "bar.sch.uk", "foo.bar.sch.uk"),   # '*.sch.uk' is a wildcard rule
    # wildcard rule and its exception (*.ck with !www.ck)
    ("foo.bar.ck", "bar.ck", "foo.bar.ck"),
    ("www.ck", "ck", "www.ck"),
    ("foo.www.ck", "ck", "www.ck"),
    # unknown TLD falls back to the default '*' rule
    ("something.unknown-tld-xyz", "unknown-tld-xyz", "something.unknown-tld-xyz"),
    # internationalized (punycode) suffix
    ("test.xn--p1ai", "xn--p1ai", "test.xn--p1ai"),
])
def test_public_suffix_and_registrable_domain(host, suffix, etld1):
    assert public_suffix(host) == suffix
    assert registrable_domain(host) == etld1


def test_icann_only_by_default_so_rdap_gets_the_registered_name():
    # github.io / vercel.app are PRIVATE-section rules: for RDAP we want the registered name.
    assert registrable_domain("user.github.io") == "github.io"
    assert registrable_domain("myapp.vercel.app") == "vercel.app"
    # with the private section enabled they become suffixes (useful for grouping, not registration)
    assert registrable_domain("user.github.io", include_private=True) == "user.github.io"
    assert registrable_domain("myapp.vercel.app", include_private=True) == "myapp.vercel.app"


def test_host_that_is_itself_a_public_suffix_falls_back_to_the_host():
    assert registrable_domain("co.uk") == "co.uk"
    assert registrable_domain("com") == "com"
    assert PublicSuffixList.load().registrable_domain("co.uk") is None


def test_case_and_trailing_dot_are_normalized():
    assert registrable_domain("WWW.Example.CO.UK.") == "example.co.uk"


def test_parser_handles_comments_wildcards_and_exceptions():
    rules = PublicSuffixList.parse(
        "// comment\n"
        "// ===BEGIN ICANN DOMAINS===\n"
        "com\n"
        "*.ck\n"
        "!www.ck\n"
        "\n"
        "// ===END ICANN DOMAINS===\n"
        "// ===BEGIN PRIVATE DOMAINS===\n"
        "github.io\n"
    )
    assert rules.exact == {"com"} and rules.wildcard == {"ck"} and rules.exception == {"www.ck"}
    with_private = PublicSuffixList.parse(
        "// ===BEGIN ICANN DOMAINS===\ncom\n// ===END ICANN DOMAINS===\n"
        "// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n", include_private=True)
    assert with_private.exact == {"com", "github.io"}


def test_bundled_list_is_present_and_substantial():
    rules = PublicSuffixList.load().rules
    assert len(rules) > 5000 and "com" in rules.exact and "co.uk" in rules.exact
