from recon.models.http import HttpData, HttpProbe
from recon.modules import HtmlCollector, HtmlParser
from recon.utils.redact import REDACTED, redact_url
from recon.utils.scope import Scope

PAGE = b"""<!doctype html>
<html lang="en"><head>
  <title> Example Site </title>
  <meta name="description" content="An example">
  <meta name="robots" content="index, follow">
  <meta name="generator" content="WordPress 6.4.2">
  <meta property="og:title" content="OG Title">
  <meta property="og:image" content="https://ik.imagekit.io/acct/hero.png">
  <meta name="twitter:card" content="summary">
  <meta name="google-site-verification" content="abc123">
  <link rel="canonical" href="/home">
  <link rel="icon" href="/favicon.ico">
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter">
  <link rel="modulepreload" href="/assets/vendor-AbCd1234.js">
  <link rel="preconnect" href="https://api.example-backend.io">
  <script type="module" crossorigin src="/assets/index-XyZ98765.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/lib.js" integrity="sha384-x" crossorigin="anonymous"></script>
  <script>window.dataLayer = [];</script>
  <script type="application/ld+json">{"@type": "Organization", "name": "Example"}</script>
  <script type="application/ld+json">{broken</script>
  <!-- <script src="https://old-tracker.test/t.js?token=SECRET123"></script> -->
</head><body>
  <img src="https://res.cloudinary.com/demo/image.jpg">
  <img src="data:image/png;base64,AAAA">
  <iframe src="https://www.youtube.com/embed/x"></iframe>
  <form action="http://forms.example.com/submit" method="POST"></form>
  <a href="javascript:void(0)">x</a>
</body></html>"""


def parse():
    return HtmlParser(PAGE, "https://example.com/", Scope.for_target("example.com")).parse()


def test_metadata():
    d = parse()
    assert d.title == "Example Site"
    assert d.meta_description == "An example"
    assert d.robots == "index, follow"
    assert d.generator == "WordPress 6.4.2"
    assert d.lang == "en"
    assert d.canonical == "https://example.com/home"
    assert d.open_graph["og:title"] == "OG Title"
    assert d.twitter == {"twitter:card": "summary"}
    assert d.verification_tokens == {"google-site-verification": "abc123"}
    assert d.favicons == ["https://example.com/favicon.ico"]
    assert d.json_ld == [{"@type": "Organization", "name": "Example"}]
    assert "unparseable JSON-LD block" in d.parse_warnings
    assert d.inline_script_count == 1


def test_resources_and_domains():
    d = parse()
    kinds = {(r.kind, r.url) for r in d.resources}
    assert ("modulepreload", "https://example.com/assets/vendor-AbCd1234.js") in kinds
    assert ("preconnect", "https://api.example-backend.io/") in kinds or \
           ("preconnect", "https://api.example-backend.io") in kinds
    assert ("meta_image", "https://ik.imagekit.io/acct/hero.png") in kinds
    assert ("form", "http://forms.example.com/submit") in kinds
    sri = next(r for r in d.resources if "jsdelivr" in r.url)
    assert sri.attributes["integrity"] == "sha384-x" and not sri.same_site   # real value, for verification
    assert not any(r.url.startswith(("data:", "javascript:")) for r in d.resources)
    assert d.external_domains == sorted({
        "fonts.googleapis.com", "api.example-backend.io", "cdn.jsdelivr.net", "ik.imagekit.io",
        "res.cloudinary.com", "www.youtube.com"})


def test_comments_are_kept_separate_and_redacted():
    d = parse()
    assert d.comment_count == 1
    assert not any("old-tracker" in r.url for r in d.resources)
    assert d.commented_urls == [f"https://old-tracker.test/t.js?token={REDACTED}".replace("[", "%5B").replace("]", "%5D")] \
        or d.commented_urls == [f"https://old-tracker.test/t.js?token={REDACTED}"]
    assert "SECRET123" not in "".join(d.commented_urls)


def test_malformed_html_does_not_raise():
    d = HtmlParser(b"<html><head><title>x</title><script src=", "https://example.com/", Scope.for_target("example.com")).parse()
    assert d.title == "x"


def test_redact_url():
    assert redact_url("https://u:p@a.com/x?id=1&access_token=abc&X-Amz-Signature=zz") == \
        f"https://a.com/x?id=1&access_token={REDACTED}&X-Amz-Signature={REDACTED}"
    assert redact_url("https://a.com/path") == "https://a.com/path"


async def test_collect_html_requires_document():
    data, errors = await HtmlCollector("example.com", HttpData(probes=[])).collect()
    assert data is None and errors[0].error_type == "no_document"


def test_select_page_prefers_https_html():
    http_p = HttpProbe(requested_url="http://example.com/", success=True, final_url="http://example.com/",
                       final_fetched=True, content_type="text/html", body=b"<html></html>")
    https_p = HttpProbe(requested_url="https://example.com/", success=True, final_url="https://example.com/",
                        final_fetched=True, content_type="text/html; charset=utf-8", body=b"<html></html>")
    json_p = HttpProbe(requested_url="https://www.example.com/", success=True, final_url="https://www.example.com/",
                       final_fetched=True, content_type="application/json", body=b"{}")
    assert HtmlCollector.select_page(HttpData(probes=[http_p, json_p, https_p])) is https_p
