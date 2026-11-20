'''
Signatures for interpreting historical (archived) URLs.

Archived URLs are evidence of the past: a path that was once fetchable, a query parameter a link once
carried, a file extension that reveals the stack a site used to run. Nothing here says a URL is reachable
today — that is deliberately left to a live check — so every signature is interpreted as a *hint* with a
first/last-seen window attached.

Three tables live here:
  * ``SENSITIVE_PATH`` — paths worth a second look if they were ever public (backups, dumps, configs, keys).
  * ``HISTORICAL_TECH_HINTS`` — path/extension conventions that identify an old stack.
  * ``PARAMETER_PATTERNS`` — query-parameter name classes (credential, redirect, file, identifier).
'''

from __future__ import annotations

import re
from dataclasses import dataclass

from recon.models.common import Confidence

# Version of the historical signature set; bump on any change.
HISTORICAL_SIGNATURES_VERSION: str = "2026.11.18"

# Paths worth a second look if they were ever public (historical exposure, never current proof).
SENSITIVE_PATH: re.Pattern[str] = re.compile(
    r"(\.(?:sql|bak|old|swp|zip|tar|gz|tgz|rar|7z|env|log|pem|key|p12|pfx|ini|conf|config|yml|yaml|json|bson|dump"
    r"|sqlite|sqlite3|db|mdb|csv|xls|xlsx|pst|ovpn|kdbx|jks|keystore)"
    r"(?:$|[?#])|/(?:\.git|\.env|\.svn|\.hg|\.ds_store|\.aws|\.ssh|\.npmrc|backup|backups|dump|db|database|wp-config|"
    r"config\.php|configuration\.php|settings\.py|local_settings|phpinfo|info\.php|test\.php|adminer|phpmyadmin|"
    r"id_rsa|id_dsa|credentials|secret|secrets|private|passwd|htpasswd|web\.config|appsettings|"
    r"docker-compose|dockerfile|\.travis\.yml|\.gitlab-ci\.yml|jenkinsfile|server-status|server-info|"
    r"actuator|swagger|graphiql|graphql-playground|debug|trace\.axd|elmah\.axd)\b)", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class TechHintSignature:
    '''
    A technology hint recoverable from a URL path or extension.

    ``confidence`` is the strength of the *hint*, not of a current detection: a ``.php`` extension is a
    decisive statement about what served that URL at the time (MEDIUM), while a directory convention such
    as ``/admin/`` is weak (LOW). Nothing here is ever promoted to a confirmed current technology.
    '''
    name: str
    category: str
    pattern: str
    confidence: Confidence
    note: str = ""


TH = TechHintSignature
_H, _M, _L = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW

# Path/extension conventions → the technology that served the URL when it was archived.
HISTORICAL_TECH_HINTS: tuple[TechHintSignature, ...] = (
    # Languages and runtimes stated by the extension — decisive for the time the URL was archived.
    TH("PHP", "language", r"\.php[3457s]?(?:$|[?#/])", _M),
    TH("ASP.NET", "backend_framework", r"\.as[pm]x(?:$|[?#])", _M),
    TH("Classic ASP", "backend_framework", r"\.asp(?:$|[?#])", _M),
    TH("JavaServer Pages", "backend_framework", r"\.jsp[xf]?(?:$|[?#])", _M),
    TH("Java Servlet", "backend_framework", r"/servlet/|\.do(?:$|[?#])|\.action(?:$|[?#])", _L),
    TH("ColdFusion", "backend_framework", r"\.cf[mc](?:$|[?#])", _M),
    TH("Perl", "language", r"\.pl(?:$|[?#])|/cgi-bin/[^/]*\.pl", _L),
    TH("CGI", "backend_framework", r"/cgi-bin/", _M),
    TH("Python (WSGI/CGI)", "language", r"\.py(?:$|[?#])", _L),
    TH("Ruby (CGI)", "language", r"\.rbx?(?:$|[?#])", _L),
    TH("Adobe Flash", "deprecated", r"\.swf(?:$|[?#])", _M,
       note="Flash has been end-of-life since 2020; archived SWF content indicates a legacy front end."),
    TH("Silverlight", "deprecated", r"\.xap(?:$|[?#])", _M, note="Silverlight is end-of-life."),
    TH("Java Applet", "deprecated", r"\.(?:jar|class)(?:$|[?#])", _L),
    # CMS and platform conventions.
    TH("WordPress", "cms", r"/wp-content/|/wp-includes/|/wp-admin/|/wp-json/|/\?p=\d+", _M),
    TH("Drupal", "cms", r"/sites/default/files/|/sites/all/modules/|/node/\d+", _M),
    TH("Joomla", "cms", r"/administrator/|option=com_|/components/com_", _M),
    TH("TYPO3", "cms", r"/typo3conf/|/typo3temp/|/fileadmin/", _M),
    TH("Magento", "ecommerce", r"/skin/frontend/|/media/catalog/product/|/checkout/cart/", _M),
    TH("PrestaShop", "ecommerce", r"/modules/[a-z]+/|/img/p/\d+", _L),
    TH("OpenCart", "ecommerce", r"index\.php\?route=", _M),
    TH("Shopify", "ecommerce", r"/cdn/shop/|/collections/[^/]+/products/", _L),
    TH("Umbraco", "cms", r"/umbraco/", _M),
    TH("Sitecore", "cms", r"/sitecore/|/-/media/", _M),
    TH("Adobe Experience Manager", "cms", r"/content/dam/|/etc\.clientlibs/", _M),
    TH("Blogger", "cms", r"/\d{4}/\d{2}/[a-z0-9-]+\.html", _L),
    # Modern front ends (still only a hint about when the URL was archived).
    TH("Next.js", "frontend_framework", r"/_next/(?:static|data|image)", _M),
    TH("Nuxt", "frontend_framework", r"/_nuxt/", _M),
    TH("Gatsby", "frontend_framework", r"/page-data/|/static/[0-9a-f]{32}", _L),
    TH("Astro", "frontend_framework", r"/_astro/", _M),
    TH("SvelteKit", "frontend_framework", r"/_app/immutable/", _M),
    TH("Angular", "frontend_framework", r"/main\.[0-9a-f]{16,}\.js", _L),
    TH("jQuery", "javascript_library", r"/jquery[.-][\d.]+(?:\.min)?\.js", _M),
    # API surfaces.
    TH("GraphQL", "api", r"/graphql(?:$|[?#/])|/gql(?:$|[?#/])", _M),
    TH("REST API (versioned)", "api", r"/api/v\d{1,2}/|/v\d{1,2}/api/", _M),
    TH("SOAP / WSDL", "api", r"\?wsdl(?:$|&)|\.asmx|\.svc(?:$|[?#/])", _M),
    TH("OpenAPI / Swagger", "api", r"/swagger|/openapi\.json|/api-docs", _M),
    TH("WebSocket endpoint", "api", r"/socket\.io/|/ws(?:$|[?#/])", _L),
    # Admin and tooling surfaces (weak hints, useful as review leads).
    TH("phpMyAdmin", "admin_tool", r"/phpmyadmin|/pma(?:$|/)", _M),
    TH("AWStats", "admin_tool", r"/awstats", _M),
    TH("Webmail", "admin_tool", r"/webmail|/roundcube|/squirrelmail|/horde", _M),
    TH("Spring Boot Actuator", "admin_tool", r"/actuator(?:$|/)", _M),
    TH("Jenkins", "admin_tool", r"/jenkins(?:$|/)|/job/[^/]+/build", _M),
)


@dataclass(frozen=True, slots=True)
class ParameterSignature:
    '''
    A query-parameter name class, with how it should be read.

    ``category`` drives which finding a parameter contributes to: ``credential`` names mean a secret may
    have been logged into an archive, ``redirect``/``file`` names mark a classic injection surface, and
    ``identifier`` names are ordinary application plumbing recorded only as inventory.
    '''
    category: str          # credential, redirect, file, identifier
    pattern: str           # regex over the lowercased parameter name
    note: str = ""


P = ParameterSignature

PARAMETER_PATTERNS: tuple[ParameterSignature, ...] = (
    P("credential", r"^(?:.*_)?(?:token|access_token|id_token|refresh_token|auth|authorization|apikey|api_key|"
                    r"key|secret|client_secret|password|passwd|pwd|pass|session|sessionid|sid|jwt|signature|sig|"
                    r"hash|otp|code|credential|credentials|private_key)$",
      note="A credential-looking parameter in an archived URL means the value itself may sit in third-party "
           "archives, proxy logs and browser history."),
    P("redirect", r"^(?:.*_)?(?:redirect|redirect_uri|redirect_url|return|return_url|returnurl|next|continue|"
                  r"callback|cb|goto|dest|destination|target|url|uri|link|forward|out|r|u)$",
      note="A URL-valued parameter is the classic open-redirect / SSRF surface; check that it is validated "
           "against an allow-list."),
    P("file", r"^(?:.*_)?(?:file|filename|filepath|path|dir|folder|doc|document|download|load|include|inc|"
              r"template|page|view|img|image|src|attachment)$",
      note="A path-valued parameter is the classic local-file-inclusion / path-traversal surface."),
    P("identifier", r"^(?:.*_)?(?:id|uid|userid|user_id|account|acct|order|order_id|invoice|customer|ref|"
                    r"reference|product|item|cart|email|phone|q|query|search|page|offset|limit|sort|lang|locale)$",
      note="Ordinary application parameter; recorded as inventory. Object identifiers are worth reviewing for "
           "authorization (IDOR) when they address per-user data."),
)


def classify_parameter(name: str) -> ParameterSignature | None:
    '''
    Classify a query-parameter name into its first matching class.
    Parameters:
        name (str): Parameter name (any casing).
    Returns:
        ParameterSignature | None: The matching class, or None when the name matches none.
    '''
    lowered = name.strip().lower()
    if not lowered:
        return None
    for sig in PARAMETER_PATTERNS:
        if re.fullmatch(sig.pattern, lowered, re.IGNORECASE):
            return sig
    return None


def match_tech_hints(path: str) -> list[TechHintSignature]:
    '''
    Every technology hint a URL path matches.
    Parameters:
        path (str): URL path (and query), already lowercased or not.
    Returns:
        list[TechHintSignature]: Matching hints, in table order (possibly empty).
    '''
    return [sig for sig in HISTORICAL_TECH_HINTS if re.search(sig.pattern, path, re.IGNORECASE)]
