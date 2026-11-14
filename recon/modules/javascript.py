'''
Static analysis of publicly referenced JavaScript and CSS bundles.

Assets are downloaded through the scope-restricted client (target scope plus explicitly allowed
asset hosts), size-capped, and scanned as text — never executed. The analysis records library
markers (versions only when a banner states one), the service hostnames and API endpoints a bundle
references, public client-configuration blocks (identifier fields shown, key fields redacted), and
whether referenced source maps are publicly reachable. Values matching private-credential patterns
are reported by type and fingerprint only: raw secret values are never stored, and none are ever used.
'''

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass
from typing import ClassVar
from urllib.parse import urljoin, urlsplit

import httpx

from recon.models import CollectionError, Confidence, CrawlData, HtmlData
from recon.models.assets import (
    AssetData,
    AssetRecord,
    ClientConfig,
    ClientConfigValue,
    EndpointRef,
    LibraryHit,
    SecretFinding,
    SkippedAsset,
)
from recon.modules.base import Collector
from recon.utils import BlockedRequestError, SafeHttpClient, Scope, matches_suffix, redact_secret, redact_url

H, M, L = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW


@dataclass(frozen=True, slots=True)
class BundleSignature:
    '''
    Library markers searched for in bundle text: (regex, strength). A 'version' group captures a version.
    '''
    name: str
    category: str
    markers: tuple[tuple[str, Confidence], ...]


B = BundleSignature

# Banner with version → high; distinctive runtime marker → medium; bare package name → low
# (a package name alone does not prove the library is used).
BUNDLE_SIGNATURES: tuple[BundleSignature, ...] = (
    B("jQuery", "javascript_library", ((r"jQuery v(?P<version>\d+\.\d+\.\d+)", H), (r"jquery\.org/license", M))),
    B("React", "frontend_framework", ((r"@license React", M), (r"react-dom\.production(?:\.min)?\.js", M),
                                      (r"__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED", M))),
    B("Vue.js", "frontend_framework", ((r"Vue\.js v(?P<version>\d+\.\d+\.\d+)", H),
                                       (r"__VUE_OPTIONS_API__|__VUE_PROD_DEVTOOLS__", M))),
    B("Angular", "frontend_framework", ((r"\bng-version\b", M), (r"@angular/core", L))),
    B("Svelte", "frontend_framework", ((r"svelte/internal", L),)),
    B("Next.js", "frontend_framework", ((r"__NEXT_DATA__|next-route-announcer", M),)),
    B("Nuxt", "frontend_framework", ((r"__NUXT__", M),)),
    B("Framer Motion", "javascript_library", ((r"framer-motion", L),)),
    B("Lodash", "javascript_library", ((r"@license Lodash|lodash\.com/license", M),)),
    B("Moment.js", "javascript_library", ((r"//! moment\.js\s*\n?\s*//! version : (?P<version>\d+\.\d+\.\d+)", H),
                                          (r"//! moment\.js", M))),
    B("GSAP", "javascript_library", ((r"GSAP (?P<version>\d+\.\d+\.\d+)", H),)),
    B("Chart.js", "javascript_library", ((r"Chart\.js v(?P<version>\d+\.\d+\.\d+)", H),)),
    B("core-js", "javascript_library", ((r"Denis Pushkarev", M),)),
    B("Axios", "javascript_library", ((r"isAxiosError", M),)),
    B("Redux Toolkit", "javascript_library", ((r"@reduxjs/toolkit", L),)),
    B("React Router", "javascript_library", ((r"react-router", L),)),
    B("Socket.IO", "javascript_library", ((r"socket\.io-client|engine\.io-client", L),)),
    B("Three.js", "javascript_library", ((r"THREE\.WebGLRenderer|three\.module\.js", L),)),
    B("Bootstrap", "css_framework", ((r"Bootstrap v(?P<version>\d+\.\d+\.\d+)", H),)),
    B("Tailwind CSS", "css_framework", ((r"tailwindcss v(?P<version>\d+\.\d+\.\d+)", H), (r"--tw-[a-z-]+:", M))),
    B("Font Awesome", "font", ((r"Font Awesome (?:Free |Pro )?(?P<version>\d+\.\d+\.\d+)", H),)),
    B("Vite", "build_tool", ((r"vite/modulepreload-polyfill|__vite__mapDeps", M),)),
    B("Webpack", "build_tool", ((r"webpackChunk|__webpack_require__", M),)),
    B("Supabase", "backend_service", ((r"@supabase/supabase-js|supabase-js", L),)),
    B("Firebase", "backend_service", ((r"@firebase/(?:app|auth|firestore|database)", L),)),
    B("Sentry", "monitoring", ((r"__SENTRY__", M), (r"@sentry/(?:browser|react|nextjs|vue|svelte)", L))),
    B("PostHog", "analytics", ((r"posthog-js", L),)),
    B("Stripe", "payment", ((r"js\.stripe\.com/v3", M),)),
)

# Hosts that appear in bundles as documentation/licence links, not as services the site uses.
NOISE_HOSTS: tuple[str, ...] = (
    "w3.org", "schema.org", "reactjs.org", "react.dev", "fb.me", "mozilla.org", "github.com", "npmjs.com",
    "npmjs.org", "nodejs.org", "vuejs.org", "angular.io", "angular.dev", "svelte.dev", "lodash.com", "jquery.org",
    "jquery.com", "getbootstrap.com", "tailwindcss.com", "momentjs.com", "opensource.org", "apache.org",
    "babeljs.io", "webpack.js.org", "vitejs.dev", "json-schema.org", "example.com", "example.org", "localhost",
    "goo.gl", "bit.ly", "tc39.es", "ecma-international.org", "whatwg.org", "chromium.org", "webkit.org",
    "gsap.com", "greensock.com", "chartjs.org", "threejs.org", "socket.io", "zloirock.ru", "feross.org",
)


class BundleAnalyzer:
    '''
    Text-only analysis of one bundle: library markers, referenced hosts and source-map reference.
    '''

    MAX_SCAN: ClassVar[int] = 3 * 1024 * 1024
    _HOST_URL: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:https?:)?//((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?=[/:?#\"'`\s]|$)", re.I)
    _SOURCE_MAP: ClassVar[re.Pattern[str]] = re.compile(r"[#@]\s*sourceMappingURL\s*=\s*([^\s*'\"]+)")
    MAX_HOSTS: ClassVar[int] = 100

    @classmethod
    def libraries(cls, text: str, signatures: tuple[BundleSignature, ...] = BUNDLE_SIGNATURES) -> list[LibraryHit]:
        '''
        Find library markers; for each library keep the strongest marker (and any stated version).
        Parameters:
            text (str): Bundle text.
            signatures (tuple[BundleSignature, ...]): Signatures to evaluate.
        Returns:
            list[LibraryHit]: One hit per detected library.
        '''
        hits: list[LibraryHit] = []
        for sig in signatures:
            matched = [(strength, pattern, m) for pattern, strength in sig.markers if (m := re.search(pattern, text))]
            if not matched:
                continue
            strength, pattern, _ = max(matched, key=lambda x: x[0].rank)
            version = next((m.groupdict().get("version") for _, _, m in matched if m.groupdict().get("version")), None)
            hits.append(LibraryHit(name=sig.name, category=sig.category, version=version, confidence=strength,
                                   evidence=f"marker /{pattern}/"))
        return hits

    @classmethod
    def hosts(cls, text: str) -> list[str]:
        '''
        Hostnames referenced by absolute or protocol-relative URLs, minus documentation/licence noise.
        Only hostnames are kept — never paths, queries or surrounding code.
        Parameters:
            text (str): Bundle text.
        Returns:
            list[str]: Sorted unique hostnames (capped).
        '''
        found = {m.group(1).lower().rstrip(".") for m in cls._HOST_URL.finditer(text)}
        kept = sorted(h for h in found if not any(matches_suffix(h, n) for n in NOISE_HOSTS))
        return kept[: cls.MAX_HOSTS]

    @classmethod
    def source_map(cls, text: str, header: str | None) -> str | None:
        '''
        Find the source-map reference (SourceMap header first, then the last sourceMappingURL comment).
        Parameters:
            text (str): Bundle text.
            header (str | None): SourceMap / X-SourceMap response header.
        Returns:
            str | None: Raw reference, or None.
        '''
        if header:
            return header.strip()
        matches = cls._SOURCE_MAP.findall(text[-4096:])
        return matches[-1] if matches else None


class EndpointExtractor:
    '''
    Extracts API paths and URLs referenced in a bundle. Query values are redacted; this is an
    inventory of reachable routes, not proof any is called.
    '''

    MAX: ClassVar[int] = 300
    # Absolute http(s)/protocol-relative URLs with a path.
    _ABSOLUTE: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?:https?:)?//(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?::\d{2,5})?/[^\s"'`)\\<>]{1,300}""",
        re.I)
    # Root-relative API-ish paths in quotes: "/api/...", "/v1/...", "/graphql", "/.netlify/functions/...".
    _RELATIVE: ClassVar[re.Pattern[str]] = re.compile(
        r"""["'`](/(?:api|rest|graphql|gql|v\d{1,2}|_next/data|\.netlify|\.vercel|oauth|auth|webhook)s?"""
        r"""[a-z0-9/_.\-{}:$]{0,200}(?:\?[^\s"'`]{0,200})?)["'`]""", re.I)
    _METHOD_PATH: ClassVar[re.Pattern[str]] = re.compile(
        r"""\b(GET|POST|PUT|PATCH|DELETE)\b[^"'`\n]{0,40}["'`]((?:https?:)?/[^\s"'`]{1,200})["'`]""", re.I)

    @classmethod
    def extract(cls, text: str, origin_host: str | None, scope: Scope) -> list[EndpointRef]:
        '''
        Find endpoint references, attach a method when one sits beside the path, and redact query values.
        Parameters:
            text (str): Bundle text.
            origin_host (str | None): The asset's own host (relative paths are attributed to it).
            scope (Scope): Target scope, used to flag same-site endpoints.
        Returns:
            list[EndpointRef]: Unique endpoint references (capped).
        '''
        methods: dict[str, str] = {}
        for m in cls._METHOD_PATH.finditer(text):
            methods.setdefault(cls._normalize(m.group(2)), m.group(1).upper())

        refs: dict[str, EndpointRef] = {}
        for m in cls._ABSOLUTE.finditer(text):
            cls._add(refs, m.group(0), methods, origin_host, scope, absolute=True)
        for m in cls._RELATIVE.finditer(text):
            cls._add(refs, m.group(1), methods, origin_host, scope, absolute=False)
            if len(refs) >= cls.MAX:
                break
        return list(refs.values())[: cls.MAX]

    @classmethod
    def _add(cls, refs: dict[str, EndpointRef], raw: str, methods: dict[str, str],
             origin_host: str | None, scope: Scope, absolute: bool) -> None:
        '''
        Normalize, redact and record one endpoint reference.
        Parameters:
            refs (dict[str, EndpointRef]): Accumulator keyed by redacted value.
            raw (str): Raw matched URL or path.
            methods (dict[str, str]): Normalized path → HTTP method.
            origin_host (str | None): The asset's own host.
            scope (Scope): Target scope.
            absolute (bool): Whether the match was an absolute URL.
        '''
        if absolute:
            cleaned = redact_url(raw)
            host = urlsplit(cleaned if "//" in cleaned else f"//{origin_host or ''}{cleaned}").hostname
            if host and any(matches_suffix(host, n) for n in NOISE_HOSTS):
                return   # documentation / namespace URLs are not endpoints
            same_site = scope.allows(host)
        else:
            cleaned = cls._redact_relative(raw)   # redact query keys on relative paths too
            host, same_site = origin_host, True
        if cleaned in refs or len(refs) >= cls.MAX:
            return
        refs[cleaned] = EndpointRef(value=cleaned, host=host, method=methods.get(cls._normalize(raw)),
                                    same_site=same_site)

    @staticmethod
    def _redact_relative(path: str) -> str:
        '''
        Redact sensitive query values on a root-relative path by routing it through redact_url.
        Parameters:
            path (str): Root-relative path, possibly with a query.
        Returns:
            str: Path with sensitive query values redacted.
        '''
        if "?" not in path:
            return path
        return redact_url("http://placeholder.invalid" + path).removeprefix("http://placeholder.invalid")

    @staticmethod
    def _normalize(value: str) -> str:
        '''
        Drop a query/fragment for method-matching keys.
        Parameters:
            value (str): Raw path or URL.
        Returns:
            str: Value without query or fragment.
        '''
        return re.split(r"[?#]", value, maxsplit=1)[0]


class ClientConfigExtractor:
    '''
    Detects public client-configuration blocks (Firebase, Supabase). Identifier fields are shown;
    key and token fields are redacted. These values are public by design.
    '''

    _FIREBASE_KEYS: ClassVar[tuple[str, ...]] = (
        "apiKey", "authDomain", "projectId", "storageBucket", "messagingSenderId", "appId", "measurementId",
        "databaseURL")
    _SECRET_FIELDS: ClassVar[frozenset[str]] = frozenset({"apikey", "appid", "messagingsenderid", "anonkey", "key"})
    _SUPABASE_URL: ClassVar[re.Pattern[str]] = re.compile(r"https://([a-z0-9]{20})\.supabase\.co", re.I)

    @classmethod
    def extract(cls, text: str, source_asset: str, retain: bool = False) -> list[ClientConfig]:
        '''
        Find Firebase and Supabase client configs.
        Parameters:
            text (str): Bundle text.
            source_asset (str): Asset URL (for attribution).
            retain (bool): Keep public key values unredacted (default redacts). These keys are public by
                design; retention is used only for authorized automated backend testing (--bypass-sec).
        Returns:
            list[ClientConfig]: Detected public config blocks.
        '''
        configs: list[ClientConfig] = []
        fb = cls._firebase(text, source_asset, retain)
        if fb:
            configs.append(fb)
        sb = cls._supabase(text, source_asset, retain)
        if sb:
            configs.append(sb)
        return configs

    @classmethod
    def _firebase(cls, text: str, source_asset: str, retain: bool = False) -> ClientConfig | None:
        '''
        Extract a Firebase config object (projectId shown; apiKey/appId redacted unless retained).
        Parameters:
            text (str): Bundle text.
            source_asset (str): Asset URL.
            retain (bool): Keep public key values unredacted.
        Returns:
            ClientConfig | None: The config, or None if not present.
        '''
        fields: list[ClientConfigValue] = []
        for key in cls._FIREBASE_KEYS:
            m = re.search(rf"""['"]?{key}['"]?\s*:\s*['"]([^'"]{{1,256}})['"]""", text)
            if m:
                fields.append(cls._field(key, m.group(1), retain))
        has_project = any(f.key == "projectId" for f in fields)
        if len(fields) >= 3 and has_project:
            return ClientConfig(provider="Firebase", kind="firebase", source_asset=source_asset, fields=fields)
        return None

    @classmethod
    def _supabase(cls, text: str, source_asset: str, retain: bool = False) -> ClientConfig | None:
        '''
        Extract a Supabase project URL (the public anon key, if adjacent, is redacted unless retained).
        Parameters:
            text (str): Bundle text.
            source_asset (str): Asset URL.
            retain (bool): Keep the public anon key unredacted.
        Returns:
            ClientConfig | None: The config, or None if not present.
        '''
        m = cls._SUPABASE_URL.search(text)
        if not m:
            return None
        fields = [ClientConfigValue(key="projectRef", value=m.group(1), sensitive=False),
                  ClientConfigValue(key="url", value=f"https://{m.group(1)}.supabase.co", sensitive=False)]
        anon = re.search(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", text)
        if anon:
            value = anon.group(0) if retain else redact_secret(anon.group(0))
            fields.append(ClientConfigValue(key="anonKey", value=value, sensitive=not retain))
        return ClientConfig(provider="Supabase", kind="supabase", source_asset=source_asset, fields=fields)

    @classmethod
    def _field(cls, key: str, value: str, retain: bool = False) -> ClientConfigValue:
        '''
        Build a config field, redacting key/token-like fields unless retention is requested.
        Parameters:
            key (str): Field name.
            value (str): Field value.
            retain (bool): Keep public key values unredacted.
        Returns:
            ClientConfigValue: Field with the value shown or redacted.
        '''
        if key.lower() in cls._SECRET_FIELDS and not retain:
            return ClientConfigValue(key=key, value=redact_secret(value), sensitive=True)
        return ClientConfigValue(key=key, value=value[:256], sensitive=False)


@dataclass(frozen=True, slots=True)
class AssetRef:
    '''
    A referenced asset awaiting download: its URL, kind, source page and declared integrity.
    '''
    url: str
    kind: str
    source_page: str | None
    integrity: str | None


class IntegrityVerifier:
    '''
    Verifies Subresource Integrity attributes against downloaded bytes (W3C SRI).
    A declaration may list several hashes; the content is valid if any one matches.
    '''

    ALGORITHMS: ClassVar[dict[str, str]] = {"sha256": "sha256", "sha384": "sha384", "sha512": "sha512"}

    @classmethod
    def verify(cls, declared: str | None, body: bytes, truncated: bool) -> tuple[str | None, str | None]:
        '''
        Check an integrity attribute against the asset body.
        Parameters:
            declared (str | None): The integrity attribute value (e.g. 'sha384-base64 sha256-base64').
            body (bytes): The bytes that were downloaded.
            truncated (bool): Whether the body hit the size cap (verification is impossible if so).
        Returns:
            tuple[str | None, str | None]: (status, algorithm). Status is absent, unverifiable,
                unsupported_algorithm, verified or mismatch.
        '''
        import base64
        import binascii

        if not declared:
            return "absent", None
        if truncated:
            return "unverifiable", None
        algorithms: list[str] = []
        for token in declared.split():
            algorithm, sep, digest = token.partition("-")
            algorithm = algorithm.lower()
            if not sep or algorithm not in cls.ALGORITHMS:
                continue
            algorithms.append(algorithm)
            expected = digest.split("?")[0]             # strip SRI options
            try:
                want = base64.b64decode(expected + "=" * (-len(expected) % 4), validate=False)
            except (binascii.Error, ValueError):
                continue
            if hashlib.new(cls.ALGORITHMS[algorithm], body).digest() == want:
                return "verified", algorithm
        if not algorithms:
            return "unsupported_algorithm", None
        return "mismatch", algorithms[0]


class SourceMapReader:
    '''
    Reads a public source map's file list. Only the 'sources' paths are kept; 'sourcesContent'
    (the original code) is explicitly discarded.
    '''

    MAX_SOURCES: ClassVar[int] = 200

    @staticmethod
    def looks_like_map(head: bytes) -> bool:
        '''
        Whether a response body looks like a source map rather than an error or app-shell page.
        Parameters:
            head (bytes): Start of the response body.
        Returns:
            bool: True if it parses as source-map-shaped JSON.
        '''
        start = head.lstrip()[:4096]
        return start.startswith(b"{") and (b'"mappings"' in start or b'"sources"' in start or b'"version"' in start)

    @classmethod
    def sources(cls, body: bytes) -> tuple[int, list[str]]:
        '''
        Parse the original source paths a map exposes.
        Parameters:
            body (bytes): Source map body.
        Returns:
            tuple[int, list[str]]: Total count and a capped sample of paths (never file contents).
        '''
        import json

        try:
            doc = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            return 0, []
        if not isinstance(doc, dict):
            return 0, []
        root = str(doc.get("sourceRoot") or "")
        raw = doc.get("sources")
        if not isinstance(raw, list):
            return 0, []
        paths = [f"{root}{s}" for s in raw if isinstance(s, str)]
        return len(paths), paths[: cls.MAX_SOURCES]


@dataclass(frozen=True, slots=True)
class SecretPattern:
    '''
    A private-credential pattern: a regex, the credential type, and a severity.
    '''
    type: str
    regex: re.Pattern[str]
    severity: str


class SecretScanner:
    '''
    Flags values matching private-credential patterns. Raw values are never stored: only a type and a
    non-reversible fingerprint (via redact_secret) are kept. Public identifiers are excluded by design.
    '''

    MAX: ClassVar[int] = 50
    # Patterns for clearly PRIVATE credentials. Group 'v' (or whole match) is the value to fingerprint.
    PATTERNS: ClassVar[tuple[SecretPattern, ...]] = (
        SecretPattern("aws_access_key_id", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), "high"),
        SecretPattern("aws_secret_access_key",
                      re.compile(r"""aws.{0,20}['"]?(?P<v>[A-Za-z0-9/+]{40})['"]?""", re.I), "high"),
        SecretPattern("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"), "high"),
        SecretPattern("stripe_secret_key", re.compile(r"\b(sk_live_[0-9a-zA-Z]{20,})\b"), "high"),
        SecretPattern("stripe_restricted_key", re.compile(r"\b(rk_live_[0-9a-zA-Z]{20,})\b"), "high"),
        SecretPattern("google_api_key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), "medium"),
        SecretPattern("github_token", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36})\b"), "high"),
        SecretPattern("github_pat", re.compile(r"\b(github_pat_[0-9A-Za-z_]{40,})\b"), "high"),
        SecretPattern("slack_token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b"), "high"),
        SecretPattern("sendgrid_key", re.compile(r"\b(SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43})\b"), "high"),
        SecretPattern("openai_key", re.compile(r"\b(sk-(?:proj-)?[0-9A-Za-z_\-]{20,})\b"), "high"),
        SecretPattern("twilio_key", re.compile(r"\b(SK[0-9a-fA-F]{32})\b"), "medium"),
        SecretPattern("npm_token", re.compile(r"\b(npm_[0-9A-Za-z]{36})\b"), "high"),
        SecretPattern("jwt_hs256",
                      re.compile(r"\b(eyJhbGciOiJI[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"), "medium"),
        SecretPattern("secret_assignment",
                      re.compile(r"""(?:secret|passwd|password|client_secret|api_secret|auth_token|access_token)"""
                                 r"""["']?\s*[:=]\s*["']([^"'\s]{12,120})["']""", re.I), "medium"),
    )
    # Public-by-design values that must never be reported as secrets.
    _PUBLIC_PREFIXES: ClassVar[tuple[str, ...]] = ("pk_live_", "pk_test_", "sk_test_", "G-", "GTM-", "UA-", "ca-pub-")

    @classmethod
    def scan(cls, text: str, source_asset: str) -> list[SecretFinding]:
        '''
        Find private-credential patterns and return redacted findings (never raw values).
        Parameters:
            text (str): Bundle text.
            source_asset (str): Asset URL.
        Returns:
            list[SecretFinding]: Deduplicated, redacted findings (capped).
        '''
        out: dict[str, SecretFinding] = {}
        for pattern in cls.PATTERNS:
            for m in pattern.regex.finditer(text):
                value = m.groupdict().get("v") or (m.group(1) if m.re.groups else m.group(0))
                if cls._is_public(value):
                    continue
                if pattern.type == "secret_assignment" and not cls._token_like(value):
                    continue   # skip plain words / obvious non-secrets
                type_, severity = pattern.type, pattern.severity
                if type_ == "jwt_hs256":
                    role = cls._jwt_role(value)
                    if role == "anon":
                        continue   # Supabase/PostgREST anon JWT is public by design
                    if role == "service_role":
                        type_, severity = "supabase_service_role_jwt", "high"
                digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()
                key = f"{type_}:{digest}"
                if key in out or len(out) >= cls.MAX:
                    continue
                out[key] = SecretFinding(type=type_, source_asset=source_asset,
                                         context_key=cls._context(text, m.start()),
                                         redacted=redact_secret(value), severity=severity)
        return list(out.values())

    @staticmethod
    def _jwt_role(token: str) -> str | None:
        '''
        Read the 'role' claim from a JWT payload without verifying the signature.
        Parameters:
            token (str): A JWT (header.payload.signature).
        Returns:
            str | None: The role claim (e.g. 'anon', 'service_role'), or None if unreadable.
        '''
        import base64
        import binascii
        import json

        parts = token.split(".")
        if len(parts) != 3:
            return None
        try:
            payload = parts[1] + "=" * (-len(parts[1]) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload))
        except (ValueError, binascii.Error, TypeError):
            return None
        role = claims.get("role") if isinstance(claims, dict) else None
        return str(role) if role is not None else None

    @staticmethod
    def _token_like(value: str) -> bool:
        '''
        Whether a generic assignment value looks like an opaque token rather than a plain word/placeholder.
        Parameters:
            value (str): Candidate value.
        Returns:
            bool: True if it mixes character classes or is long and non-dictionary-ish.
        '''
        if len(value) < 16 or value.lower() in ("undefined", "null", "changeme", "your_secret_here", "xxxxxxxxxxxxxxxx"):
            return False
        classes = sum(bool(re.search(p, value)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
        return classes >= 3 or bool(re.fullmatch(r"[A-Za-z0-9+/_-]{24,}", value))

    @classmethod
    def _is_public(cls, value: str) -> bool:
        '''
        Whether a value is a known public identifier (not a secret).
        Parameters:
            value (str): Candidate value.
        Returns:
            bool: True if it should not be reported as a secret.
        '''
        return value.startswith(cls._PUBLIC_PREFIXES)

    @staticmethod
    def _context(text: str, start: int) -> str | None:
        '''
        The nearest preceding identifier (variable or JSON key), to help locate the value — never the value.
        Parameters:
            text (str): Bundle text.
            start (int): Match start offset.
        Returns:
            str | None: The identifier, or None.
        '''
        window = text[max(0, start - 60):start]
        keys = re.findall(r"""['"]?([A-Za-z_$][A-Za-z0-9_$]{1,40})['"]?\s*[:=]\s*['"]?$""", window)
        return keys[-1] if keys else None


class AssetCollector(Collector[AssetData]):
    '''
    Downloads in-scope (and explicitly allowed) JS/CSS assets and analyzes them statically.
    '''

    name: ClassVar[str] = "javascript"
    _SCRIPT_EXT: ClassVar[tuple[str, ...]] = (".js", ".mjs", ".cjs")
    _STYLE_EXT: ClassVar[tuple[str, ...]] = (".css",)

    def __init__(
        self,
        hostname: str,
        client: SafeHttpClient,
        map_client: SafeHttpClient,
        *,
        html: HtmlData | None,
        crawl: CrawlData | None = None,
        allowed_hosts: tuple[str, ...] = (),
        max_assets: int = 30,
        max_total_bytes: int = 20 * 1024 * 1024,
        concurrency: int = 4,
        retain_client_keys: bool = False,
    ) -> None:
        '''
        Create the collector.
        Parameters:
            hostname (str): Normalized target hostname.
            client (SafeHttpClient): Client scoped to the target plus allowed asset hosts, capped per asset.
            map_client (SafeHttpClient): Same scope with a tiny body cap, used only to check source maps.
            html (HtmlData | None): Parsed landing page (asset references).
            crawl (CrawlData | None): Crawled pages (more asset references).
            allowed_hosts (tuple[str, ...]): External hosts explicitly permitted for asset downloads.
            max_assets (int): Maximum assets to download.
            max_total_bytes (int): Stop downloading once this many bytes were read.
            concurrency (int): Concurrent downloads.
        '''
        self.scope = Scope.for_target(hostname)
        self.allowed = Scope(hosts=allowed_hosts)
        self.client = client
        self.map_client = map_client
        self.html = html
        self.crawl = crawl
        self.allowed_hosts = allowed_hosts
        self.max_assets = max_assets
        self.max_total_bytes = max_total_bytes
        self.retain_client_keys = retain_client_keys
        self._sem = asyncio.Semaphore(max(1, concurrency))
        self._bytes = 0

    def references(self) -> list[AssetRef]:
        '''
        Collect unique (url, kind, source_page) asset references from the page and crawl.
        Returns:
            list[AssetRef]: References in discovery order.
        '''
        refs: dict[str, AssetRef] = {}
        if self.html:
            for r in self.html.resources:
                as_attr = r.attributes.get("as", "")
                integrity = r.attributes.get("integrity")
                if r.kind in ("script", "modulepreload") or (r.kind == "preload" and as_attr == "script"):
                    refs.setdefault(r.url, AssetRef(r.url, "script", self.html.source_url, integrity))
                elif r.kind == "stylesheet" or (r.kind == "preload" and as_attr == "style"):
                    refs.setdefault(r.url, AssetRef(r.url, "stylesheet", self.html.source_url, integrity))
        for page in self.crawl.pages if self.crawl else []:
            for url in page.resource_urls:
                path = urlsplit(url).path.lower()
                kind = "script" if path.endswith(self._SCRIPT_EXT) else "stylesheet" if path.endswith(self._STYLE_EXT) else None
                if kind:
                    refs.setdefault(url, AssetRef(url, kind, page.url, None))
        return list(refs.values())

    async def collect(self) -> tuple[AssetData, list[CollectionError]]:
        '''
        Download and analyze assets within scope and limits.
        Returns:
            tuple[AssetData, list[CollectionError]]: Asset analysis and download errors.
        '''
        data = AssetData(allowed_external_hosts=list(self.allowed_hosts))
        errors: list[CollectionError] = []
        selected: list[AssetRef] = []
        for ref in self.references():
            host = urlsplit(ref.url).hostname
            if not (self.scope.allows(host) or self.allowed.allows(host)):
                data.skipped.append(SkippedAsset(url=ref.url, source_page=ref.source_page, reason="out_of_scope"))
            elif len(selected) >= self.max_assets:
                data.skipped.append(SkippedAsset(url=ref.url, source_page=ref.source_page, reason="asset_limit"))
            else:
                selected.append(ref)

        records = await asyncio.gather(*(self._process(ref) for ref in selected))
        for rec in records:
            if rec.error == "byte_limit":
                data.skipped.append(SkippedAsset(url=rec.url, source_page=rec.source_page, reason="byte_limit"))
                continue
            data.assets.append(rec)
            if rec.error:
                errors.append(self.error(rec.url, "asset_fetch_failed", rec.error))
            for host in rec.service_hosts:
                sample = data.service_hosts.setdefault(host, [])
                if len(sample) < 3:
                    sample.append(rec.url)
        data.total_bytes = self._bytes
        data.service_hosts = dict(sorted(data.service_hosts.items()))
        data.endpoint_count = len(data.endpoints())
        data.secret_count = sum(len(a.secrets) for a in data.assets)
        data.integrity_verified = sum(1 for a in data.assets if a.integrity_status == "verified")
        data.integrity_mismatched = sum(1 for a in data.assets if a.integrity_status == "mismatch")
        return data, errors

    async def _process(self, ref: AssetRef) -> AssetRecord:
        '''
        Download one asset (if the byte budget allows), analyze it, then discard its contents.
        Parameters:
            ref (AssetRef): The asset reference to fetch.
        Returns:
            AssetRecord: Analysis result (error='byte_limit' when skipped for budget).
        '''
        url, kind, page = ref.url, ref.kind, ref.source_page
        rec = AssetRecord(url=redact_url(url), kind=kind, source_page=page, integrity_declared=ref.integrity)
        async with self._sem:
            if self._bytes >= self.max_total_bytes:
                rec.error = "byte_limit"
                return rec
            outcome = await self.client.fetch(url)
        resp = outcome.final
        if resp is None:
            rec.error = outcome.error or f"stopped: {outcome.stopped_reason}"
            return rec
        rec.status_code, rec.content_type = resp.status_code, resp.header("content-type")
        if resp.status_code != 200:
            return rec
        self._bytes += len(resp.body)
        rec.size, rec.truncated = len(resp.body), resp.truncated
        rec.sha256 = hashlib.sha256(resp.body).hexdigest()
        rec.integrity_status, rec.integrity_algorithm = IntegrityVerifier.verify(
            ref.integrity, resp.body, resp.truncated)
        text = resp.body[: BundleAnalyzer.MAX_SCAN].decode("utf-8", "replace")
        own_host = urlsplit(url).hostname or ""
        rec.libraries = BundleAnalyzer.libraries(text)
        rec.service_hosts = [h for h in BundleAnalyzer.hosts(text) if h != own_host]
        rec.endpoints = EndpointExtractor.extract(text, own_host, self.scope)
        rec.client_configs = ClientConfigExtractor.extract(text, rec.url, retain=self.retain_client_keys)
        rec.secrets = SecretScanner.scan(text, rec.url)
        map_ref = BundleAnalyzer.source_map(text, resp.header("sourcemap") or resp.header("x-sourcemap"))
        if map_ref:
            resolved = map_ref if map_ref.startswith("data:") else urljoin(resp.url, map_ref)
            await self._check_source_map(rec, resolved)
        return rec

    async def _check_source_map(self, rec: AssetRecord, map_url: str) -> None:
        '''
        Record whether a referenced source map is publicly reachable and, if so, which original source
        files it exposes. Only the 'sources' paths are kept; the original code ('sourcesContent') is discarded.
        Parameters:
            rec (AssetRecord): Asset record updated in place.
            map_url (str): Resolved source-map URL (or data: URI).
        '''
        if map_url.startswith("data:"):
            rec.source_map_url, rec.source_map_status = "data: (inline)", "inline"
            return
        rec.source_map_url = redact_url(map_url)
        host = urlsplit(map_url).hostname
        if not (self.scope.allows(host) or self.allowed.allows(host)):
            rec.source_map_status = "out_of_scope"
            return
        try:
            resp = await self.map_client.get(map_url)
        except (BlockedRequestError, httpx.HTTPError, OSError) as exc:
            rec.source_map_status = f"error: {type(exc).__name__}"
            return
        is_map = resp.status_code == 200 and SourceMapReader.looks_like_map(resp.body)
        if is_map and not resp.truncated:
            rec.source_map_source_count, rec.source_map_sources = SourceMapReader.sources(resp.body)
        rec.source_map_status = "public" if is_map else "not_public"
