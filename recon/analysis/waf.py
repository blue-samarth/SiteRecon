'''
Web Application Firewall (WAF) identification from passively collected evidence.

Matches already-collected HTTP response headers, the server banner and cookie *names* against a curated,
versioned signature set. No requests are sent and no payloads are used to provoke a block (that would be
active testing); this only reads what the passive scan already observed.

Two honesty rules shape the design:
  * Absence of a recognizable signature is NOT proof that no WAF exists — many WAFs are invisible on a
    normal 200 response — so a non-match produces no finding, never a "no WAF" claim.
  * A shared CDN/proxy signal (e.g. a Cloudflare ``cf-ray`` header) proves the proxy is in front of the
    origin and is WAF-*capable*, not that WAF rules are enabled, so such signals are MEDIUM confidence.
'''

from __future__ import annotations

from dataclasses import dataclass, field
from collections.abc import Iterable

from recon.analysis.tech_signatures import SIGNATURES_VERSION
from recon.models import Confidence

__all__ = ["WafSignature", "WafDetection", "WAF_SIGNATURES", "detect_wafs", "SIGNATURES_VERSION"]

_H, _M = Confidence.HIGH, Confidence.MEDIUM


@dataclass(frozen=True, slots=True)
class WafSignature:
    '''
    Identifies a WAF by a response header, server banner or cookie name, with the confidence a match earns.
    '''
    vendor: str
    confidence: Confidence
    note: str = ""
    headers: tuple[tuple[str, str], ...] = ()   # (lowercased header name, value substring or "" = presence)
    cookies: tuple[str, ...] = ()               # cookie-name prefixes (lowercased)
    server: tuple[str, ...] = ()                # server-banner substrings (lowercased)

    def match(self, headers: dict[str, str], cookies: list[str], server: str) -> str | None:
        '''
        Return a short description of the first matching signal, or None.
        Parameters:
            headers (dict[str, str]): Lowercased header name → joined lowercased value.
            cookies (list[str]): Lowercased cookie names.
            server (str): Lowercased server banner.
        Returns:
            str | None: What matched (for evidence), or None.
        '''
        for name, needle in self.headers:
            if name in headers and (not needle or needle in headers[name]):
                return f"header '{name}'" + (f" contains '{needle}'" if needle else "")
        for prefix in self.cookies:
            hit = next((c for c in cookies if c.startswith(prefix)), None)
            if hit is not None:
                return f"cookie '{hit}'"
        for needle in self.server:
            if needle in server:
                return f"server banner contains '{needle}'"
        return None


@dataclass(slots=True)
class WafDetection:
    '''
    One detected WAF vendor, the confidence, what matched, and any caveat.
    '''
    vendor: str
    confidence: Confidence
    evidence: list[str] = field(default_factory=list)
    note: str = ""


# Curated, low-false-positive WAF signatures. Versioned via SIGNATURES_VERSION. A vendor may appear more
# than once (e.g. a proxy header at MEDIUM and a challenge cookie at HIGH); the detector keeps the strongest.
WAF_SIGNATURES: tuple[WafSignature, ...] = (
    # Cloudflare — cf-ray/server prove the proxy (WAF-capable); the challenge/bot cookies prove active rules.
    WafSignature("Cloudflare", _M, "reverse proxy present; WAF/bot rules may or may not be enabled",
                 headers=(("cf-ray", ""),), server=("cloudflare",)),
    WafSignature("Cloudflare", _H, "bot-management / challenge cookie present",
                 cookies=("__cf_bm", "cf_clearance")),
    # Sucuri CloudProxy
    WafSignature("Sucuri CloudProxy", _H, headers=(("x-sucuri-id", ""), ("x-sucuri-cache", "")),
                 server=("sucuri",), cookies=("sucuri-",)),
    # Imperva (Incapsula)
    WafSignature("Imperva (Incapsula)", _H, headers=(("x-iinfo", ""), ("x-cdn", "incapsula")),
                 cookies=("incap_ses_", "visid_incap_", "nlbi_")),
    # Akamai — edge banner/header prove Akamai (Kona WAF capable), not that Kona rules are on.
    WafSignature("Akamai (Kona)", _M, "Akamai edge present; WAF (Kona) may or may not be enabled",
                 server=("akamaighost",), headers=(("x-akamai-transformed", ""),)),
    # F5 BIG-IP ASM — TS cookies are an ASM hint (could also be LTM); heuristic.
    WafSignature("F5 BIG-IP (ASM)", _M, "TS cookie suggests F5 BIG-IP (ASM or LTM)", cookies=("ts01",)),
    # Barracuda
    WafSignature("Barracuda", _H, cookies=("barra_counter_session", "barracuda_")),
    # Wordfence (WordPress)
    WafSignature("Wordfence", _H, cookies=("wfwaf-authcookie-", "wordfence_verifiedhuman")),
    # Fastly Next-Gen WAF (Signal Sciences)
    WafSignature("Fastly / Signal Sciences", _H, headers=(("x-sigsci-requestid", ""), ("x-sigsci-tags", ""))),
    # Azure Front Door — WAF policy may or may not be attached.
    WafSignature("Azure Front Door", _M, "Azure Front Door present; WAF policy may or may not be attached",
                 headers=(("x-azure-ref", ""),)),
    # ModSecurity (open-source engine, often behind Apache/Nginx)
    WafSignature("ModSecurity", _M, server=("mod_security", "modsecurity"), headers=(("x-mod-security", ""),)),
)


def detect_wafs(headers: dict[str, list[str]], cookie_names: Iterable[str],
                server: str | None) -> list[WafDetection]:
    '''
    Identify WAFs from response headers, cookie names and the server banner.

    Multiple vendors can be returned (a site may stack a CDN WAF and an app-level WAF). For each vendor the
    strongest matching signal sets the confidence and every matching signal is kept as evidence.
    Parameters:
        headers (dict[str, list[str]]): Response headers (any casing; values as lists).
        cookie_names (Iterable[str]): Cookie names observed (values are never needed).
        server (str | None): The server banner, if any.
    Returns:
        list[WafDetection]: Detections, most confident first then by vendor; empty if nothing matched.
    '''
    hdr: dict[str, str] = {k.lower(): " ".join(v).lower() for k, v in headers.items()}
    cookies: list[str] = [c.lower() for c in cookie_names]
    banner: str = (server or "").lower()

    collected: dict[str, list[tuple[Confidence, str, str]]] = {}
    for sig in WAF_SIGNATURES:
        matched = sig.match(hdr, cookies, banner)
        if matched is not None:
            collected.setdefault(sig.vendor, []).append((sig.confidence, matched, sig.note))

    detections: list[WafDetection] = []
    for vendor, signals in collected.items():
        confidence = max((c for c, _, _ in signals), key=lambda c: c.rank)
        note = next((n for c, _, n in sorted(signals, key=lambda s: -s[0].rank) if n), "")
        detections.append(WafDetection(vendor, confidence, [ev for _, ev, _ in signals], note))
    return sorted(detections, key=lambda d: (-d.confidence.rank, d.vendor))
