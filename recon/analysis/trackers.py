'''
Tracker taxonomy: classifies third-party services into their tracking *purpose*.

The third-party inventory already identifies external services (``modules/third_party.py``); this layer
adds the privacy lens — which of those are trackers, and of what kind — using a curated, versioned
signature set. It performs no network I/O and does not detect new domains; it reclassifies domains the
third-party inventory already found. The signature-set version is :data:`SIGNATURES_VERSION`, so every
detection can cite the exact signature database that produced it.
'''

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from recon.analysis.tech_signatures import SIGNATURES_VERSION

__all__ = ["TrackerCategory", "TrackerSignature", "TRACKER_SIGNATURES", "PRIVACY_SENSITIVE",
           "classify_tracker", "SIGNATURES_VERSION"]


class TrackerCategory(StrEnum):
    '''
    The purpose a tracker serves, from least to most privacy-sensitive-ish (order is for grouping only).
    '''
    ANALYTICS = "analytics"              # first-party-style usage measurement
    TAG_MANAGER = "tag_manager"          # injects/relays other tags
    AB_TESTING = "ab_testing"            # experimentation / feature experiments
    CONSENT = "consent"                  # consent management platforms
    CDP = "cdp"                          # customer data platforms (identity stitching)
    SOCIAL = "social"                    # social-network pixels / widgets
    ADVERTISING = "advertising"          # ad networks, retargeting, cross-site tracking
    SESSION_REPLAY = "session_replay"    # records sessions / keystrokes / mouse movement
    FINGERPRINTING = "fingerprinting"    # device/browser fingerprinting
    OTHER = "other"


# Categories whose data collection most often triggers consent/compliance obligations; surfaced separately.
PRIVACY_SENSITIVE: frozenset[TrackerCategory] = frozenset(
    {TrackerCategory.SESSION_REPLAY, TrackerCategory.FINGERPRINTING})


@dataclass(frozen=True, slots=True)
class TrackerSignature:
    '''
    Maps hostname suffixes to a tracker provider and its tracking category.
    '''
    provider: str
    category: TrackerCategory
    suffixes: tuple[str, ...]

    def matches(self, host: str) -> bool:
        '''
        Whether a hostname is this tracker (exact or label-boundary suffix match).
        Parameters:
            host (str): Hostname to test.
        Returns:
            bool: True if the host equals or ends with one of the suffixes at a label boundary.
        '''
        host = host.lower().rstrip(".")
        return any(host == s or host.endswith("." + s) for s in self.suffixes)


_C = TrackerCategory

# Curated tracker signatures. Versioned via SIGNATURES_VERSION; extend over time. A provider may appear
# once with its primary role (e.g. Microsoft Clarity is session replay, not plain analytics).
TRACKER_SIGNATURES: tuple[TrackerSignature, ...] = (
    # analytics
    TrackerSignature("Google Analytics", _C.ANALYTICS, ("google-analytics.com", "analytics.google.com")),
    TrackerSignature("Plausible", _C.ANALYTICS, ("plausible.io",)),
    TrackerSignature("PostHog", _C.ANALYTICS, ("posthog.com", "i.posthog.com")),
    TrackerSignature("Cloudflare Web Analytics", _C.ANALYTICS, ("cloudflareinsights.com",)),
    TrackerSignature("Mixpanel", _C.ANALYTICS, ("mxpnl.com", "mixpanel.com")),
    TrackerSignature("Amplitude", _C.ANALYTICS, ("amplitude.com",)),
    TrackerSignature("Heap", _C.ANALYTICS, ("heap.io", "heapanalytics.com")),
    TrackerSignature("Matomo", _C.ANALYTICS, ("matomo.cloud",)),
    TrackerSignature("Fathom", _C.ANALYTICS, ("usefathom.com",)),
    TrackerSignature("Simple Analytics", _C.ANALYTICS, ("simpleanalytics.com", "simpleanalyticscdn.com")),
    TrackerSignature("StatCounter", _C.ANALYTICS, ("statcounter.com",)),
    # tag managers
    TrackerSignature("Google Tag Manager", _C.TAG_MANAGER, ("googletagmanager.com",)),
    TrackerSignature("Adobe Experience Platform (Launch/DTM)", _C.TAG_MANAGER, ("adobedtm.com",)),
    TrackerSignature("Tealium", _C.TAG_MANAGER, ("tiqcdn.com",)),
    # A/B testing / experimentation
    TrackerSignature("Optimizely", _C.AB_TESTING, ("optimizely.com",)),
    TrackerSignature("VWO", _C.AB_TESTING, ("visualwebsiteoptimizer.com", "vwo.com")),
    TrackerSignature("AB Tasty", _C.AB_TESTING, ("abtasty.com",)),
    # consent management
    TrackerSignature("OneTrust", _C.CONSENT, ("cookielaw.org", "onetrust.com")),
    TrackerSignature("Cookiebot", _C.CONSENT, ("cookiebot.com",)),
    TrackerSignature("IAB TCF (consensu)", _C.CONSENT, ("consensu.org",)),
    TrackerSignature("Iubenda", _C.CONSENT, ("iubenda.com",)),
    TrackerSignature("Termly", _C.CONSENT, ("termly.io",)),
    TrackerSignature("Usercentrics", _C.CONSENT, ("usercentrics.eu",)),
    # customer data platforms
    TrackerSignature("Segment", _C.CDP, ("segment.com", "segment.io")),
    TrackerSignature("RudderStack", _C.CDP, ("rudderstack.com", "rudderlabs.com")),
    # social pixels
    TrackerSignature("Meta Pixel", _C.SOCIAL, ("connect.facebook.net",)),
    TrackerSignature("LinkedIn Insight", _C.SOCIAL, ("snap.licdn.com",)),
    TrackerSignature("TikTok Pixel", _C.SOCIAL, ("analytics.tiktok.com",)),
    TrackerSignature("Snap Pixel", _C.SOCIAL, ("sc-static.net",)),
    TrackerSignature("Pinterest Tag", _C.SOCIAL, ("pinimg.com",)),
    TrackerSignature("Reddit Pixel", _C.SOCIAL, ("redditstatic.com",)),
    # advertising / retargeting
    TrackerSignature("Google Ads / DoubleClick", _C.ADVERTISING,
                     ("doubleclick.net", "googlesyndication.com", "googleadservices.com")),
    TrackerSignature("Microsoft Advertising (UET)", _C.ADVERTISING, ("bat.bing.com",)),
    TrackerSignature("Twitter/X Ads", _C.ADVERTISING, ("ads-twitter.com", "analytics.twitter.com")),
    TrackerSignature("Amazon Ads", _C.ADVERTISING, ("amazon-adsystem.com",)),
    TrackerSignature("Criteo", _C.ADVERTISING, ("criteo.com", "criteo.net")),
    TrackerSignature("Taboola", _C.ADVERTISING, ("taboola.com",)),
    TrackerSignature("Outbrain", _C.ADVERTISING, ("outbrain.com",)),
    TrackerSignature("AdRoll", _C.ADVERTISING, ("adroll.com",)),
    TrackerSignature("Comscore", _C.ADVERTISING, ("scorecardresearch.com",)),
    TrackerSignature("Quantcast", _C.ADVERTISING, ("quantserve.com", "quantcast.com")),
    TrackerSignature("AppNexus (Xandr)", _C.ADVERTISING, ("adnxs.com",)),
    # session replay / heatmaps
    TrackerSignature("Hotjar", _C.SESSION_REPLAY, ("hotjar.com", "hotjar.io")),
    TrackerSignature("Microsoft Clarity", _C.SESSION_REPLAY, ("clarity.ms",)),
    TrackerSignature("FullStory", _C.SESSION_REPLAY, ("fullstory.com",)),
    TrackerSignature("LogRocket", _C.SESSION_REPLAY, ("logrocket.com", "lr-ingest.io")),
    TrackerSignature("Mouseflow", _C.SESSION_REPLAY, ("mouseflow.com",)),
    TrackerSignature("Smartlook", _C.SESSION_REPLAY, ("smartlook.com",)),
    TrackerSignature("Lucky Orange", _C.SESSION_REPLAY, ("luckyorange.com",)),
    TrackerSignature("Inspectlet", _C.SESSION_REPLAY, ("inspectlet.com",)),
    # fingerprinting
    TrackerSignature("FingerprintJS", _C.FINGERPRINTING, ("fingerprint.com", "fpjs.io", "fpnpmcdn.net")),
)


def classify_tracker(host: str) -> TrackerSignature | None:
    '''
    Classify a hostname as a known tracker, or None if it is not one.

    The most specific (longest) matching suffix wins, so ``analytics.google.com`` is not shadowed by a
    shorter ``google.com`` entry were one to exist.
    Parameters:
        host (str): Hostname to classify.
    Returns:
        TrackerSignature | None: The matching signature, or None.
    '''
    if not host:
        return None
    best: TrackerSignature | None = None
    best_len = -1
    for sig in TRACKER_SIGNATURES:
        if sig.matches(host):
            longest = max(len(s) for s in sig.suffixes if host == s or host.lower().rstrip(".").endswith("." + s))
            if longest > best_len:
                best, best_len = sig, longest
    return best
