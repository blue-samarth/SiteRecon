'''
Subdomain-takeover fingerprints.

A subdomain is takeover-prone when it delegates (CNAME) to a third-party service whose backing resource is
no longer claimed: an attacker who registers that resource (a GitHub Pages repo, an S3 bucket, a Heroku app,
…) can then serve content on the victim's subdomain. Two signals establish it:
  * the CNAME target does not resolve, for providers where a missing target means the resource is gone, or
  * the delegated page returns the provider's well-known "unclaimed resource" body.

The data here is a compact, high-confidence subset of the public can-i-take-over-xyz corpus.
'''

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class TakeoverSignature:
    '''
    One provider whose CNAME targets are associated with dangling-record takeovers.
    '''
    provider: str
    suffixes: tuple[str, ...] = ()        # CNAME target suffixes (label-boundary match)
    keywords: tuple[str, ...] = ()        # substrings of the CNAME target (for regional/variable hosts)
    fingerprints: tuple[str, ...] = field(default_factory=tuple)   # response-body strings meaning "unclaimed"
    nxdomain_vulnerable: bool = False     # a CNAME here whose target does not resolve is itself a dangling takeover

    def matches(self, cname: str) -> bool:
        '''
        Whether a CNAME target points at this provider.
        Parameters:
            cname (str): The CNAME target hostname.
        Returns:
            bool: True if the target matches a suffix or keyword for this provider.
        '''
        c = cname.lower().rstrip(".")
        if any(c == s or c.endswith("." + s) for s in self.suffixes):
            return True
        return any(k in c for k in self.keywords)

    def body_unclaimed(self, body: str) -> bool:
        '''
        Whether a fetched response body carries this provider's unclaimed-resource fingerprint.
        Parameters:
            body (str): The response body (any case).
        Returns:
            bool: True if an unclaimed fingerprint is present.
        '''
        lowered = body.lower()
        return any(fp.lower() in lowered for fp in self.fingerprints)


TAKEOVER_SIGNATURES: tuple[TakeoverSignature, ...] = (
    TakeoverSignature("GitHub Pages", suffixes=("github.io",),
                      fingerprints=("There isn't a GitHub Pages site here.",
                                    "For root URLs (like http://example.com/) you must provide an index.html file")),
    TakeoverSignature("AWS S3", keywords=("s3.amazonaws.com", "s3-website", "s3.dualstack", "s3-external"),
                      fingerprints=("NoSuchBucket", "The specified bucket does not exist"),
                      nxdomain_vulnerable=True),
    TakeoverSignature("AWS CloudFront", suffixes=("cloudfront.net",),
                      fingerprints=("ERROR: The request could not be satisfied",)),
    TakeoverSignature("AWS Elastic Beanstalk", keywords=("elasticbeanstalk.com",), nxdomain_vulnerable=True),
    TakeoverSignature("Heroku", suffixes=("herokuapp.com", "herokudns.com", "herokussl.com"),
                      fingerprints=("No such app", "herokucdn.com/error-pages/no-such-app.html"),
                      nxdomain_vulnerable=True),
    TakeoverSignature("Microsoft Azure",
                      suffixes=("azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net",
                                "blob.core.windows.net", "azureedge.net", "azure-api.net", "azurefd.net",
                                "azurecontainer.io"),
                      nxdomain_vulnerable=True),
    TakeoverSignature("Fastly", suffixes=("fastly.net",), fingerprints=("Fastly error: unknown domain",)),
    TakeoverSignature("Shopify", suffixes=("myshopify.com",),
                      fingerprints=("Sorry, this shop is currently unavailable.",)),
    TakeoverSignature("Surge.sh", suffixes=("surge.sh",), fingerprints=("project not found",),
                      nxdomain_vulnerable=True),
    TakeoverSignature("Bitbucket", suffixes=("bitbucket.io",), fingerprints=("Repository not found",)),
    TakeoverSignature("Ghost", suffixes=("ghost.io",),
                      fingerprints=("The thing you were looking for is no longer here",)),
    TakeoverSignature("Pantheon", suffixes=("pantheonsite.io",),
                      fingerprints=("The gods are wise, but do not know of the site which you seek.",)),
    TakeoverSignature("Tumblr", suffixes=("domains.tumblr.com",),
                      fingerprints=("Whatever you were looking for doesn't currently exist at this address.",)),
    TakeoverSignature("WordPress.com", suffixes=("wordpress.com",), fingerprints=("Do you want to register",)),
    TakeoverSignature("Zendesk", suffixes=("zendesk.com",), fingerprints=("Help Center Closed",)),
    TakeoverSignature("Read the Docs", suffixes=("readthedocs.io",),
                      fingerprints=("unknown to Read the Docs",), nxdomain_vulnerable=True),
    TakeoverSignature("Netlify", suffixes=("netlify.app", "netlify.com"), nxdomain_vulnerable=True),
    TakeoverSignature("Cargo", suffixes=("cargocollective.com",), fingerprints=("404 Not Found",)),
    TakeoverSignature("Helpjuice", suffixes=("helpjuice.com",), fingerprints=("We could not find what you're looking for.",)),
    TakeoverSignature("Helpscout", suffixes=("helpscoutdocs.com",), fingerprints=("No settings were found for this company:",)),
)


def match_cname(cname: str) -> TakeoverSignature | None:
    '''
    Find the takeover signature a CNAME target points at, if any.
    Parameters:
        cname (str): The CNAME target hostname.
    Returns:
        TakeoverSignature | None: The matching provider signature, or None.
    '''
    return next((sig for sig in TAKEOVER_SIGNATURES if sig.matches(cname)), None)
