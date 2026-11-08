'''
Provider signatures used to interpret collected infrastructure evidence.
'''

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ProviderSignature:
    '''
    Provider identified by keywords in free text and/or hostname suffixes.
    '''
    provider: str
    category: str
    keywords: tuple[str, ...] = ()   # case-insensitive substrings of free text
    suffixes: tuple[str, ...] = ()   # hostname suffixes (label-boundary match)

    def match_text(self, text: str) -> str | None:
        '''
        Return the first keyword contained in the text (case-insensitive).
        Parameters:
            text (str): Free text such as an ASN or organization name.
        Returns:
            str | None: The matched keyword, or None.
        '''
        lowered = text.lower()
        return next((k for k in self.keywords if k in lowered), None)

    def match_host(self, host: str) -> str | None:
        '''
        Match a hostname by suffix (label boundary), falling back to keywords.
        Parameters:
            host (str): Hostname to test.
        Returns:
            str | None: The matched suffix or keyword, or None.
        '''
        host = host.lower().rstrip(".")
        for suffix in self.suffixes:
            if host == suffix or host.endswith("." + suffix):
                return suffix
        return self.match_text(host)


# Matched against ASN names, RDAP network/org names and PTR hostnames.
NETWORK_PROVIDERS: tuple[ProviderSignature, ...] = (
    ProviderSignature("Cloudflare", "cdn", ("cloudflare",)),
    ProviderSignature("Vercel", "hosting", ("vercel",)),
    ProviderSignature("Netlify", "hosting", ("netlify",)),
    ProviderSignature("Fastly", "cdn", ("fastly",)),
    ProviderSignature("Linode (Akamai Cloud)", "cloud", ("linode",)),
    ProviderSignature("Akamai", "cdn", ("akamai",)),
    ProviderSignature("Amazon Web Services", "cloud", ("amazon", "aws", "amazonaws", "cloudfront")),
    ProviderSignature("Google Cloud", "cloud", ("google", "googleusercontent")),
    ProviderSignature("Microsoft Azure", "cloud", ("microsoft", "azure")),
    ProviderSignature("DigitalOcean", "cloud", ("digitalocean",)),
    ProviderSignature("Hetzner", "hosting", ("hetzner",)),
    ProviderSignature("OVHcloud", "hosting", ("ovh sas", "ovhcloud", "ovh.net")),
    ProviderSignature("GitHub", "hosting", ("github",)),
    ProviderSignature("Fly.io", "hosting", ("fly.io", "flyio")),
    ProviderSignature("Oracle Cloud", "cloud", ("oracle",)),
    ProviderSignature("Alibaba Cloud", "cloud", ("alibaba", "aliyun")),
)

# Matched against NS hostnames.
DNS_PROVIDERS: tuple[ProviderSignature, ...] = (
    ProviderSignature("Cloudflare DNS", "dns", suffixes=("ns.cloudflare.com",)),
    ProviderSignature("Amazon Route 53", "dns", keywords=("awsdns-",)),
    ProviderSignature("Google Cloud DNS", "dns", suffixes=("googledomains.com",)),
    ProviderSignature("Azure DNS", "dns", keywords=("azure-dns.",)),
    ProviderSignature("Vercel DNS", "dns", suffixes=("vercel-dns.com",)),
    ProviderSignature("NS1", "dns", suffixes=("nsone.net",)),
    ProviderSignature("GoDaddy", "dns", suffixes=("domaincontrol.com",)),
    ProviderSignature("Namecheap", "dns", suffixes=("registrar-servers.com",)),
    ProviderSignature("DigitalOcean DNS", "dns", suffixes=("digitalocean.com",)),
    ProviderSignature("Hostinger", "dns", suffixes=("dns-parking.com",)),
    ProviderSignature("Porkbun", "dns", suffixes=("porkbun.com",)),
    ProviderSignature("DNSimple", "dns", suffixes=("dnsimple.com",)),
    ProviderSignature("Hetzner DNS", "dns", suffixes=("hetzner.com", "hetzner.de")),
    ProviderSignature("Akamai Edge DNS", "dns", suffixes=("akam.net",)),
    ProviderSignature("UltraDNS", "dns", suffixes=("ultradns.com", "ultradns.net", "ultradns.org")),
)

# Matched against MX exchange hostnames.
MAIL_PROVIDERS: tuple[ProviderSignature, ...] = (
    ProviderSignature("Google Workspace", "email", suffixes=("google.com", "googlemail.com")),
    ProviderSignature("Microsoft 365", "email", suffixes=("protection.outlook.com", "outlook.com")),
    ProviderSignature("Zoho Mail", "email", suffixes=("zoho.com", "zoho.eu", "zoho.in")),
    ProviderSignature("Proton Mail", "email", suffixes=("protonmail.ch", "proton.me")),
    ProviderSignature("Fastmail", "email", suffixes=("messagingengine.com",)),
    ProviderSignature("Cloudflare Email Routing", "email", suffixes=("mx.cloudflare.net",)),
    ProviderSignature("ImprovMX", "email", suffixes=("improvmx.com",)),
    ProviderSignature("Mimecast", "email", keywords=("mimecast",)),
    ProviderSignature("Proofpoint", "email", suffixes=("pphosted.com",)),
    ProviderSignature("Amazon SES", "email", suffixes=("amazonaws.com",)),
    ProviderSignature("iCloud Mail", "email", suffixes=("icloud.com",)),
    ProviderSignature("Mailgun", "email", suffixes=("mailgun.org",)),
)


@dataclass(frozen=True, slots=True)
class HeaderSignature:
    '''
    Provider identified by a response header, optionally requiring a value substring.
    '''
    provider: str
    category: str
    header: str
    value_contains: str | None = None  # None: header presence alone is evidence


# Matched against final HTTP response headers.
HTTP_EDGE_PROVIDERS: tuple[HeaderSignature, ...] = (
    HeaderSignature("Cloudflare", "cdn", "cf-ray"),
    HeaderSignature("Cloudflare", "cdn", "server", "cloudflare"),
    HeaderSignature("Vercel", "hosting", "x-vercel-id"),
    HeaderSignature("Vercel", "hosting", "server", "vercel"),
    HeaderSignature("Netlify", "hosting", "x-nf-request-id"),
    HeaderSignature("Netlify", "hosting", "server", "netlify"),
    HeaderSignature("Amazon CloudFront", "cdn", "x-amz-cf-id"),
    HeaderSignature("Fastly", "cdn", "x-served-by", "cache-"),
    HeaderSignature("Fastly", "cdn", "x-fastly-request-id"),
    HeaderSignature("Akamai", "cdn", "server", "akamaighost"),
    HeaderSignature("GitHub Pages", "hosting", "x-github-request-id"),
    HeaderSignature("Fly.io", "hosting", "fly-request-id"),
    HeaderSignature("Render", "hosting", "rndr-id"),
    HeaderSignature("Google Cloud", "cloud", "via", "google"),
    HeaderSignature("Microsoft Azure", "cloud", "x-azure-ref"),
)
