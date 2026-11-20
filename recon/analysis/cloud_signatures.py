'''
Cloud-resource signatures: recognize managed cloud endpoints (object storage, serverless functions,
managed databases, edge workers, hosting) from hostnames and URL paths already collected.

This is pure pattern matching over evidence the passive scan already holds — a referenced host, a bundle
URL, a CNAME target. Nothing here contacts the resource: a bucket URL in a bundle proves the application
*references* that bucket, never that the bucket is world-readable or even that it exists. Findings built
from these matches say so explicitly, and confirming exposure is the job of an authorized active check.

Each signature matches the hostname; a path-style signature (``path`` set) recovers the resource
identifier from the URL path instead, so both ``bucket.s3.amazonaws.com`` and
``s3.amazonaws.com/bucket/key`` resolve to the same bucket name.
'''

from __future__ import annotations

import re
from dataclasses import dataclass

# Version of the cloud-pattern set; bump on any change (mirrors SIGNATURES_VERSION's purpose).
CLOUD_SIGNATURES_VERSION: str = "2026.11.18"

# Resource classes, used as the ``kind`` of a CloudResource and to pick the finding a match produces.
OBJECT_STORAGE: str = "object_storage"
SERVERLESS_FUNCTION: str = "serverless_function"
MANAGED_DATABASE: str = "managed_database"
EDGE_WORKER: str = "edge_worker"
HOSTING: str = "hosting"
AUTH: str = "auth"
SEARCH: str = "search"
CONTAINER: str = "container"


@dataclass(frozen=True, slots=True)
class CloudSignature:
    '''
    One managed-cloud endpoint pattern.

    ``host`` is matched against the hostname; a ``id``/``region`` named group names the resource and its
    region. When the identifier lives in the path instead (path-style buckets, function routes), ``path``
    supplies it from the URL path.
    '''
    provider: str
    kind: str
    host: str                            # regex over the full hostname (anchored on both ends)
    path: str | None = None              # regex over the URL path, supplying 'id' for path-style resources
    public_by_default: bool = False      # resource class commonly left world-readable when misconfigured
    note: str = ""

    def match(self, hostname: str, path: str = "") -> tuple[str, str | None] | None:
        '''
        Match a hostname (and optionally a path) and return the resource identifier and region.

        A signature with a ``path`` pattern only matches when the path matches too, so the generic entry
        for the same host (e.g. Supabase PostgREST, plain Netlify hosting) stays the fallback. The path's
        ``id`` group replaces the host identifier; a ``sub`` group (bucket, function name) qualifies it.
        Parameters:
            hostname (str): Lowercased hostname to test.
            path (str): URL path, used only by path-style signatures.
        Returns:
            tuple[str, str | None] | None: (identifier, region) when it matches, else None.
        '''
        m = re.fullmatch(self.host, hostname, re.IGNORECASE)
        if m is None:
            return None
        groups = m.groupdict()
        region = groups.get("region")
        identifier = groups.get("id")
        if self.path is not None:
            pm = re.search(self.path, path or "", re.IGNORECASE)
            if pm is None:
                return None            # a path-style signature needs its path; the generic entry handles the rest
            found = pm.groupdict()
            if found.get("id"):
                identifier = found["id"]
            elif found.get("sub"):
                identifier = f"{identifier}/{found['sub']}" if identifier else found["sub"]
        return (identifier or hostname, region)


C = CloudSignature

# Ordered most-specific first: the first match wins, so a bucket host is never reported as plain hosting.
CLOUD_SIGNATURES: tuple[CloudSignature, ...] = (
    # ---------------------------------------------------------------- AWS
    C("Amazon S3", OBJECT_STORAGE, r"(?P<id>[a-z0-9][a-z0-9.\-]{1,61})\.s3[.-](?:(?P<region>[a-z]{2}-[a-z]+-\d)\.)?amazonaws\.com",
      public_by_default=True, note="Bucket named in the hostname (virtual-hosted style)."),
    C("Amazon S3", OBJECT_STORAGE, r"s3[.-](?:(?P<region>[a-z]{2}-[a-z]+-\d)\.)?amazonaws\.com",
      path=r"^/(?P<id>[a-z0-9][a-z0-9.\-]{1,61})(?:/|$)", public_by_default=True,
      note="Bucket named in the path (path-style addressing)."),
    C("Amazon S3 (website endpoint)", OBJECT_STORAGE,
      r"(?P<id>[a-z0-9][a-z0-9.\-]{1,61})\.s3-website[.-](?P<region>[a-z]{2}-[a-z]+-\d)\.amazonaws\.com",
      public_by_default=True, note="S3 static-website endpoint; serves objects without authentication by design."),
    C("AWS Lambda Function URL", SERVERLESS_FUNCTION,
      r"(?P<id>[a-z0-9]{16,64})\.lambda-url\.(?P<region>[a-z]{2}-[a-z]+-\d)\.on\.aws"),
    C("Amazon API Gateway", SERVERLESS_FUNCTION,
      r"(?P<id>[a-z0-9]{10})\.execute-api\.(?P<region>[a-z]{2}-[a-z]+-\d)\.amazonaws\.com"),
    C("AWS AppSync", MANAGED_DATABASE,
      r"(?P<id>[a-z0-9]{26})\.appsync-api\.(?P<region>[a-z]{2}-[a-z]+-\d)\.amazonaws\.com",
      note="GraphQL API; authorization is configured per API (API key, IAM, Cognito)."),
    C("Amazon Cognito", AUTH, r"cognito-idp\.(?P<region>[a-z]{2}-[a-z]+-\d)\.amazonaws\.com"),
    C("Amazon CloudFront", HOSTING, r"(?P<id>[a-z0-9]{10,20})\.cloudfront\.net"),
    C("AWS Amplify", HOSTING, r"(?P<id>[a-z0-9-]+)\.amplifyapp\.com"),
    C("AWS Elastic Beanstalk", HOSTING, r"(?P<id>[a-z0-9-]+)\.(?:[a-z0-9-]+\.)?elasticbeanstalk\.com"),
    # ---------------------------------------------------------------- Azure
    C("Azure Blob Storage", OBJECT_STORAGE, r"(?P<id>[a-z0-9]{3,24})\.blob\.core\.windows\.net",
      public_by_default=True, note="Container access level decides whether blobs are anonymously readable."),
    C("Azure Data Lake Storage", OBJECT_STORAGE, r"(?P<id>[a-z0-9]{3,24})\.dfs\.core\.windows\.net",
      public_by_default=True),
    C("Azure File Storage", OBJECT_STORAGE, r"(?P<id>[a-z0-9]{3,24})\.file\.core\.windows\.net"),
    C("Azure Table Storage", MANAGED_DATABASE, r"(?P<id>[a-z0-9]{3,24})\.table\.core\.windows\.net"),
    C("Azure Queue Storage", MANAGED_DATABASE, r"(?P<id>[a-z0-9]{3,24})\.queue\.core\.windows\.net"),
    C("Azure Cosmos DB", MANAGED_DATABASE, r"(?P<id>[a-z0-9-]+)\.documents\.azure\.com"),
    C("Azure Functions", SERVERLESS_FUNCTION, r"(?P<id>[a-z0-9-]+)\.azurewebsites\.net",
      path=r"^/api/", note="Only the /api/ route surface is treated as a function endpoint."),
    C("Azure App Service", HOSTING, r"(?P<id>[a-z0-9-]+)\.azurewebsites\.net"),
    C("Azure Static Web Apps", HOSTING, r"(?P<id>[a-z0-9-]+)\.(?:\d\.)?azurestaticapps\.net"),
    C("Azure Container Registry", CONTAINER, r"(?P<id>[a-z0-9]+)\.azurecr\.io"),
    C("Azure AD B2C", AUTH, r"(?P<id>[a-z0-9-]+)\.b2clogin\.com"),
    # ---------------------------------------------------------------- Google Cloud / Firebase
    C("Google Cloud Storage", OBJECT_STORAGE, r"(?P<id>[a-z0-9][a-z0-9._\-]{1,61})\.storage\.googleapis\.com",
      public_by_default=True),
    C("Google Cloud Storage", OBJECT_STORAGE, r"storage\.(?:cloud\.)?googleapis\.com",
      path=r"^/(?:v1/b/)?(?P<id>[a-z0-9][a-z0-9._\-]{1,61})(?:/|$)", public_by_default=True),
    C("Firebase Storage", OBJECT_STORAGE, r"firebasestorage\.googleapis\.com",
      path=r"^/v0/b/(?P<id>[^/]+)", public_by_default=True,
      note="Readability depends on Firebase Storage security rules, not on the URL."),
    C("Firebase Realtime Database", MANAGED_DATABASE,
      r"(?P<id>[a-z0-9-]+)\.(?:(?P<region>[a-z0-9-]+)\.)?firebasedatabase\.app",
      note="Read/write access is decided entirely by Firebase security rules."),
    C("Firebase Realtime Database", MANAGED_DATABASE, r"(?P<id>[a-z0-9-]+)\.firebaseio\.com",
      note="Read/write access is decided entirely by Firebase security rules."),
    C("Firebase Hosting", HOSTING, r"(?P<id>[a-z0-9-]+)\.(?:firebaseapp\.com|web\.app)"),
    C("Firebase Authentication", AUTH, r"identitytoolkit\.googleapis\.com"),
    C("Google Cloud Functions", SERVERLESS_FUNCTION,
      r"(?P<region>[a-z]{2,}-[a-z]+\d)-(?P<id>[a-z0-9-]+)\.cloudfunctions\.net"),
    C("Google Cloud Run", SERVERLESS_FUNCTION,
      r"(?P<id>[a-z0-9-]+)-[a-z0-9]{8,10}-(?P<region>[a-z]{2})\.a\.run\.app"),
    C("Google Cloud Run", SERVERLESS_FUNCTION, r"(?P<id>[a-z0-9-]+)\.run\.app"),
    C("Google Apps Script", SERVERLESS_FUNCTION, r"script\.google(?:usercontent)?\.com"),
    C("Firestore", MANAGED_DATABASE, r"firestore\.googleapis\.com"),
    # ---------------------------------------------------------------- Supabase
    C("Supabase Storage", OBJECT_STORAGE, r"(?P<id>[a-z0-9]{20})\.supabase\.(?:co|in)",
      path=r"^/storage/v1/object/public/(?P<sub>[^/]+)",
      note="Buckets under /storage/v1/object/public/ are served without authentication by design."),
    C("Supabase Edge Function", SERVERLESS_FUNCTION, r"(?P<id>[a-z0-9]{20})\.supabase\.(?:co|in)",
      path=r"^/functions/v1/"),
    C("Supabase (PostgREST)", MANAGED_DATABASE, r"(?P<id>[a-z0-9]{20})\.supabase\.(?:co|in)",
      note="Tables are reachable with the public anon key; row-level security is the only access control."),
    # ---------------------------------------------------------------- Cloudflare
    C("Cloudflare Workers", EDGE_WORKER, r"(?P<id>[a-z0-9-]+)\.(?P<region>[a-z0-9-]+)\.workers\.dev"),
    C("Cloudflare Workers", EDGE_WORKER, r"(?P<id>[a-z0-9-]+)\.workers\.dev"),
    C("Cloudflare R2", OBJECT_STORAGE, r"pub-(?P<id>[0-9a-f]{32})\.r2\.dev", public_by_default=True,
      note="An r2.dev public development URL serves the bucket without authentication."),
    C("Cloudflare R2", OBJECT_STORAGE, r"(?P<id>[0-9a-f]{32})\.r2\.cloudflarestorage\.com"),
    C("Cloudflare Pages", HOSTING, r"(?P<id>[a-z0-9-]+)\.pages\.dev"),
    C("Cloudflare Images", OBJECT_STORAGE, r"imagedelivery\.net", path=r"^/(?P<id>[A-Za-z0-9_\-]{10,})"),
    # ---------------------------------------------------------------- Vercel / Netlify
    C("Vercel Blob", OBJECT_STORAGE, r"(?P<id>[a-z0-9]+)\.public\.blob\.vercel-storage\.com",
      public_by_default=True),
    C("Vercel Functions", SERVERLESS_FUNCTION, r"(?P<id>[a-z0-9-]+)\.vercel\.app", path=r"^/api/"),
    C("Vercel", HOSTING, r"(?P<id>[a-z0-9-]+)\.vercel\.(?:app|live)"),
    C("Netlify Functions", SERVERLESS_FUNCTION, r"(?P<id>[a-z0-9-]+)\.netlify\.app",
      path=r"^/\.netlify/(?:functions|builders)/(?P<sub>[^/?]+)"),
    C("Netlify", HOSTING, r"(?P<id>[a-z0-9-]+)\.netlify\.(?:app|com)"),
    # ---------------------------------------------------------------- other object storage
    C("DigitalOcean Spaces", OBJECT_STORAGE,
      r"(?P<id>[a-z0-9][a-z0-9.\-]{1,61})\.(?P<region>[a-z]{3}\d)\.(?:cdn\.)?digitaloceanspaces\.com",
      public_by_default=True),
    C("Backblaze B2", OBJECT_STORAGE,
      r"(?P<id>[a-z0-9-]+)\.s3\.(?P<region>[a-z]{2}-[a-z]+-\d{3})\.backblazeb2\.com", public_by_default=True),
    C("Wasabi", OBJECT_STORAGE, r"(?P<id>[a-z0-9.\-]+)\.s3\.(?:(?P<region>[a-z0-9-]+)\.)?wasabisys\.com",
      public_by_default=True),
    C("Linode Object Storage", OBJECT_STORAGE,
      r"(?P<id>[a-z0-9.\-]+)\.(?P<region>[a-z]{2}-[a-z]+-\d)\.linodeobjects\.com", public_by_default=True),
    C("Alibaba Cloud OSS", OBJECT_STORAGE,
      r"(?P<id>[a-z0-9-]+)\.oss-(?P<region>[a-z0-9-]+)\.aliyuncs\.com", public_by_default=True),
    C("Oracle Object Storage", OBJECT_STORAGE, r"objectstorage\.(?P<region>[a-z0-9-]+)\.oraclecloud\.com",
      path=r"^/n/[^/]+/b/(?P<id>[^/]+)", public_by_default=True),
    C("Scaleway Object Storage", OBJECT_STORAGE,
      r"(?P<id>[a-z0-9.\-]+)\.s3\.(?P<region>[a-z]{2}-[a-z]{3})\.scw\.cloud", public_by_default=True),
    C("Yandex Object Storage", OBJECT_STORAGE, r"(?P<id>[a-z0-9.\-]+)\.storage\.yandexcloud\.net",
      public_by_default=True),
    # ---------------------------------------------------------------- managed databases / backends
    C("MongoDB Atlas", MANAGED_DATABASE, r"(?P<id>[a-z0-9-]+)\.[a-z0-9]{5}\.mongodb\.net"),
    C("MongoDB Atlas Data API", MANAGED_DATABASE, r"data\.mongodb-api\.com", path=r"^/app/(?P<id>[^/]+)"),
    C("PlanetScale", MANAGED_DATABASE, r"(?P<id>[a-z0-9-]+)\.(?:[a-z0-9-]+\.)?psdb\.cloud"),
    C("Neon", MANAGED_DATABASE, r"(?P<id>[a-z0-9-]+)\.(?:[a-z0-9-]+\.)?neon\.tech"),
    C("Upstash", MANAGED_DATABASE, r"(?P<id>[a-z0-9-]+)\.upstash\.io"),
    C("Turso", MANAGED_DATABASE, r"(?P<id>[a-z0-9-]+)\.turso\.io"),
    C("Xata", MANAGED_DATABASE, r"(?P<id>[a-z0-9-]+)\.(?:[a-z0-9-]+\.)?xata\.sh"),
    C("Hasura", MANAGED_DATABASE, r"(?P<id>[a-z0-9-]+)\.hasura\.app"),
    C("Appwrite", MANAGED_DATABASE, r"(?:[a-z0-9-]+\.)?(?P<region>[a-z]{3})?\.?cloud\.appwrite\.io"),
    C("PocketBase", MANAGED_DATABASE, r"(?P<id>[a-z0-9-]+)\.pockethost\.io"),
    C("Directus", MANAGED_DATABASE, r"(?P<id>[a-z0-9-]+)\.directus\.app"),
    C("Contentful", MANAGED_DATABASE, r"(?:cdn|preview|graphql)\.contentful\.com"),
    C("Sanity", MANAGED_DATABASE, r"(?P<id>[a-z0-9]+)\.api\.sanity\.io"),
    C("Strapi Cloud", MANAGED_DATABASE, r"(?P<id>[a-z0-9-]+)\.strapiapp\.com"),
    # ---------------------------------------------------------------- auth / search
    C("Auth0", AUTH, r"(?P<id>[a-z0-9-]+)\.(?:(?P<region>[a-z]{2})\.)?auth0\.com"),
    C("Clerk", AUTH, r"(?P<id>[a-z0-9-]+)\.clerk\.accounts\.(?:dev|com)"),
    C("Okta", AUTH, r"(?P<id>[a-z0-9-]+)\.okta(?:preview)?\.com"),
    C("Stytch", AUTH, r"(?:test|api)\.stytch\.com"),
    C("WorkOS", AUTH, r"api\.workos\.com"),
    C("Keycloak", AUTH, r"(?P<id>[a-z0-9-]+)\.keycloak\.app"),
    C("Algolia", SEARCH, r"(?P<id>[a-z0-9]+)(?:-dsn)?\.algolia(?:net)?\.(?:net|io)"),
    C("Typesense", SEARCH, r"(?P<id>[a-z0-9-]+)\.(?:[a-z0-9-]+\.)?typesense\.net"),
    C("Meilisearch", SEARCH, r"(?P<id>[a-z0-9-]+)\.meilisearch\.io"),
    C("Elastic Cloud", SEARCH, r"(?P<id>[a-z0-9]+)\.(?:[a-z0-9-]+\.)*(?:found\.io|elastic-cloud\.com)"),
    # ---------------------------------------------------------------- PaaS hosting
    C("Heroku", HOSTING, r"(?P<id>[a-z0-9-]+)\.herokuapp\.com"),
    C("Render", HOSTING, r"(?P<id>[a-z0-9-]+)\.onrender\.com"),
    C("Railway", HOSTING, r"(?P<id>[a-z0-9-]+)\.up\.railway\.app"),
    C("Fly.io", HOSTING, r"(?P<id>[a-z0-9-]+)\.fly\.dev"),
    C("Deno Deploy", EDGE_WORKER, r"(?P<id>[a-z0-9-]+)\.deno\.dev"),
    C("Koyeb", HOSTING, r"(?P<id>[a-z0-9-]+)\.koyeb\.app"),
    C("Fastly Compute", EDGE_WORKER, r"(?P<id>[a-z0-9-]+)\.edgecompute\.app"),
    C("GitHub Pages", HOSTING, r"(?P<id>[a-z0-9-]+)\.github\.io"),
    C("GitLab Pages", HOSTING, r"(?P<id>[a-z0-9-]+)\.gitlab\.io"),
)


@dataclass(slots=True)
class CloudMatch:
    '''
    One matched cloud endpoint: which signature matched and what it identified.
    '''
    signature: CloudSignature
    host: str
    identifier: str
    region: str | None = None
    url: str | None = None


def match_cloud(host: str, url: str = "") -> CloudMatch | None:
    '''
    Identify a managed-cloud endpoint from a hostname and (optionally) the URL it came from.

    The first matching signature wins, and the table is ordered specific-first, so a bucket or function
    host is never mis-reported as generic hosting. A match means the host was *referenced*; it says
    nothing about whether the resource is reachable or publicly readable.
    Parameters:
        host (str): Hostname to classify (any casing).
        url (str): Full URL the hostname came from, when known (supplies the path for path-style matches).
    Returns:
        CloudMatch | None: The match, or None when no signature applies.
    '''
    if not host:
        return None
    hostname = host.strip().lower().rstrip(".")
    path = ""
    if url:
        from urllib.parse import urlsplit
        try:
            path = urlsplit(url if "//" in url else f"//{url}").path
        except ValueError:
            path = ""
    for sig in CLOUD_SIGNATURES:
        matched = sig.match(hostname, path)
        if matched is not None:
            identifier, region = matched
            return CloudMatch(signature=sig, host=hostname, identifier=identifier, region=region,
                              url=url or None)
    return None
