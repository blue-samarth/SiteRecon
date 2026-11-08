'''
Technology and third-party service signatures.

Each pattern is a case-insensitive regex. A named group ``version`` captures a version.
Evidence strength is assigned by source type in ``modules/technology.py``.
'''

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TechSignature:
    '''
    Technology signature: regexes over headers, generator, resource URLs, HTML and referenced domains.
    '''
    name: str
    category: str
    headers: tuple[tuple[str, str], ...] = ()  # (header name, value regex; "" = presence)
    generator: str | None = None               # <meta name="generator"> regex
    urls: tuple[str, ...] = ()                 # regex over referenced resource URLs
    html: tuple[str, ...] = ()                 # regex over active HTML (comments removed)
    domains: tuple[str, ...] = ()              # referenced host suffixes (resources, CSP)
    dns: tuple[str, ...] = ()                  # regex over CNAME targets (delivery hint, never proof of origin)
    implies: tuple[str, ...] = ()


T = TechSignature

TECH_SIGNATURES: tuple[TechSignature, ...] = (
    # Frontend frameworks / meta-frameworks
    T("Next.js", "frontend_framework", headers=(("x-powered-by", r"next\.js"), ("x-nextjs-cache", ""),
                                                ("x-nextjs-prerender", "")),
      urls=(r"/_next/static/",), html=(r"__NEXT_DATA__", r"self\.__next_f"), implies=("React",)),
    T("React", "frontend_framework", urls=(r"react(?:-dom)?(?:\.production)?(?:\.min)?\.js",),
      html=(r"data-reactroot", r"data-reactid")),
    T("Nuxt", "frontend_framework", urls=(r"/_nuxt/",), html=(r"window\.__NUXT__", r"id=\"__nuxt\""),
      implies=("Vue.js",)),
    T("Vue.js", "frontend_framework",
      urls=(r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js",),
      html=(r"\sdata-v-[0-9a-f]{8}", r"data-server-rendered=\"true\"")),
    T("Angular", "frontend_framework", html=(r"ng-version=\"(?P<version>[\d.]+)\"",)),
    T("SvelteKit", "frontend_framework", urls=(r"/_app/immutable/",), html=(r"data-sveltekit-",),
      implies=("Svelte",)),
    T("Svelte", "frontend_framework", html=(r"class=\"[^\"]*\bsvelte-[a-z0-9]{5,}",)),
    T("Gatsby", "frontend_framework", generator=r"gatsby\s*(?P<version>[\d.]+)?",
      html=(r"id=\"___gatsby\"",), implies=("React",)),
    T("Astro", "frontend_framework", generator=r"astro\s*v?(?P<version>[\d.]+)?",
      urls=(r"/_astro/",), html=(r"<astro-island",)),
    T("Remix", "frontend_framework", html=(r"__remixContext",), implies=("React",)),
    # JavaScript libraries
    T("jQuery", "javascript_library",
      urls=(r"jquery[.-]?(?P<version>\d+\.\d+(?:\.\d+)?)?(?:\.slim)?(?:\.min)?\.js",)),
    T("htmx", "javascript_library", urls=(r"htmx(?:\.min)?\.js",), html=(r"\shx-(?:get|post)=",)),
    T("Alpine.js", "javascript_library", urls=(r"alpine(?:js)?[^/]*\.js",)),
    T("Lodash", "javascript_library", urls=(r"lodash(?:\.min)?\.js",)),
    # CSS frameworks / fonts
    T("Bootstrap", "css_framework",
      urls=(r"bootstrap(?:@(?P<version>[\d.]+))?[^/]*/(?:dist/)?(?:css|js)/bootstrap", r"bootstrap(?:\.bundle)?(?:\.min)?\.(?:css|js)")),
    T("Tailwind CSS", "css_framework", urls=(r"tailwind(?:css)?[^/]*\.(?:css|js)",),
      domains=("cdn.tailwindcss.com",)),
    T("Bulma", "css_framework", urls=(r"bulma(?:\.min)?\.css",)),
    T("Font Awesome", "font", urls=(r"font-?awesome",), domains=("kit.fontawesome.com", "use.fontawesome.com")),
    T("Google Fonts", "font", domains=("fonts.googleapis.com", "fonts.gstatic.com")),
    T("Adobe Fonts", "font", domains=("use.typekit.net",)),
    # Build tools (bundler output conventions; never conclusive alone)
    T("Vite", "build_tool", urls=(r"/@vite/client",),
      html=(r"<script type=\"module\" crossorigin src=\"/assets/[\w-]+-[\w-]{8}\.js\"",)),
    T("Webpack", "build_tool", html=(r"webpackChunk", r"__webpack_require__")),
    # CMS / site builders
    T("WordPress", "cms", generator=r"wordpress\s*(?P<version>[\d.]+)?",
      urls=(r"/wp-content/", r"/wp-includes/"), headers=(("set-cookie", r"^wordpress_"), ("link", r"api\.w\.org"))),
    T("Drupal", "cms", generator=r"drupal\s*(?P<version>\d+)?", headers=(("x-drupal-cache", ""),)),
    T("Ghost", "cms", generator=r"ghost\s*(?P<version>[\d.]+)?"),
    T("Shopify", "ecommerce", headers=(("x-shopid", ""), ("set-cookie", r"^_shopify_")), domains=("cdn.shopify.com",),
      dns=(r"myshopify\.com$",)),
    T("Wix", "site_builder", headers=(("x-wix-request-id", ""),), domains=("static.wixstatic.com",), dns=(r"wixdns\.net$",)),
    T("Squarespace", "site_builder", domains=("static1.squarespace.com",), dns=(r"squarespace\.com$",)),
    T("Webflow", "site_builder", html=(r"data-wf-page=",), domains=("assets.website-files.com", "cdn.prod.website-files.com"),
      dns=(r"webflow\.io$", r"proxy-ssl\.webflow\.com$")),
    T("Ghost(Pro)", "cms", dns=(r"ghost\.io$",)),
    T("HubSpot CMS", "cms", headers=(("x-hs-hub-id", ""),), dns=(r"hubspot\.net$",)),
    T("Hugo", "static_site_generator", generator=r"hugo\s*(?P<version>[\d.]+)?"),
    T("Jekyll", "static_site_generator", generator=r"jekyll\s*v?(?P<version>[\d.]+)?"),
    T("Docusaurus", "static_site_generator", generator=r"docusaurus\s*v?(?P<version>[\d.]+)?"),
    T("Eleventy", "static_site_generator", generator=r"eleventy\s*v?(?P<version>[\d.]+)?"),
    T("Framer", "site_builder", generator=r"framer", domains=("framerusercontent.com",)),
    # Hosting / CDN / edge
    T("Vercel", "hosting", headers=(("x-vercel-id", ""), ("server", r"^vercel")), dns=(r"vercel-dns\.com$",)),
    T("Netlify", "hosting", headers=(("x-nf-request-id", ""), ("server", r"^netlify")), dns=(r"netlify\.(app|com)$",)),
    T("GitHub Pages", "hosting", headers=(("x-github-request-id", ""),), dns=(r"github\.io$",)),
    T("Heroku", "hosting", headers=(("via", r"vegur"),), dns=(r"herokudns\.com$", r"herokuapp\.com$")),
    T("Render", "hosting", headers=(("rndr-id", ""),), dns=(r"onrender\.com$",)),
    T("Fly.io", "hosting", headers=(("fly-request-id", ""),), dns=(r"fly\.dev$",)),
    T("Cloudflare Pages", "hosting", dns=(r"pages\.dev$",)),
    T("AWS Amplify", "hosting", dns=(r"amplifyapp\.com$",)),
    T("Firebase Hosting", "hosting", dns=(r"(firebaseapp\.com|web\.app)$",)),
    T("Azure App Service", "hosting", dns=(r"azurewebsites\.net$",), headers=(("x-ms-request-id", ""),)),
    T("Cloudflare", "cdn", headers=(("cf-ray", ""), ("server", r"^cloudflare")), dns=(r"cdn\.cloudflare\.net$",)),
    T("Fastly", "cdn", headers=(("x-fastly-request-id", ""), ("x-served-by", r"cache-")), dns=(r"fastly\.net$",)),
    T("Amazon CloudFront", "cdn", headers=(("x-amz-cf-id", ""),), dns=(r"cloudfront\.net$",)),
    T("Akamai", "cdn", headers=(("server", r"akamaighost"),), dns=(r"(edgekey|edgesuite|akamaiedge)\.net$",)),
    # Web servers / runtimes (from response headers)
    T("Nginx", "web_server", headers=(("server", r"^nginx(?:/(?P<version>[\d.]+))?"),)),
    T("Apache HTTP Server", "web_server", headers=(("server", r"^apache(?:/(?P<version>[\d.]+))?"),)),
    T("Caddy", "web_server", headers=(("server", r"^caddy"),)),
    T("LiteSpeed", "web_server", headers=(("server", r"^litespeed"),)),
    T("Microsoft IIS", "web_server", headers=(("server", r"^microsoft-iis(?:/(?P<version>[\d.]+))?"),)),
    T("Express", "backend_framework", headers=(("x-powered-by", r"^express"), ("set-cookie", r"^connect\.sid="))),
    T("PHP", "language", headers=(("x-powered-by", r"php(?:/(?P<version>[\d.]+))?"), ("set-cookie", r"^PHPSESSID="))),
    T("ASP.NET", "backend_framework", headers=(("x-powered-by", r"asp\.net"), ("x-aspnet-version", ""),
                                               ("set-cookie", r"^ASP\.NET_SessionId="))),
    T("Laravel", "backend_framework", headers=(("set-cookie", r"^laravel_session="),), implies=("PHP",)),
    T("Java Servlet", "backend_framework", headers=(("set-cookie", r"^JSESSIONID="),)),
    T("Ruby on Rails", "backend_framework", headers=(("x-runtime", r"^[\d.]+$"),)),
    # Analytics / tag management
    T("Google Analytics", "analytics", urls=(r"googletagmanager\.com/gtag/js", r"google-analytics\.com/(?:analytics|ga)\.js")),
    T("Google Tag Manager", "analytics", urls=(r"googletagmanager\.com/gtm\.js",), html=(r"googletagmanager\.com/gtm\.js",)),
    T("Vercel Web Analytics", "analytics", urls=(r"/_vercel/insights/script\.js",)),
    T("Vercel Speed Insights", "analytics", urls=(r"/_vercel/speed-insights/",)),
    T("Cloudflare Web Analytics", "analytics", domains=("static.cloudflareinsights.com",)),
    T("Plausible", "analytics", domains=("plausible.io",)),
    T("PostHog", "analytics", domains=("posthog.com", "i.posthog.com")),
    T("Hotjar", "analytics", domains=("static.hotjar.com", "script.hotjar.com")),
    T("Microsoft Clarity", "analytics", domains=("clarity.ms",)),
    T("Segment", "analytics", domains=("cdn.segment.com",)),
    T("Mixpanel", "analytics", domains=("cdn.mxpnl.com",)),
    T("Meta Pixel", "analytics", domains=("connect.facebook.net",)),
    # Image / media hosting
    T("ImageKit", "image_hosting", domains=("ik.imagekit.io",)),
    T("Cloudinary", "image_hosting", domains=("res.cloudinary.com",)),
    T("imgix", "image_hosting", domains=("imgix.net",)),
    # Backend services (detected only from referenced domains)
    T("Supabase", "backend_service", domains=("supabase.co", "supabase.in")),
    T("Firebase", "backend_service", urls=(r"/__/firebase/",),
      domains=("firebaseapp.com", "firebaseio.com", "firebasestorage.googleapis.com")),
    # Other integrations
    T("Stripe", "payment", domains=("js.stripe.com",)),
    T("Razorpay", "payment", domains=("checkout.razorpay.com",)),
    T("Sentry", "monitoring", domains=("browser.sentry-cdn.com", "ingest.sentry.io", "ingest.us.sentry.io")),
    T("LogRocket", "monitoring", domains=("cdn.logrocket.io", "cdn.lr-ingest.io", "r.lr-ingest.io", "cdn.lrkt-in.com",
                                          "r.logrocket.io")),
    T("AWS Lambda Function URLs", "backend_service", domains=("on.aws",)),
    T("Intercom", "customer_support", domains=("widget.intercom.io", "js.intercomcdn.com")),
    T("Crisp", "customer_support", domains=("client.crisp.chat",)),
    T("reCAPTCHA", "security", urls=(r"google\.com/recaptcha/", r"recaptcha\.net/recaptcha/")),
    T("hCaptcha", "security", domains=("js.hcaptcha.com",)),
    T("Cloudflare Turnstile", "security", domains=("challenges.cloudflare.com",)),
)


@dataclass(frozen=True, slots=True)
class DomainService:
    '''
    Maps a domain suffix to a third-party provider and category.
    '''
    suffix: str
    provider: str
    category: str


D = DomainService

# External domain → provider for the third-party inventory.
THIRD_PARTY_DOMAINS: tuple[DomainService, ...] = (
    D("googletagmanager.com", "Google Tag Manager", "analytics"),
    D("google-analytics.com", "Google Analytics", "analytics"),
    D("analytics.google.com", "Google Analytics", "analytics"),
    D("static.cloudflareinsights.com", "Cloudflare Web Analytics", "analytics"),
    D("plausible.io", "Plausible", "analytics"),
    D("posthog.com", "PostHog", "analytics"),
    D("hotjar.com", "Hotjar", "analytics"),
    D("clarity.ms", "Microsoft Clarity", "analytics"),
    D("segment.com", "Segment", "analytics"), D("segment.io", "Segment", "analytics"),
    D("mxpnl.com", "Mixpanel", "analytics"), D("mixpanel.com", "Mixpanel", "analytics"),
    D("connect.facebook.net", "Meta Pixel", "analytics"),
    D("fonts.googleapis.com", "Google Fonts", "cdn"), D("fonts.gstatic.com", "Google Fonts", "cdn"),
    D("ajax.googleapis.com", "Google Hosted Libraries", "cdn"),
    D("cdn.jsdelivr.net", "jsDelivr", "cdn"), D("unpkg.com", "unpkg", "cdn"),
    D("cdnjs.cloudflare.com", "cdnjs", "cdn"), D("use.typekit.net", "Adobe Fonts", "cdn"),
    D("fontawesome.com", "Font Awesome", "cdn"), D("cdn.tailwindcss.com", "Tailwind Play CDN", "cdn"),
    D("supabase.co", "Supabase", "backend"), D("supabase.in", "Supabase", "backend"),
    D("firebaseio.com", "Firebase", "backend"), D("firebaseapp.com", "Firebase", "backend"),
    D("firebasestorage.googleapis.com", "Firebase Storage", "storage"),
    D("identitytoolkit.googleapis.com", "Firebase Authentication", "authentication"),
    D("clerk.accounts.dev", "Clerk", "authentication"), D("clerk.com", "Clerk", "authentication"),
    D("auth0.com", "Auth0", "authentication"), D("accounts.google.com", "Google Sign-In", "authentication"),
    D("stripe.com", "Stripe", "payment"), D("paypal.com", "PayPal", "payment"),
    D("razorpay.com", "Razorpay", "payment"), D("paddle.com", "Paddle", "payment"),
    D("lemonsqueezy.com", "Lemon Squeezy", "payment"),
    D("sentry.io", "Sentry", "monitoring"), D("sentry-cdn.com", "Sentry", "monitoring"),
    D("datadoghq.com", "Datadog", "monitoring"), D("datadoghq-browser-agent.com", "Datadog", "monitoring"),
    D("nr-data.net", "New Relic", "monitoring"), D("newrelic.com", "New Relic", "monitoring"),
    D("logrocket.io", "LogRocket", "monitoring"), D("bugsnag.com", "Bugsnag", "monitoring"),
    D("logrocket.com", "LogRocket", "monitoring"), D("lr-ingest.io", "LogRocket", "monitoring"),
    D("lr-ingest.com", "LogRocket", "monitoring"), D("lr-in.com", "LogRocket", "monitoring"),
    D("lr-in-prod.com", "LogRocket", "monitoring"), D("lr-intake.com", "LogRocket", "monitoring"),
    D("lrkt-in.com", "LogRocket", "monitoring"), D("ingest-lr.com", "LogRocket", "monitoring"),
    D("intake-lr.com", "LogRocket", "monitoring"), D("logr-ingest.com", "LogRocket", "monitoring"),
    D("on.aws", "AWS Lambda Function URLs", "backend"),
    D("facebook.com", "Facebook", "other"), D("instagram.com", "Instagram", "other"),
    D("linkedin.com", "LinkedIn", "other"), D("x.com", "X (Twitter)", "other"), D("twitter.com", "X (Twitter)", "other"),
    D("imagekit.io", "ImageKit", "media"), D("cloudinary.com", "Cloudinary", "media"),
    D("imgix.net", "imgix", "media"), D("images.unsplash.com", "Unsplash", "media"),
    D("youtube.com", "YouTube", "media"), D("youtube-nocookie.com", "YouTube", "media"),
    D("ytimg.com", "YouTube", "media"), D("vimeo.com", "Vimeo", "media"),
    D("framerusercontent.com", "Framer", "hosting"), D("website-files.com", "Webflow", "hosting"),
    D("wixstatic.com", "Wix", "hosting"), D("squarespace.com", "Squarespace", "hosting"),
    D("cdn.shopify.com", "Shopify", "hosting"),
    D("vercel.app", "Vercel", "hosting"), D("vercel.live", "Vercel", "hosting"),
    D("netlify.app", "Netlify", "hosting"), D("github.io", "GitHub Pages", "hosting"),
    D("githubusercontent.com", "GitHub", "hosting"),
    D("s3.amazonaws.com", "Amazon S3", "storage"), D("amazonaws.com", "Amazon Web Services", "hosting"),
    D("cloudfront.net", "Amazon CloudFront", "cdn"),
    D("blob.core.windows.net", "Azure Blob Storage", "storage"),
    D("storage.googleapis.com", "Google Cloud Storage", "storage"),
    D("r2.dev", "Cloudflare R2", "storage"),
    D("challenges.cloudflare.com", "Cloudflare Turnstile", "other"),
    D("hcaptcha.com", "hCaptcha", "other"), D("recaptcha.net", "reCAPTCHA", "other"),
    D("intercom.io", "Intercom", "other"), D("intercomcdn.com", "Intercom", "other"),
    D("crisp.chat", "Crisp", "other"), D("tawk.to", "tawk.to", "other"),
    D("calendly.com", "Calendly", "other"), D("cal.com", "Cal.com", "other"),
    D("hs-scripts.com", "HubSpot", "analytics"), D("hsforms.net", "HubSpot", "other"),
    D("typeform.com", "Typeform", "other"), D("tally.so", "Tally", "other"),
)

# SPF include/redirect domains → sending service.
SPF_SERVICES: tuple[DomainService, ...] = (
    D("_spf.google.com", "Google Workspace", "email"),
    D("spf.protection.outlook.com", "Microsoft 365", "email"),
    D("sendgrid.net", "SendGrid", "email"), D("mailgun.org", "Mailgun", "email"),
    D("amazonses.com", "Amazon SES", "email"), D("mcsv.net", "Mailchimp", "email"),
    D("mandrillapp.com", "Mailchimp Transactional", "email"),
    D("_spf.salesforce.com", "Salesforce", "email"), D("zoho.com", "Zoho Mail", "email"),
    D("zoho.in", "Zoho Mail", "email"), D("zoho.eu", "Zoho Mail", "email"),
    D("mail.zendesk.com", "Zendesk", "email"), D("sendinblue.com", "Brevo", "email"),
    D("brevo.com", "Brevo", "email"), D("mtasv.net", "Postmark", "email"),
    D("hubspotemail.net", "HubSpot", "email"), D("protonmail.ch", "Proton Mail", "email"),
    D("messagingengine.com", "Fastmail", "email"), D("_spf.mx.cloudflare.net", "Cloudflare Email Routing", "email"),
    D("spf.improvmx.com", "ImprovMX", "email"),
)

# TXT verification token prefixes → service the domain was verified with.
TXT_VERIFICATIONS: tuple[tuple[str, str, str], ...] = (
    ("google-site-verification=", "Google", "other"),
    ("facebook-domain-verification=", "Meta", "other"),
    ("ms=", "Microsoft 365", "email"),
    ("atlassian-domain-verification=", "Atlassian", "other"),
    ("stripe-verification=", "Stripe", "payment"),
    ("apple-domain-verification=", "Apple", "other"),
    ("docusign=", "DocuSign", "other"),
    ("adobe-idp-site-verification=", "Adobe", "other"),
    ("openai-domain-verification=", "OpenAI", "other"),
    ("hubspot-developer-verification=", "HubSpot", "other"),
    ("zoom-domain-verification", "Zoom", "other"),
    ("slack-domain-verification=", "Slack", "other"),
    ("globalsign-domain-verification=", "GlobalSign", "certificate_authority"),
    ("have-i-been-pwned-verification=", "Have I Been Pwned", "other"),
    ("cisco-ci-domain-verification=", "Cisco", "other"),
    ("canva-site-verification=", "Canva", "other"),
    ("vercel-domain-verification", "Vercel", "hosting"),
    ("zoho-verification=", "Zoho", "email"),
    ("brevo-code:", "Brevo", "email"),
)

# Certificate issuer organization → CA.
CERTIFICATE_AUTHORITIES: tuple[tuple[str, str], ...] = (
    ("let's encrypt", "Let's Encrypt"), ("google trust services", "Google Trust Services"),
    ("digicert", "DigiCert"), ("sectigo", "Sectigo"), ("globalsign", "GlobalSign"),
    ("amazon", "Amazon Trust Services"), ("zerossl", "ZeroSSL"), ("cloudflare", "Cloudflare"),
    ("microsoft", "Microsoft"), ("godaddy", "GoDaddy"), ("entrust", "Entrust"),
    ("buypass", "Buypass"), ("ssl.com", "SSL.com"),
)
