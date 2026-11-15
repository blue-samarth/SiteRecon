# Hosting location estimation

SiteRecon estimates where a target's resolved IPs are hosted. It works at two levels:

- **Country + provider (always on, free, no setup).** Derived from the ASN and RDAP allocation data the
  `network` module already collects. No extra dependency, no third-party calls.
- **City (optional).** Added when you point SiteRecon at a local offline city database with `--geoip-db`.

Both are **estimates**, and the finding (`hosting.location`) and observations say so.

## What it is not

- It is not where the server physically sits. ASN/RDAP (and city databases) describe where the address
  space is *registered* to an ISP/organization — often a different city, sometimes a different country.
- It is **meaningless behind a CDN/anycast network.** The same anycast IP answers from hundreds of cities.
  SiteRecon detects known CDNs (Cloudflare, Fastly, Akamai, …) and reports those IPs as
  `CDN/anycast — hosting location not meaningful`, with no city.
- Traceroute does **not** give hosting location — it maps the network *path* (router hops), not where the
  endpoint is; and it is an active check. Geolocation is a separate, database-driven estimate.

## Enabling city-level estimates (free, no account)

SiteRecon reads a MaxMind-format `.mmdb` city database. The recommended free source is **DB-IP IP-to-City
Lite**, which needs **no account** to download (CC-BY-4.0):

1. Download the current month's MMDB from <https://db-ip.com/db/download/ip-to-city-lite> (direct link,
   e.g. `dbip-city-lite-YYYY-MM.mmdb.gz`) and gunzip it.
2. Point SiteRecon at it, by flag or environment variable:

   ```bash
   siterecon scan example.com --geoip-db /path/to/dbip-city-lite-2026-11.mmdb
   # or
   export SITERECON_GEOIP_DB=/path/to/dbip-city-lite-2026-11.mmdb
   siterecon scan example.com
   ```

A MaxMind **GeoLite2-City** `.mmdb` works identically (both use the GeoIP2-City record schema), if you
already have one.

If the file is missing, unreadable, or the `maxminddb` package is unavailable, SiteRecon logs a warning
and continues with the free country-level estimate — it never fails the scan.

### Attribution

DB-IP Lite is licensed **CC-BY-4.0**, which requires attribution. SiteRecon records the database name in
every geolocation observation and adds an attribution line to the `hosting.location` finding. If you
redistribute reports built with it, keep that attribution (e.g. "IP geolocation by DB-IP
(https://db-ip.com)"). The database is a monthly snapshot; refresh it periodically — each geolocation
observation records the database's build date (`observed_at`) so stale data is visible.

## Where it shows up

- **Finding** `hosting.location` (informational): one line per resolved IP — country, provider/org, and
  city when a geo DB is loaded; CDN/anycast IPs are flagged instead of located.
- **Observations**: `network.ip` (allocation) and, when a geo DB is loaded, `network.geo` per IP —
  stamped `collection_method = local_database`, `external_provider = <db name>`, and `observed_at = <db
  build date>`, so hosting changes are tracked across scans with honest provenance.
- **Scan options**: the configured `geoip_db` path is recorded in the report's options.
