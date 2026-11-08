'''
Domain registration data via RDAP (IANA bootstrap), with a native async WHOIS (port 43) fallback.

Only registrar, lifecycle dates, status, nameservers and DNSSEC are kept. Registrant
contact details are deliberately not collected.
'''

from __future__ import annotations

import asyncio
import contextlib
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, ClassVar
from urllib.parse import urlsplit

from recon.models import CollectionError, DomainRegistration
from recon.modules.base import Collector
from recon.modules.network import NetworkCollector
from recon.utils import Resolve, SafeHttpClient, Scope, is_public_ip, registrable_domain, system_resolve

ClientFactory = Callable[[Scope], SafeHttpClient]


class RdapUnavailableError(Exception):
    '''
    Raised when no RDAP service could answer for the domain.
    '''


class WhoisError(Exception):
    '''
    Raised when a WHOIS query cannot be completed.
    '''


class WhoisClient:
    '''
    Minimal async WHOIS (RFC 3912) client: asks IANA for the TLD's server, then queries it.
    Servers must resolve to public addresses; responses are size-capped and time-limited.
    '''

    IANA_SERVER: ClassVar[str] = "whois.iana.org"
    PORT: ClassVar[int] = 43
    _HOSTNAME: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")

    def __init__(
        self,
        *,
        timeout: float = 10.0,
        retries: int = 1,
        max_response_bytes: int = 256 * 1024,
        resolve: Resolve = system_resolve,
        allow_private_networks: bool = False,
    ) -> None:
        '''
        Create a client.
        Parameters:
            timeout (float): Timeout in seconds for connecting and for each read.
            retries (int): Retries for timeouts and connection resets.
            max_response_bytes (int): Maximum bytes read per response.
            resolve (Resolve): Async hostname resolver (injectable for tests).
            allow_private_networks (bool): Permit non-public server addresses (tests only).
        '''
        self.timeout = timeout
        self.retries = retries
        self.max_response_bytes = max_response_bytes
        self.resolve = resolve
        self.allow_private_networks = allow_private_networks

    async def lookup(self, domain: str) -> tuple[str, str]:
        '''
        Find the WHOIS server for the domain's TLD via IANA and query it.
        Parameters:
            domain (str): Registrable domain.
        Returns:
            tuple[str, str]: The WHOIS server used and its raw response.
        Raises:
            WhoisError: If IANA lists no server or a query fails.
        '''
        tld = domain.rsplit(".", 1)[-1]
        server = WhoisParser.referral(await self.query(self.IANA_SERVER, tld))
        if not server:
            raise WhoisError(f"IANA lists no WHOIS server for .{tld}")
        return server, await self.query(server, domain)

    async def query(self, server: str, query: str) -> str:
        '''
        Send one WHOIS query, retrying timeouts and connection resets with backoff.
        Parameters:
            server (str): WHOIS server hostname.
            query (str): Query string (domain or TLD).
        Returns:
            str: Decoded response text.
        Raises:
            WhoisError: If the server name is invalid, resolves only to non-public addresses, or the query fails.
        '''
        server = server.strip().lower().rstrip(".")
        if not self._HOSTNAME.match(server):
            raise WhoisError(f"invalid WHOIS server name {server!r}")
        try:
            addresses = await self.resolve(server, self.PORT)
        except OSError as exc:
            raise WhoisError(f"cannot resolve {server}: {exc}") from exc
        allowed = [a for a in addresses if self.allow_private_networks or is_public_ip(a)]
        if not allowed:
            raise WhoisError(f"{server} resolves only to non-public addresses {addresses}")

        attempt = 0
        while True:
            attempt += 1
            try:
                return await self._query_once(allowed[0], query)
            except (TimeoutError, ConnectionResetError, ConnectionRefusedError) as exc:
                if attempt > self.retries:
                    raise WhoisError(f"{server}: {type(exc).__name__}") from exc
                await asyncio.sleep(0.5 * 2 ** (attempt - 1))
            except OSError as exc:
                raise WhoisError(f"{server}: {exc}") from exc

    async def _query_once(self, ip: str, query: str) -> str:
        '''
        Connect to a vetted address, send the query and read until EOF or the size cap.
        Parameters:
            ip (str): Server address that passed the public-address check.
            query (str): Query string.
        Returns:
            str: Decoded response text.
        Raises:
            TimeoutError | OSError: On connection or read failure.
        '''
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, self.PORT), timeout=self.timeout)
        try:
            writer.write(f"{query}\r\n".encode("ascii", "ignore"))
            await writer.drain()
            body = bytearray()
            while len(body) < self.max_response_bytes:
                chunk = await asyncio.wait_for(reader.read(8192), timeout=self.timeout)
                if not chunk:
                    break
                body.extend(chunk[: self.max_response_bytes - len(body)])
            return body.decode("utf-8", "replace")
        finally:
            writer.close()
            with contextlib.suppress(OSError, TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), timeout=2)


class WhoisParser:
    '''
    Extracts registrar, dates, status, nameservers and DNSSEC from free-text WHOIS responses.
    Contact fields are never read.
    '''

    FIELDS: ClassVar[dict[str, tuple[str, ...]]] = {
        "registrar": ("registrar", "registrar name", "sponsoring registrar", "registrar organization"),
        "registrar_iana_id": ("registrar iana id",),
        "created": ("creation date", "created", "created on", "created date", "registered on",
                    "registration time", "registered", "domain registration date"),
        "updated": ("updated date", "last updated", "last modified", "changed", "last update", "modified"),
        "expires": ("registry expiry date", "registrar registration expiration date", "expiry date",
                    "expiration date", "expires", "expires on", "expire date", "paid-till", "renewal date"),
    }
    STATUS_KEYS: ClassVar[tuple[str, ...]] = ("domain status", "status", "state")
    NAMESERVER_KEYS: ClassVar[tuple[str, ...]] = ("name server", "nserver", "nameserver", "nameservers", "name servers")
    NOT_FOUND: ClassVar[tuple[str, ...]] = ("no match for", "not found", "no data found", "no entries found",
                                            "domain not found", "status: free", "status: available")
    DATE_FORMATS: ClassVar[tuple[str, ...]] = (
        "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%d-%b-%Y %H:%M:%S", "%Y.%m.%d", "%d.%m.%Y",
        "%Y/%m/%d", "%d/%m/%Y", "%Y%m%d", "%a %b %d %H:%M:%S %Z %Y", "%Y-%m-%d %H:%M:%S %Z",
    )

    @staticmethod
    def referral(text: str) -> str | None:
        '''
        Return the WHOIS server named by an IANA response ('refer:' or 'whois:' line).
        Parameters:
            text (str): IANA WHOIS response.
        Returns:
            str | None: Server hostname, or None.
        '''
        for line in text.splitlines():
            key, sep, value = line.partition(":")
            if sep and key.strip().lower() in ("refer", "whois") and value.strip():
                return value.strip().lower()
        return None

    @classmethod
    def parse(cls, domain: str, text: str, server: str | None = None) -> DomainRegistration | None:
        '''
        Parse a registry WHOIS response.
        Parameters:
            domain (str): Registrable domain.
            text (str): Raw WHOIS response.
            server (str | None): Server that answered, recorded as the source.
        Returns:
            DomainRegistration | None: Registration data, or None if the domain was not found or nothing was parseable.
        '''
        fields = cls._fields(text)
        registrar = cls._first(fields, cls.FIELDS["registrar"])
        if not fields or (not registrar and any(m in text.lower() for m in cls.NOT_FOUND)):
            return None
        created = cls._date(cls._first(fields, cls.FIELDS["created"]))
        expires = cls._date(cls._first(fields, cls.FIELDS["expires"]))
        nameservers = sorted({v.split()[0].lower().rstrip(".")
                              for k in cls.NAMESERVER_KEYS for v in fields.get(k, []) if v.split()})
        if not any((registrar, created, expires, nameservers)):
            return None
        dnssec_raw = cls._first(fields, ("dnssec",))
        return DomainRegistration(
            domain=domain, source="whois", source_url=f"whois://{server}" if server else None,
            registrar=registrar,
            registrar_iana_id=cls._first(fields, cls.FIELDS["registrar_iana_id"]),
            created=created,
            updated=cls._date(cls._first(fields, cls.FIELDS["updated"])),
            expires=expires,
            status=list(dict.fromkeys(v.split()[0] for k in cls.STATUS_KEYS for v in fields.get(k, []) if v.split())),
            nameservers=nameservers,
            dnssec=None if dnssec_raw is None else not dnssec_raw.lower().startswith(("unsigned", "no", "inactive")),
        )

    @staticmethod
    def _fields(text: str) -> dict[str, list[str]]:
        '''
        Collect 'Key: Value' lines, skipping comments and stopping at the legal footer.
        Parameters:
            text (str): Raw WHOIS response.
        Returns:
            dict[str, list[str]]: Lowercase key to values in order of appearance.
        '''
        fields: dict[str, list[str]] = {}
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(("%", "#")):
                continue
            if stripped.lower().startswith(">>> last update"):
                break
            key, sep, value = stripped.partition(":")
            if sep and value.strip():
                fields.setdefault(key.strip().lower(), []).append(value.strip())
        return fields

    @staticmethod
    def _first(fields: dict[str, list[str]], keys: tuple[str, ...]) -> str | None:
        '''
        Return the first value present under any of the keys.
        Parameters:
            fields (dict[str, list[str]]): Parsed fields.
            keys (tuple[str, ...]): Candidate keys in priority order.
        Returns:
            str | None: The value, or None.
        '''
        for key in keys:
            if fields.get(key):
                return fields[key][0]
        return None

    @classmethod
    def _date(cls, value: str | None) -> datetime | None:
        '''
        Parse the many date formats registries use; naive values are taken as UTC.
        Parameters:
            value (str | None): Raw date text.
        Returns:
            datetime | None: Aware datetime, or None if unparseable.
        '''
        if not value:
            return None
        raw = value.strip().split(" (")[0]
        parsed: datetime | None = None
        with contextlib.suppress(ValueError):
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        for fmt in cls.DATE_FORMATS if parsed is None else ():
            try:
                parsed = datetime.strptime(raw, fmt)
                break
            except ValueError:
                continue
        if parsed is None:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class WhoisCollector(Collector[DomainRegistration]):
    '''
    Looks up domain registration via RDAP, falling back to async WHOIS; registrant contacts are never kept.
    '''

    name: ClassVar[str] = "whois"
    IANA_BOOTSTRAP: ClassVar[str] = "https://data.iana.org/rdap/dns.json"

    def __init__(
        self,
        hostname: str,
        client_factory: ClientFactory,
        *,
        timeout: float = 10.0,
        retries: int = 1,
        whois_client: WhoisClient | None = None,
        now: datetime | None = None,
    ) -> None:
        '''
        Create the collector.
        Parameters:
            hostname (str): Normalized target hostname.
            client_factory (ClientFactory): Builds a SafeHttpClient for a given scope.
            timeout (float): Per-operation timeout in seconds.
            retries (int): Retries for transient WHOIS failures.
            whois_client (WhoisClient | None): WHOIS client override (tests).
            now (datetime | None): Reference time for expiry calculation; defaults to the current UTC time.
        '''
        self.hostname = hostname
        self.domain = registrable_domain(hostname)
        self.client_factory = client_factory
        self.whois_client = whois_client or WhoisClient(timeout=timeout, retries=retries)
        self.now = now

    async def collect(self) -> tuple[DomainRegistration | None, list[CollectionError]]:
        '''
        Try RDAP first, then WHOIS; errors are kept only when no source succeeded.
        Returns:
            tuple[DomainRegistration | None, list[CollectionError]]: Registration data (or None) and errors.
        '''
        errors: list[CollectionError] = []
        try:
            reg: DomainRegistration | None = await self._rdap_lookup()
        except RdapUnavailableError as exc:
            errors.append(self.error(self.domain, "rdap_unavailable", str(exc)))
            reg = None

        if reg is None:
            try:
                server, text = await self.whois_client.lookup(self.domain)
            except WhoisError as exc:
                errors.append(self.error(self.domain, "whois_failed", str(exc)[:300]))
                return None, errors
            reg = WhoisParser.parse(self.domain, text, server)
            if reg is None:
                errors.append(self.error(self.domain, "whois_no_data", f"{server} returned no registration data"))
                return None, errors
            errors.clear()  # fallback succeeded; RDAP absence is not an incomplete check

        if reg.expires:
            reg.days_until_expiry = (reg.expires - (self.now or datetime.now(UTC))).days
        return reg, errors

    async def _rdap_lookup(self) -> DomainRegistration:
        '''
        Resolve the TLD's RDAP server from the IANA bootstrap and fetch the domain object.
        Returns:
            DomainRegistration: Parsed registration data.
        Raises:
            RdapUnavailableError: If the bootstrap or registry lookup fails.
        '''
        tld = self.domain.rsplit(".", 1)[-1]
        async with self.client_factory(Scope(hosts=["data.iana.org"])) as iana:
            outcome = await iana.fetch(self.IANA_BOOTSTRAP)
        if outcome.final is None or outcome.final.status_code != 200:
            raise RdapUnavailableError(
                f"IANA RDAP bootstrap unavailable: {outcome.error or outcome.stopped_reason}")
        base = self.find_rdap_base(json.loads(outcome.final.body), tld)
        if base is None:
            raise RdapUnavailableError(f"no RDAP service registered for .{tld}")

        url = base.rstrip("/") + f"/domain/{self.domain}"
        host = urlsplit(url).hostname
        async with self.client_factory(Scope(hosts=[host])) as rdap:
            outcome = await rdap.fetch(url)
        if outcome.final is None or outcome.final.status_code != 200:
            status = outcome.final.status_code if outcome.final else None
            raise RdapUnavailableError(
                f"RDAP lookup at {host} failed: {outcome.error or outcome.stopped_reason or f'HTTP {status}'}")
        return self.parse_rdap_domain(self.domain, json.loads(outcome.final.body), outcome.final.url)

    @staticmethod
    def find_rdap_base(bootstrap: dict[str, Any], tld: str) -> str | None:
        '''
        Find the RDAP base URL for a TLD, preferring HTTPS.
        Parameters:
            bootstrap (dict[str, Any]): Decoded IANA dns.json.
            tld (str): Top-level domain without a dot.
        Returns:
            str | None: Base URL, or None.
        '''
        for tlds, urls in bootstrap.get("services", []):
            if tld.lower() in (t.lower() for t in tlds):
                https = [u for u in urls if u.startswith("https://")]
                return (https or urls or [None])[0]
        return None

    @classmethod
    def parse_rdap_domain(cls, domain: str, data: dict[str, Any], source_url: str | None = None) -> DomainRegistration:
        '''
        Parse an RDAP domain object (registrar, events, status, nameservers, DNSSEC).
        Parameters:
            domain (str): Registrable domain.
            data (dict[str, Any]): Decoded RDAP JSON.
            source_url (str | None): URL that served the response.
        Returns:
            DomainRegistration: Registration data.
        '''
        events = {e.get("eventAction"): cls._parse_dt(e.get("eventDate")) for e in data.get("events", []) or []}
        registrar, iana_id = None, None
        for entity in data.get("entities", []) or []:
            if "registrar" in (entity.get("roles") or []):
                registrar = NetworkCollector.vcard_fn(entity.get("vcardArray"))
                for pid in entity.get("publicIds", []) or []:
                    if "iana" in str(pid.get("type", "")).lower():
                        iana_id = str(pid.get("identifier"))
                break
        secure = data.get("secureDNS") or {}
        return DomainRegistration(
            domain=domain, source="rdap", source_url=source_url,
            registrar=registrar, registrar_iana_id=iana_id,
            created=events.get("registration"), updated=events.get("last changed"),
            expires=events.get("expiration"),
            status=[str(s) for s in data.get("status", []) or []],
            nameservers=sorted({str(ns.get("ldhName", "")).lower().rstrip(".")
                                for ns in data.get("nameservers", []) or [] if ns.get("ldhName")}),
            dnssec=secure.get("delegationSigned") if isinstance(secure, dict) else None,
        )

    @staticmethod
    def _parse_dt(value: Any) -> datetime | None:
        '''
        Parse an RDAP ISO-8601 timestamp.
        Parameters:
            value (Any): Raw timestamp value.
        Returns:
            datetime | None: Aware datetime or None.
        '''
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
