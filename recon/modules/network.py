'''
Network and IP intelligence: PTR, ASN (Team Cymru DNS) and RDAP allocation data.
'''

from __future__ import annotations

import asyncio
import ipaddress
import json
from typing import Any, ClassVar

from recon.models import AsnInfo, CollectionError, DnsQueryStatus, IpIntel, NetworkData, RdapNetwork
from recon.modules.base import Collector
from recon.utils import DnsClient, SafeHttpClient, Scope, is_public_ip

IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class NetworkCollector(Collector[NetworkData]):
    '''
    Gathers PTR, ASN and RDAP allocation data for each unique resolved IP.
    '''

    name: ClassVar[str] = "network"
    RDAP_BOOTSTRAP: ClassVar[str] = "https://rdap.org/ip/{ip}"
    # rdap.org redirects to the responsible Regional Internet Registry.
    RDAP_SCOPE: ClassVar[Scope] = Scope(hosts=[
        "rdap.org", "rdap.arin.net", "rdap.db.ripe.net", "rdap.apnic.net",
        "rdap.lacnic.net", "rdap.afrinic.net",
    ])

    def __init__(self, ips: list[str], dns_client: DnsClient, rdap_client: SafeHttpClient) -> None:
        '''
        Create the collector.
        Parameters:
            ips (list[str]): Resolved addresses (duplicates are ignored).
            dns_client (DnsClient): DNS client used for lookups.
            rdap_client (SafeHttpClient): HTTP client scoped to RDAP servers.
        '''
        self.ips = list(dict.fromkeys(ips))
        self.dns_client = dns_client
        self.rdap_client = rdap_client

    async def collect(self) -> tuple[NetworkData, list[CollectionError]]:
        '''
        Gather PTR, ASN and RDAP data for each unique IP concurrently.
        Returns:
            tuple[NetworkData, list[CollectionError]]: Per-IP intelligence and lookup errors.
        '''
        results = await asyncio.gather(*(self._analyze_ip(ip) for ip in self.ips))
        data = NetworkData(ips=[intel for intel, _ in results])
        errors = [err for _, errs in results for err in errs]
        return data, errors

    async def _analyze_ip(self, ip: str) -> tuple[IpIntel, list[CollectionError]]:
        '''
        Collect PTR, ASN and RDAP data for one IP; registry lookups are skipped for non-public space.
        Parameters:
            ip (str): IPv4 or IPv6 address.
        Returns:
            tuple[IpIntel, list[CollectionError]]: Intelligence for the IP and any lookup errors.
        '''
        addr = ipaddress.ip_address(ip)
        intel = IpIntel(ip=ip, version=addr.version, is_public=is_public_ip(ip))
        errors: list[CollectionError] = []

        ptr_q = await self.dns_client.query(addr.reverse_pointer, "PTR")
        intel.ptr_status = ptr_q.status
        intel.ptr = ptr_q.values
        if not ptr_q.status.is_definitive:
            errors.append(self.error(f"PTR {ip}", ptr_q.status.value, ptr_q.error or ""))

        if not intel.is_public:
            return intel, errors  # registry data is meaningless for private/reserved space

        intel.asn = await self._lookup_asn(addr, errors)

        outcome = await self.rdap_client.fetch(self.RDAP_BOOTSTRAP.format(ip=ip))
        if outcome.final is not None and outcome.final.status_code == 200:
            try:
                intel.rdap = self.parse_rdap(json.loads(outcome.final.body), outcome.final.url)
            except (ValueError, TypeError) as exc:
                errors.append(self.error(f"RDAP {ip}", "parse_error", str(exc)))
        else:
            status = outcome.final.status_code if outcome.final else None
            errors.append(self.error(
                f"RDAP {ip}", outcome.error_type or outcome.stopped_reason or f"http_{status}",
                outcome.error or outcome.stopped_url or f"RDAP returned HTTP {status}",
            ))
        return intel, errors

    async def _lookup_asn(self, addr: IpAddress, errors: list[CollectionError]) -> AsnInfo | None:
        '''
        Look up origin ASN and AS name via Team Cymru DNS.
        Parameters:
            addr (IpAddress): IP address.
            errors (list[CollectionError]): List to which lookup errors are appended.
        Returns:
            AsnInfo | None: ASN information, or None when unavailable.
        '''
        origin = await self.dns_client.query(self.cymru_origin_name(addr), "TXT")
        if origin.status is not DnsQueryStatus.NOERROR:
            if not origin.status.is_definitive:
                errors.append(self.error(f"ASN {addr}", origin.status.value, origin.error or ""))
            return None
        info = self.parse_cymru_origin(origin.values[0]) if origin.values else None
        if info is None:
            return None
        name_q = await self.dns_client.query(f"AS{info.asn}.asn.cymru.com", "TXT")
        if name_q.status is DnsQueryStatus.NOERROR and name_q.values:
            info.name = self.parse_cymru_asname(name_q.values[0])
        return info

    @staticmethod
    def cymru_origin_name(addr: IpAddress) -> str:
        '''
        Build the Team Cymru origin lookup name for an address.
        Parameters:
            addr (IpAddress): IP address.
        Returns:
            str: DNS name to query for TXT.
        '''
        if addr.version == 4:
            return addr.reverse_pointer.removesuffix(".in-addr.arpa") + ".origin.asn.cymru.com"
        return addr.reverse_pointer.removesuffix(".ip6.arpa") + ".origin6.asn.cymru.com"

    @staticmethod
    def parse_cymru_origin(txt: str) -> AsnInfo | None:
        '''
        Parse an origin TXT answer such as '13335 | 104.16.0.0/13 | US | arin | 2014-03-28'.
        Parameters:
            txt (str): TXT record value.
        Returns:
            AsnInfo | None: ASN information, or None if malformed.
        '''
        parts = [p.strip() for p in txt.split("|")]
        if not parts or not parts[0].split() or not parts[0].split()[0].isdigit():
            return None

        def get(i: int) -> str | None:
            return (parts[i] or None) if len(parts) > i else None

        return AsnInfo(asn=int(parts[0].split()[0]), prefix=get(1), country=get(2),
                       registry=get(3), allocated=get(4))

    @staticmethod
    def parse_cymru_asname(txt: str) -> str | None:
        '''
        Parse the AS name from an AS TXT answer.
        Parameters:
            txt (str): TXT record value.
        Returns:
            str | None: AS name, or None.
        '''
        parts = [p.strip() for p in txt.split("|")]
        return parts[4] if len(parts) >= 5 and parts[4] else None

    @classmethod
    def parse_rdap(cls, data: dict[str, Any], source_url: str | None = None) -> RdapNetwork:
        '''
        Parse an RDAP IP-network response.
        Parameters:
            data (dict[str, Any]): Decoded RDAP JSON.
            source_url (str | None): URL that served the response.
        Returns:
            RdapNetwork: Network allocation data.
        '''
        cidrs = []
        for c in data.get("cidr0_cidrs", []) or []:
            prefix = c.get("v4prefix") or c.get("v6prefix")
            if prefix and c.get("length") is not None:
                cidrs.append(f"{prefix}/{c['length']}")
        return RdapNetwork(
            handle=data.get("handle"),
            name=data.get("name"),
            type=data.get("type"),
            start_address=data.get("startAddress"),
            end_address=data.get("endAddress"),
            cidrs=cidrs,
            country=data.get("country"),
            organizations=cls._rdap_org_names(data.get("entities", []) or []),
            source_url=source_url,
        )

    @classmethod
    def _rdap_org_names(cls, entities: list[dict[str, Any]]) -> list[str]:
        '''
        Collect entity names, preferring registrant entities.
        Parameters:
            entities (list[dict[str, Any]]): RDAP entity list.
        Returns:
            list[str]: Unique organization names.
        '''
        preferred: list[str] = []
        others: list[str] = []

        def walk(items: list[dict[str, Any]]) -> None:
            for entity in items:
                name = cls.vcard_fn(entity.get("vcardArray"))
                if name:
                    target = preferred if "registrant" in (entity.get("roles") or []) else others
                    target.append(name)
                walk(entity.get("entities", []) or [])

        walk(entities)
        return list(dict.fromkeys(preferred or others))

    @staticmethod
    def vcard_fn(vcard: Any) -> str | None:
        '''
        Extract the 'fn' (formatted name) from an RDAP jCard.
        Parameters:
            vcard (Any): RDAP vcardArray value.
        Returns:
            str | None: The name, or None.
        '''
        if not (isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list)):
            return None
        for prop in vcard[1]:
            if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn" and isinstance(prop[3], str):
                return prop[3].strip() or None
        return None
