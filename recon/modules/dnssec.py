'''
DNSSEC inspection: DS (parent delegation), DNSKEY (zone keys) and resolver validation (AD flag).
'''

from __future__ import annotations

from typing import ClassVar

import dns.asyncresolver
import dns.dnssec
import dns.flags

from recon.models import CollectionError, DnsQueryResult, DnsQueryStatus, DnssecData, DnssecStatus
from recon.modules.base import Collector
from recon.utils import DnsClient, registrable_domain


class DnssecCollector(Collector[DnssecData]):
    '''
    Classifies the zone's DNSSEC state from DS, DNSKEY and resolver validation together.
    '''

    name: ClassVar[str] = "dnssec"

    def __init__(self, hostname: str, client: DnsClient | None = None, *, timeout: float = 10.0,
                 retries: int = 2) -> None:
        '''
        Create the collector.
        Parameters:
            hostname (str): Normalized target hostname; the registrable domain is treated as the zone.
            client (DnsClient | None): Client override (tests); by default one that requests validation (DO + AD).
            timeout (float): Per-query timeout in seconds.
            retries (int): Retries for timeouts and SERVFAIL.
        '''
        self.zone = registrable_domain(hostname)
        self.client = client or DnsClient(timeout, retries, resolver=self.validating_resolver())

    @staticmethod
    def validating_resolver() -> dns.asyncresolver.Resolver:
        '''
        Build a resolver that asks for DNSSEC records (DO) and for the validation result (AD).
        Returns:
            dns.asyncresolver.Resolver: Configured resolver.
        '''
        resolver = dns.asyncresolver.Resolver()
        resolver.use_edns(0, dns.flags.DO, 1232)
        resolver.flags = dns.flags.RD | dns.flags.AD
        return resolver

    async def collect(self) -> tuple[DnssecData, list[CollectionError]]:
        '''
        Query DS, DNSKEY and SOA (for the AD flag) and classify the result.
        Returns:
            tuple[DnssecData, list[CollectionError]]: DNSSEC observations and errors for inconclusive lookups.
        '''
        ds = await self.client.query(self.zone, "DS")
        dnskey = await self.client.query(self.zone, "DNSKEY")
        soa = await self.client.query(self.zone, "SOA")
        data = DnssecData(
            zone=self.zone,
            status=self.classify(ds, dnskey, soa),
            ds_status=ds.status.value,
            dnskey_status=dnskey.status.value,
            ds_records=ds.values,
            dnskey_count=len(dnskey.records),
            key_algorithms=sorted({self._algorithm(v.split()[2]) for v in dnskey.values if len(v.split()) > 3}),
            ds_digest_types=sorted({self._digest(v.split()[2]) for v in ds.values if len(v.split()) > 3}),
            resolver_authenticated=soa.authenticated if soa.status is DnsQueryStatus.NOERROR else None,
        )
        errors = [self.error(f"{q.name} {q.record_type}", q.status.value, q.error or q.status.value)
                  for q in (ds, dnskey, soa) if not q.status.is_definitive]
        return data, errors

    @staticmethod
    def classify(ds: DnsQueryResult, dnskey: DnsQueryResult, soa: DnsQueryResult) -> DnssecStatus:
        '''
        Combine DS, DNSKEY and validation results into one status.
        Parameters:
            ds (DnsQueryResult): DS query for the zone.
            dnskey (DnsQueryResult): DNSKEY query for the zone.
            soa (DnsQueryResult): SOA query used to read the resolver's AD flag.
        Returns:
            DnssecStatus: The combined status.
        '''
        if not (ds.status.is_definitive and dnskey.status.is_definitive):
            return DnssecStatus.UNKNOWN
        has_ds, has_key = bool(ds.records), bool(dnskey.records)
        if has_ds and has_key:
            return DnssecStatus.SIGNED_VALIDATED if soa.authenticated else DnssecStatus.SIGNED_UNVALIDATED
        if has_ds:
            return DnssecStatus.BROKEN
        if has_key:
            return DnssecStatus.ISLAND
        return DnssecStatus.UNSIGNED

    @staticmethod
    def _algorithm(number: str) -> str:
        '''
        Name a DNSSEC algorithm number.
        Parameters:
            number (str): Algorithm number from a DNSKEY/DS record.
        Returns:
            str: Mnemonic (e.g. ECDSAP256SHA256) or the number.
        '''
        try:
            return dns.dnssec.Algorithm(int(number)).name
        except ValueError:
            return number

    @staticmethod
    def _digest(number: str) -> str:
        '''
        Name a DS digest type.
        Parameters:
            number (str): Digest type number from a DS record.
        Returns:
            str: Digest name or the number.
        '''
        return {"1": "SHA-1", "2": "SHA-256", "3": "GOST", "4": "SHA-384"}.get(number, number)
