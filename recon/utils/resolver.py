'''
DNS query helpers with explicit status classification and bounded retries.
'''

from __future__ import annotations

import asyncio
import socket
from time import perf_counter

import dns.asyncresolver
import dns.exception
import dns.flags
import dns.name
import dns.rdata
import dns.rdatatype
import dns.resolver

from recon.models import DnsQueryResult, DnsQueryStatus, DnsRecord

_NAME_TYPES: set[str] = {"NS", "CNAME", "PTR"}
_RETRYABLE: set[DnsQueryStatus] = {DnsQueryStatus.TIMEOUT, DnsQueryStatus.SERVFAIL}


class DnsClient:
    '''
    Async DNS client with status classification, bounded concurrency and retries for TIMEOUT/SERVFAIL.
    '''
    def __init__(
        self,
        timeout: float = 10.0,
        retries: int = 2,
        concurrency: int = 10,
        resolver: dns.asyncresolver.Resolver | None = None,
    ) -> None:
        '''
        Create the client.
        Parameters:
            timeout (float): Per-operation timeout in seconds.
            retries (int): Number of retries for transient failures.
            concurrency (int): Maximum concurrent queries.
            resolver (dns.asyncresolver.Resolver | None): dnspython resolver override (tests).
        '''
        self.timeout = timeout
        self.retries = retries
        self.resolver = resolver or dns.asyncresolver.Resolver()
        self._sem = asyncio.Semaphore(concurrency)

    async def query(self, name: str, rtype: str) -> DnsQueryResult:
        '''
        Query a name, retrying only timeouts and SERVFAIL.
        Parameters:
            name (str): Name to query.
            rtype (str): Record type.
        Returns:
            DnsQueryResult: Classified result including attempt count.
        '''
        attempts = 0
        result: DnsQueryResult | None = None
        while attempts <= self.retries:
            attempts += 1
            async with self._sem:
                result = await self._query_once(name, rtype)
            if result.status not in _RETRYABLE:
                break
            if attempts <= self.retries:
                await asyncio.sleep(0.25 * 2 ** (attempts - 1))
        assert result is not None
        result.attempts = attempts
        return result

    async def _query_once(self, name: str, rtype: str) -> DnsQueryResult:
        '''
        Send one query and classify the outcome.
        Parameters:
            name (str): Name to query.
            rtype (str): Record type.
        Returns:
            DnsQueryResult: Classified result.
        '''
        start = perf_counter()

        def done(status: DnsQueryStatus, records=(), error: str | None = None) -> DnsQueryResult:
            return DnsQueryResult(
                name=name, record_type=rtype, status=status, records=list(records),
                response_time_ms=round((perf_counter() - start) * 1000, 2), error=error,
            )

        try:
            answer = await self.resolver.resolve(name, rtype, lifetime=self.timeout)
        except dns.resolver.NXDOMAIN:
            return done(DnsQueryStatus.NXDOMAIN)
        except dns.resolver.NoAnswer:
            return done(DnsQueryStatus.NODATA)
        except dns.resolver.NoNameservers as exc:
            return done(DnsQueryStatus.SERVFAIL, error=str(exc))
        except dns.exception.Timeout as exc:
            return done(DnsQueryStatus.TIMEOUT, error=str(exc) or "query timed out")
        except dns.exception.DNSException as exc:
            return done(DnsQueryStatus.ERROR, error=f"{type(exc).__name__}: {exc}")

        ttl = answer.rrset.ttl if answer.rrset is not None else None
        records = [DnsRecord(value=format_rdata(rtype, rd), ttl=ttl) for rd in answer]
        result = done(DnsQueryStatus.NOERROR, records)
        response = getattr(answer, "response", None)
        if response is not None:
            result.authenticated = bool(response.flags & dns.flags.AD)
        return result


def format_rdata(rtype: str, rdata: dns.rdata.Rdata) -> str:
    '''
    Render record data as a normalized string.
    Parameters:
        rtype (str): Record type.
        rdata (dns.rdata.Rdata): Record data.
    Returns:
        str: Normalized value.
    '''
    if rtype == "TXT":
        return "".join(s.decode("utf-8", "replace") for s in rdata.strings)
    if rtype in _NAME_TYPES:
        return _name(rdata.target)
    if rtype == "MX":
        return f"{rdata.preference} {_name(rdata.exchange)}"
    return rdata.to_text()


def _name(name: dns.name.Name) -> str:
    '''
    Lowercase name without trailing dot; the root name (e.g. null MX, RFC 7505) stays '.'.
    Parameters:
        name (dns.name.Name): DNS name.
    Returns:
        str: Normalized name.
    '''
    return name.to_text().rstrip(".").lower() or "."


async def system_resolve(host: str, port: int) -> list[str]:
    '''
    Resolve via the OS resolver (what sockets will actually connect to).
    Parameters:
        host (str): Hostname.
        port (int): Port, used for getaddrinfo.
    Returns:
        list[str]: Unique addresses.
    Raises:
        OSError: If resolution fails.
    '''
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(info[4][0] for info in infos))
