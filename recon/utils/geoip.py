'''
Offline IP geolocation for city-level hosting-location estimates.

Reads a local MaxMind-format (.mmdb) city database with the ``maxminddb`` reader. The intended database is
the free **DB-IP IP-to-City Lite** (CC-BY-4.0, no account needed to download); a MaxMind GeoLite2-City file
works identically because both use the GeoIP2-City record schema.

Everything here is optional and fail-soft: if the ``maxminddb`` package is not installed, or the database
path is missing or unreadable, :meth:`GeoLocator.open` returns ``None`` and the scan proceeds with the
free ASN/RDAP country estimate only. No network I/O happens — this is a local lookup on already-resolved
IPs, so it stays within passive reconnaissance.
'''

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from recon.models import GeoLocation
from recon.utils.logger import get_logger

log: logging.Logger = get_logger("geoip")


def _name(record: dict[str, Any], *path: str) -> Any:
    '''
    Safely walk a nested mapping, returning None if any step is missing.
    Parameters:
        record (dict[str, Any]): The record to walk.
        path (str): Keys to follow in order.
    Returns:
        Any: The value at the path, or None.
    '''
    node: Any = record
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def record_to_location(record: dict[str, Any], source: str, database_date: str | None) -> GeoLocation:
    '''
    Convert a GeoIP2-City-schema record (as DB-IP Lite and GeoLite2 both use) into a GeoLocation.
    Parameters:
        record (dict[str, Any]): The database record for an IP.
        source (str): The database type/name, for provenance and attribution.
        database_date (str | None): The database build date (YYYY-MM-DD).
    Returns:
        GeoLocation: The parsed location (fields absent from the record are left None).
    '''
    subdivisions = record.get("subdivisions") if isinstance(record.get("subdivisions"), list) else []
    region = _name(subdivisions[0], "names", "en") if subdivisions else None
    return GeoLocation(
        country=_name(record, "country", "names", "en"),
        country_code=_name(record, "country", "iso_code"),
        region=region,
        city=_name(record, "city", "names", "en"),
        latitude=_name(record, "location", "latitude"),
        longitude=_name(record, "location", "longitude"),
        source=source, database_date=database_date)


class GeoLocator:
    '''
    A loaded offline geolocation database. Create with :meth:`open`; close when done (or use as a context
    manager). Constructed directly with an injected reader in tests.
    '''

    def __init__(self, reader: Any, *, source: str, database_date: str | None) -> None:
        '''
        Wrap an open database reader.
        Parameters:
            reader (Any): An object with ``get(ip)`` returning a record dict or None (a maxminddb reader).
            source (str): The database type/name (for provenance/attribution).
            database_date (str | None): The database build date (YYYY-MM-DD).
        '''
        self._reader = reader
        self.source = source
        self.database_date = database_date

    @classmethod
    def open(cls, path: Path | str | None) -> GeoLocator | None:
        '''
        Open a city database, or return None if unavailable (no package, missing file, or invalid database).

        Never raises: a geolocation database is an optional enrichment and must never fail a scan.
        Parameters:
            path (Path | str | None): Path to a .mmdb city database, or None to disable.
        Returns:
            GeoLocator | None: An open locator, or None if geolocation is unavailable.
        '''
        if not path:
            return None
        if not Path(path).is_file():
            log.warning("geoip database not found at %s; continuing with ASN/RDAP country only", path)
            return None
        try:
            import maxminddb
        except ImportError:
            log.warning("the 'maxminddb' package is not installed; city-level geolocation is disabled")
            return None
        try:
            reader = maxminddb.open_database(str(path))
        except (OSError, ValueError) as exc:   # ValueError covers maxminddb.InvalidDatabaseError
            log.warning("could not open geoip database %s: %s", path, exc)
            return None
        source, database_date = cls._metadata(reader)
        log.info("loaded geoip database %s (%s, built %s)", path, source, database_date or "unknown")
        return cls(reader, source=source, database_date=database_date)

    @staticmethod
    def _metadata(reader: Any) -> tuple[str, str | None]:
        '''
        Extract the database type and build date from a reader's metadata, tolerating readers that lack it.
        Parameters:
            reader (Any): The open reader.
        Returns:
            tuple[str, str | None]: (source/database type, build date YYYY-MM-DD or None).
        '''
        try:
            meta = reader.metadata()
            source = str(getattr(meta, "database_type", None) or "offline geolocation database")
            epoch = getattr(meta, "build_epoch", None)
            date = datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%d") if epoch else None
            return source, date
        except Exception:   # noqa: BLE001 - metadata is best-effort provenance, never fatal
            return "offline geolocation database", None

    def lookup(self, ip: str) -> GeoLocation | None:
        '''
        Look up one IP, returning its estimated location or None if absent/unresolvable.
        Parameters:
            ip (str): The IP address.
        Returns:
            GeoLocation | None: The location, or None if the database has no entry.
        '''
        try:
            record = self._reader.get(ip)
        except (ValueError, KeyError):
            return None
        if not isinstance(record, dict) or not record:
            return None
        return record_to_location(record, self.source, self.database_date)

    def close(self) -> None:
        '''
        Close the underlying database reader if it supports closing.
        '''
        closer = getattr(self._reader, "close", None)
        if callable(closer):
            try:
                closer()
            except Exception:   # noqa: BLE001 - closing a read-only mmap must never fail a scan
                pass

    def __enter__(self) -> GeoLocator:
        '''
        Enter a context manager.
        Returns:
            GeoLocator: This locator.
        '''
        return self

    def __exit__(self, *exc: object) -> None:
        '''
        Close the reader on context exit.
        Parameters:
            exc (object): Exception info (ignored).
        '''
        self.close()
