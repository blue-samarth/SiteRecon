'''
Scan history storage. Import from this package, e.g. ``from recon.storage import JsonScanStore``.
'''

from recon.storage.base import ScanStore
from recon.storage.json_store import JsonScanStore

__all__ = ["ScanStore", "JsonScanStore"]
