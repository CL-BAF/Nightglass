"""External scanner subcommands (masscan, zmap, nmap) for honeywatch.

Each wrapper invokes an external binary via ``subprocess.run`` with an argv
list (never a shell string) and normalises the output into honeywatch
dataclasses or plain dicts. When a scanner binary is missing or fails, the
subcommand wrappers raise :class:`ScannerError` (except
:func:`honeywatch.scanners.nmap_probe.probe`, which returns an
``{"error": ...}`` dict by contract).
"""

from __future__ import annotations


class ScannerError(Exception):
    """Raised when an external scanner binary is missing or exits non-zero."""


from honeywatch.scanners.masscan import run as run_masscan
from honeywatch.scanners.zmap import run as run_zmap
from honeywatch.scanners.nmap_probe import probe as probe_nmap


__all__ = [
    "ScannerError",
    "run_masscan",
    "run_zmap",
    "probe_nmap",
]
