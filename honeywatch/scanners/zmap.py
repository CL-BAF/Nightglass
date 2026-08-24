"""zmap wrapper for honeywatch.

zmap scans a single TCP port per invocation, so :func:`run` launches one
zmap process per requested port and reads the IP results from stdout
(``-o -``). Hosts are returned as :class:`HostHit` records tagged with
``scanner="zmap"``.
"""

from __future__ import annotations

import subprocess
from typing import List, Optional

from honeywatch.models import HostHit, SSH_PORT
from honeywatch.scanners import ScannerError


def run(
    targets: List[str],
    ports: List[int],
    rate: int,
    timeout_s: Optional[int],
    bin_path: str = "zmap",
) -> List[HostHit]:
    """Run zmap against ``targets`` for each port and return open hosts.

    Args:
        targets: IPv4 ranges/CIDRs to scan (e.g. ``["10.0.0.0/24"]``).
        ports: TCP ports to probe, one zmap invocation per port.
        rate: packets-per-second passed via ``--rate``.
        timeout_s: subprocess timeout in seconds, or ``None`` for no timeout.
        bin_path: path to the ``zmap`` binary.

    Returns:
        A list of ``HostHit`` records (one per responsive IP per port),
        each tagged with ``scanner="zmap"``.

    Raises:
        ScannerError: if the binary is missing or zmap exits non-zero.
    """
    if not targets:
        return []
    if not ports:
        ports = [SSH_PORT]

    hits: List[HostHit] = []
    for port in ports:
        argv = [
            bin_path,
            "-q",
            "-p",
            str(port),
            "--rate",
            str(rate),
            "-o",
            "-",
            *targets,
        ]
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=timeout_s)
        except FileNotFoundError as exc:
            raise ScannerError(
                f"zmap binary not found at {bin_path!r}: "
                "install zmap (linux) (e.g. apt install zmap) or set "
                "scanners.zmap.bin / --zmap-bin"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise ScannerError(
                f"zmap timed out after {timeout_s}s "
                "(raise scanners.zmap.timeout_s or set it to null for no timeout)"
            ) from exc

        if proc.returncode != 0:
            stderr = proc.stderr.decode("utf-8", "replace").strip()
            raise ScannerError(
                f"zmap exited with code {proc.returncode}: {stderr or 'no stderr'}"
            )

        for line in proc.stdout.decode("utf-8", "replace").splitlines():
            ip = line.strip()
            if ip:
                hits.append(HostHit(ip=ip, port=port, scanner="zmap"))
    return hits
