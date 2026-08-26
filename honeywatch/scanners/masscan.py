"""masscan wrapper for honeywatch.

Runs ``masscan`` once against one or more target ranges and parses its
JSON-lines output (``--output-format json``) into :class:`HostHit` records.
The command line is built as an argv list and executed with
:func:`subprocess.run` — never a shell string. Output is written to a
temporary file that is always cleaned up.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import List, Optional

from honeywatch.models import HostHit, SSH_PORT
from honeywatch.scanners import ScannerError, run_with_sudo_fallback


def run(
    targets: List[str],
    ports: List[int],
    rate: int,
    timeout_s: Optional[int],
    bin_path: str = "masscan",
    excludes: Optional[List[str]] = None,
    wait_s: int = 3,
) -> List[HostHit]:
    """Run masscan against ``targets`` and return the open-ports as HostHits.

    Args:
        targets: IPv4 ranges/CIDRs to scan (e.g. ``["10.0.0.0/24"]``).
        ports: TCP ports to probe; defaults to SSH port 22 when empty.
        rate: packets-per-second passed via ``--rate``.
        timeout_s: subprocess timeout in seconds, or ``None`` for no timeout.
        bin_path: path to the ``masscan`` binary.
        excludes: extra CIDRs to skip via ``--exclude`` (e.g. RFC1918 ranges
            and your own egress IP on a 0.0.0.0/0 sweep).
        wait_s: seconds masscan waits after sending for late SYN-ACK replies
            (``--wait``). ``0`` drops late replies and under-counts hits;
            a small positive value improves discovery completeness.

    Returns:
        A list of ``HostHit`` records (one per open TCP port), each tagged
        with ``scanner="masscan"``.

    Raises:
        ScannerError: if the binary is missing, the run times out, or masscan
            exits non-zero.
    """
    if not targets:
        return []
    if not ports:
        ports = [SSH_PORT]

    port_spec = ",".join(str(p) for p in ports)
    tmp_path: Optional[str] = None
    try:
        fd, tmp_path = tempfile.mkstemp(prefix="honeywatch_masscan_", suffix=".json")
        os.close(fd)

        argv = [
            bin_path,
            "--rate",
            str(rate),
            "--wait",
            str(max(0, int(wait_s))),
            "--output-format",
            "json",
            "--output-filename",
            tmp_path,
            "--ports",
            port_spec,
        ]
        for net in excludes or []:
            argv += ["--exclude", str(net)]
        argv += targets

        try:
            # Non-root users hit raw-socket permission errors; run_with_sudo_fallback
            # retries via `sudo -n` (non-interactive, never prompts) so scans work
            # out of the box on hosts with passwordless sudo (default on Kali).
            proc = run_with_sudo_fallback(argv, timeout_s)
        except FileNotFoundError as exc:
            raise ScannerError(
                f"masscan binary not found at {bin_path!r}: "
                "install masscan (linux) (e.g. apt install masscan) or set "
                "scanners.masscan.bin / --masscan-bin"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise ScannerError(
                f"masscan timed out after {timeout_s}s "
                "(raise scanners.masscan.timeout_s or set it to null for no timeout)"
            ) from exc

        if proc.returncode != 0:
            stderr = proc.stderr.decode("utf-8", "replace").strip()
            hint = ""
            if "permission" in stderr.lower():
                hint = (" [hint] run with sudo or grant raw sockets: "
                        "sudo setcap cap_net_raw+ep $(which masscan)")
            raise ScannerError(
                f"masscan exited with code {proc.returncode}: {stderr or 'no stderr'}{hint}"
            )

        hits: List[HostHit] = []
        with open(tmp_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ip = record.get("ip")
                if not ip:
                    continue
                for port_entry in record.get("ports") or []:
                    if port_entry.get("status") != "open":
                        continue
                    hits.append(
                        HostHit(
                            ip=ip,
                            port=int(port_entry.get("port", SSH_PORT)),
                            scanner="masscan",
                        )
                    )
        return hits
    finally:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
