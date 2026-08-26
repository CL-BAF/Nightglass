"""External scanner subcommands (masscan, zmap, nmap) for honeywatch.

Each wrapper invokes an external binary via ``subprocess.run`` with an argv
list (never a shell string) and normalises the output into honeywatch
dataclasses or plain dicts. When a scanner binary is missing or fails, the
subcommand wrappers raise :class:`ScannerError` (except
:func:`honeywatch.scanners.nmap_probe.probe`, which returns an
``{"error": ...}`` dict by contract).

Rootless scanning: masscan/zmap need raw sockets, so a non-root user gets a
"permission denied" failure. :func:`run_with_sudo_fallback` retries the
invocation via ``sudo -n`` (non-interactive — never prompts, so it cannot
hang a scan) when the direct run fails with a permission error. This makes
scans work out of the box on hosts with passwordless sudo (default on Kali)
and degrades to a clear error otherwise.
"""

from __future__ import annotations

import subprocess


class ScannerError(Exception):
    """Raised when an external scanner binary is missing or exits non-zero."""


def _looks_like_permission_error(stderr: str, returncode: int) -> bool:
    """True when a scanner failure is the raw-socket permission problem.

    masscan prints ``FAIL: permission denied ... need to sudo or run as
    root``; zmap prints ``unable to send packet`` / ``Operation not
    permitted``. Anything else (parse errors, bad ranges) is a real failure.
    """
    low = (stderr or "").lower()
    return (
        returncode != 0
        and (
            "permission denied" in low
            or "permission" in low
            or "operation not permitted" in low
            or "unable to send" in low
            or "need to sudo" in low
            or "as root" in low
        )
    )


def run_with_sudo_fallback(
    argv: list[str],
    timeout_s: float | None,
) -> subprocess.CompletedProcess:
    """Run ``argv``; on a raw-socket permission failure, retry via ``sudo -n``.

    ``sudo -n`` (non-interactive) never prompts for a password — if the user
    has passwordless sudo (default on Kali) the scan proceeds; otherwise the
    retry fails fast with a clear "sudo: a password is required" and the
    original error is surfaced. This is what makes ``honeywatch scan`` work
    without root by default.
    """
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout_s)
    except FileNotFoundError:
        raise  # binary missing — caller reports it
    if proc.returncode == 0:
        return proc
    stderr = proc.stderr.decode("utf-8", "replace").strip()
    if not _looks_like_permission_error(stderr, proc.returncode):
        return proc
    # Retry via non-interactive sudo (no prompt, cannot hang).
    try:
        sudo_proc = subprocess.run(
            ["sudo", "-n", *argv], capture_output=True, timeout=timeout_s
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return proc  # no sudo binary — surface the original error
    if sudo_proc.returncode == 0:
        return sudo_proc
    # sudo -n failed (no passwordless sudo, or sudoers denies) — surface the
    # original permission error with the hint, not the sudo noise.
    return proc


from honeywatch.scanners.masscan import run as run_masscan
from honeywatch.scanners.zmap import run as run_zmap
from honeywatch.scanners.nmap_probe import probe as probe_nmap


__all__ = [
    "ScannerError",
    "run_masscan",
    "run_zmap",
    "probe_nmap",
    "run_with_sudo_fallback",
]
