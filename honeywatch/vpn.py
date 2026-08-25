"""Mullvad VPN gating — network subcommands refuse to start without it.

Requirement: "Have Mullvad VPN on (or tool refuses to start)."

Detection, in order (any pass is sufficient):

1. Mullvad's own egress endpoint ``https://am.i.mullvad.net/json`` reports
   ``mullvad_exit_ip: true`` — authoritative, since it is measured from our
   public exit IP. Falls back to the plain-text ``/connected`` endpoint.
2. A Mullvad / WireGuard tunnel interface is present locally (Linux
   ``/sys/class/net`` or ``ip -j link``; Windows ``Get-NetAdapter``).

An explicit opt-out exists for controlled/offline testing: the ``--skip-vpn-check``
CLI flag or ``HONEYWATCH_SKIP_VPN=1`` in the environment. The default is
enforced.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.request
from typing import Any

__all__ = [
    "DEFAULT_TIMEOUT",
    "REFUSAL",
    "VpnError",
    "egress_is_mullvad",
    "interface_is_mull",
    "mullvad_connected",
    "opt_out_requested",
    "require_mullvad",
]


class VpnError(RuntimeError):
    """Raised when the VPN gate blocks a network operation.

    Used by the library entry points (e.g. :meth:`honeywatch.pipeline.Pipeline.scan`)
    so programmatic callers get an exception instead of an on-by-default gate
    that silently passes. The CLI prints ``REFUSAL`` and exits 2 instead.
    """

MULLVAD_JSON = "https://am.i.mullvad.net/json"
MULLVAD_TEXT = "https://am.i.mullvad.net/connected"
DEFAULT_TIMEOUT = 8.0

# Interface names the Mullvad app and standard Mullvad WireGuard configs use.
# ``wg0`` is intentionally excluded — it's the conventional name for ANY
# WireGuard tunnel (not just Mullvad), so matching it would false-positive on
# a non-Mullvad WireGuard setup and report "OK" on a different tunnel. The
# egress check (am.i.mullvad.net) is authoritative and checked first, so this
# only fires when that endpoint is unreachable; when it does, we match only
# Mullvad-specific names.
IFACE_PATTERNS = ("mullvad", "wg-mullvad", "mullvad-")

# Environment values that count as an explicit "yes" to skipping the gate.
_TRUTHY = ("1", "true", "yes")

REFUSAL = (
    "honeywatch: REFUSED TO START - Mullvad VPN is not connected.\n"
    "  Connect Mullvad first. For controlled/offline testing only, you may\n"
    "  pass --skip-vpn-check (or set HONEYWATCH_SKIP_VPN=1) at your own risk."
)


def _parse_bool(value: str | None) -> bool:
    return value is not None and value.strip().lower() in _TRUTHY


def opt_out_requested() -> bool:
    """True when the environment requests skipping the gate."""
    return _parse_bool(os.environ.get("HONEYWATCH_SKIP_VPN"))


def _fetch(url: str, timeout: float) -> str | None:
    """GET ``url`` and return its body; ``None`` on any failure."""
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace")
    except Exception:
        return None


def egress_is_mullvad(timeout: float = DEFAULT_TIMEOUT) -> bool:
    """True when Mullvad's endpoint says our exit IP is a Mullvad exit."""
    body = _fetch(MULLVAD_JSON, timeout)
    if body is not None:
        try:
            data: Any = json.loads(body)
        except ValueError:
            data = None
        if isinstance(data, dict) and isinstance(data.get("mullvad_exit_ip"), bool):
            return bool(data["mullvad_exit_ip"])
    text = _fetch(MULLVAD_TEXT, timeout)
    if text is None:
        return False
    lowered = text.lower()
    return "connected" in lowered and "not connected" not in lowered


def interface_is_mull() -> bool:
    """True when a Mullvad/WireGuard tunnel interface is up locally."""
    if os.name == "nt":
        return _interface_windows()
    return _interface_linux()


def _interface_linux() -> bool:
    # /sys/class/net glob is already anchored to the interface name (the
    # directory IS the ifname), so the substring match there is exact.
    try:
        import glob

        for pat in IFACE_PATTERNS:
            if glob.glob(f"/sys/class/net/*{pat}*"):
                return True
    except Exception:
        pass
    # ``ip -j link`` returns JSON; parse it and match the ``ifname`` field
    # exactly so a peer name or description containing "mullvad" elsewhere in
    # the output doesn't false-positive (the unanchored ``pat in out`` substring
    # match did this).
    try:
        out = subprocess.run(
            ["ip", "-j", "link"], capture_output=True, text=True, timeout=10
        ).stdout or ""
        data = json.loads(out)
        if isinstance(data, list):
            for iface in data:
                if not isinstance(iface, dict):
                    continue
                ifname = str(iface.get("ifname", "")).lower()
                if any(pat in ifname for pat in IFACE_PATTERNS):
                    return True
    except Exception:
        pass
    return False


def _interface_windows() -> bool:
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | "
        "Select-Object -ExpandProperty Name",
    ]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout or ""
    except Exception:
        return False
    return any(pat in out.lower() for pat in IFACE_PATTERNS)


def mullvad_connected(timeout: float = DEFAULT_TIMEOUT) -> tuple[bool, str]:
    """Return ``(connected, detail)`` using egress then local interface checks."""
    if egress_is_mullvad(timeout):
        return True, "am.i.mullvad.net confirms a Mullvad exit IP"
    if interface_is_mull():
        return True, "Mullvad/WireGuard tunnel interface detected"
    return False, "no Mullvad exit IP and no Mullvad/WireGuard interface"


def require_mullvad(timeout: float = DEFAULT_TIMEOUT, quiet: bool = False) -> bool:
    """Enforce the gate. Returns True when satisfied or explicitly bypassed.

    Prints a refusal to stderr and returns False when Mullvad is not detected
    and no opt-out is in effect.
    """
    if opt_out_requested():
        if not quiet:
            print(
                "honeywatch: vpn gate skipped (HONEYWATCH_SKIP_VPN set)",
                file=sys.stderr,
            )
        return True
    ok, detail = mullvad_connected(timeout)
    if ok:
        if not quiet:
            print(f"honeywatch: vpn gate OK ({detail})", file=sys.stderr)
        return True
    if not quiet:
        print(REFUSAL, file=sys.stderr)
    return False
