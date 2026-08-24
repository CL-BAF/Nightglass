"""Single-host nmap -sV probe for honeywatch.

Runs ``nmap -Pn -sV --version-light`` against one host/port, parses the
``-oX -`` XML from stdout, and returns a plain dict of service facts.
Unlike the masscan/zmap wrappers this never raises: by contract it returns
``{"error": ...}`` when the binary is missing or anything fails.
"""

from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Dict


def probe(
    ip: str,
    port: int,
    timeout_s: int,
    bin_path: str = "nmap",
) -> Dict[str, Any]:
    """Probe a single (ip, port) with nmap version detection.

    Args:
        ip: target host.
        port: TCP port to probe.
        timeout_s: per-host nmap timeout in seconds (``--host-timeout``).
        bin_path: path to the ``nmap`` binary.

    Returns:
        A dict containing any of: ``port``, ``state``, ``service``,
        ``product``, ``version``, ``cpe``, ``banner``. Keys whose values
        could not be determined are omitted. On any failure the dict is
        ``{"error": <message>}`` (never raises).
    """
    argv = [
        bin_path,
        "-Pn",
        "-sV",
        "--version-light",
        "-p",
        str(port),
        "--host-timeout",
        f"{timeout_s}s",
        "-oX",
        "-",
        ip,
    ]
    # Safety margin beyond --host-timeout in case nmap hangs entirely.
    safety_timeout = max(timeout_s * 2 + 30, 60)

    try:
        proc = subprocess.run(argv, capture_output=True, timeout=safety_timeout)
    except FileNotFoundError:
        return {"error": "nmap not found"}
    except subprocess.TimeoutExpired:
        return {"error": f"nmap timed out after {safety_timeout}s"}

    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", "replace").strip()
        return {"error": f"nmap exited with code {proc.returncode}: {stderr or 'no stderr'}"}

    try:
        return _parse_xml(proc.stdout.decode("utf-8", "replace"), port)
    except ET.ParseError as exc:
        return {"error": f"failed to parse nmap XML output: {exc}"}


def _parse_xml(raw: str, port: int) -> Dict[str, Any]:
    """Extract the first useful ``<port>`` entry from nmap ``-oX`` XML."""
    root = ET.fromstring(raw)
    result: Dict[str, Any] = {}

    # Prefer the port we asked for; fall back to the first open port found.
    candidates = []
    for host in root.findall(".//host"):
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        candidates.extend(ports_el.findall("port"))

    if not candidates:
        return result

    port_el = None
    for candidate in candidates:
        if candidate.get("portid") == str(port):
            port_el = candidate
            break
    if port_el is None:
        port_el = candidates[0]

    portid = port_el.get("portid")
    if portid is not None:
        result["port"] = int(portid)

    state_el = port_el.find("state")
    if state_el is not None and state_el.get("state"):
        result["state"] = state_el.get("state")

    svc = port_el.find("service")
    if svc is not None:
        if svc.get("name"):
            result["service"] = svc.get("name")
        if svc.get("product"):
            result["product"] = svc.get("product")
        if svc.get("version"):
            result["version"] = svc.get("version")
        cpe_el = svc.find("cpe")
        if cpe_el is not None and cpe_el.text:
            result["cpe"] = cpe_el.text.strip()

    banner_el = port_el.find("banner")
    if banner_el is not None and banner_el.text:
        result["banner"] = banner_el.text.strip()

    return result
