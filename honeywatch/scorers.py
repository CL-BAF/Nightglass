"""Vulnerability scoring for honeywatch target prioritization.

Computes a 0-1 vulnerability score based on fingerprint and signal data.
Higher scores indicate more exploitable targets. Combined with
(1 - honeypot_confidence) to produce a priority_score for target selection
in the spray and foothold phases.

Scoring signals:
- Old SSH versions (pre-8.0: +0.2, 8.0-8.8: +0.1)
- Weak ciphers in KEXINIT (CBC mode: +0.05 each, capped at +0.15)
- DSA host key (+0.1, indicates old/insecure config)
- Honeypot indicators (duplicate host key: -0.3, banner reuse: -0.2)
- No banner (-0.1, likely a stub/firewall)
- Immediate banner (+0.05, real server)
- VM detection (-0.1 for cryptojacking, +0.1 for lateral movement with IMDS)
- Web ports open (+0.1, more attack surface)
"""

from __future__ import annotations

__all__ = ["compute_vulnerability_score", "compute_priority_score"]

# OUI prefixes for VM detection via MAC address.
_VM_OUIS: dict[str, str] = {
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "00:05:69": "VMware",
    "08:00:27": "VirtualBox",
    "0A:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:15:5D": "Hyper-V",
    "00:1D:D8": "Hyper-V",
    "00:16:3E": "Xen",
    "00:F0:6B": "Xen",
    "F0:1F:AF": "Xen",
}

# Weak cipher suites that indicate an outdated or insecure SSH server.
_WEAK_CIPHERS = frozenset({
    "aes128-cbc", "aes256-cbc", "3des-cbc", "blowfish-cbc",
    "arcfour", "arcfour128", "arcfour256",
})


def compute_vulnerability_score(
    software_version: str | None = None,
    enc_c2s: list[str] | None = None,
    enc_s2c: list[str] | None = None,
    host_key_type: str | None = None,
    flags: set[str] | None = None,
    is_vm: bool = False,
    has_web_port: bool = False,
    vulnerable_packages: list[dict] | None = None,
) -> float:
    """Compute a 0-1 vulnerability score for targeting priority.

    Higher = more exploitable. Combined with ``(1 - honeypot_confidence)``
    to produce a ``priority_score`` for target selection.

    Parameters
    ----------
    software_version : str or None
        SSH software version string from the banner (e.g., "OpenSSH_7.4p1").
    enc_c2s : list[str] or None
        Client-to-server encryption ciphers from KEXINIT.
    enc_s2c : list[str] or None
        Server-to-client encryption ciphers from KEXINIT.
    host_key_type : str or None
        Host key type from KEXINIT (e.g., "ssh-dss" = DSA = weak).
    flags : set[str] or None
        Signal flags from the fingerprint pipeline (duplicate_host_key,
        banner_reuse, no_banner, immediate_banner).
    is_vm : bool
        Whether the host is a VM (detected via MAC OUI or other signals).
    has_web_port : bool
        Whether port 80/443/8080 is open (more attack surface).
    vulnerable_packages : list[dict] or None
        Packages identified as CVE-prone from loot. Each dict has
        (name, version, manager, cve_prone). Adds +0.02 per CVE-prone
        package (capped at +0.2).
    """
    score = 0.0
    flags = flags or set()

    # Old SSH version (pre-8.0: likely unpatched, multiple CVEs).
    # Handles formats like "8.9p1", "7.4", "OpenSSH_8.9p1 Ubuntu-3".
    if software_version:
        version_str = software_version.lower()
        # Strip "openssh_" prefix if present
        if version_str.startswith("openssh_"):
            version_str = version_str[len("openssh_"):]
        # Strip patch level (e.g., "8.9p1" → "8.9")
        version_str = version_str.split("p")[0].split(" ")[0]
        parts = version_str.split(".")
        try:
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
            if major < 8:
                score += 0.2   # Pre-8.0 — multiple CVEs (user enumeration, etc.)
            elif major == 8 and minor < 9:
                score += 0.1   # 8.0-8.8 — some CVEs
        except (ValueError, IndexError):
            pass

    # Weak ciphers in EITHER direction (CBC mode = exploitable, arcfour = broken).
    # A weak cipher in either direction allows passive decryption or
    # injection — both directions must be strong for the connection to be
    # considered secure.
    all_ciphers = set(enc_c2s or []) | set(enc_s2c or [])
    if all_ciphers:
        weak_count = sum(1 for c in all_ciphers if c in _WEAK_CIPHERS)
        score += min(0.15, weak_count * 0.05)

    # DSA host key (weak, indicates old/insecure config).
    if host_key_type == "ssh-dss":
        score += 0.1

    # Honeypot indicators (REDUCE priority — these are likely traps).
    if "duplicate_host_key" in flags:
        score -= 0.3
    if "banner_reuse" in flags:
        score -= 0.2
    if "no_banner" in flags:
        score -= 0.1   # Stub/firewall, not worth cracking
    if "immediate_banner" in flags:
        score += 0.05  # Fast response = real server

    # VM detection (lower priority for cryptojacking, higher for lateral movement
    # with IMDS access — the loot phase will flag IMDS separately).
    if is_vm:
        score -= 0.1

    # NOTE: Web port bonus (+0.1) is not computed here because service
    # discovery happens in the loot phase, after initial scoring. This will
    # be added when S13 (service discovery) is implemented.
    if has_web_port:
        score += 0.1

    # CVE-prone packages found on the host (each adds +0.02, capped at +0.2).
    if vulnerable_packages:
        score += min(0.2, len(vulnerable_packages) * 0.02)

    return max(0.0, min(1.0, score))


def compute_priority_score(
    final_confidence: float,
    vulnerability_score: float,
) -> float:
    """Combine honeypot confidence and vulnerability into a targeting priority.

    High priority = low honeypot confidence (likely real) + high vulnerability.

    Parameters
    ----------
    final_confidence : float
        Honeypot confidence from the AI scorer (0 = not a honeypot, 1 = definitely
        a honeypot). Lower confidence = more likely a real target.
    vulnerability_score : float
        Vulnerability score from ``compute_vulnerability_score()``. Higher =
        more exploitable.

    Returns
    -------
    float
        Priority score in [0, 1]. Higher = more valuable target.
    """
    return (1.0 - final_confidence) * 0.5 + vulnerability_score * 0.5