"""Rule-based heuristic scoring of an SSH fingerprint.

The ``analyze`` function turns a ``Fingerprint`` into a ``Signals`` object:
machine-readable ``flags``, human-readable ``anomalies``, an evidence dict, and
a heuristic honeypot-confidence score in ``[0.0, 0.95]``. Higher scores mean
the host looks more like a honeypot.
"""

from __future__ import annotations

import re

from ..models import Fingerprint, Signals

LEGACY_CIPHERS = frozenset({
    "3des-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
    "blowfish-cbc",
    "cast128-cbc",
})
LEGACY_MACS = frozenset({
    "hmac-md5",
    "hmac-md5-96",
    "hmac-sha1-96",
    "hmac-sha1",
})
WEAK_HOST_KEYS = frozenset({"ssh-dss"})
CHACHA = "chacha20-poly1305@openssh.com"
CURVE = "curve25519-sha256"
CURVE_OPENSSH = "curve25519-sha256@libssh.org"

# Host-key algorithms a genuine OpenSSH server may present.
OPENSSH_HOST_KEY_TYPES = frozenset({
    "ssh-rsa",
    "rsa-sha2-256",
    "rsa-sha2-512",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
})

_SCORE_CAP = 0.95
_VERSION_RE = re.compile(r"(\d+(?:\.\d+)*)")

# Top-level flag -> human-readable label for reports.
SIGNAL_NAMES = {
    "fp.unreachable": "Host did not respond with an SSH banner",
    "fp.error": "Probe failed with an error",
    "crypto.legacy_cipher": "Server offered a legacy weak cipher",
    "crypto.legacy_mac": "Server offered a legacy weak MAC",
    "crypto.no_chacha": "OpenSSH server missing chacha20-poly1305",
    "crypto.kex_skew": "OpenSSH server missing curve25519 key exchange",
    "hostkey.mismatch": "Host key type inconsistent with the software claim",
    "hostkey.weak": "Host offered a weak host-key algorithm",
    "proto.bad_banner": "Banner does not match SSH-2.0-<software> pattern",
    "banner.no_version": "Banner names software without a version",
    "farm.hostkey_reuse": "Host key matches a known host-key set",
    "timing.instant_banner": "Banner returned suspiciously fast",
    "auth.accepted_wrong_password": "Server accepted a deliberately wrong password",
}


def _version_float(version: str | None) -> float | None:
    """Extract the leading numeric version from ``"8.9p1"`` -> ``8.9``."""
    if not version:
        return None
    m = _VERSION_RE.match(version)
    if not m:
        return None
    try:
        return float(m.group(1))
    except ValueError:
        return None


def _fill_evidence(fp: Fingerprint, evidence: dict[str, str]) -> None:
    evidence["banner"] = fp.banner or ""
    evidence["software"] = fp.software or ""
    evidence["version"] = fp.software_version or ""
    evidence["protocol"] = fp.protocol or ""
    evidence["kex_count"] = str(len(fp.kex_algorithms))
    evidence["enc_c2s"] = ",".join(fp.enc_c2s[:6])
    evidence["enc_s2c"] = ",".join(fp.enc_s2c[:6])
    evidence["mac_c2s"] = ",".join(fp.mac_c2s[:4])
    evidence["comp"] = ",".join(fp.comp_c2s[:4])
    evidence["host_key_type"] = fp.host_key_type or ""
    evidence["host_key_sha256"] = (fp.host_key_sha256 or "")[:16]
    evidence["connect_ms"] = f"{fp.connect_ms:.1f}" if fp.connect_ms is not None else ""
    evidence["banner_ms"] = f"{fp.banner_ms:.1f}" if fp.banner_ms is not None else ""
    evidence["time_to_banner_ms"] = (
        f"{fp.time_to_banner_ms:.1f}" if fp.time_to_banner_ms is not None else ""
    )
    evidence["error"] = fp.error or ""
    for key, value in (getattr(fp, "evidence", None) or {}).items():
        if isinstance(value, (str, int, float, bool)):
            evidence[f"auth.{key}"] = str(value)


def analyze(
    fp: Fingerprint | None,
    known_hashes: set[str] = frozenset(),
) -> Signals:
    """Score a fingerprint against the honeywatch heuristics.

    Returns a ``Signals`` object with machine flags, human anomalies, an
    evidence dict (all string values), and a capped heuristic score.
    """
    flags: list[str] = []
    anomalies: list[str] = []
    score = 0.0
    evidence: dict[str, str] = {}

    if fp is None:
        flags.append("fp.unreachable")
        anomalies.append("host produced no fingerprint data")
        score += 0.35
        return Signals(
            anomalies=anomalies,
            flags=flags,
            heuristic_score=min(score, _SCORE_CAP),
            evidence=evidence,
        )

    _fill_evidence(fp, evidence)

    if fp.error:
        flags.append("fp.error")
        anomalies.append(f"probe error: {fp.error}")
        score += 0.35
    elif not fp.banner:
        flags.append("fp.unreachable")
        anomalies.append("host sent no SSH banner")
        score += 0.35

    if fp.banner:
        if fp.protocol not in {"2.0", "1.99"} or not fp.software:
            flags.append("proto.bad_banner")
            anomalies.append(f"malformed SSH banner: {fp.banner!r}")
            score += 0.15

    ciphers = set(fp.enc_c2s) | set(fp.enc_s2c)
    if ciphers & LEGACY_CIPHERS:
        flags.append("crypto.legacy_cipher")
        anomalies.append("server offered a legacy weak cipher")
        score += 0.30

    macs = set(fp.mac_c2s) | set(fp.mac_s2c)
    if macs & LEGACY_MACS:
        flags.append("crypto.legacy_mac")
        anomalies.append("server offered a legacy weak MAC")
        score += 0.25

    version = _version_float(fp.software_version) if fp.software == "OpenSSH" else None

    if version is not None and version >= 6.5 and CHACHA not in set(fp.enc_c2s):
        flags.append("crypto.no_chacha")
        anomalies.append("OpenSSH server does not offer chacha20-poly1305")
        score += 0.20

    if (
        fp.software == "OpenSSH"
        and fp.host_key_type
        and fp.host_key_type not in OPENSSH_HOST_KEY_TYPES
    ):
        flags.append("hostkey.mismatch")
        anomalies.append(f"OpenSSH host-key type {fp.host_key_type!r} is unexpected")
        score += 0.20

    if fp.host_key_type in WEAK_HOST_KEYS:
        flags.append("hostkey.weak")
        anomalies.append(f"weak host-key algorithm offered: {fp.host_key_type}")
        score += 0.15

    if version is not None and version >= 7.0:
        kex_set = set(fp.kex_algorithms)
        if CURVE not in kex_set and CURVE_OPENSSH not in kex_set:
            flags.append("crypto.kex_skew")
            anomalies.append("OpenSSH server lacks curve25519 key exchange")
            score += 0.15

    if fp.software and not fp.software_version:
        flags.append("banner.no_version")
        anomalies.append("banner names software without a version")
        score += 0.10

    if fp.host_key_sha256 and fp.host_key_sha256 in known_hashes:
        flags.append("farm.hostkey_reuse")
        anomalies.append("host-key fingerprint matches a known host-key set")
        score += 0.20

    if fp.time_to_banner_ms is not None and fp.time_to_banner_ms < 5.0:
        flags.append("timing.instant_banner")
        anomalies.append(f"banner received in {fp.time_to_banner_ms:.1f} ms")
        score += 0.10

    if (fp.evidence or {}).get("auth_password_accepted") is True:
        flags.append("auth.accepted_wrong_password")
        anomalies.append("server accepted a deliberately wrong password")
        score += 0.15

    return Signals(
        anomalies=anomalies,
        flags=flags,
        heuristic_score=min(score, _SCORE_CAP),
        evidence=evidence,
    )
