"""Artifact integrity verification for honeywatch payload deployments.

Payload install scripts fetch binaries over the network (xmrig, xmrigcc, upx,
metasploit installer) and execute them. Without a checksum that is a
blind ``curl | tar | exec`` — a trojaned release or a network MITM ships
arbitrary code onto the target as root.

This module provides the verification *mechanism*:

- :func:`load_integrity` reads an optional TOML manifest mapping a payload id
  (or an ``artifact`` name) to an expected ``sha256``.
- :func:`expected_for` looks up the expected hash for a payload.
- The install-script templates consult an ``{{expected_sha256}}`` variable;
  when it is set they run ``sha256sum -c`` against the downloaded tarball and
  abort on mismatch. When it is empty they print a loud "UNVERIFIED" warning.
- :func:`verify_file` is the Python-side helper for programmatic downloads.

The manifest is *opt-in*: ship a ``payloads/integrity.toml`` next to your
config (or point ``payloads.integrity_file`` at it) and pin the releases you
trust. With ``payloads.require_integrity = true`` (or ``--require-integrity``)
a deployment whose payload has no known hash is refused outright — closing
the blind-download gap without guessing hashes we cannot vouch for.

Example ``payloads/integrity.toml``::

    # sha256 of the pinned xmrig v6.22.0 linux-x64 release tarball
    xmrig = "abcd...0123"
    upx   = "ef56...789"
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

__all__ = [
    "KNOWN_HASHES",
    "expected_for",
    "load_integrity",
    "verify_bytes",
    "verify_file",
]

# Bundled defaults — intentionally empty. Operators populate a manifest
# (``payloads/integrity.toml``) with the real sha256s of the pinned releases
# they trust. Keeping this empty means we never silently *claim* a hash we
# have not verified against the real artifact.
KNOWN_HASHES: dict[str, str] = {}


def load_integrity(path: str | None) -> dict[str, str]:
    """Load an optional ``{payload_id_or_artifact: sha256}`` manifest.

    Returns an empty dict when ``path`` is ``None`` or unreadable so callers
    can treat a missing manifest as "no hashes known" rather than an error.
    """
    if not path:
        return {}
    try:
        import tomllib

        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except (FileNotFoundError, OSError, ImportError, Exception):
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, str] = {}
    # Accept either a flat ``{id: sha}`` table or a ``[integrity]`` sub-table.
    table: Any = data.get("integrity", data) if isinstance(data, dict) else {}
    if not isinstance(table, dict):
        return {}
    for key, value in table.items():
        if isinstance(key, str) and isinstance(value, str) and value:
            out[key] = value.strip().lower()
    return out


def expected_for(payload_id: str, manifest: dict[str, str] | None = None) -> str:
    """Return the expected sha256 for ``payload_id`` (or its artifact name)."""
    manifest = manifest if manifest is not None else KNOWN_HASHES
    return (manifest.get(payload_id) or "").strip().lower()


def verify_bytes(data: bytes, expected_sha256: str) -> bool:
    """True when ``sha256(data)`` equals ``expected_sha256``."""
    if not expected_sha256:
        return False
    return hashlib.sha256(data).hexdigest() == expected_sha256.lower().strip()


def verify_file(path: str, expected_sha256: str) -> bool:
    """True when the file at ``path`` hashes to ``expected_sha256``."""
    if not expected_sha256 or not os.path.isfile(path):
        return False
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest() == expected_sha256.lower().strip()


# Shared shell fragment injected into every network-fetching install script.
# ``{{expected_sha256}}`` is rendered by the template engine; an empty value
# means "no hash pinned" -> loud warning, never a silent pass.
INTEGRITY_VERIFY_SNIPPET = """
# --- honeywatch integrity check ---
EXPECTED_SHA256="{{expected_sha256}}"
if [ -n "$EXPECTED_SHA256" ]; then
    echo "$EXPECTED_SHA256  {{integrity_file}}" | sha256sum -c - || {
        echo "[!] honeywatch: INTEGRITY FAILURE for {{integrity_file}} (expected $EXPECTED_SHA256)" >&2
        rm -f "{{integrity_file}}"
        exit 1
    }
    echo "[*] honeywatch: {{integrity_file}} integrity verified"
else
    echo "[!] honeywatch: {{integrity_file}} downloaded WITHOUT integrity verification." >&2
    echo "[!] honeywatch: pin a sha256 via the payloads integrity manifest or --var expected_sha256=... ; use --require-integrity to make this fatal." >&2
fi
"""