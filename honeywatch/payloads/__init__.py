"""Red-team payload registry and script builders for honeywatch.

This package defines deployable payload categories (miners, exploit
frameworks, evasion tooling) and helpers for rendering per-host install/run
scripts. No bundled malware is shipped; workers fetch or build artifacts on
the target according to the generated manifest.
"""

from __future__ import annotations

from honeywatch.models import Payload
from honeywatch.payloads.registry import (
    PAYLOAD_CATEGORIES,
    PAYLOAD_IDS,
    by_category,
    get_payload,
    list_payloads,
    registry,
)
from honeywatch.payloads.scripts import render_manifest_scripts

__all__ = [
    "Payload",
    "PAYLOAD_CATEGORIES",
    "PAYLOAD_IDS",
    "by_category",
    "get_payload",
    "list_payloads",
    "registry",
    "render_manifest_scripts",
]
