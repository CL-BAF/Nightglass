"""Red-team operations orchestration for honeywatch.

Turns scored scan results into verified target sets, builds payload deployment
manifests, applies evasion pipelines, and enqueues operations on the C2
controller.
"""

from __future__ import annotations

from honeywatch.ops.deploy import (
    build_manifest,
    enqueue_operation,
    prepare_evasion_pipeline,
)
from honeywatch.ops.targeting import TargetFilter, select_targets

__all__ = [
    "TargetFilter",
    "build_manifest",
    "enqueue_operation",
    "prepare_evasion_pipeline",
    "select_targets",
]
