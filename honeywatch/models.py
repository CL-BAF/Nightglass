"""Shared data models for honeywatch.

These dataclasses form the contract between the scanner, fingerprint, AI
scoring and reporting layers of the package. Field names, types and defaults
are stable API: other modules import them by these exact names, so do not
rename fields or change defaults here without updating every consumer.

There are no extra required fields beyond what is declared below.
"""

from __future__ import annotations
from dataclasses import asdict, dataclass, field
from typing import Any

SSH_PORT = 22


@dataclass
class HostHit:
    ip: str
    port: int = SSH_PORT
    banner: str | None = None
    scanner: str | None = None
    timestamp: float = 0.0


@dataclass
class Fingerprint:
    ip: str
    port: int = SSH_PORT
    banner: str | None = None
    protocol: str | None = None
    software: str | None = None
    software_version: str | None = None
    kex_algorithms: list[str] = field(default_factory=list)
    server_host_key_algorithms: list[str] = field(default_factory=list)
    enc_c2s: list[str] = field(default_factory=list)
    enc_s2c: list[str] = field(default_factory=list)
    mac_c2s: list[str] = field(default_factory=list)
    mac_s2c: list[str] = field(default_factory=list)
    comp_c2s: list[str] = field(default_factory=list)
    comp_s2c: list[str] = field(default_factory=list)
    host_key_type: str | None = None
    host_key_sha256: str | None = None
    connect_ms: float | None = None
    banner_ms: float | None = None
    time_to_banner_ms: float | None = None
    error: str | None = None
    evidence: dict[str, str] = field(default_factory=dict)


@dataclass
class Signals:
    anomalies: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    heuristic_score: float = 0.0
    evidence: dict[str, str] = field(default_factory=dict)


@dataclass
class AiVerdict:
    classification: str = "uncertain"
    confidence: float = 0.0
    reasons: list[str] = field(default_factory=list)
    model: str = ""
    raw: str = ""


@dataclass
class Score:
    ip: str
    port: int
    fingerprint: Fingerprint | None = None
    signals: Signals = field(default_factory=Signals)
    ai: AiVerdict | None = None
    final_confidence: float = 0.0
    final_label: str = "uncertain"


def score_record(score: Score) -> dict:
    """Plain-dict representation of a :class:`Score`, safe for ``json.dumps``.

    Single canonical serializer shared by the store (the ``hosts.json`` blob
    column) and the report writers, so the persisted and exported shapes cannot
    drift apart the way two copied implementations inevitably do. ``Signals``
    is normalized to plain lists/dicts so the result round-trips through
    ``json.loads`` without dataclass awareness.
    """
    sig = score.signals
    return {
        "ip": score.ip,
        "port": score.port,
        "final_label": score.final_label,
        "final_confidence": score.final_confidence,
        "fingerprint": asdict(score.fingerprint) if score.fingerprint else None,
        "signals": {
            "anomalies": list(sig.anomalies) if sig else [],
            "flags": list(sig.flags) if sig else [],
            "heuristic_score": sig.heuristic_score if sig else 0.0,
            "evidence": dict(sig.evidence) if sig else {},
        },
        "ai": asdict(score.ai) if score.ai else None,
    }


# --------------------------------------------------------------------------- #
# Red-team payload / C2 / ops models
# --------------------------------------------------------------------------- #


@dataclass
class Payload:
    """A deployable red-team payload definition.

    Payloads are metadata + install/run script templates. They are not bundled
    binaries; the tool generates deployment manifests and the workers fetch or
    build the required artifacts on the target host.
    """

    id: str
    category: str  # miner, exploit, evasion
    name: str
    description: str
    platforms: list[str] = field(default_factory=list)
    install_type: str = "script"  # script | binary | package | source | msf_module
    dependencies: list[str] = field(default_factory=list)
    config_schema: dict[str, Any] = field(default_factory=dict)
    install_script: str = ""
    run_script: str | None = None
    artifacts: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class Target:
    """A verified host selected for a red-team operation."""

    ip: str
    port: int
    label: str = ""
    confidence: float = 0.0
    profile_key: str = ""
    allowed_categories: list[str] = field(default_factory=list)
    ssh_user: str | None = None
    ssh_key: str | None = None  # path to private key
    ssh_pass: str | None = None


@dataclass
class DeploymentManifest:
    """Concrete plan produced by the ops layer for a payload + targets."""

    payload: Payload
    targets: list[Target]
    variables: dict[str, Any] = field(default_factory=dict)
    per_host_scripts: dict[str, str] = field(default_factory=dict)
    # Evasion payload ids chained onto the install flow (upx, symbol_strip,
    # anti_vm, anti_debug, ...). Recorded so the operation manifest carries a
    # full audit trail of what was applied to each deployment.
    evasion: list[str] = field(default_factory=list)


@dataclass
class Operation:
    """Persisted red-team operation record."""

    id: str
    payload_id: str
    target_ips: list[str] = field(default_factory=list)
    status: str = "pending"  # pending | running | completed | failed | cancelled
    manifest: dict[str, Any] = field(default_factory=dict)
    result_log: list[dict[str, Any]] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""


@dataclass
class WorkerTask:
    """Task handed from controller to a worker."""

    id: str
    operation_id: str
    payload_id: str
    category: str
    target: Target | None = None
    script: str = ""
    variables: dict[str, Any] = field(default_factory=dict)
    status: str = "pending"
    worker_id: str | None = None
    result: dict[str, Any] | None = None
