# API — Models

`honeywatch/models.py:160` — shared dataclass contracts between scanner, fingerprint, AI, and reporting layers. Field names, types, and defaults are stable API.

## `SSH_PORT`

```python
from honeywatch.models import SSH_PORT
SSH_PORT  # 22
```

## `HostHit`

Discovery hit from a scanner (`models.py:18`):

```python
@dataclass
class HostHit:
    ip: str
    port: int = 22
    banner: str | None = None
    scanner: str | None = None
    timestamp: float = 0.0
```

Produced by `scanners/masscan.py:126` `run` and `scanners/zmap.py:83` `run` as `HostHit(ip, port, scanner="masscan"|"zmap")`.

## `Fingerprint`

RFC 4253 probe result (`models.py:28`, `fingerprint/probe.py:343`):

```python
@dataclass
class Fingerprint:
    ip: str
    port: int = 22
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
    host_key_type: str | None = None        # full only (paramiko)
    host_key_sha256: str | None = None      # full only
    connect_ms: float | None = None
    banner_ms: float | None = None
    time_to_banner_ms: float | None = None
    error: str | None = None
    evidence: dict[str, str] = field(default_factory=dict)
```

- `ip`/`port` — target.
- `banner`/`protocol`/`software`/`software_version` — from `parse_banner`.
- `kex_algorithms` etc. — from `parse_kexinit`.
- `host_key_type`/`sha256` — `full` level via paramiko.
- `connect_ms`/`banner_ms`/`time_to_banner_ms` — timing for `instant_banner` signal.
- `error` — per-host failure, never raises.
- `evidence` — 13 fields + `auth.*` for AI prompts.

## `Signals`

Heuristic output (`models.py:53`, `fingerprint/features.py:209`):

```python
@dataclass
class Signals:
    anomalies: list[str] = field(default_factory=list)   # human-readable per signal
    flags: list[str] = field(default_factory=list)        # machine flags, stored in SQLite
    heuristic_score: float = 0.0                          # [0.0, 0.95]
    evidence: dict[str, str] = field(default_factory=dict)
```

## `AiVerdict`

LLM verdict (`models.py:61`, `ai/scorer.py:354`):

```python
@dataclass
class AiVerdict:
    classification: str = "uncertain"   # real | likely_real | uncertain | likely_honeypot | honeypot
    confidence: float = 0.0             # 0.0–1.0
    reasons: list[str] = field(default_factory=list)
    model: str = ""
    raw: str = ""
```

Malformed LLM output → `uncertain` `0.0` with `reasons=["parse_failed"]`.

## `Score`

Fused result (`models.py:70`):

```python
@dataclass
class Score:
    ip: str
    port: int
    fingerprint: Fingerprint | None = None
    signals: Signals = field(default_factory=Signals)
    ai: AiVerdict | None = None
    final_confidence: float = 0.0
    final_label: str = "uncertain"
```

- `final_confidence = ai*0.6 + heuristic*0.4` (or heuristic alone).
- `final_label = _classify(final_confidence)` (`pipeline.py:352`): `<0.2 real`, `<0.4 likely_real`, `<0.6 uncertain`, `<0.8 likely_honeypot`, else `honeypot`.

## Red-Team Models

### `Payload` (`models.py:86`)

```python
@dataclass
class Payload:
    id: str
    category: str  # miner | exploit | evasion
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
```

### `Target` (`models.py:108`)

```python
@dataclass
class Target:
    ip: str
    port: int
    label: str = ""
    confidence: float = 0.0
    profile_key: str = ""
    allowed_categories: list[str] = field(default_factory=list)
    ssh_user: str | None = None
    ssh_key: str | None = None
    ssh_pass: str | None = None
```

### `DeploymentManifest` (`models.py:123`)

```python
@dataclass
class DeploymentManifest:
    payload: Payload
    targets: list[Target]
    variables: dict[str, Any] = field(default_factory=dict)
    per_host_scripts: dict[str, str] = field(default_factory=dict)
```

### `Operation` (`models.py:133`)

```python
@dataclass
class Operation:
    id: str
    payload_id: str
    target_ips: list[str] = field(default_factory=list)
    status: str = "pending"  # pending | running | completed | failed | cancelled
    manifest: dict[str, Any] = field(default_factory=dict)
    result_log: list[dict[str, Any]] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
```

### `WorkerTask` (`models.py:147`)

```python
@dataclass
class WorkerTask:
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
```

## Source

Full file at `honeywatch/models.py:160`.
