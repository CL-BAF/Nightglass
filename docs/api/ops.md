# API — Ops

`honeywatch/ops/` — re-exports at `ops/__init__.py:23`.

```python
from honeywatch.ops import TargetFilter, select_targets, build_manifest, enqueue_operation, prepare_evasion_pipeline
from honeywatch.ops.deploy import dispatch_to_controller
```

## `ops/targeting.py`

`honeywatch/ops/targeting.py:76`.

```python
@dataclass
class TargetFilter:
    labels: set[str]|None = None
    min_confidence: float = 0.0
    max_confidence: float = 1.0
    require_flags: set[str]|None = None
    exclude_flags: set[str]|None = None
    allowed_categories: list[str]|None = None
    limit: int|None = None

    def match(self, score: Score) -> bool: ...
```

```python
def select_targets(store: Store, filter_: TargetFilter, ssh_user=None, ssh_key=None) -> list[Target]: ...
# queries store.query_scores(limit or 1000, min_confidence), _score_to_target, local filters, caps limit
```

Internal `_score_to_target(score, allowed_categories) -> Target`.

## `ops/deploy.py`

`honeywatch/ops/deploy.py:192`.

| Symbol | Detail |
|---|---|
| `build_manifest(payload_id, targets, variables, apply_evasion) -> DeploymentManifest` | validates `get_payload`, `validate_variables` ValueError, `merge_defaults`, `render_manifest_scripts`, optional `_wrap_with_evasion` |
| `_wrap_with_evasion(payload, scripts, evasion_ids)` | anti_vm first, payload, upx/packers/symbol_strip targeting `"/opt/honeywatch/{id}/{artifact0}"`, anti_debug last |
| `_render_evasion_for_payload(ev, payload)` | sub `input_file/output_file/install_dir` |
| `prepare_evasion_pipeline(evasion_spec) -> list[str]` | split CSV or list, filter `_is_evasion_payload` |
| `enqueue_operation(c2_store, manifest, operation_id) -> Operation` | `generate_operation_id` if needed, `create_operation` + per-target `create_task` + status `running` |
| `dispatch_to_controller(controller_url, manifest, operation_id) -> dict` | POST `/api/operations` via `urllib`, 60 s timeout |

See [Ops & Targeting](../ops.md) and [Payloads](../payloads.md).
