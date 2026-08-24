# API — Payloads

`honeywatch/payloads/`.

## `payloads/__init__.py`

```python
from honeywatch.payloads import registry, PAYLOAD_IDS, PAYLOAD_CATEGORIES, get_payload, list_payloads, by_category, render_manifest_scripts

registry: dict[str, Payload]           # PAYLOAD_IDS tuple, PAYLOAD_CATEGORIES tuple
get_payload(id: str) -> Payload        # KeyError if unknown
list_payloads(category=None) -> list[Payload]
by_category() -> dict[str, list[Payload]]
render_manifest_scripts(manifest)      # from payloads/scripts.py:100
```

## `payloads/registry.py`

`honeywatch/payloads/registry.py:616`.

- `_PREAMBLE: str` — `set -e`, `LOG`, `tee`
- `_XMRIG_INSTALL`, `_XMRIG_RUN`, `_XMRIGCC_INSTALL/RUN`, `_STRATUM_INSTALL/RUN`, `_METASPLOIT_INSTALL/RUN`, `_UPX_INSTALL/RUN`, `_PACKERS_INSTALL/RUN`, `_OBFUSCATORS_INSTALL/RUN`, `_SYMBOL_STRIP_INSTALL/RUN`, `_ANTI_DEBUG_INSTALL/RUN`, `_ANTI_VM_INSTALL/RUN`
- `_payloads() -> list[Payload]` — 10 payloads
- `registry`, `PAYLOAD_IDS`, `PAYLOAD_CATEGORIES` — built at import

10 payloads: `xmrig`/`xmrigcc`/`stratum` (miner), `metasploit` (exploit), `upx`/`packers`/`obfuscators`/`symbol_strip`/`anti_debug`/`anti_vm` (evasion).

## `payloads/scripts.py`

`honeywatch/payloads/scripts.py:100`.

| Symbol | Detail |
|---|---|
| `_TOKEN_RE` | `\{\{\s*([a-zA-Z_]\w*)\s*(?:\|\s*default\(...\))?\s*\}\}` |
| `_render_template(tmpl, vars, strict)` | `-> str` |
| `_inject_ids(script, payload_id, target)` | `op_id` hex 12 + payload/target injection |
| `render_payload_script(payload, vars, target)` | inject + render + append `run_script` |
| `validate_variables(payload, vars)` | `-> list[str]` missing required |
| `merge_defaults(payload, vars)` | `-> dict` fill defaults |
| `render_manifest_scripts(manifest)` | `-> dict[str,str]` per-ip |
| `generate_operation_id() -> str` | `"hw-" + random 10 hex` |

See [Payloads](../payloads.md) for full payload table and evasion chaining.
