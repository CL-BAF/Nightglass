# Configuration

honeywatch resolves configuration in three layers, highest wins:

1. **Built-in defaults** — `honeywatch/config.py:32` `default_config()`
2. **TOML file** — `--config PATH` → `$HONEYWATCH_CONFIG` → `./config.toml` if it exists (`honeywatch/config.py:220` `_resolve_config_path`)
3. **Environment overrides** — `HONEYWATCH_MODEL`, `HONEYWATCH_AI_BASE`, `OLLAMA_API_KEY` (via `ai.api_key_env`) (`honeywatch/config.py:257`)

Missing keys are never an error — partial TOML files only override what they mention (`_deep_merge`, `honeywatch/config.py:199`). `Config` exposes dot access: `cfg.scanners.masscan.rate` (`honeywatch/config.py:131`).

## Writing a Config

```bash
honeywatch config --write config.toml   # write_example() → honeywatch/config.py:377
honeywatch config                        # print default TOML to stdout
honeywatch config --write /path/to/config.toml
```

The emitted file mirrors `default_config()` exactly, so copying it to `./config.toml` and deleting keys you want defaulted is a no-op. A reference is also checked in as `config.example.toml`.

## Full Reference

### `[scanners.masscan]`

| Key | Default | Meaning |
|---|---|---|
| `bin` | `"masscan"` | masscan executable path/name |
| `rate` | `1000` | packets/sec — conservative default, raise only with authorization |
| `timeout_s` | `null` | subprocess bound in seconds; `null` = no timeout (planet-scale sweeps); set e.g. `600` to guard hung scans |
| `exclude` | `[]` | CIDRs skipped via `--exclude` (e.g. `["10.0.0.0/8", "192.168.0.0/16"]` + your egress IP on `0.0.0.0/0`) |

Passed through to `honeywatch/scanners/masscan.py:1` `run(targets, ports, rate, timeout_s, bin_path, excludes)`. The CLI `--rate` flag overrides `rate` per-run.

### `[scanners.zmap]`

| Key | Default | Meaning |
|---|---|---|
| `bin` | `"zmap"` | zmap executable path/name |
| `timeout_s` | `null` | per-port subprocess bound |

Wraps `zmap -q -p PORT --rate RATE -o - targets` per port (`honeywatch/scanners/zmap.py:1`).

### `[scanners.nmap]`

| Key | Default | Meaning |
|---|---|---|
| `bin` | `"nmap"` | nmap executable path/name (optional) |

Used by `honeywatch/scanners/nmap_probe.py:1` `probe(ip, port, timeout_s)` → `nmap -Pn -sV --version-light -oX -` + XML parse. Never raises — returns `{error}` on failure. Timeout is `max(timeout*2+30, 60)`.

### `[scan]`

| Key | Default | Meaning |
|---|---|---|
| `only_ssh` | `true` | drop non-SSH hosts after probing. `false` (or `--all-hosts`) keeps unreachable/refused/non-SSH banners for debug (`honeywatch/pipeline.py:352` `only_ssh`) |

### `[probe]`

| Key | Default | Meaning |
|---|---|---|
| `concurrency` | `512` | max simultaneous async probes (`asyncio.Semaphore`, `honeywatch/pipeline.py:509` / `honeywatch/fingerprint/probe.py:343` `probe_many`) |
| `timeout_s` | `6.0` | per-connection timeout in seconds |
| `level` | `"fast"` | `"fast"` = banner + KEXINIT + timing; `"full"` = above + host-key type & SHA-256 (requires `paramiko`, else falls back) |
| `auth_probe` | `false` | opt-in single bogus `auth_password` attempt; logs only the rejection reply, sends no credential |
| `progress` | `false` | print a live heartbeat every 1000 probes during long scans (`--progress`) |

CLI flags `--concurrency`, `--timeout`, `--probe-level`, `--auth-probe`, `--progress` fold into this section via `_apply_scan_options` (`honeywatch/cli.py:805`).

### `[ai]`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | run the LLM verdict stage at all |
| `model` | `"llama3.1:8b"` | model tag on Ollama Cloud |
| `base_url` | `"https://ollama.com/v1"` | Ollama Cloud OpenAI-compatible endpoint (no local fallback) |
| `api_key_env` | `"OLLAMA_API_KEY"` | env var holding the key — **REQUIRED** for AI |
| `batch_profiles` | `true` | one prompt per identical profile (planet-scale optimization) |
| `batch_size` | `100` | max profiles per LLM call (keeps prompt in-context) |
| `temperature` | `0.0` | sampling temperature; `0.0` = deterministic |
| `timeout_s` | `120` | LLM request timeout |
| `retries` | `3` | transient-failure retries with exponential backoff |
| `retry_base_delay` | `1.0` | seconds; `backoff = retry_base_delay * 2**attempt` |

Resolution: constructor arg → `$HONEYWATCH_AI_BASE` / `$HONEYWATCH_MODEL` → `api_key_env` env var → defaults (`honeywatch/ai/ollama.py:1`). CLI `--model` / `--no-ai` override `model` / `enabled` per-run. See [AI Integration](ai-integration.md).

### `[storage]`

| Key | Default | Meaning |
|---|---|---|
| `db` | `"honeywatch.db"` | SQLite database path |
| `reports_dir` | `"reports"` | reports output directory |

CLI `--db` / `--out-dir` override per-run. The DB runs in WAL + `synchronous=NORMAL` + `temp_store=MEMORY` with 5 indexes (`honeywatch/store.py:383`). See [Storage](storage.md).

### `[vpn]`

| Key | Default | Meaning |
|---|---|---|
| `required` | `true` | refuse to start `scan`/`probe` unless Mullvad is on |
| `provider` | `"mullvad"` | tunnel provider required (currently only `mullvad`) |
| `timeout_s` | `8.0` | Mullvad connectivity-check timeout |

Checked via `https://am.i.mullvad.net/json` (`mullvad_exit_ip`) + `/connected` fallback + tunnel interface glob (`mullvad`, `wg-mullvad`, `wg0`) (`honeywatch/vpn.py:169`). Bypass: `--skip-vpn-check` or `HONEYWATCH_SKIP_VPN=1` or `vpn.required=false`. See [VPN Gate](vpn.md).

### `[payloads]`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | enable red-team payload registry |
| `allowed_categories` | `["miner","exploit","evasion"]` | categories deployable via CLI |
| `default_evasion` | `["upx","symbol_strip"]` | evasion payloads chained by default when `--evasion` omitted |
| `exec_mode` | `"dry_run"` | default task execution mode (`dry_run` / `local_simulate` / `ssh`) |

See [Payloads](payloads.md).

### `[c2]`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | start C2 controller on demand (not auto-started) |
| `host` | `"0.0.0.0"` | controller bind host |
| `port` | `8443` | controller bind port |
| `tls_cert` | `null` | TLS certificate path |
| `tls_key` | `null` | TLS private key path |
| `api_token` | `null` | shared bearer secret; when set, every API + WS request must carry `Authorization: Bearer <token>` or `?token=` |
| `db` | `null` | C2 SQLite path; defaults to `storage.db` |

See [C2 Controller](c2.md).

### `[workers]`

| Key | Default | Meaning |
|---|---|---|
| `controller_url` | `"http://127.0.0.1:8443"` | worker controller endpoint |
| `categories` | `["miner","exploit","evasion"]` | categories this worker accepts |
| `poll_interval` | `5.0` | seconds between task polls |
| `exec_mode` | `"dry_run"` | how the worker runs task scripts |
| `ssh_user` | `"root"` | SSH user for `ssh` exec mode |
| `ssh_key` | `null` | SSH private key path |

See [C2 Controller — Worker](c2.md#worker).

## Environment Variables

| Variable | Effect |
|---|---|
| `HONEYWATCH_CONFIG` | path to TOML file (tried after `--config`) |
| `OLLAMA_API_KEY` | API key (env name itself is configurable via `ai.api_key_env`) |
| `HONEYWATCH_MODEL` | overrides `ai.model` |
| `HONEYWATCH_AI_BASE` | overrides `ai.base_url` |
| `HONEYWATCH_SKIP_VPN` | `1`/`true`/`yes` bypasses Mullvad gate |

`.env.example` documents the same set for dotenv users.

## Example `config.toml`

Annotated reference is `config.example.toml` (132 lines). Minimal override example:

```toml
[probe]
concurrency = 256
timeout_s = 10.0
level = "full"

[ai]
model = "gpt-oss:20b"
batch_size = 50

[storage]
db = "/data/honeywatch.db"
reports_dir = "/data/reports"

[vpn]
required = false   # lab only

[workers]
controller_url = "https://c2.example.com:8443"
exec_mode = "ssh"
ssh_user = "admin"
ssh_key = "/home/admin/.ssh/id_rsa"
```

## Config Object API

```python
from honeywatch.config import Config, default_config, load_config, write_example

cfg = load_config()                    # auto-discovers TOML + env
cfg = load_config("my.toml")           # explicit path
cfg.scanners.masscan.rate              # 1000
cfg["probe"]["timeout_s"]              # 6.0
cfg.get("vpn")                         # Config or None
cfg.to_dict()                          # plain nested dict
cfg == {"probe": {"concurrency": 512}} # equality vs dict works

write_example("config.toml")           # write fully-populated example
default_config()                       # fresh dict, safe to mutate
```

`Config` is at `honeywatch/config.py:131` — every nested dict becomes a `Config`, so dot and dict access are interchangeable.
