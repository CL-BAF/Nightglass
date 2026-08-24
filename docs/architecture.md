# Architecture

## Module Map

```
honeywatch/
├── __init__.py            # __version__ = "0.1.0"
├── __main__.py            # python -m honeywatch → cli.main
├── models.py              # dataclass contracts (HostHit, Fingerprint, Signals, AiVerdict, Score, Payload, Target, ...)
├── config.py              # defaults → TOML → env; Config dot-access wrapper
├── pipeline.py            # Pipeline: scan → probe_hosts → analyze_and_score → store
├── store.py               # SQLite honeywatch.db (WAL, 5 indexes, known_keys)
├── report.py              # write_json / write_csv / write_md
├── vpn.py                 # Mullvad gate
├── cli.py                 # argparse with 10 subcommands, lazy imports
├── cli_chat.py            # TerminalUI, ANSI panels/tables, slash commands
├── fingerprint/
│   ├── __init__.py        # re-exports analyze, probe_ssh, probe_many, ...
│   ├── probe.py           # asyncio SSH fingerprinting, RFC4253 KEXINIT
│   └── features.py        # heuristic Signals engine (11 signals, capped 0.95)
├── ai/
│   ├── __init__.py
│   ├── ollama.py          # OllamaClient (urllib, OpenAI-compatible)
│   ├── prompts.py         # SYSTEM_PROMPT, OUTPUT_JSON, user_prompt_for
│   └── scorer.py          # AiScorer, profile_key, batching, retries
├── scanners/
│   ├── __init__.py        # ScannerError
│   ├── masscan.py         # masscan wrapper (JSON temp file)
│   ├── zmap.py            # zmap wrapper (per-port stdout)
│   └── nmap_probe.py      # nmap -oX wrapper (XML, never raises)
├── payloads/
│   ├── __init__.py
│   ├── registry.py        # 10 payloads: miner/exploit/evasion
│   └── scripts.py         # template engine, manifest rendering
├── c2/
│   ├── __init__.py
│   ├── store.py           # C2Store (operations/tasks/workers)
│   ├── controller.py      # aiohttp Controller (dashboard + REST + WS)
│   ├── worker.py          # Worker (polling + WebSocket, 3 exec modes)
│   └── tls.py             # certs + nginx config
├── ops/
│   ├── __init__.py
│   ├── targeting.py       # TargetFilter, select_targets
│   └── deploy.py          # build_manifest, evasion chaining, enqueue
└── agent/
    ├── __init__.py
    ├── setup.py           # SetupStore, AgentConfig, run_setup_wizard
    ├── tools.py           # 10 LLM-callable tools + TOOL_REGISTRY
    └── ollama_agent.py    # ChatAgent (tool loop, 5 iterations)
```

## Data Flow

```
targets (CIDR/IP) 
  → scanners/masscan or zmap → list[HostHit]  (models.py:18)
  → fingerprint/probe.probe_many → list[Fingerprint]  (fingerprint/probe.py:343)
      fast: banner + KEXINIT + timing
      full: + host-key via paramiko
  → fingerprint/features.analyze → Signals  (fingerprint/features.py:209)
      known_hashes = Counter(host_key_sha256 >=2) ∪ store.known_key_set()
  → ai/scorer.profile_key → dict[profile_key → (Fingerprint, Signals)]
      batched by ai.batch_profiles / ai.batch_size
  → ai/scorer.AiScorer.score → dict[profile_key → AiVerdict]
  → pipeline._classify + fusion: final_confidence = ai*0.6 + heuristic*0.4
      thresholds: <0.2 real, <0.4 likely_real, <0.6 uncertain, <0.8 likely_honeypot else honeypot
  → store.Store.upsert_scores → SQLite + store.learn_from_scores
  → report.write_* → reports/
```

For red-team ops after scoring:

```
store.Store.query_scores → ops/TargetFilter → select_targets → list[Target]
  → ops/deploy.build_manifest (validate vars, render scripts, chain evasion)
  → ops/deploy.enqueue_operation or dispatch_to_controller
  → c2/store.C2Store → Operation + WorkerTask rows
  → c2/controller.Controller (aiohttp) ↔ c2/worker.Worker (poll/WS) → execute_task
```

For chat:

```
cli_chat.TerminalUI → agent/ollama_agent.ChatAgent
  → OllamaClient.chat (system prompt + TOOL_DESCRIPTIONS)
  → _extract_json → execute_tool (agent/tools.py) → ToolContext (Store + C2Store)
  → feed tool results back to LLM (up to 5 rounds) → speak to user
```

## Design Principles

- **Stdlib-only runtime.** `asyncio` drives I/O, `tomllib` reads config, `sqlite3` is the store, `urllib.request` speaks OpenAI chat, `subprocess` wraps scanners, `hashlib` hashes keys, `xml.etree` parses nmap XML. No `numpy`/`pandas`/`requests`.
- **Async concurrency.** `probe_many` uses `asyncio.Semaphore(concurrency)` so a `/16` with 512 in flight never opens 65k sockets. Each probe has a hard timeout (`probe.timeout_s`).
- **No credentials, ever.** Probing reads banners/KEXINITs, never authenticates. `auth_probe` is opt-in, sends one bogus attempt and records only the rejection.
- **Graceful degradation.** Missing `paramiko` downgrades `full→fast`; missing `nmap` skips optional probe; unreachable LLM (`is_reachable()`) keeps heuristics and reports `uncertain` verdicts.
- **Deterministic AI.** `temperature=0.0` + profile batching = same profile → same verdict run-to-run.
- **Batch-aware scoring.** Profile key is a stable `sha256(canonical JSON of sorted algo lists)`; hosts sharing a key share a cached verdict.
- **Optional C2.** `honeywatch[c2]` pulls `aiohttp`+`websockets`; without it, core scanning still runs.
- **Worker isolation.** Workers claim tasks only from allowed categories.

## Configuration Resolution

```
default_config()  (config.py:32)
  ↓ deep-merge
TOML file  (--config → $HONEYWATCH_CONFIG → ./config.toml)
  ↓ in-place
_env overrides  (HONEYWATCH_MODEL, HONEYWATCH_AI_BASE, OLLAMA_API_KEY)
  ↓ wrap
Config object  (dot + dict access, config.py:131)
```

## Storage

- **Main store** `honeywatch/store.py:383`: `hosts` table (`ip,port PK`) + 5 indexes (`final_label`, `final_confidence`, `profile_key`, `banner`, `software`) + `known_keys` table. WAL + `synchronous=NORMAL` + `temp_store=MEMORY`.
- **C2 store** `honeywatch/c2/store.py:424`: `c2_operations`, `c2_tasks`, `c2_workers`. Atomic `claim_next_task` via `UPDATE ... WHERE status='pending'`.
- **Setup store** `honeywatch/agent/setup.py:247`: `agent_setup` table (`key PK`) for `AgentConfig`.

## Key Constants

- `SSH_PORT = 22` (`models.py:15`)
- `CLIENT_BANNER = b"SSH-2.0-honeywatch_0.1\r\n"` (`fingerprint/probe.py:343`)
- `LABELS = ["real","likely_real","uncertain","likely_honeypot","honeypot"]` (`report.py:142`)
- `CLASSIFICATIONS = {real,likely_real,uncertain,likely_honeypot,honeypot}` (`ai/scorer.py:354`)
- `IFACE_PATTERNS = ("mullvad","wg-mullvad","wg0")` (`vpn.py:169`)
- `PAYLOAD_IDS` / `PAYLOAD_CATEGORIES` (`payloads/registry.py:590`)
