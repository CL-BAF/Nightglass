# honeywatch — planet-scale SSH honeypot scanner with AI confidence scoring

> **Scan millions of hosts. Fingerprint every SSH service. Let AI tell you which ones are fake.**

`honeywatch` scans large address spaces for open SSH (port 22) services, builds a deep protocol fingerprint of every one, scores it with **deterministic heuristic signals**, and then asks the **Ollama Cloud LLM** for a final confidence verdict. The trick that makes AI feasible at planet scale: hosts with an *identical fingerprint profile* are batched into a single prompt, so one LLM call classifies millions of hosts instead of millions of calls.

Everything runs on the **Python 3.10+ standard library** — `asyncio`, `sqlite3`, `tomllib`, `urllib.request`, `argparse`, `hashlib`, `json`, `xml.etree`. No `numpy`, no `pandas`, no `requests`. Two *optional* extras make it stronger: `paramiko` (full host-key probing) and `pytest` (tests). The scanners themselves (`masscan`, `zmap`) and `nmap` are separate Linux binaries that honeywatch shells out to.

---

## Pipeline at a Glance

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
      └──────────────────────────────────────┘
```

### How it Works

1. **Discover.** Run `masscan` or `zmap` over your target range, or hand honeywatch a list of hosts directly. A "hit" is just `ip:22` reachable.
2. **Probe.** An asyncio pool (default 512 concurrent connections, 6 s timeout) talks to each open port. At `fast` level it captures the banner line, the RFC 4253 `SSH_MSG_KEXINIT` (kex / host-key / cipher / MAC / compression algorithms in both directions), and connect/banner timing. At `full` level (requires `paramiko`) it completes real key exchange to capture the host key type and SHA-256 fingerprint.
3. **Signal.** The rule engine turns each fingerprint into a set of anomalies, flags, evidence, and a heuristic score in `[0, 1]`.
4. **AI verdict.** Fingerprints are grouped by an **identity profile** (the normalized banner + algorithm set + host key). Each unique profile gets one LLM prompt; every host sharing that profile inherits the verdict. This is what makes planet-scale AI scoring practical.
5. **Persist.** Final scores (heuristic + AI) are written to SQLite and rendered to JSON / CSV / Markdown reports.

### Why Honeypot Detection Matters

A honeypot is a service that *pretends* to be a real SSH server to observe attackers. At internet scale, honeypots are cheap to deploy and plentiful — any study of "which hosts are really running SSH" is polluted by them.

A real OpenSSH/sshd stack is a complex, specific protocol implementation, while most honeypots are thin scripts that emulate just enough of the wire protocol to fool casual tools. The discrepancies are measurable:

- **Depth of protocol.** A real server speaks RFC 4253: it sends a banner, then an `SSH_MSG_KEXINIT` with a rich, internally-consistent set of algorithms. A scripted honeypot often sends a pasted banner and no meaningful KEXINIT.
- **Timing.** Real handshakes take real CPU time and jitter. A stub that answers in microseconds is suspicious.
- **Identity.** Honeypot farms reuse the same host key and banner across thousands of IPs. Real fleets do not.
- **Consistency.** A banner that claims `OpenSSH_7.4` while offering only modern `ssh-ed25519` KEX is a red flag — banners are copy-pasted, algorithm lists come from the actual stack.

---

## Feature Highlights

| Feature | Detail |
|---|---|
| **Stdlib-only runtime** | `asyncio` + `sqlite3` + `tomllib` + `urllib` — zero required dependencies |
| **Planet-scale AI** | One LLM call per unique profile, not per host — 10k identical honeypots = 1 call |
| **Deterministic heuristics** | 11 rule-based signals with capped scoring in `[0, 0.95]` |
| **Async fingerprinting** | Semaphore-bounded concurrency (512 default), 6 s timeout, `fast` vs `full` |
| **SQLite + WAL** | `honeywatch.db` with indexes on label/confidence/profile/banner/software |
| **Mullvad VPN gate** | Refuses to scan unless egress is Mullvad (bypassable for testing) |
| **Red-team ops** | 10 payloads (miners, exploit, evasion) + C2 dashboard + worker plane |
| **AI agent chat** | Conversational `honeywatch chat` with 10 LLM-callable tools |

---

## Quick Links

- [Installation](installation.md) — dependencies, optional extras, scanner setup
- [Quickstart](quickstart.md) — probe a host, scan a subnet, generate reports in 5 minutes
- [CLI Reference](cli.md) — every subcommand and flag
- [Configuration](configuration.md) — `config.toml` + environment overrides
- [Architecture](architecture.md) — module map and data flow
- [API Reference](api/index.md) — Python API for every module

---

## Project Info

- **Package:** `honeywatch` `0.1.0` — `pyproject.toml:6`
- **Python:** `>=3.10`
- **License:** MIT
- **Entry point:** `honeywatch = honeywatch.cli:main` (`pyproject.toml:42`) / `python -m honeywatch` via `honeywatch/__main__.py:1`
- **Tests:** `pytest -q` (19 test modules, ~150 tests)

---

## Legal Notice

Scanning networks you do not own, or that you are not **explicitly authorized to test**, may be **illegal** — under the US Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, the EU's NIS/cybercrime frameworks, and equivalent national law worldwide. honeywatch is a **research and authorized-audit tool**. See [Security & Legal](security.md) for full disclaimers.
