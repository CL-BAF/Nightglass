# Installation

## Requirements

- **Python:** `>=3.10` (`pyproject.toml:10`)
- **OS:** Linux recommended. `masscan`/`zmap` need raw sockets and Linux. `honeywatch probe` itself is pure `asyncio` sockets and works anywhere Python does (Windows, macOS via WSL2 or natively for probing).
- **No runtime dependencies** — core install pulls zero packages (`pyproject.toml:31`).

## Install from Source

```bash
# from the repo root
python -m pip install -e .

# verify
honeywatch --version
honeywatch --help
```

`honeywatch` is now on your `PATH` via `pyproject.toml:42`:

```toml
[project.scripts]
honeywatch = "honeywatch.cli:main"
```

You can also run without installing the script:

```bash
python -m honeywatch --help   # honeywatch/__main__.py:1
```

## Optional Extras

| Extra | What it adds | Install |
|---|---|---|
| `full` | `paramiko>=3.0` — enables `--probe-level full` (host-key type & SHA-256 via real KEX) | `pip install -e .[full]` |
| `c2` | `aiohttp>=3.8`, `websockets>=12.0` — C2 dashboard + worker WebSocket transport | `pip install -e .[c2]` |
| `dev` | `pytest>=7.0` — test suite | `pip install -e .[dev]` |
| Combined | | `pip install -e .[full,c2,dev]` |

Without `paramiko`, `full` silently falls back to `fast` (`honeywatch/fingerprint/probe.py`). Without `aiohttp`, `honeywatch c2` prints an install prompt and exits.

`requirements.txt` is intentionally empty (all commented) — it documents the same optional installs.

## External Scanners

`masscan` and `zmap` are **not** Python packages — they are Linux binaries honeywatch shells out to via `subprocess`.

```bash
sudo apt install masscan zmap        # Debian/Ubuntu
sudo dnf install masscan zmap        # Fedora
# nmap is optional, for single-host version-light probes
sudo apt install nmap
```

They need raw-socket capability:

```bash
sudo setcap cap_net_raw+ep $(which masscan)
sudo setcap cap_net_raw+ep $(which zmap)
# or just run honeywatch scan with sudo
```

Binary paths are configurable in `config.toml` (`scanners.masscan.bin`, etc.) if you build from source to a non-standard location.

### Windows / macOS

`masscan`/`zmap` are Linux-only. Options:

- **WSL2** (Windows) — install honeywatch + scanners inside WSL2.
- **Skip discovery** — use `honeywatch probe` directly (pure asyncio) or `honeywatch scan` with a small `--max-hosts` on an `nmap`-reachable target.

## Ollama Cloud Setup

honeywatch uses **Ollama Cloud only** (`https://ollama.com/v1` by default, `honeywatch/config.py:71`). There is no local-server fallback.

1. Create an API key at [ollama.com/settings/keys](https://ollama.com/settings/keys).
2. Export it:

```bash
export OLLAMA_API_KEY=ollama_...
# optional overrides
export HONEYWATCH_MODEL=gpt-oss:20b          # default: llama3.1:8b
export HONEYWATCH_AI_BASE=https://ollama.com/v1   # default is this
```

Also see `.env.example:1` — copy to `.env` if you use a dotenv loader, or just `export`.

Without a key the AI stage is skipped and scores fall back to pure heuristics (a warning is printed). Verify the key:

```bash
curl https://ollama.com/v1/models \
  -H "Authorization: Bearer $OLLAMA_API_KEY"
```

See [AI Integration](ai-integration.md) and [Configuration](configuration.md) for `[ai]` table details.

## VPN Prerequisite

`honeywatch scan` and `honeywatch probe` **refuse to start unless your traffic egresses through Mullvad**. See [VPN Gate](vpn.md) for the check logic and `--skip-vpn-check` / `HONEYWATCH_SKIP_VPN=1` bypass for controlled testing.

```bash
mullvad connect
honeywatch scan 0.0.0.0/0   # "honeywatch: vpn gate OK (am.i.mullvad.net confirms a Mullvad exit IP)"
```

## Verify Installation

```bash
pip show honeywatch
honeywatch --version
honeywatch config              # prints default TOML
honeywatch probe 1.1.1.1 --skip-vpn-check --no-ai  # smoke test, no scanner needed
pytest -q                      # with [dev] extra
```

## Upgrading

```bash
git pull
python -m pip install -e . --upgrade
honeywatch --version
```
