# Scanners

`honeywatch/scanners/` — thin wrappers that shell out to external discovery tools via `subprocess`. They return `list[HostHit]` (`models.py:18`). All wrappers use stdlib only.

## `ScannerError`

`honeywatch/scanners/__init__.py:28`:

```python
from honeywatch.scanners import ScannerError

class ScannerError(Exception): ...
```

Raised on missing binary (`FileNotFoundError`), non-zero exit, or timeout (`TimeoutExpired`).

## masscan (`scanners/masscan.py`)

```python
from honeywatch.scanners.masscan import run as run_masscan

hits = run_masscan(
    targets=["192.0.2.0/24", "198.51.100.7"],
    ports=[22],
    rate=1000,
    timeout_s=None,          # or 600 for bounded scans
    bin_path="masscan",      # from scanners.masscan.bin
    excludes=["10.0.0.0/8"], # from scanners.masscan.exclude
)
```

**What it does** (`masscan.py:126` `run`):

- Builds `argv = [bin, --rate <rate>, --wait 0, --output-format json, --output-filename <tmp>, --ports <csv>] + [--exclude <cidr> ...] + targets`.
- Creates a temp file via `tempfile.NamedTemporaryFile(delete=False, suffix=".json")`.
- Runs `subprocess.run(argv, capture_output=True, timeout=timeout_s)`.
- Parses line-delimited JSON from the temp file: each line has `ip`/`ports` → emits `HostHit(ip, port, scanner="masscan")`.
- Cleans up the temp file.

**Rate** — conservative default `1000` pps (`config.py:42`). Raise only with authorization. Full-internet `0.0.0.0/0` at `10000` pps is shown in the README planet-scale examples.

**Excludes** — extra CIDRs to skip via `--exclude`. On a `0.0.0.0/0` sweep you should exclude RFC1918 + your own egress IP.

**Timeout** — `scanners.masscan.timeout_s` or `None` (no timeout). Set e.g. `600` for bounded scans so a hung run can't block forever.

**Requires** — `masscan` binary + raw sockets (root or `cap_net_raw`). Linux-only.

## zmap (`scanners/zmap.py`)

```python
from honeywatch.scanners.zmap import run as run_zmap

hits = run_zmap(
    targets=["192.0.2.0/24"],
    ports=[22],          # loops per-port
    rate=5000,
    timeout_s=None,
    bin_path="zmap",
)
```

**What it does** (`zmap.py:83` `run`):

- Loops per port: `argv = [bin, -q, -p <port>, --rate <rate>, -o -, <targets...>]`.
- `subprocess.run(argv, capture_output=True, timeout=timeout_s)`, decodes stdout lines, each non-empty line is an IP → `HostHit(ip, port, scanner="zmap")`.
- Aggregates across ports.

**Notes** — single-port by design, much lighter than `masscan`. Rate, timeout, and bin path work the same as masscan but `zmap` has no `--exclude` (filter in your target list).

## nmap probe (`scanners/nmap_probe.py`)

```python
from honeywatch.scanners.nmap_probe import probe

info = probe("192.0.2.1", port=22, timeout_s=6.0, bin_path="nmap")
# → {"port": 22, "state": "open", "service": "ssh", "product": "OpenSSH", "version": "9.3p1", "cpe": "...", "banner": "..."}
# or {"error": "..."} on failure — never raises
```

**What it does** (`nmap_probe.py:117` `probe`):

- Runs `nmap -Pn -sV --version-light -oX - <ip> -p <port>` via `subprocess.run` with `safety_timeout = max(timeout_s*2+30, 60)`.
- Parses XML stdout via `xml.etree.ElementTree` (`_parse_xml` helper).
- Returns dict with `port`, `state`, `service`, `product`, `version`, `cpe`, `banner` (or `error`).

**Never raises** — missing binary, timeout, non-zero exit, or bad XML all return `{error: ...}`. This makes it safe to call opportunistically alongside the main probe.

## Integration with Pipeline

`Pipeline.scan` (`pipeline.py:352`):

- Resolves `bin_path`/`timeout_s`/`exclude` from `scanners.<tool>` config.
- Calls `masscan.run` or `zmap.run` via `asyncio.to_thread` (blocking subprocess off the event loop).
- Applies `max_hosts` slice and `resume` filter (`store.scored_hosts()`).
- Hands the resulting `list[HostHit]` to `probe_hosts`.

`config.toml` keys:

```toml
[scanners.masscan]
bin = "masscan"
rate = 1000
# timeout_s = 600
# exclude = ["10.0.0.0/8", "192.168.0.0/16"]

[scanners.zmap]
bin = "zmap"
# timeout_s = 600

[scanners.nmap]
bin = "nmap"
```

## Troubleshooting

- **`masscan: command not found`** — `sudo apt install masscan` / `sudo dnf install masscan`.
- **Permission denied / raw-socket errors** — `sudo honeywatch scan ...` or `sudo setcap cap_net_raw+ep $(which masscan)`.
- **Windows/macOS** — scanners are Linux-only; use WSL2 or skip discovery and use `honeywatch probe` directly.
