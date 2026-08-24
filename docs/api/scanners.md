# API — Scanners

`honeywatch/scanners/`.

## `scanners/__init__.py`

```python
from honeywatch.scanners import ScannerError
class ScannerError(Exception)
```

## `scanners/masscan.py`

`honeywatch/scanners/masscan.py:126`.

```python
from honeywatch.scanners.masscan import run

hits: list[HostHit] = run(
    targets: list[str],
    ports: list[int],
    rate: int,
    timeout_s: int|None = None,
    bin_path: str = "masscan",
    excludes: list[str]|None = None,
)  # → list[HostHit(ip, port, scanner="masscan")]
```

Builds `masscan --rate --wait 0 --output-format json --output-filename tmp --ports csv --exclude ...`, parses line-delimited JSON temp file. Raises `ScannerError` on `FileNotFoundError`/`TimeoutExpired`/non-zero.

## `scanners/zmap.py`

`honeywatch/scanners/zmap.py:83`.

```python
from honeywatch.scanners.zmap import run

hits = run(targets, ports, rate, timeout_s=None, bin_path="zmap")
# loops per-port: zmap -q -p PORT --rate RATE -o - targets
```

## `scanners/nmap_probe.py`

`honeywatch/scanners/nmap_probe.py:117`.

```python
from honeywatch.scanners.nmap_probe import probe

info: dict = probe(ip: str, port: int = 22, timeout_s: float = 6.0, bin_path="nmap")
# → {port, state, service, product, version, cpe, banner} or {error}
# never raises; safety_timeout = max(timeout*2+30, 60); XML via xml.etree, _parse_xml helper
```

See [Scanners](../scanners.md).
