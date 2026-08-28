# Fingerprinting

`honeywatch/fingerprint/` captures the SSH wire protocol per host. Re-exports at `honeywatch/fingerprint/__init__.py:22`.

## Overview

Two depths:

- **`fast`** (default) — TCP connect + banner + RFC 4253 `SSH_MSG_KEXINIT` + timing. Pure `asyncio` + `stdlib`, no deps.
- **`full`** — above + real key exchange via `paramiko` to capture `host_key_type` and `host_key_sha256` (SHA-256 of the raw key bytes). Requires `pip install honeywatch[full]`. Without `paramiko`, silently falls back to `fast`.

## Probe (`probe.py`)

Source: `honeywatch/fingerprint/probe.py:343`.

### Constants

- `CLIENT_BANNER` — backwards-compat alias for a single plausible OpenSSH banner; no longer used by the probe (kept for static imports).
- `_client_banner_bytes(ip, port=22)` — a per-target sticky spoofed OpenSSH client banner (`spoofed_ssh_banner_for_target(ip, port).encode() + b"\r\n"`) actually sent to every host. The banner is memoized per `(ip, port)` within the process so repeat probes of one host present one consistent client identity (a real client's banner is fixed for its process — per-call randomization to the same host is itself an anomaly); different targets and different process instances draw independently, so there is no shared client fingerprint. See `opsec.spoofed_ssh_banner_for_target`.
- `_probe_credentials()` — per-call `(username, password)` for the deliberate-wrong auth probe (generic username pool + random high-entropy password), replacing the former fixed `honeywatch_probe_xz9` / `wrong-pass-12345` handle.
- `MSG_KEXINIT = 20` — RFC 4253 message type.
- `_MAX_PACKET = 1<<16` — 64 KiB cap per packet.
- `_NAME_LIST_KEYS` — tuple order for KEXINIT name-lists.

### `parse_banner(line: str) -> (protocol, software, version)`

Parses `SSH-2.0-OpenSSH_7.4`-style banners. Handles `OpenSSH_` underscore, extracts `protocol` (e.g. `2.0`), `software` (e.g. `OpenSSH`), `version` (e.g. `7.4`). Returns `(None, None, None)` on non-`SSH-` input. Used by `features.analyze` to detect `banner.no_version`.

### `parse_kexinit(payload: bytes) -> dict`

Parses RFC 4253 §7.1 `SSH_MSG_KEXINIT` payload: 16-byte cookie + ten name-lists (`kex_algorithms`, `server_host_key_algorithms`, `encryption_algorithms_client_to_server`, etc.) + `first_kex_packet_follows` + reserved. Tolerant of truncated input and optional transport prefix. Returns dict with list values.

### `is_ssh(fp: Fingerprint) -> bool`

True when `fp.banner` starts with `SSH-` and `fp.protocol` is not None. Used by `Pipeline.probe_hosts` to filter when `only_ssh=true`.

### `async probe_ssh(ip, port=22, level="fast", timeout=6.0, auth_probe=False) -> Fingerprint`

Per-host logic:

1. `asyncio.open_connection(ip, port)` — measures `connect_ms`, `time_to_banner_ms`, `banner_ms`.
2. `_read_banner(reader)` — reads until `\n`, decodes as UTF-8/ignore, strips.
3. Sends a per-target spoofed client banner via `_client_banner_bytes(ip, port)` (sticky per target), then `_read_packet` loop (up to 4 attempts) to capture `SSH_MSG_KEXINIT`.
4. Parses banner via `parse_banner`, KEXINIT via `parse_kexinit`, populates `Fingerprint` fields (`kex_algorithms`, `server_host_key_algorithms`, `enc_c2s/s2c`, `mac_c2s/s2c`, `comp_c2s/s2c`).
5. When `level=="full"` and `paramiko` is available, delegates `_full_probe` via `asyncio.to_thread`: creates `paramiko.Transport`, sets `transport.local_version` to a per-target sticky spoofed OpenSSH banner (`spoofed_ssh_banner_for_target(fp.ip, fp.port)`), completes KEX, extracts `host_key_type` and `host_key_sha256` (`hashlib.sha256` of `_key_bytes(key)`), optionally does one `auth_password(*_probe_credentials())` with a per-call random wrong credential and records the rejection in `evidence` when `auth_probe=True`.
6. Never raises for a single host — errors populate `Fingerprint.error`.

### `async probe_many(ips, port=22, level="fast", timeout=6.0, auth_probe=False, concurrency=512, on_result=None) -> list[Fingerprint]`

Semaphore-bounded gather (`asyncio.Semaphore(concurrency)`). Preserves input order, invokes `on_result(fp)` per completion (progress reporter). The workhorse behind `Pipeline.probe_hosts`.

### Internal Helpers

- `_elapsed_ms(start)`, `_read_banner`, `_read_packet`, `_key_bytes(key)` (paramiko `as_bytes`/`asbytes` across generations), `_full_probe(fp, auth_probe, timeout)`, `_client_banner_bytes(ip, port)`, `_probe_credentials()`.

## Heuristic Signals (`features.py`)

Source: `honeywatch/fingerprint/features.py:209`.

### `analyze(fp: Fingerprint | None, known_hashes=set[str]) -> Signals`

Scores a fingerprint in `[0.0, 0.95]` (`_SCORE_CAP`). Each signal adds to the score and populates `Signals.anomalies`, `Signals.flags`, `Signals.evidence`. Evidence is a dict of 13 fields + `auth.*` when auth-probed.

| Signal | Condition | Score | Flag |
|---|---|---|---|
| `proto.bad_banner` | banner missing or not `SSH-` | `+0.15` | — |
| `legacy_cipher` | any cipher in `LEGACY_CIPHERS` (`3des-cbc`, `arcfour*`, `blowfish-cbc`, `cast128-cbc`) | `+0.30` | `legacy_cipher` |
| `legacy_mac` | any MAC in `LEGACY_MACS` (`hmac-md5*`, `hmac-sha1*`) | `+0.25` | `legacy_mac` |
| `no_chacha` | OpenSSH ≥6.5 but no `chacha20-poly1305` (from `CHACHA`) | `+0.20` | `no_chacha` |
| `hostkey.mismatch` | banner software/version contradicts KEX host-key algos vs `OPENSSH_HOST_KEY_TYPES` | `+0.20` | `hostkey.mismatch` |
| `hostkey.weak` | key type in `WEAK_HOST_KEYS={ssh-dss}` | `+0.15` | `weak_host_key` |
| `kex_skew` | OpenSSH ≥7.0 missing `curve25519-sha256` (from `CURVE`/`CURVE_OPENSSH`) | `+0.15` | `kex_skew` |
| `banner.no_version` | banner has no version (`_VERSION_RE` fails) | `+0.10` | `banner.no_version` |
| `farm.hostkey_reuse` | `host_key_sha256` in `known_hashes` (shared across ≥2 hosts or learned) | `+0.20` | `host_key_reuse` |
| `timing.instant_banner` | `time_to_banner_ms < 5` | `+0.10` | `instant_banner` |
| `auth.accepted_wrong_password` | bogus auth accepted (should be rejected) | `+0.15` | `auth_probe_rejected` |

Plus error handling: `None` fingerprint → `0.35` with `no_fingerprint`; probe error → flags propagated. Final `min(score, 0.95)`.

### Helpers

- `_version_float(version_str) -> float | None` — extracts `major.minor` for version comparisons.
- `_fill_evidence(fp)` — populates 13 evidence fields for prompts.

### Constants

- `LEGACY_CIPHERS`, `LEGACY_MACS`, `WEAK_HOST_KEYS`, `CHACHA`, `CURVE`, `CURVE_OPENSSH`, `OPENSSH_HOST_KEY_TYPES` — all defined at `features.py:1`.
- `_SCORE_CAP = 0.95`
- `SIGNAL_NAMES: dict[str, str]` — 11 entries mapping flag → human label.

## Fingerprint Model

See `honeywatch/models.py:28` `Fingerprint`:

```python
@dataclass
class Fingerprint:
    ip: str
    port: int = 22
    banner: str | None = None
    protocol: str | None = None
    software: str | None = None
    software_version: str | None = None
    kex_algorithms: list[str] = field(default_factory=list)
    server_host_key_algorithms: list[str] = field(default_factory=list)
    enc_c2s: list[str] = ...
    enc_s2c: list[str] = ...
    mac_c2s: list[str] = ...
    mac_s2c: list[str] = ...
    comp_c2s: list[str] = ...
    comp_s2c: list[str] = ...
    host_key_type: str | None = None
    host_key_sha256: str | None = None
    connect_ms: float | None = None
    banner_ms: float | None = None
    time_to_banner_ms: float | None = None
    error: str | None = None
    evidence: dict[str, str] = field(default_factory=dict)
```

## Usage Examples

```python
from honeywatch.fingerprint import probe_ssh, probe_many, analyze
from honeywatch.fingerprint.probe import parse_banner, parse_kexinit, is_ssh

# Single host
fp = await probe_ssh("1.2.3.4", port=22, level="fast", timeout=6.0)
print(parse_banner(fp.banner))  # ('2.0', 'OpenSSH', '9.3p1')
print(is_ssh(fp))               # True

# Many hosts, bounded concurrency
fps = await probe_many(["1.2.3.4", "5.6.7.8"], concurrency=512)

# Score
signals = analyze(fp, known_hashes={"SHA256:abc..."})
print(signals.heuristic_score, signals.flags, signals.anomalies)
```
