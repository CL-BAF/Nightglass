# API — Fingerprint

`honeywatch/fingerprint/` — re-exports at `fingerprint/__init__.py:22`.

## `fingerprint/__init__.py`

```python
from honeywatch.fingerprint import analyze, probe_ssh, probe_many, parse_banner, parse_kexinit, SIGNAL_NAMES, LEGACY_CIPHERS, LEGACY_MACS, WEAK_HOST_KEYS
__all__ = ["analyze", "probe_ssh", "probe_many", "parse_banner", "parse_kexinit", "SIGNAL_NAMES", "LEGACY_CIPHERS", "LEGACY_MACS", "WEAK_HOST_KEYS"]
```

## `probe.py`

`honeywatch/fingerprint/probe.py:343`.

| Symbol | Signature | Meaning |
|---|---|---|
| `CLIENT_BANNER` | deprecated back-compat alias | no longer used; probe sends `_client_banner_bytes(ip, port)` per target |
| `_client_banner_bytes` | `(ip, port=22) -> bytes` | per-target sticky spoofed OpenSSH client banner sent to every host (see `opsec.spoofed_ssh_banner_for_target`) |
| `_probe_credentials` | `() -> (str, str)` | per-call random wrong `(user, pass)` for the auth probe |
| `MSG_KEXINIT` | `20` | RFC 4253 |
| `is_ssh(fp)` | `(Fingerprint) -> bool` | banner starts `SSH-` |
| `parse_banner(line)` | `(str) -> (protocol, software, version)` | handles `OpenSSH_` |
| `parse_kexinit(payload)` | `(bytes) -> dict` | RFC 4253 §7.1, tolerant |
| `probe_ssh(ip, port, level, timeout, auth_probe)` | `async (str,int,str,float,bool) -> Fingerprint` | TCP + banner + KEXINIT + optional paramiko |
| `probe_many(ips, port, level, timeout, auth_probe, concurrency, on_result)` | `async (...) -> list[Fingerprint]` | semaphore-bounded gather |

Internals: `_elapsed_ms`, `_read_banner`, `_read_packet`, `_key_bytes`, `_full_probe`.

## `features.py`

`honeywatch/fingerprint/features.py:209`.

| Symbol | Detail |
|---|---|
| `LEGACY_CIPHERS` | `{"3des-cbc","arcfour*","blowfish-cbc","cast128-cbc"}` |
| `LEGACY_MACS` | `{"hmac-md5*","hmac-sha1*"}` |
| `WEAK_HOST_KEYS` | `{"ssh-dss"}` |
| `CHACHA` | `{"chacha20-poly1305@openssh.com"}` etc. |
| `CURVE` / `CURVE_OPENSSH` | `curve25519-sha256` sets |
| `OPENSSH_HOST_KEY_TYPES` | expected types per version |
| `_SCORE_CAP` | `0.95` |
| `SIGNAL_NAMES` | `dict[str,str]` 11 entries |
| `_VERSION_RE` | banner version regex |
| `analyze(fp, known_hashes)` | `(Fingerprint|None, set[str]) -> Signals` — main scorer, `[0.0,0.95]` |
| `_version_float(s)` | `(str) -> float|None` |
| `_fill_evidence(fp)` | populates 13 evidence fields |

See [Fingerprinting](../fingerprinting.md) and [Heuristic Signals](../heuristic-signals.md) for scoring tables.
