# Heuristic Signals

Deterministic rule engine in `honeywatch/fingerprint/features.py:209` `analyze()` — no ML, no network, pure logic over the `Fingerprint`. Scores in `[0.0, 0.95]`, higher = more likely honeypot. Each signal contributes evidence; enough strong signals move the label toward `honeypot` even when the LLM says nothing.

## Signal Table

| Signal | What the probe saw | Why it suggests honeypot | Score |
|---|---|---|---|
| `no_banner` / `proto.bad_banner` | TCP accept, nothing sent before timeout | many stubs never emit a banner | `+0.15` |
| `immediate_banner` / `timing.instant_banner` | banner in <5 ms with no stack jitter | deterministic script, no real protocol | `+0.10` |
| `banner.no_version` | banner has no version string | copy-pasted or stub banner | `+0.10` |
| `banner_version_mismatch` / `hostkey.mismatch` | banner software/version contradicts KEXINIT algorithm set | banners are pasted; KEXINIT is real code | `+0.20` |
| `obsolete_algorithms` / `legacy_cipher` | modern-sounding banner + only legacy kex/ciphers (`3des-cbc`, `arcfour*`, `blowfish-cbc`, `cast128-cbc`) | thin stacks implement few algorithms | `+0.30` |
| `legacy_mac` | legacy MACs (`hmac-md5*`, `hmac-sha1*`) | same | `+0.25` |
| `no_kexinit` | no `SSH_MSG_KEXINIT` after the banner | deeper protocol never arrives | implicit via other signals |
| `kexinit_inconsistent` / `kex_skew` | OpenSSH ≥7.0 missing `curve25519-sha256` | hand-assembled packet | `+0.15` |
| `no_chacha` | OpenSSH ≥6.5 without `chacha20-poly1305` | same | `+0.20` |
| `duplicate_host_key` / `farm.hostkey_reuse` | same `host_key_sha256` across ≥2 IPs | shared key = honeypot farm | `+0.20` |
| `weak_host_key` / `hostkey.weak` | `ssh-dss` / 512-bit RSA / odd type | canned test keys | `+0.15` |
| `host_key_reuse` | hash in `known_keys` learned from prior honeypot verdicts | catalogued honeypot identity | `+0.20` |
| `auth.accepted_wrong_password` | bogus auth accepted | broken auth stack | `+0.15` |

The README table at `README.md:294` lists the same signals in consolidated form; the per-rule breakdown above is the source at `features.py:209`.

## Scoring Details

```python
from honeywatch.fingerprint import analyze

signals = analyze(fp, known_hashes=store.known_key_set())
# signals.heuristic_score  e.g. 0.65
# signals.anomalies        ["legacy_cipher: 3des-cbc", "farm.hostkey_reuse"]
# signals.flags            ["legacy_cipher", "host_key_reuse"]
# signals.evidence         {"banner": "SSH-2.0-...", "kex": "...", ...}
```

- `None` fingerprint → `0.35` + `["no_fingerprint"]`.
- Errors in `fp.error` are reflected in flags.
- Final `min(score, 0.95)` — never 1.0 from heuristics alone.

### Version Helpers

- `_version_float("9.3p1") -> 9.3` — used for `>=6.5` / `>=7.0` gates.
- `_fill_evidence(fp)` — populates 13 evidence fields (`banner`, `kex`, `host_key_algorithms`, `ciphers`, `macs`, `compression`, `timing`, etc.) plus `auth.*` when `auth_probe` was used.

## Flags vs Anomalies

- **`flags`** — special-interest marks the score weights but that you may want to see in raw output (e.g. `auth_probe_rejected`, `host_key_reuse`). Stored in SQLite column `flags` and indexed for `by_flag` stats.
- **`anomalies`** — human-readable strings per signal, included in the AI prompt via `summarize()` (`ai/scorer.py:354`).

## Farm Detection

`Pipeline.analyze_and_score` (`pipeline.py:352`) builds `known_hashes` as:

```python
Counter(fp.host_key_sha256 for fp in fingerprints where count>=2)  ∪  store.known_key_set()
```

`store.known_key_set()` are SHA-256 hashes learned from prior runs where `final_label` was `honeypot` or `likely_honeypot` (`store.py:383` `learn_from_scores`). This makes the second scan of a honeypot farm automatically flagged even if the heuristic alone would be borderline.

## Tuning

No thresholds to tune — the score is additive and capped. The mapping to labels happens later in `Pipeline._classify` (`pipeline.py:352`):

```
<0.2 real, <0.4 likely_real, <0.6 uncertain, <0.8 likely_honeypot else honeypot
```

After AI fusion (`ai*0.6 + heuristic*0.4`), the label is recomputed from `final_confidence`.

To whitelist a known host key, insert its hash into `known_keys` or exclude it from `known_hashes` passed to `analyze`.

## Related

- [Fingerprinting](fingerprinting.md) — how `Fingerprint` is captured
- [AI Integration](ai-integration.md) — how `Signals` are summarized for the LLM
- [Storage](storage.md) — how `known_keys` are persisted
