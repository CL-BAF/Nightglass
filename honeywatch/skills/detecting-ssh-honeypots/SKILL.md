---
name: detecting-ssh-honeypots
description: Heuristic + AI signals for distinguishing real SSH hosts from honeypots at scale
domain: cybersecurity
subdomain: reconnaissance
tags: [honeypot, ssh, detection, fingerprinting, ai-scoring]
version: '1.0'
nist_csf: [ID.RA-01]
mitre_attack: [T1595.002]
---

## When to use

Before spraying or cracking — don't waste credentials on a honeypot. Run
`scan` to fingerprint hosts and get honeypot confidence scores. Only target
hosts labelled `real` or `likely_real` (confidence >= 0.7).

## Signals

- **no_banner / immediate_banner** — stubs that never emit a real banner or
  respond too fast (< 5ms) with no stack jitter
- **banner_version_mismatch** — banner claims OpenSSH 9.0 but KEXINIT offers
  only legacy algorithms (pasted banner, thin stack)
- **duplicate_host_key** — same SHA-256 host key across many IPs (honeypot farm)
- **no_kexinit** — TCP accepts but no SSH_MSG_KEXINIT follows (stub)
- **obsolete_algorithms** — modern banner + only legacy kex/ciphers

## AI verdict

The AI scorer groups fingerprints by profile and sends one LLM call per unique
profile. A `honeypot` label means "evidence strongly suggests honeypot" — it's
probabilistic, not truth. Use `--min-confidence 0.8` for conservative targeting.