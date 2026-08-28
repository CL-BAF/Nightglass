---
name: shadow-hash-cracking
description: Offline hashcat/john workflow for cracking /etc/shadow hashes after exfiltration
domain: cybersecurity
subdomain: credential-recovery
tags: [hashcat, john, shadow, hash-cracking, offline]
version: '1.0'
nist_csf: [PR.AA-01]
mitre_attack: [T1110.002]
---

## When to use

After grabbing `/etc/shadow` from a foothold (via `grab_shadow` or the
privesc phase). Offline cracking doesn't touch the target — no lockout risk,
no network noise.

## Workflow

1. **Grab the shadow** — `grab_shadow` or `sudo -n cat /etc/shadow` via privesc
2. **Identify hash families** — the hashcrack module auto-detects:
   - `$6$` = SHA-512 (most common on modern Linux)
   - `$5$` = SHA-256
   - `$y$` = yescrypt (newer distros)
   - `$1$` = MD5 (old distros)
3. **Choose the tool**:
   - `hashcat` — GPU-accelerated, much faster. Use when a GPU is available.
   - `john` — CPU-only, works everywhere. Use when no GPU.
4. **Wordlist selection**:
   - Bundled default wordlist works for common passwords
   - `rockyou.txt` for broader coverage
   - Custom wordlist with company name + mutations for targeted cracking

## Auto-detection

The `hashcrack` command auto-detects the hash mode per family. For mixed
hash families (some $6$, some $y$), it splits by family and cracks each
separately. Use `--force-mode` to override.

## Chaining

Cracked credentials flow back into the store → `phase_spray` re-uses them
across the fleet → more footholds → more shadows → more cracked creds.
This is the growth loop.