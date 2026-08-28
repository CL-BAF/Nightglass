---
name: credential-reuse-across-fleet
description: Spray recovered passwords across the entire fleet for lateral growth via password reuse
domain: cybersecurity
subdomain: lateral-movement
tags: [credential-reuse, password-spray, lateral-movement, fleet-growth]
version: '1.0'
nist_csf: [PR.AA-01]
mitre_attack: [T1110.004]
---

## When to use

In round 2+ of the botnet chain, after passwords have been recovered from
the first round of hosts. Password reuse across a fleet is the highest-yield
growth primitive — a password cracked on host A often works on host B, C, and D.

## What it does

The chain's `phase_spray` automatically prepends recovered passwords to the
spray list in round 2+. Use `honeywatch spray --reuse-creds` to do this
manually: it reads every stored password and sprays them across every
discovered host.

## Why this works

- **Default passwords**: devices shipped with the same default (admin/admin,
  root/toor, ubnt/ubnt) across an entire fleet
- **Shared service accounts**: a fleet managed by the same team often uses
  the same admin password across all hosts
- **Password policies**: if the policy requires "Summer2024!", every host has
  a user with that password

## OPSEC notes

- Use `--business-hours` + `--delay` + `--jitter` — a fleet-wide spray is
  loud if done too fast
- Use `--max-user-attempts 5` to avoid lockouts on AD-joined hosts
- Use `--proxy-file` for source rotation across a large fleet