---
name: pivot-subnet-discovery
description: Discover adjacent subnets from a foothold via ip/ifconfig output and pivot into them
domain: cybersecurity
subdomain: lateral-movement
tags: [pivot, subnet, network-discovery, ip-addr, growth]
version: '1.0'
nist_csf: [ID.RA-01]
mitre_attack: [T1018]
---

## When to use

After gaining a foothold and looting it — the pivot phase discovers adjacent
subnets the foothold can reach, feeds them back into recon, and the chain
loops (growth). This is how a single foothold becomes a fleet.

## What it does

1. Runs `ip -o -4 addr` (or `ifconfig` fallback) on the foothold
2. Parses the interfaces to find all IPs + their CIDR prefixes
3. Skips loopback (127.x) and link-local (169.254.x)
4. Caps at /20 (4096 hosts) to avoid scanning a /8 (too loud + too slow)
5. Feeds the discovered subnets back into `cfg.targets` for the next round

## Why the /20 cap

A /16 corporate network has 65k hosts — scanning all of them from a single
foothold takes hours and generates massive network noise. A /20 (4096 hosts)
is large enough to find adjacent targets but small enough to finish in minutes.
The cap is in `_adjacent_subnets` in `chain.py`.

## Growth loop

```
recon (scan /24) → spray → foothold → loot → pivot (discover /20)
  → recon (scan /20) → spray → foothold → loot → pivot (discover more)
  → ... until no new subnets found
```

The chain stops when a pivot round produces no new targets (growth exhausted).

## OPSEC notes

- Scanning a /20 from a foothold is noisy — use `--rate 1000` (the conservative
  default) and `--business-hours` if the target is in an enterprise
- Each pivot round increases the blast radius — consider stopping after 2-3
  rounds to limit exposure