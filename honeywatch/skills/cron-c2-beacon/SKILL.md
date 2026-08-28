---
name: cron-c2-beacon
description: Cron-based C2 callback for persistent command retrieval when the primary worker process is killed
domain: cybersecurity
subdomain: persistence
tags: [persistence, cron, beacon, c2, fallback, T1053.003]
version: '1.0'
nist_csf: [PR.DS-01]
mitre_attack: [T1053.003]
---

## When to use

As a persistence fallback alongside the primary worker process. If the worker
is killed (by an admin, OOM killer, or competing miner), the cron beacon
periodically checks the C2 controller for new tasks and re-launches the worker.

## What it does

Installs a cron entry (default: every 10 minutes) that curls the C2
`/api/beacon` endpoint. If the controller has a pending task, it returns a
shell script to execute; otherwise 204 No Content. Uses `chattr +ia` on the
crontab file for persistence, and `printf` for safe cron line construction.

## OPSEC notes

- Cron entries are visible via `crontab -l` and `/var/spool/cron/`
- The beacon uses `Bearer` token auth with `hmac.compare_digest` verification
- Callback interval can be customized with `--human-timing` for time-of-day variance
- Pair with `systemd_persist` for dual persistence (cron + systemd)