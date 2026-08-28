---
name: lateral-movement-via-ssh-keys
description: Recover SSH private keys from footholds and spray them across the fleet for key-based access
domain: cybersecurity
subdomain: lateral-movement
tags: [ssh-keys, lateral-movement, key-reuse, ansible, managed-fleet]
version: '1.0'
nist_csf: [PR.AA-05]
mitre_attack: [T1021.004]
---

## When to use

After looting SSH private keys from a foothold (phase_loot recovers id_rsa,
id_ed25519, etc. from ~/.ssh/). Use the key-spray round in phase_spray to try
every recovered key against every sprayable host.

## Why this is high-yield

On managed fleets (Ansible, Puppet, Chef), a single private key often works
across hundreds of hosts — all under the same service account (ansible,
ubuntu, debian, git). One recovered key can open an entire fleet segment.

## Users to try

Don't just try root. Service accounts are where keys live:
- `ansible` — Ansible-controlled fleets
- `ubuntu` / `debian` — cloud images
- `git` — GitLab/GitHub runners
- `jenkins` — CI/CD servers
- `oracle` — Oracle DB hosts

The chain's key-spray round uses the configured users list + root as fallback.

## OPSEC notes

Key-based auth is quieter than password spray — no failed-password log entries.
But SSH key auth still logs the source IP + user. Use source rotation.