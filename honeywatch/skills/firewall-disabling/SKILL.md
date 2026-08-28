---
name: firewall-disabling
description: Flush iptables/nftables rules and disable firewalld/ufw to ensure unrestricted mining traffic
domain: cybersecurity
subdomain: evasion
tags: [evasion, firewall, iptables, T1562.004]
version: '1.0'
nist_csf: [PR.DS-01]
mitre_attack: [T1562.004]
---

## When to use

Immediately after gaining root on a host with restrictive firewall rules.
A host with `iptables -P INPUT DROP` would block the miner's pool connection
and the C2 callback. This payload flushes all rules and sets ACCEPT policies.

## What it does

Runs the `firewall_disable` payload which:
- Flushes iptables and ip6tables rules and chains
- Sets ACCEPT policies for INPUT, FORWARD, OUTPUT
- Stops and disables firewalld (RHEL/CentOS/Fedora)
- Disables ufw (Ubuntu/Debian)
- Flushes nftables ruleset
- Removes iptables persistence files

## OPSEC notes

- A completely open firewall is a significant IOC
- iptables rules are logged to `/var/log/syslog` or journald
- Consider adding back specific rules for essential services (SSH) to reduce visibility
- This runs as the first evasion payload (prepend position) to ensure pool connectivity