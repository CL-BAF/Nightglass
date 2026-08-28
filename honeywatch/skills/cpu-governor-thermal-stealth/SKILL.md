---
name: cpu-governor-thermal-stealth
description: Reduce CPU thermal footprint by setting powersave governor and capping frequency to avoid cryptojacking detection
domain: cybersecurity
subdomain: evasion
tags: [evasion, thermal, cpu, stealth, governor, T1562]
version: '1.0'
nist_csf: [PR.DS-01]
mitre_attack: [T1562.001]
---

## When to use

After gaining root on a host that will run a miner. Sustained 100% CPU heats the
host — some datacenters and cloud providers monitor CPU temperature as a
cryptojacking signal. Capping frequency to 80% keeps mining throughput
acceptable while reducing thermal output.

## What it does

Sets the CPU governor to `powersave` and caps `scaling_max_freq` to 80% of
`cpuinfo_max_freq` for every CPU core. This is applied via the
`cpu_governor` payload, which runs as part of the evasion chain after binary
hardening but before persistence.

## OPSEC notes

- The governor change is visible in `/sys/devices/system/cpu/cpu*/cpufreq/`
- `powersave` is a legitimate governor that system admins may also set
- Capping at 80% reduces hashrate by ~15-20% but eliminates thermal spikes
- Pair with `memfd_exec` to avoid binary artifacts on disk