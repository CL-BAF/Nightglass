---
name: evasion-via-anti-vm
description: Check CPU, DMI, dmesg, and filesystem indicators to detect virtualized sandboxes
domain: cybersecurity
subdomain: evasion
tags: [evasion, anti-vm, sandbox-detection, vmware, virtualbox]
version: '1.0'
nist_csf: [PR.DS-01]
mitre_attack: [T1497.001]
---

## When to use

As the **first** evasion step (prepend position in the evasion chain). The
anti-VM checker runs before the main payload and bails early if a sandbox is
detected — saving the payload from being analyzed.

## What it checks

- **CPU features**: hypervisor flag in `/proc/cpuinfo` (`flags: ... hypervisor`)
- **DMI**: `/sys/class/dmi/id/product_name` contains "VMware", "VirtualBox",
  "KVM", "QEMU", "Xen"
- **dmesg**: boot messages mentioning "Booting paravirtualized kernel"
- **Mac address**: OUI prefixes for VMware (00:0c:29), VirtualBox (08:00:27)
- **.dockerenv**: container environment

## What it does

If any sandbox indicator is found, the script exits with a non-zero code
before the main payload runs. This prevents the payload from executing in an
analysis environment.

## OPSEC notes

- Anti-VM checks are themselves a detection signal — some sandboxes flag
  scripts that check for VM indicators.
- Cloud instances (AWS, GCP, Azure) also show hypervisor flags — the check
  may false-positive on legitimate cloud hosts. Disable for known cloud targets.