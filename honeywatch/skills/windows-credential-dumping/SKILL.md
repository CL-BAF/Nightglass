---
name: windows-credential-dumping
description: Dump Windows SAM/SYSTEM registry hives for offline credential cracking and lateral movement
domain: cybersecurity
subdomain: evasion
tags: [evasion, windows, credentials, sam, T1003.001]
version: '1.0'
nist_csf: [PR.DS-01]
mitre_attack: [T1003.001]
---

## When to use

On Windows hosts where `reg.exe` is available (all modern Windows versions).
Use after gaining a foothold on a Windows target to extract SAM hashes for
lateral movement. This is the `windows_cred_dump` payload.

## What it does

Uses `reg save` to dump the SAM and SYSTEM registry hives to temp files, then
exfiltrates them via curl to the C2 `/api/loot` endpoint. No Mimikatz —
avoids AV detection by using built-in Windows tools only.

## OPSEC notes

- `reg save` requires admin privileges
- SAM dump triggers Windows Event ID 4662 (object access)
- Exfiltrated files are cleaned up after transfer
- Hashes can be cracked offline with hashcat/john for lateral movement