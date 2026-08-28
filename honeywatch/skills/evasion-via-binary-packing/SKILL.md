---
name: evasion-via-binary-packing
description: UPX packing and ELF packers to compress and obfuscate deployed binaries
domain: cybersecurity
subdomain: evasion
tags: [evasion, upx, packer, elf, binary, compression]
version: '1.0'
nist_csf: [PR.DS-01]
mitre_attack: [T1027.002]
---

## When to use

After deploying a binary payload (xmrig, xmrigcc) but before the target's
EDR/AV scans it. Packing compresses the binary and changes its entropy + hash,
making static signature detection harder.

## What it does

- **UPX**: compresses ELF binaries ~50-70%. The binary self-unpacks at runtime.
  Fast, widely available, but UPX-packed binaries are a known IOC — some EDR
  flags any UPX-packed binary.
- **Generic packers**: creates a self-extracting ELF stub that decompresses
  the payload at runtime. Less detectable than UPX but requires custom code.
- **Obfuscators**: rewrites string literals in scripts as `chr()` concatenation
  to raise the cost of casual static analysis.

## Chaining order

1. Deploy the binary (xmrig)
2. Apply `upx` or `packers` (append position in the evasion chain)
3. Apply `symbol_strip` (remove debug symbols after packing)
4. Apply `obfuscators` (if any scripts need obfuscation)
5. Apply `anti_debug` (final — LD_PRELOAD shim)
6. Run `cleanup` (wipe traces)

## OPSEC notes

UPX is a double-edged sword: it reduces binary size (good) but is itself a
detection signal (bad). If the target has EDR, prefer `packers` over `upx`.