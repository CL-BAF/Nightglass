---
name: evasion-via-anti-debug
description: LD_PRELOAD shim that calls PTRACE_TRACEME to detect and deter debuggers
domain: cybersecurity
subdomain: evasion
tags: [evasion, anti-debug, ptrace, ld_preload]
version: '1.0'
nist_csf: [PR.DS-01]
mitre_attack: [T1622]
---

## When to use

As the final evasion step before cleanup. The anti-debug shim is an
LD_PRELOAD-able .so that calls PTRACE_TRACEME on process startup — if a
debugger is already attached, the call fails and the process exits.

## What it does

1. Compiles a small C shared object (`anti_debug.so`) that calls
   `ptrace(PTRACE_TRACEME, 0, 0, 0)` in its constructor.
2. The shim is loaded via `LD_PRELOAD=./anti_debug.so ./xmrig`.
3. If a debugger (gdb, strace, ltrace) is attached, PTRACE_TRACEME fails
   and the process aborts.

## Limitations

- Only deters casual debugging — a determined analyst can patch the binary
  or use `LD_PRELOAD` overrides.
- Does not detect eBPF-based tracing (bpftrace, Falco) — those don't use
  ptrace.
- The .so is itself a small artifact that can be fingerprinted.

## Chaining

Apply as the **final** evasion step (after packing, stripping, obfuscation).
The evasion chain order: `anti_vm` (prepend) → main payload → `upx`/`packers`/
`symbol_strip`/`obfuscators` (append) → `anti_debug` (final).