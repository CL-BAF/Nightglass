---
name: audit-chain-verification
description: Verify the tamper-evident SHA256 audit chain to prove what ran on each target
domain: cybersecurity
subdomain: accountability
tags: [audit, sha256, chain, verification, evidence, tamper-detection]
version: '1.0'
nist_csf: [PR.AA-01]
mitre_attack: []
---

## When to use

After any deploy, crack, or grab operation — verify the audit chain to prove
the actions recorded are the actions that actually ran. Also use during
post-operation review to prove what was deployed, what was cracked, and what
was grabbed on each target.

## What it does

The audit chain is an append-only SQLite table where each row's `this_hash` =
SHA256 of the canonical JSON of the row (excluding `this_hash`). Row N+1's
`prev_hash` = row N's `this_hash`. Verification re-walks the chain and
recomputes every hash — any tampering (modified row, deleted row, inserted
row) breaks the chain.

## How to verify

- **Agent tool**: `verify_audit(run_id="auto-xxx")` — returns
  `{chain_valid: true/false, reason: "..."}`
- **Python API**: `AuditStore(db_path).verify_chain(run_id="...")`
- **CLI** (planned): `honeywatch audit verify [--run-id ID]`

## What the chain records

Every `execute_tool` call: tool name, redacted arguments, redacted result,
target IP, cycle number, SHA256 of any deployed code, exit code, timestamp,
and the chain hash links.

## Redaction

Credentials are redacted before hashing:
- Secret-named args (password, ssh_pass, ssh_key, token) → `***`
- Inline credential shapes (URL user:pass@, --password, Bearer token) →
  secret portion replaced with `***`
- The hash is computed on the redacted form so the chain is verifiable
  without exposing secrets

## What a broken chain means

- **Hash mismatch**: a row was modified after insertion (tampering)
- **prev_hash mismatch**: a row was deleted or inserted out of order
- Both are fatal — the chain's integrity is broken and no record after the
  break can be trusted