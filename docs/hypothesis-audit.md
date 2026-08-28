# Hypothesis Ledger + Audit Chain

Phase 1+2 of the Nightglass v2 architecture upgrade. Two new foundational
modules that separate "the tool ran" (operational success) from "the evidence
proved the claim" (evidential success), and provide a tamper-evident record of
every action.

## Hypothesis ledger (`honeywatch/agent/hypothesis.py`)

### The problem

The autonomous agent runs tools and moves on. A successful `crack_ssh` that
returns credentials is operational success — but a `grab_shadow` that returns
an empty file is operational success *and* evidential failure (the host has no
shadow to crack, so the "this host has crackable hashes" hypothesis is
refuted even though the tool ran fine). Without a ledger, the agent can't
distinguish these, and keeps trying refuted approaches.

### The judge

`judge_outcome(hypothesis, tool_result)` is a deterministic pure-Python
function that evaluates a tool result against the hypothesis that motivated it:

- **Operational success** — did the tool run without error? (A tool returning
  `{"error": ...}` is operational failure.)
- **Evidential status** — did the evidence confirm, refute, or leave
  inconclusive the claim?
  - Artifacts produced → `confirmed` (confidence increases)
  - Empty result → `refuted` (confidence decreases)
  - Tool error → `inconclusive` (we learned nothing about the claim)
  - Ambiguous result → `inconclusive` (no artifacts, not empty)

Terminal statuses (`confirmed`, `refuted`, `exhausted`) stop further work on
that claim — the agent doesn't keep trying a refuted approach.

### Auto-exhaustion

An open/inconclusive hypothesis that has been judged 5+ times without
converging is auto-exhausted to preserve budget. The threshold is
`_EXHAUSTION_THRESHOLD` in `hypothesis.py`.

### The halt signal

`HypothesisStore.all_exhausted(run_id)` returns True when every hypothesis for
a run is terminal. The autonomous loop consults this after each cycle — if
there are no open claims left to test, the run halts with
`stop_reason="all hypotheses exhausted"`. This is the outcome judge's
authority to stop the run, not the model saying DONE.

### Agent tools

- `propose_hypothesis(statement, target, expected_evidence)` — model declares
  what it's testing
- `list_hypotheses(status, limit)` — model queries the ledger
- `score_outcome(hypothesis_id, evidence)` — model provides evidence for the
  judge to evaluate

### SQLite table

```sql
CREATE TABLE IF NOT EXISTS hypotheses (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    cycle INTEGER NOT NULL DEFAULT 0,
    statement TEXT NOT NULL,
    target TEXT,
    tool TEXT,
    arguments_json TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    confidence REAL DEFAULT 0.5,
    evidence_json TEXT,
    expected_evidence TEXT,
    failure_class TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    independent_check_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT,
    judged_at TEXT
)
```

Indexes on `(run_id, cycle)` and `status`.

## Audit chain (`honeywatch/audit.py`)

### The problem

The agent deploys miners, cracks hashes, grabs shadow files, and pivots to
new subnets. An operator needs to prove *what actually ran* on each target.
Without a tamper-evident record, there's no way to distinguish "I ran xmrig
on 10.0.0.5" from "someone tampered with the log to make it look like I did."

### The chain

Every `execute_tool` call appends a record to the `audit_chain` SQLite table.
Each record's `this_hash` is `sha256(canonical_json(record_without_this_hash))`.
Record N+1's `prev_hash` is record N's `this_hash`. The first record's
`prev_hash` is a fixed genesis (`0` * 64).

Verification (`verify_chain()`) re-walks the chain and recomputes every hash.
Any tampering — a modified row, a deleted row, an inserted row — breaks the
chain and is detected with the specific record + reason.

### Credential redaction

Arguments and results are redacted *before* hashing:
- Secret-named args (`password`, `ssh_pass`, `ssh_key`, `token`, etc.) → `***`
- Inline credential shapes (URL `user:pass@`, `--password <v>`,
  `Authorization: Bearer <t>`) → secret portion replaced with `***`
- Nested dicts and lists are recursively redacted

The hash is computed on the redacted form, so the chain is verifiable without
exposing secrets.

### Process-wide continuity

The last hash for each `db_path` is cached in a class-level dict so a new
`AuditStore` instance continues the chain rather than starting a new genesis.
This matters because `chain.py` builds fresh stores per phase.

### Agent tools

- `verify_audit(run_id)` — verify chain integrity (returns valid + reason)
- `get_evidence(target, limit)` — read recent audit records for a target

### SQLite table

```sql
CREATE TABLE IF NOT EXISTS audit_chain (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT,
    session_id TEXT,
    cycle INTEGER,
    timestamp TEXT,
    target_ip TEXT,
    tool TEXT,
    action TEXT,
    arguments_json TEXT,
    result_json TEXT,
    code_sha256 TEXT,
    exit_code INTEGER,
    prev_hash TEXT,
    this_hash TEXT
)
```

Indexes on `(run_id, cycle)` and `target_ip`.

### CLI (planned)

`honeywatch audit verify [--run-id ID]` — standalone chain verification.

## Integration into the agent loop

The autonomous loop (`run_autonomous`) wires the context with `run_id`,
`session_id`, and `cycle` so every hypothesis and audit record is attributed.
Per cycle:

1. **Fleet status** — `_fleet_status()` now shows hypothesis counts
   (open/confirmed/refuted/exhausted) + audit chain status (record count +
   chain valid/broken).
2. **Tool execution** — `execute_tool` wraps every call with an audit record
   (best-effort: an audit failure never breaks the tool).
3. **Halt check** — after each cycle, `all_exhausted(run_id)` is consulted; if
   every hypothesis is terminal, the run halts.

## What this enables

- **Phase 3 (capability graph)** — the graph uses confirmed/refuted
  hypotheses to decide which capabilities are blocked and which are ready.
- **Phase 4 (failure taxonomy)** — the `failure_class` field on each
  hypothesis records the failure classification, driving recovery decisions.
- **Operator accountability** — the audit chain proves what was deployed,
  what was cracked, and what was grabbed, with cryptographic integrity.