# Opsec Model

`honeywatch/opsec.py` + `honeywatch/spray.py` — the tradecraft layer under the
cracker and sprayer. This page is the threat model, the public research it's
grounded in, and the knob that maps to each detection.

The goal is to move honeywatch from "loud red-team scanner" to "quiet blackhat
operator" **without lying about what is and isn't evadable**. Every claim
below has a source; the ones we can't fully close are called out as residual
risk, not hidden.

---

## Threat model (and what defeats each detector)

### 1. SSH client fingerprinting — HASSH / JA4SSH

The client's `SSH_MSG_KEXINIT` algorithm set (kex / host-key / cipher / mac /
compression) is itself a fingerprint. Salesforce's **HASSH** standard hashes
that ordered list; **JA4SSH** does the same. The HASSH documentation explicitly
lists **paramiko, Meterpreter, Empire, and Ruby** as lateral-movement /
brute-force indicators, and Zeek/Suricata rules ship for exactly these.

Spoofing only the version string (`SSH-2.0-OpenSSH_9.0p1 …`, which the engine
already does) defeats the trivial `ssh.protoversion` regex rules but **does
not** change the algorithm fingerprint. paramiko's KEXINIT order is fixed and
distinct from OpenSSH.

**Mitigation (closed):** the sprayer prefers the **real system `ssh` client +
`sshpass`** backend (`honeywatch.opsec.attempt_sshpass`). The KEXINIT the
target sees is then genuine OpenSSH — a real HASSH — so HASSH/JA4SSH detectors
do not flag it as automation tooling. paramiko is the no-extra-deps fallback
and is tagged with `PARAMIKO_HASSH_RISK` whenever it's used so the operator
knows the residual exposure.

**Residual risk:** the `ssh` backend requires `sshpass` + `openssh` on the
operator box (Linux). On Windows, or without sshpass, the engine falls back to
paramiko and inherits the paramiko HASSH. Install sshpass to close it.

Sources: [salesforce/hassh](https://github.com/salesforce/hassh),
[JA4SSH](https://www.threatrelay.com/Quick-Labs/JA4/JA4SSH).

### 2. Rate bans — fail2ban / SSHGuard / CrowdSec + recidive

fail2ban monitors `auth.log`, bans a source IP after `maxretry` failures inside
`findtime` for `bantime`, and a **recidive** jail re-bans repeat offenders for
7–30 days. A steady spray from one IP is banned in minutes; a single Mullvad
exit sprayed at planet scale is globally banned in hours.

**Mitigation (closed):**

- **Source rotation.** `--proxy-file` (a pool of `socks5://…` proxies) and
  `--jump-file` (SSH `ProxyJump` hosts) round-robin so successive attempts
  egress from different IPs. This is the TREVORspray / CredMaster pattern.
  `honeywatch.opsec.ProxyPool` is the selector.
- **Timing.** `--delay` / `--jitter` spread attempts so they don't form a
  clean rate signature inside a `findtime` window; `--lockout-delay` adds an
  extra backoff when an attempt looks like a lockout/ban.
- **Volume.** Spraying is lockout-safe (one password across many users), so a
  host sees *few* attempts per password round — far below typical `maxretry`.

Sources: [fail2ban recidive](https://github.com/fail2ban/fail2ban),
[knavesec/CredMaster](https://github.com/knavesec/CredMaster),
[blacklanternsecurity/TREVORspray](https://github.com/blacklanternsecurity/TREVORspray).

### 3. Account lockout (AD / PAM)

Grid brute force (users × passwords against one host) trips lockout
thresholds almost immediately. The lockout-safe primitive is the **spray**: one
password across many users, then wait out the lockout window, then the next
password.

**Mitigation (closed):** `honeywatch spray` is built around this. One password
per round (`SprayPlan`), `--delay`/`--jitter` between users on the same host,
and `build_password_schedule` lays out successive rounds with a per-password
cooldown so you never hit the same account twice inside a lockout window.

### 4. SOC analyst attention

Off-hours auth bursts are the single loudest thing an analyst hunts. A spray at
03:00 Sunday stands out; the same noise at 10:42 Tuesday blends with organic
logins.

**Mitigation (closed):** `--business-hours` gates attempts to 08:00–18:00 local,
weekdays only (`honeywatch.opsec.within_business_hours`). This is CredMaster's
"WeekdayWarrior" idea — time the spray to when real users are logging in.

### 5. Wasted noise on publickey-only hosts

Spraying a box that advertises only `publickey` auth is pure log pollution — it
can't accept a password, so every attempt is a guaranteed, logged failure that
buys you nothing and raises a count.

**Mitigation (closed):** an **auth-method precheck**
(`honeywatch.opsec.auth_methods`) enumerates the methods the server offers for
the first user, and the sprayer skips any host that doesn't offer `password`.
Disable with `--no-precheck` (e.g. when you want to confirm coverage).

Sources: [SSH auth-method enumeration](https://hackindex.io/services/ssh/enumeration/ssh-authentication-method-enumeration),
[nmap ssh-auth-methods](https://nmap.org/nsedoc/scripts/ssh-auth-methods.html).

### 6. Credential hygiene on the operator + worker

- The worker's password-SSH exec uses `sshpass -e` (env var), not `-p` (argv),
  so recovered passwords never appear in process listings on the worker.
- The cracker's live output masks passwords (`****`); the transcript is
  in-memory only.
- Recovered creds persist to the `credentials` table and auto-feed `deploy`.

**Residual risk:** the `credentials` table is plaintext SQLite. If the
operator box is seized, the keys to the whole fleet come with it. At-rest
encryption (optional `cryptography` extra) is the open item — track it under
the roadmap.

---

## `honeywatch spray`

```text
honeywatch spray [HOSTS...] [options]
```

Lockout-aware password spraying. One password per round across every host's
users; recovered creds persist to the store and auto-feed `deploy`.

| Flag | Default | Purpose |
|---|---|---|
| `--users a,b,c` | built-ins | usernames to spray |
| `--user-file PATH` | — | username list (one per line) |
| `--passwords a,b,c` | sensible defaults | one spray round per password |
| `--password-file PATH` | — | password list |
| `--reuse-creds` | off | spray every recovered password across every discovered host (fleet growth) |
| `--delay S` | 0.0 | seconds between guesses on the same host |
| `--jitter S` | 0.5 | random extra delay (defeats rate signatures) |
| `--lockout-delay S` | 0.0 | extra delay when a guess looks like a lockout/ban |
| `--business-hours` | off | only spray 08:00–18:00 local weekdays |
| `--no-precheck` | off | spray even publickey-only hosts (skip the auth-method precheck) |
| `--proxy-file PATH` | — | `socks5://…` pool to round-robin (source rotation) |
| `--jump-file PATH` | — | `user@host` SSH jumps to round-robin (TREVORspray style) |
| `--host-concurrency N` | 8 | hosts sprayed in parallel |
| `--target-label` / `--min-confidence` / `--target-file` | — | pull hosts from the store |
| `--no-save` | off | don't persist recovered creds |

```bash
# Lockout-safe spray of one strong password across real hosts, business hours,
# rotating through a SOCKS pool so each attempt egresses from a different IP.
honeywatch spray --target-label real --min-confidence 0.8 \
  --passwords 'Summer2024!' --users admin,root,ubuntu \
  --delay 2 --jitter 1 --business-hours \
  --proxy-file proxies.txt --skip-vpn-check

# Fleet growth: re-spray every password you've already recovered across every
# host you've ever discovered (password reuse = botnet growth).
honeywatch spray --reuse-creds --skip-vpn-check
```

---

## The opsec loop, end to end

```
  scan real hosts (masscan/zmap + fingerprint + AI)
        │
        ▼
  spray one password across the fleet   ── HASSH: real OpenSSH (sshpass)
        │                                  ── source: rotating SOCKS/jump pool
        │                                  ── timing: delay+jitter, business-hours
        │                                  ── precheck: skip publickey-only
        ▼
  recovered creds → credentials table (persist, reuse)
        │
        ▼
  crack → grab /etc/shadow → hashcrack (hashcat/john)
        │                                  ── offline, zero target-side noise
        ▼
  more creds → spray --reuse-creds (fleet growth)
        │
        ▼
  deploy xmrig via cracked password (worker sshpass -e)
```

Every arrow has an opsec control attached. The two places that touch the
target (spray, deploy) use the genuine OpenSSH client fingerprint and a rotated
source; the offline cracking (hashcat/john) touches nothing on the target.

---

## What is and isn't evadable — honest list

| Detector | Status |
|---|---|
| Version-string regex (Suricata `ssh.protoversion` for hydra/medusa) | **Closed** — spoofed banner + real `ssh` client; per-target stickiness so repeat connections to one host carry one consistent client banner (per-call randomization to the same host is itself an anomaly) |
| HASSH / JA4SSH client fingerprint | **Closed with sshpass backend; residual with paramiko** |
| fail2ban per-IP rate bans | **Mitigated** — source rotation + low-and-slow; not zero-risk if a proxy pool is thin |
| Account lockout (AD/PAM) | **Closed** — lockout-safe spray cadence |
| SOC off-hours anomaly hunting | **Closed** — `--business-hours` |
| EDR on the target (xmrig process/CPU) | **Not addressed here** — payload-layer concern (rename binary, throttle CPU, persistence) |
| At-rest credential theft (operator box seized) | **Open** — plaintext `credentials` table; roadmap: optional `cryptography` encryption |
| Clearing `/var/log/auth.log` on the target | **Intentionally NOT done** — log clearing is itself a high-signal detection; the answer is not generating the noise, not erasing it |

The last two rows are the honest gaps. The EDR gap lives in the payload layer;
the at-rest gap is a small optional-extra fix. Neither is hidden.