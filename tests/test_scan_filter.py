"""Tests for SSH-only result filtering (is_ssh + pipeline probe filter)."""

from __future__ import annotations

import asyncio

from honeywatch.config import Config
from honeywatch.fingerprint.probe import is_ssh
from honeywatch.models import Fingerprint, HostHit
from honeywatch.pipeline import Pipeline


def _fp(ip, banner=None, protocol=None, error=None):
    return Fingerprint(ip=ip, port=22, banner=banner, protocol=protocol, error=error)


def test_is_ssh_true_for_ssh_banner():
    assert is_ssh(_fp("1.2.3.4", banner="SSH-2.0-OpenSSH_8.9p1", protocol="2.0"))


def test_is_ssh_false_for_http_banner():
    assert not is_ssh(_fp("1.2.3.4", banner="HTTP/1.1 400 Bad Request"))


def test_is_ssh_false_when_unreachable():
    assert not is_ssh(_fp("1.2.3.4", error="timeout"))


def test_is_ssh_false_when_no_banner():
    assert not is_ssh(_fp("1.2.3.4"))


def test_probe_hosts_drops_non_ssh_by_default(monkeypatch):
    import honeywatch.pipeline as pipe_mod

    ssh = _fp("1.1.1.1", banner="SSH-2.0-OpenSSH_8.9p1", protocol="2.0")
    http = _fp("2.2.2.2", banner="HTTP/1.1 200 OK")
    refused = _fp("3.3.3.3", error="connection_refused")

    async def fake_probe_many(ips, **kwargs):
        return [f for f in (ssh, http, refused) if f.ip in ips]

    monkeypatch.setattr(pipe_mod, "probe_many", fake_probe_many)
    pipe = Pipeline(Config({"scan": {"only_ssh": True}, "probe": {}}))
    hits = [HostHit(ip=f.ip, port=22) for f in (ssh, http, refused)]
    out = asyncio.run(pipe.probe_hosts(hits))
    assert out == [ssh]


def test_probe_hosts_keeps_all_when_filter_disabled(monkeypatch):
    import honeywatch.pipeline as pipe_mod

    ssh = _fp("1.1.1.1", banner="SSH-2.0-OpenSSH_8.9p1", protocol="2.0")
    http = _fp("2.2.2.2", banner="HTTP/1.1 200 OK")

    async def fake_probe_many(ips, **kwargs):
        return [f for f in (ssh, http) if f.ip in ips]

    monkeypatch.setattr(pipe_mod, "probe_many", fake_probe_many)
    pipe = Pipeline(Config({"scan": {"only_ssh": False}, "probe": {}}))
    hits = [HostHit(ip=f.ip, port=22) for f in (ssh, http)]
    out = asyncio.run(pipe.probe_hosts(hits))
    assert out == [ssh, http]


def test_probe_hosts_defaults_to_ssh_only(monkeypatch):
    import honeywatch.pipeline as pipe_mod

    ssh = _fp("1.1.1.1", banner="SSH-2.0-OpenSSH_8.9p1", protocol="2.0")
    http = _fp("2.2.2.2", banner="HTTP/1.1 200 OK")

    async def fake_probe_many(ips, **kwargs):
        return [f for f in (ssh, http) if f.ip in ips]

    monkeypatch.setattr(pipe_mod, "probe_many", fake_probe_many)
    pipe = Pipeline(Config({"probe": {}}))  # no scan section -> default true
    hits = [HostHit(ip=f.ip, port=22) for f in (ssh, http)]
    out = asyncio.run(pipe.probe_hosts(hits))
    assert out == [ssh]
