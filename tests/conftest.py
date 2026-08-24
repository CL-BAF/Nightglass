"""Shared helpers and fixtures for the honeywatch test suite."""

from __future__ import annotations

import pytest

from honeywatch.fingerprint.probe import parse_banner
from honeywatch.models import Fingerprint

# RFC 4253 section 12 message numbers.
SSH_MSG_KEXINIT = 20  # NOT 5; 5 is SSH_MSG_SERVICE_REQUEST.


def craft_banner(software: str, version: str, protocol: str = "2.0") -> bytes:
    """Build an SSH identification line like ``b"SSH-2.0-OpenSSH_9.3p1\\r\\n"``.

    ``software`` may include the trailing underscore for OpenSSH-style banners
    (e.g. ``"OpenSSH_"``) so the software/version split works exactly as a
    real server presents it.
    """
    return f"SSH-{protocol}-{software}{version}\r\n".encode("ascii")


def build_kexinit_packet(
    kex_algorithms: list[str] | None = None,
    host_key_algorithms: list[str] | None = None,
    enc_c2s: list[str] | None = None,
    enc_s2c: list[str] | None = None,
    mac_c2s: list[str] | None = None,
    mac_s2c: list[str] | None = None,
    comp_c2s: list[str] | None = None,
    comp_s2c: list[str] | None = None,
    lang_c2s: list[str] | None = None,
    lang_s2c: list[str] | None = None,
    cookie: bytes = b"\x00" * 16,
    first_kex_packet_follows: int = 0,
    reserved: bytes = b"\x00\x00\x00\x00",
    include_msg_id: bool = True,
) -> bytes:
    """Return valid RFC 4253 SSH_MSG_KEXINIT packet bytes.

    The wire order follows RFC 4253 section 7.1: 16-byte cookie, ten name
    lists (kex, host keys, enc, mac, comp, lang in c2s/s2c pairs), the
    ``boolean first_kex_packet_follows`` byte and a 4-byte ``uint32``
    reserved field.

    With ``include_msg_id=True`` (default) the bytes begin with the transport
    packet-body prefix a server sends on the wire: a 1-byte padding length
    followed by the SSH_MSG_KEXINIT message number (20). With
    ``include_msg_id=False`` the bytes start at the 16-byte cookie.
    """
    body = cookie
    body += _ssh_name_bytes(kex_algorithms or [])
    body += _ssh_name_bytes(host_key_algorithms or [])
    body += _ssh_name_bytes(enc_c2s or [])
    body += _ssh_name_bytes(enc_s2c or [])
    body += _ssh_name_bytes(mac_c2s or [])
    body += _ssh_name_bytes(mac_s2c or [])
    body += _ssh_name_bytes(comp_c2s or [])
    body += _ssh_name_bytes(comp_s2c or [])
    body += _ssh_name_bytes(lang_c2s or [])
    body += _ssh_name_bytes(lang_s2c or [])
    body += bytes([first_kex_packet_follows & 0xFF])
    body += (reserved or b"\x00\x00\x00\x00")[:4]
    if not include_msg_id:
        return body
    # Transport packet body prefix: byte padding_length + SSH_MSG_KEXINIT id.
    return bytes([8, SSH_MSG_KEXINIT]) + body


def _ssh_name_bytes(names: list[str]) -> bytes:
    """RFC 4253 string encoding: uint32 length + comma-joined names."""
    raw = ",".join(names).encode("ascii")
    return len(raw).to_bytes(4, "big") + raw


def real_openssh_fp() -> Fingerprint:
    """A realistic OpenSSH 9.3 server fingerprint (banner + KEXINIT lists).

    Modern cipher/MAC/kex suite: chacha20-poly1305, AES-CTR/GCM, curve25519,
    etm MACs — nothing that should trip the honeypot heuristics.
    """
    banner = craft_banner("OpenSSH_", "9.3p1").decode("ascii")
    protocol, software, version = parse_banner(banner)
    return Fingerprint(
        ip="203.0.113.7",
        port=22,
        banner=banner,
        protocol=protocol,
        software=software,
        software_version=version,
        kex_algorithms=[
            "sntrup761x25519-sha512@openssh.com",
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
            "diffie-hellman-group-exchange-sha256",
            "diffie-hellman-group16-sha512",
            "diffie-hellman-group18-sha512",
            "diffie-hellman-group14-sha256",
        ],
        server_host_key_algorithms=[
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
            "ssh-rsa",
            "rsa-sha2-512",
            "rsa-sha2-256",
        ],
        enc_c2s=[
            "chacha20-poly1305@openssh.com",
            "aes128-ctr",
            "aes192-ctr",
            "aes256-ctr",
            "aes128-gcm@openssh.com",
            "aes256-gcm@openssh.com",
        ],
        enc_s2c=[
            "chacha20-poly1305@openssh.com",
            "aes128-ctr",
            "aes192-ctr",
            "aes256-ctr",
            "aes128-gcm@openssh.com",
            "aes256-gcm@openssh.com",
        ],
        mac_c2s=[
            "umac-64-etm@openssh.com",
            "umac-128-etm@openssh.com",
            "hmac-sha2-256-etm@openssh.com",
            "hmac-sha2-512-etm@openssh.com",
            "hmac-sha2-256",
            "hmac-sha2-512",
        ],
        mac_s2c=[
            "umac-64-etm@openssh.com",
            "umac-128-etm@openssh.com",
            "hmac-sha2-256-etm@openssh.com",
            "hmac-sha2-512-etm@openssh.com",
            "hmac-sha2-256",
            "hmac-sha2-512",
        ],
        comp_c2s=["none", "zlib@openssh.com"],
        comp_s2c=["none", "zlib@openssh.com"],
        connect_ms=24.3,
        banner_ms=1.9,
    )


def cowrie_like_fp() -> Fingerprint:
    """A COWRIE honeypot masquerading as an ancient OpenSSH 5.1 server.

    Old CBC ciphers (3des-cbc, arcfour), hmac-md5 MACs, no chacha, and a
    weak ssh-dss host key — the classic honeypot signal set.
    """
    banner = craft_banner("OpenSSH_", "5.1p1").decode("ascii")
    protocol, software, version = parse_banner(banner)
    return Fingerprint(
        ip="198.51.100.42",
        port=22,
        banner=banner,
        protocol=protocol,
        software=software,
        software_version=version,
        kex_algorithms=[
            "diffie-hellman-group-exchange-sha256",
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group1-sha1",
        ],
        server_host_key_algorithms=["ssh-dss", "ssh-rsa"],
        enc_c2s=["aes128-cbc", "3des-cbc", "aes256-cbc", "arcfour"],
        enc_s2c=["aes128-cbc", "3des-cbc", "aes256-cbc", "arcfour"],
        mac_c2s=["hmac-md5", "hmac-sha1"],
        mac_s2c=["hmac-md5", "hmac-sha1"],
        comp_c2s=["none"],
        comp_s2c=["none"],
        host_key_type="ssh-dss",
        connect_ms=1.2,
    )


@pytest.fixture
def openssh_fp() -> Fingerprint:
    return real_openssh_fp()


@pytest.fixture
def cowrie_fp() -> Fingerprint:
    return cowrie_like_fp()
