"""Tests for banner parsing and KEXINIT decoding."""

from __future__ import annotations

from conftest import SSH_MSG_KEXINIT, build_kexinit_packet, craft_banner

from honeywatch.fingerprint.probe import parse_banner, parse_kexinit


# ---------------------------------------------------------------------------
# parse_banner
# ---------------------------------------------------------------------------

def test_parse_banner_normal_openssh():
    raw = craft_banner("OpenSSH_", "9.3p1")
    assert parse_banner(raw.decode("ascii")) == ("2.0", "OpenSSH", "9.3p1")


def test_parse_banner_with_comment_after_version():
    banner = "SSH-2.0-OpenSSH_9.3p1 Ubuntu-9.3.0"
    assert parse_banner(banner) == ("2.0", "OpenSSH", "9.3p1")


def test_parse_banner_ssh_1_99():
    assert parse_banner("SSH-1.99-OpenSSH_8.9p1") == ("1.99", "OpenSSH", "8.9p1")


def test_parse_banner_software_without_version():
    assert parse_banner("SSH-2.0-dropbear") == ("2.0", "dropbear", None)


def test_parse_banner_version_separate_token():
    # No underscore: software and version split on whitespace.
    assert parse_banner("SSH-2.0-TestSoft 1.2.3") == ("2.0", "TestSoft", "1.2.3")


def test_parse_banner_garbage():
    assert parse_banner("Not an SSH banner at all") == (None, None, None)


def test_parse_banner_empty():
    assert parse_banner("") == (None, None, None)
    assert parse_banner("   ") == (None, None, None)


def test_parse_banner_strips_crlf():
    assert parse_banner("SSH-2.0-OpenSSH_8.9p1\r\n") == ("2.0", "OpenSSH", "8.9p1")


# ---------------------------------------------------------------------------
# parse_kexinit
# ---------------------------------------------------------------------------

KEX = ["curve25519-sha256", "ecdh-sha2-nistp256"]
HOST_KEYS = ["ssh-ed25519", "ssh-rsa"]
ENC = ["chacha20-poly1305@openssh.com", "aes128-ctr"]
MACS = ["hmac-sha2-256-etm@openssh.com"]
COMP = ["none", "zlib@openssh.com"]


def _standard_lists():
    return dict(
        kex_algorithms=KEX,
        host_key_algorithms=HOST_KEYS,
        enc_c2s=ENC,
        enc_s2c=ENC,
        mac_c2s=MACS,
        mac_s2c=MACS,
        comp_c2s=COMP,
        comp_s2c=COMP,
    )


def test_parse_kexinit_empty_input():
    result = parse_kexinit(b"")
    assert result["kex_algorithms"] == []
    assert result["server_host_key_algorithms"] == []
    assert result["first_kex_packet_follows"] == 0


def test_parse_kexinit_roundtrip_cookie_start():
    """A payload starting at the 16-byte cookie round-trips cleanly."""
    packet = build_kexinit_packet(
        **_standard_lists(),
        lang_c2s=["en-US"],
        first_kex_packet_follows=1,
        include_msg_id=False,
    )
    parsed = parse_kexinit(packet)
    assert parsed["kex_algorithms"] == KEX
    assert parsed["server_host_key_algorithms"] == HOST_KEYS
    assert parsed["enc_c2s"] == ENC
    assert parsed["enc_s2c"] == ENC
    assert parsed["mac_c2s"] == MACS
    assert parsed["mac_s2c"] == MACS
    assert parsed["comp_c2s"] == COMP
    assert parsed["comp_s2c"] == COMP
    assert parsed["lang_c2s"] == ["en-US"]
    assert parsed["lang_s2c"] == []
    assert parsed["first_kex_packet_follows"] == 1


def test_parse_kexinit_roundtrip_full_rfc4253_packet():
    """A complete RFC 4253 KEXINIT packet body (padding + msg id 20) parses.

    This is the exact shape ``probe_ssh._read_packet`` returns from a real
    SSH server. If the honeywatch ``MSG_KEXINIT`` constant is wrong (5 instead
    of RFC 4253's 20), the parser fails to strip the packet prefix and the
    name lists come back empty.
    """
    packet = build_kexinit_packet(**_standard_lists())
    parsed = parse_kexinit(packet)
    assert parsed["kex_algorithms"] == KEX
    assert parsed["server_host_key_algorithms"] == HOST_KEYS
    assert parsed["enc_c2s"] == ENC
    assert parsed["enc_s2c"] == ENC
    assert parsed["mac_c2s"] == MACS
    assert parsed["mac_s2c"] == MACS
    assert parsed["comp_c2s"] == COMP
    assert parsed["comp_s2c"] == COMP


def test_rfc4253_kexinit_message_number():
    """SSH_MSG_KEXINIT must be 20 per RFC 4253, not 5."""
    from honeywatch.fingerprint import probe as probe_mod

    assert probe_mod.MSG_KEXINIT == SSH_MSG_KEXINIT
