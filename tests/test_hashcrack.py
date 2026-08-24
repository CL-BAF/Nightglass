"""Tests for the offline hash-cracking layer (hashcat / john).

The shadow parsing + type detection paths are tested against real /etc/shadow
syntax. The tool runners are exercised with a fake ``hashcat``/``john`` shell
script written to a temp dir so the subprocess plumbing is covered without
requiring the real binaries.
"""

from __future__ import annotations

import os
import platform
import stat
import sys

import pytest

from honeywatch.hashcrack import (
    HashCrackResult,
    detect_hash_type,
    parse_shadow,
)


# --------------------------------------------------------------------------- #
# Type detection
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "prefix,expected_mode,expected_family",
    [
        ("$6$rounds=5000$salt$hash", 1800, "sha512crypt"),
        ("$5$salt$hash", 7400, "sha256crypt"),
        ("$1$salt$hash", 500, "md5crypt"),
        ("$2b$05$saltsaltsaltsaltsaltsalthashhashhashhashhashhashhash", 3200, "bcrypt"),
        ("$y$j9T$salt$hash", 22500, "yescrypt"),
    ],
)
def test_detect_hash_type(prefix, expected_mode, expected_family):
    mode, fmt, family = detect_hash_type(prefix)
    assert mode == expected_mode
    assert family == expected_family
    assert fmt != ""


def test_detect_hash_type_unknown():
    mode, fmt, family = detect_hash_type("not-a-hash")
    assert mode is None
    assert family == ""
    assert fmt == ""


def test_detect_legacy_des_crypt():
    mode, fmt, family = detect_hash_type("aBcDeFgHiJkLm")
    assert mode == 1500
    assert family == "descrypt"


# --------------------------------------------------------------------------- #
# Shadow parsing
# --------------------------------------------------------------------------- #


SHADOW_SAMPLE = """# comment line
root:$6$rounds=5000$saltsalt$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:19000:0:99999:7:::
locked:!:19000:0:99999:7:::
nobody:*:19000:0:99999:7:::
empty::19000:0:99999:7:::
flag:^rootpassword:19000:0:99999:7:::
admin:$1$abc$bbbbbbbbbbbbbbbbbbbbbbbb:19000:0:99999:7:::
service:$5$cccccccccccccccccccccccccccccccccccccccccccccccccccccc:19000:0:99999:7:::
""".strip()


def test_parse_shadow_skips_locked_empty_and_flags():
    entries = parse_shadow(SHADOW_SAMPLE)
    users = [e.user for e in entries]
    # locked/empty/* and the ^ flag row are all skipped.
    assert users == ["root", "admin", "service"]


def test_parse_shadow_records_detected_family():
    entries = {e.user: e for e in parse_shadow(SHADOW_SAMPLE)}
    assert entries["root"].family == "sha512crypt"
    assert entries["root"].hashcat_mode == 1800
    assert entries["admin"].family == "md5crypt"
    assert entries["admin"].hashcat_mode == 500
    assert entries["service"].family == "sha256crypt"


def test_parse_shadow_empty_returns_empty_list():
    assert parse_shadow("") == []
    assert parse_shadow("# only a comment\n") == []


# --------------------------------------------------------------------------- #
# Tool runners with a fake binary
# --------------------------------------------------------------------------- #


def _write_fake_hashcat(tmp_path, recovered: dict[str, str]):
    """Write a fake `hashcat` that prints recovered hashes on --show.

    Cross-platform: a batch file on Windows (subprocess can exec .bat directly),
    an executable shell script on POSIX. The production hashcrack runner shells
    out to the real binary; this fake exercises the subprocess plumbing without
    requiring hashcat to be installed.
    """
    if platform.system() == "Windows":
        fake = tmp_path / "hashcat.bat"
        lines = [f'echo {h}:{p}' for h, p in recovered.items()]
        fake.write_text(
            "@echo off\n"
            "setlocal enabledelayedexpansion\n"
            "set SHOW=0\n"
            ":lp\n"
            'if "%~1"=="--show" set SHOW=1\n'
            "shift\n"
            'if not "%~1"=="" goto lp\n'
            'if "%SHOW%"=="1" (\n'
            + "\n".join(lines) + "\n"
            ")\n"
            "exit /b 0\n",
            encoding="utf-8",
        )
    else:
        fake = tmp_path / "hashcat"
        fake.write_text(
            "#!/bin/sh\n"
            'for a in "$@"; do [ "$a" = "--show" ] && {\n'
            + "".join(f'  echo "{h}:{p}"\n' for h, p in recovered.items())
            + "  exit 0\n"
            "}; done\n"
            "exit 0\n",
            encoding="utf-8",
        )
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(fake)


def _write_fake_john(tmp_path, recovered: dict[str, str]):
    """Write a fake `john` that prints user:password on --show."""
    if platform.system() == "Windows":
        fake = tmp_path / "john.bat"
        lines = [f'echo {u}:{p}:::' for u, p in recovered.items()]
        fake.write_text(
            "@echo off\n"
            'if "%~1"=="--show" (\n'
            + "\n".join(lines) + "\n"
            + 'echo 0g 0:passwords cracked \n'
            ")\n"
            "exit /b 0\n",
            encoding="utf-8",
        )
    else:
        fake = tmp_path / "john"
        fake.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "--show" ]; then\n'
            + "".join(f'echo "{u}:{p}:::"\n' for u, p in recovered.items())
            + 'echo "0g 0:passwords cracked "\n'
            "exit 0\n"
            "fi\n"
            "exit 0\n",
            encoding="utf-8",
        )
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(fake)


def _sha512_hash():
    # A real-shape $6$ hash (content is not a valid crypt, but the parser only
    # checks the prefix; the fake binary echoes it back verbatim).
    return "$6$rounds=5000$saltsalt$" + "a" * 86


def test_crack_with_hashcat_recovers(monkeypatch, tmp_path):
    from honeywatch.hashcrack import ShadowEntry, crack_with_hashcat

    h = _sha512_hash()
    entries = [ShadowEntry(user="root", hash=h, hashcat_mode=1800,
                            john_format="sha512crypt", family="sha512crypt")]
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("letmein\n", encoding="utf-8")

    fake = _write_fake_hashcat(tmp_path, {h: "letmein"})
    res = crack_with_hashcat(entries, str(wordlist), mode=1800, bin_path=fake,
                             timeout_s=10)
    assert res.error is None
    assert res.success_count == 1
    assert res.cracked[0].password == "letmein"
    assert res.cracked[0].user == "root"


def test_crack_with_john_recovers(monkeypatch, tmp_path):
    from honeywatch.hashcrack import ShadowEntry, crack_with_john

    h = _sha512_hash()
    entries = [ShadowEntry(user="root", hash=h, hashcat_mode=1800,
                            john_format="sha512crypt", family="sha512crypt")]
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("letmein\n", encoding="utf-8")

    fake = _write_fake_john(tmp_path, {"root": "letmein"})
    res = crack_with_john(entries, str(wordlist), bin_path=fake, timeout_s=10)
    assert res.error is None
    assert res.success_count == 1
    assert res.cracked[0].password == "letmein"


def test_crack_shadow_missing_wordlist(tmp_path):
    from honeywatch.hashcrack import crack_shadow

    shadow = tmp_path / "shadow"
    shadow.write_text("root:" + _sha512_hash() + ":19000::::::\n")
    res = crack_shadow(str(shadow), str(tmp_path / "nope.txt"), tool="hashcat")
    assert res.error and "wordlist not found" in res.error


def test_crack_shadow_missing_binary(tmp_path):
    from honeywatch.hashcrack import crack_shadow

    shadow = tmp_path / "shadow"
    shadow.write_text("root:" + _sha512_hash() + ":19000::::::\n")
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("x\n", encoding="utf-8")
    res = crack_shadow(str(shadow), str(wordlist), tool="hashcat",
                       bin_path=str(tmp_path / "no_such_hashcat"))
    assert res.error and "not found" in res.error


def test_crack_shadow_mixed_families(tmp_path):
    """Mixed crypt families are split into per-family runs."""
    from honeywatch.hashcrack import crack_shadow

    h6 = "$6$salt$" + "a" * 86
    h1 = "$1$salt$bbbbbbbbbbbbbbbbbbbbbbbb"
    shadow = tmp_path / "shadow"
    shadow.write_text(
        f"root:{h6}:19000::::::\nadmin:{h1}:19000::::::\n", encoding="utf-8"
    )
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("x\n", encoding="utf-8")

    fake = _write_fake_hashcat(tmp_path, {h6: "pw6", h1: "pw1"})
    res = crack_shadow(str(shadow), str(wordlist), tool="hashcat",
                       bin_path=fake, timeout_s=10)
    # Both families cracked (two separate hashcat calls, both echoed back).
    assert res.error is None
    assert res.success_count == 2
    creds = {c.user: c.password for c in res.cracked if c.success}
    assert creds == {"root": "pw6", "admin": "pw1"}


def test_hashcrack_result_credentials():
    from honeywatch.hashcrack import CrackedHash, HashCrackResult

    r = HashCrackResult(tool="hashcat")
    r.cracked = [
        CrackedHash(user="root", hash="h", password="pw", success=True),
        CrackedHash(user="x", hash="h2", success=False),
    ]
    assert r.success_count == 1
    assert r.credentials() == [{"user": "root", "password": "pw", "hash": "h"}]