"""SSH banner / KEXINIT fingerprinting over raw asyncio sockets.

Stdlib only at import time. ``paramiko`` is imported lazily, and only for the
optional ``level="full"`` host-key probe.

Implements the server exchange used by the honeywatch confidence scanner:

1. read the server identification string (banner),
2. send our own identification string,
3. read the SSH_MSG_KEXINIT packet (RFC 4253 section 7.1),
4. optionally (level == "full") verify the host key over paramiko.
"""

from __future__ import annotations

import asyncio
import hashlib
import time

from ..models import Fingerprint

CLIENT_BANNER = b"SSH-2.0-honeywatch_0.1\r\n"
MSG_KEXINIT = 20  # RFC 4253 section 7.1: SSH_MSG_KEXINIT
_MAX_PACKET = 1 << 16  # defensive cap on a single SSH packet

# RFC 4253 section 7.1 name-list field order, in the wire order they appear.
_NAME_LIST_KEYS = (
    "kex_algorithms",
    "server_host_key_algorithms",
    "enc_c2s",
    "enc_s2c",
    "mac_c2s",
    "mac_s2c",
    "comp_c2s",
    "comp_s2c",
    "lang_c2s",
    "lang_s2c",
)


def _elapsed_ms(start: float) -> float:
    return (time.perf_counter() - start) * 1000.0


def is_ssh(fp: Fingerprint) -> bool:
    """True when a real SSH identification banner was parsed.

    ``Fingerprint.protocol`` is set only when the banner line began with
    ``SSH-``; a host that answered with an HTTP response, refused the
    connection, or timed out has ``protocol is None``.
    """
    return bool(fp.banner) and fp.protocol is not None


def parse_banner(line: str) -> tuple[str | None, str | None, str | None]:
    """Parse an SSH identification banner into (protocol, software, version).

    ``SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6`` -> ``("2.0", "OpenSSH", "8.9p1")``.
    A line that does not start with ``SSH-`` yields ``(None, None, None)``.
    """
    if not line:
        return (None, None, None)
    stripped = line.strip("\r\n")
    if not stripped.startswith("SSH-"):
        return (None, None, None)
    rest = stripped[len("SSH-"):]
    protocol, _, after = rest.partition("-")
    protocol = protocol or None
    parts = after.split()
    if not parts:
        return (protocol, None, None)
    first = parts[0]
    if "_" in first:
        # OpenSSH-style: software_version joined to the name with an underscore.
        software, version = first.split("_", 1)
    else:
        software = first
        version = parts[1] if len(parts) > 1 else None
    return (protocol, software or None, version or None)


def parse_kexinit(payload: bytes) -> dict:
    """Parse a SSH_MSG_KEXINIT payload per RFC 4253 section 7.1.

    Accepts either the full packet body (1-byte padding length + 1-byte message
    id 20 followed by the cookie) or a payload that starts at the 16-byte cookie.
    Returns as much as can be decoded; never raises on truncated input.
    """
    result: dict = {
        "kex_algorithms": [],
        "server_host_key_algorithms": [],
        "enc_c2s": [],
        "enc_s2c": [],
        "mac_c2s": [],
        "mac_s2c": [],
        "comp_c2s": [],
        "comp_s2c": [],
        "lang_c2s": [],
        "lang_s2c": [],
        "first_kex_packet_follows": 0,
    }
    if not payload:
        return result
    data = payload
    # Strip the transport padding-length byte and the SSH_MSG_KEXINIT id (20)
    # when the caller handed us the whole packet body (the form _read_packet
    # returns). A payload handed in starting at the 16-byte cookie has no such
    # prefix. data[1]==20 alone is ambiguous: a cookie whose second byte happens
    # to be 20 would make us strip two real cookie bytes and corrupt the parse
    # (~1/256 of cookie-start inputs). Disambiguate by also requiring the
    # name-list length that would sit right after the 2-byte prefix + 16-byte
    # cookie to be plausible; if it isn't, treat the input as cookie-start.
    if len(data) >= 18 and data[1] == MSG_KEXINIT:
        looks_like_body = True
        if len(data) >= 22:
            first_len = int.from_bytes(data[18:22], "big")
            looks_like_body = (
                first_len <= _MAX_PACKET and 22 + first_len <= len(data)
            )
        if looks_like_body:
            data = data[2:]
    if len(data) < 16:  # cookie
        return result
    offset = 16
    for key in _NAME_LIST_KEYS:
        if offset + 4 > len(data):
            break
        length = int.from_bytes(data[offset:offset + 4], "big")
        offset += 4
        if length > _MAX_PACKET or offset + length > len(data):
            break
        raw = data[offset:offset + length]
        offset += length
        names = [n for n in raw.decode("utf-8", "replace").split(",") if n]
        result[key] = names
    if offset < len(data):
        result["first_kex_packet_follows"] = data[offset]
    return result


async def _read_banner(reader: asyncio.StreamReader, timeout: float) -> bytes | None:
    """Read the newline-terminated server banner.

    Returns ``None`` on timeout; a partial read is returned as-is so the caller
    can still use whatever bytes arrived.
    """
    try:
        data = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=timeout)
        return data
    except asyncio.IncompleteReadError as exc:
        # EOF before a complete line: keep whatever was sent.
        return exc.partial
    except asyncio.TimeoutError:
        return None
    except asyncio.LimitOverrunError:
        # A misbehaving server sent more than the stream limit with no newline.
        # Hand back whatever is already buffered so the banner is still
        # best-effort parsed, instead of letting the exception escape and
        # violate probe_ssh's never-raises contract.
        try:
            return reader.read_nowait()
        except Exception:
            return None


async def _read_packet(reader: asyncio.StreamReader, timeout: float) -> bytes | None:
    """Read one length-prefixed SSH binary packet body. None on EOF/timeout."""
    try:
        header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError):
        return None
    length = int.from_bytes(header, "big")
    if length <= 0 or length > _MAX_PACKET:
        return None
    try:
        return await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError):
        return None


def _key_bytes(key) -> bytes | None:
    """Extract the raw host-key blob across paramiko API generations."""
    for name in ("as_bytes", "asbytes"):
        fn = getattr(key, name, None)
        if callable(fn):
            try:
                data = fn()
                if isinstance(data, bytes):
                    return data
            except Exception:
                continue
    try:
        data = bytes(key)
        return data if isinstance(data, bytes) else None
    except Exception:
        return None


def _full_probe(fp: Fingerprint, auth_probe: bool, timeout: float) -> dict:
    """Optionally-fatal host-key probe using paramiko (imported lazily).

    Opens its own connection, records host_key_type / host_key_sha256 on the
    fingerprint, and (optionally) attempts a deliberately-wrong password auth.
    Returns an evidence dict; never raises.
    """
    evidence: dict = {}
    try:
        import paramiko  # type: ignore[import-not-found]
    except Exception as exc:
        evidence["full_probe"] = f"paramiko unavailable: {exc!r}"
        return evidence

    transport = None
    try:
        # Create the socket with an explicit connect timeout so a host that
        # blackholes the SYN (rather than refusing) cannot hold a worker thread
        # indefinitely -- paramiko.Transport((host, port)) connects with no
        # timeout of its own.
        import socket as _socket

        deadline = max(6.0, float(timeout))
        sock = _socket.create_connection((fp.ip, fp.port), timeout=deadline)
        sock.settimeout(deadline)
        transport = paramiko.Transport(sock)
        transport.set_timeout(deadline)
        try:
            transport.start_client(timeout=deadline)
        except TypeError:
            # Ancient paramiko without the timeout kwarg.
            transport.start_client()
        key = transport.get_remote_server_key()
        fp.host_key_type = key.get_name()
        blob = _key_bytes(key)
        if blob:
            fp.host_key_sha256 = hashlib.sha256(blob).hexdigest()
        if auth_probe:
            try:
                transport.auth_password("honeywatch_probe_xz9", "wrong-pass-12345")
                evidence["auth_password_accepted"] = True
            except Exception as exc:
                evidence["auth_password_accepted"] = False
                evidence["auth_password_error"] = f"{exc!r}"
    except Exception as exc:
        evidence["full_probe"] = f"{exc!r}"
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
    return evidence


async def probe_ssh(
    ip: str,
    port: int = 22,
    level: str = "fast",
    timeout: float = 6.0,
    auth_probe: bool = False,
) -> Fingerprint:
    """Probe a single SSH endpoint and return a Fingerprint.

    ``level="fast"`` performs the raw banner + KEXINIT exchange only;
    ``level="full"`` additionally extracts the host key (via paramiko) and,
    when ``auth_probe`` is set, records whether a deliberately wrong password
    was accepted.

    .. note:: The ``level="full"`` host key and auth-probe evidence are gathered
       on a *second* TCP connection (paramiko owns that handshake end-to-end),
       while the banner + KEXINIT algorithm lists come from the first raw
       connection. The two are blended into one :class:`Fingerprint`. For a
       single backend host this is fine; behind a load balancer the second
       connection may hit a different real server, so ``host_key_sha256`` and
       ``kex_algorithms`` could describe different nodes. Callers that need a
       guaranteed single-session view should drive paramiko end-to-end instead
       of mixing the two transports here.

    Never raises; the outcome is described by ``Fingerprint.error`` in
    ``{"no_banner", "connection_refused", "timeout", "error:<repr>"}``.
    """
    fp = Fingerprint(ip=ip, port=port)
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
    except asyncio.TimeoutError:
        fp.connect_ms = _elapsed_ms(start)
        fp.error = "timeout"
        return fp
    except ConnectionRefusedError:
        fp.connect_ms = _elapsed_ms(start)
        fp.error = "connection_refused"
        return fp
    except OSError as exc:
        fp.connect_ms = _elapsed_ms(start)
        fp.error = f"error:{exc!r}"
        return fp

    fp.connect_ms = _elapsed_ms(start)
    evidence: dict = {}
    try:
        banner_at = time.perf_counter()
        banner_raw = await _read_banner(reader, timeout)
        if banner_raw is None:
            fp.error = "timeout"
            return fp
        fp.time_to_banner_ms = _elapsed_ms(start)
        banner = banner_raw.decode("utf-8", "replace").strip("\r\n")
        if not banner:
            fp.error = "no_banner"
            return fp
        fp.banner = banner
        fp.protocol, fp.software, fp.software_version = parse_banner(banner)

        writer.write(CLIENT_BANNER)
        await writer.drain()

        # Read packets until we hit an SSH_MSG_KEXINIT (or run out of tries).
        kex_body: bytes | None = None
        for _ in range(4):
            body = await _read_packet(reader, timeout)
            if body is None:
                break
            if len(body) >= 2 and body[1] == MSG_KEXINIT:
                kex_body = body
                break
        if kex_body is not None:
            fp.banner_ms = (time.perf_counter() - banner_at) * 1000.0
            kdata = parse_kexinit(kex_body)
            fp.kex_algorithms = kdata["kex_algorithms"]
            fp.server_host_key_algorithms = kdata["server_host_key_algorithms"]
            fp.enc_c2s = kdata["enc_c2s"]
            fp.enc_s2c = kdata["enc_s2c"]
            fp.mac_c2s = kdata["mac_c2s"]
            fp.mac_s2c = kdata["mac_s2c"]
            fp.comp_c2s = kdata["comp_c2s"]
            fp.comp_s2c = kdata["comp_s2c"]

        if level == "full":
            evidence = await asyncio.to_thread(_full_probe, fp, auth_probe, timeout)
            if evidence:
                fp.evidence = evidence
    except asyncio.TimeoutError:
        fp.error = fp.error or "timeout"
    except Exception as exc:
        fp.error = fp.error or f"error:{exc!r}"
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return fp


async def probe_many(
    ips: list[str],
    port: int = 22,
    level: str = "fast",
    timeout: float = 6.0,
    auth_probe: bool = False,
    concurrency: int = 512,
    on_result=None,
) -> list[Fingerprint]:
    """Probe many IPs concurrently, bounded by a semaphore.

    ``on_result`` (if given) is invoked per completed Fingerprint; all results
    are still collected and returned in input order.
    """
    sem = asyncio.Semaphore(concurrency)

    async def probe_one(ip: str) -> Fingerprint:
        async with sem:
            fp = await probe_ssh(
                ip, port=port, level=level, timeout=timeout, auth_probe=auth_probe
            )
        if on_result is not None:
            try:
                on_result(fp)
            except Exception:
                pass
        return fp

    return list(await asyncio.gather(*(probe_one(ip) for ip in ips)))
