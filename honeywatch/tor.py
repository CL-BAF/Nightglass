"""Tor SOCKS5 proxy integration for honeywatch.

Provides a :class:`TorProxy` that wraps a local Tor process (or an existing
Tor control port) into a SOCKS5 proxy that :class:`ProxyPool` can rotate
through. Circuit rotation via the Tor control port gives each rotation a
fresh exit IP — the same pattern TREVORspray / CredMaster use for
per-attempt source rotation.

The design is intentionally lightweight: no dependency on ``stem`` or
``txtorcon``. The control protocol is three lines of socket I/O
(``AUTHENTICATE``, ``SIGNAL NEWNYM``, ``QUIT``). The SOCKS5 proxy is the
same ``socks5://127.0.0.1:<port>`` string ProxyPool already accepts.

Usage::

    from honeywatch.tor import TorProxy

    tor = TorProxy(socks_port=9050, control_port=9051)
    await tor.start()              # spawn tor if not running
    proxy_url = tor.socks_url()   # "socks5://127.0.0.1:9050"
    await tor.rotate()            # SIGNAL NEWNYM -> fresh circuit
    await tor.stop()              # graceful shutdown

Synchronous equivalents (``start_sync``, ``rotate_sync``, ``stop_sync``)
are provided for the non-async code paths (crack, spray).
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess
import time
from dataclasses import dataclass, field

__all__ = ["TorProxy"]

logger = logging.getLogger(__name__)

_TOR_BIN = "tor"


@dataclass
class TorProxy:
    """Manage a local Tor SOCKS5 proxy with circuit rotation.

    Parameters
    ----------
    socks_port : int
        Tor SOCKS5 listen port (default 9050 — Tor's default).
    control_port : int
        Tor control port (default 9051 — Tor's default).
    control_password : str
        Password for the Tor control port. Empty = cookie or
        unauthenticated (common on Debian/Tor Browser).
    tor_bin : str
        Path to the ``tor`` binary. Default ``"tor"`` (uses $PATH).
    auto_start : bool
        If True, :meth:`start` spawns a Tor subprocess when one isn't
        already listening on ``socks_port``.
    rotate_delay : float
        Seconds to sleep after ``SIGNAL NEWNYM`` before using the new
        circuit. Tor needs a moment to build a fresh circuit; 1.0s is
        conservative. Lower values risk reusing the old circuit.
    """

    socks_port: int = 9050
    control_port: int = 9051
    control_password: str = ""
    tor_bin: str = _TOR_BIN
    auto_start: bool = True
    rotate_delay: float = 1.0

    _process: subprocess.Popen | None = field(default=None, init=False, repr=False)
    _started_by_us: bool = field(default=False, init=False, repr=False)

    def socks_url(self) -> str:
        """Return the SOCKS5 proxy URL for :class:`ProxyPool` rotation."""
        return f"socks5://127.0.0.1:{self.socks_port}"

    async def start(self) -> None:
        """Ensure a Tor proxy is listening on ``socks_port``.

        If a proxy is already reachable, this is a no-op. When
        ``auto_start`` is True and ``tor`` is found on $PATH, a Tor
        subprocess is spawned with the right ports. Raises
        ``RuntimeError`` if Tor cannot be started.
        """
        if await self._is_listening():
            logger.debug("Tor already listening on port %d", self.socks_port)
            return
        if not self.auto_start:
            raise RuntimeError(
                f"Tor not listening on port {self.socks_port} and auto_start=False"
            )
        tor_path = shutil.which(self.tor_bin)
        if tor_path is None:
            raise RuntimeError(
                f"Tor binary '{self.tor_bin}' not found on $PATH; "
                f"install Tor or set tor_bin= to the full path"
            )
        logger.info("Starting Tor: socks_port=%d control_port=%d",
                     self.socks_port, self.control_port)
        self._process = subprocess.Popen(
            [
                tor_path,
                "--SocksPort", str(self.socks_port),
                "--ControlPort", str(self.control_port),
                "--CookieAuthentication", "0",
                "--Log", "notice stdout",
                "--Quiet",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._started_by_us = True
        # Wait up to 30s for Tor to bootstrap.
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            await asyncio.sleep(0.5)
            if await self._is_listening():
                logger.info("Tor ready on port %d", self.socks_port)
                return
            if self._process.poll() is not None:
                raise RuntimeError(
                    f"Tor process exited with rc={self._process.returncode}"
                )
        raise RuntimeError(f"Tor did not start listening on port {self.socks_port} within 30s")

    def start_sync(self) -> None:
        """Synchronous wrapper for :meth:`start`."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                pool.submit(lambda: asyncio.run(self.start())).result()
        else:
            asyncio.run(self.start())

    async def rotate(self) -> None:
        """Send ``SIGNAL NEWNYM`` to the Tor control port to build a fresh circuit.

        After sending NEWNYM, sleeps ``rotate_delay`` seconds to let the
        new circuit stabilize before the next connection uses it.
        """
        await self._send_control("SIGNAL NEWNYM")
        logger.debug("Sent NEWNYM, sleeping %.1fs for circuit rotation", self.rotate_delay)
        await asyncio.sleep(self.rotate_delay)

    def rotate_sync(self) -> None:
        """Synchronous wrapper for :meth:`rotate`."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                pool.submit(lambda: asyncio.run(self.rotate())).result()
        else:
            asyncio.run(self.rotate())

    async def stop(self) -> None:
        """Stop the Tor subprocess if we started it."""
        if self._process and self._started_by_us:
            logger.info("Stopping Tor process (pid %d)", self._process.pid)
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None
            self._started_by_us = False

    def stop_sync(self) -> None:
        """Synchronous wrapper for :meth:`stop`."""
        if self._process and self._started_by_us:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None
            self._started_by_us = False

    async def _is_listening(self) -> bool:
        """Check if a SOCKS5 proxy is reachable on ``socks_port``."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", self.socks_port),
                timeout=2.0,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (OSError, asyncio.TimeoutError):
            return False

    async def _send_control(self, command: str) -> str:
        """Send a command to the Tor control port and return the response.

        The Tor control protocol is line-oriented: send a command, read
        until ``<code> <status>``, e.g. ``250 OK``. Authentication uses
        ``AUTHENTICATE "<password>"`` or ``AUTHENTICATE`` for
        unauthenticated/cookie access.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", self.control_port),
                timeout=5.0,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            raise RuntimeError(
                f"Cannot connect to Tor control port {self.control_port}: {exc}"
            ) from exc
        try:
            if self.control_password:
                auth_cmd = f'AUTHENTICATE "{self.control_password}"\r\n'
            else:
                auth_cmd = "AUTHENTICATE\r\n"
            writer.write(auth_cmd.encode("utf-8"))
            await writer.drain()
            auth_resp = await asyncio.wait_for(reader.readline(), timeout=5.0)
            auth_line = auth_resp.decode("utf-8", errors="replace").strip()
            if not auth_line.startswith("250"):
                raise RuntimeError(f"Tor AUTHENTICATE failed: {auth_line}")

            writer.write(f"{command}\r\n".encode("utf-8"))
            await writer.drain()
            # Read response lines until we get a final status line (2xx/5xx).
            response_lines: list[str] = []
            while True:
                line_bytes = await asyncio.wait_for(reader.readline(), timeout=5.0)
                line = line_bytes.decode("utf-8", errors="replace").strip()
                response_lines.append(line)
                if line and (line[0:3].isdigit() and " " in line[3:4]):
                    break
            # Send QUIT to close cleanly.
            writer.write(b"QUIT\r\n")
            await writer.drain()
            return "\n".join(response_lines)
        finally:
            writer.close()
            await writer.wait_closed()