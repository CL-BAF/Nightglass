"""Interactive setup wizard and configuration store for the honeywatch agent.

Guides the operator through configuring:
- Ollama Cloud API credentials (key, base URL, model)
- XMRig / XMRigCC mining destination (pool, wallet, worker, pass, TLS)

Values are stored in a SQLite table and exposed as defaults to the chat agent
and payload deployment tools.
"""

from __future__ import annotations

import getpass
import json
import os
import shutil
import sqlite3
from dataclasses import asdict, dataclass
from typing import Any

_DEFAULT_DB = "honeywatch.db"
_SCHEMA = """
CREATE TABLE IF NOT EXISTS agent_setup (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT
)
"""


@dataclass
class AgentConfig:
    """Runtime configuration bundle returned by the setup wizard / store."""

    # Ollama
    ollama_api_key: str = ""
    ollama_base_url: str = "https://ollama.com/v1"
    ollama_model: str = "llama3.1:8b"
    # Mining
    pool: str = ""
    wallet: str = ""
    pass_: str = "x"  # dataclass field cannot be named `pass`
    worker: str = "honeywatch"
    tls: bool = False
    # C2
    controller_url: str = "http://127.0.0.1:8443"
    exec_mode: str = "dry_run"
    ssh_user: str = "root"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["pass"] = d.pop("pass_")
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AgentConfig":
        kw = dict(data)
        if "pass" in kw:
            kw["pass_"] = kw.pop("pass")
        # Only accept known fields.
        known = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in kw.items() if k in known})


class SetupStore:
    """SQLite-backed store for the agent setup key/value pairs."""

    def __init__(self, db_path: str = _DEFAULT_DB):
        self.db_path = db_path
        conn = self._connect()
        self._close(conn)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.executescript(_SCHEMA)
        conn.commit()
        return conn

    def _close(self, conn: sqlite3.Connection) -> None:
        conn.close()

    def set(self, key: str, value: str) -> None:
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO agent_setup (key, value, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value = excluded.value,
                        updated_at = excluded.updated_at
                    """,
                    (key, value, now),
                )
        finally:
            self._close(conn)

    def get(self, key: str, default: str = "") -> str:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT value FROM agent_setup WHERE key = ?", (key,)
            ).fetchone()
        finally:
            self._close(conn)
        return row[0] if row else default

    def get_many(self, keys: list[str]) -> dict[str, str]:
        """Read several keys through one connection instead of one per key."""
        if not keys:
            return {}
        placeholders = ",".join("?" for _ in keys)
        conn = self._connect()
        try:
            rows = conn.execute(
                f"SELECT key, value FROM agent_setup WHERE key IN ({placeholders})",
                tuple(keys),
            ).fetchall()
        finally:
            self._close(conn)
        found = {k: v for k, v in rows}
        return {k: found.get(k, "") for k in keys}

    def set_many(self, items: dict[str, str]) -> None:
        """Write several key/value pairs in a single transaction.

        Used by :meth:`save_config` so persisting a full AgentConfig is one
        connection + one commit instead of ~11 sequential opens.
        """
        if not items:
            return
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            with conn:
                conn.executemany(
                    """
                    INSERT INTO agent_setup (key, value, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value = excluded.value,
                        updated_at = excluded.updated_at
                    """,
                    [(k, v, now) for k, v in items.items()],
                )
        finally:
            self._close(conn)

    def load_config(self) -> AgentConfig:
        """Load a full AgentConfig from stored values."""
        raw = self.get_many([
            "ollama_api_key",
            "ollama_base_url",
            "ollama_model",
            "pool",
            "wallet",
            "pass",
            "worker",
            "tls",
            "controller_url",
            "exec_mode",
            "ssh_user",
        ])
        defaults = {
            "ollama_base_url": "https://ollama.com/v1",
            "ollama_model": "llama3.1:8b",
            "pass": "x",
            "worker": "honeywatch",
            "controller_url": "http://127.0.0.1:8443",
            "exec_mode": "dry_run",
            "ssh_user": "root",
        }
        for k, d in defaults.items():
            if not raw.get(k):
                raw[k] = d
        raw["tls"] = (raw.get("tls") or "false").lower() in ("1", "true", "yes")
        return AgentConfig.from_dict(raw)

    def save_config(self, cfg: AgentConfig) -> None:
        d = cfg.to_dict()
        self.set_many({key: str(value) for key, value in d.items()})


def _prompt(
    text: str,
    default: str = "",
    password: bool = False,
    allow_empty: bool = False,
) -> str:
    """Prompt the user for a single line of input."""
    if default:
        prompt = f"{text} [{default}]: "
    else:
        prompt = f"{text}: "
    while True:
        try:
            if password:
                value = getpass.getpass(prompt)
            else:
                value = input(prompt)
        except (EOFError, KeyboardInterrupt):
            # stdin closed (piped / no TTY) or Ctrl-C. Fall back to the default
            # when one exists; otherwise bail with a clear message instead of
            # letting the raw EOFError/K KeyboardInterrupt traceback escape.
            if allow_empty or default:
                return default or ""
            raise SystemExit(
                "honeywatch setup: input interrupted with no default available; "
                "run non-interactively via non_interactive=... when unattended"
            )
        value = value.strip()
        if value:
            return value
        if allow_empty or default:
            return default or ""
        print("  (required)")


def run_setup_wizard(
    store: SetupStore | None = None,
    db_path: str = _DEFAULT_DB,
    non_interactive: dict[str, Any] | None = None,
) -> AgentConfig:
    """Run the interactive setup wizard and persist the result.

    When ``non_interactive`` is provided, values are taken from that dict
    instead of prompting. Useful for tests and automation.
    """
    store = store or SetupStore(db_path)
    existing = store.load_config()

    def _get(key: str, prompt: str, default: str = "", password: bool = False) -> str:
        if non_interactive is not None:
            return str(non_interactive.get(key, default or ""))
        return _prompt(prompt, default=default, password=password)

    print("\nhoneywatch agent setup")
    print("=" * 40)
    print("Configure the AI backend and default mining destination.")
    print("These values are stored locally and used by the chat agent.")
    print()

    cfg = AgentConfig()

    # Ollama
    cfg.ollama_api_key = _get(
        "ollama_api_key",
        "Ollama API key",
        default=existing.ollama_api_key or os.environ.get("OLLAMA_API_KEY", ""),
        password=True,
    )
    cfg.ollama_base_url = _get(
        "ollama_base_url",
        "Ollama base URL",
        default=existing.ollama_base_url or "https://ollama.com/v1",
    )
    cfg.ollama_model = _get(
        "ollama_model",
        "Ollama model",
        default=existing.ollama_model or "llama3.1:8b",
    )

    # Mining
    cfg.pool = _get(
        "pool",
        "Mining pool (e.g. stratum+tcp://pool.example.com:3333)",
        default=existing.pool,
    )
    cfg.wallet = _get(
        "wallet",
        "Monero wallet address (required for miner deploy)",
        default=existing.wallet,
    )
    cfg.pass_ = _get(
        "pass",
        "Pool password / worker identifier",
        default=existing.pass_ or "x",
    )
    cfg.worker = _get(
        "worker",
        "Worker name",
        default=existing.worker or "honeywatch",
    )

    tls_default = "true" if existing.tls else "false"
    tls_answer = _get("tls", "Use TLS for pool connection? (true/false)", default=tls_default)
    cfg.tls = tls_answer.lower() in ("1", "true", "yes")

    # Defaults for C2 / deploy
    cfg.controller_url = _get(
        "controller_url",
        "Default controller URL",
        default=existing.controller_url or "http://127.0.0.1:8443",
    )
    cfg.exec_mode = _get(
        "exec_mode",
        "Default execution mode (dry_run/local_simulate/ssh)",
        default=existing.exec_mode or "dry_run",
    )
    cfg.ssh_user = _get(
        "ssh_user",
        "Default SSH user",
        default=existing.ssh_user or "root",
    )

    store.save_config(cfg)
    print("\nsetup saved.")

    # Check external tool availability and offer to install missing ones.
    # Only offer interactive installs when running interactively.
    tool_status = check_external_tools()
    if tool_status:
        _print_tool_summary(tool_status)
        missing = [t for t in tool_status if not t["available"]]
        if missing and non_interactive is None:
            offer_install_tools(missing)

    return cfg


# --------------------------------------------------------------------------- #
# External tool availability
# --------------------------------------------------------------------------- #

# (tool_name, package_name_apt, package_name_brew)
_EXTERNAL_TOOLS: list[tuple[str, str, str]] = [
    ("masscan", "masscan", "masscan"),
    ("zmap", "zmap", "zmap"),
    ("nmap", "nmap", "nmap"),
    ("hashcat", "hashcat", "hashcat"),
    ("john", "john", "john"),
    ("sshpass", "sshpass", "hudochenkov/sshpass"),
    ("ssh", "openssh-client", "openssh"),
]


def check_external_tools() -> list[dict[str, str | bool]]:
    """Check which external tools honeywatch can use are available on PATH.

    Returns a list of dicts with keys ``name``, ``available``, and
    ``install_cmd`` (a human-readable apt/brew command string).
    """
    results: list[dict[str, str | bool]] = []
    for name, apt_pkg, brew_pkg in _EXTERNAL_TOOLS:
        available = shutil.which(name) is not None
        results.append({
            "name": name,
            "available": available,
            "apt": f"sudo apt install -y {apt_pkg}",
            "brew": f"brew install {brew_pkg}",
        })
    return results


def _print_tool_summary(tool_status: list[dict[str, str | bool]]) -> None:
    """Print a summary of available / missing external tools."""
    print("\nexternal tool availability:")
    print("-" * 50)
    for t in tool_status:
        status = "[ok]" if t["available"] else "[--]"
        print(f"  {status} {t['name']}")
    missing = [t for t in tool_status if not t["available"]]
    if missing:
        print(f"\n{len(missing)} tool(s) missing -- some commands will not work")
    else:
        print("\nall external tools found.")


def offer_install_tools(
    missing: list[dict[str, str | bool]],
) -> None:
    """Interactively offer to install each missing external tool.

    Detects the platform (Linux via apt, or macOS via brew) and runs the
    appropriate install command when the operator confirms.
    """
    if not missing:
        return

    import platform
    import subprocess

    system = platform.system()
    if system == "Linux":
        # Check if apt is available.
        has_apt = shutil.which("apt") is not None
        if not has_apt:
            print(
                "\nno apt package manager found -- install missing tools manually."
            )
            return
        pkg_mgr = "apt"
    elif system == "Darwin":
        has_brew = shutil.which("brew") is not None
        if not has_brew:
            print(
                "\nno Homebrew found -- install it from https://brew.sh, "
                "then install the missing tools."
            )
            return
        pkg_mgr = "brew"
    elif system == "Windows":
        print(
            "\nautomatic installs are not supported on Windows. "
            "Install missing tools manually or via WSL."
        )
        return
    else:
        print(
            f"\nplatform '{system}' is not supported for automatic installs -- "
            "install missing tools manually."
        )
        return

    print(f"\nmissing tools can be installed via {pkg_mgr}:")
    for t in missing:
        cmd = t[pkg_mgr]  # type: ignore[literal-required]
        print(f"  {cmd}")

    # Offer to install each one.
    for t in missing:
        cmd = t[pkg_mgr]  # type: ignore[literal-required]
        try:
            answer = input(f"\ninstall {t['name']}? [Y/n] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nskipping remaining installs.")
            break
        if answer in ("", "y", "yes"):
            print(f"running: {cmd}")
            try:
                result = subprocess.run(cmd.split(), capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"[ok] {t['name']} installed")
                else:
                    print(f"[--] {t['name']} install failed: {result.stderr.strip()}")
            except Exception as exc:
                print(f"[--] {t['name']} install error: {exc}")
        else:
            print(f"skipped {t['name']}")
