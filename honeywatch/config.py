"""Configuration loading for honeywatch.

Pure-stdlib configuration handling. The resolution order is:

1. Built-in defaults (see :func:`default_config`).
2. An optional TOML file — the ``path`` argument (the CLI ``--config`` arg),
   else ``$HONEYWATCH_CONFIG``, else ``./config.toml`` if it exists.
3. Environment overrides applied last (highest precedence):
   ``HONEYWATCH_MODEL`` -> ``ai.model``,
   ``HONEYWATCH_AI_BASE`` -> ``ai.base_url``,
   the variable named by ``ai.api_key_env`` (default ``OLLAMA_API_KEY``)
   -> ``ai.api_key``.

Configuration is exposed through :class:`Config`, a small nested
attribute-access object so callers can write ``cfg.scanners.masscan.rate``
instead of digging through dictionaries. Missing keys are never an error —
they fall back to the defaults above.
"""

from __future__ import annotations

import os
import sys
import tomllib
from typing import Any


# ---------------------------------------------------------------------------
# defaults
# ---------------------------------------------------------------------------


def default_config() -> dict[str, Any]:
    """Return the built-in default configuration as a nested dict.

    Every call returns a fresh, independent copy so callers may mutate the
    result without affecting later lookups.
    """
    return {
        "scanners": {
            "masscan": {
                "bin": "masscan",
                "rate": 1000,
                # Seconds masscan waits for late SYN-ACK replies after sending.
                # 0 drops late replies and under-counts open hosts; a small
                # positive value improves discovery completeness.
                "wait_s": 3,
                # Subprocess bound in seconds (None = no timeout). Set this
                # for controlled scans so a hung run cannot block forever.
                "timeout_s": None,
                # Extra CIDRs to exclude from the scan, e.g. RFC1918 ranges
                # and your own egress IP on a 0.0.0.0/0 sweep.
                "exclude": [],
            },
            "zmap": {
                "bin": "zmap",
                "timeout_s": None,
            },
            "nmap": {
                "bin": "nmap",
            },
        },
        "scan": {
            "only_ssh": True,
        },
        "probe": {
            "concurrency": 512,
            "timeout_s": 6.0,
            "level": "fast",
            "auth_probe": False,
            "progress": False,  # print a live heartbeat every N probes during long scans
        },
        "ai": {
            "enabled": True,
            "model": "llama3.1:8b",
            "base_url": "https://ollama.com/v1",
            "api_key_env": "OLLAMA_API_KEY",
            "batch_profiles": True,
            "batch_size": 100,  # max profiles per LLM call (keeps prompts in-context)
            "temperature": 0.0,
            "timeout_s": 120,
            "retries": 3,  # transient-failure retries with exponential backoff
            "retry_base_delay": 1.0,  # seconds; doubles each attempt
        },
        "storage": {
            "db": "honeywatch.db",
            "reports_dir": "reports",
        },
        "vpn": {
            "required": True,
            "provider": "mullvad",
            "timeout_s": 8.0,
        },
        # ------------------------------------------------------------------ #
        # Red-team payloads
        # ------------------------------------------------------------------ #
        "payloads": {
            "enabled": True,
            "allowed_categories": ["miner", "exploit", "evasion"],
            "default_evasion": ["upx", "symbol_strip"],
            "exec_mode": "dry_run",  # dry_run | local_simulate | ssh
            # Optional path to a {payload_id: sha256} manifest. When set, the
            # install scripts verify downloaded tarballs against these hashes.
            "integrity_file": None,
            # When true, refuse to deploy any payload that has no pinned hash.
            "require_integrity": False,
        },
        # ------------------------------------------------------------------ #
        # C2 / web control plane
        # ------------------------------------------------------------------ #
        "c2": {
            "enabled": False,
            "host": "0.0.0.0",
            "port": 8443,
            "tls_cert": None,
            "tls_key": None,
            "api_token": None,  # shared bearer secret; when set, the controller &
                                # workers require it on every API + WS request
            # Defaults to storage.db when null.
            "db": None,
            # Internal CA for mutual-TLS worker auth. When ca_path is set (and a
            # server cert/key are configured), the controller requires every
            # worker to present a client cert chaining to this CA -- so only
            # CA-signed workers even complete the TLS handshake. The bearer token
            # remains a second factor at the app layer. None = no mTLS.
            "ca_path": None,
        },
        # ------------------------------------------------------------------ #
        # Controller-to-worker plane
        # ------------------------------------------------------------------ #
        "workers": {
            "controller_url": "http://127.0.0.1:8443",
            "categories": ["miner", "exploit", "evasion"],
            "poll_interval": 5.0,
            # Beacon jitter fraction (0.0-1.0): each wait is drawn from
            # [level - spread, level + spread] where spread = level*jitter.
            # 0.0 = fixed cadence (metronomic beacon signature); 0.2 spreads
            # each wait +/-20% so the controller flow is not a clean metronome.
            "jitter_fraction": 0.2,
            # Max seconds to back off on idle cycles / controller errors.
            "max_backoff": 60.0,
            "exec_mode": "dry_run",
            "ssh_user": "root",
            "ssh_key": None,
            # Bearer token gating controller API + WS. None = unauthenticated
            # (matches the controller default; set to match --api-token).
            "api_token": None,
            # mTLS: pin the internal CA, present a CA-signed client cert. When
            # ca_path is set the worker builds a client SSL context that trusts
            # ONLY this CA (chain-level pinning); ca_pin is the CA cert's SHA-256
            # fingerprint, checked constant-time before the CA file is trusted to
            # guard against on-disk CA substitution. None = plaintext HTTP.
            "ca_path": None,
            "worker_cert": None,
            "worker_key": None,
            "ca_pin": None,
        },
        # ------------------------------------------------------------------ #
        # SSH password cracker
        # ------------------------------------------------------------------ #
        "crack": {
            # Parallel login attempts against a single host. Many sshd builds
            # throttle or temp-ban a source that fires too many parallel auth
            # failures, so this stays modest by default.
            "concurrency": 8,
            # How many hosts to attack at once.
            "host_concurrency": 32,
            # Seconds allowed for one TCP + KEX + auth attempt.
            "timeout_s": 6.0,
            # Cap guesses per host before giving up (None = drain the wordlist).
            "max_attempts": None,
            # Expand a wordlist with case/year/symbol mutations.
            "mutations": True,
            # Persist cracked credentials into the credentials table so later
            # deploy runs can reuse them.
            "save_credentials": True,
        },
    }


# ---------------------------------------------------------------------------
# nested attribute-access view
# ---------------------------------------------------------------------------


class Config:
    """A read-mostly, dot-accessible view over a nested configuration dict.

    Every nested mapping becomes another :class:`Config` instance, so
    ``cfg.scanners.masscan.rate`` works exactly like
    ``cfg["scanners"]["masscan"]["rate"]``. Use :meth:`to_dict` to get the
    underlying plain dict back.
    """

    def __init__(self, data: dict[str, Any]):
        object.__setattr__(self, "_data", {})
        for key, value in dict(data).items():
            wrapped = _wrap(value)
            object.__setattr__(self, key, wrapped)
            self._data[key] = wrapped

    # -- dict-style helpers -------------------------------------------------

    def __getitem__(self, key: str) -> Any:
        try:
            return getattr(self, key)
        except AttributeError as exc:  # pragma: no cover - trivial bridge
            raise KeyError(key) from exc

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return getattr(self, key)
        except AttributeError:
            return default

    def to_dict(self) -> dict[str, Any]:
        """Return this configuration as a plain (nested) dict."""
        return {
            key: (value.to_dict() if isinstance(value, Config) else value)
            for key, value in self._data.items()
        }

    # -- dunder niceties ----------------------------------------------------

    def __contains__(self, key: str) -> bool:
        return key in self._data

    def __repr__(self) -> str:
        return f"Config({self._data!r})"

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Config):
            return self.to_dict() == other.to_dict()
        if isinstance(other, dict):
            return self.to_dict() == other
        return NotImplemented

    def __bool__(self) -> bool:
        return True


def _wrap(value: Any) -> Any:
    """Wrap a nested dict in :class:`Config`; leave every other value alone."""
    if isinstance(value, dict):
        return Config(value)
    return value


# ---------------------------------------------------------------------------
# deep merge
# ---------------------------------------------------------------------------


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Return ``base`` with ``override`` merged in, recursively.

    Nested dicts are merged key-by-key so partial TOML files only override the
    keys they actually mention. Non-dict values in ``override`` replace the
    base value wholesale.
    """
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


# ---------------------------------------------------------------------------
# config file discovery + parsing
# ---------------------------------------------------------------------------


def _resolve_config_path(path: str | None) -> str | None:
    """Pick which TOML file to load, or ``None`` to use pure defaults.

    Precedence: explicit ``path`` (``--config`` arg), then the
    ``HONEYWATCH_CONFIG`` environment variable, then ``./config.toml`` if it
    exists. The first candidate that is actually a file wins; anything missing
    is skipped so resolution always falls back to defaults.
    """
    candidates: list[str] = []
    if path is not None:
        candidates.append(path)
    env_path = os.environ.get("HONEYWATCH_CONFIG")
    if env_path:
        candidates.append(env_path)

    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate

    if os.path.isfile("config.toml"):
        return "config.toml"

    return None


def _load_toml(path: str) -> dict[str, Any]:
    """Parse a TOML file, returning an empty dict if it cannot be read.

    A missing file is normal (the config file is optional) and stays silent.
    A file that exists but cannot be parsed or read is a real operator error,
    so we surface a stderr warning rather than silently falling back to an
    empty config — otherwise a typo'd TOML looks identical to "no config".
    """
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except FileNotFoundError:
        return {}
    except (OSError, tomllib.TOMLDecodeError) as exc:
        print(f"honeywatch: warning: failed to load config {path!r}: {exc!r}",
              file=sys.stderr)
        return {}
    if not isinstance(data, dict):
        print(f"honeywatch: warning: config {path!r} top level is not a table; ignored",
              file=sys.stderr)
        return {}
    return data


def _apply_env_overrides(data: dict[str, Any]) -> None:
    """Apply environment overrides in place (last, so highest precedence)."""
    ai = data.setdefault("ai", {})

    model = os.environ.get("HONEYWATCH_MODEL")
    if model:
        ai["model"] = model

    base = os.environ.get("HONEYWATCH_AI_BASE")
    if base:
        ai["base_url"] = base

    api_key_env = ai.get("api_key_env") or "OLLAMA_API_KEY"
    env_api_key = os.environ.get(api_key_env)
    if env_api_key:
        ai["api_key"] = env_api_key


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------


def load_config(path: str | None = None) -> Config:
    """Load configuration, merging defaults, an optional TOML file, and env.

    :param path: explicit TOML path (the ``--config`` CLI argument). When
        omitted (or when the file does not exist), ``$HONEYWATCH_CONFIG`` and
        then ``./config.toml`` are tried, and finally plain defaults.
    :returns: a :class:`Config` object with nested attribute access.
    """
    merged = default_config()

    resolved = _resolve_config_path(path)
    if resolved is not None:
        merged = _deep_merge(merged, _load_toml(resolved))

    _apply_env_overrides(merged)

    return Config(merged)


# ---------------------------------------------------------------------------
# example file
# ---------------------------------------------------------------------------


def _toml_scalar(value: Any) -> str:
    """Render a single scalar (or list of scalars) as a TOML literal."""
    if isinstance(value, list):
        return "[" + ", ".join(_toml_scalar(item) for item in value) + "]"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return _toml_basic_string(value)
    if value is None:
        return '""'
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError(f"cannot render {value!r} as TOML")
        return repr(value)
    raise TypeError(f"cannot render {value!r} as a TOML scalar")


def _toml_basic_string(value: str) -> str:
    """Quote a string as a TOML basic string (subset of JSON escapes)."""
    chars = []
    for ch in value:
        code = ord(ch)
        if ch == '"':
            chars.append('\\"')
        elif ch == "\\":
            chars.append("\\\\")
        elif ch == "\b":
            chars.append("\\b")
        elif ch == "\t":
            chars.append("\\t")
        elif ch == "\n":
            chars.append("\\n")
        elif ch == "\f":
            chars.append("\\f")
        elif ch == "\r":
            chars.append("\\r")
        elif code < 0x20 or code == 0x7F:
            chars.append(f"\\u{code:04x}")
        else:
            chars.append(ch)
    return '"' + "".join(chars) + '"'


def _render_toml(data: dict[str, Any]) -> str:
    """Serialize a nested dict to a valid TOML document.

    Nested dicts become tables with dotted headers (e.g. ``[scanners.masscan]``);
    all scalar values live directly in their table. Order is preserved.
    """
    lines: list[str] = []

    def walk(prefix: str, node: dict[str, Any]) -> None:
        if prefix:
            lines.append(f"[{prefix}]")
        # None-valued keys mean "use the loader default"; omit them so a
        # written example cannot force a literal null / "" onto a caller.
        scalars = [
            (k, v)
            for k, v in node.items()
            if not isinstance(v, dict) and v is not None
        ]
        nested = [(k, v) for k, v in node.items() if isinstance(v, dict)]
        for key, value in scalars:
            lines.append(f"{key} = {_toml_scalar(value)}")
        if scalars and nested:
            lines.append("")
        for key, value in nested:
            walk(f"{prefix}.{key}" if prefix else key, value)

    walk("", data)
    return "\n".join(lines) + "\n"


def write_example(path: str) -> None:
    """Write a valid, fully-populated example ``config.toml`` to ``path``.

    The emitted file mirrors :func:`default_config`, so copying it to
    ``./config.toml`` and deleting the keys you want defaulted is a no-op.
    """
    rendered = _render_toml(default_config())
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(rendered)


# Expose the version for introspection.
__all__ = ["Config", "default_config", "load_config", "write_example"]
