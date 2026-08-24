# API — Config

`honeywatch/config.py:389` — pure-stdlib configuration (defaults → TOML → env) via `tomllib`.

## `default_config() -> dict`

Returns the built-in nested dict. Every call is a fresh copy (`config.py:32`).

```python
from honeywatch.config import default_config
cfg = default_config()
cfg["probe"]["concurrency"]  # 512
```

Keys: `scanners.masscan|zmap|nmap`, `scan`, `probe`, `ai`, `storage`, `vpn`, `payloads`, `c2`, `workers` — see [Configuration](../configuration.md).

## `class Config(data: dict)`

Dot-accessible view over a nested dict (`config.py:131`).

```python
from honeywatch.config import Config

cfg = Config({"probe": {"concurrency": 256}})
cfg.probe.concurrency  # 256
cfg["probe"]["timeout_s"]  # via __getitem__
cfg.get("vpn", None)
cfg.to_dict()          # plain nested dict
"probe" in cfg         # __contains__
cfg == {"probe": {"concurrency": 256}}  # __eq__ vs dict
bool(cfg)              # always True
repr(cfg)              # Config({...})
```

Nested dicts become `Config` instances recursively via `_wrap` (`config.py:187`).

## `load_config(path=None) -> Config`

Public loader (`config.py:278`):

```python
from honeywatch.config import load_config

cfg = load_config()                 # auto: --config → $HONEYWATCH_CONFIG → ./config.toml → defaults
cfg = load_config("my.toml")        # explicit path
print(cfg.scanners.masscan.rate)    # 1000
```

Resolution: `_resolve_config_path` (`config.py:220`) picks the first existing file among candidates; fallback to defaults. Then `_deep_merge` (`config.py:199`) merges TOML, then `_apply_env_overrides` (`config.py:257`) applies `HONEYWATCH_MODEL`, `HONEYWATCH_AI_BASE`, `api_key_env` → `ai.api_key`.

## `write_example(path) -> None`

Writes a fully-populated `config.toml` to `path` (`config.py:377`):

```python
from honeywatch.config import write_example
write_example("config.toml")
```

Emits via `_render_toml` (`config.py:347`) with dotted tables and `_toml_scalar`/`_toml_basic_string` (`config.py:302`). `None` values are omitted (use loader defaults).

## Internals

- `_deep_merge(base, override) -> dict` — recursive key-by-key merge, non-dicts replace wholesale.
- `_resolve_config_path(path) -> str|None` — precedence: explicit `path` → `$HONEYWATCH_CONFIG` → `./config.toml`.
- `_load_toml(path) -> dict` — `tomllib.load`, empty dict on `FileNotFoundError`/`OSError`/`TOMLDecodeError`.
- `_apply_env_overrides(data)` — in-place.
- `_toml_scalar`, `_toml_basic_string`, `_render_toml` — TOML serialization.

`__all__ = ["Config","default_config","load_config","write_example"]` (`config.py:389`).
