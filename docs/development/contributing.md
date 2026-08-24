# Contributing

## Repository Layout

```
Shhhh/
├── honeywatch/          # package
├── tests/               # pytest suite (19 modules)
├── config.example.toml  # reference config (132 lines, mirrors default_config)
├── .env.example         # env reference (OLLAMA_API_KEY, HONEYWATCH_MODEL, etc.)
├── pyproject.toml       # build + deps + scripts + pytest config
├── requirements.txt     # commented reference (stdlib-only core)
├── README.md            # user manual (634 lines, pipeline diagram)
├── docs/                # this documentation (mkdocs)
└── mkdocs.yml           # material theme, nav
```

## Development Install

```bash
python -m pip install -e .[full,c2,dev]
honeywatch --help
pytest -q
```

## Style

- **Stdlib-only runtime** — `asyncio`, `sqlite3`, `tomllib`, `urllib.request`, `argparse`, `hashlib`, `json`, `xml.etree`. No `numpy`/`pandas`/`requests` in core. Optional `paramiko`, `aiohttp`/`websockets`, `pytest`.
- **Lazy imports in CLI** — `cli.py` imports `config`/`pipeline`/`store` inside handlers so `--help` works without optional deps.
- **Dataclass contracts** — `models.py` field names are frozen API; don't rename without updating every consumer (`__all__` lists).
- **Comments** — concise; no long chain-of-thought in code comments.
- **Tests** — `pytest -q`, fixtures in `conftest.py`, mock network/subprocess.

## Adding a Payload

1. Define `install_script` + `run_script` templates with `{{var|default('val')}}` in `payloads/registry.py:616` `_payloads()`.
2. Add `Payload(id, category, name, description, platforms, install_type, dependencies, config_schema, install_script, run_script, artifacts, tags)`.
3. The registry is built at import time — `registry`, `PAYLOAD_IDS`, `PAYLOAD_CATEGORIES` update automatically.
4. Add tests in `tests/test_payloads.py` (`test_registry_contains_*`, `test_validate_variables`).

## Adding a Scanner

1. Add `honeywatch/scanners/<name>.py` with `run(targets, ports, rate, timeout_s, bin_path) -> list[HostHit]`, raising `ScannerError` on failure.
2. Re-export `ScannerError` in `scanners/__init__.py:28`.
3. Wire into `pipeline.py:352` `Pipeline.scan` tool switch and `config.py:32` `scanners.<name>`.
4. Add CLI `--tool` choice in `cli.py:26` `build_parser`.

## Adding a Tool (Agent)

1. Add `_tool_<name>(args, ctx) -> dict` in `agent/tools.py:626`.
2. Register via `_tool("name", func)` to populate `TOOL_REGISTRY` + `TOOL_SPECS`.
3. Update `_SYSTEM_PROMPT_TEMPLATE` tool descriptions via `_build_system_prompt()` if needed.
4. Add tests in `tests/test_agent_tools.py`.

## Configuration Keys

Add defaults in `config.py:32` `default_config()`, document in `config.example.toml` + `docs/configuration.md`, wire CLI folding in `cli.py:805` `_apply_scan_options` / `_call_scan` if needed.

## Docs

```bash
pip install mkdocs mkdocs-material
mkdocs serve      # live preview at http://127.0.0.1:8000
mkdocs build      # builds to site/
```

Nav is in `mkdocs.yml`. Each guide has `file_path:line_number` references for navigation.

## Pull Requests

- Run `pytest -q` before pushing.
- Update `docs/` for any user-facing change.
- Keep `pyproject.toml` classifiers and `README.md` pipeline diagram in sync.
- No empty commits, no force-push without request.
