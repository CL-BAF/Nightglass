# API — CLI

`honeywatch/cli.py:1156` — `argparse` with 10 subcommands, lazy imports.

## `build_parser() -> ArgumentParser`

```python
from honeywatch.cli import build_parser
parser = build_parser()
parser.print_help()
```

Constructs `ArgumentParser(prog="honeywatch", description="internet-scale SSH honeypot confidence scanner")` with `subparsers` required. Subcommands: `scan`, `probe`, `report`, `config`, `stats`, `c2`, `worker`, `deploy`, `setup`, `chat`. Each has `set_defaults(func=_cmd_*)`. Global `--version` via `_package_version()`.

## `main(argv=None) -> int`

```python
from honeywatch.cli import main
import sys
sys.exit(main())
sys.exit(main(["scan", "192.0.2.0/24", "--skip-vpn-check"]))
```

Parses `argv or sys.argv[1:]`, catches `SystemExit` from `argparse` (0 for `--help`, 2 for usage errors), dispatches `args.func(args, argv)`, catches `KeyboardInterrupt → 130`, generic `Exception → 1` with `type: message` to stderr.

## Helpers

| Symbol | Detail |
|---|---|
| `_package_version() -> str` | `importlib.metadata.version("honeywatch")` or `"0.1.0"` (`cli.py:422`) |
| `_set(obj, name, value)` | best-effort `setattr`, tolerates frozen (`cli.py:432`) |
| `_maybe_await(value)` | `asyncio.run` if awaitable else passthrough (`cli.py:440`) |
| `_match_signature(func, candidates) -> dict` | filters kwargs to signature-accepted names, handles `**kwargs` (`cli.py:447`) |
| `parse_host(spec, default_port=22) -> (ip, port)` | handles `ip`, `ip:port`, `[v6]:port` (`cli.py:466`) |
| `parse_ports(spec) -> list[int]` | `22` / `22,80,443` / `2200-2222`, deduped (`cli.py:488`) |
| `_toml_dumps(data) -> str` | minimal TOML serializer for default config dict (`cli.py:511`) |
| `_parse_key_value(items) -> dict` | `["k=v"] → {k:v}`, ignores malformed (`cli.py:879`) |

## Subcommand Handlers

| Handler | File:Line | CLI |
|---|---|---|
| `_cmd_config` | `cli.py:550` | `config --write` |
| `_enforce_vpn` | `cli.py:561` | gate for scan/probe/c2/deploy/chat |
| `_cmd_probe` | `cli.py:580` | `probe ip[:port]` |
| `_print_probe` | `cli.py:624` | human probe output |
| `_score_to_jsonable` | `cli.py:653` | flat JSON for `--json` |
| `_print_probe_json` | `cli.py:686` | JSON probe output |
| `_cmd_report` | `cli.py:691` | `report` |
| `_cmd_scan` | `cli.py:723` | `scan TARGET...` — `run_once` loop, `print_summary`, `--interval` |
| `_apply_scan_options` | `cli.py:805` | fold scan flags into `cfg` |
| `_call_scan` | `cli.py:823` | signature-safe `pipeline.scan` call |
| `_cmd_stats` | `cli.py:854` | `stats --json` |
| `_cmd_c2` | `cli.py:890` | `c2 --generate-certs` |
| `_cmd_worker` | `cli.py:931` | `worker` |
| `_cmd_deploy` | `cli.py:981` | `deploy payload_id` |
| `_cmd_setup` | `cli.py:1064` | `setup` |
| `_cmd_chat` | `cli.py:1095` | `chat --prompt` |
| `print_summary` | `cli.py:1118` | `counts by final label` + `top 10 by confidence` |

## `__all__`

`__all__ = ["build_parser", "main"]` (`cli.py:23`).

See [CLI Reference](../cli.md) for full flag tables and [Configuration](../configuration.md) for config folding.
