# API Reference — Overview

Public imports for every module. Field names, types, and defaults in `honeywatch/models.py:1` are **stable API** — other modules import them by exact name.

## Top-Level Package

```python
import honeywatch
honeywatch.__version__  # "0.1.0" — honeywatch/__init__.py:8
```

`python -m honeywatch` via `honeywatch/__main__.py:1`.

## Import Map

| Module | Import | Doc |
|---|---|---|
| `honeywatch.config` | `from honeywatch.config import Config, default_config, load_config, write_example` | [Config](config.md) |
| `honeywatch.store` | `from honeywatch.store import Store` | [Store](store.md) |
| `honeywatch.pipeline` | `from honeywatch.pipeline import Pipeline` | [Pipeline](pipeline.md) |
| `honeywatch.models` | `from honeywatch.models import HostHit, Fingerprint, Signals, AiVerdict, Score, Payload, Target, DeploymentManifest, Operation, WorkerTask, SSH_PORT` | [Models](models.md) |
| `honeywatch.report` | `from honeywatch.report import write_json, write_csv, write_md, LABELS` | [Report](report.md) |
| `honeywatch.vpn` | `from honeywatch.vpn import VpnError, require_mullvad, mullvad_connected, egress_is_mullvad, interface_is_mull, opt_out_requested, DEFAULT_TIMEOUT, REFUSAL` | [VPN](vpn.md) |
| `honeywatch.cli` | `from honeywatch.cli import build_parser, main, parse_host, parse_ports, print_summary` | [CLI](cli.md) |
| `honeywatch.cli_chat` | `from honeywatch.cli_chat import TerminalUI, panel, table, Spinner, format_tool_result, check_setup` | — |
| `honeywatch.fingerprint` | `from honeywatch.fingerprint import analyze, probe_ssh, probe_many, parse_banner, parse_kexinit, SIGNAL_NAMES, LEGACY_CIPHERS, LEGACY_MACS, WEAK_HOST_KEYS` | [Fingerprint](fingerprint.md) |
| `honeywatch.ai` | `from honeywatch.ai import OllamaClient, AiError, AiScorer, profile_key, summarize, verdict_from_text, SYSTEM_PROMPT, OUTPUT_JSON, user_prompt_for` | [AI](ai.md) |
| `honeywatch.scanners` | `from honeywatch.scanners import ScannerError, run_masscan, run_zmap, probe_nmap` (via `scanners/__init__.py:28` re-exports) | [Scanners](scanners.md) |
| `honeywatch.payloads` | `from honeywatch.payloads import registry, PAYLOAD_IDS, PAYLOAD_CATEGORIES, get_payload, list_payloads, by_category, render_manifest_scripts` | [Payloads](payloads.md) |
| `honeywatch.payloads.scripts` | `from honeywatch.payloads.scripts import render_payload_script, validate_variables, merge_defaults, generate_operation_id` | — |
| `honeywatch.c2` | `from honeywatch.c2 import Controller, C2Store, Worker, WorkerError, build_ssl_context, ensure_self_signed_pair` | [C2](c2.md) |
| `honeywatch.c2.tls` | `from honeywatch.c2.tls import generate_self_signed, render_nginx_config, write_nginx_config` | — |
| `honeywatch.ops` | `from honeywatch.ops import TargetFilter, select_targets, build_manifest, enqueue_operation, prepare_evasion_pipeline` + `dispatch_to_controller` | [Ops](ops.md) |
| `honeywatch.agent` | `from honeywatch.agent import ChatAgent, SetupStore, run_setup_wizard, TOOL_REGISTRY, execute_tool` + `ToolContext` | [Agent](agent.md) |

## Configuration Resolution

```
defaults (code)  <  TOML (--config / $HONEYWATCH_CONFIG / ./config.toml)  <  env (OLLAMA_API_KEY, HONEYWATCH_MODEL, HONEYWATCH_AI_BASE, HONEYWATCH_SKIP_VPN)
```

`Config` attribute access mirrors dict: `cfg.scanners.masscan.rate` == `cfg["scanners"]["masscan"]["rate"]`.

## Database Defaults

- `honeywatch.db` (WAL), `reports/` for reports, `certs/honeywatch.crt|key`, `0.0.0.0:8443` for C2.

## Subpages

- [Models](models.md) — `HostHit`, `Fingerprint`, `Signals`, `AiVerdict`, `Score`, `Payload`, `Target`, `DeploymentManifest`, `Operation`, `WorkerTask`
- [Config](config.md)
- [Pipeline](pipeline.md)
- [Fingerprint](fingerprint.md)
- [AI](ai.md)
- [Store](store.md)
- [Report](report.md)
- [VPN](vpn.md)
- [Scanners](scanners.md)
- [Payloads](payloads.md)
- [C2](c2.md)
- [Ops](ops.md)
- [Agent](agent.md)
- [CLI](cli.md)
