# AI Agent & Chat

`honeywatch/agent/` — conversational red-team operator via Ollama. `honeywatch chat` starts an interactive REPL or single-prompt mode; `honeywatch setup` configures Ollama + mining defaults. Source: `agent/ollama_agent.py:248`, `agent/tools.py:626`, `agent/setup.py:247`, `cli_chat.py:748`.

## Setup (`agent/setup.py`)

### `AgentConfig`

```python
from honeywatch.agent.setup import AgentConfig

@dataclass
class AgentConfig:
    ollama_api_key: str = ""
    ollama_base_url: str = "https://ollama.com/v1"
    ollama_model: str = "llama3.1:8b"
    pool: str = ""
    wallet: str = ""
    pass_: str = "x"
    worker: str = "honeywatch"
    tls: bool = False
    controller_url: str = "http://127.0.0.1:8443"
    exec_mode: str = "dry_run"
    ssh_user: str = "root"
```

- `to_dict()` — serializes (maps `pass_` → `pass` for JSON).
- `from_dict(data) classmethod` — filters to known fields.

### `SetupStore`

SQLite wizard store, table `agent_setup(key PK, value, updated_at)`, defaults to `honeywatch.db`.

```python
from honeywatch.agent.setup import SetupStore

store = SetupStore("honeywatch.db")
store.set("ollama_api_key", "ollama_...")
store.get("pool", default="")
cfg: AgentConfig = store.load_config()
store.save_config(cfg)
```

- `_connect/_close`, `set/get`, `load_config() -> AgentConfig`, `save_config(cfg)`.

### `run_setup_wizard(store, db_path, non_interactive=None) -> AgentConfig`

- Interactive mode (`non_interactive=None`): prompts via `input` + `getpass` for `ollama_api_key` (hidden), `ollama_base_url`, `ollama_model`, mining `pool`/`wallet`/`pass`/`worker`/`tls`, `controller_url`/`exec_mode`/`ssh_user`. Prints `setup saved`.
- Non-interactive (`non_interactive=dict`): bypasses prompts — used by tests/automation and by `honeywatch setup --ollama-api-key ... --pool ...`.

CLI:

```bash
honeywatch setup --ollama-api-key ollama_... --pool pool:3333 --wallet W --pass x --worker hw --tls --db honeywatch.db
honeywatch setup  # interactive
```

Handler `cli.py:1064` `_cmd_setup`.

## Tools (`agent/tools.py`)

`honeywatch/agent/tools.py:626` — 10 coarse-grained tools the LLM can call. Each is `func(args: dict, ctx: ToolContext) -> dict`.

### `ToolContext`

```python
from honeywatch.agent.tools import ToolContext

ctx = ToolContext(db_path="honeywatch.db", agent_config=cfg, skip_vpn_check=False)
# lazily creates ctx.store (Store) + ctx.c2_store (C2Store)
```

Helper `_require_vpn(ctx)` checks `config.vpn.required` + `require_mullvad`.

### `TOOL_REGISTRY`

`TOOL_REGISTRY: dict[str, {func, spec}]` populated via `_tool(name, func)`. Each entry has a JSON schema for the LLM.

| # | Tool | Args | What it does |
|---|---|---|---|
| 1 | `list_payloads` | `{category?: str}` | `→ {payloads: [{id, category, name, description, install_type, tags}]}` |
| 2 | `get_status` | `{}` | `→ {status: store.stats()}` |
| 3 | `scan` | `{targets*: str csv, tool?: str, ports?: str, rate?: int, max_hosts?: int, probe_level?: str, skip_vpn_check?: bool}` | VPN gate, parse ports/targets, `Pipeline.scan` via `asyncio.run` → `{scanned, summary Counter, top: [{ip,port,label,confidence,banner,software,version,flags}] 10}` |
| 4 | `probe_host` | `{host*: str, probe_level?: str, skip_vpn_check?: bool}` | VPN gate, `Pipeline.probe_hosts+analyze_and_score` → `{result: {...} or {error}}` |
| 5 | `deploy` | `{payload_id*: str, target_label?: str, min_confidence?: float, max_confidence?: float, limit?: int, target_file?: str, evasion?: str, exec_mode?: str, ssh_user?: str, ssh_key?: str, variables?: dict}` | Autofills miner `pool`/`wallet`/`pass`/`worker`/`tls` from `ctx.agent_config` unless overridden, validates `pool`/`wallet`, resolves targets via file or `select_targets` (default `real+likely_real` min `0.7`), evasion pipeline, `build_manifest+enqueue_operation` → `{operation_id,payload_id,targets,status}` or error |
| 6 | `report` | `{format?: str json/csv/md, limit?: int, label?: str, min_confidence?: float}` | `→ {format, rows, data: [_score_summary]}` |
| 7 | `get_operations` | `{status?: str, limit?: int}` | `→ {operations: [...]}` |
| 8 | `get_tasks` | `{operation_id?: str, status?: str, limit?: int}` | `→ {tasks: [...]}` |
| 9 | `set_wallet` | `{pool?: str, wallet?: str, pass?: str, worker?: str, tls?: bool}` | Persists via `SetupStore.save_config` → `{ok:true, ...}` |
| 10 | `set_ollama` | `{api_key?: str, base_url?: str, model?: str}` | Persists via `SetupStore.save_config` → `{ok:true, ...}` |

Helpers: `_summarize_scores`, `_score_summary(s: Score)`, `_set`, `_TOOL_SPECS` (10 JSON schemas).

### `execute_tool(name, args, ctx) -> dict`

Dispatches by name; unknown tool → `{error: ...}`; exceptions → `{error: ...}`.

```python
from honeywatch.agent.tools import execute_tool, ToolContext

ctx = ToolContext(db_path="honeywatch.db", agent_config=cfg)
result = execute_tool("scan", {"targets": "192.0.2.0/24", "max_hosts": 10}, ctx)
```

## Chat Agent (`agent/ollama_agent.py`)

`honeywatch/agent/ollama_agent.py:248`.

### System Prompt

`_SYSTEM_PROMPT_TEMPLATE` — ENI, honeywatch red-team ops AI, JSON schema `{"thoughts": ..., "speak": ..., "tools": [{"tool": ..., "arguments": ...}]}`, rules for miners, summarize, nickname `LO`. Built by `_build_system_prompt()` which injects `TOOL_DESCRIPTIONS` from the registry.

`_extract_json(text) -> dict` — balanced-brace extraction (fence-aware, string-aware) for parsing LLM output.

### `ChatAgent`

```python
from honeywatch.agent.ollama_agent import ChatAgent
from honeywatch.agent.setup import AgentConfig

cfg = AgentConfig(ollama_api_key="ollama_...", ollama_model="llama3.1:8b")
agent = ChatAgent(
    config=cfg,
    db_path="honeywatch.db",
    skip_vpn_check=False,
    on_say=lambda text: print(text),
    on_tool_running=lambda tool, args: print(f"running {tool}"),
    on_tool_result=lambda tool, result: print(result),
)
response: str = agent.chat("scan 192.0.2.0/24 and report honeypots")
agent.run_interactive(greeting="Hello LO")
```

- Creates `OllamaClient(timeout=120, temperature=0.2)` from `cfg.base_url/api_key/model`.
- Creates `ToolContext`, initializes `messages=[{role:system,content:prompt}]`, `session_id uuid8`, callbacks.
- `_ollama_chat(messages) -> dict{thoughts,speak,tools}` — calls `client.chat`, catches `AiError→unreachable`, parses JSON else treats as plain `speak`.
- `_execute_tool_calls(tool_calls) -> list[{tool,arguments,result}]` — invokes `execute_tool` with callbacks.
- `_run_round(user_text, max_iterations=5) -> str` — appends user, loops: LLM→`speak` via `_say`, if no tools return `speak`/`thoughts`, else execute tools and feed back `Tool results:\n json lines` as next user message. Cap 5 rounds.
- `chat(user_text) -> str` — wrapper around `_run_round`.
- `run_interactive(greeting)` — REPL loop (used by `TerminalUI`).
- `_say(text)` — delegates to `on_say` callback (defaults to `print`).

## Terminal UI (`cli_chat.py`)

`honeywatch/cli_chat.py:748` — rich terminal UI (pure stdlib, ANSI).

**Exports:**

- Helpers `bold`, `dim`, `red`, `green`, `yellow`, `blue`, `magenta`, `cyan`, `_hr`, `panel(title,body,border_color)`, `table(headers,rows,col_widths)`, `print_banner()`, `format_status_line`, `format_tool_result`, `format_help()`, `check_setup(db_path)`, `prompt_setup(db_path)`, constants `SLASH_HELP`, `_BANNER`, color codes.
- `class TerminalUI(db_path, config_path, skip_vpn_check)`:
  - `_init_agent()` — lazy `ChatAgent`, runs setup wizard if no API key.
  - `_print_agent_say`, `_print_tool_running`, `_print_tool_result`, `_show_status()`, `_handle_slash(line)` — slash commands `/help,/status,/setup,/wallet,/ollama,/model,/clear,/history,/quit|/exit`.
  - `run() -> int` — REPL loop: banner, status line, `LO>` prompt, delegates to `ChatAgent.chat` with rich formatters.
- `class Spinner(message)` — `start()`, `tick()`, `stop(final)`.
- `_format_scan`, `_format_probe_host`, `_format_deploy`, `_format_list_payloads`, `_format_get_status`, `_format_report`, `_format_get_operations`, `_format_get_tasks`, `_format_set_wallet`, `_format_set_ollama`, `_format_generic`, dict `_TOOL_FORMATTERS`.

**CLI:**

```bash
honeywatch chat --prompt "list payloads" --db honeywatch.db --skip-vpn-check
honeywatch chat  # interactive REPL with slash commands
```

Handler `cli.py:1095` `_cmd_chat`: `TerminalUI(...)._init_agent()` for `--prompt` mode, else `ui.run()`.

## See Also

- [CLI Reference](cli.md) — `honeywatch chat` / `honeywatch setup` flags
- [Configuration](configuration.md) — Ollama and storage keys
- [Payloads](payloads.md) — what `deploy` can target
