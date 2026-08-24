# API — Agent

`honeywatch/agent/` — re-exports at `agent/__init__.py:20`.

```python
from honeywatch.agent import ChatAgent, SetupStore, run_setup_wizard, TOOL_REGISTRY, execute_tool
from honeywatch.agent.tools import ToolContext
```

## `agent/setup.py`

`honeywatch/agent/setup.py:247`.

```python
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

    def to_dict(self) -> dict: ...        # pass_ → pass
    @classmethod
    def from_dict(cls, data: dict) -> AgentConfig: ...  # filters known fields
```

```python
class SetupStore(db_path="honeywatch.db"):
    def _connect(self) -> Connection: ...
    def _close(self, conn): ...
    def set(self, key: str, value: str): ...
    def get(self, key: str, default="") -> str: ...
    def load_config(self) -> AgentConfig: ...
    def save_config(self, cfg: AgentConfig): ...

def run_setup_wizard(store: SetupStore, db_path: str, non_interactive: dict|None = None) -> AgentConfig: ...
# interactive prompts (getpass for key) or non-interactive dict for automation
```

Table `agent_setup(key PK, value, updated_at)`.

## `agent/tools.py`

`honeywatch/agent/tools.py:626`.

```python
class ToolContext(db_path: str, agent_config: AgentConfig, skip_vpn_check: bool = False):
    # lazily: ctx.store (Store), ctx.c2_store (C2Store)

TOOL_REGISTRY: dict[str, {func, spec}]  # via _tool(name, func)
_TOOLSPECS: list[dict]  # 10 JSON schemas

def execute_tool(name: str, args: dict, ctx: ToolContext) -> dict: ...
# unknown tool → {error}, exceptions → {error}
```

10 tools: `list_payloads`, `get_status`, `scan`, `probe_host`, `deploy`, `report`, `get_operations`, `get_tasks`, `set_wallet`, `set_ollama` — see [Agent](../agent.md) for args and returns.

Helpers: `_require_vpn`, `_summarize_scores`, `_score_summary`, `_set`, `_TOOL_SPECS`, `_tool`.

## `agent/ollama_agent.py`

`honeywatch/agent/ollama_agent.py:248`.

```python
_SYSTEM_PROMPT_TEMPLATE: str  # ENI, JSON THOUGHTS/SPEAK/TOOLS, nickname LO
def _build_system_prompt() -> str: ...  # injects TOOL_DESCRIPTIONS from registry
def _extract_json(text: str) -> dict: ...  # balanced brace, fence-aware

class ChatAgent(config: AgentConfig|None, db_path="honeywatch.db", skip_vpn_check=False, on_say=None, on_tool_running=None, on_tool_result=None):
    def __init__(self, ...): ...  # OllamaClient(timeout 120, temp 0.2), ToolContext, messages=[system], session_id
    def _ollama_chat(self, messages) -> dict: ...  # {thoughts,speak,tools}
    def _execute_tool_calls(self, tool_calls) -> list[dict]: ...
    def _run_round(self, user_text, max_iterations=5) -> str: ...
    def chat(self, user_text) -> str: ...
    def run_interactive(self, greeting=None): ...
    def _say(self, text): ...
```

## `cli_chat.py`

`honeywatch/cli_chat.py:748`.

```python
# color helpers: bold, dim, red, green, yellow, blue, magenta, cyan, _hr
def panel(title, body, border_color) -> str: ...
def table(headers, rows, col_widths=None) -> str: ...
def print_banner(): ...
def format_status_line(...) -> str: ...
def format_tool_result(tool, result) -> str: ...
def format_help() -> str: ...
def check_setup(db_path) -> bool: ...
def prompt_setup(db_path): ...
SLASH_HELP: str
_BANNER: str

class TerminalUI(db_path, config_path, skip_vpn_check):
    def _init_agent(self): ...
    def _print_agent_say(self, text): ...
    def _print_tool_running(self, tool, args): ...
    def _print_tool_result(self, tool, result): ...
    def _show_status(self): ...
    def _handle_slash(self, line) -> bool: ...  # /help /status /setup /wallet /ollama /model /clear /history /quit
    def run(self) -> int: ...

class Spinner(message):
    def start(self): ...
    def tick(self): ...
    def stop(self, final=""): ...

# formatters: _format_scan, _format_probe_host, _format_deploy, _format_list_payloads, _format_get_status, _format_report, _format_get_operations, _format_get_tasks, _format_set_wallet, _format_set_ollama, _format_generic, _TOOL_FORMATTERS: dict
```

See [Agent](../agent.md).
