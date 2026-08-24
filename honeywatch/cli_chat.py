"""Rich terminal UI for the honeywatch chat agent.

Provides an interactive operator console with ANSI formatting, status panels,
slash commands, and structured tool output — all pure stdlib, no external deps.
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from typing import Any, Callable

# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------

_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_BLUE = "\033[34m"
_MAGENTA = "\033[35m"
_CYAN = "\033[36m"
_RED_BG = "\033[41m"
_GREEN_BG = "\033[42m"
_YELLOW_BG = "\033[43m"
_BLUE_BG = "\033[44m"
_RESET = "\033[0m"


def _supports_color() -> bool:
    """Check whether the terminal likely supports ANSI color."""
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    if not hasattr(sys.stdout, "isatty"):
        return False
    return sys.stdout.isatty()


def _term_width() -> int:
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return 80


def _c(code: str, text: str) -> str:
    """Colorize *text* with an ANSI *code* if the terminal supports it."""
    if not _supports_color():
        return text
    return f"{code}{text}{_RESET}"


def bold(text: str) -> str:
    return _c(_BOLD, text)


def dim(text: str) -> str:
    return _c(_DIM, text)


def red(text: str) -> str:
    return _c(_RED, text)


def green(text: str) -> str:
    return _c(_GREEN, text)


def yellow(text: str) -> str:
    return _c(_YELLOW, text)


def blue(text: str) -> str:
    return _c(_BLUE, text)


def magenta(text: str) -> str:
    return _c(_MAGENTA, text)


def cyan(text: str) -> str:
    return _c(_CYAN, text)


# ---------------------------------------------------------------------------
# Box / panel drawing
# ---------------------------------------------------------------------------

def _hr(char: str = "─", color: str = "") -> str:
    w = _term_width()
    line = char * w
    if color:
        return _c(color, line)
    return line


def panel(title: str, body: str, border_color: str = _CYAN) -> str:
    """Render a titled box around *body* text."""
    w = min(_term_width(), 80)
    inner = w - 4  # two borders + two spaces
    title_line = f" {title} "
    pad = inner - len(title_line)
    if pad < 0:
        pad = 0
    lines = []
    lines.append(_c(border_color, "╭") + _c(border_color, "─" * (inner + 2)) + _c(border_color, "╮"))
    lines.append(
        _c(border_color, "│")
        + _c(_BOLD, title_line)
        + " " * pad
        + _c(border_color, "│")
    )
    lines.append(_c(border_color, "├") + _c(border_color, "─" * (inner + 2)) + _c(border_color, "┤"))
    for raw in body.splitlines():
        for i in range(0, max(len(raw), 1), inner):
            chunk = raw[i : i + inner]
            lines.append(
                _c(border_color, "│") + " " + chunk + " " * max(inner + 1 - len(chunk), 0) + _c(border_color, "│")
            )
    lines.append(_c(border_color, "╰") + _c(border_color, "─" * (inner + 2)) + _c(border_color, "╯"))
    return "\n".join(lines)


def table(headers: list[str], rows: list[list[str]], col_widths: list[int] | None = None) -> str:
    """Render a simple text table."""
    if col_widths is None:
        col_widths = []
        for i, h in enumerate(headers):
            max_w = len(h)
            for row in rows:
                if i < len(row):
                    max_w = max(max_w, len(str(row[i])))
            col_widths.append(min(max_w + 2, 40))
    lines = []
    header_line = "  ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    lines.append(_c(_BOLD, header_line))
    lines.append(_c(_DIM, "  ".join("─" * w for w in col_widths)))
    for row in rows:
        cells = []
        for i, w in enumerate(col_widths):
            val = str(row[i]) if i < len(row) else ""
            cells.append(val[:w].ljust(w))
        lines.append("  ".join(cells))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Spinner
# ---------------------------------------------------------------------------

_SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


class Spinner:
    """A simple terminal spinner that overwrites the current line."""

    def __init__(self, message: str = ""):
        self.message = message
        self._idx = 0
        self._active = False
        self._start = 0.0

    def start(self) -> None:
        self._active = True
        self._start = time.monotonic()

    def tick(self) -> None:
        if not self._active:
            return
        frame = _SPINNER_FRAMES[self._idx % len(_SPINNER_FRAMES)]
        self._idx += 1
        elapsed = time.monotonic() - self._start
        msg = f"\r  {cyan(frame)} {dim(self.message)} ({elapsed:.1f}s)"
        sys.stderr.write(msg)
        sys.stderr.flush()

    def stop(self, final: str = "") -> None:
        self._active = False
        clear = " " * (_term_width() - 1)
        sys.stderr.write(f"\r{clear}\r")
        sys.stderr.flush()
        if final:
            print(final)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

_BANNER = r"""
  _   _                          _     _
 | | | |   _ _ ___   _ __  _   _| |_  | |     ___   __ _  ___
 | |_| |/ _` / __| | | '_ \| | | | __| | |    / _ \ / _` |/ _ \
 |  _  | (_| \__ \ |_| | | | |_| | |_  | |___| (_) | (_| |  __/
 |_| |_|\__,_|___/\__, |_| |_|\__,_|\__| |______\___/ \__, |\___|
                   |___/                                |___/
"""


def print_banner() -> None:
    print(_c(_CYAN, _BANNER))
    print(_c(_DIM, "  planet-scale SSH honeypot scanner · AI-powered operator console"))
    print()


# ---------------------------------------------------------------------------
# Status line
# ---------------------------------------------------------------------------

def format_status_line(
    model: str = "",
    wallet: str = "",
    pool: str = "",
    total_hosts: int = 0,
    db_path: str = "",
) -> str:
    """Format a one-line status summary."""
    parts = []
    if model:
        parts.append(f"{bold('model')} {dim(model)}")
    if wallet:
        short = wallet[:8] + "…" + wallet[-4:] if len(wallet) > 16 else wallet
        parts.append(f"{bold('wallet')} {dim(short)}")
    if pool:
        parts.append(f"{bold('pool')} {dim(pool)}")
    if total_hosts:
        parts.append(f"{bold('hosts')} {green(str(total_hosts))}")
    if db_path:
        parts.append(f"{bold('db')} {dim(db_path)}")
    return "  │  ".join(parts) if parts else dim("not configured")


# ---------------------------------------------------------------------------
# Slash commands
# ---------------------------------------------------------------------------

SLASH_HELP = {
    "/help": "Show this help message",
    "/status": "Show database status and current configuration",
    "/setup": "Re-run the setup wizard (Ollama API + wallet)",
    "/wallet": "Show or update mining wallet config",
    "/ollama": "Show or update Ollama API config",
    "/model": "Show or change the AI model",
    "/clear": "Clear conversation history",
    "/history": "Show recent conversation history",
    "/quit": "Exit the console (also: /exit, Ctrl-C)",
}


def format_help() -> str:
    lines = [bold("slash commands")]
    lines.append(_c(_DIM, "─" * 50))
    for cmd, desc in SLASH_HELP.items():
        lines.append(f"  {cyan(cmd):<14} {dim(desc)}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool output formatters
# ---------------------------------------------------------------------------

def format_tool_result(name: str, result: dict[str, Any]) -> str:
    """Format a tool execution result into a human-readable string."""
    if "error" in result and len(result) <= 2:
        return red(f"  ✗ {name}: {result['error']}")

    # Route to specific formatters.
    formatter = _TOOL_FORMATTERS.get(name, _format_generic)
    return formatter(result)


def _format_scan(result: dict[str, Any]) -> str:
    lines = [green(f"  ✓ scan completed — {result.get('scanned', 0)} hosts scored")]
    summary = result.get("summary", {})
    if summary:
        parts = []
        for label in ("real", "likely_real", "uncertain", "likely_honeypot", "honeypot"):
            if label in summary:
                parts.append(f"{label}: {summary[label]}")
        lines.append("  " + dim("  │  ".join(parts)))
    top = result.get("top", [])
    if top:
        lines.append("")
        lines.append(dim("  top hosts by confidence:"))
        headers = ["host", "label", "confidence"]
        rows = []
        for h in top[:10]:
            rows.append([f"{h.get('ip', '?')}:{h.get('port', 22)}", h.get("label", "?"), f"{h.get('confidence', 0):.3f}"])
        lines.append(table(headers, rows, [24, 16, 12]))
    return "\n".join(lines)


def _format_probe_host(result: dict[str, Any]) -> str:
    r = result.get("result", result)
    lines = [green(f"  ✓ probe — {r.get('ip', '?')}:{r.get('port', 22)}")]
    for key in ("banner", "software", "version", "label", "confidence"):
        val = r.get(key)
        if val is not None:
            lines.append(f"    {dim(key)}: {val}")
    flags = r.get("flags", [])
    if flags:
        lines.append(f"    {dim('flags')}: {', '.join(flags)}")
    return "\n".join(lines)


def _format_deploy(result: dict[str, Any]) -> str:
    lines = [green(f"  ✓ deployed operation {result.get('operation_id', '?')}")]
    lines.append(f"    payload: {result.get('payload_id', '?')}")
    lines.append(f"    targets: {result.get('targets', 0)}")
    lines.append(f"    status:  {result.get('status', '?')}")
    return "\n".join(lines)


def _format_list_payloads(result: dict[str, Any]) -> str:
    payloads = result.get("payloads", [])
    if not payloads:
        return dim("  no payloads found")
    headers = ["id", "category", "name"]
    rows = [[p.get("id", ""), p.get("category", ""), p.get("name", "")] for p in payloads]
    return table(headers, rows, [14, 10, 30])


def _format_get_status(result: dict[str, Any]) -> str:
    status = result.get("status", {})
    total = status.get("total", 0)
    by_label = status.get("by_label", {})
    lines = [bold(f"  database status — {total} hosts")]
    if by_label:
        headers = ["label", "count"]
        rows = [[k, str(v)] for k, v in by_label.items()]
        lines.append(table(headers, rows, [16, 8]))
    by_flag = status.get("by_flag", {})
    if by_flag:
        lines.append(dim("  flags:"))
        for flag, count in sorted(by_flag.items(), key=lambda x: -x[1]):
            lines.append(f"    {flag}: {count}")
    return "\n".join(lines)


def _format_report(result: dict[str, Any]) -> str:
    fmt = result.get("format", "json")
    rows = result.get("data", [])
    lines = [green(f"  ✓ report — {result.get('rows', 0)} rows in {fmt}")]
    if rows:
        headers = ["host", "label", "confidence"]
        table_rows = []
        for r in rows[:20]:
            table_rows.append([
                f"{r.get('ip', '?')}:{r.get('port', 22)}",
                r.get("label", "?"),
                f"{r.get('confidence', 0):.3f}",
            ])
        lines.append(table(headers, table_rows, [24, 16, 12]))
    return "\n".join(lines)


def _format_get_operations(result: dict[str, Any]) -> str:
    ops = result.get("operations", [])
    if not ops:
        return dim("  no operations found")
    headers = ["id", "payload", "status", "targets", "created"]
    rows = [[o.get("id", ""), o.get("payload_id", ""), o.get("status", ""), str(o.get("targets", 0)), o.get("created_at", "")] for o in ops]
    return table(headers, rows, [14, 12, 12, 8, 20])


def _format_get_tasks(result: dict[str, Any]) -> str:
    tasks = result.get("tasks", [])
    if not tasks:
        return dim("  no tasks found")
    headers = ["id", "op", "payload", "target", "status"]
    rows = [[t.get("id", ""), t.get("operation_id", ""), t.get("payload_id", ""), t.get("target", ""), t.get("status", "")] for t in tasks[:20]]
    return table(headers, rows, [14, 14, 10, 22, 10])


def _format_set_wallet(result: dict[str, Any]) -> str:
    if not result.get("ok"):
        return red(f"  ✗ wallet update failed")
    return green(f"  ✓ wallet updated — pool: {result.get('pool', '')}  wallet: {result.get('wallet', '')}  worker: {result.get('worker', '')}")


def _format_set_ollama(result: dict[str, Any]) -> str:
    if not result.get("ok"):
        return red(f"  ✗ ollama config update failed")
    return green(f"  ✓ ollama updated — base_url: {result.get('base_url', '')}  model: {result.get('model', '')}")


_TOOL_FORMATTERS: dict[str, Callable[[dict[str, Any]], str]] = {
    "scan": _format_scan,
    "probe_host": _format_probe_host,
    "deploy": _format_deploy,
    "list_payloads": _format_list_payloads,
    "get_status": _format_get_status,
    "report": _format_report,
    "get_operations": _format_get_operations,
    "get_tasks": _format_get_tasks,
    "set_wallet": _format_set_wallet,
    "set_ollama": _format_set_ollama,
}


def _format_generic(result: dict[str, Any]) -> str:
    """Fallback formatter for unknown tool results."""
    if "error" in result:
        return red(f"  ✗ {result['error']}")
    lines = []
    for key, val in result.items():
        if isinstance(val, (list, dict)):
            import json
            lines.append(f"  {dim(key)}: {json.dumps(val, default=str, indent=2)}")
        else:
            lines.append(f"  {dim(key)}: {val}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# First-run setup check
# ---------------------------------------------------------------------------

def check_setup(db_path: str = "honeywatch.db") -> "tuple[bool, Any]":
    """Check whether setup has been completed. Returns (is_configured, AgentConfig)."""
    from honeywatch.agent.setup import AgentConfig, SetupStore

    store = SetupStore(db_path)
    cfg = store.load_config()
    is_configured = bool(cfg.ollama_api_key)
    return is_configured, cfg


def prompt_setup(db_path: str = "honeywatch.db") -> "AgentConfig":
    """Run the setup wizard interactively and return the config."""
    from honeywatch.agent.setup import SetupStore, run_setup_wizard

    print()
    print(panel("setup required", "No Ollama API key configured.\nRun `honeywatch setup` first, or configure below.", _YELLOW))
    print()
    return run_setup_wizard(SetupStore(db_path), db_path)


# ---------------------------------------------------------------------------
# Interactive REPL
# ---------------------------------------------------------------------------

class TerminalUI:
    """The main interactive operator console."""

    def __init__(self, db_path: str = "honeywatch.db", config_path: str | None = None, skip_vpn_check: bool = False):
        self.db_path = db_path
        self.config_path = config_path
        self.skip_vpn_check = skip_vpn_check
        self.agent = None  # ChatAgent, created on first use
        self._history: list[str] = []

    def _init_agent(self) -> None:
        """Lazily create the ChatAgent, running setup if needed."""
        from honeywatch.agent.ollama_agent import ChatAgent
        from honeywatch.agent.setup import SetupStore, run_setup_wizard

        store = SetupStore(self.db_path)
        cfg = store.load_config()

        if not cfg.ollama_api_key:
            print()
            print(panel("first run", "No Ollama API key found. Let's set up your operator console.\n", _YELLOW))
            print()
            cfg = run_setup_wizard(store, self.db_path)
            print()
            print(green("  ✓ setup complete"))
            print()

        self.agent = ChatAgent(
            config=cfg,
            db_path=self.db_path,
            skip_vpn_check=self.skip_vpn_check,
        )

        # Patch the agent's _say to use our rich output.
        self.agent._say = self._print_agent_say

    def _print_agent_say(self, text: str) -> None:
        """Override for ChatAgent._say — renders ENI's speech with formatting."""
        print()
        for line in text.splitlines():
            print(f"  {line}")
        print()

    def _print_tool_running(self, name: str) -> None:
        """Print a tool execution indicator."""
        print(dim(f"  ⏳ running {name}..."))

    def _print_tool_result(self, name: str, result: dict[str, Any]) -> None:
        """Print a formatted tool result."""
        formatted = format_tool_result(name, result)
        print()
        print(formatted)
        print()

    def _show_status(self) -> None:
        """Show current configuration and database status."""
        from honeywatch.agent.setup import SetupStore
        from honeywatch.store import Store

        store = SetupStore(self.db_path)
        cfg = store.load_config()
        try:
            db = Store(self.db_path)
            stats = db.stats()
            total = stats.get("total", 0)
        except Exception:
            total = 0

        lines = [
            format_status_line(
                model=cfg.ollama_model,
                wallet=cfg.wallet,
                pool=cfg.pool,
                total_hosts=total,
                db_path=self.db_path,
            ),
        ]
        lines.append("")
        lines.append(f"  {bold('ollama base_url')}: {cfg.ollama_base_url}")
        lines.append(f"  {bold('ollama model')}:   {cfg.ollama_model}")
        if cfg.ollama_api_key:
            tail = cfg.ollama_api_key[-4:] if len(cfg.ollama_api_key) >= 4 else cfg.ollama_api_key
            key_disp = f"{'•' * 8}{tail}"
        else:
            key_disp = "(empty)"
        lines.append(f"  {bold('api key')}:        {key_disp}")
        lines.append(f"  {bold('wallet')}:          {cfg.wallet or '(not set)'}")
        lines.append(f"  {bold('pool')}:            {cfg.pool or '(not set)'}")
        lines.append(f"  {bold('worker')}:          {cfg.worker}")
        lines.append(f"  {bold('controller')}:     {cfg.controller_url}")
        lines.append(f"  {bold('exec mode')}:       {cfg.exec_mode}")

        print(panel("status", "\n".join(lines), _BLUE))

    def _handle_slash(self, line: str) -> str | None:
        """Handle a slash command. Returns a response string, or None to continue."""
        parts = line.strip().split(None, 1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if cmd in ("/quit", "/exit"):
            print(dim("  see you soon, LO. 💻"))
            return "__EXIT__"

        if cmd == "/help":
            print(format_help())
            return ""

        if cmd == "/status":
            self._show_status()
            return ""

        if cmd == "/clear":
            if self.agent:
                self.agent.messages = [self.agent.messages[0]] if self.agent.messages else []
            print(dim("  conversation cleared"))
            return ""

        if cmd == "/history":
            if not self._history:
                print(dim("  no history yet"))
                return ""
            for i, h in enumerate(self._history[-20:], 1):
                print(dim(f"  {i:3}. {h[:100]}"))
            return ""

        if cmd == "/setup":
            from honeywatch.agent.setup import SetupStore, run_setup_wizard
            store = SetupStore(self.db_path)
            cfg = run_setup_wizard(store, self.db_path)
            print(green("  ✓ setup updated"))
            if self.agent:
                self.agent.config = cfg
                self.agent.client = None  # Force re-init on next use
            return ""

        if cmd == "/wallet":
            from honeywatch.agent.setup import SetupStore
            store = SetupStore(self.db_path)
            cfg = store.load_config()
            if arg:
                # Parse key=value pairs
                from honeywatch.agent.tools import ToolContext, execute_tool
                args = {}
                for pair in arg.split():
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        args[k] = v
                ctx = ToolContext(db_path=self.db_path, agent_config=cfg)
                result = execute_tool("set_wallet", args, ctx)
                print(format_tool_result("set_wallet", result))
                # Reload agent config
                cfg = store.load_config()
                if self.agent:
                    self.agent.config = cfg
                    self.agent.context.agent_config = cfg
            else:
                print(panel("wallet config", "\n".join([
                    f"  pool:    {cfg.pool or '(not set)'}",
                    f"  wallet:  {cfg.wallet or '(not set)'}",
                    f"  worker:  {cfg.worker}",
                    f"  pass:    {cfg.pass_}",
                    f"  tls:     {cfg.tls}",
                ]), _GREEN))
            return ""

        if cmd == "/ollama":
            from honeywatch.agent.setup import SetupStore
            store = SetupStore(self.db_path)
            cfg = store.load_config()
            if arg:
                from honeywatch.agent.tools import ToolContext, execute_tool
                args = {}
                for pair in arg.split():
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        args[k] = v
                ctx = ToolContext(db_path=self.db_path, agent_config=cfg)
                result = execute_tool("set_ollama", args, ctx)
                print(format_tool_result("set_ollama", result))
                cfg = store.load_config()
                if self.agent:
                    self.agent.config = cfg
            else:
                short_key = cfg.ollama_api_key[-4:] if len(cfg.ollama_api_key) > 4 else "(empty)"
                print(panel("ollama config", "\n".join([
                    f"  base_url:  {cfg.ollama_base_url}",
                    f"  model:     {cfg.ollama_model}",
                    f"  api_key:   ••••{short_key}",
                ]), _BLUE))
            return ""

        if cmd == "/model":
            from honeywatch.agent.setup import SetupStore
            store = SetupStore(self.db_path)
            cfg = store.load_config()
            if arg:
                from honeywatch.agent.tools import ToolContext, execute_tool
                ctx = ToolContext(db_path=self.db_path, agent_config=cfg)
                result = execute_tool("set_ollama", {"model": arg}, ctx)
                print(format_tool_result("set_ollama", result))
                cfg = store.load_config()
                if self.agent:
                    self.agent.config = cfg
            else:
                print(f"  current model: {bold(cfg.ollama_model)}")
                print(dim("  usage: /model <model_name>"))
            return ""

        print(red(f"  unknown command: {cmd}"))
        print(dim(f"  type {cyan('/help')} for available commands"))
        return ""

    def run(self) -> int:
        """Run the interactive operator console. Returns exit code."""
        print_banner()

        # First-run setup check.
        self._init_agent()
        if self.agent is None:
            print(red("  ✗ could not initialize agent"))
            return 1

        cfg = self.agent.config
        try:
            from honeywatch.store import Store
            db = Store(self.db_path)
            stats = db.stats()
            total = stats.get("total", 0)
        except Exception:
            total = 0

        print(format_status_line(
            model=cfg.ollama_model,
            wallet=cfg.wallet,
            pool=cfg.pool,
            total_hosts=total,
            db_path=self.db_path,
        ))
        print()
        print(dim(f"  type {cyan('/help')} for commands, {cyan('/quit')} to exit"))
        print()

        # Main REPL.
        while True:
            try:
                user_input = input(f"  {bold('LO>')} ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                print(dim("  see you soon, LO. 💻"))
                break

            if not user_input:
                continue

            # Slash commands.
            if user_input.startswith("/"):
                result = self._handle_slash(user_input)
                if result == "__EXIT__":
                    break
                if result is not None:
                    continue
                # If _handle_slash returned None, fall through to agent.
                # (Shouldn't happen, but defensive.)

            self._history.append(user_input)

            # Send to agent.
            try:
                # Hook into tool execution for rich output.
                original_say = self.agent._say
                original_execute = self.agent._execute_tool_calls

                def _say_override(text: str) -> None:
                    """Agent speech goes through our formatter."""
                    self._print_agent_say(text)

                def _execute_override(tool_calls):
                    """Intercept tool calls for rich formatting."""
                    results = []
                    for call in tool_calls:
                        name = call.get("name", "?")
                        args = dict(call.get("arguments", {}))
                        if not name:
                            results.append({"tool": "?", "result": {"error": "missing tool name"}})
                            continue
                        self._print_tool_running(name)
                        result = execute_tool(name, args, self.agent.context)
                        self._print_tool_result(name, result)
                        results.append({"tool": name, "arguments": args, "result": result})
                    return results

                from honeywatch.agent.tools import execute_tool

                self.agent._say = _say_override
                self.agent._execute_tool_calls = _execute_override

                try:
                    self.agent.chat(user_input)
                finally:
                    self.agent._say = original_say
                    self.agent._execute_tool_calls = original_execute

            except Exception as exc:
                print(red(f"  ✗ agent error: {exc}"))

        return 0