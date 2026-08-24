"""Interactive AI agent for honeywatch.

Provides a conversational CLI that lets the operator ask the AI to run scans,
deploy payloads, manage the C2 plane, and update configuration. The agent is
backed by the same Ollama Cloud client used for honeypot scoring.
"""

from __future__ import annotations

from honeywatch.agent.ollama_agent import ChatAgent
from honeywatch.agent.setup import SetupStore, run_setup_wizard
from honeywatch.agent.tools import TOOL_REGISTRY, execute_tool

__all__ = [
    "ChatAgent",
    "SetupStore",
    "TOOL_REGISTRY",
    "execute_tool",
    "run_setup_wizard",
]
