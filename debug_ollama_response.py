#!/usr/bin/env python3
"""Minimal repro script for diagnosing empty-content responses from Ollama Cloud.

Usage:
    # Set your API key via env var:
    set OLLAMA_API_KEY=your-key-here

    # Option 1: Reproduce the original bug (empty content)
    python debug_ollama_response.py

    # Option 2: Specify model / base URL
    python debug_ollama_response.py --model minimax-m2.7:cloud
    python debug_ollama_response.py --model glm-5.2:cloud --base-url https://ollama.com/v1

    # Option 3: Use the config stored in honeywatch.db
    python debug_ollama_response.py --from-db honeywatch.db
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# Add project root to path so we can import honeywatch
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from honeywatch.ai.ollama import OllamaClient, AiError
from honeywatch.agent.setup import SetupStore


def main() -> None:
    parser = argparse.ArgumentParser(description="Debug Ollama Cloud empty-content bug")
    parser.add_argument("--model", default=None, help="Model name (e.g. glm-5.2:cloud)")
    parser.add_argument("--base-url", default=None, help="Base URL (default: https://ollama.com/v1)")
    parser.add_argument("--api-key", default=None, help="API key (or set OLLAMA_API_KEY env var)")
    parser.add_argument("--from-db", default=None, help="Load config from a honeywatch.db file")
    parser.add_argument("--json-mode", action="store_true", help="Send with json_mode=True")
    args = parser.parse_args()

    # Resolve config
    if args.from_db:
        store = SetupStore(args.from_db)
        cfg = store.load_config()
        base_url = args.base_url or cfg.ollama_base_url
        api_key = args.api_key or cfg.ollama_api_key or os.environ.get("OLLAMA_API_KEY", "")
        model = args.model or cfg.ollama_model
    else:
        base_url = args.base_url or "https://ollama.com/v1"
        api_key = args.api_key or os.environ.get("OLLAMA_API_KEY", "")
        model = args.model or "llama3.1:8b"

    print(f"=== Ollama Cloud Debug ===")
    print(f"Base URL : {base_url}")
    print(f"Model    : {model}")
    print(f"API key  : {'*' * 8}{api_key[-4:] if len(api_key) > 8 else '***'}")
    print(f"JSON mode: {args.json_mode}")
    print()

    client = OllamaClient(base_url=base_url, api_key=api_key, model=model)

    # ── Test 1: Reachability check ──
    print("--- Test 1: Reachability ---")
    try:
        reachable = client.is_reachable()
        print(f"  is_reachable(): {reachable}")
    except Exception as exc:
        print(f"  is_reachable() error: {exc}")
    print()

    # ── Test 2: Raw response dump ──
    print("--- Test 2: Raw response dump ---")
    messages = [
        {
            "role": "system",
            "content": (
                "Reply with ONLY a JSON object with this exact schema, no markdown:\n"
                '{"TOOLS":[{"name":"scan","arguments":{"targets":"10.0.0.0/24"}}],'
                '"SPEAK":"ok","DONE":false}'
            ),
        },
        {"role": "user", "content": "begin"},
    ]

    try:
        raw_full = client.raw_chat(messages, json_mode=args.json_mode)
        print("  Full response (pretty-printed):")
        print(json.dumps(raw_full, indent=2, default=str)[:3000])

        # Highlight the message object
        if "choices" in raw_full and raw_full["choices"]:
            msg = raw_full["choices"][0].get("message", {})
            print()
            print("  Message object keys:", list(msg.keys()))
            content_val = msg.get("content", "<MISSING>")
            reasoning_val = msg.get("reasoning_content", "<MISSING>")
            thinking_val = msg.get("thinking", "<MISSING>")
            print(f"  content           : {repr(content_val[:200] if isinstance(content_val, str) else content_val)}")
            print(f"  reasoning_content : {repr(reasoning_val[:200] if isinstance(reasoning_val, str) else reasoning_val)}")
            print(f"  thinking          : {repr(thinking_val[:200] if isinstance(thinking_val, str) else thinking_val)}")
    except AiError as exc:
        print(f"  AiError: {exc}")
    except Exception as exc:
        print(f"  Unexpected error: {type(exc).__name__}: {exc}")
    print()

    # ── Test 3: Normal chat (with fallback fix) ──
    print("--- Test 3: chat() with fallback fix ---")
    try:
        result = client.chat(messages, json_mode=args.json_mode)
        print(f"  chat() returned: {repr(result[:300] if len(result) > 300 else result)}")
    except AiError as exc:
        print(f"  AiError: {exc}")
    except Exception as exc:
        print(f"  Unexpected error: {type(exc).__name__}: {exc}")
    print()

    # ── Test 4: Simulated autonomous agent cycle ──
    print("--- Test 4: Simulated _ollama_chat ---")
    from honeywatch.agent.ollama_agent import ChatAgent

    try:
        agent = ChatAgent(
            db_path=args.from_db or ":memory:",
            skip_vpn_check=True,
        )
        # Override client config in case we got it from CLI args
        agent.client = OllamaClient(base_url=base_url, api_key=api_key, model=model, temperature=0.2)
        response = agent._ollama_chat(messages)
        print(f"  thoughts: {repr(response.get('thoughts', '')[:200])}")
        print(f"  speak    : {repr(response.get('speak', '')[:200])}")
        print(f"  tools    : {response.get('tools', [])}")
        print(f"  done     : {response.get('DONE', response.get('done', 'N/A'))}")
    except Exception as exc:
        print(f"  Error: {type(exc).__name__}: {exc}")

    print()
    print("=== Done ===")


if __name__ == "__main__":
    main()