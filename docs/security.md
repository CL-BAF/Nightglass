# Security & Legal

## Scanning Without Authorization Is Illegal

> **honeywatch is a research and authorized-audit tool. Use it strictly on networks you own, or where you hold written authorization (pen-test contract, bug bounty scope, or as an internal security research box on your own lab).**

Scanning networks you do not own, or that you are not **explicitly authorized to test**, may be **illegal** — under:

- **US** — Computer Fraud and Abuse Act (CFAA)
- **UK** — Computer Misuse Act
- **EU** — NIS / cybercrime frameworks
- Equivalent national law worldwide

It can get your IP banned, your hosting account terminated, or worse. Unlimited internet scanning is noise. Respect [responsible disclosure](https://en.wikipedia.org/wiki/Responsible_disclosure), rate-limit politely (default `1000` pps, `scanners.masscan.rate`), and keep `--max-hosts` bounded when sweeping ranges you're not allowed to touch.

The README `## Full-internet scan examples` (`README.md:198`) carries a **STRONG WARNING** for exactly this reason — `0.0.0.0/0` at `10000` pps from a data-center IP against networks you don't own is how people get felony charges.

Also note: `masscan` and `zmap` need **root** (raw sockets) and are **Linux-only**.

## Honeypot Detection Is Probabilistic

Both the heuristic engine and the LLM return **confidence, not truth**:

- `real` means "consistent with a real SSH stack"
- `honeypot` means "evidence strongly suggests a honeypot"

Do not make perimeter decisions on a single scan. Feed verified hosts and `known_hashes` to `features.analyze()` to narrow the set.

## VPN Gate

`honeywatch scan` / `probe` refuse to start unless egress is Mullvad (`honeywatch/vpn.py:169`). This is a safety rail, not a guarantee of anonymity. Bypassing with `--skip-vpn-check` or `HONEYWATCH_SKIP_VPN=1` is at your own risk. See [VPN Gate](vpn.md).

## No Credentials, Ever

Probing reads banners and `KEXINIT`s, never authenticates. The single `auth_probe` opt-in (`probe.auth_probe`, `fingerprint/probe.py:343`) sends one deliberately bogus attempt and records only the rejection — it is off by default and sends no usable credential.

## C2 Hardening

- **TLS** — always front the controller with TLS (`honeywatch c2 --tls-cert/--tls-key` or `--generate-certs` for lab). For production, use `c2/tls.py:132` `render_nginx_config` behind nginx.
- **Bearer token** — set `c2.api_token` / `--api-token` so every REST + WebSocket request must carry `Authorization: Bearer <token>` or `?token=`. Workers must be started with the matching token.
- **Worker isolation** — workers claim tasks only from allowed `categories` (`miner`/`exploit`/`evasion`), keeping payload types separated by worker role and network scope.
- **Exec mode** — default `dry_run` is safe for review; `local_simulate` and `ssh` run real scripts — only use them on authorized targets.

## Payloads Are Not Bundled

Payloads (`payloads/registry.py:616`) are metadata + install/run script templates. The generated manifest tells a worker how to fetch or build the tool on the target (e.g. `curl` the `xmrig` release, `apt` install `metasploit`). No malware is shipped in the honeywatch distribution. Workers fetch or build artifacts on the target host.

Included tools (`masscan`, `zmap`, `nmap`, `paramiko`) are their own projects with their own licenses; honeywatch only orchestrates them.

## Reporting Abuse

If you find a genuinely misconfigured *real* service flagged as a honeypot, fix the config rather than ignoring the scan.

## No Warranty

honeywatch is provided as-is for security research and authorized testing. No warranty.

## Responsible Use Checklist

- [ ] Do you own the target or hold a signed scope?
- [ ] Is `--max-hosts` bounded for external ranges?
- [ ] Is `scanners.*.rate` conservative (default `1000`)?
- [ ] Are you egressing via Mullvad or have you explicitly opted out for a lab?
- [ ] Are C2 and workers using TLS + bearer tokens in production?
- [ ] Are workers scoped to allowed categories and networks?
