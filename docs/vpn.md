# VPN Gate

`honeywatch/vpn.py:169` — Mullvad VPN gating for `honeywatch scan` and `honeywatch probe`. Network subcommands refuse to start unless your traffic egresses through Mullvad.

## Why

Scanning without Mullvad exposes your real IP to every target. The gate is a safety rail — it forces you to be intentional about egress. For controlled/offline testing, it can be bypassed explicitly.

## Check Logic

`mullvad_connected(timeout=8.0) -> tuple[bool, str]` tries in order:

1. **Egress IP check** — `egress_is_mullvad(timeout)`:
   - GET `https://am.i.mullvad.net/json` → JSON `mullvad_exit_ip is true`
   - Fallback GET `https://am.i.mullvad.net/connected` → plain text `You are connected`
   - Uses `urllib.request` with `DEFAULT_TIMEOUT=8.0`, handles `OSError`/`HTTPError` as not-connected.

2. **Interface check** — `interface_is_mull() -> bool` — delegates by OS:
   - Linux (`_interface_linux`): glob `/sys/class/net/*mullvad*`, `/sys/class/net/*wg*` + `ip -j link` JSON parsing for `mullvad`, `wg-mullvad`, `wg0` (`IFACE_PATTERNS`).
   - Windows (`_interface_windows`): PowerShell `Get-NetAdapter` for the same patterns.

`opt_out_requested() -> bool` checks `HONEYWATCH_SKIP_VPN` in `("1","true","yes")` (`_TRUTHY`). When true, the gate is skipped.

`require_mullvad(timeout, quiet=False) -> bool` is the public gate: calls `mullvad_connected`, prints `honeywatch: vpn gate OK (am.i.mullvad.net confirms a Mullvad exit IP)` to stderr on success, or `REFUSAL` on failure, returns bool.

```python
from honeywatch.vpn import require_mullvad, mullvad_connected, egress_is_mullvad, interface_is_mull, opt_out_requested, VpnError

if not require_mullvad(timeout=8.0):
    print(REFUSAL)  # REFUSAL constant at vpn.py:169
```

## Enforcement

`cli.py:561` `_enforce_vpn(cfg, skip_vpn_check) -> bool`:

```python
required = bool(cfg.vpn.required)  # default True
if skip_vpn_check or not required:
    return True
timeout = cfg.vpn.timeout_s  # default 8.0
return require_mullvad(timeout=timeout)
```

Called by `_cmd_scan`, `_cmd_probe`, `_cmd_c2`, `_cmd_deploy`, `_cmd_chat` network paths. On `False`, the command exits with code `2` and prints `REFUSAL` (`vpn.py:169`):

```
honeywatch: REFUSAL — Mullvad VPN required. Connect with `mullvad connect` or use --skip-vpn-check to bypass at your own risk.
```

`Pipeline._require_vpn(skip)` (`pipeline.py:352`) raises `VpnError(RuntimeError)` for the same condition when called directly.

## Bypass

For controlled/offline testing only:

```bash
honeywatch scan 192.0.2.0/24 --skip-vpn-check
HONEYWATCH_SKIP_VPN=1 honeywatch probe 1.2.3.4
```

Or permanently in `config.toml`:

```toml
[vpn]
required = false
provider = "mullvad"
timeout_s = 8.0
```

All three are equivalent; `--skip-vpn-check` is per-invocation, `HONEYWATCH_SKIP_VPN=1` is env, `vpn.required=false` is config file. The env/config bypass is checked before any network call.

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `vpn.required` | `true` | enforce the gate |
| `vpn.provider` | `"mullvad"` | tunnel provider (only `mullvad` today) |
| `vpn.timeout_s` | `8.0` | connectivity-check timeout |

Piping through a different VPN is not currently supported — the gate explicitly checks for Mullvad's endpoint and interface names.

## Constants

- `MULLVAD_JSON = "https://am.i.mullvad.net/json"`
- `MULLVAD_TEXT = "https://am.i.mullvad.net/connected"`
- `DEFAULT_TIMEOUT = 8.0`
- `IFACE_PATTERNS = ("mullvad","wg-mullvad","wg0")`
- `REFUSAL: str` — full refusal message printed to stderr
- `class VpnError(RuntimeError)` — raised by `Pipeline._require_vpn` on failure

## Testing

`tests/test_vpn.py` mocks `urllib.request.urlopen` and `glob`/`subprocess` to cover `egress_is_mullvad`, `interface_is_mull`, `require_mullvad`, `opt_out_requested`.
