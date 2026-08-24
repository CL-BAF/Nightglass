# API — VPN

`honeywatch/vpn.py:169`.

```python
from honeywatch.vpn import VpnError, egress_is_mullvad, interface_is_mull, mullvad_connected, opt_out_requested, require_mullvad, DEFAULT_TIMEOUT, REFUSAL
```

| Symbol | Detail |
|---|---|
| `MULLVAD_JSON` | `"https://am.i.mullvad.net/json"` |
| `MULLVAD_TEXT` | `"https://am.i.mullvad.net/connected"` |
| `DEFAULT_TIMEOUT` | `8.0` |
| `IFACE_PATTERNS` | `("mullvad","wg-mullvad","wg0")` |
| `_TRUTHY` | `("1","true","yes")` |
| `REFUSAL: str` | full refusal message to stderr |
| `class VpnError(RuntimeError)` | raised by `Pipeline._require_vpn` |
| `opt_out_requested() -> bool` | `HONEYWATCH_SKIP_VPN` in `_TRUTHY` |
| `_fetch(url, timeout)` | `urllib.request` helper |
| `egress_is_mullvad(timeout) -> bool` | JSON `mullvad_exit_ip` + text fallback |
| `interface_is_mull() -> bool` | delegates by OS |
| `_interface_linux()` | glob `/sys/class/net/*pat*` + `ip -j link` |
| `_interface_windows()` | PowerShell `Get-NetAdapter` |
| `mullvad_connected(timeout) -> tuple[bool,str]` | egress OR interface |
| `require_mullvad(timeout, quiet=False) -> bool` | prints gate OK/REFUSAL, returns bool |

Bypass: `--skip-vpn-check`, `HONEYWATCH_SKIP_VPN=1`, or `vpn.required=false`. See [VPN Gate](../vpn.md).
