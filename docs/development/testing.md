# Testing

`tests/` — 19 test modules, ~150 tests, `pytest -q` via `tool.pytest.ini_options` (`pyproject.toml:47` `testpaths=["tests"]`, `addopts="-q"`).

## Running

```bash
pip install -e .[dev]   # pytest>=7.0
pytest -q
pytest -v tests/test_vpn.py
pytest -k "test_analyze"
pytest --collect-only
```

## Fixtures (`tests/conftest.py`)

`conftest.py:191`:

- `craft_banner(software, version)` — helper to build `SSH-2.0-...` banners.
- `build_kexinit_packet(...)` — RFC 4253 packet builder: 16-byte cookie + ten name-lists + flags, returns raw bytes for `parse_kexinit` tests.
- `openssh_fp` — realistic `Fingerprint` for OpenSSH 9.3p1 (modern algos, `chacha20-poly1305`, `curve25519-sha256`).
- `cowrie_fp` — honeypot-like `Fingerprint` for Cowrie 5.1p1 (legacy `3des`/`arcfour`, `hmac-md5`, `ssh-dss`).
- `SSH_MSG_KEXINIT = 20`.

## Test Matrix

| File | Coverage | Key tests |
|---|---|---|
| `test_cli.py` | CLI help & parsing | `test_build_parser_help_exits_zero`, `test_cli_main_help_returns_zero`, `test_build_parser_has_subcommands` (10), `test_cli_main_deploy_dry_run_with_target_file`, `test_cli_main_setup_non_interactive`, `parse_host`/`parse_ports` helpers |
| `test_cli_chat.py` | ANSI UI & slash | `TestAnsiFormatting` (bold/dim/red/green/no-color), `TestPanelAndTable`, `TestFormatToolResult`, `TestFormatStatusLine`, `TestSlashHelp`, `TestCheckSetup` |
| `test_fingerprint.py` | Banner/KEXINIT | `test_parse_banner_*`, `test_parse_kexinit_*`, `test_probe_ssh_*` |
| `test_features.py` | Heuristics | `test_analyze_*` legacy cipher/mac, missing chacha, weak key, instant banner, farm reuse |
| `test_ai_scorer.py` | AI scorer | `test_verdict_from_text_*` (valid/wrapped/garbage/empty/clamped), `test_profile_key_*` (stable/reorder/differs/hex), `test_scorer_batch/individual/unreachable/empty` |
| `test_scan_filter.py` | SSH-only filter | `test_is_ssh_*`, `test_probe_hosts_*` (drops non-ssh by default, keeps when disabled) |
| `test_store_report.py` | Store & reports | `test_upsert_scores`, `test_query_*`, `test_write_json/csv/md`, `test_stats` |
| `test_vpn.py` | VPN gate | `test_egress_is_mullvad_*`, `test_interface_is_mull_*`, `test_require_mullvad_*`, `test_opt_out_requested` |
| `test_payloads.py` | Registry | `test_registry_contains_*`, `test_get_payload_*`, `test_render_manifest_scripts`, `test_validate_variables` |
| `test_agent_ollama.py` | ChatAgent | `test_chat_agent_*` tool calls + fallback |
| `test_agent_tools.py` | Tools | `test_list_payloads_tool`, `test_get_status_tool`, `test_deploy_tool_autofills_wallet`, `test_set_wallet_tool`, `test_report_tool`, `test_get_operations_tool` |
| `test_agent_setup.py` | SetupStore | `test_setup_store_*`, `test_run_setup_wizard_*` |
| `test_c2_store.py` | C2Store | `test_create_operation`, `test_claim_next_task_*`, `test_complete_task`, `test_list_workers` |
| `test_c2_worker.py` | Worker | `test_worker_execute_*` (dry_run/local_simulate), `test_worker_claim_task` |
| `test_c2_controller.py` | Controller | async `test_health_endpoint`, `test_dashboard_served`, `test_create_operation`, `test_claim_and_complete_task` (aiohttp) |
| `test_ops.py` | Targeting/deploy | `test_select_targets_*` (by label/limit/ssh creds), `test_build_manifest_*`, `test_prepare_evasion_pipeline`, `test_enqueue_operation_creates_tasks` |
| `test_regressions.py` | Regressions | `test_farm_flagged_when_same_key_on_two_hosts`, `test_distinct_keys_not_farms`, `test_single_host_not_farm`, `test_instant_banner_*`, `test_scorer_batch_chunks_large_profile_sets`, `test_scan_*vpn*`, `test_scan_passes_scanner_timeout/excludes`, `test_query_scores_*` |
| `test_upgrades.py` | WAL/keys/indexes | `test_store_runs_in_wal_with_indexes`, `test_store_query_uses_indexes_not_full_scan`, `test_store_schema_applied_once`, `test_known_keys_*`, `test_learn_from_scores` |

## Writing Tests

- Use `Store(":memory:")` for isolated DB (shared single connection, no WAL).
- Mock `urllib.request.urlopen` for VPN/Ollama tests.
- Mock `subprocess.run` for scanner tests.
- Use `conftest.py` helpers `build_kexinit_packet` / `craft_banner` for fingerprint fixtures.
- Non-interactive wizard: `run_setup_wizard(store, db_path, non_interactive={...})`.

## CI Hints

- `pytest` is the only dev dependency; no coverage plugin by default.
- Tests avoid network — all HTTP/subprocess is mocked.
- VPN tests mock both JSON endpoint and interface glob.
