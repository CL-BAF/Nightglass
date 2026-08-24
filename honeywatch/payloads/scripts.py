"""Script rendering helpers for red-team payload manifests.

Keeps honeywatch stdlib-only by using a tiny regex template engine instead of
pulling in Jinja2. Templates use ``{{var}}`` and ``{{var|default('value')}}``.
"""

from __future__ import annotations

import random
import re
import string
import uuid
from typing import Any

from honeywatch.models import DeploymentManifest, Payload, Target

_TOKEN_RE = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\|\s*default\(['\"]?([^)'\"]*)['\"]?\))?\s*\}\}")


def _render_template(
    template: str, variables: dict[str, Any], strict: bool = False
) -> str:
    """Substitute ``{{key|default('x')}}`` placeholders in ``template``.

    When ``strict`` is True, unknown placeholders are left untouched instead
    of being replaced by their default or an empty string.
    """

    def repl(match: re.Match) -> str:
        key = match.group(1)
        default = match.group(2)
        value = variables.get(key)
        if value is None or value == "":
            if strict:
                return match.group(0)
            return default if default is not None else ""
        return str(value)

    return _TOKEN_RE.sub(repl, template)


def _inject_ids(
    script: str, payload_id: str, target: Target | None, op_id: str
) -> str:
    """Add deterministic runtime identifiers to a rendered script.

    ``op_id`` is generated once per :func:`render_payload_script` call and shared
    between the install and run sections so both report the same operation id.
    """
    extras = {
        "payload_id": payload_id,
        "operation_id": op_id,
        "target_ip": target.ip if target else "",
        "target_port": target.port if target else 22,
    }
    return _render_template(script, extras, strict=True)


def render_payload_script(payload: Payload, variables: dict[str, Any], target: Target | None = None) -> str:
    """Render a payload's install script (and optionally run script) for one host."""
    # One operation id for both the install and run sections so they agree.
    op_id = uuid.uuid4().hex[:12]
    script = _inject_ids(payload.install_script, payload.id, target, op_id)
    script = _render_template(script, variables)
    if payload.run_script:
        run = _inject_ids(payload.run_script, payload.id, target, op_id)
        run = _render_template(run, variables)
        script += f"\n\n# --- run command ---\n{run}\n"
    return script


def validate_variables(payload: Payload, variables: dict[str, Any]) -> list[str]:
    """Return a list of missing required variables for ``payload``."""
    missing: list[str] = []
    for key, spec in payload.config_schema.items():
        if spec.get("required") and variables.get(key) in (None, ""):
            missing.append(key)
    return missing


def validate_variable_types(payload: Payload, variables: dict[str, Any]) -> list[str]:
    """Return human-readable type-mismatch errors for present variables.

    Only variables that are actually set (non-None, non-empty) are checked, so
    unset optional fields and defaults filled in later by :func:`merge_defaults`
    are not flagged. Integer fields must ``int()``-parse; boolean fields must be
    a real bool or the string form ``true``/``false`` (the forms the CLI and the
    chain orchestrator pass after coercing config values to strings).
    """
    errors: list[str] = []
    for key, spec in payload.config_schema.items():
        value = variables.get(key)
        if value is None or value == "":
            continue
        vtype = spec.get("type")
        if vtype == "integer":
            try:
                int(str(value))
            except (TypeError, ValueError):
                errors.append(f"{key} must be an integer, got {value!r}")
        elif vtype == "boolean":
            if str(value).strip().lower() not in {"true", "false"}:
                errors.append(f"{key} must be a boolean (true/false), got {value!r}")
    return errors


# Variables whose values are intentionally free-form script/program text and so
# are exempt from the shell-metacharacter sanitizer below. Everything else
# (wallets, pools, paths, usernames, tokens, arch tags) never legitimately
# contains command-substitution or sequence operators.
_FREEFORM_VARS = frozenset({"resource_script"})

# Patterns that, in a payload variable value, almost always indicate an attempt
# (or accident) to break out of the surrounding shell context. Blocking these
# protects the operator from self-injection via a pasted wallet/pool/etc.
_UNSAFE_PATTERNS = (
    "`",     # command substitution
    "$(",    # command substitution
    "${",    # parameter expansion
    "$",     # bare variable expansion ($HOME, $PATH etc.)
    "&&",    # command sequencing
    "||",    # command sequencing
    ";",     # command separator
    '"',     # breaks out of double-quoted shell strings
    "\n",    # newline injection
    "\r",    # carriage return
)


def unsafe_variable_reasons(
    variables: dict[str, Any],
    freeform: frozenset[str] = _FREEFORM_VARS,
) -> list[tuple[str, str]]:
    """Return ``(key, reason)`` pairs for values containing shell hazards.

    A value is flagged when it contains a command-substitution / sequencing /
    newline pattern and the key is not in ``freeform``. Used by
    :func:`build_manifest` to refuse dangerous variable values unless the
    operator explicitly opts in via ``allow_unsafe_vars``.
    """
    problems: list[tuple[str, str]] = []
    for key, value in variables.items():
        if key in freeform:
            continue
        text = "" if value is None else str(value)
        for pat in _UNSAFE_PATTERNS:
            if pat in text:
                problems.append((key, repr(pat)))
                break
    return problems


def merge_defaults(payload: Payload, variables: dict[str, Any]) -> dict[str, Any]:
    """Return ``variables`` with schema defaults filled in where absent."""
    merged = dict(variables)
    for key, spec in payload.config_schema.items():
        if key not in merged or merged[key] in (None, ""):
            default = spec.get("default")
            if default is not None:
                merged[key] = default
    return merged


def render_manifest_scripts(manifest: DeploymentManifest) -> dict[str, str]:
    """Render per-host install scripts for every target in ``manifest``."""
    payload = manifest.payload
    variables = merge_defaults(payload, manifest.variables)
    scripts: dict[str, str] = {}
    for target in manifest.targets:
        host_vars = dict(variables)
        if target.ssh_user:
            host_vars.setdefault("run_user", target.ssh_user)
        scripts[target.ip] = render_payload_script(payload, host_vars, target)
    return scripts


def generate_operation_id() -> str:
    """Return a short random operation id."""
    return "hw-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
