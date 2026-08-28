"""Programmatic failure-recovery enforcer for the honeywatch agent.

Sits between ``execute_tool`` and the model. When a tool call returns an error,
the enforcer classifies it (via :mod:`honeywatch.failure`) and, for failures
whose recovery action is a *programmatic* retry, injects a corrected tool call
and executes it before the model ever sees the failure -- so a transient
transport error or a bad-argument schema error is recovered without a model
round-trip (the model would often just blindly re-emit the same failing call).

Recovery is bounded and conservative:

* **Per-run retry cap** -- each original call may be auto-retried at most
  ``MAX_RETRIES`` times (keyed by a stable signature of the *original* call, so
  a RETRY_WITH_PARAMS that mutates args still counts against the same cap). A
  persistently failing call can't loop forever.
* **Only retryable classes** are auto-recovered: ``TRANSPORT_ERROR``
  (RETRY_SAME), ``TIMEOUT`` (RETRY_WITH_PARAMS -- bumps a ``timeout`` arg if
  the tool declares one), and ``SCHEMA_ERROR`` (strip invalid/unknown args
  against the tool's parameter schema and retry with the cleaned args).
* **Non-retryable failures** (STOP, SWITCH_CAPABILITY, CREATE_PREREQUISITE,
  GATHER_INFO, ESCALATE_OPERATOR) are *not* auto-retried -- they need a
  decision the enforcer can't make. They surface to the model with the
  ``FAILURE_CLASS`` / ``RECOVERY`` hint (appended by the agent loop) so the
  model picks the right next move instead of blindly retrying.
* **SCHEMA_ERROR arg-stripping** never invents arguments. It only removes args
  the tool's schema doesn't declare and coerces simple type mismatches
  (``"30"`` -> ``30`` for an integer param). A *missing required* argument
  can't be auto-fixed (there's nothing to strip into existence) and is left to
  the model.

Every injected recovery goes back through ``execute_tool``, so it is audited on
the tamper-evident chain like any other call -- recovery is observable, not
silent. Injected records carry a ``recovery`` marker so the model/operator can
see why a tool ran twice.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

from honeywatch.agent.tools import TOOL_REGISTRY, ToolContext, execute_tool
from honeywatch.failure import (
    FailureClass,
    RecoveryAction,
    classify_failure,
    recovery_for,
)

log = logging.getLogger(__name__)

# Max auto-retries per original failing call. Two is enough to absorb a single
# transient blip (transport reset, momentary timeout) without turning a
# genuinely broken call into a tight retry loop.
MAX_RETRIES = 2

# Sentinel for "could not coerce this value to the declared type".
_UNCOERCIBLE = object()


class RecoveryEnforcer:
    """Enforce programmatic failure recovery around ``execute_tool``.

    One instance per agent. Call :meth:`reset` at the start of each run (an
    autonomous run or one interactive turn) so per-run retry counters don't
    leak across runs.
    """

    def __init__(self, ctx: ToolContext):
        self._ctx = ctx
        # (tool, signature) -> retries already spent on this original call.
        self._retry_counts: dict[tuple[str, str], int] = {}
        # Log of injected corrective calls, for observability/metrics.
        self._injected: list[dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def reset(self) -> None:
        """Clear per-run retry counters and the injected-call log."""
        self._retry_counts.clear()
        self._injected.clear()

    @property
    def injected_calls(self) -> list[dict[str, Any]]:
        """A copy of the corrective calls injected since the last reset."""
        return list(self._injected)

    # ------------------------------------------------------------------ #
    # Main entry point
    # ------------------------------------------------------------------ #
    def execute_with_recovery(
        self,
        tool_calls: list[dict[str, Any]],
        on_running: Callable[[str], None] | None = None,
        on_result: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> list[dict[str, Any]]:
        """Execute ``tool_calls`` with programmatic recovery.

        Returns a list of result records shaped like
        ``{"tool", "arguments", "result"}`` (matching the historical
        ``_execute_tool_calls`` contract), with injected recovery records
        additionally carrying a ``recovery`` marker. Callbacks fire for every
        executed call, originals and recoveries alike.
        """
        records: list[dict[str, Any]] = []
        for call in tool_calls:
            records.extend(
                self._exec_one(call, origin_key=None, on_running=on_running, on_result=on_result)
            )
        return records

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    def _exec_one(
        self,
        call: dict[str, Any],
        origin_key: tuple[str, str] | None,
        on_running: Callable[[str], None] | None,
        on_result: Callable[[str, dict[str, Any]], None] | None,
        is_recovery: bool = False,
        recovery_tag: str = "",
    ) -> list[dict[str, Any]]:
        """Execute one call; on a retryable error, recurse into a recovery call."""
        name = call.get("name")
        args = _normalize_args(call.get("arguments", {}))
        if origin_key is None:
            origin_key = (name or "?", _arg_signature(args))

        if not name:
            record = {"tool": "?", "arguments": args, "result": {"error": "missing tool name"}}
            if on_result:
                on_result("?", record["result"])
            return [record]

        if on_running:
            on_running(name)
        result = execute_tool(name, args, self._ctx)
        if on_result:
            on_result(name, result)

        record: dict[str, Any] = {"tool": name, "arguments": args, "result": result}
        if is_recovery:
            record["recovery"] = recovery_tag

        records = [record]

        error = _error_text(result)
        if error is not None:
            recovery_call, tag = self._maybe_recover(name, args, error, origin_key)
            if recovery_call is not None:
                self._injected.append({"name": recovery_call["name"], "arguments": recovery_call["arguments"], "tag": tag})
                records.extend(
                    self._exec_one(
                        recovery_call, origin_key=origin_key,
                        on_running=on_running, on_result=on_result,
                        is_recovery=True, recovery_tag=tag,
                    )
                )
        return records

    def _maybe_recover(
        self,
        name: str,
        args: dict[str, Any],
        error_text: str,
        origin_key: tuple[str, str],
    ) -> tuple[dict[str, Any] | None, str]:
        """Decide whether to inject a corrective call for a failed tool.

        Returns ``(recovery_call, tag)`` or ``(None, "")`` when the failure is
        not programmatically recoverable (non-retryable, or retry budget
        exhausted). Never raises.
        """
        fc = classify_failure(error_text)
        action = recovery_for(fc)
        count = self._retry_counts.get(origin_key, 0)
        if count >= MAX_RETRIES:
            log.debug("recovery: %s/%s retry budget exhausted (%d)", name, fc.value, count)
            return None, ""

        try:
            if action == RecoveryAction.RETRY_SAME:
                self._retry_counts[origin_key] = count + 1
                return {"name": name, "arguments": dict(args)}, f"auto-retry:retry_same:{fc.value}"

            if action == RecoveryAction.RETRY_WITH_PARAMS:
                new_args = _bump_timeout(args)
                self._retry_counts[origin_key] = count + 1
                tag = "auto-retry:retry_with_params:" + fc.value
                if new_args is not args:
                    tag += ":timeout_bumped"
                return {"name": name, "arguments": new_args}, tag

            if action == RecoveryAction.REPAIR_CODE and fc == FailureClass.SCHEMA_ERROR:
                stripped = self._strip_invalid_args(name, args)
                if stripped is None:
                    # Schema error but nothing strip/coerce-able (e.g. a missing
                    # required arg) -> leave to the model.
                    return None, ""
                self._retry_counts[origin_key] = count + 1
                return {"name": name, "arguments": stripped}, "auto-retry:schema_strip"
        except Exception as exc:  # pragma: no cover - defensive
            log.debug("recovery: %s recovery planning failed: %r", name, exc)
            return None, ""

        # Non-retryable (STOP / SWITCH_CAPABILITY / CREATE_PREREQUISITE /
        # GATHER_INFO / ESCALATE_OPERATOR) -- a decision the enforcer can't make.
        return None, ""

    # ------------------------------------------------------------------ #
    # Schema-based argument cleaning (SCHEMA_ERROR)
    # ------------------------------------------------------------------ #
    def _strip_invalid_args(
        self, name: str, args: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Return args with unknown/invalid-type args removed/coerced, or None.

        None means "not strip-recoverable": either the tool isn't registered,
        the only problem is a *missing required* argument (stripping can't
        create it), or cleaning produced no change (the schema error wasn't an
        arg-shape issue we can fix). Coerces simple type mismatches against the
        declared schema (``"30"`` -> ``30`` for integer) rather than dropping
        the arg where possible.
        """
        spec = TOOL_REGISTRY.get(name, {}).get("spec", {})
        params = spec.get("parameters", {}) or {}
        props = params.get("properties", {}) or {}
        required = set(params.get("required", []) or [])

        if not props:
            return None  # unknown tool / no schema to clean against

        cleaned: dict[str, Any] = {}
        for key, value in args.items():
            declared = props.get(key)
            if declared is None:
                # Arg the tool doesn't accept -> drop it.
                continue
            coerced = _coerce_arg(value, declared.get("type"))
            if coerced is _UNCOERCIBLE:
                # Wrong type and not coercible. If it's a required arg we can't
                # drop it (that'd just trade a type error for a missing-required
                # error) -> give up and let the model fix it.
                if key in required:
                    return None
                continue
            cleaned[key] = coerced

        # If a required arg is now missing, stripping can't help.
        missing_required = [r for r in required if r not in cleaned or cleaned[r] is None]
        if missing_required:
            return None

        # Only retry if cleaning actually changed something.
        if cleaned == args:
            return None
        return cleaned


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _normalize_args(raw_args: Any) -> dict[str, Any]:
    """Coerce the model's ``arguments`` field to a dict (mirrors _execute_tool_calls)."""
    if isinstance(raw_args, dict):
        return dict(raw_args)
    if isinstance(raw_args, str):
        try:
            parsed = json.loads(raw_args)
            return parsed if isinstance(parsed, dict) else {}
        except (json.JSONDecodeError, ValueError):
            return {}
    return {}


def _arg_signature(args: dict[str, Any]) -> str:
    """A stable signature of a call's args for retry-keying.

    Uses sorted keys + json values so two calls with the same args in a
    different order share a signature (they're the same logical call).
    """
    try:
        return json.dumps(args, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return repr(sorted(args.items()))


def _error_text(result: Any) -> str | None:
    """Extract an error string from a tool result, or None if it succeeded."""
    if isinstance(result, dict) and result.get("error"):
        err = result["error"]
        return err if isinstance(err, str) else str(err)
    return None


def _bump_timeout(args: dict[str, Any]) -> dict[str, Any]:
    """Double a ``timeout`` argument if present and numeric (RETRY_WITH_PARAMS)."""
    if "timeout" not in args:
        return args
    new_args = dict(args)
    val = args["timeout"]
    if isinstance(val, bool):
        return args  # a boolean timeout is nonsensical; don't "bump" it
    if isinstance(val, (int, float)):
        new_args["timeout"] = val * 2
        return new_args
    # String timeout: parse int first, then float.
    try:
        new_args["timeout"] = int(val) * 2
    except (TypeError, ValueError):
        try:
            new_args["timeout"] = float(val) * 2
        except (TypeError, ValueError):
            return args  # can't bump; retry with unchanged args
    return new_args


def _coerce_arg(value: Any, type_name: str | None) -> Any:
    """Coerce ``value`` to ``type_name`` (JSON-schema primitive), or _UNCOERCIBLE.

    None stays None (an explicitly-null arg is the model's way of omitting it).
    Unknown/None type names pass the value through unchanged.
    """
    if value is None:
        return None
    if not type_name:
        return value
    t = type_name.lower()
    if t == "string":
        if isinstance(value, str):
            return value
        # Numbers/bools -> str is a safe, lossless-ish coercion for string params.
        if isinstance(value, (int, float, bool)):
            return str(value)
        return _UNCOERCIBLE
    if t == "integer":
        if isinstance(value, bool):  # bool is an int subclass; reject as int
            return _UNCOERCIBLE
        if isinstance(value, int):
            return value
        if isinstance(value, float) and value.is_integer():
            return int(value)
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                return _UNCOERCIBLE
        return _UNCOERCIBLE
    if t == "number":
        if isinstance(value, bool):
            return _UNCOERCIBLE
        if isinstance(value, (int, float)):
            return value
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                return _UNCOERCIBLE
        return _UNCOERCIBLE
    if t == "boolean":
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            low = value.strip().lower()
            if low in ("true", "1", "yes", "y"):
                return True
            if low in ("false", "0", "no", "n"):
                return False
            return _UNCOERCIBLE
        if isinstance(value, (int, float)):
            return bool(value)
        return _UNCOERCIBLE
    # Unknown type (array/object/etc.) -- don't guess; pass through.
    return value