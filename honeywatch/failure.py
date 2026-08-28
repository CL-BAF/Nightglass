"""Failure taxonomy for honeywatch.

Classifies tool/phase failures into a deterministic taxonomy and maps each
class to a recovery action.  The capability graph (Phase 3) consults this to
decide: retry with params?  Create a prerequisite?  Switch capability?  Stop?

The classifier is pure Python — deterministic regex rules, first match wins.
No LLM calls.  Cheap, testable, and the same logic runs in the agent loop's
stall-nudge path so the model gets a ``FAILURE_CLASS: <fc> — RECOVERY: <hint>``
line instead of a generic "try again" prompt.

Adapted from NetAttackAi's ``tools/failure_taxonomy.py`` but honeywatch-specific:
the regex patterns match honeywatch's own error strings (e.g. "paramiko
unavailable", "VPN gate blocked", "no sprayable hosts", "auth timeout").
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #


class FailureClass(str, Enum):
    """The classification of a failure.

    Each class maps to a :class:`RecoveryAction` that tells the graph / agent
    what to do next.
    """

    TARGET_UNREACHABLE = "target_unreachable"
    TIMEOUT = "timeout"
    UNSUPPORTED_TARGET = "unsupported_target"
    PREREQUISITE_MISSING = "prerequisite_missing"
    AUTH_FAILED = "auth_failed"
    TOOL_UNAVAILABLE = "tool_unavailable"
    MALFORMED_CODE = "malformed_code"
    UNEXPECTED_OUTPUT = "unexpected_output"
    FALSE_POSITIVE = "false_positive"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    SCOPE_BLOCKED = "scope_blocked"
    TRANSPORT_ERROR = "transport_error"
    SCHEMA_ERROR = "schema_error"
    UNKNOWN = "unknown"


class RecoveryAction(str, Enum):
    """What to do when a capability fails with a given :class:`FailureClass`."""

    RETRY_SAME = "retry_same"
    RETRY_WITH_PARAMS = "retry_with_params"
    REPAIR_CODE = "repair_code"
    CREATE_PREREQUISITE = "create_prerequisite"
    SWITCH_CAPABILITY = "switch_capability"
    GATHER_INFO = "gather_info"
    STOP = "stop"
    ESCALATE_OPERATOR = "escalate_operator"


# --------------------------------------------------------------------------- #
# Class -> recovery mapping
# --------------------------------------------------------------------------- #

_RECOVERY: dict[FailureClass, tuple[RecoveryAction, str]] = {
    FailureClass.TARGET_UNREACHABLE: (
        RecoveryAction.SWITCH_CAPABILITY,
        "Target is unreachable (connection refused / no route / host down); "
        "switch to a different target or skip this one.",
    ),
    FailureClass.TIMEOUT: (
        RecoveryAction.RETRY_WITH_PARAMS,
        "Retry once with a higher timeout or narrower scope; a second "
        "timeout means stop.",
    ),
    FailureClass.UNSUPPORTED_TARGET: (
        RecoveryAction.SWITCH_CAPABILITY,
        "Target does not support this capability (wrong OS, wrong service, "
        "wrong version); pick an alternate via query_capabilities.",
    ),
    FailureClass.PREREQUISITE_MISSING: (
        RecoveryAction.CREATE_PREREQUISITE,
        "A required artifact (credentials/foothold/privilege/shadow) is "
        "missing; create a task for a capability that produces it.",
    ),
    FailureClass.AUTH_FAILED: (
        RecoveryAction.CREATE_PREREQUISITE,
        "Authentication failed — obtain or validate credentials before "
        "retrying.",
    ),
    FailureClass.TOOL_UNAVAILABLE: (
        RecoveryAction.SWITCH_CAPABILITY,
        "The tool this capability needs is not installed (paramiko, sshpass, "
        "hashcat, john); switch to an alternate capability or install the tool.",
    ),
    FailureClass.MALFORMED_CODE: (
        RecoveryAction.REPAIR_CODE,
        "Generated code/payload is malformed (syntax error, bad template "
        "render); repair and retry.",
    ),
    FailureClass.UNEXPECTED_OUTPUT: (
        RecoveryAction.GATHER_INFO,
        "Tool produced unexpected output that doesn't match any known "
        "pattern; gather more info (probe the host) before retrying.",
    ),
    FailureClass.FALSE_POSITIVE: (
        RecoveryAction.STOP,
        "Hypothesis explicitly refuted (the target is not vulnerable / not "
        "a honeypot / patched version); stop trying this approach.",
    ),
    FailureClass.INSUFFICIENT_EVIDENCE: (
        RecoveryAction.GATHER_INFO,
        "Evidence is ambiguous — the tool ran but the result doesn't "
        "confirm or refute the claim; gather more info or try a different "
        "check.",
    ),
    FailureClass.SCOPE_BLOCKED: (
        RecoveryAction.STOP,
        "Action blocked by scope/VPN gate; never retry against another host.",
    ),
    FailureClass.TRANSPORT_ERROR: (
        RecoveryAction.RETRY_SAME,
        "Transient transport error (connection reset, broken pipe); retry "
        "once. A second failure means the backend is down — stop.",
    ),
    FailureClass.SCHEMA_ERROR: (
        RecoveryAction.REPAIR_CODE,
        "Tool arguments failed schema validation; fix the arguments and "
        "retry.",
    ),
    FailureClass.UNKNOWN: (
        RecoveryAction.RETRY_WITH_PARAMS,
        "Unknown failure; retry once with different parameters. An "
        "identical repeat means stop.",
    ),
}


# --------------------------------------------------------------------------- #
# Regex rules — first match wins (case-insensitive)
# --------------------------------------------------------------------------- #

# Ordered tuple of (pattern, FailureClass). The first pattern that
# matches the lowercased text wins. Patterns are ordered so more specific
# classes (FALSE_POSITIVE, PREREQUISITE_MISSING) are checked before the
# generic fallbacks (UNKNOWN, UNEXPECTED_OUTPUT).
_RULES: tuple[tuple[re.Pattern[str], FailureClass], ...] = (
    # FALSE_POSITIVE — hypothesis refuted, not vulnerable, patched
    (re.compile(r"vuln_not_confirmed|not vulnerable|patched version|"
               r"false positive|not a honeypot|refuted"),
     FailureClass.FALSE_POSITIVE),

    # PREREQUISITE_MISSING — missing creds/foothold/shadow/wordlist
    (re.compile(r"requires?\s+(a\s+|an\s+)?(credential|foothold|session|"
               r"admin|root|privilege)|missing\s+(credential|prerequisite|"
               r"shadow|wordlist)|no\s+(valid\s+)?credentials|no\s+active\s+session|"
               r"foothold\s+required|no\s+footholds|no\s+sprayable|"
               r"wordlist\s+(not\s+found|missing)|no\s+wordlist"),
     FailureClass.PREREQUISITE_MISSING),

    # AUTH_FAILED — authentication rejected
    (re.compile(r"authentication\s*(failed|exception|error)|auth_failed|"
               r"bad\s+password|permission\s+denied|auth\s+error"),
     FailureClass.AUTH_FAILED),

    # SCOPE_BLOCKED — VPN gate or scope refusal (NOT "refused" alone —
    # that matches "connection refused" which is TARGET_UNREACHABLE)
    (re.compile(r"scope\s+(blocked|violation|exceeded)|"
               r"vpn\s+gate\s+blocked|mullvad.*not\s+connected|"
               r"refusal\s+from\s+(vpn|mullvad)"),
     FailureClass.SCOPE_BLOCKED),

    # TARGET_UNREACHABLE — host down, no route, refused
    (re.compile(r"connection\s+refused|no\s+route\s+to\s+host|host\s+is\s+down|"
               r"unreachable|network\s+is\s+unreachable"),
     FailureClass.TARGET_UNREACHABLE),

    # TOOL_UNAVAILABLE — paramiko/sshpass/hashcat/nmap/etc. missing
    (re.compile(r"paramiko\s+unavailable|"
               r"(?:sshpass|hashcat|john|nmap|masscan|zmap|openssl|python3)\s+(?:not\s+found|missing)|"
               r"backend\s+missing|tool.*not\s+installed|command\s+not\s+found|"
               r"\w+\s+not\s+found.*(?:path|binary|executable)"),
     FailureClass.TOOL_UNAVAILABLE),

    # TIMEOUT
    (re.compile(r"timeout|timed?\s+out|deadline\s+exceeded|connect\s+timeout|"
               r"auth\s+timeout"),
     FailureClass.TIMEOUT),

    # UNSUPPORTED_TARGET — wrong OS / service / version
    (re.compile(r"unsupported\s+target|wrong\s+(os|platform|service|version)|"
               r"not\s+supported\s+(on|for)|no\s+supported\s+(hashcat|john)\s+mode"),
     FailureClass.UNSUPPORTED_TARGET),

    # MALFORMED_CODE — syntax error, bad template, render failed
    (re.compile(r"syntax\s*error|template\s+(render|rendering)\s+(failed|error)|"
               r"malformed|unterminated|indentation\s+error"),
     FailureClass.MALFORMED_CODE),

    # SCHEMA_ERROR — missing required arg, invalid type
    (re.compile(r"missing\s+required\s+argument|invalid\s+(argument|type|"
               r"parameter)|schema\s+validation|argument\s+error"),
     FailureClass.SCHEMA_ERROR),

    # TRANSPORT_ERROR — connection reset, broken pipe, EOF, closed
    (re.compile(r"connection\s+reset|broken\s+pipe|eof\s+error|"
               r"transport\s+error|transport\(\d+\)|sshexception|ssl\s+error|"
               r"connection\s+(closed|dropped|lost)"),
     FailureClass.TRANSPORT_ERROR),

    # INSUFFICIENT_EVIDENCE — ambiguous result, no confirmation
    (re.compile(r"insufficient\s+evidence|ambiguous|inconclusive|"
               r"no\s+evidence|cannot\s+determine"),
     FailureClass.INSUFFICIENT_EVIDENCE),
)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def classify_failure(text: str | None) -> FailureClass:
    """Classify a failure text into a :class:`FailureClass`.

    The classifier is deterministic: ordered regex rules, first match wins
    on lowercased text.  Empty/None input returns ``UNKNOWN``.

    Args:
        text: tool result text, stderr, exception text, or a module note.

    Returns:
        The :class:`FailureClass` that best matches the text.
    """
    if not text:
        return FailureClass.UNKNOWN
    lower = text.lower()
    for pattern, fc in _RULES:
        if pattern.search(lower):
            return fc
    # Fallback: if generic error/failed/exception words appear, it's UNKNOWN;
    # otherwise UNEXPECTED_OUTPUT (the tool produced something but it doesn't
    # match any known failure pattern).
    if any(word in lower for word in ("error", "failed", "exception", "traceback")):
        return FailureClass.UNKNOWN
    return FailureClass.UNEXPECTED_OUTPUT


def recovery_for(fc: FailureClass) -> RecoveryAction:
    """Return the recovery action for a failure class."""
    entry = _RECOVERY.get(fc)
    if entry is None:
        return RecoveryAction.RETRY_WITH_PARAMS
    return entry[0]


def recovery_hint(fc: FailureClass) -> str:
    """Return the human/model-facing hint string for a failure class."""
    entry = _RECOVERY.get(fc)
    if entry is None:
        return "Unknown failure; retry once with different parameters."
    return entry[1]


def is_retryable(fc: FailureClass) -> bool:
    """True when the recovery action is a retry (RETRY_SAME, RETRY_WITH_PARAMS,
    REPAIR_CODE).  Non-retryable failures (STOP, SWITCH_CAPABILITY,
    CREATE_PREREQUISITE, GATHER_INFO, ESCALATE_OPERATOR) should not be
    blindly retried."""
    return recovery_for(fc) in (
        RecoveryAction.RETRY_SAME,
        RecoveryAction.RETRY_WITH_PARAMS,
        RecoveryAction.REPAIR_CODE,
    )


def is_permanent(fc: FailureClass) -> bool:
    """True when the failure is permanent (STOP, ESCALATE_OPERATOR) and the
    capability should not be retried at all.  A scope block or a refuted
    hypothesis means the approach is dead — don't waste budget retrying."""
    return recovery_for(fc) in (RecoveryAction.STOP, RecoveryAction.ESCALATE_OPERATOR)


def failure_class_line(text: str | None) -> str:
    """Format a ``FAILURE_CLASS: <fc> — RECOVERY: <hint>`` line for the model.

    Used in the agent loop's stall-nudge path so the model follows the
    recovery action instead of blindly retrying.
    """
    fc = classify_failure(text)
    action = recovery_for(fc)
    hint = recovery_hint(fc)
    return f"FAILURE_CLASS: {fc.value} — RECOVERY: {action.value} — {hint}"


def _coerce(fc: str | FailureClass) -> FailureClass:
    """Coerce a string to a FailureClass, falling back to UNKNOWN."""
    if isinstance(fc, FailureClass):
        return fc
    try:
        return FailureClass(fc)
    except (ValueError, TypeError):
        return FailureClass.UNKNOWN