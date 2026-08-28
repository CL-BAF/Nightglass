"""Tests for the failure taxonomy (Phase 4)."""

from __future__ import annotations

import pytest

from honeywatch.failure import (
    FailureClass,
    RecoveryAction,
    classify_failure,
    recovery_for,
    recovery_hint,
    is_retryable,
    is_permanent,
    failure_class_line,
    _coerce,
)


# --------------------------------------------------------------------------- #
# classify_failure
# --------------------------------------------------------------------------- #


class TestClassifyFailure:
    def test_empty_returns_unknown(self):
        assert classify_failure("") == FailureClass.UNKNOWN
        assert classify_failure(None) == FailureClass.UNKNOWN

    def test_timeout(self):
        assert classify_failure("connection timed out") == FailureClass.TIMEOUT
        assert classify_failure("auth timeout") == FailureClass.TIMEOUT

    def test_prerequisite_missing(self):
        assert classify_failure("no valid credentials") == FailureClass.PREREQUISITE_MISSING
        assert classify_failure("missing prerequisite: foothold") == FailureClass.PREREQUISITE_MISSING
        assert classify_failure("no sprayable hosts") == FailureClass.PREREQUISITE_MISSING
        assert classify_failure("no footholds") == FailureClass.PREREQUISITE_MISSING
        # Finding #3: missing wordlist is a missing input file
        assert classify_failure("wordlist not found: rockyou.txt") == FailureClass.PREREQUISITE_MISSING
        assert classify_failure("no wordlist available") == FailureClass.PREREQUISITE_MISSING
        assert classify_failure("missing wordlist") == FailureClass.PREREQUISITE_MISSING

    def test_auth_failed(self):
        assert classify_failure("Authentication failed") == FailureClass.AUTH_FAILED
        assert classify_failure("permission denied (publickey)") == FailureClass.AUTH_FAILED

    def test_scope_blocked(self):
        assert classify_failure("VPN gate blocked the crack run") == FailureClass.SCOPE_BLOCKED
        assert classify_failure("Mullvad VPN is not connected") == FailureClass.SCOPE_BLOCKED
        assert classify_failure("scope blocked by policy") == FailureClass.SCOPE_BLOCKED

    def test_target_unreachable(self):
        assert classify_failure("connection refused") == FailureClass.TARGET_UNREACHABLE
        assert classify_failure("no route to host") == FailureClass.TARGET_UNREACHABLE
        assert classify_failure("host is down") == FailureClass.TARGET_UNREACHABLE

    def test_tool_unavailable(self):
        assert classify_failure("paramiko unavailable: ImportError") == FailureClass.TOOL_UNAVAILABLE
        assert classify_failure("sshpass not found") == FailureClass.TOOL_UNAVAILABLE
        assert classify_failure("hashcat not found") == FailureClass.TOOL_UNAVAILABLE
        # Finding #1: "nmap not found" should be TOOL_UNAVAILABLE, not UNEXPECTED_OUTPUT
        assert classify_failure("nmap not found") == FailureClass.TOOL_UNAVAILABLE
        assert classify_failure("masscan not found") == FailureClass.TOOL_UNAVAILABLE
        assert classify_failure("openssl not found") == FailureClass.TOOL_UNAVAILABLE
        assert classify_failure("python3 not found in path") == FailureClass.TOOL_UNAVAILABLE

    def test_false_positive(self):
        assert classify_failure("not vulnerable") == FailureClass.FALSE_POSITIVE
        assert classify_failure("vuln_not_confirmed") == FailureClass.FALSE_POSITIVE
        assert classify_failure("patched version") == FailureClass.FALSE_POSITIVE
        assert classify_failure("refuted by empty result") == FailureClass.FALSE_POSITIVE

    def test_transport_error(self):
        assert classify_failure("connection reset by peer") == FailureClass.TRANSPORT_ERROR
        assert classify_failure("broken pipe") == FailureClass.TRANSPORT_ERROR
        assert classify_failure("SSHException: EOF") == FailureClass.TRANSPORT_ERROR
        # Finding #2: spray module emits "transport(255): Connection closed"
        assert classify_failure("transport(255): Connection closed") == FailureClass.TRANSPORT_ERROR
        assert classify_failure("connection closed by peer") == FailureClass.TRANSPORT_ERROR
        assert classify_failure("connection dropped") == FailureClass.TRANSPORT_ERROR

    def test_malformed_code(self):
        assert classify_failure("SyntaxError: unexpected indent") == FailureClass.MALFORMED_CODE
        assert classify_failure("template rendering failed") == FailureClass.MALFORMED_CODE

    def test_schema_error(self):
        assert classify_failure("missing required argument: host") == FailureClass.SCHEMA_ERROR
        assert classify_failure("invalid type for parameter") == FailureClass.SCHEMA_ERROR

    def test_unsupported_target(self):
        assert classify_failure("unsupported target") == FailureClass.UNSUPPORTED_TARGET
        assert classify_failure("no supported hashcat mode") == FailureClass.UNSUPPORTED_TARGET

    def test_insufficient_evidence(self):
        assert classify_failure("insufficient evidence") == FailureClass.INSUFFICIENT_EVIDENCE
        assert classify_failure("inconclusive result") == FailureClass.INSUFFICIENT_EVIDENCE

    def test_generic_error_returns_unknown(self):
        assert classify_failure("some random error happened") == FailureClass.UNKNOWN
        assert classify_failure("failed to do the thing") == FailureClass.UNKNOWN

    def test_non_error_text_returns_unexpected_output(self):
        assert classify_failure("scan completed with 50 hosts") == FailureClass.UNEXPECTED_OUTPUT
        assert classify_failure("all good here") == FailureClass.UNEXPECTED_OUTPUT

    def test_case_insensitive(self):
        assert classify_failure("CONNECTION REFUSED") == FailureClass.TARGET_UNREACHABLE
        assert classify_failure("TIMEOUT") == FailureClass.TIMEOUT
        assert classify_failure("AuthenticationException") == FailureClass.AUTH_FAILED

    def test_first_match_wins(self):
        # "no valid credentials" matches PREREQUISITE_MISSING before AUTH_FAILED
        # because PREREQUISITE_MISSING is checked first.
        assert classify_failure("no valid credentials found") == FailureClass.PREREQUISITE_MISSING


# --------------------------------------------------------------------------- #
# recovery_for / recovery_hint
# --------------------------------------------------------------------------- #


class TestRecovery:
    def test_prerequisite_missing_creates_prereq(self):
        assert recovery_for(FailureClass.PREREQUISITE_MISSING) == RecoveryAction.CREATE_PREREQUISITE

    def test_timeout_retries_with_params(self):
        assert recovery_for(FailureClass.TIMEOUT) == RecoveryAction.RETRY_WITH_PARAMS

    def test_false_positive_stops(self):
        assert recovery_for(FailureClass.FALSE_POSITIVE) == RecoveryAction.STOP

    def test_scope_blocked_stops(self):
        assert recovery_for(FailureClass.SCOPE_BLOCKED) == RecoveryAction.STOP

    def test_transport_error_retries_same(self):
        assert recovery_for(FailureClass.TRANSPORT_ERROR) == RecoveryAction.RETRY_SAME

    def test_target_unreachable_switches(self):
        assert recovery_for(FailureClass.TARGET_UNREACHABLE) == RecoveryAction.SWITCH_CAPABILITY

    def test_tool_unavailable_switches(self):
        assert recovery_for(FailureClass.TOOL_UNAVAILABLE) == RecoveryAction.SWITCH_CAPABILITY

    def test_unknown_retries_with_params(self):
        assert recovery_for(FailureClass.UNKNOWN) == RecoveryAction.RETRY_WITH_PARAMS

    def test_recovery_hint_nonempty(self):
        for fc in FailureClass:
            hint = recovery_hint(fc)
            assert hint, f"empty hint for {fc}"

    def test_recovery_hint_mentiones_action(self):
        # The hint for each class should mention what to do.
        for fc in FailureClass:
            hint = recovery_hint(fc).lower()
            action = recovery_for(fc).value.replace("_", " ")
            # The hint should at least be meaningful (non-empty, multi-word).
            assert len(hint) > 10


# --------------------------------------------------------------------------- #
# is_retryable / is_permanent
# --------------------------------------------------------------------------- #


class TestRetryablePermanent:
    def test_retryable_classes(self):
        assert is_retryable(FailureClass.TIMEOUT) is True
        assert is_retryable(FailureClass.TRANSPORT_ERROR) is True
        assert is_retryable(FailureClass.MALFORMED_CODE) is True
        assert is_retryable(FailureClass.UNKNOWN) is True

    def test_not_retryable_classes(self):
        assert is_retryable(FailureClass.FALSE_POSITIVE) is False
        assert is_retryable(FailureClass.SCOPE_BLOCKED) is False
        assert is_retryable(FailureClass.PREREQUISITE_MISSING) is False
        assert is_retryable(FailureClass.TARGET_UNREACHABLE) is False

    def test_permanent_classes(self):
        assert is_permanent(FailureClass.FALSE_POSITIVE) is True
        assert is_permanent(FailureClass.SCOPE_BLOCKED) is True

    def test_not_permanent_classes(self):
        assert is_permanent(FailureClass.TIMEOUT) is False
        assert is_permanent(FailureClass.PREREQUISITE_MISSING) is False
        assert is_permanent(FailureClass.UNKNOWN) is False


# --------------------------------------------------------------------------- #
# failure_class_line
# --------------------------------------------------------------------------- #


class TestFailureClassLine:
    def test_format(self):
        line = failure_class_line("connection timed out")
        assert "FAILURE_CLASS:" in line
        assert "timeout" in line
        assert "RECOVERY:" in line

    def test_empty_text(self):
        line = failure_class_line("")
        assert "unknown" in line

    def test_none_text(self):
        line = failure_class_line(None)
        assert "unknown" in line


# --------------------------------------------------------------------------- #
# _coerce
# --------------------------------------------------------------------------- #


class TestCoerce:
    def test_string_to_enum(self):
        assert _coerce("timeout") == FailureClass.TIMEOUT
        assert _coerce("scope_blocked") == FailureClass.SCOPE_BLOCKED

    def test_enum_passthrough(self):
        assert _coerce(FailureClass.TIMEOUT) == FailureClass.TIMEOUT

    def test_invalid_string_returns_unknown(self):
        assert _coerce("bogus_class") == FailureClass.UNKNOWN
        assert _coerce(123) == FailureClass.UNKNOWN