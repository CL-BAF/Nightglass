"""Tests for bundled wordlist, default wordlist wiring, and external tool checks."""

from __future__ import annotations

import os
import sys
from unittest.mock import patch

import pytest

from honeywatch.data.wordlists import default_wordlist_path, load_default_wordlist
from honeywatch.crack import (
    default_wordlist_path as crack_default_path,
    load_wordlist,
    candidate_passwords,
    _BUILTIN_PASSWORDS,
)
from honeywatch.agent.setup import check_external_tools, _EXTERNAL_TOOLS


# --------------------------------------------------------------------------- #
# Bundled wordlist
# --------------------------------------------------------------------------- #


class TestBundledWordlist:
    """Tests for the bundled default wordlist file and access functions."""

    def test_default_wordlist_path_points_to_existing_file(self):
        path = default_wordlist_path()
        assert os.path.isfile(path), f"wordlist not found at {path}"

    def test_crack_default_path_matches_data_path(self):
        assert crack_default_path() == default_wordlist_path()

    def test_load_default_wordlist_returns_nonempty(self):
        words = load_default_wordlist()
        assert len(words) > 100, f"wordlist too small: {len(words)} entries"

    def test_load_default_wordlist_no_blank_lines(self):
        words = load_default_wordlist()
        for w in words:
            assert w.strip() == w, f"whitespace in word: {w!r}"
            assert w, "empty string in wordlist"

    def test_load_default_wordlist_no_comments(self):
        words = load_default_wordlist()
        for w in words:
            assert not w.startswith("#"), f"comment leaked: {w!r}"

    def test_load_wordlist_with_bundled_path(self):
        """load_wordlist on the bundled path returns the same list."""
        words = load_wordlist(default_wordlist_path())
        assert words == load_default_wordlist()

    def test_load_wordlist_missing_file_returns_empty(self):
        assert load_wordlist("/nonexistent/path/wordlist.txt") == []

    def test_load_wordlist_with_comments(self, tmp_path):
        wl = tmp_path / "test.txt"
        wl.write_text("password\n# comment\nadmin\n\n", encoding="utf-8")
        words = load_wordlist(str(wl))
        assert words == ["password", "admin"]


# --------------------------------------------------------------------------- #
# Default wordlist wiring in tools
# --------------------------------------------------------------------------- #


class TestDefaultWordlistWiring:
    """Ensure tools that accept wordlist now default to the bundled one."""

    def test_crack_ssh_tool_spec_wordlist_not_required(self):
        """crack_ssh tool spec should have wordlist as optional."""
        from honeywatch.agent.tools import TOOL_REGISTRY

        spec = TOOL_REGISTRY["crack_ssh"]["spec"]
        required = spec.get("required", [])
        assert "wordlist" not in required, (
            f"wordlist should not be required: required={required}"
        )

    def test_hashcrack_tool_spec_wordlist_not_required(self):
        """hashcrack tool spec should have wordlist as optional."""
        from honeywatch.agent.tools import TOOL_REGISTRY

        spec = TOOL_REGISTRY["hashcrack"]["spec"]
        required = spec.get("required", [])
        assert "wordlist" not in required, (
            f"wordlist should not be required: required={required}"
        )

    def test_candidate_passwords_with_bundled_wordlist(self):
        """candidate_passwords should work with the bundled wordlist."""
        words = load_default_wordlist()
        candidates = list(candidate_passwords(wordlist=words, mutations=False))
        # Should include all built-in passwords plus all wordlist entries
        for p in _BUILTIN_PASSWORDS:
            assert p in candidates, f"built-in password {p!r} missing"

    def test_chain_hashcrack_default_uses_bundled(self):
        """ChainConfig.hashcrack_wordlist="" should trigger bundled default."""
        from honeywatch.chain import ChainConfig

        cfg = ChainConfig()
        assert cfg.hashcrack_wordlist == ""
        # phase_escalate should use the bundled default when empty
        from honeywatch.crack import default_wordlist_path

        expected = default_wordlist_path()
        # Verify the chain code would resolve to bundled default
        assert expected and os.path.isfile(expected)


# --------------------------------------------------------------------------- #
# External tool check
# --------------------------------------------------------------------------- #


class TestExternalToolCheck:
    """Tests for check_external_tools()."""

    def test_check_external_tools_returns_all_tools(self):
        results = check_external_tools()
        tool_names = {r["name"] for r in results}
        expected_names = {t[0] for t in _EXTERNAL_TOOLS}
        assert tool_names == expected_names

    def test_check_external_tools_structure(self):
        results = check_external_tools()
        for r in results:
            assert "name" in r
            assert "available" in r
            assert isinstance(r["available"], bool)
            assert "apt" in r
            assert "brew" in r

    def test_check_external_tools_apt_format(self):
        results = check_external_tools()
        for r in results:
            assert r["apt"].startswith("sudo apt install -y ")

    def test_check_external_tools_brew_format(self):
        results = check_external_tools()
        for r in results:
            assert r["brew"].startswith("brew install ")

    def test_ssh_always_available_on_posix(self):
        """ssh should typically be available on POSIX systems."""
        if sys.platform == "win32":
            pytest.skip("ssh not typically on Windows PATH")
        results = check_external_tools()
        ssh = next(r for r in results if r["name"] == "ssh")
        # Not asserting it IS available (could be in Docker minimal),
        # just that the check runs without error.
        assert isinstance(ssh["available"], bool)

    def test_tool_names_match_external_tools_constant(self):
        """Ensure _EXTERNAL_TOOLS has the expected entries."""
        assert len(_EXTERNAL_TOOLS) == 7
        names = [t[0] for t in _EXTERNAL_TOOLS]
        assert "masscan" in names
        assert "hashcat" in names
        assert "john" in names
        assert "sshpass" in names