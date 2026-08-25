"""Bundled wordlist and resource access for honeywatch.

Provides a default password wordlist so cracking tools work out of the box
without requiring the operator to supply a ``--wordlist`` path manually.
"""

from __future__ import annotations

import os


def _data_dir() -> str:
    """Return the directory containing bundled data files."""
    return os.path.dirname(os.path.abspath(__file__))


def default_wordlist_path() -> str:
    """Return the path to the bundled default wordlist.

    The file is a newline-separated list of common passwords suitable for
    online SSH cracking and offline shadow cracking.
    """
    return os.path.join(_data_dir(), "default.txt")


def load_default_wordlist() -> list[str]:
    """Load and return the bundled default wordlist as a list of strings.

    Blank lines and ``#``-prefixed comments are skipped.
    """
    path = default_wordlist_path()
    words: list[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip("\r\n")
                if not line or line.startswith("#"):
                    continue
                words.append(line)
    except OSError:
        pass  # degrade gracefully — callers fall back to _BUILTIN_PASSWORDS
    return words