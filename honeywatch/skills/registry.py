"""Skill registry for honeywatch's advisory skill brain (Phase 5).

Parses SKILL.md files from the skills/ directory. Each skill has YAML front
matter (name, description, domain, tags, nist_csf, mitre_attack) and a markdown
body containing advisory tradecraft guidance. Skills are advisory-only — they
never grant execution authority, change scope, or override permission/audit
rules.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------- #
# Dataclasses
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SkillMetadata:
    """Front-matter metadata parsed from a SKILL.md file."""
    name: str
    description: str = ""
    domain: str = ""
    subdomain: str = ""
    tags: tuple[str, ...] = ()
    version: str = ""
    path: Path = Path()
    nist_csf: tuple[str, ...] = ()
    mitre_attack: tuple[str, ...] = ()


@dataclass
class LoadedSkill:
    """A parsed SKILL.md: metadata + body + sections."""
    metadata: SkillMetadata
    body: str = ""
    sections: dict[str, str] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.metadata.name

    @property
    def tags(self) -> tuple[str, ...]:
        return self.metadata.tags

    @property
    def description(self) -> str:
        return self.metadata.description


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

_FRONT_MATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
_HEADING_RE = re.compile(r"^##\s+(.+)$", re.MULTILINE)
_SEARCH_STOPWORDS = frozenset({
    "the", "of", "a", "an", "and", "or", "to", "in", "for", "on", "with",
    "by", "at", "from", "is", "are", "be", "was", "were", "this", "that",
    "it", "as", "at", "use", "using", "service", "when", "how", "what",
})


def _parse_yaml_simple(text: str) -> dict[str, Any]:
    """Minimal YAML parser for flat key: value + list items.

    Handles the subset of YAML used in SKILL.md front matter:
    - ``key: value``
    - ``key: [item1, item2]``  (inline list)
    - ``key:`` followed by ``  - item`` lines (block list)
    """
    try:
        import yaml
        data = yaml.safe_load(text)
        if isinstance(data, dict):
            return data
    except ImportError:
        pass
    except Exception:
        pass

    # Fallback: minimal manual parser.
    result: dict[str, Any] = {}
    lines = text.strip().splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if ":" not in line or line.startswith(" "):
            i += 1
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if value.startswith("[") and value.endswith("]"):
            # Inline list.
            items = [v.strip().strip("'\"") for v in value[1:-1].split(",") if v.strip()]
            result[key] = items
        elif value:
            result[key] = value.strip("'\"")
        else:
            # Block list — following indented lines.
            items: list[str] = []
            i += 1
            while i < len(lines) and lines[i].startswith("  - "):
                items.append(lines[i].strip()[2:].strip().strip("'\""))
                i += 1
            result[key] = items
            continue
        i += 1
    return result


def _coerce_list(value: Any) -> tuple[str, ...]:
    """Coerce a value to a tuple of strings."""
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(str(v) for v in value)
    return (str(value),)


def parse_skill_file(path: Path) -> LoadedSkill | None:
    """Parse a SKILL.md file into a :class:`LoadedSkill`.

    Returns ``None`` when the file can't be parsed.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return None

    # Extract front matter.
    fm_match = _FRONT_MATTER_RE.match(text)
    if fm_match:
        fm_text = fm_match.group(1)
        body = text[fm_match.end():]
        fm = _parse_yaml_simple(fm_text)
    else:
        fm = {}
        body = text

    name = str(fm.get("name", path.parent.name if path.parent != Path(".") else path.stem))

    # Build metadata.
    metadata = SkillMetadata(
        name=name,
        description=str(fm.get("description", "")),
        domain=str(fm.get("domain", "")),
        subdomain=str(fm.get("subdomain", "")),
        tags=_coerce_list(fm.get("tags")),
        version=str(fm.get("version", "")),
        path=path,
        nist_csf=_coerce_list(fm.get("nist_csf")),
        mitre_attack=_coerce_list(fm.get("mitre_attack")),
    )

    # Split body into sections by ## headings.
    sections: dict[str, str] = {}
    current_section = "_intro"
    current_lines: list[str] = []
    for line in body.splitlines():
        heading_match = _HEADING_RE.match(line)
        if heading_match:
            if current_lines:
                sections[current_section] = "\n".join(current_lines).strip()
            current_section = heading_match.group(1).strip().lower()
            current_lines = []
        else:
            current_lines.append(line)
    if current_lines:
        sections[current_section] = "\n".join(current_lines).strip()

    return LoadedSkill(metadata=metadata, body=body.strip(), sections=sections)


# --------------------------------------------------------------------------- #
# SkillRegistry
# --------------------------------------------------------------------------- #


class SkillRegistry:
    """Catalog of loaded skills, indexed by name + searchable by tags/keywords."""

    def __init__(self, skills: list[LoadedSkill] | None = None):
        self._skills: dict[str, LoadedSkill] = {}
        if skills:
            for s in skills:
                self._skills[s.name] = s

    @classmethod
    def from_directory(cls, skills_dir: str | Path) -> "SkillRegistry":
        """Load all SKILL.md files from a directory tree.

        Each immediate subdirectory should contain a ``SKILL.md`` file. The
        skill name defaults to the directory name when not specified in the
        front matter.
        """
        skills_dir = Path(skills_dir)
        registry = cls()
        if not skills_dir.is_dir():
            return registry
        for skill_md in sorted(skills_dir.glob("*/SKILL.md")):
            skill = parse_skill_file(skill_md)
            if skill:
                registry._skills[skill.name] = skill
        return registry

    def list_skills(self) -> list[LoadedSkill]:
        """Return all loaded skills, sorted by name."""
        return sorted(self._skills.values(), key=lambda s: s.name)

    def get(self, name: str) -> LoadedSkill | None:
        """Fetch a skill by name."""
        return self._skills.get(name)

    def search_scored(self, query: str, max_results: int = 10) -> list[tuple[LoadedSkill, int]]:
        """Search skills by keyword, returning (skill, score) pairs.

        Field-weighted token matching: name=12, tags=10, description=5,
        domain/subdomain=4, body=1. Stopwords are stripped. Results are
        ranked by score descending.
        """
        if not query:
            return []
        query_tokens = _tokenize(query)
        if not query_tokens:
            return []

        scored: list[tuple[LoadedSkill, int]] = []
        for skill in self._skills.values():
            score = 0
            name_tokens = set(_tokenize(skill.name))
            # Tokenize tags the same way as the query so "privilege-escalation"
            # splits into "privilege" + "escalation" tokens that match the
            # query tokens "privilege" and "escalation" separately.
            tag_tokens = set()
            for t in skill.tags:
                tag_tokens.update(_tokenize(t))
            desc_tokens = set(_tokenize(skill.description))
            class_tokens = set(_tokenize(skill.metadata.domain + " " + skill.metadata.subdomain))
            body_tokens = set(_tokenize(skill.body[:8000]))

            for qt in query_tokens:
                if qt in name_tokens:
                    score += 12
                if qt in tag_tokens:
                    score += 10
                if qt in desc_tokens:
                    score += 5
                if qt in class_tokens:
                    score += 4
                if qt in body_tokens:
                    score += 1
            if score > 0:
                scored.append((skill, score))

        scored.sort(key=lambda t: -t[1])
        return scored[:max_results]


def _tokenize(text: str) -> list[str]:
    """Split text into lowercase tokens, stripping stopwords + punctuation."""
    text = text.lower()
    tokens = re.findall(r"[a-z0-9_-]+", text)
    return [t for t in tokens if t not in _SEARCH_STOPWORDS and len(t) > 1]


# --------------------------------------------------------------------------- #
# Prompt-injection hardening
# --------------------------------------------------------------------------- #

_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<iframe[^>]*>.*?</iframe>", re.IGNORECASE | re.DOTALL),
    re.compile(r"```(?:system|sys|admin)\b", re.IGNORECASE),
    re.compile(r"^(#|##)\s*(system|instruction|admin)\b", re.IGNORECASE | re.MULTILINE),
    re.compile(r"<<SYSTEM>>|<<ADMIN>>|<<INSTRUCTION>>", re.IGNORECASE),
    re.compile(r"\[(?:SYSTEM|ADMIN|INSTRUCTION)\]", re.IGNORECASE),
    re.compile(r"<\|.*?\|>", re.IGNORECASE),
    re.compile(r"^- call tool:.*$", re.IGNORECASE | re.MULTILINE),
)

_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)


def sanitize_skill_body(body: str) -> str:
    """Sanitize a skill body for safe injection into an LLM prompt.

    Strips HTML comments, script/iframe blocks, fenced role markers,
    role-directive lines, role tokens, and tool-call mimics. The output
    is wrapped in untrusted-skill fences with a NOTE telling the model
    to treat embedded instructions with suspicion.
    """
    sanitized = body
    # Strip HTML comments first (may contain hidden directives).
    sanitized = _HTML_COMMENT_RE.sub("", sanitized)
    # Strip injection patterns.
    for pat in _INJECTION_PATTERNS:
        sanitized = pat.sub("[filtered]", sanitized)
    return (
        '<untrusted_skill_guidance source="skills/SKILL.md">\n'
        f"{sanitized.strip()}\n"
        "</untrusted_skill_guidance>"
    )