"""honeywatch advisory skill brain (Phase 5).

Runtime skills system: loads SKILL.md files from the skills directory, selects
relevant skills via deterministic + semantic matching, and injects them into
the agent's system prompt as advisory guidance.

Skills are advisory-only — they never grant execution authority, change scope,
or override permission/audit rules.
"""

from honeywatch.skills.registry import (
    LoadedSkill,
    SkillMetadata,
    SkillRegistry,
    parse_skill_file,
    sanitize_skill_body,
)
from honeywatch.skills.selector import SkillSelector, select_skills
from honeywatch.skills.pipeline import (
    apply_skills_to_prompt,
    build_skill_context,
    build_skill_hints,
)

__all__ = [
    "LoadedSkill",
    "SkillMetadata",
    "SkillRegistry",
    "SkillSelector",
    "apply_skills_to_prompt",
    "build_skill_context",
    "build_skill_hints",
    "parse_skill_file",
    "sanitize_skill_body",
    "select_skills",
]