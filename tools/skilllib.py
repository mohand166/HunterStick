#!/usr/bin/env python3
"""Canonical discovery and resolution for nested skill bodies."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SKILLS_ROOT = ROOT / "skills"
FRONTMATTER_NAME = re.compile(r"\A---\s*\nname:\s*([^\n]+)", re.M)


def iter_skill_files(skills_root=SKILLS_ROOT):
    """Yield invocable skill bodies recursively, excluding navigation and shared files."""
    root = Path(skills_root)
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*.md")):
        if path.name == "README.md" or path.name.startswith("_"):
            continue
        yield path


def skill_name(path):
    """Return the declared skill slug, or None when frontmatter is absent."""
    text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    match = FRONTMATTER_NAME.search(text)
    return match.group(1).strip() if match else None


def discover(skills_root=SKILLS_ROOT):
    """Return {slug: path}; fail loudly if two bodies claim the same invocation name."""
    found = {}
    for path in iter_skill_files(skills_root):
        slug = skill_name(path) or path.stem
        if slug in found:
            first = found[slug]
            raise ValueError(f"duplicate skill slug '{slug}': {first} and {path}")
        found[slug] = path
    return found


def resolve(name, skills_root=SKILLS_ROOT):
    """Resolve an exact or unambiguous partial slug to its canonical body."""
    query = re.sub(r"^\d+-", "", str(name).strip())
    skills = discover(skills_root)
    if query in skills:
        return skills[query]
    matches = [path for slug, path in skills.items() if query in slug]
    if not matches:
        raise KeyError(query)
    if len(matches) > 1:
        names = ", ".join(sorted(skill_name(path) or path.stem for path in matches))
        raise ValueError(f"'{query}' matches {len(matches)} skills: {names}")
    return matches[0]


def relative(path, skills_root=SKILLS_ROOT):
    """Return the repository-relative canonical path used in model instructions."""
    root = Path(skills_root).resolve().parent
    return Path(path).resolve().relative_to(root).as_posix()


def category(path, skills_root=SKILLS_ROOT):
    """Return the first directory below skills/ for grouped listings."""
    parts = Path(path).resolve().relative_to(Path(skills_root).resolve()).parts
    return parts[0] if len(parts) > 1 else "uncategorized"
