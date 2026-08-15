#!/usr/bin/env python3
"""Resolve a recon input ROLE (`@hosts.resolved`) to a path inside a target brain.

Why this exists
---------------
A recon skill used to declare its inputs as literal paths. A path written into two dozen
playbooks rots in two dozen places, and it rotted on every axis at once:

* `host-correlation-and-clustering` declared bare `technologies.md`, `ips-asn.md`, `dns.md`,
  `js-findings.md`, `endpoints.md` — the `recon/` prefix missing. `preflight.py` looked for
  `targets/<t>/technologies.md`, correctly said `missing`, and BLOCKED the skill, while every
  one of those files existed under `recon/`. Un-runnable since the day it was written.
* `http-probing` declared `recon/subdomains.txt` while its own body consumed
  `recon/resolved.txt` and `recon/ips.txt` — the gate checked a file the run never opened.
* Identifying a skill by number left all seven scope-filter temp paths carrying an OLD number
  after a renumbering — which is why identity is a slug now.

So the path is named once, in the `## Input roles` table in
`playbooks/system/target-schema.md`, and everything else asks for it by role. Renaming an
artifact is one row.

The markdown table is the authority and this file only parses it — the same arrangement as
`scopelib.py` over `scope.md`. The thing a human edits is the thing the code reads; there is no
second copy to drift.

Usage
    tools/roles.py --list                              every role -> path
    tools/roles.py @hosts.resolved                     -> recon/resolved.txt   (relative)
    tools/roles.py path targets/acme @hosts.resolved   -> targets/acme/recon/resolved.txt
    tools/roles.py path targets/acme @app.current --host app.acme.com
    tools/roles.py path targets/acme @hosts.resolved --require   exit 2 if absent/empty

Exit: 0 ok · 2 unknown role, unreadable table, or --require unmet.
An unknown role is always a loud failure. A typo must never read as "nothing to check".
"""
import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import applib  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "playbooks" / "system" / "target-schema.md"

_CACHE = None


def load(schema=SCHEMA):
    """{role: (path, produced_by)} parsed from the `## Input roles` table."""
    global _CACHE
    if _CACHE is not None and schema == SCHEMA:
        return _CACHE
    try:
        text = schema.read_text(encoding="utf-8")
    except OSError as e:
        raise SystemExit(f"FAIL — cannot read the role table at {schema}: {e}")

    sec = re.search(r"^## Input roles\b.*?$(.*?)(?=^## )", text, re.M | re.S)
    if not sec:
        raise SystemExit(
            f"FAIL — {schema} has no '## Input roles' section. That table is the authority for "
            "every phase input; without it no phase can be preflighted."
        )

    roles = {}
    for line in sec.group(1).splitlines():
        # | `@role` | `path` | `produced by` |
        m = re.match(r"\s*\|\s*`(@[\w.]+)`\s*\|\s*`([^`]+)`\s*\|\s*(.*?)\s*\|", line)
        if not m:
            continue
        role, path, produced = m.group(1), m.group(2).strip(), m.group(3).strip()
        if role in roles and roles[role][0] != path:
            raise SystemExit(
                f"FAIL — role {role} is defined twice in {schema.name} with different paths "
                f"({roles[role][0]} and {path}). The table is the authority; it cannot disagree "
                "with itself."
            )
        roles[role] = (path, re.sub(r"[`*]", "", produced))

    if not roles:
        raise SystemExit(
            f"FAIL — the '## Input roles' table in {schema} parsed to zero rows. Expected rows "
            "shaped `| `@role` | `path` | produced by |`."
        )
    if schema == SCHEMA:
        _CACHE = roles
    return roles


HUNTER_PREFIX = "@hunter."
DYNAMIC_PREFIX = "<dynamic:"


def is_hunter_supplied(role):
    """A subject the hunter hands over in the prompt — a pasted request, an entrypoint, a class.

    Required, but no file check can find it. Declaring it keeps the skill honest: without this,
    a skill whose subject comes from the prompt has no `## Inputs` at all and reports *ready*
    whether or not the hunter actually supplied one.
    """
    return role.startswith(HUNTER_PREFIX)


def resolve(role, schema=SCHEMA):
    """Relative path for a role, or None if the role is unknown or hunter-supplied."""
    hit = load(schema).get(role)
    return hit[0] if hit else None


def is_dynamic_path(path):
    """Whether a role needs the invocation's exact subject before it has a path."""
    return bool(path and path.startswith(DYNAMIC_PREFIX))


def resolve_path(target, role, host=None, schema=SCHEMA):
    """Resolve static roles and the host-selected application role through one interface."""
    rel = resolve(role, schema)
    if rel is None:
        return None, None
    if not is_dynamic_path(rel):
        return Path(target) / rel, None
    if role != "@app.current":
        return None, f"unsupported dynamic role {role}"
    if not host:
        return None, f"{role} needs the exact host/URL (`--host`)"
    try:
        resolution = applib.resolve(target, host)
    except ValueError as error:
        return None, str(error)
    if resolution.status == "ambiguous":
        names = ", ".join(path.name for path in resolution.candidates)
        return None, f"ambiguous application ({names}); supply an explicit port"
    if resolution.status == "missing":
        wanted = Path(target) / "applications" / resolution.subject.slug
        return wanted, "missing"
    return resolution.path, resolution.state


def unknown(role, schema=SCHEMA):
    """A one-line message naming the closest real roles — never a silent miss."""
    roles = sorted(load(schema))
    stem = role.lstrip("@").split(".")[0].lower()
    near = [r for r in roles if stem and stem[:4] in r.lower()]
    hint = f" Did you mean: {', '.join(near[:4])}?" if near else ""
    return (f"unknown input role {role!r} — it is not in the '## Input roles' table in "
            f"playbooks/system/target-schema.md.{hint}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("a", nargs="?", help="a role, or the literal word 'path'")
    ap.add_argument("b", nargs="?", help="target dir, when the first arg is 'path'")
    ap.add_argument("c", nargs="?", help="the role, when the first arg is 'path'")
    ap.add_argument("--list", action="store_true", help="print every role and its path")
    ap.add_argument("--require", action="store_true",
                    help="with 'path': exit 2 unless the file exists and is non-empty")
    ap.add_argument("--host", help="exact URL/host for a dynamic role such as @app.current")
    args = ap.parse_args()

    roles = load()

    if args.list or not args.a:
        width = max(len(r) for r in roles)
        print(f"# input roles — authority: {SCHEMA.relative_to(ROOT)}")
        for role in sorted(roles):
            path, produced = roles[role]
            print(f"  {role:<{width}}  {path:<26}  {produced}")
        return 0

    if args.a == "path":
        if not (args.b and args.c):
            print("usage: tools/roles.py path <target-dir> <@role>", file=sys.stderr)
            return 2
        tdir, role = Path(args.b), args.c
        rel = resolve(role)
        if rel is None:
            print(f"FAIL — {unknown(role)}", file=sys.stderr)
            return 2
        full, dynamic_state = resolve_path(tdir, role, args.host)
        if full is None:
            print(f"FAIL — {dynamic_state}", file=sys.stderr)
            return 2
        print(full)
        if args.require:
            # A directory counts as present when it holds anything; a file when it is non-empty.
            # `missing` and `0` are different states and the caller must be able to tell them
            # apart, so say which one it is rather than a bare non-zero exit.
            if not full.exists():
                print(f"FAIL — {role} resolves to {full}, which does not exist. Produced by: "
                      f"{roles[role][1]}.", file=sys.stderr)
                return 2
            empty = ((dynamic_state == "scaffold") if is_dynamic_path(rel) else
                     ((not any(full.iterdir())) if full.is_dir() else full.stat().st_size == 0))
            if empty:
                print(f"FAIL — {role} resolves to {full}, which is EMPTY. That is a real result, "
                      f"not a missing file — decide deliberately before running on it.",
                      file=sys.stderr)
                return 2
        return 0

    rel = resolve(args.a)
    if rel is None:
        print(f"FAIL — {unknown(args.a)}", file=sys.stderr)
        return 2
    print(rel)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
