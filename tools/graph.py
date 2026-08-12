#!/usr/bin/env python3
"""The skill dependency graph — computed, never maintained.

    tools/graph.py                 what produces what, and what each skill needs
    tools/graph.py --entry         skills runnable with no prior skill (the entry points)
    tools/graph.py --for <skill>   the chain that has to exist before this one can be useful
    tools/graph.py --check         structural problems only; exit 1 if any

Why this exists
---------------
`phase-routing.md` carried a hand-written dependency graph. After the phases were renumbered,
**every single number in it was wrong** — liveness attributed to the HTTP skill, ports to
http-probing, prioritization off by one, a reference to a phase that does not exist, and one
bullet that contradicted itself inside a single sentence ("`24 components` … so without `23`").
It stayed wrong because nothing could detect it: prose cannot be executed.

Every fact that graph asserted is already declared elsewhere and machine-readable. A skill's
`## Inputs` names the roles it consumes; the `## Input roles` table names the skill that
produces each role. The graph is the join of those two. So it is computed here and the prose
version is deleted — a derived thing that is hand-maintained is a drift generator, and this one
drifted silently for an entire renumbering.

Consequence worth stating: this is a **graph, not a pipeline**. Enter wherever the target's
shape allows and run only what you need. `--entry` prints the skills with no unmet dependency,
which is the honest answer to "where do I start".
"""
import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import roles                                                    # noqa: E402
import skilllib                                                 # noqa: E402
from preflight import declared_inputs                           # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def skills():
    """{slug: {'required': [roles], 'optional': [roles], 'path': Path}}"""
    out = {}
    for slug, f in skilllib.discover().items():
        decl = declared_inputs(f.read_text(encoding="utf-8-sig", errors="replace"))
        # An "at least one of" group is NOT a set of independent requirements. Flattening it
        # made `--for derive-properties` report the entire recon chain as prerequisite when a
        # single artifact is enough — structurally consistent and semantically wrong.
        out[slug] = {
            "required": [r for r, _p, req, grp in decl if req and not grp],
            "any_of":   [r for r, _p, _q, grp in decl if grp],
            "optional": [r for r, _p, req, grp in decl if not req and not grp],
            "path": f,
        }
    return out


def producers():
    """{role: producing-skill-slug} — the second half of the join."""
    out = {}
    for role, (_path, produced) in roles.load().items():
        # a cell may name several producers ("api-discovery / application-mapping") or a
        # non-skill origin ("init-target (filled by the hunter)")
        first = re.split(r"[/,]", produced)[0].strip()
        out[role] = re.sub(r"\s*\(.*", "", first).strip()
    return out


def _resolvable(name):
    """A producer may be a skill, a workflow, or the scaffold — all are real origins."""
    if name in ("init-target", "hunter", "the hunter", ""):
        return True
    if (ROOT / "playbooks" / "workflows" / f"{name}.md").exists():
        return True
    if name in skilllib.discover():
        return True
    # a runtime skill directory is a real origin too, until the portable layer folds it in
    return (ROOT / ".claude" / "skills" / name / "SKILL.md").exists()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--entry", action="store_true", help="skills with no unmet dependency")
    ap.add_argument("--for", dest="target", help="what must exist before this skill is useful")
    ap.add_argument("--check", action="store_true", help="structural problems only")
    args = ap.parse_args()

    sk, prod = skills(), producers()
    known = set(sk)

    if args.check:
        bad = []
        for slug, meta in sorted(sk.items()):
            for role in meta["required"] + meta.get("any_of", []) + meta["optional"]:
                p = prod.get(role)
                if p is None:
                    bad.append(f"{slug}: role {role} has no producer in the role table")
                elif p not in known and not _resolvable(p):
                    bad.append(f"{slug}: role {role} claims producer '{p}', which is neither a "
                               f"skill nor a workflow")
        for line in bad:
            print(f"  {line}")
        print(f"\n  {len(bad)} structural problem(s).\n" if bad else "\n  Graph is consistent.\n")
        return 1 if bad else 0

    if args.target:
        slug = args.target
        if slug not in sk:
            print(f"FAIL — no skill '{slug}'. Try: tools/graph.py", file=sys.stderr)
            return 2
        seen, order = set(), []

        def walk(s, depth=0):
            for role in sk.get(s, {}).get("required", []) or []:
                if roles.is_hunter_supplied(role):
                    continue
                p = prod.get(role)
                if p and p in sk and (p, role) not in seen:
                    seen.add((p, role))
                    walk(p, depth + 1)
                    order.append((depth, p, role))
        walk(slug)
        print(f"\n# what {slug} depends on\n")
        grp_early = sk[slug].get("any_of") or []
        if not order and not grp_early:
            print("  nothing — this is an entry point.\n")
            return 0
        if not order:
            print("  no hard prerequisite.")
        for depth, p, role in order:
            print(f"  {'  ' * depth}{p}  →  {role}")
        grp = sk[slug].get("any_of") or []
        if grp:
            print(f"\n  plus ANY ONE of — this skill degrades, it does not fail:")
            for role in grp:
                print(f"    {prod.get(role, '?'):<32} → {role}")
        print()
        return 0

    if args.entry:
        print("\n# entry points — no unmet dependency on another skill\n")
        for slug, meta in sorted(sk.items()):
            # A skill reading a role it also produces is the INCREMENTAL pattern (report what
            # is new against your own last run), not a dependency on someone else. Counting it
            # as one hid the real entry points.
            deps = {prod.get(r) for r in meta["required"]
                    if not roles.is_hunter_supplied(r)} - {slug}
            if not (deps & known):
                print(f"  {slug}")
        print("\n  A graph, not a pipeline: enter where the target's shape allows.\n")
        return 0

    print(f"\n# skill graph — {len(sk)} skills, computed from ## Inputs x the role table\n")
    width = max((len(s) for s in sk), default=20)
    for slug, meta in sorted(sk.items()):
        req = ", ".join(f"{r}<-{prod.get(r, '?')}" for r in meta["required"]) or "—"
        print(f"  {slug:<{width}}  needs: {req}")
        if meta.get("any_of"):
            print(f"  {'':<{width}}  any1:  {', '.join(meta['any_of'])}")
        if meta["optional"]:
            print(f"  {'':<{width}}  opt:   {', '.join(meta['optional'])}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
