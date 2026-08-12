#!/usr/bin/env python3
"""Does this skill have what it needs? Resolve its declared inputs, then get out of the way.

    tools/preflight.py targets/acme http-probing
    tools/preflight.py targets/acme --list          # every skill, one line each

What this is
------------
**One check: are the skill's declared inputs present?** Nothing else. The hunter chose the
skill and the target; if the inputs are there it runs, and this tool has no opinion about
scope, accounts, calibration, selectors, budgets or which objective "should" come first.

When an input is missing it does the one useful thing: names the input, names the skill that
produces it, and stops. "This needs @hosts.live, which `http-probing` produces." That sentence
is the entire value — it turns a dead end into a next step.

It reads the skill's own `## Inputs` section, so there is no second registry to drift. Roles
(`@hosts.live`) resolve through the `## Input roles` table in `playbooks/system/target-schema.md`.

Two states, and only two
------------------------
* **A REQUIRED input is missing → the objective cannot run as asked.** Say which input, say
  which skill produces it, and stop. That is the one stopping condition in this workspace, and
  it exists because a skill run without its subject reports a zero the missing input caused.
  The hunter can always resolve it: supply the value directly (record it with `record.py`), run
  the producing skill, or name a different objective.
* **An OPTIONAL input is missing → run, and say what it cost.** The run is narrower, not
  invalid. That belongs in the run's `--limitations`, written from what this reported.

What it does NOT gate on, deliberately
--------------------------------------
Scope, principals, calibration, selectors and fan-out budget. Those were global gates once, and
the result was an objective that had been un-runnable for months because five filenames were
missing a directory prefix. They are now **inputs of the skills that genuinely need them** — a
skill that compares two principals says so in its own `## Inputs` and stops there, which is the
same single rule rather than a second kind of veto.

Exit: 0 every required input present, run it · 1 a required input is missing, and it names the
input and the producer · 2 the check itself could not run (not a target brain, unknown skill).
"""
import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import roles      # noqa: E402
import skilllib   # noqa: E402
from dashboard import state_of                                  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
# Kept as a public compatibility constant for callers that import it. Discovery itself is
# recursive and centralized in skilllib so nesting skills does not hide them from a runtime.
SKILL_DIRS = (skilllib.SKILLS_ROOT,)

# A bullet hedged like this describes an input that makes the run richer, not one it needs.
OPTIONAL = re.compile(r"\b(optional\b|if |when |where available|if done)", re.I)
# A role introduced by a negation is being excluded — "not `@hosts.live`, which is the HTTP-only
# set". Matched against the text immediately BEFORE the role, since the negation attaches forward.
NEGATED = re.compile(r"\b(not|never|rather than|instead of|as opposed to)\b[\s*_`]*$", re.I)


def die(msg, code=2):
    print(f"FAIL — {msg}", file=sys.stderr)
    raise SystemExit(code)


def skill_file(name):
    try:
        return skilllib.resolve(name)
    except KeyError:
        die(f"no skill matching '{name}'. Try: tools/preflight.py <target> --list")
    except ValueError as error:
        die(f"{error}. Be specific.")


def declared_inputs(text):
    """[(role, path, required)] from the skill's own ## Inputs section.

    An unknown role yields path=None so the caller can report it loudly. Silently skipping a
    typo would report "no inputs to check" on a skill that has several.
    """
    m = re.search(r"^## Inputs\s*$(.*?)(?=^## |\Z)", text, re.M | re.S)
    if not m:
        return []
    section = m.group(1)
    anyof = re.search(r"at least one of", section, re.I)
    anyof_from = anyof.start() if anyof else None
    out, group = {}, set()
    for bullet in re.split(r"\n(?=\s*[-*] )", m.group(1)):
        if not bullet.strip():
            continue
        hits = list(re.finditer(r"`(@[\w.]+)`", bullet))
        for i, h in enumerate(hits):
            role = h.group(1)
            if NEGATED.search(bullet[:h.start()][-40:]):
                continue
            end = hits[i + 1].start() if i + 1 < len(hits) else len(bullet)
            # The hedge must sit in the role's OWN qualifier — the parenthetical or leading
            # clause — not merely somewhere later in the same bullet. Scanning the whole span
            # made "`@hosts.all` (from `x`) — the enumerated set. If it was produced by ..."
            # read as OPTIONAL because of an "If" three sentences away, and a required input
            # silently reading as optional is how a run reports "ready" on a missing file.
            span = bullet[h.end():end]
            qualifier = re.split(r"\s[—–]\s|\.\s", span, maxsplit=1)[0]
            required = not OPTIONAL.search(qualifier)
            path = roles.resolve(role)
            if anyof_from is not None and section.find(bullet.strip()[:40]) >= anyof_from:
                group.add(role)
            prev = out.get(role)
            out[role] = (path, (prev[1] if prev else False) or required)
    return [(role, path, required, role in group)
            for role, (path, required) in out.items()]


def check(tdir, sf, provided=()):
    """(present, missing_required, missing_optional, prompt_needed) — each a list of display rows.

    `provided` is the set of @hunter.* roles the caller confirmed with --provided. A prompt-subject
    skill is NOT unconditionally ready: a weak model told "Ready to run" when nothing was pasted is
    the failure this bucket prevents. Confirmed → present; unconfirmed → prompt_needed, and the
    single-skill path exits non-zero on it.
    """
    text = sf.read_text(encoding="utf-8-sig", errors="replace")
    present, missing_req, missing_opt, prompt_needed = [], [], [], []
    provided = set(provided)
    decl = declared_inputs(text)
    grouped = [d for d in decl if d[3]]
    group_satisfied = False
    for role, rel, required, in_group in decl:
        if roles.is_hunter_supplied(role):
            # The subject comes from the invocation, not the brain. Declaring it is what stops a
            # skill whose subject is a pasted request from reporting "ready" with nothing pasted.
            if role in provided:
                present.append((role, None, "supplied by you (--provided)", "the hunter"))
                if in_group:
                    group_satisfied = True
            else:
                row = (role, None,
                       "must be in your message; confirm with --provided " + role,
                       "the hunter")
                if in_group:
                    missing_opt.append(row)
                else:
                    prompt_needed.append(row)
            continue
        if rel is None:
            missing_req.append((role, None, roles.unknown(role), None))
            continue
        p = tdir / rel
        if rel.endswith("/"):
            ok = p.is_dir() and any(p.iterdir())
            kind, n = ("populated" if ok else ("empty" if p.is_dir() else "missing")), None
        else:
            kind, n = state_of(p)
            # `demoted` = real data living on the VPS behind a pointer stub. Present.
            ok = kind in ("lines", "rows", "prose", "demoted")
        detail = f"{kind}" + (f" ({n:,})" if n else "")
        if kind == "demoted":
            # `demoted` means the data lives on the VPS behind a pointer stub. The stub proves
            # it was demoted; it does NOT prove the remote is still reachable. Saying so costs
            # nothing and stops a run from starting on data that is not there — the alternative
            # is one ssh round trip on every preflight, which is a poor trade.
            detail += ("  on the VPS, reachability UNVERIFIED — `vps.sh 'ls <path>'` before "
                       "relying on it, or `vps-sync.py pull`")
        producer = roles.load().get(role, (None, "unknown"))[1]
        row = (role, rel, detail, producer)
        if ok and in_group:
            group_satisfied = True
        if ok:
            present.append(row)
        elif in_group:
            missing_opt.append(row)          # provisional; re-sorted once the group is known
        elif required:
            missing_req.append(row)
        else:
            missing_opt.append(row)
    # An any-of group with NO member present is a real gap: promote the whole group.
    if grouped and not group_satisfied:
        names = {d[0] for d in grouped}
        promoted = [r for r in missing_opt if r[0] in names]
        missing_opt = [r for r in missing_opt if r[0] not in names]
        missing_req.extend(promoted)
    return present, missing_req, missing_opt, prompt_needed


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target")
    ap.add_argument("skill", nargs="?", help="a skill name, e.g. http-probing")
    ap.add_argument("--list", action="store_true", help="every skill and whether it can run")
    ap.add_argument("--provided", action="append", default=[], metavar="@ROLE",
                    help="confirm a prompt-supplied input was actually given, e.g. "
                         "--provided @hunter.class. Repeatable. Without it, a prompt-subject "
                         "skill reports PROMPT-CHECK REQUIRED rather than 'Ready to run'.")
    # Accepted and ignored: older callers pass these. They are no longer gates.
    ap.add_argument("--selector", help=argparse.SUPPRESS)
    ap.add_argument("--budget", help=argparse.SUPPRESS)
    ap.add_argument("--skip-vps-check", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()

    tdir = Path(args.target).resolve()
    if not (tdir / "index.md").exists():
        die(f"{args.target} is not a target brain (no index.md)")

    if args.list or not args.skill:
        print(f"\n# inputs — {tdir.name}\n")
        current_category = None
        for stem, sf in sorted(skilllib.discover().items(),
                               key=lambda item: (skilllib.category(item[1]), item[0])):
            category = skilllib.category(sf)
            if category != current_category:
                print(f"  [{category}]")
                current_category = category
            _, miss, _, prompt = check(tdir, sf)
            if miss:
                mark, why = "needs ", f"  {miss[0][0]} (from {miss[0][3]})"
            elif prompt:
                # Never call a prompt-subject skill unconditionally ready in --list: it has
                # no context to know whether the subject was supplied. Honest third state.
                mark, why = "prompt", f"  needs {prompt[0][0]} in your message"
            else:
                mark, why = "ready ", ""
            print(f"    {mark:<7} {stem:<38}{why[:52]}")

        print("\n  needs  = a REQUIRED input is not in the brain — run the producer or supply it.\n"
              "  prompt = ready once you supply the @hunter.* subject in your message (and pass\n"
              "           --provided to confirm it). Not unconditionally ready. An optional input\n"
              "           missing never appears here — it just narrows the run.\n")
        return 0

    sf = skill_file(args.skill)
    present, missing_req, missing_opt, prompt_needed = check(tdir, sf, provided=args.provided)
    stem = re.sub(r"^\d+-", "", sf.stem)

    print(f"\n# inputs — {tdir.name} · {stem}\n")
    # One column width across all buckets, or the arrows do not line up and a long
    # role name silently shifts everything after it.
    def label(role, rel):
        return f"{role} -> {rel}" if rel else role
    rows = present + missing_opt + missing_req + prompt_needed
    w = max((len(label(r[0], r[1])) for r in rows), default=20)
    for role, rel, detail, _ in present:
        print(f"  ok       {label(role, rel):<{w}}  {detail}")
    for role, rel, detail, producer in missing_opt:
        print(f"  --       {label(role, rel):<{w}}  {detail}   (optional — narrower without it)")
    for role, rel, detail, _ in prompt_needed:
        print(f"  PROMPT?  {label(role, rel):<{w}}  {detail}")
    for role, rel, detail, producer in missing_req:
        print(f"  MISSING  {label(role, rel):<{w}}  {detail}")
        if rel is not None:
            print(f"           {'':<{w}}  produced by: {producer}")

    if missing_req:
        names = ", ".join(r for r, *_ in missing_req)
        producers = sorted({p for *_, p in missing_req if p})
        print(f"\n  {len(missing_req)} REQUIRED input(s) missing: {names}")
        print("  This objective cannot run as asked — without them it would report a zero the\n"
              "  missing input caused, which is indistinguishable from a real result.")
        if producers:
            print(f"\n  Produced by: {', '.join(producers)}. Run one of those, or supply the value\n"
                  f"  directly — what you tell me is a real source, it just is not written down yet:\n"
                  f"      tools/record.py {args.target} --into <file> --source 'hunter, prompt' -- <values>")
        print()
        return 1

    if prompt_needed:
        names = ", ".join(r for r, *_ in prompt_needed)
        print(f"\n  PROMPT-CHECK REQUIRED — this skill's subject comes from your message, not the\n"
              f"  brain: {names}. No file check can see it. If you supplied it, re-run with\n"
              f"      tools/preflight.py {args.target} {stem} "
              + " ".join(f'--provided {r}' for r, *_ in prompt_needed) + "\n"
              "  Until then this is NOT 'ready' — a run with no subject reports an empty result\n"
              "  that reads like a real one.\n")
        return 1

    print("\n  Ready to run.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
