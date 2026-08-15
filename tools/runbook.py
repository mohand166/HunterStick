#!/usr/bin/env python3
"""Validate a target's runbook and print tonight's ordered plan with live step state.

    tools/runbook.py targets/acme           # validate + plan (state per step)
    tools/runbook.py targets/acme --check   # validate only — structure, skill names, conditions

The runbook is the hunter's standing order (`runbook.md` in the target brain): an ordered bundle
of steps approved once. This tool is its mechanical half —

* **validate**: every `step` names a real skill, a real flow, or the `closing-brief` action; the
  `when` column uses the fixed vocabulary; rows are numbered and ordered. A runbook that names a
  skill that was renamed is the dead-router-entry failure — it reads fine and sends the model to
  a file that is not there. Fail loud instead.
* **plan**: for each step, resolve its CURRENT state — preflight the skill against this brain so
  a blocked step (missing required input) is named before the run starts, not discovered
  mid-sequence; mark mechanical `when` conditions (components-present) as met/unmet and the
  judgment ones (recon-stale, custom:…) as *evaluate*.

What it deliberately does NOT do: execute anything. Steps run through their own skill lifecycles
under the model; this tool plans and validates. The closing brief is written by the run, and the
digest notification is sent by the run (`notify.py`, event `runbook-digest`) — one ping, not one
per step.

Exit: 0 plan printed (blocked steps are information, not failure) · 2 the runbook itself is
invalid (unknown step, bad `when`, unparseable table) or the target has no runbook.
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import preflight                                   # noqa: E402
import skilllib                                    # noqa: E402

WHEN_WORDS = ("always", "monitor-enabled", "components-present", "recon-stale",
              "findings-open", "custom:")
CLOSING = "closing-brief"
# Steps that are direct tool invocations rather than skill bodies — the mechanical evening
# routine. An explicit map, so a typo'd tool step fails like a typo'd skill and adding one is a
# deliberate edit here rather than an accident of string matching.
STEP_TOOLS = {
    "brief": ("brief.py", "state snapshot; --resume shows unfinished work and stale inputs"),
    "techwatch": ("techwatch.py", "advisories vs the recorded stack; needs recon/components.md"),
    "monitor-pending": ("monitor.py", "unreviewed monitor deltas; needs an enabled monitor"),
}
MECHANICAL = {
    "components-present": lambda t: (t / "recon" / "components.md").exists()
    and bool(_table_rows(t / "recon" / "components.md")),
    "findings-open": lambda t: (t / "hypotheses.md").exists()
    and bool(_prose(t / "hypotheses.md")),
}


def die(msg, code=2):
    print(f"FAIL — {msg}", file=sys.stderr)
    raise SystemExit(code)


def _table_rows(path):
    if not path.exists():
        return []
    return [ln for ln in path.read_text(encoding="utf-8-sig").splitlines()
            if ln.startswith("| ") and not ln.startswith("| host")
            and not ln.startswith("|---") and not ln.startswith("| <")]


def _prose(path):
    if not path.exists():
        return []
    return [ln for ln in path.read_text(encoding="utf-8-sig").splitlines()
            if ln.strip() and not ln.startswith("#") and not ln.startswith(">")]


def parse_steps(tdir):
    """[(num, when, step, selector, note)] from runbook.md's Steps table."""
    f = tdir / "runbook.md"
    if not f.exists():
        die(f"{tdir.name} has no runbook.md — copy targets/_template/runbook.md and edit it. "
            f"A runbook is written by the hunter, never generated mid-run.")
    steps = []
    for line in f.read_text(encoding="utf-8-sig").splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 5 or cells[0] in ("#", "---", "—") or cells[0].startswith("<"):
            continue
        if not re.fullmatch(r"[0-9]+", cells[0]):
            continue
        steps.append((int(cells[0]), cells[1], cells[2], cells[3], cells[4]))
    if not steps:
        die("runbook.md parsed to zero numbered step rows — an empty runbook is a missing one. "
            "The Steps table needs at least the closing-brief row.")
    return sorted(steps)


def validate(steps):
    failures = []
    for num, when, step, _sel, _note in steps:
        if not (when == "always" or when.startswith("custom:")
                or when in WHEN_WORDS):
            failures.append(f"step {num}: `when` must be one of {WHEN_WORDS} or custom:<line> "
                            f"— got '{when}'")
        if step == CLOSING:
            continue
        if step in STEP_TOOLS:
            tool = STEP_TOOLS[step][0]
            if not (ROOT / "tools" / tool).exists():
                failures.append(f"step {num}: '{step}' maps to tools/{tool}, which does not exist")
            continue
        known_flow = (ROOT / "playbooks" / "flows" / f"{step}.md").exists()
        try:
            skilllib.resolve(step)
            known_skill = True
        except (KeyError, ValueError):
            known_skill = False
        if not known_skill and not known_flow:
            failures.append(f"step {num}: '{step}' is neither a skill, a flow, nor "
                            f"'{CLOSING}' — a dead step sends the run to a file that is not there")
    return failures


def step_state(tdir, step):
    """(marker, one line) for the plan — preflight skills, spot mechanical conditions."""
    if step == CLOSING:
        return "always", "consolidated brief + one digest notification"
    if step in STEP_TOOLS:
        tool, line = STEP_TOOLS[step]
        return "tool", f"tools/{tool} — {line}"
    known_flow = (ROOT / "playbooks" / "flows" / f"{step}.md").exists()
    try:
        sf = skilllib.resolve(step)
    except (KeyError, ValueError):
        sf = None
    if sf is None and known_flow:
        return "flow", "its own steps and gates apply when it runs"
    if sf is None:
        return "?", "unresolvable"
    present, missing_req, _missing_opt, prompt = preflight.check(tdir, sf)
    if missing_req:
        roles = ", ".join(r for r, _p, _s, _prod in missing_req)
        return "blocked", f"missing required {roles} — name the producer and stop there"
    if prompt:
        roles = ", ".join(r for r, _p, _s, _prod in prompt)
        return "subject", f"needs {roles} supplied in the invocation"
    return "ready", f"inputs present ({len(present)})"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="targets/<name>")
    ap.add_argument("--check", action="store_true", help="validate structure only, no live state")
    args = ap.parse_args()
    tdir = Path(args.target).resolve()
    if not tdir.is_dir():
        die(f"{args.target} is not a target directory")
    steps = parse_steps(tdir)
    failures = validate(steps)
    if failures:
        print(f"FAIL — {len(failures)} runbook problem(s):", file=sys.stderr)
        for f_ in failures:
            print(f"  - {f_}", file=sys.stderr)
        return 2
    if args.check:
        print(f"runbook OK — {len(steps)} step(s), names resolve, conditions in vocabulary")
        return 0
    print(f"# {tdir.name} — runbook plan\n")
    for num, when, step, selector, note in steps:
        cond = "always" if when == "always" else when
        if when in MECHANICAL:
            cond = f"{when}: {'MET' if MECHANICAL[when](tdir) else 'not met — skip'}"
        elif when not in ("always",) and not when.startswith("custom:"):
            cond = f"{when}: evaluate (model judges from live state)"
        marker, line = step_state(tdir, step)
        sel = f" · {selector}" if selector != "—" else ""
        print(f"  {num:>2}. [{marker:<7}] {step}{sel}")
        print(f"       when    {cond}")
        if note and note != "—":
            print(f"       note    {note}")
        print(f"       {line}")
    print("\n  contract: each step runs its own lifecycle; a blocked step stops there and names")
    print("  the producer; the closing brief proposes hunts, never starts them; one digest ping.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
