#!/usr/bin/env python3
"""Write something the hunter stated in the prompt into the brain, with provenance.

    tools/record.py targets/acme --into recon/root-domains.md \
        --source "hunter, prompt" -- acme.com acme.net

    tools/record.py targets/acme --into scope --source "program page" -- '*.acme.com'
    tools/record.py targets/acme --into recon/subdomains.txt --source "hunter, prompt" -- @/tmp/list

Why this exists
---------------
A phase's inputs are a hard gate — a tool that runs on an input nobody supplied produces a zero
that reads like a result. But the gate was checking the wrong thing: it demanded that a *file*
exist, when what actually matters is that the *fact* is recorded.

So "run subdomain enum on acme, the roots are acme.com and acme.net" was refused, even though the
hunter had just supplied the missing input. The prompt is a legitimate source. It simply is not a
durable one: nothing in the brain remembers a sentence, and next month nobody can tell whether
`acme.net` came from the program page or from a guess.

This closes that gap without weakening the gate. The statement is written to the file the phase
reads, tagged with where it came from and when, and then preflight passes **honestly** — because
the input genuinely exists now.

Scope does not veto this. The hunter chose the target and supplied the value; a tool whose job is
to persist that input cannot also refuse it — that was the exact contradiction where the user could
provide a required input and the mechanism meant to store it vetoed it. So a value the hunter states
is recorded. If it is not yet inside `scope.md`'s allowlist, that is **noted, not refused** — the
note is fail-loud (you see it), and adding it to `scope.md` is one `--into scope` away. Scope stays
what it is everywhere else now: routing and context, not an execution gate.

Exit: 0 recorded · 1 nothing to do · 2 the check itself could not run.
"""
import argparse
import re
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runlog                                                     # noqa: E402
from scopelib import in_scope, parse_scope                        # noqa: E402

HOSTISH = re.compile(r"^(?:\*\.)?(?:[a-z0-9-]+\.)+[a-z]{2,}$", re.I)


def die(msg, code=2):
    print(f"FAIL — {msg}", file=sys.stderr)
    raise SystemExit(code)


def read_values(items):
    """Literal values, or the lines of a file given as `@path`."""
    out = []
    for it in items:
        if it.startswith("@"):
            p = Path(it[1:])
            if not p.exists():
                die(f"{p} does not exist")
            out += [l.strip() for l in p.read_text(encoding="utf-8-sig").splitlines() if l.strip()]
        else:
            out.append(it.strip())
    return [v for v in out if v and not v.startswith("#")]


def append_scope(tdir, values, source, today):
    """Establish or widen the authority itself — the one thing not checked against scope."""
    p = tdir / "scope.md"
    t = p.read_text(encoding="utf-8-sig")
    placeholder = ("- TBD — blocking: derive from the verbatim statement above; the ingest "
                   "tools match against it")
    rows = "\n".join(f"- `{v}`" for v in values)
    if placeholder in t:
        t = t.replace(placeholder, rows, 1)
    else:
        m = re.search(r"^#{2,3}\s*In scope\s*$", t, re.M)
        if not m:
            die("scope.md has no `In scope` section to append to")
        end = t.find("\n#", m.end())
        end = len(t) if end == -1 else end
        t = t[:end].rstrip() + "\n" + rows + "\n" + t[end:]
    p.write_text(t, encoding="utf-8")

    ev = tdir / "scope-evidence.md"
    if ev.exists():
        with ev.open("a", encoding="utf-8") as fh:
            fh.write(f"\n- {today} — added {', '.join(values)} · source: {source}\n")
    return len(values)


def append_file(dest, values, source, today, is_table):
    dest.parent.mkdir(parents=True, exist_ok=True)
    existing = dest.read_text(encoding="utf-8-sig") if dest.exists() else ""
    fresh = [v for v in values if v not in existing]          # never duplicate a known row
    if not fresh:
        return 0
    with dest.open("a", encoding="utf-8") as fh:
        if not existing.endswith("\n") and existing:
            fh.write("\n")
        for v in fresh:
            # a .md input file is a table; a .txt one is a plain list the tools read directly
            fh.write(f"| {v} | {source} | {today} |\n" if is_table else f"{v}\n")
    return len(fresh)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target")
    ap.add_argument("--into", required=True,
                    help="`scope`, or a path inside the target, e.g. recon/root-domains.md")
    ap.add_argument("--source", required=True,
                    help="where this came from — 'hunter, prompt' · 'program page' · a URL. "
                         "An unattributed fact is one nobody can re-verify.")
    argv = sys.argv[1:]
    # `--help` before the `--` split, or asking the tool what it does exits 2.
    if not argv or argv[0] in ("-h", "--help"):
        ap.print_help()
        return 0
    if "--" not in argv:
        die("give the values after `--`, e.g. ... --source 'hunter, prompt' -- acme.com acme.net")
    cut = argv.index("--")
    args = ap.parse_args(argv[:cut])
    values = read_values(argv[cut + 1:])
    if not values:
        die("nothing to record", 1)

    tdir = Path(args.target).resolve()
    if not (tdir / "index.md").exists():
        die(f"{args.target} is not a target brain")
    today = date.today().isoformat()

    if args.into == "scope":
        n = append_scope(tdir, values, args.source, today)
        print(f"\n  scope.md   +{n} · source: {args.source}")
        print("  Re-run preflight — the input exists now, so the gate passes honestly.\n")
        return 0

    # Note — never veto — a host that scope.md's allowlist does not yet cover. The hunter
    # supplied it; recording it is the whole job. If scope is still a placeholder we cannot even
    # compare, which is fine: the value is recorded and the note says scope is unset.
    scope = parse_scope(tdir)
    if scope["state"] == "ok":
        off = [v for v in values if HOSTISH.match(v) and not in_scope(v.lstrip("*."), scope)]
    else:
        off = []
    dest = tdir / args.into
    if not dest.resolve().is_relative_to(tdir.resolve()):
        die(f"{args.into} escapes the target directory")
    n = append_file(dest, values, args.source, today, dest.suffix == ".md")
    if n == 0:
        print(f"\n  {args.into} already has all {len(values)} value(s). Nothing appended.\n")
        return 1
    print(f"\n  {args.into}   +{n} of {len(values)} · source: {args.source} · {today}")
    if off:
        print(f"\n  ⚠ {len(off)} value(s) are not in scope.md's allowlist: {', '.join(off[:5])}"
              f"{' …' if len(off) > 5 else ''}")
        print("    Recorded anyway — you supplied them. If the program covers them, add them to\n"
              f"    scope.md so later sessions see the boundary:\n"
              f"      tools/record.py {args.target} --into scope --source '<where>' -- {' '.join(off[:3])}")
    print("  Re-run preflight — the input exists now, so the gate passes honestly.\n")
    return 0


if __name__ == "__main__":
    sys.exit(runlog.wrap()(main)())
