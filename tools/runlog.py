#!/usr/bin/env python3
"""Every tool invocation, its exit code, and what it said — append-only.

    tools/runlog.py targets/acme                 # recent invocations
    tools/runlog.py targets/acme --failures      # only what went wrong
    tools/runlog.py targets/acme --since 2026-07-31

Why this exists
---------------
The model runs the tools. If one exits 2 and the model summarises the turn without mentioning it,
the failure is gone — there is no terminal scrollback in a fresh session, and the next model reads
a brain that looks fine. That is the silent failure this workspace is otherwise built to prevent,
reappearing at the one layer that had no record.

So every tool appends one line before it exits, whatever the outcome. The log is **evidence about
the tooling**, independent of what anyone reported. `brief.py --resume` surfaces recent failures so
a new session starts by seeing them.

It records the argv, the exit code, and a one-line summary. It never records tool *output* — that
can contain target data and credentials, and this file is not the place for either.

Exit: 0 · 1 nothing logged yet · 2 unusable target.
"""
import argparse
import csv
import os
import sys
from datetime import datetime
from pathlib import Path

COLS = ["ts", "tool", "exit", "summary", "argv"]
LOGREL = "logs/tools.tsv"

# a credential can arrive on a command line; the log is durable, so scrub before writing
SECRETISH = ("--header", "-H", "--token", "--password", "--key", "--api-key", "--secret",
             "-b", "--cookie", "--cookie-jar", "--bearer", "--auth", "-p", "--pass")


def _redact(argv):
    out, skip = [], False
    for a in argv:
        if skip:
            out.append("<redacted>")
            skip = False
            continue
        if a in SECRETISH:
            out.append(a)
            skip = True
            continue
        if "=" in a and a.split("=", 1)[0].lstrip("-").lower() in {
                s.lstrip("-").lower() for s in SECRETISH}:
            out.append(a.split("=", 1)[0] + "=<redacted>")
            continue
        out.append(a)
    return " ".join(out)


def record(target_dir, tool, code, summary=""):
    """Append one line. Never raises — a logging failure must not break the tool it logs."""
    try:
        if not target_dir:
            return code
        d = Path(target_dir)
        if not (d / "index.md").exists():
            return code
        f = d / LOGREL
        f.parent.mkdir(parents=True, exist_ok=True)
        new = not f.exists()
        with f.open("a", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=COLS, delimiter="\t", lineterminator="\n")
            if new:
                w.writeheader()
            w.writerow({"ts": datetime.now().isoformat(timespec="seconds"),
                        "tool": tool, "exit": code,
                        "summary": (summary or "").replace("\t", " ")[:160],
                        "argv": _redact(sys.argv[1:])})
    except Exception:
        pass
    return code


def wrap(target_arg_index=0):
    """Decorator for a tool's main(): log the exit code whatever happens, then re-raise."""
    def deco(fn):
        def inner(*a, **kw):
            if any(argument in ("-h", "--help") for argument in sys.argv[1:]):
                return fn(*a, **kw)
            tool = Path(sys.argv[0]).name
            tgt = sys.argv[target_arg_index + 1] if len(sys.argv) > target_arg_index + 1 else None
            if tgt and tgt.startswith("-"):
                tgt = None
            try:
                code = fn(*a, **kw)
            except SystemExit as e:
                record(tgt, tool, e.code if isinstance(e.code, int) else 2, "SystemExit")
                raise
            except BaseException as e:
                record(tgt, tool, 3, f"{type(e).__name__}: {e}"[:160])
                raise
            record(tgt, tool, code or 0)
            return code
        return inner
    return deco


def read_log(tdir):
    f = Path(tdir) / LOGREL
    if not f.exists():
        return []
    with f.open(encoding="utf-8-sig", newline="") as fh:
        return [r for r in csv.DictReader(fh, delimiter="\t") if r.get("tool")]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target")
    ap.add_argument("--failures", action="store_true", help="only non-zero exits")
    ap.add_argument("--since", metavar="YYYY-MM-DD")
    ap.add_argument("--limit", type=int, default=25)
    args = ap.parse_args()

    tdir = Path(args.target).resolve()
    if not (tdir / "index.md").exists():
        print(f"FAIL — {args.target} is not a target brain", file=sys.stderr)
        return 2

    rows = read_log(tdir)
    if args.since:
        rows = [r for r in rows if r["ts"][:10] >= args.since]
    bad = [r for r in rows if r["exit"] not in ("0", "")]
    if args.failures:
        rows = bad
    if not rows:
        print("  nothing logged" + (" that failed" if args.failures else " yet"))
        return 1

    print(f"\n# tool log — {tdir.name}   ({len(read_log(tdir))} total, {len(bad)} non-zero)\n")
    for r in rows[-args.limit:]:
        mark = "   " if r["exit"] == "0" else " ! "
        print(f" {mark}{r['ts']}  exit={r['exit']:<2} {r['tool']:<20} {r['argv'][:52]}")
        if r["summary"]:
            print(f"        {r['summary']}")
    if bad and not args.failures:
        print(f"\n  {len(bad)} non-zero exit(s). `--failures` to see only those. A tool that exited "
              f"2\n  did NOT do its job — check that whatever depended on it was not written anyway.")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
