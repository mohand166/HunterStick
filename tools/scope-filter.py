#!/usr/bin/env python3
"""Filter a host list down to what scope.md authorises — before a tool ever sees it.

    tools/scope-filter.py targets/acme recon/live-hosts.txt          # -> stdout, in-scope only
    tools/scope-filter.py targets/acme recon/live-hosts.txt --out /tmp/in-scope.txt
    cat hosts.txt | tools/scope-filter.py targets/acme -             # stdin

Why this exists
---------------
This is an **opt-in convenience**, not a gate. Scope in this workspace is context and routing, and
`run.py`/`preflight.py` do not consult it — a skill the human invoked is never blocked on how
`scope.md` reads. But when *you* want a host list narrowed to the allowlist before handing it to a
raw `httpx`/`dnsx`/`naabu`/`katana`/`ffuf`/`nuclei` run — the same shaping `import-http.py`,
`monitor.py` and `sweep.py` do on their own inputs — this is the tool. It filters the **input**, the
one place shaping is cheap: a tool fed a filtered list cannot send a packet to a host that was never
in the list. Put it between the host file and the tool when you want that:

    tools/scope-filter.py targets/acme recon/live-hosts.txt --out /tmp/t.txt
    httpx -l /tmp/t.txt -follow-host-redirects ...

What it does NOT do — say so out loud rather than implying coverage
-------------------------------------------------------------------
* It cannot stop a tool that discovers new hosts mid-run (a redirect, a CNAME, a crawled link).
  Use `-follow-host-redirects` over `-follow-redirects`, and reconcile anything new as a
  *candidate*, not as something already probed.
* It cannot enforce a rate limit, an attribution header, or a method restriction.
* It cannot enforce a non-domain exclusion ("divested brands") — it names them instead.

Exit: 0 wrote a non-empty list · 1 nothing survived the filter · 2 unusable scope or input.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runlog   # noqa: E402
from scopelib import enumeration_roots, in_scope, matches, parse_scope   # noqa: E402


def die(msg, code=2):
    print(f"FAIL — {msg}", file=sys.stderr)
    raise SystemExit(code)


def host_of(line):
    """Accept a bare host, host:port, or a URL — tools are fed all three."""
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split("@")[-1]
    return s.rsplit(":", 1)[0] if s.count(":") == 1 and s.rsplit(":", 1)[1].isdigit() else s


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="path to targets/<slug>")
    ap.add_argument("hosts", nargs="?", help="host list file, or - for stdin")
    ap.add_argument("--roots", action="store_true",
                    help="print the authorised enumeration roots and exit — the seeds "
                         "for `subdomain-enumeration`, which has no host-list input")
    ap.add_argument("--out", help="write here instead of stdout")
    ap.add_argument("--quiet", action="store_true", help="suppress the summary on stderr")
    args = ap.parse_args()

    tdir = Path(args.target).resolve()
    if not (tdir / "index.md").exists():
        die(f"{args.target} is not a target brain")

    scope = parse_scope(tdir)
    if scope["state"] != "ok":
        die(scope["detail"])

    if args.roots:
        roots, skipped = enumeration_roots(scope)
        for r in roots:
            print(r)
        if not args.quiet:
            for dom, why in skipped:
                print(f"  not a root: {dom} — {why}", file=sys.stderr)
        if not roots:
            print("FAIL — no wildcard entry in scope.md, so there is nothing to enumerate. An "
                  "exact\n       host authorises only itself; start at 08, not 03.", file=sys.stderr)
            return 1
        return 0

    if not args.hosts:
        die("give a host list (or - for stdin), or --roots")

    if args.hosts == "-":
        lines = sys.stdin.read().splitlines()
    else:
        f = Path(args.hosts)
        if not f.is_absolute():
            f = tdir / args.hosts if (tdir / args.hosts).exists() else f
        if not f.exists():
            die(f"no such host list: {args.hosts}")
        lines = f.read_text(encoding="utf-8-sig", errors="replace").splitlines()

    kept, dropped, excluded = [], 0, 0
    for line in lines:
        h = host_of(line)
        if not h:
            continue
        if in_scope(h, scope):
            kept.append(line.strip())
        elif matches(h, scope["out_of_scope"]):
            excluded += 1
        else:
            dropped += 1

    body = "\n".join(kept) + ("\n" if kept else "")
    if args.out:
        Path(args.out).write_text(body, encoding="utf-8")
    else:
        sys.stdout.write(body)

    if not args.quiet:
        tot = len(kept) + dropped + excluded
        print(f"  scope-filter: {len(kept)}/{tot} in scope · {excluded} explicitly excluded · "
              f"{dropped} not in scope.md", file=sys.stderr)
        if scope["prose"]:
            print(f"  ⚠ {len(scope['prose'])} exclusion(s) in scope.md are not domain-shaped and "
                  f"CANNOT be filtered\n    mechanically — read them before you run:",
                  file=sys.stderr)
            for s in scope["prose"][:3]:
                print(f"      {s}", file=sys.stderr)

    if not kept:
        print("FAIL — nothing survived the scope filter. Running the tool now would either do "
              "nothing\n       or, worse, be given a wider list by hand. Check scope.md and the "
              "input.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(runlog.wrap()(main)())
