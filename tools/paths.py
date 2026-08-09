#!/usr/bin/env python3
"""Derive the host-stripped path list — the thing you replay across hosts.

    tools/paths.py targets/acme                     # print them
    tools/paths.py targets/acme --write             # recon/paths.txt, for a tool to read
    tools/paths.py targets/acme --for trunk.acme.com   # full URLs against one host
    tools/paths.py targets/acme --min-hosts 2       # only paths already seen on 2+ hosts

Why derived and not maintained
------------------------------
`recon/endpoints.md` already stores the full URL, which is the right primary record: an endpoint
without its host is not addressable, and a finding needs the address. But the *reusable* unit is
the path — `cross-host-endpoint-reuse` exists because an object id obtained legitimately on prod,
replayed against a
`trunk.`/`staging.` sibling, is the estate-scale authorization test.

Reconstructing that list by hand every time is how it drifts from the endpoints file. So this
computes it, and there is nothing to keep in sync: `endpoints.md` is the source, `paths.txt` is a
view of it. A path that appears on several hosts is ranked first — shared paths mean shared code,
and shared code with unshared configuration is the whole point of cross-host replay.

Exit: 0 wrote/printed · 1 nothing to derive · 2 refused.
"""
import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runlog                                                     # noqa: E402
from scopelib import in_scope, parse_scope                        # noqa: E402
from surfacelib import read as read_endpoints                     # noqa: E402

SOURCES = ("recon/endpoints.md", "recon/urls.txt")

# Segments that are object identifiers, not route structure. Without this, /orders/123 and
# /orders/456 count as two different paths on one host each — and a tool whose entire job is
# finding shared routes reports "0 shared" on an estate that shares every route it has.
ID_SHAPES = (
    (re.compile(r"^\d+$"), "{id}"),
    (re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I), "{uuid}"),
    (re.compile(r"^[0-9a-f]{16,}$", re.I), "{hash}"),
    (re.compile(r"^[A-Za-z0-9_-]{20,}$"), "{token}"),
    (re.compile(r"^\d{4}-\d{2}-\d{2}$"), "{date}"),
)


def templatize(path):
    """`/api/v1/orders/123` -> `/api/v1/orders/{id}` — the route, not the instance."""
    out = []
    for seg in path.split("/"):
        for rx, label in ID_SHAPES:
            if rx.match(seg):
                out.append(label)
                break
        else:
            out.append(seg)
    return "/".join(out)


def die(msg, code=2):
    print(f"FAIL — {msg}", file=sys.stderr)
    raise SystemExit(code)


def urls_from(tdir):
    """Every URL the brain knows, from the table and from the raw corpus if present."""
    found = []
    md = tdir / "recon/endpoints.md"
    for endpoint in read_endpoints(md):
        found.append((endpoint.url, endpoint.method))
    txt = tdir / "recon/urls.txt"
    if txt.exists():
        for line in txt.read_text(encoding="utf-8-sig", errors="replace").splitlines():
            line = line.strip()
            if line.startswith("http"):
                found.append((line, "GET"))
    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target")
    ap.add_argument("--write", action="store_true", help="write recon/paths.txt")
    ap.add_argument("--for", dest="host", metavar="HOST",
                    help="print full URLs against this host — it must be in scope")
    ap.add_argument("--min-hosts", type=int, default=1,
                    help="only paths already observed on at least N hosts (default 1)")
    args = ap.parse_args()

    tdir = Path(args.target).resolve()
    if not (tdir / "index.md").exists():
        die(f"{args.target} is not a target brain")

    urls = urls_from(tdir)
    if not urls:
        die(f"no URLs in {' or '.join(SOURCES)} — run `url-collection`, `api-discovery` or "
            f"`application-mapping` first. "
            f"An empty path list is not 'no paths', it is no data.", 1)

    # path -> {methods}, and the set of hosts it was seen on
    paths = defaultdict(lambda: {"methods": set(), "hosts": set(), "sample": ""})
    for url, method in urls:
        s = urlsplit(url)
        if not s.netloc:
            continue
        concrete = s.path or "/"
        if s.query:
            # keep the parameter NAMES — they are the reusable part; values are per-host noise
            names = "?" + "&".join(sorted(q.split("=", 1)[0] for q in s.query.split("&") if q))
        else:
            names = ""
        key = templatize(concrete) + names
        paths[key]["methods"].add(method)
        paths[key]["hosts"].add(s.netloc)
        # the template groups; the sample is what you can actually request
        paths[key]["sample"] = paths[key]["sample"] or concrete + (s.query and "?" + s.query or "")

    rows = [(p, v) for p, v in paths.items() if len(v["hosts"]) >= args.min_hosts]
    if not rows:
        die(f"no path is on {args.min_hosts}+ hosts. Lower --min-hosts, or this estate does not "
            f"share code the way clustering suggested.", 1)
    # shared first: a path on many hosts is the cross-host test worth running
    rows.sort(key=lambda kv: (-len(kv[1]["hosts"]), kv[0]))

    if args.host:
        # The human named this host explicitly, so this does not veto it — that would be a scope
        # gate on a human-selected action, which this workspace does not do. It warns when the host
        # is outside scope.md's allowlist (fail-loud, so a typo or a genuinely out-of-scope replay
        # is visible) and builds the list anyway. Their choice, their engagement.
        scope = parse_scope(tdir)
        if scope["state"] == "ok" and not in_scope(args.host, scope):
            print(f"  ⚠ `{args.host}` is not in scope.md's allowlist — building the replay list "
                  f"anyway because you named it.\n    If that host is authorised, add it to "
                  f"scope.md; if it was a typo, this is your warning.", file=sys.stderr)
        for _p, v in rows:
            # a template is not requestable — replay the concrete path that was actually observed
            print(f"https://{args.host}{v['sample']}")
        return 0

    if args.write:
        out = tdir / "recon/paths.txt"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("".join(f"{p}\n" for p, _ in rows), encoding="utf-8")
        (tdir / "recon/paths-concrete.txt").write_text(
            "".join(f"{v['sample']}\n" for _, v in rows), encoding="utf-8")
        multi = sum(1 for _, v in rows if len(v["hosts"]) > 1)
        print(f"\n  recon/paths.txt   {len(rows):,} paths from {len(urls):,} URLs across "
              f"{len({h for _, v in rows for h in v['hosts']})} hosts")
        print(f"  {multi:,} appear on more than one host — the `cross-host-endpoint-reuse` "
              f"candidates.")
        print(f"  recon/paths-concrete.txt  the same routes with a real id in place, for replay.")
        print(f"  Derived from {' + '.join(s for s in SOURCES if (tdir / s).exists())}; "
              f"regenerate, never edit.\n")
        return 0

    for p, v in rows[:200]:
        marks = ",".join(sorted(v["methods"]))
        print(f"  {len(v['hosts']):>3} host(s)  {marks:<12} {p}")
    if len(rows) > 200:
        print(f"  … {len(rows) - 200:,} more. --write to get them all.")
    return 0


if __name__ == "__main__":
    sys.exit(runlog.wrap()(main)())
