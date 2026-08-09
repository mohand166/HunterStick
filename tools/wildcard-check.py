#!/usr/bin/env python3
"""Verify a hostname list against DNS wildcards, independently of whatever produced it.

    tools/wildcard-check.py hosts.txt --out clean.txt --dropped dropped.txt
    cat hosts.txt | tools/wildcard-check.py - --out clean.txt

Why this exists
---------------
A wildcard record (`*.t.example.com`) answers for every label, so a brute/permutation run
"discovers" thousands of hosts that do not exist. Those names then flow into `attack-surface.md`,
get ranked, get probed, and produce findings against something that was never there.

**The resolver tool's own wildcard filter is not sufficient.** Measured on a real run: puredns
reported 11 wildcard roots, still left 21 artifacts in its output, and MISSED 4 real wildcard
parents entirely. 33 of 395 "discovered" names were echoes. That is why this checks the list
again from the outside instead of trusting the producer.

How it decides
--------------
For each distinct parent, ask **two different labels that cannot exist**. If BOTH answer, the
parent is a wildcard and every child in the list is an artifact. Two labels, not one, because a
single lucky collision with a real host would condemn a legitimate parent.

A name is kept when its parent does NOT wildcard. Kept names are not *proven* live — they are
merely not explained away by a wildcard; liveness is `live-host-validation`'s job.

Exit: 0 = nothing dropped · 1 = wildcards found and filtered · 2 = could not run the check.
"""
import argparse
import concurrent.futures
import shutil
import subprocess
import sys
from pathlib import Path

# Two fixed improbable labels. Fixed rather than random so a run is reproducible and a future
# reader can re-issue the exact query that made the decision.
CONTROLS = ("zzq7x-ctrl-a", "q9m2w-ctrl-b")


def parent_of(host):
    """`a.b.example.com` -> `b.example.com`. A bare apex has no parent to test."""
    bits = host.split(".")
    return ".".join(bits[1:]) if len(bits) > 2 else ""


def resolve(name, resolver, timeout):
    """First answer for `name`, or '' — shelling out to dig so the resolver is explicit.

    The system resolver is deliberately NOT used: it may be a corporate/VPN forwarder that
    synthesises answers, which is the very failure mode being tested for.
    """
    cmd = ["dig", "+short", f"+time={timeout}", "+tries=2", name]
    if resolver:
        cmd.append(f"@{resolver}")
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout * 3 + 5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.splitlines()[0].strip() if out else ""


def is_wildcard(parent, resolver, timeout):
    """True when BOTH impossible labels answer under `parent`."""
    return all(resolve(f"{c}.{parent}", resolver, timeout) for c in CONTROLS)


def classify(hosts, wildcard_parents):
    """Pure split, so the decision is testable without touching the network."""
    clean, dropped = [], []
    for h in hosts:
        (dropped if parent_of(h) in wildcard_parents else clean).append(h)
    return clean, dropped


def die(msg):
    """Exit 2, not 1. `sys.exit("text")` exits 1 — which is this tool's 'wildcards were found
    and filtered' code, so a refusal would be read as a successful filtering run."""
    print(msg, file=sys.stderr)
    sys.exit(2)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("hosts", help="file of hostnames, or - for stdin")
    ap.add_argument("--out", type=Path, help="write surviving hosts here")
    ap.add_argument("--dropped", type=Path, help="write wildcard artifacts here")
    ap.add_argument("--resolver", default="1.1.1.1",
                    help="resolver to query (default 1.1.1.1); '' uses the system resolver")
    ap.add_argument("--timeout", type=int, default=3)
    ap.add_argument("--concurrency", type=int, default=20)
    args = ap.parse_args()

    if not shutil.which("dig"):
        die("FAILURE: `dig` not found — cannot verify wildcards, refusing to pass the "
            "list through unchecked")

    text = sys.stdin.read() if args.hosts == "-" else Path(args.hosts).read_text(
        encoding="utf-8-sig", errors="replace")
    hosts = [l.strip().lower() for l in text.splitlines() if l.strip()]
    if not hosts:
        die("FAILURE: no hostnames on input — an empty check is not a pass")

    parents = sorted({p for p in (parent_of(h) for h in hosts) if p})
    print(f"  {len(hosts):,} host(s) · {len(parents):,} distinct parent(s) · "
          f"resolver {args.resolver or 'system'}")

    wild = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {pool.submit(is_wildcard, p, args.resolver, args.timeout): p for p in parents}
        for f in concurrent.futures.as_completed(futures):
            if f.result():
                wild.add(futures[f])

    clean, dropped = classify(hosts, wild)

    if wild:
        print(f"  {len(wild)} WILDCARD parent(s) — every child of these is an artifact:")
        for p in sorted(wild):
            print(f"      *.{p}")
    else:
        print("  no wildcard parents found")

    if args.out:
        args.out.write_text("\n".join(clean) + ("\n" if clean else ""), encoding="utf-8")
    if args.dropped:
        args.dropped.write_text("\n".join(dropped) + ("\n" if dropped else ""), encoding="utf-8")

    print(f"  clean: {len(clean):,}   dropped: {len(dropped):,}")
    if not args.out:
        print("\n".join(clean))
    print("  NOTE: 'clean' means not explained by a wildcard — NOT proven live. "
          "That is `live-host-validation`.")
    return 1 if dropped else 0


if __name__ == "__main__":
    sys.exit(main())
