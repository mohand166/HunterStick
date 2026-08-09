#!/usr/bin/env python3
"""Who is an IP range actually registered to? RDAP org lookup — the WHOIS replacement.

    tools/rdap-org.py --ip 198.51.100.10
    tools/rdap-org.py --list reps.tsv --out raw/asn/rdap-ownership.tsv --expect example

Why RDAP and not `whois`
------------------------
`whois` is a package, and a hardened VPS often has no passwordless sudo to install one. RDAP is
its IETF successor — JSON over HTTPS, no daemon, no package, works from any box that can reach the
internet. One endpoint covers every region: ARIN redirects to APNIC/RIPE/LACNIC/AFRINIC for
allocations it does not hold.

Why bother at all
-----------------
A scanner's ASN *name* is not ownership evidence. On one estate, RDAP refuted several ranges that
had already been written into the scope allowlist on the strength of a provider label alone.
Corroborating turned "probably theirs" into a list of ranges that must not be touched.

`--expect <substring>` makes that check mechanical: every row whose org does NOT contain it is
reported as UNCONFIRMED and the exit code is non-zero, so a pipeline notices.

Exit: 0 every row confirmed (or no --expect given) · 1 at least one unconfirmed · 2 refused.
"""
import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path

ENDPOINT = "https://rdap.arin.net/registry/ip/{}"


def die(msg):
    print(f"FAIL — {msg}", file=sys.stderr)
    sys.exit(2)


def org_from_rdap(doc):
    """Registered organisation name from an RDAP response document.

    Pure, so the parsing is testable without a network. The org lives in a vCard on one of the
    `entities`; the network `name` is the fallback and is a weaker claim — it is the allocation
    label, not the registrant.
    """
    if not isinstance(doc, dict):
        return ""
    for entity in doc.get("entities", []) or []:
        vcard = entity.get("vcardArray")
        if not vcard or len(vcard) < 2:
            continue
        for field in vcard[1]:
            if field and field[0] == "fn" and len(field) > 3 and field[3]:
                return str(field[3]).strip()
    return str(doc.get("name") or "").strip()


def lookup(ip, timeout=25):
    req = urllib.request.Request(
        ENDPOINT.format(ip),
        headers={"Accept": "application/rdap+json", "User-Agent": "HunterStick-rdap/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return org_from_rdap(json.load(r)) or "NO-ORG-FIELD"
    except Exception as exc:                                     # noqa: BLE001
        return f"ERROR:{exc.__class__.__name__}"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ip", action="append", default=[])
    ap.add_argument("--list", type=Path,
                    help="file of IPs, or TSV whose LAST tab-separated field before the org is an IP")
    ap.add_argument("--out", type=Path, help="write label<TAB>ip<TAB>org here")
    ap.add_argument("--expect", help="substring every org should contain, e.g. the company name")
    ap.add_argument("--rate", type=float, default=0.8, help="queries per second (default 0.8)")
    args = ap.parse_args()

    rows = []                                                    # (label, ip)
    for ip in args.ip:
        rows.append((ip, ip))
    if args.list:
        if not args.list.is_file():
            die(f"{args.list} does not exist")
        for line in args.list.read_text().splitlines():
            parts = [p.strip() for p in line.split("\t") if p.strip()]
            if not parts:
                continue
            # "AS123<TAB>1.2.3.4" -> label AS123; a bare "1.2.3.4" is its own label
            rows.append((parts[0], parts[1]) if len(parts) >= 2 else (parts[0], parts[0]))
    if not rows:
        die("no IPs given — an empty ownership check is not a confirmation")

    delay = 1.0 / args.rate if args.rate > 0 else 0
    out, unconfirmed = [], 0
    for label, ip in rows:
        org = lookup(ip)
        ok = (not args.expect) or (args.expect.lower() in org.lower())
        if not ok:
            unconfirmed += 1
        mark = "   " if ok else "  ✗"
        print(f"{mark} {label:<12} {ip:<18} {org}")
        out.append((label, ip, org))
        time.sleep(delay)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text("".join(f"{a}\t{b}\t{c}\n" for a, b, c in out), encoding="utf-8")
        print(f"\n  wrote {args.out}")

    if args.expect:
        print(f"\n  {len(out) - unconfirmed}/{len(out)} confirm '{args.expect}'")
        if unconfirmed:
            print(f"  {unconfirmed} UNCONFIRMED — marked ✗ above. A range you cannot attribute is a\n"
                  f"  range you must not scan: remove it from scope.md rather than assuming the\n"
                  f"  scanner's ASN label was right.")
    return 1 if unconfirmed else 0


if __name__ == "__main__":
    sys.exit(main())
