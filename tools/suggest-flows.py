#!/usr/bin/env python3
"""Which flow should run against this target — computed from the brain, never guessed.

    tools/suggest-flows.py targets/acme
    tools/suggest-flows.py targets/acme --why      # show the evidence for every verdict

A hunter with 3,918 hosts and thirteen data files does not need another inventory. They need one
answer to "what now". This prints that, with the evidence under it, and — the part that matters —
it prints what it **cannot** determine and what would settle it.

The honesty rule this tool exists to hold: a situation is either **proven from structured data**
or it is **not claimed**. Four of the nine situations (dead-end-host, spa-frontend, api-surface,
static-site) need someone to look at a response, and the brain stores prose there. Those are listed
under "needs your eyes" with the evidence to check — never asserted.

Reuses tools/dashboard.py for file-state and principal counting so the two can never disagree
about whether an account is real.

Exit: 0 suggestions printed · 2 unusable target directory.
"""
import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runlog   # noqa: E402
from dashboard import (DATA_FILES, age_days, field, read, state_of,   # noqa: E402
                       table_rows, table_with, usable_principals)
from kb import calibration_of, read_runs                              # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
STALE_DAYS = 14
BIG_ESTATE = 200

FLOWS = "playbooks/flows"

# situations that need a human to look at a live response — never asserted from the brain
NEEDS_EYES = [
    ("dead-end-host", "live host, but no links, no forms, everything 404s",
     "fetch the root of a top-ranked host: are there links or forms in the body?"),
    ("spa-frontend", "the page is a JS shell and a bundle",
     "is the HTML body basically empty with a few <script src>?"),
    ("api-surface", "JSON responses, or a spec / introspection answers",
     "does the host return JSON, and does /openapi.json or GraphQL introspection give a real body "
     "(not the SPA shell)?"),
    ("static-site", "no forms, no state, cacheable, informational",
     "any Set-Cookie, form, or JSON anywhere? if not, three checks and triage it out."),
]


class Out:
    def __init__(self):
        self.start = None
        self.blocking = []
        self.flows = []
        self.notes = []


def counts(tdir):
    st = {}
    for rel, label, _ in DATA_FILES:
        st[rel] = state_of(tdir / rel)
    return st


def n_of(state):
    """Numeric count, or None when the file is missing/empty/prose.

    `demoted` counts: the file is populated, it just lives on the VPS. Excluding it would make a
    target with 44k demoted subdomains look as empty as one that never ran enumeration.
    """
    kind, n = state
    return n if kind in ("lines", "rows", "demoted") else None


def analyse(tdir):
    o = Out()
    idx = read(tdir / "index.md")
    st = counts(tdir)

    live = n_of(st.get("recon/live-hosts.txt", ("missing", None)))
    subs = n_of(st.get("recon/subdomains.txt", ("missing", None)))
    clusters_kind, clusters_n = st.get("clusters.md", ("missing", None))

    nprin = usable_principals(read(tdir / "accounts.md"))
    _, surf_rows = table_with(read(tdir / "attack-surface.md"), "entrypoint", "vuln_class")
    surf_rows = [r for r in surf_rows if any(c.strip() for c in r)]
    _, test_rows = table_rows(read(tdir / "tested.md"))
    test_rows = [r for r in test_rows if any(c.strip() for c in r)]

    upd = field(idx, "Last updated") or ""
    age = age_days(upd)

    # A brand-new target is not a stale one. Nothing has run, so no situation can hold yet and
    # the entry point comes from the SHAPE of the scope statement, not from a flow.
    virgin = (not live and not subs and not surf_rows and not test_rows)
    if virgin:
        o.start = (None, None)
        o.notes.append("no recon data at all — this target has not been worked yet.")
        o.notes.append("Entry point comes from the shape of the scope statement, not from a flow: "
                       "company name → `organization-and-roots` · wildcard apex → "
                       "`subdomain-enumeration` · host list → `http-probing` · one host → "
                       "`http-probing` then `application-mapping`/`api-discovery` · URL+path → "
                       "`application-mapping`/`api-discovery` · IP/CIDR → `asn-and-ip-discovery` "
                       "(playbooks/system/phase-routing.md §1).")
        if nprin == 0:
            o.notes.append("0 usable principals — plan for accounts early; without 2 the whole "
                           "authz family stays blocked.")
        return o, {"live": live, "subs": subs, "principals": nprin, "ranked": 0, "probed": 0}

    # ---- blocking conditions: these invalidate work done after them ----------
    # Calibration is STRUCTURED state, never a keyword match. "Soft-404 calibration passed" and
    # "no catch-all detected" both contain the words and both mean the opposite of a problem.
    cal = calibration_of(tdir) or {}
    broken = {h: r for h, r in cal.items() if r["object"].strip().lower() == "broken"}
    if broken:
        o.blocking.append((
            "broken-calibration",
            f"{len(broken)} host(s) recorded calibration=broken: " +
            ", ".join(sorted(broken)[:4]),
            "Every discovery count taken on those hosts before the repair is void, and it will "
            "not look void."))
    elif not cal:
        o.notes.append("calibration state is UNRECORDED. Not 'clean' — unrecorded. Before any "
                       "discovery phase, probe an impossible path and log the result: "
                       "`kb.py add <t> --subject <host> --predicate calibration "
                       "--object clean|broken --confidence observed --evidence <artifact>`.")

    if age is None:
        o.blocking.append((
            "stale-return",
            "index.md has no Last updated date",
            "Every number in the brain is of unknown age. Establish ages before acting on any."))
    elif age > STALE_DAYS:
        o.blocking.append((
            "stale-return",
            f"brain last updated {upd} — {age} days ago",
            "Re-read scope first (programs change scope), then diff rather than re-run."))

    # ---- provable situations -------------------------------------------------
    if live is not None and live >= BIG_ESTATE:
        if clusters_kind in ("missing", "empty"):
            o.flows.append(("huge-estate",
                            f"{live:,} live hosts and clusters.md is {clusters_kind}",
                            "Cluster first. Testing hosts instead of clusters at this scale is how "
                            "an estate gets tested at random."))
        else:
            o.notes.append(f"{live:,} live hosts, already clustered "
                           f"({clusters_n} clusters) — work the representatives, not the members.")
    elif live is not None and live > 0:
        o.notes.append(f"{live:,} live host(s) — small enough to work individually.")

    if nprin == 0:
        o.flows.append(("no-signup",
                        "0 usable principals in accounts.md "
                        "(rows with placeholder credentials are plans, not accounts)",
                        "Do the unauth classes properly and park authz as blocked (needs-account). "
                        "One credential would unblock the largest set of classes here."))
    elif nprin == 1:
        o.blocking.append(("no-signup",
                           "exactly 1 usable principal",
                           "Authz / IDOR / tenant / privesc need 2. With one account you cannot "
                           "tell 'authorized' from 'unauthorized but unchecked'."))
    else:
        o.flows.append(("auth-app",
                        f"{nprin} usable principals available",
                        "Two-principal diffing is possible — the classes scanners cannot reach."))

    # ---- coverage state ------------------------------------------------------
    if not surf_rows:
        o.notes.append("attack-surface.md is empty — nothing is ranked, so any model-chosen test "
                       "would be picking by whatever it happened to notice. Run "
                       "`attack-surface-prioritization`.")
    elif not test_rows:
        o.notes.append(f"{len(surf_rows)} ranked entries, 0 probes in tested.md — "
                       "coverage is 0%, not unknown. The surface is ready; nothing has been tried.")
    else:
        o.notes.append(f"{len(surf_rows)} ranked entries, {len(test_rows)} probe(s) logged — "
                       "run tools/coverage.py for the untested cells.")

    runs = read_runs(tdir)
    if runs:
        newest = max(r["date"] for r in runs)
        o.notes.append(f"{len(runs)} bounded run(s) recorded, newest {newest} — "
                       f"`kb.py runs` for selectors and what each did NOT cover.")
    else:
        o.notes.append("no runs recorded in runs.tsv. Without them nothing can say WHICH "
                       "selector a skill covered, so 'subdomain-enumeration' reads as "
                       "'subdomain discovery is finished' — which it never is.")

    missing = [rel for rel, (k, _) in st.items() if k == "missing"]
    if missing:
        o.notes.append("missing inputs (a skill needing one of these must FAIL its preflight, not "
                       "run empty): " + ", ".join(missing))

    # ---- pick the single starting point -------------------------------------
    if o.blocking:
        o.start = (o.blocking[0][0], "it invalidates anything you do before it")
    elif o.flows:
        o.start = (o.flows[0][0], "highest-value situation provable from the brain")
    return o, {"live": live, "subs": subs, "principals": nprin,
               "ranked": len(surf_rows), "probed": len(test_rows)}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target")
    ap.add_argument("--why", action="store_true", help="show evidence for every verdict")
    args = ap.parse_args()

    tdir = Path(args.target).resolve()
    if not tdir.is_dir() or not (tdir / "index.md").exists():
        print(f"FAIL — {args.target} is not a target brain (no index.md).", file=sys.stderr)
        return 2

    o, m = analyse(tdir)
    print(f"\n# {tdir.name} — what to run")
    print(f"  {format(m['live'], ',') if m['live'] is not None else '?'} live · "
          f"{m['principals']} usable principals · {m['ranked']} ranked · {m['probed']} probed\n")

    if o.start and o.start[0]:
        print(f"  ▶ START HERE   {FLOWS}/{o.start[0]}.md")
        print(f"                 {o.start[1]}\n")
    elif o.start:
        print("  ▶ START HERE   no flow applies yet — nothing has been collected.\n")

    if o.blocking:
        print("  MUST RESOLVE FIRST — these make later numbers wrong, not just incomplete")
        for name, ev, why in o.blocking:
            print(f"    ! {name:<20} {ev}")
            print(f"      {'':<20} {why}")
        print()

    if o.flows:
        print("  APPLICABLE — proven from the brain")
        for name, ev, why in o.flows:
            print(f"    · {name:<20} {ev}")
            if args.why:
                print(f"      {'':<20} {why}")
        print()

    print("  NEEDS YOUR EYES — cannot be computed; the brain stores prose here"
          if o.flows or o.blocking else
          "  SITUATIONS TO WATCH FOR once hosts come back")
    for name, sit, check in NEEDS_EYES:
        print(f"    ? {name:<20} {sit}")
        if args.why:
            print(f"      {'':<20} check: {check}")
    print()

    if o.notes:
        print("  STATE")
        for n in o.notes:
            print(f"    - {n}")
        print()

    print(f"  Flow contract and the full situation table: {FLOWS}/_index.md")
    print("  Two intents: \"what should I run?\" recommends and stops; a named flow runs without\n"
          "  asking again. A flow declares its steps and cost first, and never sends a payload.\n")
    return 0


if __name__ == "__main__":
    sys.exit(runlog.wrap()(main)())
