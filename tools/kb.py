#!/usr/bin/env python3
"""The observation ledger — every fact the target ever showed you, and what it changes.

    tools/kb.py add targets/acme --subject api.acme.com \
        --predicate runs --object "Ruby on Rails 7.0.4" \
        --confidence observed --source application-mapping --evidence raw/profile-resp.txt

    tools/kb.py show     targets/acme [--subject H] [--predicate P]
    tools/kb.py reassess targets/acme [--since YYYY-MM-DD]   # current + new = updated
    tools/kb.py chains   targets/acme [--depth 3]            # multi-host pivots

Why this exists
---------------
Two failures this workspace kept having, which turn out to be the same failure:

  1. Recon was treated as done. `technology-fingerprinting` wrote `technologies.md` on day one;
     41 files read it
     forever; nothing ever corrected it when app-mapping saw the real framework on day nine.
  2. Facts about *relationships between hosts* had nowhere to live at all, so a chain could only
     be found by one person remembering four files at once.

Both come from the same hole: a phase writes the file it owns, and has nowhere to put what it
learned incidentally. This is that place.

The three rules that make it work
---------------------------------
* **Append-only.** A later observation never overwrites an earlier one. Both are kept, and the
  disagreement is visible — "httpx reported nginx on day 1, mapping observed Rails on day 9" is
  itself a finding (usually a proxy in front of an origin). Overwriting destroys that.
* **Confidence is about provenance, not certainty.** `observed` (you saw the behaviour, artifact
  stored) beats `reported` (the target's own header said so — headers lie) beats `inferred`
  (similarity, fingerprint, heuristic). This is what lets day-9 evidence correctly supersede
  day-1 evidence instead of just being newer.
* **Closed vocabulary.** Unknown predicates are refused. A free-text ledger is prose with tabs in
  it, and nothing can compute over prose.

Exit: 0 ok · 1 nothing to report · 2 refused / failed.
"""
import argparse
import csv
import hashlib
import re
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import runlog   # noqa: E402
from scopelib import clean   # noqa: E402  (one normaliser, not three)
LEDGER = "observations.tsv"
COLS = ["date", "subject", "predicate", "object", "confidence", "source", "evidence"]

# ---- closed vocabulary ------------------------------------------------------

NODE_PREDICATES = {
    "runs":        "framework / language / server / library, with version when known",
    "behind":      "CDN, WAF, proxy or load balancer in front of it",
    "serves":      "what it is: spa | api | static | app | redirect | error",
    "auth":        "auth mechanism: oauth | saml | basic | session-cookie | bearer | none",
    "resolves-to": "IP address or CNAME target",
    "status":      "characteristic response: 200 | 401 | 403 | 404 | soft-404 | catch-all | 500",
    "calibration": "clean | broken | unknown — is discovery on this host trustworthy",
}

# Direction matters. "A's JS names B" does NOT mean B names A, and a token issued by A being
# accepted by B says nothing about the reverse. Treating every edge as symmetric invents
# attack paths that cannot exist — the chain walker follows `directed` edges one way only.
EDGE_PREDICATES = {
    "references":        "A's JS, config or HTML names B",
    "shares-session":    "a token issued by A is ACCEPTED by B",
    "shares-secret":     "a key or credential present in A is consumed by B",
    "shares-endpoint":   "the same path with the same behaviour exists on both",
    "shares-backend":    "same origin IP, fingerprint or error page",
    "authenticates-via": "A's login flow terminates at B",
    "same-tenant-model": "a tenant id from A is recognized by B",
}

# symmetric: the relation genuinely holds both ways from one observation
SYMMETRIC_EDGES = {"shares-backend", "shares-endpoint", "same-tenant-model"}
# directed: A→B only. The reverse needs its own observation.
DIRECTED_EDGES = set(EDGE_PREDICATES) - SYMMETRIC_EDGES

CALIBRATION_STATES = {"clean", "broken", "unknown"}

# Cardinality. Only a genuinely single-valued fact can be "superseded"; everything else can hold
# several true values at once. A host runs nginx AND Rails (proxy in front of an origin), accepts
# oauth AND a session cookie, and references many other hosts. Treating those as competing
# alternatives discarded real edges — which broke the cross-host chain feature outright.
SINGLE_VALUED = {"calibration", "status"}


def is_single_valued(predicate):
    return predicate in SINGLE_VALUED

PREDICATES = {**NODE_PREDICATES, **EDGE_PREDICATES}
CONFIDENCE = ["observed", "reported", "inferred"]      # strongest first
CONF_RANK = {c: i for i, c in enumerate(CONFIDENCE)}   # lower = stronger


def die(msg, code=2):
    print(f"FAIL — {msg}", file=sys.stderr)
    raise SystemExit(code)


def target_of(arg):
    p = Path(arg).resolve()
    if not p.is_dir() or not (p / "index.md").exists():
        die(f"{arg} is not a target brain (no index.md)")
    return p


def ledger_path(tdir):
    return Path(tdir) / LEDGER          # accept a str or a Path — callers pass both


def read_rows(tdir):
    f = ledger_path(tdir)
    if not f.exists():
        return []
    out = []
    with f.open(encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            if row.get("subject") and row.get("predicate"):
                out.append({k: (row.get(k) or "").strip() for k in COLS})
    return out


def append_row(tdir, row):
    f = ledger_path(tdir)
    new = not f.exists()
    with f.open("a", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLS, delimiter="\t", lineterminator="\n")
        if new:
            w.writeheader()
        w.writerow(row)


def table_rows(text):
    """Data rows of the first markdown table (header excluded)."""
    text = clean(text)
    rows, header, seen_sep = [], None, False
    for line in text.splitlines():
        if not line.lstrip().startswith("|"):
            if seen_sep and rows:
                break
            continue
        if re.match(r"^\s*\|[\s|:-]+\|\s*$", line):
            seen_sep = True
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if header is None:
            header = cells
            continue
        if seen_sep and any(cells):
            rows.append(cells)
    return rows


NOT_PROBED = ("blocked", "deferred", "out-of-scope", "not-applicable")


def tested_subjects(tdir):
    """Hosts a probe was actually SENT to.

    A `blocked (needs-account)` or `out-of-scope` row means the opposite of tested — nothing was
    sent. Counting those as probed hid the host from pivot candidates, which is exactly backwards:
    a host you could not reach is a host still worth reaching.
    """
    f = Path(tdir) / "tested.md"
    if not f.exists():
        return set()
    out = set()
    for r in table_rows(f.read_text(encoding="utf-8-sig", errors="replace")):
        blob = " ".join(r).lower()
        if any(k in blob for k in NOT_PROBED):
            continue
        out |= {h.lower() for h in re.findall(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", blob, re.I)}
    return out


# ---------------------------------------------------------------- add

def cmd_add(args):
    tdir = target_of(args.target)
    if args.predicate not in PREDICATES:
        print(f"FAIL — unknown predicate '{args.predicate}'. The vocabulary is closed:",
              file=sys.stderr)
        for group, d in (("node", NODE_PREDICATES), ("edge", EDGE_PREDICATES)):
            for k, v in d.items():
                print(f"       {group:<5} {k:<18} {v}", file=sys.stderr)
        return 2
    if args.confidence not in CONFIDENCE:
        die(f"confidence must be one of {', '.join(CONFIDENCE)}")
    if args.confidence == "observed" and not args.evidence:
        die("confidence=observed requires --evidence (the stored artifact). "
            "Without an artifact it is 'inferred', not 'observed'.")
    # calibration drives a BLOCKING flow, so its vocabulary is closed like the predicates.
    # A typo ("cleen") would otherwise sit in the ledger meaning nothing and matching nothing.
    if args.predicate == "calibration":
        v = args.object.strip().lower()
        if v not in CALIBRATION_STATES:
            die(f"calibration must be one of {', '.join(sorted(CALIBRATION_STATES))} — got "
                f"'{args.object}'. It gates every discovery count on that host, so it cannot be "
                f"free text.")
        args.object = v

    row = {"date": args.date or date.today().isoformat(),
           "subject": args.subject.strip().lower(),
           "predicate": args.predicate,
           "object": args.object.strip(),
           "confidence": args.confidence,
           "source": args.source or "unstated",
           "evidence": args.evidence or ""}

    prior = [r for r in read_rows(tdir)
             if r["subject"] == row["subject"] and r["predicate"] == row["predicate"]]
    append_row(tdir, row)
    print(f"  + {row['subject']}  {row['predicate']}  {row['object']}  "
          f"[{row['confidence']}, {row['source']}]")
    other = [p for p in prior if p["object"].lower() != row["object"].lower()]
    if other and is_single_valued(row["predicate"]):
        print(f"  ⚠ supersedes {len(other)} earlier value(s) — both kept:")
        for p in other[-3:]:
            print(f"      {p['date']}  {p['object']}  [{p['confidence']}, {p['source']}]")
        print("    Run: tools/kb.py reassess " + args.target)
    elif other:
        print(f"  + adds to {len(other)} existing value(s) — {row['predicate']} is multi-valued, "
              f"so they all stand:")
        for p in other[-3:]:
            print(f"      {p['date']}  {p['object']}  [{p['confidence']}]")
    return 0


# ---------------------------------------------------------------- show

def cmd_show(args):
    tdir = target_of(args.target)
    rows = read_rows(tdir)
    if args.subject:
        rows = [r for r in rows if r["subject"] == args.subject.lower()]
    if args.predicate:
        rows = [r for r in rows if r["predicate"] == args.predicate]
    if not rows:
        print("  no observations match")
        return 1
    for r in rows:
        ev = f"  <- {r['evidence']}" if r["evidence"] else ""
        print(f"  {r['date']}  {r['subject']:<34} {r['predicate']:<18} {r['object']:<28} "
              f"[{r['confidence']}/{r['source']}]{ev}")
    print(f"\n  {len(rows)} observation(s)")
    return 0


# ---------------------------------------------------------------- reassess

def current_value(observations):
    """Strongest confidence wins; newest breaks a tie. Provenance beats recency."""
    return sorted(observations, key=lambda r: (CONF_RANK[r["confidence"]], _neg_date(r["date"])))[0]


def _neg_date(d):
    return tuple(-int(x) for x in (re.findall(r"\d+", d) or ["0"])[:3])


def cmd_reassess(args):
    tdir = target_of(args.target)
    rows = read_rows(tdir)
    if not rows:
        print(f"  {LEDGER} is empty — nothing has been recorded yet.\n"
              f"  Phases append to it with `tools/kb.py add`; without that, recon stays a "
              f"one-shot pass.")
        return 1

    print(f"\n# {tdir.name} — reassessment   ({len(rows)} observations)")

    # ---- 1. what the target IS right now, and where the record disagrees ----
    by_key = defaultdict(list)
    for r in rows:
        by_key[(r["subject"], r["predicate"])].append(r)

    # A dispute is only possible where the fact can hold ONE value.
    disputed = {k: v for k, v in by_key.items()
                if is_single_valued(k[1]) and len({x["object"].lower() for x in v}) > 1}
    multi = {k: v for k, v in by_key.items()
             if not is_single_valued(k[1]) and len({x["object"].lower() for x in v}) > 1}

    # A month-old target must give a BETTER view, not a longer one. Printing every pair means
    # output grows with the ledger — 120 observations became 133 lines, and at six months it is
    # unreadable. The default is the summary plus what changed; `--full` still dumps everything.
    subjects = len({s for s, _ in by_key})
    print(f"\n## Current picture   {subjects} hosts · {len(by_key)} facts · "
          f"{len(disputed)} disputed · {len(multi)} multi-valued")
    if not args.full:
        top = sorted(({s for s, _ in by_key}), key=lambda s: -len(
            [1 for (a, _) in by_key if a == s]))[:5]
        for s in top:
            preds = sorted({p for (a, p) in by_key if a == s})
            print(f"  {s:<34} {', '.join(preds)}")
        if subjects > 5:
            print(f"  … {subjects - 5} more hosts — `--full` to list every fact")
    for (subj, pred), obs in (sorted(by_key.items()) if args.full else []):
        if is_single_valued(pred):
            cur = current_value(obs)
            mark = " ⚠" if (subj, pred) in disputed else ""
            print(f"  {subj:<34} {pred:<18} {cur['object']:<28} "
                  f"[{cur['confidence']}, {cur['date']}]{mark}")
        else:
            for r in sorted({o["object"]: o for o in obs}.values(),
                            key=lambda x: (CONF_RANK[x["confidence"]], x["date"])):
                print(f"  {subj:<34} {pred:<18} {r['object']:<28} "
                      f"[{r['confidence']}, {r['date']}]")

    if multi:
        layered = [(s, p, v) for (s, p), v in multi.items() if p == "runs"]
        if layered:
            print("\n## Layered stacks — all values true at once, not a contradiction")
            for subj, pred, obs in sorted(layered):
                vals = ", ".join(f"{o['object']} [{o['confidence']}]"
                                 for o in sorted({o["object"]: o for o in obs}.values(),
                                                 key=lambda x: CONF_RANK[x["confidence"]]))
                print(f"  {subj}: {vals}")
            print("  A `reported` banner beside an `observed` framework is normally a proxy in "
                  "front of\n  an origin. Both are facts about different layers — test the origin, "
                  "note the edge.")

    if disputed:
        print("\n## Disagreements — the record contradicts itself, and that is information")
        for (subj, pred), obs in sorted(disputed.items()):
            print(f"  {subj}  {pred}")
            for r in sorted(obs, key=lambda x: x["date"]):
                win = "→" if r is current_value(obs) else " "
                print(f"    {win} {r['date']}  {r['object']:<26} "
                      f"[{r['confidence']}, {r['source']}]")
            confs = {r["confidence"] for r in obs}
            if "reported" in confs and "observed" in confs:
                print("      a reported value lost to an observed one — usually a proxy or CDN "
                      "in front of a different origin. Both are true of different layers.")

    # ---- 2. what changed since ------------------------------------------------
    if args.since:
        fresh = [r for r in rows if r["date"] >= args.since]
        print(f"\n## New since {args.since}   ({len(fresh)})")
        if not fresh:
            print("  nothing")
        for r in fresh:
            print(f"  {r['date']}  {r['subject']:<34} {r['predicate']:<18} {r['object']}")

    # ---- 3. derived views that now predate the evidence ----------------------
    newest = max(r["date"] for r in rows)
    stale, undated = [], []
    for rel in ("recon/technologies.md", "clusters.md", "attack-surface.md"):
        f = tdir / rel
        if not f.exists():
            continue
        m = re.findall(r"(\d{4}-\d{2}-\d{2})", f.read_text(encoding="utf-8-sig", errors="replace"))
        if not m:
            undated.append(rel)              # cannot be checked — say so, never assume current
        elif max(m) < newest:
            stale.append((rel, max(m)))
    if stale or undated:
        print(f"\n## Derived views vs the evidence   (newest observation {newest})")
        for rel, d in stale:
            print(f"  {rel:<28} last dated {d}  — recompute before trusting it")
        for rel in undated:
            print(f"  {rel:<28} NO DATE — staleness cannot be checked. Undated is not current.")
        if stale:
            print("  A ranking computed before these observations is ranking a target that has "
                  "since changed shape.")

    # ---- 4. tech changes invalidate class applicability ----------------------
    tech_changed = [(s, p) for (s, p) in list(disputed) + list(multi) if p == "runs"]
    if tech_changed:
        print("\n## Tech changed — class applicability is now unresolved")
        for subj, pred in tech_changed:
            vals = ", ".join(sorted({o["object"] for o in by_key[(subj, pred)]}))
            print(f"  {subj} now: {vals}")
        print("  Resolve the new stack through playbooks/system/class-signals.md. Classes implied "
              "by the superseded stack may no longer apply, and vice versa — this is not "
              "computed for you, because guessing a tech→class map is how a wrong one gets "
              "trusted.")

    # ---- 4b. the impacted slice — what re-ranking must cover ------------------
    # reassess used to stop at "here is what changed", which left the human to work out which
    # rows were affected. This names them, so the output is an input rather than a paragraph.
    impacted = {}
    surf = tdir / "attack-surface.md"
    surf_text = surf.read_text(encoding="utf-8-sig", errors="replace") if surf.exists() else ""
    for (subj, pred), obs in by_key.items():
        cur = current_value(obs)
        why = None
        if pred == "runs" and args.since and any(
                o["date"] >= args.since and o["confidence"] == "observed" for o in obs):
            seen = ", ".join(sorted({o["object"] for o in obs}))
            why = f"stack now observed as [{seen}] — class applicability unresolved"
        elif pred == "calibration" and cur["object"].strip().lower() == "broken":
            why = "calibration broken — every discovery count on this host is void"
        elif args.since and cur["date"] >= args.since and pred in EDGE_PREDICATES:
            why = f"new {pred} edge to {cur['object']}"
        elif args.since and cur["date"] >= args.since and pred in ("serves", "auth"):
            why = f"new {pred}={cur['object']}"
        if why:
            impacted.setdefault(subj, []).append(why)

    if impacted:
        print(f"\n## Impacted slice — re-rank these, not the whole surface   ({len(impacted)})")
        for subj in sorted(impacted):
            ranked = "in attack-surface.md" if subj in surf_text else "NOT ranked yet"
            print(f"  {subj}   ({ranked})")
            for w in impacted[subj]:
                print(f"      - {w}")
        print("\n  Feed exactly this set to `attack-surface-prioritization`. Re-scoring the\n"
              "  whole estate because three hosts moved is how a re-rank stops being affordable,\n"
              "  and re-scoring nothing is how a stale ranking gets trusted.")
        print("  Rows marked NOT ranked have no entry to update — they need one adding first.")

    # ---- 5. pivots: untested nodes one observed edge from something we know ---
    edges = [r for r in rows if r["predicate"] in EDGE_PREDICATES and r["confidence"] == "observed"]
    known = tested_subjects(tdir)
    if edges:
        pivots = []
        for e in edges:
            a, b = e["subject"], e["object"].strip().lower()
            pairs = ((a, b), (b, a)) if e["predicate"] in SYMMETRIC_EDGES else ((a, b),)
            for src, dst in pairs:
                if src in known and dst not in known:
                    pivots.append((src, e["predicate"], dst, e["date"]))
        seen, uniq = set(), []
        for p in pivots:
            if p[:3] not in seen:
                seen.add(p[:3])
                uniq.append(p)
        print(f"\n## Pivot candidates   ({len(uniq)})")
        if not uniq:
            print("  none — no observed edge leads from a host you have probed to one you "
                  "have not.")
        for src, pred, dst, d in uniq:
            print(f"  {src}  --{pred}-->  {dst}    (untested; edge seen {d})")
        if uniq:
            print("  You already understand the left-hand side. That knowledge transfers — which "
                  "is a better reason to test the right-hand side than its score.")
    print()
    return 0


# ---------------------------------------------------------------- chains

def cmd_chains(args):
    tdir = target_of(args.target)
    rows = read_rows(tdir)
    edges = [r for r in rows if r["predicate"] in EDGE_PREDICATES and r["confidence"] == "observed"]
    if not edges:
        print("  no observed edges recorded — nothing to chain.\n"
              "  Edges come from `javascript-analysis` (references),\n"
              "  `authentication-surface-mapping` (shares-secret), `application-mapping`\n"
              "  (shares-session), `host-correlation-and-clustering` (shares-backend) and\n"
              "  `cross-host-endpoint-reuse` (shares-endpoint), appended with `tools/kb.py add`.")
        return 1

    adj = defaultdict(list)
    for e in edges:
        a, b = e["subject"], e["object"].strip().lower()
        adj[a].append((b, e["predicate"], e["date"]))
        if e["predicate"] in SYMMETRIC_EDGES:
            adj[b].append((a, e["predicate"], e["date"]))   # holds both ways by nature
        # directed edges are NOT reversed: "A's JS names B" is not "B names A", and a token
        # issued by A being accepted by B says nothing about the reverse. Reversing them
        # fabricates reachability that was never observed.

    known = tested_subjects(tdir)
    seen_paths, out = set(), []

    def walk(node, path, preds):
        if len(path) > args.depth:
            return
        for nxt, pred, _ in adj.get(node, []):
            if nxt in path:
                continue
            np, npr = path + [nxt], preds + [pred]
            if len(np) >= 3:                      # a chain is 2+ hops
                key = tuple(np)
                if key not in seen_paths and tuple(reversed(np)) not in seen_paths:
                    seen_paths.add(key)
                    out.append((np, npr))
            walk(nxt, np, npr)

    for start in list(adj):
        walk(start, [start], [])

    print(f"\n# {tdir.name} — chain candidates   (observed edges only, depth ≤ {args.depth})")
    if not out:
        print("  no multi-hop path exists yet. Single edges are in `kb.py reassess` under pivots.")
        return 1

    # a chain ending somewhere untested is the interesting kind
    out.sort(key=lambda x: (x[0][-1] in known, len(x[0])))
    for path, preds in out[:args.limit]:
        arrow = path[0]
        for p, n in zip(preds, path[1:]):
            arrow += f"  --{p}-->  {n}"
        tag = "" if path[-1] in known else "   ← endpoint UNTESTED"
        print(f"  {arrow}{tag}")
    if len(out) > args.limit:
        print(f"  … {len(out) - args.limit} more (raise --limit)")

    print("\n  A chain is a HYPOTHESIS about reachability, not an impact claim. Each hop still "
          "needs\n  its own artifact, and anything crossing a trust boundary needs approval "
          "before you\n  demonstrate it — record it in investigations/<lead>/chain.md.")
    print()
    return 0


# ---------------------------------------------------------------- patterns

NAME_PREFIXES = ("trunk", "stage", "staging", "dev", "test", "qa", "canary", "ha", "internal",
                 "admin", "api", "legacy", "old", "beta", "preprod", "sandbox", "uat")


def _prefix_of(host):
    """The environment family a hostname belongs to, if any.

    Numbering is the norm in real estates — `api1`, `internal2`, `stage-3` — so a trailing index
    is stripped before matching. Without that, `internal1.acme.com` looked like an unrelated
    one-off and a four-host blind spot went unreported.
    """
    first = re.sub(r"[-_]?\d+$", "", host.split(".")[0])
    for p in NAME_PREFIXES:
        if first == p or first.startswith(p + "-") or first.endswith("-" + p):
            return p
    return None


def cmd_patterns(args):
    """Mine the ledger for GENERALISATIONS — the thing a month-long engagement has and a
    five-day one does not.

    Facts accumulate on their own; understanding does not. A hunter three weeks in knows "staging
    here is always under trunk.*" and "every internal API trusts the same header" — statements
    about the *estate*, derived from many observations, that no single observation contains.
    Eyeballing 400 rows will not surface them; counting will.

    Nothing here is written automatically. It proposes candidates with their evidence count; you
    decide which are real and promote them to `target.md`, which IS loaded every session.
    """
    tdir = target_of(args.target)
    rows = read_rows(tdir)
    if not rows:
        print("  no observations yet — patterns need a ledger to generalise from.")
        return 1

    hosts = {r["subject"] for r in rows}
    out = []

    # 1. a value shared by most hosts -> a house style
    for pred in ("runs", "behind", "serves", "auth", "status"):
        vals = defaultdict(set)
        for r in rows:
            if r["predicate"] == pred:
                vals[r["object"].strip()].add(r["subject"])
        seen = {h for s in vals.values() for h in s}
        for val, subj in sorted(vals.items(), key=lambda x: -len(x[1])):
            if len(subj) >= max(3, len(seen) * 0.6) and len(seen) >= 4:
                out.append((len(subj), f"{pred} = {val}",
                            f"{len(subj)}/{len(seen)} hosts with a `{pred}` observation",
                            f"house style — a host that DIVERGES is the interesting one"))

    # 2. a naming prefix that correlates with a property -> a deployment convention
    for pred in ("serves", "auth", "runs", "status"):
        combo = defaultdict(set)
        for r in rows:
            pre = _prefix_of(r["subject"])
            if pre and r["predicate"] == pred:
                combo[(pre, r["object"].strip())].add(r["subject"])
        for (pre, val), subj in sorted(combo.items(), key=lambda x: -len(x[1])):
            if len(subj) >= 3:
                out.append((len(subj), f"{pre}.* → {pred} = {val}",
                            f"{len(subj)} hosts named `{pre}*` share it",
                            "deployment convention — predicts hosts you have NOT found yet"))

    # 3. an edge type that keeps recurring -> a structural relationship
    edges = defaultdict(set)
    for r in rows:
        if r["predicate"] in EDGE_PREDICATES:
            edges[r["predicate"]].add((r["subject"], r["object"]))
    for pred, pairs in sorted(edges.items(), key=lambda x: -len(x[1])):
        if len(pairs) >= 3:
            out.append((len(pairs), f"{pred} recurs",
                        f"{len(pairs)} instances across {len({a for a,_ in pairs})} hosts",
                        "structural — the estate reuses one thing; find the shared component"))

    # 4. a prefix family with no observations at all -> a blind spot, not an absence
    fams = defaultdict(set)
    for h in hosts:
        pre = _prefix_of(h)
        if pre:
            fams[pre].add(h)
    described = {r["subject"] for r in rows if r["predicate"] in ("runs", "serves", "auth")}
    for pre, hs in sorted(fams.items(), key=lambda x: -len(x[1])):
        unknown = hs - described
        if len(hs) >= 3 and len(unknown) >= max(2, len(hs) * 0.5):
            out.append((len(unknown), f"{pre}.* is unmapped",
                        f"{len(unknown)}/{len(hs)} `{pre}*` hosts have no runs/serves/auth",
                        "blind spot — absence of evidence, not evidence of absence"))

    print(f"\n# {tdir.name} — candidate patterns   ({len(rows)} observations, {len(hosts)} hosts)")
    if not out:
        print("\n  nothing generalises yet. Patterns need repetition; keep observing.")
        return 1
    print("\n  These are CANDIDATES, not conclusions. Promote the real ones to target.md —\n"
          "  that file is loaded every session, so it is the only place a generalisation makes\n"
          "  the next session smarter.\n")
    seen_txt = set()
    for n, claim, evidence, why in sorted(out, key=lambda x: -x[0])[:args.limit]:
        if claim in seen_txt:
            continue
        seen_txt.add(claim)
        print(f"  [{n:>3}]  {claim}")
        print(f"         {evidence}")
        print(f"         {why}")
    print("\n  Write the ones you believe into target.md §Patterns with their evidence count and\n"
          "  today's date. A pattern that later breaks is itself a finding — record the exception\n"
          "  rather than deleting the pattern.")
    return 0


# ---------------------------------------------------------------- runs

RUN_COLS = ["run_id", "date", "phase", "selector", "sources", "budget",
            "status", "result", "output_ptr", "limitations", "resume_from", "scope_sha",
            "model"]

# `running` is the one that makes interruption visible. A run logged only on completion cannot
# distinguish "never started" from "traffic was sent and the session died before normalizing" —
# and those demand opposite actions: start it, versus pick up the raw output already on the VPS.
# Re-running a loud phase because the record was missing doubles the traffic for nothing.
RUN_STATES = {"running", "complete-for-this-run", "partial", "failed", "aborted"}
OPEN_STATES = {"running"}
RUNS = "runs.tsv"


def scope_sha(tdir):
    """Short hash of scope.md, stamped on each run. A change between runs is worth surfacing on
    resume — the ranked surface may now list hosts the hunter narrowed out, or a standing constraint
    may have moved — so the next session reconciles it. It is context to reconcile, not an
    authorisation that a diff revokes; scope is the hunter's (AGENTS.md §Scope is the hunter's)."""
    f = Path(tdir) / "scope.md"
    if not f.exists():
        return ""
    return hashlib.sha256(f.read_bytes()).hexdigest()[:12]



def read_runs(tdir):
    f = tdir / RUNS
    if not f.exists():
        return []
    with f.open(encoding="utf-8-sig", newline="") as fh:
        return [{k: (r.get(k) or "").strip() for k in RUN_COLS}
                for r in csv.DictReader(fh, delimiter="\t") if r.get("phase")]


_RUN_ID_RE = re.compile(r"^R-\d+$")


def _cell(s, limit=160):
    """One runs.tsv value as one markdown table cell."""
    s = " ".join((s or "").split())
    if not s:
        return "—"
    if len(s) > limit:
        s = s[:limit - 1].rstrip() + "…"
    return s.replace("|", "\\|")



def render_progress(tdir):
    """Refresh the generated hunter view when a run reaches a terminal state."""
    try:
        import importlib
        progress = importlib.import_module("progress")
        page = progress.render(tdir)
        (tdir / "progress.md").write_text(page, encoding="utf-8")
        return "progress.md regenerated"
    except Exception as exc:                                   # noqa: BLE001 - run record wins
        return (f"progress.md NOT regenerated ({exc.__class__.__name__}: {exc}) — "
                f"run tools/progress.py {tdir} by hand")


def _default_model():
    """The model/tier stamped on a run when --model was not passed: config `runtime.model`,
    env-overridable as BBW_RUNTIME_MODEL. Metadata, never a gate — unset stays empty ('—' in
    displays), so a missing value degrades the audit, never the run."""
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import config
        v = config.load().get("runtime.model")
        return str(v).strip() if v else ""
    except (SystemExit, Exception):                               # noqa: BLE001
        return ""


def _migrate_runs_header(f):
    """Older brains predate the `model` column. Rewrite ONLY the header line so the whole file
    shares one schema; short rows still parse (DictReader + `.get` reads them as model='')."""
    text = f.read_text(encoding="utf-8-sig")
    lines = text.splitlines()
    if not lines or "model" in [c.strip() for c in lines[0].split("\t")]:
        return
    lines[0] = lines[0].rstrip("\n") + "\tmodel"
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")


def cmd_run(args):
    """Record one BOUNDED run. There is no such thing as a phase being globally done."""
    tdir = target_of(args.target)
    if not args.finish and not (args.phase and args.selector):
        die("--phase and --selector are required when opening a run "
            "(omit them only with --finish)")
    if args.status not in RUN_STATES:
        die(f"--status must be one of: {', '.join(sorted(RUN_STATES))}. "
            f"Note there is no 'done': a run completes for its selector and sources, "
            f"not for all time.")
    existing = read_runs(tdir)
    if args.finish:
        open_rows = [r for r in existing if r["run_id"] == args.finish]
        if not open_rows:
            die(f"no run {args.finish} in runs.tsv")
        prior = open_rows[-1]
        rid = args.finish
        row = dict(prior)
        row.update({"date": args.date or date.today().isoformat(), "status": args.status,
                    "result": args.result or prior["result"],
                    "output_ptr": args.output or prior["output_ptr"],
                    "limitations": args.limitations or prior["limitations"],
                    "resume_from": args.resume_from or "",
                    "model": getattr(args, "model", "") or prior.get("model", "")})
    else:
        # Next id from the highest id ALREADY USED, not from the row count. A run writes one row
        # when it opens and another when it closes, so `len(existing) + 1` burned an id per
        # completed run — which is why a ledger of four runs read R-001, R-003, R-005, R-009 and
        # looked like three runs had been lost.
        used = [int(m.group(1)) for r in existing
                if (m := re.fullmatch(r"R-(\d+)", r.get("run_id", "").strip()))]
        rid = f"R-{(max(used) + 1) if used else 1:03d}"
        row = {"run_id": rid, "date": args.date or date.today().isoformat(),
               "phase": args.phase, "selector": args.selector,
               "sources": args.sources or "unstated", "budget": args.budget or "",
               "status": args.status, "result": args.result or "",
               "output_ptr": args.output or "", "limitations": args.limitations or "",
               "resume_from": args.resume_from or "",
               "scope_sha": scope_sha(tdir),
               "model": getattr(args, "model", "") or _default_model()}
    f = tdir / RUNS
    if f.exists():
        _migrate_runs_header(f)
    new = not f.exists()
    with f.open("a", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=RUN_COLS, delimiter="\t", lineterminator="\n")
        if new:
            w.writeheader()
        w.writerow(row)
    print(f"  {rid}  {row['phase']}  selector={row['selector']}  [{args.status}]"
          + (f"  model={row['model']}" if row.get("model") else ""))
    # A run that is still `running` has changed nothing worth re-rendering; every terminal status
    # ends a phase and must leave the derived view current. The live console needs no re-render —
    # it recomputes on request — so only progress.md regenerates here.
    if args.status != "running":
        print(f"  {render_progress(tdir)}")
    if args.status == "running":
        print("  Logged BEFORE the work. If this session dies, the next one sees an interrupted run\n"
              "  instead of nothing. Close it with:  kb.py run <t> --finish " + rid +
              " --status … --resume-from …")
    if not args.limitations:
        print("  note: no --limitations recorded. What this run did NOT cover is the part a "
              "future\n        reader cannot reconstruct — say 'passive sources only', "
              "'top 500 hosts', or 'none'.")
    return 0


def cmd_runs(args):
    tdir = target_of(args.target)
    runs = read_runs(tdir)
    if not runs:
        print(f"  no runs recorded. Every bounded run should be logged with `kb.py run` —\n"
              f"  without it, 'subdomain-enumeration' reads as 'subdomain discovery is "
              f"finished', which it "
              f"never is.")
        return 1
    print(f"\n# {tdir.name} — bounded runs ({len(runs)})")

    # An interrupted run is the single most actionable thing in this file, so it goes first
    # and it goes loud. Anything else buries it under history.
    latest = {}
    for r in runs:
        latest[r["run_id"]] = r
    open_runs = [r for r in latest.values() if r["status"] in OPEN_STATES]
    unfinished = [r for r in latest.values()
                  if r["status"] in ("partial", "failed") and r["resume_from"]]
    if open_runs or unfinished:
        print("\n  ⚠ UNFINISHED WORK — pick this up before starting anything new")
        for r in open_runs:
            print(f"    {r['run_id']}  {r['phase']}  on {r['selector']}  [{r['status']}]")
            print(f"          left RUNNING — the session ended before it was closed. Traffic may")
            print(f"          already have been sent; check the VPS before re-running it.")
            if r["resume_from"]:
                print(f"          resume from: {r['resume_from']}")
        for r in unfinished:
            print(f"    {r['run_id']}  {r['phase']}  on {r['selector']}  [{r['status']}]")
            print(f"          resume from: {r['resume_from']}")

    print()
    by_phase = defaultdict(list)
    for r in latest.values():
        by_phase[r["phase"]].append(r)
    for phase in sorted(by_phase):
        for r in by_phase[phase]:
            print(f"  {r['run_id']}  {r['date']}  {r['phase']}")
            print(f"          selector: {r['selector'] or '—'}   sources: {r['sources']}")
            print(f"          {r['status']}"
                  + (f" · {r['model']}" if r.get("model") else "")
                  + (f" · {r['result']}" if r["result"] else ""))
            if r["limitations"]:
                print(f"          not covered: {r['limitations']}")
            if r["resume_from"]:
                print(f"          resume from: {r['resume_from']}")
    by_model = defaultdict(int)
    for r in latest.values():
        by_model[r.get("model") or "—"] += 1
    if any(r.get("model") for r in latest.values()):
        print("\n  by model: " + " · ".join(
            f"{m} {n}" for m, n in sorted(by_model.items(), key=lambda kv: -kv[1]))
            + "   (cheap tier does the volume, strong tier the judgment — measure, don't assume)")
    stale = [r for r in runs if age_of(r["date"]) is not None and age_of(r["date"]) > 14]
    if stale:
        print(f"\n  {len(stale)} run(s) older than 14 days. State the age before you rely on "
              f"their output.")
    print("\n  A run is complete for its selector, its sources and its date — never for the "
          "phase.\n  New roots, new sources, or a changed target all make the same phase "
          "worth re-running.\n")
    return 0


def age_of(d):
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", d or "")
    if not m:
        return None
    try:
        return (date.today() - date(*map(int, m.groups()))).days
    except ValueError:
        return None


def calibration_of(tdir):
    """Structured calibration state per host, or None. Never inferred from prose.

    Uses `current_value` so provenance beats recency here exactly as it does everywhere else: a
    newer `inferred` guess must not overturn an `observed` result backed by an artifact. The
    earlier hand-rolled comparison here compared one row's date against another's *confidence*,
    which reduced to "newest wins" and silently discarded the stronger evidence.
    """
    rows = [r for r in read_rows(tdir) if r["predicate"] == "calibration"]
    if not rows:
        return None
    by_host = defaultdict(list)
    for r in rows:
        by_host[r["subject"]].append(r)
    return {h: current_value(obs) for h, obs in by_host.items()}


# ---------------------------------------------------------------- cohort

def _ver(s):
    m = re.search(r"(\d+(?:\.\d+){0,3})", s or "")
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def _cmp_ver(a, b):
    a = a + (0,) * (4 - len(a))
    b = b + (0,) * (4 - len(b))
    return (a > b) - (a < b)


def components_from_table(tdir):
    """recon/components.md — `component-inventory`'s versioned inventory.

    This is the table `--version-lt` was written for. The `technology-fingerprinting` fingerprint
    has no version column,
    so before this existed the cohort selector could only match versions that happened to be
    embedded in an observation's free-text object. A row here with precision `unknown` is skipped
    deliberately: selecting a cohort on a guessed version sends traffic to hosts that were never
    affected.
    """
    f = tdir / "recon" / "components.md"
    if not f.exists():
        return []
    out = []
    for r in table_rows(f.read_text(encoding="utf-8-sig", errors="replace")):
        if len(r) < 4 or not r[0] or r[0].startswith("<") or r[0].startswith("&lt;"):
            continue
        host = re.sub(r"[`*]", "", r[0]).strip().lower()
        comp = re.sub(r"[`*]", "", r[1]).strip()
        ver = re.sub(r"[`*]", "", r[2]).strip()
        prec = re.sub(r"[`*]", "", r[3]).strip().lower()
        if not host or not comp:
            continue
        if prec == "unknown" or ver in ("", "—", "-", "unknown"):
            # Emit it WITHOUT a version rather than dropping it. It must not join a
            # version-filtered cohort — but silently vanishing is worse: the host is then neither
            # selected nor cleared, and nobody knows it was set aside.
            out.append({"subject": host, "object": comp, "confidence": "inferred",
                        "source": "recon/components.md (version unknown)", "date": "",
                        "predicate": "runs"})
            continue
        conf = "reported"
        if len(r) > 6 and r[6].strip().lower() in CONF_RANK:
            conf = r[6].strip().lower()
        out.append({"subject": host, "object": f"{comp} {ver}", "confidence": conf,
                    "source": "recon/components.md", "date": "", "predicate": "runs"})
    return out


def tech_from_table(tdir):
    """recon/technologies.md — `technology-fingerprinting`'s bulk output. Weaker than the ledger."""
    f = tdir / "recon" / "technologies.md"
    if not f.exists():
        return []
    out = []
    for r in table_rows(f.read_text(encoding="utf-8-sig", errors="replace")):
        if len(r) < 2 or not r[0] or r[0].startswith("<"):
            continue
        host = re.sub(r"[`*]", "", r[0]).strip().lower()
        for cell in r[1:]:
            cell = re.sub(r"[`*]", "", cell).strip()
            if cell and cell not in ("—", "-"):
                out.append({"subject": host, "object": cell, "confidence": "reported",
                            "source": "recon/technologies.md", "date": "", "predicate": "runs"})
    return out


def cmd_cohort(args):
    tdir = target_of(args.target)
    rows = [r for r in read_rows(tdir) if r["predicate"] in ("runs", "behind")]
    table = (components_from_table(tdir) + tech_from_table(tdir)) if not args.ledger_only else []
    if not rows and not table:
        print("  no tech data. Run `technology-fingerprinting` for the fingerprint and "
              "`component-inventory` for versioned "
              "components, or import traffic, or record observations with "
              "`kb.py add --predicate runs`.")
        return 1

    needle = args.tech.lower()
    hits = {}
    for r in rows + table:
        if needle not in r["object"].lower():
            continue
        host = r["subject"]
        prev = hits.get(host)
        if prev is None or CONF_RANK[r["confidence"]] < CONF_RANK[prev["confidence"]]:
            hits[host] = r

    if args.min_confidence:
        cap = CONF_RANK[args.min_confidence]
        hits = {h: r for h, r in hits.items() if CONF_RANK[r["confidence"]] <= cap}

    unversioned = []
    if args.version_lt:
        want = _ver(args.version_lt)
        if not want:
            die(f"--version-lt '{args.version_lt}' has no parseable version")
        keep = {}
        for h, r in hits.items():
            v = _ver(r["object"])
            if v is None:
                unversioned.append((h, r))
            elif _cmp_ver(v, want) < 0:
                keep[h] = r
        hits = keep

    print(f"\n# cohort — {args.tech}"
          + (f" < {args.version_lt}" if args.version_lt else "")
          + f"   ({len(hits)} host(s))")
    for h, r in sorted(hits.items()):
        src = r["source"] or "?"
        print(f"  {h:<44} {r['object']:<28} [{r['confidence']}, {src}]")

    if unversioned:
        print(f"\n  ⚠ {len(unversioned)} host(s) match the tech but carry NO VERSION — excluded "
              f"from a version-filtered cohort:")
        for h, r in sorted(unversioned)[:10]:
            print(f"      {h:<42} {r['object']}")
        print("    Unversioned is not 'not vulnerable'. Fingerprint them before you write them off.")

    weak = [h for h, r in hits.items() if r["confidence"] != "observed"]
    if weak:
        print(f"\n  {len(weak)} of {len(hits)} rest on `reported` or `inferred` evidence — a banner, "
              f"not behaviour.\n  Banners are set by proxies and can be wrong in both directions.")

    if args.out and hits:
        Path(args.out).write_text("\n".join(sorted(hits)) + "\n", encoding="utf-8")
        print(f"\n  wrote {args.out}  ({len(hits)} hosts)")
    print()
    return 0 if hits else 1


# ---------------------------------------------------------------- vocab

def cmd_vocab(_args):
    print("\n  node predicates — facts about one subject")
    for k, v in NODE_PREDICATES.items():
        print(f"    {k:<19} {v}")
    print("\n  edge predicates — subject and object are both hosts")
    for k, v in EDGE_PREDICATES.items():
        print(f"    {k:<19} {v}")
    print("\n  confidence — provenance, strongest first")
    print("    observed            you saw the behaviour; an artifact is stored (--evidence required)")
    print("    reported            the target said so (Server:, X-Powered-By:) — headers lie")
    print("    inferred            similarity, fingerprint, heuristic\n")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="append one observation")
    a.add_argument("target")
    a.add_argument("--subject", required=True, help="host the fact is about")
    a.add_argument("--predicate", required=True, help="see `vocab`")
    a.add_argument("--object", required=True, help="the value, or the other host for an edge")
    a.add_argument("--confidence", default="inferred", choices=CONFIDENCE)
    a.add_argument("--source", help="skill or workflow that saw it, e.g. application-mapping")
    a.add_argument("--evidence", help="artifact path; REQUIRED for --confidence observed")
    a.add_argument("--date", help="ISO date; defaults to today")
    a.set_defaults(fn=cmd_add)

    s = sub.add_parser("show", help="list observations")
    s.add_argument("target")
    s.add_argument("--subject")
    s.add_argument("--predicate")
    s.set_defaults(fn=cmd_show)

    r = sub.add_parser("reassess", help="current + new = updated; what it changes")
    r.add_argument("target")
    r.add_argument("--since", metavar="YYYY-MM-DD")
    r.add_argument("--full", action="store_true",
                   help="list every fact; the default summarises so output does not grow with "
                        "the ledger")
    r.set_defaults(fn=cmd_reassess)

    c = sub.add_parser("chains", help="multi-host paths through observed edges")
    c.add_argument("target")
    c.add_argument("--depth", type=int, default=3)
    c.add_argument("--limit", type=int, default=25)
    c.set_defaults(fn=cmd_chains)

    rn = sub.add_parser("run", help="record one BOUNDED run (there is no globally 'done' phase)")
    rn.add_argument("target")
    rn.add_argument("--skill", "--phase", dest="phase",
                    help="the skill this run belongs to, e.g. subdomain-enumeration")
    rn.add_argument("--selector", help="what it covered: apex, host list, cluster")
    rn.add_argument("--sources", help="tools / APIs used — a run is only complete for these")
    rn.add_argument("--budget", help="requests / rate / time bound")
    rn.add_argument("--status", required=True,
                    choices=sorted(RUN_STATES), help="no 'done' — a run completes for its selector")
    rn.add_argument("--result", help="one line: what came back")
    rn.add_argument("--output", help="pointer to the raw output")
    rn.add_argument("--limitations", help="what this run did NOT cover")
    rn.add_argument("--resume-from", dest="resume_from",
                    help="exact state to pick up from if this was interrupted, e.g. "
                         "'openapi.json downloaded; endpoint normalisation not started'")
    rn.add_argument("--finish", metavar="RUN_ID",
                    help="close an earlier `running` row instead of opening a new one")
    rn.add_argument("--model", metavar="NAME",
                    help="model/tier that ran this unit (e.g. deepseek-v4, glm). Default: "
                         "config runtime.model / BBW_RUNTIME_MODEL. Metadata for the audit — "
                         "'which tier found what' — never a gate.")
    rn.add_argument("--date")
    rn.set_defaults(fn=cmd_run)

    pt = sub.add_parser("patterns", help="generalisations across the ledger — what a long "
                                          "engagement knows that a short one cannot")
    pt.add_argument("target")
    pt.add_argument("--limit", type=int, default=12)
    pt.set_defaults(fn=cmd_patterns)

    rs = sub.add_parser("runs", help="every bounded run, with its selector and limits")
    rs.add_argument("target")
    rs.set_defaults(fn=cmd_runs)

    co = sub.add_parser("cohort", help="hosts running a given technology")
    co.add_argument("target")
    co.add_argument("--tech", required=True, help="substring, e.g. rails · log4j · struts")
    co.add_argument("--version-lt", metavar="V", help="keep only versions below V")
    co.add_argument("--min-confidence", choices=CONFIDENCE,
                    help="observed = behaviour seen; reported = a banner said so")
    co.add_argument("--ledger-only", action="store_true",
                    help="ignore recon/technologies.md; use observations.tsv alone")
    co.add_argument("--out", metavar="FILE", help="write the host list for tools/sweep.py")
    co.set_defaults(fn=cmd_cohort)

    v = sub.add_parser("vocab", help="the closed predicate vocabulary")
    v.set_defaults(fn=cmd_vocab)

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(runlog.wrap()(main)())
