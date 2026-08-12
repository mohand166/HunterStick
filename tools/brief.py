#!/usr/bin/env python3
"""The session brief — run this first, on any runtime.

    tools/brief.py                 # every target: phase, blockers, what is missing
    tools/brief.py <target>        # one target in detail
    tools/brief.py --rules         # + AGENTS.md verbatim, for a cold runtime

Why this exists: on Claude Code, AGENTS.md auto-loads. Everywhere else the first message is cold,
and pasting the whole brain costs thousands of tokens before you have said hello. This prints a
small snapshot from the target files. index.md holds decisions, not counts — ask coverage.py or kb.py runs
when verified counts matter.

It reads only small files (index.md, scope.md, accounts.md, TARGETS.md) and never opens
config.json, which holds secrets. The one remote exception is `<target> --resume`: it checks the
named target's monitor status so an unattended delta or quarantined run cannot remain invisible.

Exit: 0 always unless the workspace itself is unreadable (2). This is a report, not a gate.
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import skilllib  # noqa: E402
from scopelib import parse_scope                                  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TARGETS = ROOT / "targets"
SKIP = {"_template"}


def resume_skill(raw):
    """Translate a historical run name to the CURRENT skill slug to LOAD.

    `runs.tsv` records what was run at the time — `02-subdomain-enumeration`, `phase-07`, whatever
    the identity scheme was that week. Resume must not tell a fresh model to "load the
    02-subdomain-enumeration playbook": that file was deleted in the slug migration. Strip any
    numeric prefix, and verify the result is a real skill on disk before naming it. If it does not
    resolve, say so loudly rather than pointing at a ghost — a wrong load target is worse than
    none, because the model acts on it.
    """
    if not raw:
        return None, None
    slug = re.sub(r"^(?:phase[-_]?)?\d+[-_]?", "", str(raw).strip()).strip("-_ ")
    try:
        path = skilllib.resolve(slug)
    except (KeyError, ValueError):
        return slug, None
    if skilllib.skill_name(path) == slug:
        return slug, skilllib.relative(path)
    return slug, None


def read(p):
    try:
        return p.read_text(encoding="utf-8-sig", errors="replace")
    except Exception:
        return ""


def field(text, label):
    """Pull `- **Label:** value` out of an index.md Status block."""
    m = re.search(rf"^\s*-\s*\*\*{re.escape(label)}:?\*\*\s*(.+?)\s*$", text, re.M)
    if not m:
        return None
    v = re.sub(r"`", "", m.group(1)).strip()
    return None if not v or v.startswith("<") else v


def blockers(text):
    """Every 'TBD — blocking: X' plus anything under a Blocking/TBD heading.

    Template placeholders are NOT blockers. `- <every `TBD — blocking: X` left by init …>` is
    instructions to the author; reporting it makes every fresh target look blocked on nothing.
    A line is a placeholder if the match sits inside <angle brackets> or backticks.
    """
    out = []
    for m in re.finditer(r"TBD\s*—\s*blocking:[^\n|]*", text):
        line = text[text.rfind("\n", 0, m.start()) + 1: text.find("\n", m.start()) % (len(text) + 1)]
        stripped = line.strip().lstrip("-*").strip()
        if stripped.startswith("<") or stripped.startswith("`"):
            continue
        out.append(m.group(0).strip().rstrip("`>"))
    sec = re.search(r"^##+\s*Blocking\s*/?\s*TBD.*?$(.*?)(?=^##|\Z)", text, re.M | re.S)
    if sec:
        for line in sec.group(1).splitlines():
            line = line.strip(" -*\t")
            if line and not line.startswith("<") and "TBD — blocking" not in line:
                out.append(line)
    return out


def counts_table(text):
    """The data-files table: return [(path, count)] so we can show what is missing."""
    rows = []
    for m in re.finditer(r"^\|\s*`([^`]+)`\s*\|[^|]*\|\s*([^|]+?)\s*\|", text, re.M):
        rows.append((m.group(1), m.group(2).strip()))
    return rows


def account_rows(accounts_text):
    """Return account rows keyed by normalized table headers."""
    headers = None
    rows = []
    for line in accounts_text.splitlines():
        if not line.lstrip().startswith("|"):
            if headers and rows:
                break
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        normalized = [re.sub(r"[*`]", "", cell).strip().lower() for cell in cells]
        if "label" in normalized and "role" in normalized:
            headers = normalized
            continue
        if headers and not all(re.fullmatch(r":?-{2,}:?", cell) for cell in cells):
            rows.append(dict(zip(headers, cells)))
    return rows


def is_resolvable_reference(reference):
    normalized = re.sub(r"[*`]", "", reference).strip()
    return bool(
        normalized
        and "<" not in normalized
        and ">" not in normalized
        and normalized not in {"—", "-"}
    )


def accounts_state(target):
    accounts_text = read(target / "accounts.md")
    if not accounts_text:
        return "no accounts.md"
    ready_count = 0
    for row in account_rows(accounts_text):
        status = row.get("status", "").strip().lower()
        credential = row.get("credential_ref", row.get("password", ""))
        if status == "ready" and is_resolvable_reference(credential):
            ready_count += 1
    if ready_count >= 2:
        return f"{ready_count} principals — two-principal work is possible"
    if ready_count == 1:
        return "1 principal — authz/IDOR/tenant/privesc is blocked (needs 2)"
    # Not "blocked" — nothing here stops you asking for IDOR. It says what a two-principal
    # test cannot demonstrate without a second account, so the answer arrives before the work.
    # "none" alone hides the only thing that matters: whether one can be OBTAINED. A target with
    # open signup and a target with no way in are the same word and completely different work.
    policy = ""
    m = re.search(r"^- \*\*Policy:\*\*\s*(.+)$", accounts_text, re.M)
    if m:
        first = re.sub(r"`|\*\*", "", m.group(1)).strip()
        policy = f" · policy: {first[:120]}"
    return ("none held — a differential authz test (idor-bola, function-level-authorization, "
            "multi-tenant-isolation, privilege-escalation) needs 2" + policy)


def monitor_attention(status_output):
    """Parse the stable attention fields printed by monitor.py status."""
    pending_match = re.search(r"^\s*pending\s+(\d+)\s+unreviewed", status_output, re.M)
    snapshot_match = re.search(
        r"^\s*snapshots\s+\d+\s+good\s+·\s+(\d+)\s+quarantined", status_output, re.M)
    pending = int(pending_match.group(1)) if pending_match else 0
    quarantined = int(snapshot_match.group(1)) if snapshot_match else 0
    recent_failure = bool(re.search(r"^\s*\S.*\bFAIL\b", status_output, re.M))
    if not (pending or quarantined or recent_failure):
        return None
    return {"pending": pending, "quarantined": quarantined,
            "recent_failure": recent_failure}


def monitor_resume_state(target):
    """Return monitor attention counts, or why the remote state could not be checked."""
    command = [sys.executable, str(ROOT / "tools" / "monitor.py"), "status", str(target)]
    try:
        status = subprocess.run(command, capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        return {"check_error": "status check timed out"}
    if status.returncode == 0:
        return monitor_attention(status.stdout)
    if "vps.enabled is false" in status.stderr:
        return None
    return {"check_error": f"status command exited {status.returncode}"}


def print_monitor_notice(target_name, monitor_state):
    """Render attention without reviewing or clearing the pending delta."""
    if monitor_state.get("check_error"):
        print("\n## ⚠ Monitor status unknown")
        print(f"  {monitor_state['check_error']}; pending deltas could not be checked.")
    else:
        print("\n## ⚠ Monitor needs attention")
        if monitor_state["pending"]:
            print(f"  {monitor_state['pending']} unreviewed delta block(s) are waiting on the "
                  "VPS.")
        if monitor_state["quarantined"]:
            print(f"  {monitor_state['quarantined']} run(s) were quarantined and were not "
                  "diffed.")
        if monitor_state["recent_failure"]:
            print("  The recent monitor log contains FAIL.")
        print(f"  Review: tools/monitor.py pending targets/{target_name}")
        print("  Nothing was processed or cleared automatically.")
    print(f"  Diagnose: tools/monitor.py status targets/{target_name}")


def target_names():
    if not TARGETS.is_dir():
        print(f"FAIL — no {TARGETS.relative_to(ROOT)}/ directory.", file=sys.stderr)
        raise SystemExit(2)
    return sorted(p.name for p in TARGETS.iterdir()
                  if p.is_dir() and p.name not in SKIP and (p / "index.md").exists())


def line_one(name):
    t = TARGETS / name
    idx = read(t / "index.md")
    def clip(s, n):
        s = re.sub(r"\*\*|`", "", s or "")
        return (s[: n - 1] + "…") if len(s) > n else s
    phase = clip(field(idx, "Last activity") or field(idx, "Current phase") or "—", 42)
    arch = clip(field(idx, "Archetype") or field(idx, "Scope type") or "?", 16)
    upd = clip(field(idx, "Last updated") or "?", 12)
    b = blockers(idx)
    print(f"  {name:<12} {arch:<16} {phase:<42} {upd}")
    if b:
        print(f"  {'':<14} ⚠ {len(b)} blocker(s): {b[0][:70]}")


def detail(name):
    t = TARGETS / name
    idx = read(t / "index.md")
    print(f"\n## {name}")
    for lbl in ("Program", "Archetype", "Scope type", "Last activity", "Suggested next",
                "Current phase", "Last updated"):
        v = field(idx, lbl)
        if v:
            print(f"   {lbl+':':<16} {v}")
    print(f"   {'Accounts:':<16} {accounts_state(t)}")

    # Use the ONE parser. This used to regex the verbatim-statement section instead, so a target
    # whose statement was a company name ("Example Corp.") reported "prose only" while every
    # enforcing tool was happily matching the derived allowlist. The brief is the first thing
    # anyone reads; it must not disagree with what the tools will actually permit.
    parsed = parse_scope(t)
    if parsed["state"] == "ok":
        shown = [("*." if w else "") + d for w, d in parsed["in_scope"]]
        line = ", ".join(shown[:6]) + (" …" if len(shown) > 6 else "")
        excl = parsed["out_of_scope"]
        line += f"   ({len(excl)} exclusion(s))" if excl else "   (exclusions: none stated \u2260 none)"
        print(f"   {'In scope:':<16} {line}")
    else:
        print(f"   {'In scope:':<16} {parsed['detail'].splitlines()[0]}")

    rows = counts_table(idx)
    if rows:
        have = [(p, c) for p, c in rows if c not in ("missing", "0", "—", "")]
        miss = [p for p, c in rows if c == "missing"]
        print(f"   {'Have:':<16} " + (", ".join(f"{p.split('/')[-1]}={c}" for p, c in have[:8]) or "nothing yet"))
        if miss:
            print(f"   {'Missing:':<16} " + ", ".join(m.split('/')[-1] for m in miss))
            print(f"   {'':<16} a phase that needs one of these must FAIL its preflight, not run empty.")

    b = blockers(idx)
    if b:
        print("   Blocking:")
        for x in b:
            print(f"      - {x}")




def resume(name):
    """Reconstruct a session from the files — never from chat history.

    Chat history is the wrong source: it holds abandoned reasoning, target-controlled text and
    credentials, and none of it is verified. Everything below is read from canonical files, so a
    different model on a different runtime reconstructs the same picture.

    Budget is ~1.5k tokens. If this grows past that it stops being a resume and becomes the thing
    you were trying to avoid re-reading.
    """
    sys.path.insert(0, str(ROOT / "tools"))
    from kb import read_runs, read_rows, scope_sha, OPEN_STATES     # noqa: E402
    t = TARGETS / name
    idx = read(t / "index.md")

    print(f"\n# Resume — {name}")

    # ---- scope: a change worth surfacing, not a veto -------------------------
    runs = read_runs(t)
    prior = [r["scope_sha"] for r in runs if r.get("scope_sha")]
    now = scope_sha(t)
    if prior and prior[-1] and prior[-1] != now:
        print("\n## ⚠ SCOPE CHANGED since the last recorded run")
        print("  Re-read scope.md before relying on the ranked surface — it may now list hosts the")
        print("  hunter narrowed out, and standing constraints may have moved. This is context to")
        print("  reconcile, not a stop; the hunter decides what that means for the work.")
    elif prior:
        print(f"\n## Scope   unchanged since {runs[-1]['date']} (sha {now})")
    else:
        print(f"\n## Scope   sha {now} — no prior run to compare against")

    scope = read(t / "scope.md")
    dec = [l for l in scope.splitlines()
           if l.startswith("|") and not l.startswith("| date") and "---" not in l
           and not l.strip().startswith("| <")]
    if dec:
        print("\n## Standing decisions — these bind you")
        for l in dec[:6]:
            cells = [c.strip() for c in l.strip().strip("|").split("|")]
            if len(cells) >= 2 and cells[1]:
                print(f"  {cells[0]}  {cells[1]}")

    # ---- unfinished work: the reason this command exists ---------------------
    latest = {}
    for r in runs:
        latest[r["run_id"]] = r
    openr = [r for r in latest.values() if r["status"] in OPEN_STATES]
    partial = [r for r in latest.values()
               if r["status"] in ("partial", "failed") and r.get("resume_from")]
    if openr or partial:
        print("\n## Unfinished — pick this up before starting anything new")
        for r in openr:
            print(f"  {r['run_id']} {r['phase']} on {r['selector']} — left RUNNING.")
            print(f"     Traffic may already have been sent. Check the VPS before re-running.")
            if r.get("resume_from"):
                print(f"     resume from: {r['resume_from']}")
        for r in partial:
            print(f"  {r['run_id']} {r['phase']} on {r['selector']} [{r['status']}]")
            print(f"     resume from: {r['resume_from']}")
    else:
        print("\n## Unfinished   none — every run was closed")

    done = [r for r in latest.values() if r["status"] == "complete-for-this-run"]
    if done:
        print(f"\n## Last completed   ({len(done)} total)")
        for r in done[-3:]:
            print(f"  {r['run_id']} {r['date']} {r['phase']} on {r['selector']}"
                  + (f" — {r['result']}" if r["result"] else ""))
            if r["limitations"]:
                print(f"     not covered: {r['limitations']}")

    monitor_state = monitor_resume_state(t)
    if monitor_state:
        print_monitor_notice(name, monitor_state)

    # ---- stale foundations ---------------------------------------------------
    stale = []
    for rel, label in (("recon/live-hosts.txt", "live hosts"),
                       ("recon/technologies.md", "technologies"),
                       ("attack-surface.md", "attack-surface ranking")):
        f = t / rel
        if not f.exists():
            continue
        ds = re.findall(r"(\d{4}-\d{2}-\d{2})", read(f))
        src = max(ds) if ds else None
        rp = [r["date"] for r in runs if rel.split("/")[-1].split(".")[0] in r["phase"]]
        d = src or (max(rp) if rp else None)
        if d:
            a = age(d)
            if a is not None and a > 14:
                stale.append(f"{label}: {a} days old")
    if stale:
        print("\n## Stale foundations   state the age before relying on these")
        for s in stale:
            print(f"  {s}")

    # ---- open leads ----------------------------------------------------------
    hyp = read(t / "hypotheses.md")
    openh = [l for l in hyp.splitlines()
             if l.startswith("|") and "| open" in l.replace("|open", "| open")]
    if openh:
        print(f"\n## Open leads   ({len(openh)})")
        for l in openh[:4]:
            c = [x.strip() for x in l.strip().strip("|").split("|")]
            if len(c) >= 4:
                print(f"  {c[0]}  {c[1][:52]}  [{c[2]}]")

    # a tool that failed and went unmentioned is the failure this project exists to prevent
    try:
        from runlog import read_log                                   # noqa: E402
        bad = [r for r in read_log(t) if r["exit"] not in ("0", "")]
        if bad:
            print(f"\n## ⚠ {len(bad)} tool invocation(s) exited non-zero")
            for r in bad[-3:]:
                print(f"  {r['ts'][:16]}  exit={r['exit']}  {r['tool']}  {r['argv'][:44]}")
            print("  Whatever depended on these may have been written anyway. "
                  "`tools/runlog.py <t> --failures`")
    except Exception:
        pass

    print(f"\n## Coverage")
    print(f"   {accounts_state(t)}")
    print("   run `tools/coverage.py targets/%s` for untested cells" % name)

    # ---- the read set --------------------------------------------------------
    need = ["scope.md", "index.md"]
    if openr or partial:
        r = (openr + partial)[0]
        slug, path = resume_skill(r.get("phase"))
        if path:
            need.append(path)
        elif slug:
            need.append(f"⚠ run recorded as '{r['phase']}' → no current skill '{slug}.md'; "
                        f"pick the closest in skills/ — do NOT load the old name")
        if r.get("output_ptr"):
            need.append(r["output_ptr"])
    if openh:
        need.append("hypotheses.md")
    print("\n## Load these — and nothing else yet")
    for n in need:
        print(f"  {n}")
    print("\n## Do NOT load")
    print("  the other recon skills · the full observations ledger · unrelated applications")
    print()
    return 0


def age(d):
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", d or "")
    if not m:
        return None
    from datetime import date as _d
    try:
        return (_d.today() - _d(*map(int, m.groups()))).days
    except ValueError:
        return None



def print_canonical():
    """Print AGENTS.md itself — never a summary of it.

    This used to be a hand-maintained copy of the rules and the router. It drifted exactly as you
    would expect: five router entries against the canonical eight, and none of the rules added
    after it was written. The whole reason CLAUDE.md is a pointer is that a second copy always
    rots, so this prints the file rather than paraphrasing it.
    """
    f = ROOT / "AGENTS.md"
    if not f.exists():
        print("FAIL — AGENTS.md is missing. It is the canonical instruction set; without it this\n"
              "       workspace has no rules to follow.", file=sys.stderr)
        raise SystemExit(2)
    print("\n" + "=" * 78)
    print("AGENTS.md — canonical instructions. On a runtime that does not read it automatically,\n"
          "paste everything below as your first message.")
    print("=" * 78 + "\n")
    print(f.read_text(encoding="utf-8-sig").rstrip())


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", nargs="?", help="one target; omit for all")
    ap.add_argument("--resume", action="store_true",
                    help="reconstruct a session from the files: unfinished work, standing "
                         "decisions, stale inputs, and the exact read set")
    ap.add_argument("--rules", action="store_true", help="also print the rules and router")
    args = ap.parse_args()

    names = target_names()
    print("# session brief")

    # config presence, without ever reading config.json
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "config.py"), "check"],
                       capture_output=True, text=True)
    tail = [l for l in r.stdout.splitlines() if "set ·" in l]
    print(f"  config    {tail[0].strip() if tail else 'tools/config.py check failed — run it'}")
    vps = subprocess.run([sys.executable, str(ROOT / "tools" / "config.py"), "ssh"],
                         capture_output=True, text=True)
    print(f"  vps       {'configured' if vps.returncode == 0 else 'not configured — passive/reasoning work only'}")

    if not names:
        print("\n  no targets yet. Say: \"Initialize a new target <name>\"")
        # NOT a bare return: --rules is the cold-start mechanism on runtimes that do not
        # auto-load AGENTS.md, and a fresh clone has zero targets. Returning here printed
        # five lines with no rules in them to exactly the users who needed them most.
        if args.rules:
            print_canonical()
        return 0

    if args.target:
        if args.target not in names:
            print(f"\nFAIL — no target '{args.target}'. Known: {', '.join(names)}", file=sys.stderr)
            return 2
        if args.resume:
            return resume(args.target)
        detail(args.target)
    else:
        print(f"\n## targets ({len(names)}) — no 'active' one; name the target you mean")
        for n in names:
            line_one(n)
        if len(names) > 1:
            print("\n  Two or more targets exist: NAME the one you mean, or resolve a host against")
            print("  each targets/*/scope.md. Never assume the last one touched.")

    if args.rules:
        print_canonical()
    else:
        print("\n  instructions: AGENTS.md  ·  print it here: tools/brief.py --rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
