#!/usr/bin/env python3
"""Scaffold a target brain — atomically, or not at all.

    tools/init-target.py acme --scope '*.acme.com' --dry-run
    tools/init-target.py acme --scope '*.acme.com' --exclude admin.acme.com \
        --program https://hackerone.com/acme --accounts self-register --yes

**The model conducts the interview. This performs the writes.** That split matters: asking good
questions is judgement, and copying a directory then editing nine files correctly is not. The old
flow was `cp -R` followed by a series of model edits — every one a chance to half-finish and leave
a target that looks initialized and is not.

What it guarantees
------------------
* **Atomic.** It builds in a temporary directory and renames into place. An interrupted run leaves
  no half-target — the thing that is worst to inherit, because it reads as complete.
* **Refuses to overwrite.** An existing target is never touched; resume it instead.
* **Verbatim scope.** Your statement goes in exactly as given. The tool does not expand a company
  into domains or reinterpret a wildcard.
* **Derives the mechanical allowlist only from what you supplied** — and leaves it a blocker when
  the scope is a company name, because guessing hostnames is the inference this workspace forbids.
* **Asserts the result.** Every file the schema promises must exist before the rename happens, and
  `scopelib` must be able to parse the scope it just wrote.

Exit: 0 created · 1 dry run / refused · 2 failed.
"""
import argparse
import re
import shutil
import sys
import tempfile
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runlog                                          # noqa: E402
from scopelib import parse_scope                       # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "targets" / "_template"
TARGETS = ROOT / "targets"

# every file the schema promises. A scaffold missing one is not a scaffold.
REQUIRED = [
    "index.md", "scope.md", "target.md", "accounts.md", "attack-surface.md",
    "hypotheses.md", "tested.md", "clusters.md", "user-flows.md",
    "observations.tsv", "runs.tsv", "recon/README.md",
]

SHAPES = [
    (re.compile(r"^\*\.[a-z0-9.-]+$", re.I),            "wildcard apex",  "subdomain-enumeration"),
    (re.compile(r"^https?://[^/]+/.+", re.I),           "URL with a path", "application-mapping / api-discovery"),
    (re.compile(r"^https?://[^/]+/?$", re.I),           "a single host",  "http-probing"),
    (re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$"), "IP or CIDR", "asn-and-ip-discovery"),
    (re.compile(r"^[0-9a-f:]*:[0-9a-f:]*(?:/\d{1,3})?$", re.I), "IP or CIDR", "asn-and-ip-discovery"),
    (re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", re.I), "a single host",  "http-probing"),
]
# a bare apex is genuinely ambiguous: `acme.com` may mean that one host, or the whole estate
# behind it. Guessing picks a skill the hunter did not choose, so it asks instead.
BARE_APEX = re.compile(r"^(?:[a-z0-9-]+\.)?[a-z0-9-]+\.[a-z]{2,}$", re.I)
LABELS = re.compile(r"^(?:[a-z0-9-]+\.){2,}[a-z]{2,}$", re.I)


def die(msg, code=2):
    print(f"FAIL — {msg}", file=sys.stderr)
    raise SystemExit(code)


def slugify(name):
    s = re.sub(r"[^a-z0-9-]+", "-", name.strip().lower()).strip("-")
    if not s:
        die(f"'{name}' does not reduce to a usable slug")
    return s


def classify(scope):
    """(shape, entry skill) from the SHAPE of the statement — the same table as phase-routing §1.

    Returning `None` for the entry skill is a real answer, not a failure: routing a target into the
    wrong first skill costs more than one question. Several shapes deliberately land there.
    """
    s = scope.strip()
    parts = [p for p in re.split(r"[,\s]+", s) if p]
    if len(parts) > 1:
        # several assets, not a sentence — a host list starts at probing, not at org mapping
        if all(any(rx.match(p) for rx, _, _ in SHAPES) for p in parts):
            return f"{len(parts)} assets — a host list", "http-probing"
        return "a company or brand name", "organization-and-roots"
    for rx, shape, entry in SHAPES:
        if rx.match(s):
            # `acme.com` is ambiguous where `www.acme.com` is not: one is usually shorthand for
            # the estate, the other names a host
            if shape == "a single host" and BARE_APEX.match(s) and not LABELS.match(s):
                return ("a bare apex — could mean this host alone or the estate behind it", None)
            return shape, entry
    return "unclassified", None


def build(tmp, slug, args, shape, entry):
    shutil.copytree(TEMPLATE, tmp, dirs_exist_ok=True)
    today = date.today().isoformat()

    # ---- scope.md: verbatim first, derived second --------------------------
    p = tmp / "scope.md"
    t = p.read_text(encoding="utf-8-sig")
    t = t.replace("# <TARGET> — Scope Authority", f"# {slug} — Scope Authority")
    t = t.replace("TBD — blocking: the hunter has not supplied an authorization boundary",
                  args.scope.strip())
    if args.exclude:
        t = t.replace("exclusions: none stated", "\n".join(args.exclude))
    # the mechanical allowlist is DERIVED, and only from what was actually given
    if re.match(r"^\*\.", args.scope.strip()) or re.match(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$",
                                                          args.scope.strip(), re.I):
        t = t.replace("- TBD — blocking: derive from the verbatim statement above; the ingest "
                      "tools match against it", f"- `{args.scope.strip()}`")
    if args.exclude:
        t = t.replace("- <host or subtree the program excluded, one per line — or leave empty>",
                      "\n".join(f"- `{e}`" for e in args.exclude))
    if args.program:
        t = t.replace("- **Program page:** <URL or none supplied>",
                      f"- **Program page:** {args.program}")
    t = t.replace("- **Recorded:** <YYYY-MM-DD>", f"- **Recorded:** {today}")
    t = t.replace("- **Supplied by:** <hunter / program page / private brief>",
                  "- **Supplied by:** hunter (stated directly)")
    if not args.program:
        t = t.replace("- **Program page:** <URL or none supplied>",
                      "- **Program page:** none supplied")
    # The workspace already knows the researcher header and the default rate. Writing "unknown"
    # for a value config.py can answer is a gap the hunter has to close by hand for no reason.
    hdr, rate = None, None
    try:
        import config as _cfg                                     # noqa: E402
        flat = _cfg.load()                        # {dotted.path: value}, env overrides applied
        hdr_n = flat.get("researcher.header_name")
        hdr_v = flat.get("researcher.header_value")
        rate = flat.get("defaults.rate_limit_rps") if _cfg.is_set(
            flat.get("defaults.rate_limit_rps")) else None
        # Record the header NAME, never the value: the value is attribution identity, and writing it
        # into every target brain is exactly the exposure we are closing. vps-run.py injects it from
        # config at dispatch — the brain does not need the raw value.
        if _cfg.is_set(hdr_n) and _cfg.is_set(hdr_v):
            hdr = f"`{hdr_n}`"
            t = t.replace("- **Required attribution header:** unknown — from `tools/config.py` "
                          "unless the program says otherwise",
                          f"- **Required attribution header:** `{hdr_n}` — value in config.py, "
                          f"injected by `vps-run.py`; confirm the name against the program page")
        if _cfg.is_set(rate):
            t = t.replace("- **Maximum request rate:** unknown — `defaults.rate_limit_rps` applies "
                          "until the program states one",
                          f"- **Maximum request rate:** {rate}/s (config default; confirm against "
                          f"the program page)")
    except Exception as e:
        # config is optional and must never fail a scaffold — but a swallowed exception is how a
        # feature quietly stops working, so say it happened
        print(f"  note      could not read config for the quick checks ({type(e).__name__}); "
              f"they stay 'unknown'")
    p.write_text(t, encoding="utf-8")

    # ---- index.md ----------------------------------------------------------
    p = tmp / "index.md"
    t = p.read_text(encoding="utf-8-sig")
    t = t.replace("# <TARGET> — Index / Manifest", f"# {slug} — Index / Manifest")
    t = t.replace('- **Last activity:** <what actually happened, e.g. "R-004 · subdomain-enumeration '
                  'on *.acme.com">', "- **Last activity:** init-target — scaffolded")
    t = t.replace("- **Suggested next:** <derived from the scope shape — a suggestion, not a queue>",
                  f"- **Suggested next:** `{entry or 'unclassified — ask'}`, derived from the "
                  f"scope shape. **A suggestion, not a queue.** Run whichever skill you "
                  f"want; preflight names the inputs a given one needs, and some genuinely "
                  f"cannot run without them.")
    t = t.replace("- **Last updated:** <YYYY-MM-DD>", f"- **Last updated:** {today}")
    t = t.replace("- **Engagement started:** <YYYY-MM-DD>", f"- **Engagement started:** {today}")
    if args.program:
        t = t.replace("- **Program:** <platform / program name / URL>",
                      f"- **Program:** {args.program}")
    # Everything below is knowable at scaffold time. Leaving `<menu | of | options>` in a live
    # file makes an unanswered question look like content.
    t = t.replace("- **Program:** <platform / program name / URL>",
                  f"- **Program:** {args.program or 'not supplied'}")
    t = t.replace("- **Scope type:** <wildcard *.site.com | specific hosts | ...>",
                  f"- **Scope type:** {shape} — `{args.scope.strip()}`")
    t = t.replace("- **Archetype:** <single-app | huge-wildcard | auth-heavy | api-spec | unknown>",
                  "- **Archetype:** unknown — set it after `http-probing` / "
                  "`technology-fingerprinting`")
    t = t.replace("- **Required header:** <e.g. `X-Bug-Bounty: <handle>` | none>",
                  f"- **Required header:** {hdr or 'unknown — check the program page'}")
    t = t.replace("- **Rate limit:** <max req/s the program allows>",
                  f"- **Rate limit:** {str(rate) + '/s (config default)' if rate else 'unknown'} "
                  f"— the program's own limit overrides it")
    t = t.replace("- **Accounts:** <self-register allowed | provided | none — none blocks authz/"
                  "IDOR/tenant testing>",
                  f"- **Accounts:** {args.accounts or 'unknown'}"
                  f"{' — a differential authz test needs 2; the unauth half of those classes '
                     'still runs' if args.accounts == 'none' else ''}")
    t = t.replace("- **Scope recorded:** <YYYY-MM-DD> · evidence: `scope-evidence.md`",
                  f"- **Scope recorded:** {today} · evidence: `scope-evidence.md`")
    t = t.replace("- **Tools installed:** <yes/no — see playbooks/system/vps-setup.md>",
                  "- **Tools installed:** unknown — see playbooks/system/vps-setup.md")
    t = t.replace("**Nuclei templates:** <date>", "**Nuclei templates:** unknown")
    t = t.replace("- **Program rate limit:** <from scope.md — overrides `defaults.rate_limit_rps` "
                  "when stricter>",
                  "- **Program rate limit:** not stated by the program yet")
    t = t.replace("<target>", slug)              # VPS paths; <vps.workdir> stays, deliberately
    t = t.replace("- <what the human should consider running next>",
                  f"- run `tools/preflight.py targets/{slug} "
                  f"{(entry or 'organization-and-roots').split(' / ')[0]}`, then open a run "
                  f"before any traffic")

    blockers = []
    if not args.program:
        blockers.append("- TBD — blocking: no program page recorded; scope cannot be re-verified")
    if args.accounts == "none":
        blockers.append("- TBD — blocking: no accounts — authz/IDOR/multi-tenant/privesc are "
                        "blocked, not untested")
    elif not args.accounts:
        # omitted is not "none" and not "fine" — it is unknown, and the summary line printed
        # below says a blocker was recorded, so one has to actually be recorded
        blockers.append("- TBD — blocking: account availability was never established; until it "
                        "is, authz/IDOR/multi-tenant/privesc are unknown, not untested")
    if entry is None:
        blockers.append("- TBD — blocking: scope shape unclassified; ask before routing")
    if blockers:
        t = t.replace("- <every `TBD — blocking: X` left by init lives here until resolved>",
                      "\n".join(blockers))
    p.write_text(t, encoding="utf-8")

    # ---- target.md / accounts.md ------------------------------------------
    p = tmp / "target.md"
    t = p.read_text(encoding="utf-8-sig").replace("# <TARGET> — Profile / Brain",
                                                  f"# {slug} — Profile / Brain")
    t = t.replace("- **Company:** <name>", f"- **Company:** {args.scope.strip()}  "
                                           f"[FACT: supplied by the hunter at init]")
    p.write_text(t, encoding="utf-8")
    p = tmp / "accounts.md"
    t = p.read_text(encoding="utf-8-sig")
    if args.accounts:
        t = t.replace("<self-register allowed | provided accounts | none | unknown>",
                      f"{args.accounts} — stated at init, {today}")
        if args.accounts == "none":
            t = t.replace("- **Consequence:** <what authenticated work is possible or blocked>",
                          "- **Consequence:** no authenticated work. `idor-bola`, "
                          "`function-level-authorization`, `multi-tenant-isolation` and "
                          "`privilege-escalation` are blocked, not untested.")
    p.write_text(t, encoding="utf-8")

    # `<TARGET>` in EVERY file, not a hand-kept list of five. Eleven files — every recon/*.md,
    # accounts.md, scope-evidence.md — were shipping into live targets still titled `# <TARGET>`
    # because they were not on that list. The two real templates keep their placeholders.
    KEEP_TEMPLATE = ("applications/_host-template/", "investigations/chain.template.md")
    for f in sorted(tmp.rglob("*.md")):
        rel = f.relative_to(tmp).as_posix()
        if any(rel.startswith(k) or rel == k for k in KEEP_TEMPLATE):
            continue
        body = f.read_text(encoding="utf-8-sig")
        if "<TARGET>" in body:
            f.write_text(body.replace("<TARGET>", slug), encoding="utf-8")

    # ---- scope-evidence.md: where the statement came from --------------------
    p = tmp / "scope-evidence.md"
    if p.exists():
        t = p.read_text(encoding="utf-8-sig")
        t = t.replace("- **Supplied by:** <hunter / program page / private brief>",
                      "- **Supplied by:** hunter (stated directly)")
        t = t.replace("- **Captured:** <YYYY-MM-DD>", f"- **Captured:** {today}")
        t = t.replace("- **Source URL:** <URL or none supplied>",
                      f"- **Source URL:** {args.program or 'none supplied'}")
        p.write_text(t, encoding="utf-8")


# Fields init claims to fill. If one still holds a `<placeholder>`, a `.replace()` missed —
# usually because the template wording changed and the search string here did not. That failure is
# invisible otherwise: the file looks populated and the field quietly stays a menu of options.
MUST_RESOLVE = [
    ("index.md", "- **Program:**"), ("index.md", "- **Scope type:**"),
    ("index.md", "- **Archetype:**"), ("index.md", "- **Required header:**"),
    ("index.md", "- **Rate limit:**"), ("index.md", "- **Accounts:**"),
    ("index.md", "- **Scope recorded:**"), ("index.md", "- **Suggested next:**"), ("scope.md", "- **Supplied by:**"),
    ("scope.md", "- **Recorded:**"), ("accounts.md", "- **Policy:**"),
    ("target.md", "- **Company:**"),
]


def verify(tmp):
    missing = [r for r in REQUIRED if not (tmp / r).exists()]
    if missing:
        return f"scaffold is incomplete: {', '.join(missing)}"
    for rel, field in MUST_RESOLVE:
        f = tmp / rel
        if not f.exists():
            continue
        for line in f.read_text(encoding="utf-8-sig").splitlines():
            if line.startswith(field) and "<" in line:
                return (f"{rel}: `{field}` still holds a placeholder — a replacement in build() "
                        f"missed, probably because the template wording changed:\n         {line.strip()}")
    if "<TARGET>" in "".join(
            f.read_text(encoding="utf-8-sig") for f in tmp.rglob("*.md")
            if "_host-template" not in f.as_posix() and "chain.template" not in f.name):
        return "a file still contains `<TARGET>` — the slug substitution missed it"
    s = parse_scope(tmp)
    if s["state"] == "no-file":
        return "scope.md was not written"
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("name", help="target name; slugified for the directory")
    ap.add_argument("--scope", required=True, help="the statement, VERBATIM, as the human gave it")
    ap.add_argument("--exclude", action="append", default=[], help="out-of-scope entry; repeatable")
    ap.add_argument("--program", help="program page URL")
    ap.add_argument("--accounts", choices=["self-register", "provided", "none"])
    ap.add_argument("--dry-run", action="store_true", help="show what would be written")
    ap.add_argument("--yes", action="store_true", help="actually create it")
    args = ap.parse_args()

    slug = slugify(args.name)
    dest = TARGETS / slug
    if dest.exists():
        die(f"targets/{slug}/ already exists. Resume it — `tools/brief.py {slug} --resume` — "
            f"or pick another name.\n       Initialization never overwrites a brain.", 1)
    if not TEMPLATE.is_dir():
        die(f"no template at {TEMPLATE}")

    shape, entry = classify(args.scope)
    print(f"\n  target      {slug}")
    print(f"  scope       {args.scope.strip()}   (stored verbatim)")
    print(f"  shape       {shape}")
    print(f"  entry       {entry or '⚠ unclassified — ask before routing'}")
    print(f"  exclusions  {', '.join(args.exclude) if args.exclude else 'none stated '
                                                                       '(≠ none)'}")
    print(f"  program     {args.program or 'not supplied — recorded as a blocker'}")
    print(f"  accounts    {args.accounts or 'not supplied — recorded as a blocker'}")

    if not args.yes or args.dry_run:
        print("\n  dry run — nothing written. Re-run with --yes to create it.\n")
        return 1

    tmp = Path(tempfile.mkdtemp(prefix=f".{slug}-", dir=TARGETS))
    try:
        build(tmp, slug, args, shape, entry)
        problem = verify(tmp)
        if problem:
            die(f"{problem}\n       Nothing was created — a half-written brain is worse than none.")
        tmp.rename(dest)          # atomic on the same filesystem
    except SystemExit:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    except Exception as e:
        shutil.rmtree(tmp, ignore_errors=True)
        die(f"{type(e).__name__}: {e}\n       Nothing was created.")

    reg = TARGETS / "TARGETS.md"
    if not reg.exists() and (TARGETS / "TARGETS.example.md").exists():
        shutil.copy(TARGETS / "TARGETS.example.md", reg)
    if reg.exists():
        with reg.open("a", encoding="utf-8") as fh:
            fh.write(f"| [{slug}]({slug}/index.md) | {args.program or '—'} | {shape} | "
                     f"scaffolded | {date.today().isoformat()} |\n")

    print(f"\n  created  targets/{slug}/")
    print(f"  next     tools/preflight.py targets/{slug} {(entry or '01')[:2]}")
    print("           …then open the run before any traffic. No recon has been performed.\n")
    return 0


if __name__ == "__main__":
    sys.exit(runlog.wrap()(main)())
