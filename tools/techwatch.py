#!/usr/bin/env python3
"""Watch public advisories against the target's recorded component inventory.

    tools/techwatch.py targets/acme              # query OSV + CISA KEV, write tech-watch.md, notify on NEW
    tools/techwatch.py targets/acme --dry-run    # no network: print what would be queried

What it is
----------
The recorded brain already knows which components run on which hosts
(`recon/components.md`, produced by `component-inventory`). This tool asks the OUTSIDE world a
passive question — *which published advisories affect the versions we recorded?* — and writes the
answer to `tech-watch.md` in the brain.

What it is not
--------------
* It sends **no traffic to the target**. OSV.dev and the CISA KEV feed are not the target; the
  tool runs locally with no VPS.
* It **proposes** a cohort sweep (`kb.py cohort` + `playbooks/workflows/n-day-sweep.md`); it never
  runs one. A scanner match is a hypothesis; the sweep workflow keeps its own pilot discipline.
* Version `unknown` rows are NOT cleared: they are listed as "cannot version-filter", the same
  honesty rule `kb.py cohort` applies. Unversioned is not "not vulnerable".

Mapping: component names → OSV ecosystems
-----------------------------------------
OSV queries need `(ecosystem, package)`. The alias table below covers the common web components;
a row may also carry its own mapping as `component@ecosystem:package` (e.g. ` lodash@npm:lodash.ts `).
Anything unmapped is reported in the **Unmatched** section with the reason — never silently
dropped, never guessed (querying "Apache" against npm would return a clean-looking zero that
means nothing). Extend `--map name=ecosystem:package` for one-offs, or the table for keeps.

State: advisory ids already reported live in `logs/techwatch-seen.txt`; a run reports **NEW**
matches as the delta, then records everything it saw.

Exit: 0 ran (zero matches is a real, bounded result) · 2 could not run (no inventory, unreadable
tables, OSV unreachable — a failed query is never "no advisories").
"""
import argparse
import datetime as _dt
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

OSV_API = "https://api.osv.dev/v1/querybatch"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
TIMEOUT_S = 25
REPORT = "tech-watch.md"
SEEN = "logs/techwatch-seen.txt"

# component (lowercased) -> (OSV ecosystem, package). Deliberately small: an entry here is a
# claim that the mapping is right, and a wrong mapping produces a confident zero.
ALIASES = {
    "jquery": ("npm", "jquery"),
    "lodash": ("npm", "lodash"),
    "moment": ("npm", "moment"),
    "moment.js": ("npm", "moment"),
    "bootstrap": ("npm", "bootstrap"),
    "react": ("npm", "react"),
    "vue": ("npm", "vue"),
    "vue.js": ("npm", "vue"),
    "angular": ("npm", "@angular/core"),
    "axios": ("npm", "axios"),
    "next.js": ("npm", "next"),
    "express": ("npm", "express"),
    "django": ("PyPI", "django"),
    "flask": ("PyPI", "flask"),
    "requests": ("PyPI", "requests"),
    "rails": ("RubyGems", "rails"),
    "ruby on rails": ("RubyGems", "rails"),
    "wordpress": ("WordPress", "wordpress"),
    "spring boot": ("Maven", "org.springframework.boot:spring-boot"),
    "spring framework": ("Maven", "org.springframework:spring-web"),
    "laravel": ("Packagist", "laravel/framework"),
    "symfony": ("Packagist", "symfony/symfony"),
    "gunicorn": ("PyPI", "gunicorn"),
    "stripe-js": ("npm", "@stripe/stripe-js"),
}


def _now():
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def die(msg, code=2):
    print(f"FAIL — {msg}", file=sys.stderr)
    raise SystemExit(code)


def parse_rows(text, wanted):
    """Rows of a recon markdown table as dicts, keyed by the file's own header.
    Placeholder template rows (`| <…`) and separators are skipped."""
    lines = text.splitlines()
    header = None
    out = []
    for line in lines:
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if all(re.fullmatch(r":?-+:?", c) for c in cells if cells):
            continue
        if header is None:
            if all(w in [h.lower() for h in cells] for w in wanted):
                header = [h.lower() for h in cells]
            continue
        if cells and cells[0].startswith("<"):
            continue                       # a template placeholder, not data
        if header and len(cells) == len(header):
            out.append(dict(zip(header, cells)))
    return out, header


def load_inventory(tdir):
    """[(host, component, version, precision)] plus the buckets that cannot be queried."""
    comps = tdir / "recon" / "components.md"
    if not comps.exists():
        die(f"recon/components.md does not exist — it is produced by the `component-inventory` "
            f"skill.\n       Run that first; tech-watch has nothing to watch without it.")
    rows, _ = parse_rows(comps.read_text(encoding="utf-8-sig"),
                         ("host", "component", "version"))
    if not rows:
        die("recon/components.md parsed to zero rows — the inventory is empty. "
            "`component-inventory` has not recorded anything; run it first.")
    queryable, unversioned = [], []
    for r in rows:
        version = (r.get("version") or "").strip()
        precision = (r.get("precision") or "").strip().lower()
        item = (r["host"], r["component"], version, precision)
        (queryable if re.fullmatch(r"[0-9][0-9A-Za-z.+-]*", version) else unversioned).append(item)
    return queryable, unversioned


def resolve_mapping(component, extra_map):
    """component string -> (ecosystem, package) or (None, reason).

    A `name@ecosystem:package` suffix on the row itself wins; then --map; then the table."""
    raw = component.strip()
    m = re.search(r"@(npm|PyPI|Maven|Go|RubyGems|Packagist|crates\.io|WordPress|NuGet):([A-Za-z0-9@/._:-]+)$",
                  raw)
    if m:
        return m.group(1), m.group(2)
    key = raw.lower()
    if key in extra_map:
        eco, pkg = extra_map[key]
        return eco, pkg
    if key in ALIASES:
        return ALIASES[key]
    return None, "no ecosystem mapping — extend ALIASES or pass --map"


def osv_batch(pairs, api=OSV_API, timeout=TIMEOUT_S):
    """[(eco, pkg, version)] -> {(eco,pkg,version): [vuln dicts]} via one querybatch POST."""
    if not pairs:
        return {}
    body = json.dumps({"queries": [
        {"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in pairs]}).encode()
    req = urllib.request.Request(api, data=body, headers={"Content-Type": "application/json"})
    from netlib import ssl_context
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_context()) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError) as e:
        die(f"cannot query OSV ({api}): {e}\n       A failed query is not 'no advisories' — "
            f"re-run when the network allows.")
    out = {}
    for pair, result in zip(pairs, data.get("results", [])):
        out[pair] = (result or {}).get("vulns", []) or []
    return out


def kev_cves(url=KEV_URL, timeout=TIMEOUT_S):
    """Set of CVE ids in the CISA KEV catalog, or None when the feed is unreachable."""
    from netlib import ssl_context
    try:
        with urllib.request.urlopen(url, timeout=timeout, context=ssl_context()) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return {v.get("cve", "").upper() for v in data.get("vulnerabilities", []) if v.get("cve")}
    except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError):
        return None


def _vuln_cves(vuln):
    ids = {a.upper() for a in vuln.get("aliases", []) if a.upper().startswith("CVE-")}
    if vuln.get("id", "").upper().startswith("CVE-"):
        ids.add(vuln["id"].upper())
    return ids


def collect(queryable, extra_map, api, kev_url):
    """One pass: map components, query OSV, flag KEV. Returns the report model."""
    mapped, unmatched = {}, []
    for host, comp, version, _prec in queryable:
        eco, pkg = resolve_mapping(comp, extra_map)
        if eco is None:
            if (comp, pkg) not in unmatched:      # pkg carries the reason here
                unmatched.append((comp, pkg))
            continue
        mapped.setdefault((eco, pkg, version), set()).add(host)
    results = osv_batch(sorted(mapped), api=api) if mapped else {}
    kev = kev_cves(kev_url)
    matches = []          # dicts: advisory, aliases, component, version, hosts, kev
    for (eco, pkg, version), vulns in sorted(results.items()):
        for v in vulns:
            cves = _vuln_cves(v)
            matches.append({
                "advisory": v.get("id", "?"),
                "aliases": ", ".join(sorted(a for a in v.get("aliases", []))[:4]),
                "component": pkg, "version": version,
                "hosts": sorted(mapped[(eco, pkg, version)]),
                "kev": bool(kev is not None and kev & cves),
                "summary": (v.get("summary") or v.get("details") or "")[:110],
            })
    matches.sort(key=lambda m: (not m["kev"], m["advisory"]))
    return matches, unmatched, kev is None


def load_seen(tdir):
    f = tdir / SEEN
    return set(f.read_text(encoding="utf-8-sig").split()) if f.exists() else set()


def save_seen(tdir, ids):
    f = tdir / SEEN
    f.parent.mkdir(parents=True, exist_ok=True)
    old = load_seen(tdir)
    f.write_text("\n".join(sorted(old | set(ids))) + "\n", encoding="utf-8")


def render(tdir_name, matches, new, unversioned, unmatched, kev_unreachable, dry):
    lines = [f"# {tdir_name} — tech-watch (advisories vs the recorded stack)", "",
             f"> `tools/techwatch.py` · {_now()}"
             + (" · DRY RUN (no network — planning view only)" if dry else ""),
             "> Proposes cohort sweeps; never runs one. Unversioned is not 'not vulnerable'.", ""]
    lines += ["## NEW this run", ""]
    if new:
        lines += ["| advisory | aliases | component | version | hosts | KEV | summary |",
                  "|---|---|---|---|---|---|---|"]
        lines += [f"| {m['advisory']} | {m['aliases']} | {m['component']} | {m['version']} "
                  f"| {len(m['hosts'])} | {'**KEV**' if m['kev'] else ''} | {m['summary']} |"
                  for m in new]
    else:
        lines += ["_none — every advisory below was already reported in an earlier run._"]
    lines += ["", "## All current matches", ""]
    if matches:
        lines += ["| advisory | component | version | hosts | KEV | summary |",
                  "|---|---|---|---|---|---|"]
        lines += [f"| {m['advisory']} | {m['component']} | {m['version']} | {len(m['hosts'])} "
                  f"| {'**KEV**' if m['kev'] else ''} | {m['summary']} |" for m in matches]
    else:
        lines += [f"_zero advisories against {len(matches)} mapped components — bounded by what "
                  f"the inventory recorded and what OSV maps._"]
    if unversioned:
        lines += ["", "## Cannot version-filter (recorded without a version)", "",
                  "| host | component | precision |", "|---|---|---|"]
        lines += [f"| {h} | {c} | {p or '—'} |" for h, c, _v, p in unversioned]
        lines += ["", "Fingerprint these before ruling them out — everyone else's tooling "
                      "silently dropped them too."]
    if unmatched:
        lines += ["", "## Unmatched components (no ecosystem mapping)", "",
                  "| component | reason |", "|---|---|"]
        lines += [f"| {c} | {why} |" for c, why in unmatched]
    lines += ["", "## Proposed next actions", ""]
    for comp in sorted({m["component"] for m in (new or matches)}):
        lines += [f"- `tools/kb.py cohort targets/{tdir_name} --tech \"{comp}\"` → then "
                  f"`playbooks/workflows/n-day-sweep.md` (pilot one host, human reads, scale). "
                  f"A match is a hypothesis, not a finding."]
    if not matches and not new:
        lines += ["- nothing to sweep from this run; re-run after `component-inventory` widens "
                  "the stack record"]
    if kev_unreachable and not dry:
        lines += ["", "> ⚠ CISA KEV feed unreachable — KEV flags are absent this run, not "
                      "negative."]
    return "\n".join(lines) + "\n"


def cmd_check(args):
    tdir = Path(args.target).resolve()
    if not (tdir / "index.md").exists() and not tdir.name.startswith("_"):
        die(f"{args.target} does not look like a target brain (no index.md)")
    extra = {}
    for m in args.map or []:
        if "=" not in m:
            die(f"--map expects name=ecosystem:package, got '{m}'")
        name, _, rest = m.partition("=")
        eco, _, pkg = rest.partition(":")
        extra[name.strip().lower()] = (eco.strip(), pkg.strip())
    queryable, unversioned = load_inventory(tdir)
    if args.dry_run:
        mapped = []
        for host, comp, version, _ in queryable:
            eco, pkg = resolve_mapping(comp, extra)
            mapped.append((comp, eco or "UNMAPPED", pkg, version))
        print(f"dry run — {len(queryable)} versioned row(s), {len(unversioned)} unversioned, "
              f"{sum(1 for m in mapped if m[1] == 'UNMAPPED')} unmatched:")
        for comp, eco, pkg, version in mapped:
            print(f"  {'QUERY ' if eco != 'UNMAPPED' else 'SKIP  '} {comp} {version} -> "
                  f"{eco}:{pkg}")
        return 0
    matches, unmatched, kev_down = collect(queryable, extra, args.api, args.kev_url)
    seen = load_seen(tdir)
    new = [m for m in matches if m["advisory"] not in seen]
    report = render(tdir.name, matches, new, unversioned, unmatched, kev_down, dry=False)
    (tdir / REPORT).write_text(report, encoding="utf-8")
    save_seen(tdir, [m["advisory"] for m in matches])
    print(f"tech-watch: {len(matches)} advisories match the recorded stack "
          f"({len(new)} NEW) · {len(unversioned)} unversioned · {len(unmatched)} unmatched")
    print(f"  report   targets/{tdir.name}/{REPORT}")
    for m in new[:5]:
        print(f"  NEW {'KEV ' if m['kev'] else '    '}{m['advisory']}  {m['component']} "
              f"{m['version']}  ({len(m['hosts'])} host(s))")
    if new:
        body = "\n".join(f"{m['advisory']} — {m['component']} {m['version']} on "
                         f"{len(m['hosts'])} host(s){' [KEV]' if m['kev'] else ''}"
                         for m in new[:3])
        try:
            import notify
            sent, _spooled, note = notify.send(
                "tech-watch", f"{len(new)} new advisories vs the recorded stack",
                body, target=tdir.name)
            if note and sent == 0:
                print(f"  notify   {note}")
        except Exception:
            pass    # notification is an afterthought, never a gate
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="targets/<name> (or targets/<name>)")
    ap.add_argument("--dry-run", action="store_true",
                    help="no network: print the queries that would run and the mapping gaps")
    ap.add_argument("--map", action="append", metavar="NAME=ECOSYSTEM:PACKAGE",
                    help="one-off component mapping, repeatable (e.g. --map fabricjs=npm:fabric)")
    ap.add_argument("--api", default=OSV_API, help=argparse.SUPPRESS)
    ap.add_argument("--kev-url", default=KEV_URL, help=argparse.SUPPRESS)
    args = ap.parse_args()
    return cmd_check(args)


if __name__ == "__main__":
    sys.exit(main())
