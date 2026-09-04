#!/usr/bin/env python3
"""Serve the target brains as a live read-only JSON API + the SPA console in web/.

    tools/dashboard-server.py                  # http://127.0.0.1:8787
    tools/dashboard-server.py --port 9000      # another port
    tools/dashboard-server.py --host 0.0.0.0   # expose (you asked for it, not the default)

Unlike tools/dashboard.py, which renders a static snapshot that ages the moment it is
written, the server recomputes every response from the brain files at request time —
the page is never stale while the browser tab is open, and "currently running" updates
on its own.

Endpoint map (the whole surface — there is no generic file endpoint on purpose):

    GET /                     the SPA (web/index.html + app.js + style.css)
    GET /api/overview         fleet totals, per-target cards, activity series
    GET /api/target/<name>    one target's full dashboard payload
    GET /api/health           liveness

The same three honesty rules the static dashboard runs on, plus the safety rules of
the workspace:

  1. Counts are COMPUTED from the files, never copied from index.md.
  2. `missing` != `0` != `prose` — every number carries its state.
  3. Everything is stamped; stale inputs are labeled.

  4. READ-ONLY. No endpoint writes to the brain, ever.
  5. accounts.md is summarized (usable principals), never serialized — credential
     references do not belong in a response body. config.json is never opened.
  6. Local by default (127.0.0.1). Target names are validated against the discovered
     set; there is no path parameter anywhere, so nothing to traverse.

Exit: 0 after clean shutdown · 2 bad invocation.
"""
import argparse
import base64
import csv
import json
import re
import shlex
import subprocess
import sys
import time
import traceback
from collections import Counter
from datetime import date, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import dashboard as dash        # noqa: E402  one parser set, not two
import runlog                   # noqa: E402

STALE_DAYS = dash.STALE_DAYS
RUN_CAP = 300                   # rows serialized per target; more is unreadable, not informative
LOG_CAP = 200
SURFACE_CAP = 500
TESTED_CAP = 500

# What one "funnel stage" is on cards and KPIs: (file, key, label).
FUNNEL = [
    ("recon/subdomains.txt", "subdomains", "subdomains"),
    ("recon/live-hosts.txt", "live_hosts", "live hosts"),
    ("recon/urls.txt", "urls", "urls"),
    ("recon/endpoints.md", "endpoints", "endpoints"),
]
HYP_STATUSES = ("open", "testing", "confirmed", "rejected")

_CACHE = {"t": 0.0, "overview": None, "targets": {}, "extras": {}, "remote": {}}
_CACHE_TTL = 5.0        # seconds; the browser polls slower than this


# ------------------------------------------------------------------ payloads

def _runs(tdir):
    """Latest row per run_id — the open→close pattern writes the id twice."""
    latest = {}
    for r in dash._runs(tdir):
        latest[r["run_id"]] = r
    return list(latest.values())


def _host_key(u):
    """Normalize any host-ish line (URL, host, host:port) to one comparable key."""
    u = (u or "").strip()
    if "://" in u:
        u = u.split("://", 1)[1]
    return u.strip().strip("/").lower()


def _mentions_host(text, hk):
    """Boundary-aware host mention: `on.yahoo.com` must not match inside
    `location.yahoo.com`. A bare substring test charges one host's activity
    to every host that happens to end the same way."""
    if not text:
        return False
    return re.search(rf"(?<![a-z0-9.-]){re.escape(hk)}(?![a-z0-9-])", text.lower()) is not None


def _observations(tdir):
    f = tdir / "observations.tsv"
    if not f.exists():
        return []
    with f.open(encoding="utf-8-sig", newline="") as fh:
        return [r for r in csv.DictReader(fh, delimiter="\t") if r.get("subject")]


def _app_brains(tdir):
    """[{dir, host}] for every per-application brain that actually has a map."""
    base = tdir / "applications"
    out = []
    if not base.is_dir():
        return out
    for d in sorted(base.iterdir()):
        if not d.is_dir() or d.name.startswith(("_", ".")):
            continue
        if (d / "map.md").exists():
            host = re.sub(r"-(\d+)$", r":\1", d.name)   # host[-port] convention
            out.append({"dir": d.name, "host": host})
    return out


def _tech_by_host(tdir):
    """host-key → joined tech string, from the technologies.md table."""
    hdr, rows = dash.table_rows(dash.read(tdir / "recon/technologies.md"))
    out = {}
    if not hdr:
        return out
    keys = [re.sub(r"[`*]", "", h).strip().lower() for h in hdr]
    if "host" not in keys:
        return out
    hi = keys.index("host")
    for r in rows:
        if len(r) <= hi or not r[hi].strip():
            continue
        bits = []
        for name in ("server", "framework", "language", "cdn/waf", "cms"):
            if name in keys:
                v = r[keys.index(name)].strip() if len(r) > keys.index(name) else ""
                if v and v not in ("—", "-"):
                    bits.append(v)
        out[_host_key(r[hi])] = " · ".join(bits)
    return out


def hosts_payload(tdir, enrich="auto"):
    """The live-host inventory. The base list is live-hosts.txt; every column that
    is not in the local brain is honestly absent, never invented. With the VPS
    configured, the newest httpx artifact fills the gaps (local facts still win)."""
    lh = tdir / "recon/live-hosts.txt"
    lh_state = dash.state_of(lh)
    urls = []
    if lh.is_file():
        urls = [l.strip() for l in dash.read(lh).splitlines() if l.strip()]

    tech = _tech_by_host(tdir)
    obs = {}
    for row in _observations(tdir):
        obs.setdefault(_host_key(row.get("subject")), []).append(row)
    apps = {_host_key(a["host"]): a for a in _app_brains(tdir)}

    if not urls:                       # demoted/missing: fall back to what we do have
        urls = sorted(set(tech) | set(obs) | set(apps))

    runs = _runs(tdir)
    _, tested_rows = dash.table_rows(dash.read(tdir / "tested.md"))
    _, surf_rows = surface_table(tdir)
    _, hyp_rows = dash.table_rows(dash.read(tdir / "hypotheses.md"))

    hosts = []
    for u in urls:
        k = _host_key(u)
        status = title = None
        tech_str = tech.get(k)
        for row in obs.get(k, []):
            p = (row.get("predicate") or "").strip().lower()
            if p == "status":
                status = row.get("object")
            elif p == "title":
                title = row.get("object")
            elif p in ("runs", "runs-on", "server") and not tech_str:
                tech_str = row.get("object")
        n_runs = sum(1 for r in runs if _mentions_host(r.get("selector"), k) or _mentions_host(r.get("phase"), k))
        n_probes = sum(1 for r in tested_rows if _mentions_host(" ".join(r), k))
        n_surf = sum(1 for r in surf_rows if _mentions_host(" ".join(r), k))
        n_hyp = sum(1 for r in hyp_rows if _mentions_host(" ".join(r), k))
        hosts.append({
            "host": k, "url": u,
            "status": status, "title": title, "tech": tech_str,
            "app": k in apps,
            "activity": {"runs": n_runs, "probes": n_probes, "surface": n_surf, "hypotheses": n_hyp},
        })
    out = {"live_hosts_state": {"state": lh_state[0], "count": lh_state[1]},
           "total": len(hosts),
           "rich_local": sum(1 for h in hosts if h["status"] or h["tech"]),
           "hosts": hosts}
    mapping = {}
    if enrich == "auto":
        enr = httpx_enrichment(tdir)
        out["vps"] = "not-configured" if enr.get("error") == "not-configured" \
            else ("error: " + enr["error"] if enr.get("error") else "ok")
        mapping = enr.get("hosts") or {}
    elif isinstance(enrich, dict):
        out["vps"] = "ok" if enrich else "not-configured"
        mapping = enrich
    out["enriched"] = merge_enrichment(hosts, mapping)
    return out


def endpoints_payload(tdir):
    """Target-level endpoints.md plus the url/parameter bulk states."""
    hdr, rows = dash.table_rows(dash.read(tdir / "recon/endpoints.md"))
    rows = [r for r in rows if any(c.strip() for c in r)]
    return {
        "header": hdr, "rows": rows, "total": len(rows),
        "urls": dict(zip(("state", "count"), dash.state_of(tdir / "recon/urls.txt"))),
        "params": dict(zip(("state", "count"), dash.state_of(tdir / "recon/parameters.txt"))),
    }


def progress_for_host(tdir, host):
    p = tdir / "progress.md"
    if not p.exists():
        return None
    text = dash.read(p)
    m = re.search(rf"^###\s+`?{re.escape(host)}`?\s*$(.*?)(?=^###?\s|\Z)", text, re.M | re.S)
    return dash.md_to_html(m.group(1)) if m else None


def app_payload(tdir, host):
    """One host's dashboard: its application brain where one exists, plus every
    target-level row that names this host. Same honesty as everywhere else —
    a host with no brain and no activity is shown as exactly that."""
    hk = _host_key(host)
    app = next((a for a in _app_brains(tdir) if _host_key(a["host"]) == hk), None)
    base = {"host": hk, "app": app}
    if app:
        adir = tdir / "applications" / app["dir"]
        map_html = dash.md_to_html(dash.read(adir / "map.md"))
        notes_html = dash.md_to_html(dash.read(adir / "notes.md"))
        ep_hdr, ep_rows = dash.table_rows(dash.read(adir / "endpoints.md"))
        ep_rows = [r for r in ep_rows if any(c.strip() for c in r)]
        base.update({"map_html": map_html, "notes_html": notes_html,
                     "endpoints": {"header": ep_hdr, "rows": ep_rows, "total": len(ep_rows)}})
    else:
        base.update({"map_html": None, "notes_html": None,
                     "endpoints": {"header": [], "rows": [], "total": 0}})

    runs = _runs(tdir)
    t_hdr, tested_rows = dash.table_rows(dash.read(tdir / "tested.md"))
    s_hdr, surf_rows = surface_table(tdir)
    hyp_hdr, hyp_rows = dash.table_rows(dash.read(tdir / "hypotheses.md"))
    urls_f = tdir / "recon/urls.txt"
    urls = None
    if urls_f.is_file():
        urls = [l.strip() for l in dash.read(urls_f).splitlines()
                if l.strip() and _mentions_host(l, hk)][:800]

    hosts = hosts_payload(tdir)["hosts"]
    hrow = next((h for h in hosts if h["host"] == hk), None)
    base.update({
        "host_row": hrow,
        "runs": [r for r in runs if _mentions_host(r.get("selector"), hk) or _mentions_host(r.get("phase"), hk)],
        "tested": {"header": t_hdr, "rows": [r for r in tested_rows if _mentions_host(" ".join(r), hk)]},
        "surface": {"header": s_hdr, "rows": [r for r in surf_rows if _mentions_host(" ".join(r), hk)]},
        "hypotheses": {"header": hyp_hdr, "rows": [r for r in hyp_rows if _mentions_host(" ".join(r), hk)]},
        "observations": [r for r in _observations(tdir) if _host_key(r.get("subject")) == hk],
        "urls": urls,
        "progress_html": progress_for_host(tdir, hk),
        "apps": _app_brains(tdir),
    })
    return base


def _activity(runs):
    c = Counter((r.get("date") or "")[:10] for r in runs if r.get("date"))
    return [{"date": d, "n": n} for d, n in sorted(c.items()) if d]


def _hyp_status(cell):
    s = (cell or "").strip().lower()
    for st in HYP_STATUSES:
        if s.startswith(st):
            return st
    return "unstated"


def _blockers(idx):
    out = [m.group(0).strip() for m in re.finditer(r"TBD\s*—\s*blocking:[^\n|]*", idx)]
    sec = re.search(r"^##+\s*Blocking\s*/?\s*TBD.*?$(.*?)(?=^##|\Z)", idx, re.M | re.S)
    if sec:
        out += [l.strip(" -*\t") for l in sec.group(1).splitlines()
                if l.strip(" -*\t") and not l.strip(" -*\t").startswith("<")]
    seen, uniq = set(), []
    for b in out:
        if b not in seen and not b.startswith("RESOLVED"):
            seen.add(b)
            uniq.append(b)
    return uniq


def _fence_after(text, heading):
    m = re.search(rf"##\s*{re.escape(heading)}.*?```(?:text)?\n(.*?)```", text, re.S)
    return m.group(1).strip() if m else None


def scope_bits(tdir):
    t = dash.read(tdir / "scope.md")
    attr = re.search(r"Required attribution header:\*\*\s*`([^`]*)`", t)
    rate = re.search(r"Maximum request rate:\*\*\s*([^`\n]*)", t)
    _, decisions = dash.table_with(t, "decision")
    return {
        "statement": _fence_after(t, "Supplied scope statement"),
        "exclusions": _fence_after(t, "Supplied exclusions"),
        "decisions": decisions,
        "attribution": attr.group(1) if attr else None,
        "rate": rate.group(1).strip() if rate else None,
    }


def funnel_states(tdir):
    out = {}
    for relp, key, _label in FUNNEL:
        st, n = dash.state_of(tdir / relp)
        out[key] = {"state": st, "count": n}
    return out


def _findings(tdir):
    out = {}
    for kind in ("confirmed", "draft", "rejected"):
        d = tdir / "findings" / kind
        out[kind] = sorted(p.name for p in d.glob("*.md")) if d.is_dir() else []
    return out


def _testers(tdir):
    hdr, rows = dash.table_rows(dash.read(tdir / "tested.md"))
    rows = [r for r in rows if any(c.strip() for c in r)]
    keys = [re.sub(r"[^a-z]", "", h.lower()) for h in hdr]
    by = {"result": Counter(), "coverage": Counter()}
    try:
        ri, ci = keys.index("result"), keys.index("coverage")
        for r in rows:
            by["result"][r[ri] if ri < len(r) else ""] += 1
            by["coverage"][r[ci] if ci < len(r) else ""] += 1
    except ValueError:
        pass
    return {"header": hdr, "rows": rows[:TESTED_CAP],
            "total": len(rows), "by_result": dict(by["result"]), "by_coverage": dict(by["coverage"])}


def surface_table(tdir):
    """The main (entrypoint × class) table of attack-surface.md.

    dash.table_with's exact-subset header match cannot see the real header — the
    template ships `entrypoint (host/endpoint/param/flow)`, not `entrypoint` — and
    where the file carries a smaller example table it matches that one instead
    (dvwa read as 2 rows; its real table has 14). Pick by column prefix and let
    the match with the most data rows win.
    """
    text = dash.read(tdir / "attack-surface.md")
    best = ([], [])
    block = []

    def flush():
        nonlocal best
        if not block:
            return
        hdr, rows = dash.table_rows("\n".join(block))
        keys = [re.sub(r"[`*]", "", h).strip().lower() for h in hdr]
        if (any(k.startswith("entrypoint") for k in keys)
                and any(k.startswith("vuln_class") for k in keys)
                and len(rows) > len(best[1])):
            best = (hdr, rows)

    for line in text.splitlines():
        if line.lstrip().startswith("|"):
            block.append(line)
        else:
            flush()
            block = []
    flush()
    return best


def card(tdir):
    """Everything the fleet grid and the sidebar need for one target."""
    idx = dash.read(tdir / "index.md")
    runs = _runs(tdir)
    open_runs = [r for r in runs if r.get("status") == "running"]
    resume = [r for r in runs if r.get("status") in ("partial", "failed") and r.get("resume_from")]
    _, hyp_rows = dash.table_rows(dash.read(tdir / "hypotheses.md"))
    hyp = Counter(_hyp_status(r[4]) if len(r) > 4 else "unstated" for r in hyp_rows)
    _, surf_rows = surface_table(tdir)
    findings = _findings(tdir)
    tested = _testers(tdir)
    upd = dash.field(idx, "Last updated") or ""
    age = dash.age_days(upd)
    closed = sorted((r for r in runs if r.get("status") != "running"),
                    key=lambda r: (r.get("date") or "", r.get("run_id") or ""))
    return {
        "name": tdir.name,
        "program": dash.field(idx, "Program"),
        "scope_type": dash.field(idx, "Scope type") or dash.field(idx, "Archetype"),
        "scope": (scope_bits(tdir)["statement"] or "").splitlines()[0] if scope_bits(tdir)["statement"] else None,
        "updated": upd, "age_days": age, "stale": age is not None and age > STALE_DAYS,
        "last_activity": dash.field(idx, "Last activity"),
        "suggested_next": dash.field(idx, "Suggested next"),
        "open_runs": len(open_runs), "resume_points": len(resume),
        "blockers": _blockers(idx),
        "funnel": funnel_states(tdir),
        "surface": len(surf_rows), "probes": tested["total"],
        "hypotheses": {s: hyp.get(s, 0) for s in HYP_STATUSES},
        "findings": {k: len(v) for k, v in findings.items()},
        "principals": dash.usable_principals(dash.read(tdir / "accounts.md")),
        "last_run": ({ "id": closed[-1]["run_id"], "date": closed[-1].get("date"),
                      "phase": closed[-1].get("phase"), "status": closed[-1].get("status")}
                     if closed else None),
        "activity": _activity(runs),
        "apps": _app_brains(tdir),
    }


def detail(tdir):
    c = card(tdir)
    runs = sorted(_runs(tdir), key=lambda r: (r.get("date") or "", r.get("run_id") or ""), reverse=True)
    surf_hdr, surf_rows = surface_table(tdir)
    hyp_hdr, hyp_rows = dash.table_rows(dash.read(tdir / "hypotheses.md"))
    files = []
    today = date.today()
    for relf in dash.BRAIN_FILES:
        p = tdir / relf
        st, n = dash.state_of(p)
        try:
            age = (today - date.fromtimestamp(p.stat().st_mtime)).days
        except OSError:
            age = None
        files.append({"file": relf, "state": st, "count": n, "age_days": age})
    p = tdir / "progress.md"
    progress_html = dash.md_to_html(dash.read(p)) if p.exists() else None
    logs = list(reversed(runlog.read_log(tdir)))[:LOG_CAP]
    return {
        "meta": c,
        "scope": scope_bits(tdir),
        "runs": runs[:RUN_CAP], "runs_total": len(runs),
        "open_runs": [r for r in runs if r.get("status") == "running"],
        "resume": [r for r in runs if r.get("status") in ("partial", "failed") and r.get("resume_from")],
        "logs": logs,
        "log_failures": sum(1 for r in runlog.read_log(tdir) if r["exit"] not in ("0", "")),
        "surface": {"header": surf_hdr, "rows": surf_rows[:SURFACE_CAP], "total": len(surf_rows)},
        "hypotheses": {"header": hyp_hdr, "rows": hyp_rows},
        "tested": _testers(tdir),
        "findings": _findings(tdir),
        "files": files,
        "progress_html": progress_html,
    }


def overview():
    tdirs = dash.discover()
    cards = [card(t) for t in tdirs]
    tot = Counter()
    for c in cards:
        for k in ("subdomains", "live_hosts", "urls", "endpoints"):
            st = c["funnel"][k]
            if st["state"] in ("lines", "rows", "demoted") and st["count"]:
                tot[k] += st["count"]
        tot["surface"] += c["surface"]
        tot["probes"] += c["probes"]
        tot["open_runs"] += c["open_runs"]
        tot["resume_points"] += c["resume_points"]
        tot["principals"] += c["principals"]
        for s in HYP_STATUSES:
            tot["hyp_" + s] += c["hypotheses"][s]
        for k, v in c["findings"].items():
            tot["findings_" + k] += v
        tot["blockers"] += len(c["blockers"])
    act = Counter()
    for c in cards:
        for a in c["activity"]:
            act[a["date"]] += a["n"]
    return {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "stale_days": STALE_DAYS,
        "totals": dict(tot) | {"targets": len(cards)},
        "activity": [{"date": d, "n": n} for d, n in sorted(act.items())],
        "targets": cards,
    }


# ------------------------------------------------------------------ cache

def cached_overview():
    now = time.monotonic()
    if _CACHE["overview"] is None or now - _CACHE["t"] > _CACHE_TTL:
        _CACHE["overview"] = overview()
        _CACHE["t"] = now
    return _CACHE["overview"]


def cached_detail(name):
    now = time.monotonic()
    hit = _CACHE["targets"].get(name)
    if hit is None or now - hit[0] > _CACHE_TTL:
        tdir = next((t for t in dash.discover() if t.name == name), None)
        if tdir is None:
            return None
        hit = (now, detail(tdir))
        _CACHE["targets"][name] = hit
    return hit[1]


def cached_extra(name, kind, arg=None):
    """hosts / endpoints / app payloads, cached per (target, kind, arg)."""
    now = time.monotonic()
    key = (name, kind, arg)
    hit = _CACHE["extras"].get(key)
    if hit is None or now - hit[0] > _CACHE_TTL:
        tdir = next((t for t in dash.discover() if t.name == name), None)
        if tdir is None:
            return None
        if kind == "hosts":
            hit = (now, hosts_payload(tdir))
        elif kind == "endpoints":
            hit = (now, endpoints_payload(tdir))
        else:
            hit = (now, app_payload(tdir, arg))
        _CACHE["extras"][key] = hit
    return hit[1]


# ------------------------------------------------------------------ VPS bridge (read-only)
#
# AGENTS.md: "Query the VPS live whenever you need something from it." The console does exactly
# that — READ-ONLY, over SSH, through the sanctioned interface (`tools/config.py ssh`); it never
# opens config.json, never writes the VPS, and never sends a packet to the target. Fetches are
# parsed remotely into compact extracts so bulk stays on the VPS, cached locally for a minute.

_VPS = {"checked": 0.0, "state": "not-configured", "prefix": None, "workdir": None}

# Runs ON the VPS against the newest httpx artifact; emits one compact JSON per live host.
# httpx JSONL field names are defensive (.get everywhere): tech may be a list or a string.
_HTTPX_REMOTE_PY = (
    "import sys,json\n"
    "for ln in open(sys.argv[1],encoding='utf-8',errors='replace'):\n"
    " ln=ln.strip()\n"
    " if not ln: continue\n"
    " try: d=json.loads(ln)\n"
    " except Exception: continue\n"
    " if isinstance(d,list): d=d[0] if d else {}\n"
    " u=str(d.get('url') or d.get('input') or '')\n"
    " h=str(d.get('host') or u).lower().strip()\n"
    " if not h: continue\n"
    " t=d.get('tech') or []\n"
    " if isinstance(t,str): t=[t]\n"
    " w=str(d.get('webserver') or '')\n"
    " parts=[p for p in (', '.join(str(x) for x in t),w) if p]\n"
    " print(json.dumps({'host':h,'url':u,'status':d.get('status_code'),"
    "'title':str(d.get('title') or ''),'tech':' | '.join(dict.fromkeys(parts)),"
    "'cdn':str(d.get('cdn_name') or '')}))\n"
)


def vps_status():
    """('ok' | 'not-configured', ssh argv, workdir) — resolved via tools/config.py, cached 30s."""
    now = time.monotonic()
    if _VPS["checked"] and now - _VPS["checked"] < 30:
        return _VPS
    _VPS.update(checked=now, state="not-configured", prefix=None, workdir=None)
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import config as _config                       # the sanctioned loader; config.json itself stays unread here
        if _config.load().get("vps.enabled"):
            r = subprocess.run([sys.executable, str(ROOT / "tools" / "config.py"), "ssh"],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0 and r.stdout.startswith("ssh "):
                _VPS.update(state="ok", prefix=r.stdout.split(),
                            workdir=str(_config.load().get("vps.workdir") or "~/targets"))
    except Exception:
        pass            # stays not-configured; the UI says exactly that
    return _VPS


def vps_remote(cmd, timeout=25):
    """(stdout | None, error | None). One ssh round trip; never raises."""
    st = vps_status()
    if st["state"] != "ok":
        return None, "not-configured"
    try:
        r = subprocess.run(st["prefix"] + [cmd], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "ssh timeout"
    except OSError as e:
        return None, f"ssh failed: {e}"[:120]
    if r.returncode != 0:
        return None, (r.stderr.strip() or f"remote exit {r.returncode}")[:200]
    return r.stdout, None


def cached_remote(key, ttl, fetch):
    """Success cached `ttl` seconds; errors cached 8s so a dead VPS is not hammered."""
    now = time.monotonic()
    hit = _CACHE["remote"].get(key)
    if hit is not None:
        age = now - hit[0]
        if hit[1].get("error") and age < 8:
            return hit[1]
        if not hit[1].get("error") and age < ttl:
            return hit[1]
    out = fetch()
    _CACHE["remote"][key] = (now, out)
    return out


def parse_extract_lines(lines):
    """The remote extract (compact JSON per line) → {host_key: row}. Testable locally."""
    out = {}
    for line in lines:
        try:
            row = json.loads(line)
        except (ValueError, TypeError):
            continue
        h = _host_key(row.get("host") or row.get("url"))
        if h and row.get("status") is not None:
            out[h] = {"status": str(row["status"]),
                      "title": row.get("title") or None,
                      "tech": row.get("tech") or None,
                      "url": row.get("url") or None}
    return out


def merge_enrichment(hosts, mapping):
    """Fill the hosts table's empty cells from the VPS artifact. Local brain facts win —
    observations are curated; the artifact fills gaps, never overrides. Returns count filled."""
    n = 0
    for h in hosts:
        e = mapping.get(h["host"])
        if not e:
            continue
        filled = False
        if not h["status"] and e["status"]:
            h["status"] = e["status"]; filled = True
        if not h["title"] and e["title"]:
            h["title"] = e["title"]; filled = True
        if not h["tech"] and e["tech"]:
            h["tech"] = e["tech"]; filled = True
        n += 1 if filled else 0
    return n


def httpx_enrichment(tdir):
    def fetch():
        st = vps_status()
        if st["state"] != "ok":
            return {"error": "not-configured", "hosts": {}}
        raw_dir = f"{st['workdir'].rstrip('/')}/{shlex.quote(tdir.name)}/raw/http"
        code = base64.b64encode(_HTTPX_REMOTE_PY.encode()).decode()
        cmd = (f'f=$(ls -t {raw_dir}/*.json {raw_dir}/*.jsonl 2>/dev/null | head -1); '
               f'[ -n "$f" ] && echo {code} | base64 -d | python3 - "$f" || true')
        out, err = vps_remote(cmd, timeout=60)
        if err:
            return {"error": err, "hosts": {}}
        return {"error": None, "hosts": parse_extract_lines((out or "").splitlines())}
    return cached_remote(("httpx", tdir.name), 60, fetch)


def vps_target_payload(tdir):
    """Raw-artifact inventory + pending monitor deltas for one target — one cache entry each."""
    def fetch_inventory():
        st = vps_status()
        if st["state"] != "ok":
            return {"error": "not-configured", "files": [], "monitor_deltas": 0}
        base = f"{st['workdir'].rstrip('/')}/{shlex.quote(tdir.name)}"
        name = shlex.quote(tdir.name)
        cmd = (
            f'for d in {base}/raw/*/; do [ -d "$d" ] || continue; '
            f'n=$(basename "$d"); find "$d" -maxdepth 1 -type f -printf "%s\\t%TY-%Tm-%Td\\t$n\\t%P\\n"; done 2>/dev/null; '
            f'p="$HOME"/targets/{name}/monitor-pending.md; [ -f "$p" ] || p={base}/monitor-pending.md; '
            f'[ -f "$p" ] && printf "MONITOR\\t%s\\n" "$(grep -c "^## " "$p")"; true'
        )
        out, err = vps_remote(cmd, timeout=30)
        if err:
            return {"error": err, "files": [], "monitor_deltas": 0}
        files, deltas = [], 0
        for line in (out or "").splitlines():
            parts = line.split("\t")
            if parts[0] == "MONITOR" and len(parts) > 1:
                try: deltas = int(parts[1])
                except ValueError: pass
                continue
            if len(parts) == 4 and parts[0].isdigit():
                files.append({"size": int(parts[0]), "date": parts[1], "dir": parts[2], "file": parts[3]})
        files.sort(key=lambda f: (f["dir"], f["file"]))
        return {"error": None, "files": files, "monitor_deltas": deltas}

    def fetch_monitor():
        st = vps_status()
        if st["state"] != "ok":
            return {"error": "not-configured", "markdown": None}
        name = shlex.quote(tdir.name)
        base = f"{st['workdir'].rstrip('/')}/{name}"
        cmd = (f'p="$HOME"/targets/{name}/monitor-pending.md; [ -f "$p" ] || p={base}/monitor-pending.md; '
               f'[ -f "$p" ] && cat "$p" || true')
        out, err = vps_remote(cmd, timeout=25)
        if err:
            return {"error": err, "markdown": None}
        return {"error": None, "markdown": (out or "").strip() or None}

    return {"inventory": cached_remote(("inv", tdir.name), 60, fetch_inventory),
            "monitor": cached_remote(("mon", tdir.name), 60, fetch_monitor)}


# ------------------------------------------------------------------ http

STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}
VERBOSE = False


class Handler(BaseHTTPRequestHandler):
    server_version = "HunterStickConsole/1.0"

    def log_message(self, fmt, *args):
        if VERBOSE:
            super().log_message(fmt, *args)

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False, default=str).encode(),
                   "application/json; charset=utf-8")

    def do_GET(self):  # noqa: N802 — stdlib naming
        path = urlparse(self.path).path
        try:
            if path in STATIC:
                fname, ctype = STATIC[path]
                f = ROOT / "web" / fname
                if not f.is_file():
                    return self._json({"error": f"web/{fname} is missing"}, 500)
                return self._send(200, f.read_bytes(), ctype)
            if path == "/api/health":
                return self._json({"ok": True, "when": datetime.now().isoformat(timespec="seconds")})
            if path == "/api/overview":
                return self._json(cached_overview())
            if path == "/api/vps":
                st = vps_status()
                return self._json({"state": st["state"], "workdir": st["workdir"]})
            m = re.fullmatch(r"/api/target/([^/]+)/vps", path)
            if m:
                tdir = next((t for t in dash.discover() if t.name == unquote(m.group(1))), None)
                if tdir is None:
                    return self._json({"error": "unknown target"}, 404)
                return self._json(vps_target_payload(tdir))
            m = re.fullmatch(r"/api/target/([^/]+)", path)
            if m:
                name = unquote(m.group(1))
                payload = cached_detail(name)      # None unless name is a discovered brain
                if payload is None:
                    return self._json({"error": f"unknown target {name!r}"}, 404)
                return self._json(payload)
            m = re.fullmatch(r"/api/target/([^/]+)/hosts", path)
            if m:
                payload = cached_extra(unquote(m.group(1)), "hosts")
                return self._json(payload) if payload else self._json({"error": "unknown target"}, 404)
            m = re.fullmatch(r"/api/target/([^/]+)/endpoints", path)
            if m:
                payload = cached_extra(unquote(m.group(1)), "endpoints")
                return self._json(payload) if payload else self._json({"error": "unknown target"}, 404)
            m = re.fullmatch(r"/api/target/([^/]+)/app/(.+)", path)
            if m:
                payload = cached_extra(unquote(m.group(1)), "app", unquote(m.group(2)))
                return self._json(payload) if payload else self._json({"error": "unknown target"}, 404)
            return self._json({"error": "not found", "path": path}, 404)
        except BrokenPipeError:
            pass
        except Exception:
            if VERBOSE:
                traceback.print_exc()
            return self._json({"error": "internal error — run with --verbose for the trace"}, 500)


def main():
    global VERBOSE
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (default 127.0.0.1 — local only)")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--verbose", action="store_true", help="log every request")
    args = ap.parse_args()
    VERBOSE = args.verbose

    tdirs = dash.discover()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"  HunterStick console  →  http://{args.host}:{args.port}")
    print(f"  {len(tdirs)} target(s): {', '.join(t.name for t in tdirs) or 'none'}")
    print("  read-only · recomputed per request · accounts summarized, never rendered")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  bye")
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
