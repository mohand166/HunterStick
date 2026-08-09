#!/usr/bin/env python3
"""Render one target brain as a single self-contained HTML page — numbers, not prose.

    tools/dashboard.py targets/acme               # -> targets/acme/recon-review.html
    tools/dashboard.py targets/acme --stdout     # print instead of writing

Why this exists: the brain is ~10 markdown files. Reading them tells you the state; it does not
show you the *shape* of it — how 55,200 became 3,918, what is ranked, what is untested, what is
missing. This renders that in one screen.

Three honesty rules, the same ones the workspace runs on:

  1. Counts are COMPUTED from the files, never copied from index.md. Where index.md claims a
     different number, both are shown and the row is flagged. A dashboard that repeats a stale
     manifest is worse than no dashboard, because HTML looks authoritative.
  2. `missing` != `0` != `prose`. A missing file is a preflight failure waiting to happen; an
     empty one is a real result; a reasoning file with no table is neither.
  3. Everything is stamped, and inputs older than STALE_DAYS are called out. Numbers with no age
     are how a hunter ends up testing a surface that moved three weeks ago.

Local-only. Reads the brain; never opens config.json, never renders a credential, never touches
the network or the VPS.

Exit: 0 rendered · 2 unusable target directory.
"""
import argparse
import html
import re
import sys
from datetime import date, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import runlog   # noqa: E402
from scopelib import clean   # noqa: E402  (one normaliser, not three)


def rel(p):
    """Path relative to the workspace when it is inside it, absolute when it is not.

    A target brain may legitimately live outside this repo (a scratch dir, a mounted volume).
    `Path.relative_to` raises ValueError there, which crashed the tool at the very last line —
    after all the real work had already succeeded.
    """
    try:
        return p.relative_to(ROOT)
    except ValueError:
        return p
STALE_DAYS = 14

# file -> label, in funnel order. Everything the recon graph is supposed to produce.
DATA_FILES = [
    ("recon/root-domains.md", "root domains",      True),
    ("recon/subdomains.txt",  "subdomains",        True),
    ("recon/live-hosts.txt",  "live hosts",        True),
    ("recon/urls.txt",        "urls",              True),
    ("recon/parameters.txt",  "parameters",        True),
    ("recon/endpoints.md",    "notable endpoints", True),
    ("recon/ips-asn.md",      "IP / ASN",          False),
    ("recon/dns.md",          "DNS",               False),
    ("recon/ports.md",        "ports",             False),
    ("recon/technologies.md", "technologies",      False),
    ("recon/js-findings.md",  "JS findings",       False),
    ("recon/cloud.md",        "cloud assets",      False),
    ("recon/repos.md",        "repos / secrets",   False),
    ("clusters.md",           "backend clusters",  False),
]

SEP = re.compile(r"^\s*\|[\s|:-]+\|\s*$")


def read(p):
    try:
        return p.read_text(encoding="utf-8-sig", errors="replace")
    except Exception:
        return ""


def field(text, label):
    m = re.search(rf"^\s*-\s*\*\*{re.escape(label)}:?\*\*\s*(.+?)\s*$", text, re.M)
    if not m:
        return None
    v = re.sub(r"[`*]", "", m.group(1)).strip()
    return None if not v or v.startswith("<") else v


def table_rows(text):
    """Data rows of the first markdown table: list of cell-lists, header excluded."""
    text = clean(text)
    rows, header, seen_sep = [], None, False
    for line in text.splitlines():
        if not line.lstrip().startswith("|"):
            if seen_sep and rows:
                break
            continue
        if SEP.match(line):
            seen_sep = True
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if header is None:
            header = cells
            continue
        if seen_sep:
            rows.append(cells)
    return header or [], rows



def table_with(text, *required):
    """Rows of the FIRST table whose header contains every required column.

    Taking "the first table" is wrong the moment a file carries an explanatory one — a guidance
    table added to attack-surface.md made an empty template report 4 ranked entries, and
    suggest-flows stopped treating a brand-new target as new. Locate the table by its schema.
    """
    want = {r.lower() for r in required}
    block, out = [], []
    for line in clean(text).splitlines():
        if line.lstrip().startswith("|"):
            block.append(line)
            continue
        if block:
            hdr, rows = table_rows("\n".join(block))
            if want <= {re.sub(r"[*`]", "", h).strip().lower() for h in hdr}:
                return hdr, rows
            block = []
    if block:
        hdr, rows = table_rows("\n".join(block))
        if want <= {re.sub(r"[*`]", "", h).strip().lower() for h in hdr}:
            return hdr, rows
    return [], []


# Files whose PAYLOAD is the table — their schemas are defined in
# `playbooks/system/target-schema.md`. For these, an empty table means empty, however much
# explanatory prose surrounds it: `attack-surface.md` ships a page of guidance about variants and
# properties, and none of it means a single entrypoint has been ranked.
#
# Everything NOT on this list is judged on its prose, because a table there is incidental —
# `scope.md` is dense authority text that merely happens to carry an empty standing-decisions
# table, and treating it as empty blocks every phase on a fully-populated scope file.
TABLE_PAYLOAD = {
    "root-domains.md", "ips-asn.md", "dns.md", "ports.md", "technologies.md", "endpoints.md",
    "js-findings.md", "cloud.md", "repos.md", "components.md", "clusters.md",
    "attack-surface.md", "hypotheses.md", "tested.md", "user-flows.md",
}

def count_table_rows(text):
    """Data rows across EVERY table in the file — every table, not just the first.

    `table_rows()` returns the FIRST table only. That is right for schema lookups and wrong for
    counting: a reasoning file carries several tables, and counting one of them reported 5 rows
    for a `recon/dns.md` the manifest already said held 24. A header row is identified by the
    separator line that follows it, exactly as the awk does.
    """
    lines = clean(text).splitlines()
    n = 0
    for i, line in enumerate(lines):
        if not line.lstrip().startswith("|") or SEP.match(line):
            continue
        if SEP.match(lines[i + 1] if i + 1 < len(lines) else ""):
            continue                                    # header row
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if any(c and not _PLACEHOLDER_ONLY.match(c) for c in cells):
            n += 1
    return n


_PLACEHOLDER_ONLY = re.compile(r"^<.*>$")
_LEGEND = re.compile(r"^`[A-Za-z_][A-Za-z0-9_]*`\s*=")
_PLACEHOLDER = re.compile(r"<[^<>]*>")
_DECORATION = re.compile(r"[-*_:`|·.,()/\s]")


def has_real_prose(text):
    """Has a human actually written anything here, or is it still the scaffold?

    A brain file ships as a template of headings, blockquotes and `<fill this in>` slots. Counting
    those as content is the difference between `prose` (present — a skill may run) and `empty`
    (a required input that is missing). The rule: a line counts as content only once you strip the
    headings, blockquotes, tables and `<fill this in>` slots and something is still left. Every
    reader of a brain file must apply that ONE rule, because whatever reports a file's state and
    whatever gates a run on it have to agree. Two implementations disagreed once — `recon/dns.md`,
    an untouched template, read as `0` in one and as present in preflight, so
    `asn-and-ip-discovery` was cleared on an input that did not exist.
    """
    for line in text.splitlines():
        t = line.strip()
        if not t or t.startswith(("#", ">", "```", "<!--", "|")) or _LEGEND.match(t):
            continue
        stripped = _PLACEHOLDER.sub("", t)
        if stripped == t:
            return True                       # no placeholder at all -> real content
        r = _DECORATION.sub("", stripped)
        r = re.sub(r"[A-Za-z]", "", r)
        if r == "":
            continue                          # a label plus an empty slot
        return True
    return False


POINTER_SUFFIX = ".pointer.md"
_POINTER_LINES = re.compile(r"^(\d[\d,]*)\s+lines\b", re.M)


def pointer_for(path):
    """The `<name>.pointer.md` stub vps-sync.py leaves behind after a demote, or None."""
    p = path.parent / (path.name + POINTER_SUFFIX)
    return p if p.is_file() else None


def state_of(path):
    """(state, count) where state is missing | empty | rows | lines | prose | demoted.

    `demoted` is a file that IS populated but lives on the VPS: `vps-sync.py demote` moved it
    and left a `<name>.pointer.md` stub holding its line count. Without this, demoting a file —
    the thing vps-sync itself tells you to do — made every downstream tool report `missing`,
    and `missing` is a hard preflight blocker. A demoted file is present-but-remote, which is
    neither `missing` nor an ordinary local file, so it gets its own state rather than being
    quietly folded into `lines`.
    """
    if not path.exists():
        ptr = pointer_for(path)
        if ptr is not None:
            m = _POINTER_LINES.search(read(ptr))
            return "demoted", (int(m.group(1).replace(",", "")) if m else None)
        return "missing", None
    text = read(path)
    if path.suffix == ".txt":
        n = sum(1 for l in text.splitlines() if l.strip())
        return ("empty", 0) if n == 0 else ("lines", n)
    # Data rows -> count. Otherwise the file is `prose` only if a human actually wrote something
    # OUTSIDE the table scaffolding; an untouched template is `empty`.
    #
    # Note the rule deliberately is NOT "any table at all -> 0". That is safe for the schema files
    # in DATA_FILES and wrong everywhere else: `scope.md` is dense prose that happens to carry an
    # empty standing-decisions table, and the blunt rule marked it `empty`, which blocked every
    # skill on a scope file that was fully populated. Testing for real prose instead gives the same
    # answer on all 14 DATA_FILES *and* keeps mixed files correct.
    n_rows = count_table_rows(text)
    if n_rows:
        return "rows", n_rows
    if path.name in TABLE_PAYLOAD:
        return "empty", 0
    return ("prose", None) if has_real_prose(text) else ("empty", 0)


def claimed_counts(index_text):
    """What index.md says, keyed by file path — so we can flag disagreement."""
    out = {}
    for m in re.finditer(r"^\|\s*`([^`]+)`\s*\|[^|]*\|\s*([^|]+?)\s*\|", index_text, re.M):
        out[m.group(1)] = re.sub(r"[`*]", "", m.group(2)).strip()
    return out


def usable_principals(accounts_text):
    """Rows that are a real, usable login — NOT rows that merely plan one.

    `| user-a | standard | a@x | <set> | own |` is an intention, not an account. Counting it
    says two-principal work is possible when it is blocked. Same test as tools/brief.py.
    """
    hdr, rows = table_rows(accounts_text)
    keys = [re.sub(r"[*`]", "", h).strip().lower() for h in hdr]
    if "label" not in keys:
        return 0
    n = 0
    for r in rows:
        row = dict(zip(keys, [c.strip() for c in r]))
        if not row.get("label") or row["label"].startswith("<"):
            continue
        cred = row.get("credential_ref") or row.get("password") or ""
        cred = re.sub(r"[*`]", "", cred).strip()
        if not cred or cred.startswith("<") or cred in {"—", "-"}:
            continue                      # placeholder → not a usable principal
        if row.get("status", "").strip().lower() in {"blocked", "planned", "pending"}:
            continue
        n += 1
    return n


def age_days(stamp):
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})", stamp or "")
    if not m:
        return None
    try:
        return (date.today() - date(*map(int, m.groups()))).days
    except ValueError:
        return None


def e(s):
    return html.escape(str(s if s is not None else ""))


def md_inline(s):
    """Just enough markdown for table cells: **bold** and `code`."""
    s = e(s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"`(.+?)`", r"<code>\1</code>", s)
    return s


# ---------------------------------------------------------------- render

CSS = """
*{box-sizing:border-box}
body{margin:0;padding:2rem 1.25rem 4rem;font:15px/1.55 ui-sans-serif,-apple-system,'Segoe UI',sans-serif;
  background:#0f1115;color:#e6e8ee}
.wrap{max-width:1180px;margin:0 auto}
h1{font-size:1.45rem;margin:0 0 .15rem}
h2{font-size:.82rem;text-transform:uppercase;letter-spacing:.09em;color:#8b93a7;
  margin:2.4rem 0 .7rem;font-weight:600}
.sub{color:#8b93a7;font-size:.86rem;margin:0 0 .25rem}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.86em;
  background:#1b1f28;padding:.08em .34em;border-radius:3px}
.banner{border-left:3px solid;padding:.6rem .85rem;border-radius:0 5px 5px 0;margin:1rem 0;font-size:.88rem}
.warn{background:#2a1e12;border-color:#d98b3a;color:#f0cba0}
.bad{background:#2b1517;border-color:#d9534f;color:#f2b8b5}
.ok{background:#152318;border-color:#4caf6a;color:#a8dcb8}
.funnel{display:flex;flex-wrap:wrap;gap:.55rem;align-items:stretch;margin:.4rem 0 0}
.cell{background:#171b23;border:1px solid #262c38;border-radius:7px;padding:.7rem .95rem;min-width:118px}
.cell .n{font-size:1.55rem;font-weight:650;letter-spacing:-.02em}
.cell .l{font-size:.71rem;text-transform:uppercase;letter-spacing:.06em;color:#8b93a7;margin-top:.15rem}
.cell.is-missing{border-style:dashed;border-color:#5a3a3a}
.cell.is-missing .n{color:#d9534f;font-size:1.05rem}
.cell.is-prose .n{color:#7aa2d9;font-size:1.05rem}
.cell.is-empty .n{color:#8b93a7}
.arrow{align-self:center;color:#4a5265;font-size:1.1rem}
table{border-collapse:collapse;width:100%;font-size:.87rem;margin-top:.3rem}
th{text-align:left;font-weight:600;color:#8b93a7;font-size:.72rem;text-transform:uppercase;
  letter-spacing:.06em;padding:.4rem .55rem;border-bottom:1px solid #262c38}
td{padding:.48rem .55rem;border-bottom:1px solid #1c212b;vertical-align:top}
tr:hover td{background:#151922}
.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.score{font-weight:700}
.miss{color:#d9534f;font-weight:600}
.prose{color:#7aa2d9}
.zero{color:#8b93a7}
.demoted{color:#c8a45c}
.cell.is-demoted .n{color:#c8a45c}
.flag{color:#d98b3a;font-weight:600}
.pill{display:inline-block;padding:.06em .5em;border-radius:99px;font-size:.74rem;
  background:#1b1f28;border:1px solid #2c3341;color:#aab2c4;max-width:100%;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:bottom}
.tabs{display:flex;flex-wrap:wrap;gap:.3rem;margin:1.6rem 0 .2rem;
  border-bottom:1px solid #262c38;padding-bottom:.5rem}
.tab{font:inherit;font-size:.82rem;padding:.42rem .8rem;border-radius:6px;cursor:pointer;
  background:transparent;border:1px solid transparent;color:#8b93a7}
.tab:hover{color:#e6e8ee;background:#171b23}
.tab.on{background:#1b2130;border-color:#2f3950;color:#e6e8ee;font-weight:600}
.panel{display:none}
.panel.on{display:block}
.panel>h2{margin-top:1.1rem}
#q{width:100%;padding:.6rem .8rem;margin:1.1rem 0 .2rem;font:inherit;
  border:1px solid #262c38;border-radius:7px;background:#171b23;color:#e6e8ee}
#q::placeholder{color:#6b7387}
#q:focus{outline:2px solid #7aa2d9;outline-offset:1px}
#qhint{min-height:1.15em;font-size:.8rem}
section{transition:opacity .12s}
.foot{color:#666e80;font-size:.78rem;margin-top:2.5rem;border-top:1px solid #1c212b;padding-top:.9rem}
@media(prefers-color-scheme:light){
  body{background:#fbfbfd;color:#1a1d24}
  .cell{background:#fff;border-color:#e2e5ec}
  code{background:#eef0f4}
  th{border-color:#e2e5ec}td{border-color:#eef0f4}tr:hover td{background:#f5f6f9}
  .warn{background:#fdf5e8;color:#7a5010}.bad{background:#fdeceb;color:#8c1f1b}.ok{background:#eef8f0;color:#1e5c30}
  .sub,.l,th{color:#666e80}
}
"""


TAB_JS = """<script>
(function () {
  var tabs = [].slice.call(document.querySelectorAll('.tab'));
  var panels = [].slice.call(document.querySelectorAll('.panel'));
  function show(id) {
    tabs.forEach(function (t) { t.classList.toggle('on', t.dataset.panel === id); });
    panels.forEach(function (p) { p.classList.toggle('on', p.id === id); });
  }
  tabs.forEach(function (t) { t.onclick = function () { show(t.dataset.panel); }; });

  // A filter that searches only the visible tab would report "0 matches" while the row sits one
  // tab away. Typing therefore opens every panel; clearing restores the tab you were on.
  var q = document.getElementById('q');
  if (q) q.addEventListener('input', function () {
    var searching = q.value.trim() !== '';
    panels.forEach(function (p) { p.classList.toggle('on', searching || p.id === current()); });
    document.querySelector('.tabs').style.opacity = searching ? 0.4 : 1;
  });
  function current() {
    var on = tabs.filter(function (t) { return t.classList.contains('on'); })[0];
    return on ? on.dataset.panel : 'p0';
  }
})();
</script>"""

SEARCH_JS = """<script>
(function () {
  var q = document.getElementById('q'), hint = document.getElementById('qhint');
  if (!q) return;
  // every data row on the page, captured once — re-querying on each keystroke is what makes
  // a filter feel slow on a brain with a few thousand rows
  var rows = [].slice.call(document.querySelectorAll('table tr')).filter(function (r) {
    return !r.querySelector('th');
  });
  rows.forEach(function (r) { r.dataset.hay = r.textContent.toLowerCase(); });

  function apply() {
    var term = q.value.trim().toLowerCase();
    var shown = 0;
    rows.forEach(function (r) {
      var hit = !term || r.dataset.hay.indexOf(term) !== -1;
      r.style.display = hit ? '' : 'none';
      if (hit) shown++;
    });
    // a filter that hides rows silently is the same lie as a zero that means "missing"
    hint.textContent = term
      ? shown + ' of ' + rows.length + ' rows match "' + term + '"' +
        (shown === 0 ? ' — nothing on this page, which is not the same as nothing in the brain' : '')
      : '';
    document.querySelectorAll('table').forEach(function (tb) {
      var any = [].slice.call(tb.querySelectorAll('tr')).some(function (r) {
        return !r.querySelector('th') && r.style.display !== 'none';
      });
      var sec = tb.closest('section') || tb.parentElement;
      if (sec) sec.style.opacity = (term && !any) ? 0.35 : 1;
    });
  }
  q.addEventListener('input', apply);
  document.addEventListener('keydown', function (ev) {
    if (ev.key === '/' && document.activeElement !== q) { ev.preventDefault(); q.focus(); }
    if (ev.key === 'Escape') { q.value = ''; apply(); q.blur(); }
  });
})();
</script>"""


def tabify(html):
    """Split the page at each `<h2>` into tab panels.

    A brain with a few thousand rows renders as one column you scroll for a minute to find the
    section you wanted. The sections already exist — each `<h2>` is one — so this needs no change
    to how they are built: assemble as before, then cut on the headings.

    Everything before the first `<h2>` (title, status line, banners) stays pinned above the tabs,
    because a stale-brain warning that only shows on one tab is a warning nobody reads.
    """
    head, sep, rest = html.partition("<h2>")
    if not sep:
        return html                                   # nothing sectioned; leave it alone
    panels = []
    for chunk in ("<h2>" + rest).split("<h2>")[1:]:
        title, _, content = chunk.partition("</h2>")
        # the tab label is the heading before its first em dash — "Root domains — 14 apex(es)"
        # is a good heading and a terrible tab
        label = re.sub(r"<[^>]+>", "", title).split("—")[0].strip()
        panels.append((label, title, content))
    if len(panels) < 2:
        return html

    nav = ['<nav class="tabs" role="tablist">']
    for i, (label, _t, _c) in enumerate(panels):
        nav.append(f'<button class="tab{" on" if i == 0 else ""}" data-panel="p{i}" '
                   f'role="tab">{e(label)}</button>')
    nav.append("</nav>")

    out = [head, "\n".join(nav)]
    for i, (_l, title, content) in enumerate(panels):
        out.append(f'<section class="panel{" on" if i == 0 else ""}" id="p{i}">'
                   f'<h2>{title}</h2>{content}</section>')
    out.append(TAB_JS)
    return "\n".join(out)


def render(tdir):
    name = tdir.name
    idx = read(tdir / "index.md")
    claims = claimed_counts(idx)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    out = ['<meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width,initial-scale=1">',
           f"<title>{e(name)} — attack surface</title>", f"<style>{CSS}</style>",
           '<div class="wrap">', f"<h1>{e(name)} — attack surface</h1>",
           '<input id="q" type="search" autocomplete="off" spellcheck="false" '
           'placeholder="filter every table below — host, path, class, tech, anything">',
           '<p class="sub" id="qhint"></p>']

    prog = field(idx, "Program") or "—"
    arch = field(idx, "Archetype") or field(idx, "Scope type") or "—"
    phase = field(idx, "Last activity") or field(idx, "Current phase") or "—"
    upd = field(idx, "Last updated") or ""
    out.append(f'<p class="sub">{md_inline(prog)}</p>')
    out.append(f'<p class="sub"><span class="pill" title="{e(arch)}">{e(arch)}</span></p>')
    out.append(f'<p class="sub">{md_inline(phase)}</p>')

    a = age_days(upd)
    if a is None:
        out.append('<div class="banner bad">index.md has no <code>Last updated</code> date. '
                   'Every number below is of unknown age.</div>')
    elif a > STALE_DAYS:
        out.append(f'<div class="banner warn">Brain last updated <b>{e(upd)}</b> — {a} days ago. '
                   'State the age of the recon before testing anything off this page.</div>')

    # ---- funnel -----------------------------------------------------
    out.append("<h2>Collected</h2><div class=\"funnel\">")
    drift = []
    for i, (rel, label, in_funnel) in enumerate(DATA_FILES):
        if not in_funnel:
            continue
        st, n = state_of(tdir / rel)
        cls, txt = {"missing": ("is-missing", "missing"),
                    "empty":   ("is-empty", "0"),
                    "prose":   ("is-prose", "prose"),
                    "demoted": ("is-demoted", f"{n:,} ⇡" if n is not None else "on VPS"),
                    }.get(st, ("", f"{n:,}" if n is not None else "?"))
        if i:
            out.append('<span class="arrow">›</span>')
        out.append(f'<div class="cell {cls}"><div class="n">{txt}</div>'
                   f'<div class="l">{e(label)}</div></div>')
    out.append("</div>")

    # ---- inventory --------------------------------------------------
    out.append("<h2>Data inventory — computed, not copied</h2>"
               "<table><tr><th>file</th><th>what</th><th class=num>on disk</th>"
               "<th class=num>index.md claims</th><th></th></tr>")
    for rel, label, _ in DATA_FILES:
        st, n = state_of(tdir / rel)
        shown = {"missing": '<span class="miss">missing</span>',
                 "empty": '<span class="zero">0</span>',
                 "prose": '<span class="prose">prose</span>',
                 "demoted": (f'{n:,} <span class="demoted" title="on the VPS">⇡</span>'
                             if n is not None else '<span class="demoted">on VPS</span>'),
                 }.get(st, f"{n:,}" if n is not None else "?")
        claim = claims.get(rel, "—")
        note = ""
        # a demoted file's count is the number the pointer records — compare it as a number,
        # so index.md saying `44485` does not read as drift against a file that lives remotely
        norm_disk = {"missing": "missing", "empty": "0", "prose": "prose"}.get(st, str(n))
        if claim not in ("—", "") and re.sub(r"[^\w]", "", claim.lower()) != re.sub(r"[^\w]", "", norm_disk.lower()):
            # a prose file cannot be counted — the manifest's number is unverifiable, not wrong
            note = ('<span class="prose">⚠ unverifiable — prose</span>' if st == "prose"
                    else '<span class="flag">⚠ disagrees</span>')
            drift.append((rel, norm_disk, claim))
        out.append(f"<tr><td><code>{e(rel)}</code></td><td>{e(label)}</td>"
                   f"<td class=num>{shown}</td><td class=num>{e(claim)}</td><td>{note}</td></tr>")
    out.append("</table>")
    if drift:
        out.append(f'<div class="banner warn">{len(drift)} file(s) disagree with the manifest. '
                   'The <b>on disk</b> column is the fact; index.md holds decisions, not counts, '
                   'so delete the stale number rather than refreshing it.</div>')

    # ---- root domains -------------------------------------------------
    # A count in the funnel is not the answer to "which apexes are confirmed". The whole point of
    # the evidence table is that a reader can see the claim and its source side by side.
    roots = read(tdir / "recon/root-domains.md")
    rhdr, rrows = table_with(roots, "apex")
    if rrows:
        def cell(row, name):
            for i, h in enumerate(rhdr):
                if name in h.lower():
                    return (row[i] if i < len(row) else "").strip()
            return ""
        in_scope = [r for r in rrows if cell(r, "scope_status") == "in-scope"]
        unres = [r for r in rrows if "unresolved" in cell(r, "ownership")
                 or cell(r, "scope_status") in ("unknown", "not-listed")]
        out.append(f"<h2>Root domains — {len(rrows)} apex(es), {len(in_scope)} in scope, "
                   f"{len(unres)} unresolved</h2>")
        keep = [i for i, h in enumerate(rhdr)
                if re.sub(r"[^a-z_]", "", h.lower()) in
                ("apex", "ownership", "scope_status", "confidence") or "evidence" in h.lower()]
        keep = keep or list(range(len(rhdr)))
        out.append("<table><tr>" + "".join(f"<th>{e(rhdr[i])}</th>" for i in keep) + "</tr>")
        for r in rrows:
            st = cell(r, "scope_status")
            cls = (' class="is-missing"' if st == "out-of-scope" else
                   ' class="is-prose"' if st in ("unknown", "not-listed") else "")
            cells = "".join(f"<td>{md_inline(r[i] if i < len(r) else '')}</td>" for i in keep)
            out.append(f"<tr{cls}>{cells}</tr>")
        out.append("</table>")
        if unres:
            out.append('<div class="banner warn"><b>' + str(len(unres)) + ' apex(es) unresolved.'
                       '</b> Ownership or authorisation could not be established — do not touch '
                       'them. The settling check for each is in <code>recon/root-domains.md</code>.'
                       '</div>')
    else:
        out.append("<h2>Root domains</h2>")
        out.append('<div class="banner bad">No apex has been recorded with evidence yet. '
                   '<code>organization-and-roots</code> writes <code>recon/root-domains.md</code>; '
                   'a domain that merely '
                   'carries the company name is not a root.</div>')

    # ---- takeover candidates ----------------------------------------------
    # `dns-analysis`'s highest-value output. It was invisible here: the page summarised counts and
    # never showed the one thing a hunter would act on next.
    dns_text = read(tdir / "recon" / "dns.md")
    thdr, trows = table_with(dns_text, "host", "takeover_candidate")
    cand = []
    for r in trows:
        val = ""
        for i, h in enumerate(thdr):
            if "takeover_candidate" in h.lower():
                val = (r[i] if i < len(r) else "").strip().lower()
        if val and val not in ("no", "-", "—", "n/a", ""):
            cand.append(r)
    if trows:
        out.append(f"<h2>Takeover candidates — {len(cand)} of {len(trows)} DNS record(s)</h2>")
        if cand:
            out.append('<div class="banner warn"><b>A dangling record is a CANDIDATE, never a '
                       'confirmed takeover.</b> Confirming one means claiming the third-party '
                       'resource — intrusive, and only on explicit authorisation.</div>')
            out.append("<table><tr>" + "".join(f"<th>{e(h)}</th>" for h in thdr) + "</tr>")
            for r in cand:
                cells = "".join(f"<td>{md_inline(r[i] if i < len(r) else '')}</td>"
                                for i in range(len(thdr)))
                out.append(f'<tr class="is-prose">{cells}</tr>')
            out.append("</table>")
        else:
            out.append('<div class="banner">DNS records recorded, none flagged as a takeover '
                       'candidate.</div>')

    # ---- where the data actually lives ------------------------------------
    # "Why isn't the subdomain list here?" is a question this page caused, so it should answer it.
    out.append("<h2>Where the data lives</h2>")
    out.append('<div class="banner">Bulk lists live on the VPS; the brain keeps a count and a '
               'pointer. <code>tools/vps-sync.py pull &lt;target&gt;</code> brings one back.</div>')
    out.append("<table><tr><th>file</th><th>state</th><th>location</th></tr>")
    for rel, label, _ in DATA_FILES:
        st, n = state_of(tdir / rel)
        if st == "missing":
            continue
        if st == "demoted":
            ptr = pointer_for(tdir / rel)
            loc = ""
            m = re.search(r"^\s{2,}(\S+)\s*$", read(ptr), re.M) if ptr else None
            loc = m.group(1) if m else "on the VPS"
            where = f'<span class="demoted">{e(loc)}</span>'
        else:
            where = f"<code>{e(str(rel))}</code> (local)"
        out.append(f"<tr><td>{e(label)}</td><td class=num>"
                   f"{n if n is not None else st}</td><td>{where}</td></tr>")
    out.append("</table>")

    # ---- ranked surface ---------------------------------------------
    surf = read(tdir / "attack-surface.md")
    hdr, rows = table_with(surf, "entrypoint", "vuln_class")
    out.append(f"<h2>Ranked surface — {len(rows)} entr{'y' if len(rows)==1 else 'ies'}</h2>")
    if not rows:
        out.append('<div class="banner bad">No ranked surface. '
                   '<code>attack-surface-prioritization</code> has not run, so any '
                   'model-chosen test would be picking by whatever it happened to notice.</div>')
    else:
        keep = [i for i, h in enumerate(hdr)
                if re.sub(r"[^a-z]", "", h.lower()) in
                ("rank", "score", "entrypoint", "clusterrepresentativehosts", "cluster")
                or "why" in h.lower() or "entrypoint" in h.lower()]
        keep = keep or list(range(len(hdr)))
        out.append("<table><tr>" + "".join(f"<th>{e(hdr[i])}</th>" for i in keep) + "</tr>")
        for r in rows:
            cells = []
            for i in keep:
                v = r[i] if i < len(r) else ""
                sc = ' class="score"' if "score" in hdr[i].lower() else ""
                cells.append(f"<td{sc}>{md_inline(v)}</td>")
            out.append("<tr>" + "".join(cells) + "</tr>")
        out.append("</table>")

    # ---- backlog / coverage -----------------------------------------
    hyp = read(tdir / "hypotheses.md")
    _, hrows = table_rows(hyp)
    by = {}
    for r in hrows:
        s = next((c.strip().lower() for c in r if c.strip().lower()
                  in ("open", "testing", "confirmed", "rejected")), "unstated")
        by[s] = by.get(s, 0) + 1

    _, trows = table_rows(read(tdir / "tested.md"))
    trows = [r for r in trows if any(c.strip() for c in r)]

    conf = tdir / "findings" / "confirmed"
    nconf = len([p for p in conf.glob("*.md")]) if conf.is_dir() else 0

    nprin = usable_principals(read(tdir / "accounts.md"))

    out.append("<h2>Testing state</h2><div class=\"funnel\">")
    for n, l in ((len(hrows), "hypotheses"), (len(trows), "probes logged"),
                 (nconf, "confirmed"), (nprin, "usable principals")):
        cls = " is-empty" if n == 0 else ""
        out.append(f'<div class="cell{cls}"><div class="n">{n}</div><div class="l">{e(l)}</div></div>')
    for s in ("open", "testing", "confirmed", "rejected"):
        if s in by:
            out.append(f'<div class="cell"><div class="n">{by[s]}</div>'
                       f'<div class="l">{s}</div></div>')
    out.append("</div>")

    if nprin < 2:
        out.append(f'<div class="banner warn">Only {nprin} <b>usable</b> principal(s) in '
                   '<code>accounts.md</code> — rows whose credential is still a placeholder are '
                   'plans, not accounts. Authz / IDOR / multi-tenant / privesc work is '
                   '<b>blocked</b>, not untested: a clean "not vulnerable" from one account is '
                   'not a result.</div>')
    if len(trows) == 0 and rows:
        out.append('<div class="banner warn">Surface is ranked but <code>tested.md</code> is empty — '
                   'nothing has been probed yet. Coverage is 0%, not unknown.</div>')

    # ---- blockers ----------------------------------------------------
    blk = [m.group(0).strip() for m in re.finditer(r"TBD\s*—\s*blocking:[^\n|]*", idx)]
    sec = re.search(r"^##+\s*Blocking\s*/?\s*TBD.*?$(.*?)(?=^##|\Z)", idx, re.M | re.S)
    if sec:
        blk += [l.strip(" -*\t") for l in sec.group(1).splitlines()
                if l.strip(" -*\t") and not l.strip(" -*\t").startswith("<")]
    if blk:
        out.append("<h2>Blocking</h2><ul>")
        out += [f"<li>{md_inline(b)}</li>" for b in blk]
        out.append("</ul>")

    out.append(f'<p class="foot">Generated {now} by <code>tools/dashboard.py</code> from '
               f'<code>targets/{e(name)}/</code>. Read-only view — the markdown is the source of '
               f'truth. Counts in the <b>on disk</b> column are computed from the files at '
               f'generation time; raw bulk output lives on the VPS and is not counted here.</p>')
    body = tabify("\n".join(out))
    return body + "\n" + SEARCH_JS + "\n</div>"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="path to targets/<name>")
    ap.add_argument("--stdout", action="store_true", help="print instead of writing the file")
    args = ap.parse_args()

    tdir = Path(args.target).resolve()
    if not tdir.is_dir():
        print(f"FAIL — no directory {args.target}", file=sys.stderr)
        return 2
    if not (tdir / "index.md").exists():
        print(f"FAIL — {args.target} has no index.md; is it a target brain?", file=sys.stderr)
        return 2

    page = render(tdir)
    if args.stdout:
        print(page)
        return 0
    dest = tdir / "recon-review.html"
    dest.write_text(page, encoding="utf-8")
    print(f"  wrote {rel(dest)}  ({len(page):,} bytes)")
    print(f"  open it:  open {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(runlog.wrap()(main)())
