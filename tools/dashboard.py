#!/usr/bin/env python3
"""Render the target brains as HTML — one page per target, or one SPA over all of them.

    tools/dashboard.py targets/acme               # -> targets/acme/recon-review.html
    tools/dashboard.py targets/acme --stdout      # print instead of writing
    tools/dashboard.py --all                      # -> dashboard.html (workspace SPA)

The SPA is the hunter's cockpit: a sidebar with every target, click one and its dashboard loads
into the main area with no reload (hash-routed, so refresh and back stay where you were). Each
target view answers, in order: where do we stand, what is running, what has been run, what is
the attack surface, what does progress.md say. Raw bulk output stays on the VPS — this renders
the brain only.

Three honesty rules, the same ones the workspace runs on:

  1. Counts are COMPUTED from the files, never copied from index.md. Where index.md claims a
     different number, both are shown and the row is flagged. A dashboard that repeats a stale
     manifest is worse than no dashboard, because HTML looks authoritative.
  2. `missing` != `0` != `prose`. A missing file is a preflight failure waiting to happen; an
     empty one is a real result; a reasoning file with no table is neither.
  3. Everything is stamped, and inputs older than STALE_DAYS are called out. Numbers with no age
     are how a hunter ends up testing a surface that moved three weeks ago.

Local-only. Reads the brain; never opens config.json, never renders a credential, never touches
the network or the VPS. accounts.md is summarized (usable principals), never rendered raw — the
one brain file that carries credential references.

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

# The Files tab: every brain artifact a hunter might wonder about, with state and age. Order is
# reading order, not importance — importance is what the tabs above it are for.
BRAIN_FILES = [
    "index.md", "scope.md", "target.md", "accounts.md", "progress.md", "runbook.md",
    "tech-watch.md", "attack-surface.md", "hypotheses.md", "tested.md", "clusters.md",
    "user-flows.md", "runs.tsv", "observations.tsv",
] + [rel for rel, _l, _f in DATA_FILES]

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


def unfilled(value):
    """A manifest field nobody actually filled in, as opposed to a real value.

    `index.md`'s template ships fields like `**Archetype:** <single-app | huge-wildcard | ...> ->
    routes via playbooks/system/phase-routing.md` — the "-> routes via ..." tail is boilerplate
    written for the NEXT MODEL SESSION to read, meant to survive even after the bracketed slot is
    filled in with a real choice; a hunter who never got around to classifying the archetype at
    all just leaves the bracket as `unknown` and the routing tail stays attached. The header of
    every target page used to print that whole sentence verbatim into a badge, so a routing
    instruction meant for the model became the first thing a human reads.

    Unlike the funnel's `missing` cells — which mean "you haven't run this yet, go run it" and are
    worth a loud dashed-red flag — Program/Archetype are optional metadata with nothing to run.
    `render()` uses this to omit the line entirely rather than announce an unset one; a hunter who
    wants it filled in edits `index.md` directly.
    """
    v = (value or "").strip()
    if not v or v in ("—", "-"):
        return True
    if _PLACEHOLDER_ONLY.match(v):
        return True
    low = v.lower()
    if low in ("not supplied", "not stated", "not stated by the program yet", "unknown"):
        return True
    if low.startswith("unknown") and "routes via" in low:
        return True
    return False


def has_real_prose(text):
    """Has a human actually written anything here, or is it still the scaffold?

    A brain file ships as a template of headings, blockquotes and `<fill this in>` slots. Counting
    those as content is the difference between `prose` (present — a skill may run) and `empty`
    (a required input that is missing). The rule: a line counts as content only once you strip the
    headings, blockquotes, tables and `<fill this in>` slots and something is still left. Every
    reader of a brain file must apply that ONE rule, because whatever reports a file's state and
    whatever gates a run on it have to agree. Two implementations disagreed once — `recon/dns.md`,
    an untouched template, read as `0` in one and as present in preflight, so `asn-and-ip-discovery`
    was cleared on an input that did not exist.
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


# --------------------------------------------------------------- markdown-lite renderer

def md_to_html(text):
    """Just enough markdown for the prose-and-table brain files: headings, tables, lists,
    quotes, fences, paragraphs. The brain's load-bearing format is the table; everything else
    only has to be readable. Escaped-first: target-controlled content is rendered, never run.
    """
    out, lines, i, para = [], text.splitlines(), 0, []
    in_code, code_buf = False, []

    def flush_para():
        if para:
            out.append("<p>" + md_inline(" ".join(para)) + "</p>")
            para.clear()

    while i < len(lines):
        ln = lines[i]
        if ln.strip().startswith("```"):
            flush_para()
            if in_code:
                out.append("<pre>" + e("\n".join(code_buf)) + "</pre>")
                code_buf, in_code = [], False
            else:
                in_code = True
            i += 1
            continue
        if in_code:
            code_buf.append(ln)
            i += 1
            continue
        s = ln.strip()
        if not s:
            flush_para()
        elif s.startswith("|"):
            flush_para()
            block = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                block.append(lines[i])
                i += 1
            hdr, rows = table_rows("\n".join(block))
            if hdr:
                out.append("<table><tr>" + "".join(f"<th>{md_inline(h)}</th>" for h in hdr)
                           + "</tr>")
                for r in rows:
                    out.append("<tr>" + "".join(f"<td>{md_inline(c)}</td>"
                                                for c in (list(r) + [""] * len(hdr))[:len(hdr)])
                               + "</tr>")
                out.append("</table>")
            continue
        elif s.startswith("####"):
            flush_para(); out.append(f"<h4>{md_inline(s.lstrip('#').strip())}</h4>")
        elif s.startswith("###"):
            flush_para(); out.append(f"<h3>{md_inline(s.lstrip('#').strip())}</h3>")
        elif s.startswith("##"):
            flush_para(); out.append(f"<h2x>{md_inline(s.lstrip('#').strip())}</h2x>")
        elif s.startswith("#"):
            flush_para(); out.append(f"<h3>{md_inline(s.lstrip('#').strip())}</h3>")
        elif s.startswith(">"):
            flush_para(); out.append(f"<blockquote>{md_inline(s.lstrip('>').strip())}</blockquote>")
        elif re.match(r"^[-*]\s+", s):
            flush_para()
            items = []
            while i < len(lines) and re.match(r"^[-*]\s+", lines[i].strip()):
                items.append(f"<li>{md_inline(re.sub(r'^[-*]\\s+', '', lines[i].strip()))}</li>")
                i += 1
            out.append("<ul>" + "".join(items) + "</ul>")
            continue
        else:
            para.append(s)
        i += 1
    if in_code and code_buf:
        out.append("<pre>" + e("\n".join(code_buf)) + "</pre>")
    flush_para()
    return "\n".join(out)


# ---------------------------------------------------------------- render: one target

CSS = """
*{box-sizing:border-box;min-width:0}
body{margin:0;padding:2rem 1.25rem 4rem;font:15px/1.55 ui-sans-serif,-apple-system,'Segoe UI',sans-serif;
  background:#0f1115;color:#e6e8ee;overflow-wrap:anywhere}
.wrap{max-width:1180px;margin:0 auto}
h1{font-size:1.45rem;margin:0 0 .15rem}
h2{font-size:.82rem;text-transform:uppercase;letter-spacing:.09em;color:#8b93a7;
  margin:2.4rem 0 .7rem;font-weight:600}
h2x{display:block;font-size:1.02rem;font-weight:650;color:#c8cede;margin:1.5rem 0 .5rem}
h3,h4{margin:1.2rem 0 .4rem}
blockquote{border-left:3px solid #2c3341;margin:.5rem 0;padding:.2rem .8rem;color:#9aa2b5}
pre{background:#171b23;border:1px solid #262c38;border-radius:6px;padding:.7rem .9rem;
  overflow:auto;font-size:.84em}
.sub{color:#8b93a7;font-size:.86rem;margin:0 0 .25rem;max-width:75ch}
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
  background:#1b1f28;border:1px solid #2c3341;color:#aab2c4;max-width:min(100%,32rem);
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

SPA_CSS = """
body.spa{padding:0;display:grid;grid-template-columns:264px minmax(0,1fr);min-height:100vh}
#side{border-right:1px solid #1c212b;padding:1.1rem .9rem;position:sticky;top:0;
  height:100vh;overflow-y:auto;background:#0d0f13;color:#e6e8ee}
#side h1{font-size:1rem;margin:.2rem 0 1rem;letter-spacing:.02em}
#tq{width:100%;padding:.45rem .6rem;margin-bottom:.7rem;font:inherit;font-size:.85rem;
  border:1px solid #262c38;border-radius:6px;background:#171b23;color:#e6e8ee}
.titem{display:block;padding:.5rem .6rem;border-radius:6px;color:#c8cede;
  text-decoration:none;margin-bottom:.15rem;border:1px solid transparent}
.titem:hover{background:#171b23}
.titem.on{background:#1b2130;border-color:#2f3950;color:#fff;font-weight:600}
.titem .chips{display:block;margin-top:.18rem;font-size:.7rem;color:#7d8598}
.chip{display:inline-block;padding:.02em .45em;border-radius:99px;margin-right:.25em;
  border:1px solid #2c3341;background:#151923}
.chip.bad{color:#f2b8b5;border-color:#5a3a3a;background:#2b1517}
.chip.warn{color:#f0cba0;border-color:#5a4426;background:#2a1e12}
#main{padding:1.6rem 1.6rem 4rem;min-width:0}
.tview{display:none;max-width:1180px}
.tview.on{display:block}
@media(max-width:860px){
  body.spa{grid-template-columns:1fr}
  #side{position:static;height:auto;border-right:0;border-bottom:1px solid #1c212b}
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

# The SPA shell's JS: hash routing (no reload), event-delegated tabs, one search scoped to the
# active target's rows. Deliberately dumb — a static page must stay a static page.
SPA_JS = """<script>
(function () {
  var views = [].slice.call(document.querySelectorAll('.tview'));
  var items = [].slice.call(document.querySelectorAll('.titem'));
  var q = document.getElementById('q'), hint = document.getElementById('qhint');
  var tq = document.getElementById('tq');
  var rowCache = {};

  function rowsFor(view) {
    if (!rowCache[view.id]) {
      rowCache[view.id] = [].slice.call(view.querySelectorAll('table tr')).filter(function (r) {
        return !r.querySelector('th');
      });
      rowCache[view.id].forEach(function (r) { r.dataset.hay = r.textContent.toLowerCase(); });
    }
    return rowCache[view.id];
  }

  function select(id) {
    var found = false;
    views.forEach(function (v) { var on = v.id === id; if (on) found = true; v.classList.toggle('on', on); });
    if (!found && views.length) select(views[0].id);
    items.forEach(function (it) { it.classList.toggle('on', it.getAttribute('href') === '#/' + activeId()); });
    if (q) { q.value = ''; if (hint) hint.textContent = ''; applySearch(); }
    document.title = (activeName() || 'HunterStick') + ' — dashboard';
  }
  function activeId() {
    var on = views.filter(function (v) { return v.classList.contains('on'); })[0];
    return on ? on.id : '';
  }
  function activeName() {
    var on = views.filter(function (v) { return v.classList.contains('on'); })[0];
    return on ? (on.dataset.name || '') : '';
  }

  function applySearch() {
    if (!q) return;
    var view = views.filter(function (v) { return v.classList.contains('on'); })[0];
    if (!view) return;
    var term = q.value.trim().toLowerCase();
    var rows = rowsFor(view), shown = 0;
    rows.forEach(function (r) {
      var hit = !term || r.dataset.hay.indexOf(term) !== -1;
      r.style.display = hit ? '' : 'none';
      if (hit) shown++;
    });
    if (hint) hint.textContent = term
      ? shown + ' of ' + rows.length + ' rows in ' + activeName() + ' match "' + term + '"' +
        (shown === 0 ? ' — nothing on this page, which is not the same as nothing in the brain' : '')
      : '';
    // a search must reach every tab of this target, not just the visible one
    var searching = term !== '';
    view.querySelectorAll('.panel').forEach(function (p) {
      var any = [].slice.call(p.querySelectorAll('table tr')).some(function (r) {
        return !r.querySelector('th') && r.style.display !== 'none';
      });
      p.style.opacity = (searching && !any) ? 0.35 : 1;
    });
  }
  if (q) {
    q.addEventListener('input', applySearch);
    document.addEventListener('keydown', function (ev) {
      if (ev.key === '/' && document.activeElement !== q) { ev.preventDefault(); q.focus(); }
      if (ev.key === 'Escape') { q.value = ''; applySearch(); q.blur(); }
    });
  }
  if (tq) tq.addEventListener('input', function () {
    var t = tq.value.trim().toLowerCase();
    items.forEach(function (it) {
      it.style.display = !t || it.dataset.hay.indexOf(t) !== -1 ? '' : 'none';
    });
  });

  // tabs: delegated, because every target renders its own tab set
  document.addEventListener('click', function (ev) {
    var t = ev.target.closest('.tab');
    if (!t) return;
    var view = t.closest('.tview');
    view.querySelectorAll('.tab').forEach(function (x) { x.classList.toggle('on', x === t); });
    view.querySelectorAll('.panel').forEach(function (p) {
      p.classList.toggle('on', p.dataset.panel === t.dataset.panel);
    });
  });

  function fromHash() {
    var name = (location.hash || '').replace(/^#\\//, '').split('/')[0];
    var id = 'tv-' + (name || '').toLowerCase().replace(/[^a-z0-9-]/g, '-');
    select(id);
  }
  window.addEventListener('hashchange', fromHash);
  fromHash();
})();
</script>"""


def tabify(html_text, prefix="", include_tab_js=True):
    """Split the page at each `<h2>` into tab panels.

    A brain with a few thousand rows renders as one column you scroll for a minute to find the
    section you wanted. The sections already exist — each `<h2>` is one — so this needs no change
    to how they are built: assemble as before, then cut on the headings.

    Everything before the first `<h2>` (title, status line, banners) stays pinned above the tabs,
    because a stale-brain warning that only shows on one tab is a warning nobody reads.
    `prefix` keeps panel ids unique when several targets live in one SPA page.
    """
    head, sep, rest = html_text.partition("<h2>")
    if not sep:
        return html_text                                   # nothing sectioned; leave it alone
    panels = []
    for chunk in ("<h2>" + rest).split("<h2>")[1:]:
        title, _, content = chunk.partition("</h2>")
        # the tab label is the heading before its first em dash — "Root domains — 14 apex(es)"
        # is a good heading and a terrible tab
        label = re.sub(r"<[^>]+>", "", title).split("—")[0].strip()
        panels.append((label, title, content))
    if len(panels) < 2:
        return html_text

    nav = ['<nav class="tabs" role="tablist">']
    for i, (label, _t, _c) in enumerate(panels):
        nav.append(f'<button class="tab{" on" if i == 0 else ""}" data-panel="{prefix}p{i}" '
                   f'role="tab">{e(label)}</button>')
    nav.append("</nav>")

    out = [head, "\n".join(nav)]
    for i, (_l, title, content) in enumerate(panels):
        out.append(f'<section class="panel{" on" if i == 0 else ""}" id="{prefix}p{i}" '
                   f'data-panel="{prefix}p{i}"><h2>{title}</h2>{content}</section>')
    if include_tab_js:
        out.append(TAB_JS)
    return "\n".join(out)


# ---- runs: what is running / what has been run -------------------------------------------

RUN_CAP = 300          # rows shown per target; more than this is unreadable, not informative


def _runs(tdir):
    from kb import read_runs       # same parser brief.py trusts; one csv schema, one reader
    latest = {}
    for r in read_runs(tdir):
        latest[r["run_id"]] = r
    return list(latest.values())


def running_section(tdir):
    """Open runs, resume points, and recent tool failures — the three things that need a human
    before anything new starts. Mirrors brief.py's resume buckets so the page and the CLI can
    never disagree silently (both read runs.tsv)."""
    runs = _runs(tdir)
    open_runs = [r for r in runs if r.get("status") == "running"]
    resume = [r for r in runs if r.get("status") in ("partial", "failed") and r.get("resume_from")]
    out = [f"<h2>What is running — {len(open_runs)} open, {len(resume)} resume point(s)</h2>"]
    if open_runs:
        out.append('<div class="banner bad">A run left <b>RUNNING</b> may already have sent '
                   'traffic. Check the VPS before re-running it.</div>')
        out.append("<table><tr><th>run</th><th>date</th><th>objective</th><th>selector</th>"
                   "<th>resume from</th></tr>")
        for r in open_runs:
            out.append(f"<tr><td><code>{e(r['run_id'])}</code></td><td>{e(r['date'])}</td>"
                       f"<td>{md_inline(r['phase'])}</td><td>{md_inline(r['selector'])}</td>"
                       f"<td>{md_inline(r.get('resume_from') or '—')}</td></tr>")
        out.append("</table>")
    if resume:
        out.append("<table><tr><th>run</th><th>status</th><th>objective</th><th>selector</th>"
                   "<th>resume from</th></tr>")
        for r in resume:
            out.append(f"<tr><td><code>{e(r['run_id'])}</code></td><td>{e(r['status'])}</td>"
                       f"<td>{md_inline(r['phase'])}</td><td>{md_inline(r['selector'])}</td>"
                       f"<td>{md_inline(r['resume_from'])}</td></tr>")
        out.append("</table>")
    if not open_runs and not resume:
        out.append('<div class="banner ok">No unfinished work — every run was closed.</div>')
    try:
        bad = [r for r in runlog.read_log(tdir) if r["exit"] not in ("0", "")]
        if bad:
            out.append(f'<div class="banner warn">{len(bad)} tool invocation(s) exited non-zero '
                       '(last 5 below). Whatever depended on them may have been written anyway — '
                       '<code>tools/runlog.py &lt;t&gt; --failures</code>.</div>')
            out.append("<table><tr><th>when</th><th>tool</th><th>command</th><th>exit</th></tr>")
            for r in bad[-5:]:
                out.append(f"<tr><td>{e(r['ts'][:16])}</td><td><code>{e(r['tool'])}</code></td>"
                           f"<td>{md_inline(r['argv'][:80])}</td>"
                           f"<td class=num>{e(r['exit'])}</td></tr>")
            out.append("</table>")
    except Exception:
        pass
    return "\n".join(out)


def history_section(tdir):
    runs = sorted(_runs(tdir), key=lambda r: (r.get("date") or "", r.get("run_id") or ""),
                  reverse=True)
    shown = runs[:RUN_CAP]
    out = [f"<h2>What has been run — {len(runs)} closed record(s)</h2>"]
    if not runs:
        out.append('<div class="banner">No runs recorded yet — <code>kb.py run</code> opens one '
                   'before every unit that sends traffic.</div>')
        return "\n".join(out)
    if len(runs) > RUN_CAP:
        out.append(f'<div class="banner">Showing the newest {RUN_CAP} of {len(runs)} runs — '
                   '<code>tools/kb.py runs</code> for the full ledger.</div>')
    out.append("<table><tr><th>run</th><th>date</th><th>objective</th><th>selector</th>"
               "<th>status</th><th>result</th></tr>")
    for r in shown:
        result = r.get("result") or ""
        if len(result) > 150:
            result = result[:149].rstrip() + "…"
        lim = r.get("limitations") or ""
        title = f' title="{e(lim[:300])}"' if lim else ""
        out.append(f"<tr><td><code>{e(r['run_id'])}</code></td><td>{e(r['date'])}</td>"
                   f"<td>{md_inline(r['phase'])}</td><td>{md_inline(r['selector'])}</td>"
                   f"<td>{e(r['status'])}</td><td{title}>{md_inline(result)}</td></tr>")
    out.append("</table>")
    return "\n".join(out)


def progress_section(tdir):
    p = tdir / "progress.md"
    if not p.exists():
        return ("<h2>Progress</h2>"
                '<div class="banner">progress.md not generated yet — run '
                '<code>tools/progress.py targets/&lt;t&gt;</code> after a unit of work.</div>')
    return "<h2>Progress</h2>" + md_to_html(read(p))


def files_section(tdir):
    out = ["<h2>Brain files — state and age</h2>",
           '<div class="banner">Bulk raw output lives on the VPS and is not here. '
           'accounts.md is summarized (usable principals), never rendered — credential '
           'references do not belong in a generated page.</div>',
           "<table><tr><th>file</th><th>state</th><th class=num>rows/lines</th>"
           "<th class=num>age</th></tr>"]
    today = date.today()
    for relf in BRAIN_FILES:
        p = tdir / relf
        st, n = state_of(p)
        shown = {"missing": '<span class="miss">missing</span>',
                 "empty": '<span class="zero">0</span>',
                 "prose": '<span class="prose">prose</span>',
                 "demoted": '<span class="demoted">on VPS</span>',
                 }.get(st, "present")
        try:
            age = (today - date.fromtimestamp(p.stat().st_mtime)).days
            age_txt = f"{age}d" if age else "today"
        except OSError:
            age_txt = "—"
        note = ' · <span class="prose">summarized</span>' if p.name == "accounts.md" else ""
        out.append(f"<tr><td><code>{e(relf)}</code>{note}</td><td>{shown}</td>"
                   f"<td class=num>{n if n is not None else '—'}</td>"
                   f"<td class=num>{age_txt}</td></tr>")
    out.append("</table>")
    return "\n".join(out)


def collect_meta(tdir):
    """The sidebar's one-line answer to 'is this target hot?' — computed, never claimed."""
    idx = read(tdir / "index.md")
    runs = _runs(tdir)
    upd = field(idx, "Last updated") or ""
    a = age_days(upd)
    _, tested_rows = table_rows(read(tdir / "tested.md"))
    _, surf_rows = table_with(read(tdir / "attack-surface.md"), "entrypoint", "vuln_class")
    return {
        "name": tdir.name,
        "program": field(idx, "Program") or "",
        "updated": upd,
        "age": a,
        "open_runs": len([r for r in runs if r.get("status") == "running"]),
        "resume_points": len([r for r in runs
                              if r.get("status") in ("partial", "failed") and r.get("resume_from")]),
        "probes": len([r for r in tested_rows if any(c.strip() for c in r)]),
        "surface": len(surf_rows),
    }


def _chips(meta):
    out = []
    if meta["open_runs"]:
        out.append(f'<span class="chip bad">{meta["open_runs"]} running</span>')
    if meta["resume_points"]:
        out.append(f'<span class="chip warn">{meta["resume_points"]} resume</span>')
    if meta["age"] is not None and meta["age"] > STALE_DAYS:
        out.append(f'<span class="chip warn">{meta["age"]}d stale</span>')
    out.append(f'<span class="chip">{meta["probes"]} probes</span>')
    out.append(f'<span class="chip">{meta["surface"]} surface</span>')
    return "".join(out)


def render(tdir, search=True):
    """One target's dashboard fragment: pinned header + tabbed panels + foot.

    `search=False` in the SPA, which provides one global search box for the active target."""
    name = tdir.name
    idx = read(tdir / "index.md")
    claims = claimed_counts(idx)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    out = [f"<h1>{e(name)}</h1>"]
    if search:
        out.append('<input id="q" type="search" autocomplete="off" spellcheck="false" '
                   'placeholder="filter every table below — host, path, class, tech, anything">'
                   '<p class="sub" id="qhint"></p>')

    prog = field(idx, "Program") or ""
    arch = field(idx, "Archetype") or field(idx, "Scope type") or ""
    phase = field(idx, "Last activity") or field(idx, "Current phase") or "—"
    upd = field(idx, "Last updated") or ""

    # Program/Archetype are optional metadata, not a recon deliverable — unlike the funnel's
    # "missing" cells (which mean "you haven't run this yet, go run it"), an unset one here is
    # not actionable, so it is omitted rather than announced.
    if not unfilled(prog):
        out.append(f'<p class="sub">{md_inline(prog)}</p>')

    if not unfilled(arch):
        out.append(f'<p class="sub"><span class="pill" title="{e(arch)}">{e(arch)}</span></p>')

    out.append(f'<p class="sub">{md_inline(phase)}</p>')

    a = age_days(upd)
    if a is None:
        out.append('<div class="banner bad">index.md has no <code>Last updated</code> date. '
                   'Every number below is of unknown age.</div>')
    elif a > STALE_DAYS:
        out.append(f'<div class="banner warn">Brain last updated <b>{e(upd)}</b> — {a} days ago. '
                   'State the age of the recon before testing anything off this page.</div>')

    # ---- funnel (overview) -------------------------------------------
    funnel = ["<h2>Where we stand</h2><div class=\"funnel\">"]
    for i, (relp, label, in_funnel) in enumerate(DATA_FILES):
        if not in_funnel:
            continue
        st, n = state_of(tdir / relp)
        cls, txt = {"missing": ("is-missing", "missing"),
                    "empty":   ("is-empty", "0"),
                    "prose":   ("is-prose", "prose"),
                    "demoted": ("is-demoted", f"{n:,} ⇡" if n is not None else "on VPS"),
                    }.get(st, ("", f"{n:,}" if n is not None else "?"))
        if i:
            funnel.append('<span class="arrow">›</span>')
        funnel.append(f'<div class="cell {cls}"><div class="n">{txt}</div>'
                      f'<div class="l">{e(label)}</div></div>')
    funnel.append("</div>")

    # ---- testing state ------------------------------------------------
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

    testing = ["<h2>Testing state</h2><div class=\"funnel\">"]
    for n, l in ((len(hrows), "hypotheses"), (len(trows), "probes logged"),
                 (nconf, "confirmed"), (nprin, "usable principals")):
        cls = " is-empty" if n == 0 else ""
        testing.append(f'<div class="cell{cls}"><div class="n">{n}</div>'
                       f'<div class="l">{e(l)}</div></div>')
    for s in ("open", "testing", "confirmed", "rejected"):
        if s in by:
            testing.append(f'<div class="cell"><div class="n">{by[s]}</div>'
                           f'<div class="l">{s}</div></div>')
    testing.append("</div>")
    if nprin < 2:
        testing.append(f'<div class="banner warn">Only {nprin} <b>usable</b> principal(s) in '
                       '<code>accounts.md</code> — rows whose credential is still a placeholder '
                       'are plans, not accounts. Authz / IDOR / multi-tenant / privesc work is '
                       '<b>blocked</b>, not untested: a clean "not vulnerable" from one account '
                       'is not a result.</div>')

    # ---- ranked surface ----------------------------------------------
    surf = read(tdir / "attack-surface.md")
    hdr, rows = table_with(surf, "entrypoint", "vuln_class")
    surface = [f"<h2>Attack surface — {len(rows)} entr{'y' if len(rows)==1 else 'ies'}</h2>"]
    if not rows:
        surface.append('<div class="banner bad">No ranked surface. '
                       '<code>attack-surface-prioritization</code> has not run, so any '
                       'model-chosen test would be picking by whatever it happened to '
                       'notice.</div>')
    else:
        if len(trows) == 0:
            surface.append('<div class="banner warn">Surface is ranked but '
                           '<code>tested.md</code> is empty — nothing has been probed yet. '
                           'Coverage is 0%, not unknown.</div>')
        keep = [i for i, h in enumerate(hdr)
                if re.sub(r"[^a-z]", "", h.lower()) in
                ("rank", "score", "entrypoint", "clusterrepresentativehosts", "cluster")
                or "why" in h.lower() or "entrypoint" in h.lower()]
        keep = keep or list(range(len(hdr)))
        surface.append("<table><tr>" + "".join(f"<th>{e(hdr[i])}</th>" for i in keep) + "</tr>")
        for r in rows:
            cells = []
            for i in keep:
                v = r[i] if i < len(r) else ""
                sc = ' class="score"' if "score" in hdr[i].lower() else ""
                cells.append(f"<td{sc}>{md_inline(v)}</td>")
            surface.append("<tr>" + "".join(cells) + "</tr>")
        surface.append("</table>")

    # ---- root domains -------------------------------------------------
    roots = read(tdir / "recon/root-domains.md")
    rhdr, rrows = table_with(roots, "apex")
    domains = []
    if rrows:
        def cell(row, cname):
            for i, h in enumerate(rhdr):
                if cname in h.lower():
                    return (row[i] if i < len(row) else "").strip()
            return ""
        in_scope = [r for r in rrows if cell(r, "scope_status") == "in-scope"]
        unres = [r for r in rrows if "unresolved" in cell(r, "ownership")
                 or cell(r, "scope_status") in ("unknown", "not-listed")]
        domains.append(f"<h2>Root domains — {len(rrows)} apex(es), {len(in_scope)} in scope, "
                       f"{len(unres)} unresolved</h2>")
        keep = [i for i, h in enumerate(rhdr)
                if re.sub(r"[^a-z_]", "", h.lower()) in
                ("apex", "ownership", "scope_status", "confidence") or "evidence" in h.lower()]
        keep = keep or list(range(len(rhdr)))
        domains.append("<table><tr>" + "".join(f"<th>{e(rhdr[i])}</th>" for i in keep) + "</tr>")
        for r in rrows:
            st = cell(r, "scope_status")
            cls = (' class="is-missing"' if st == "out-of-scope" else
                   ' class="is-prose"' if st in ("unknown", "not-listed") else "")
            cells = "".join(f"<td>{md_inline(r[i] if i < len(r) else '')}</td>" for i in keep)
            domains.append(f"<tr{cls}>{cells}</tr>")
        domains.append("</table>")
        if unres:
            domains.append('<div class="banner warn"><b>' + str(len(unres)) + ' apex(es) '
                           'unresolved.</b> Ownership or authorisation could not be established '
                           '— do not touch them. The settling check for each is in '
                           '<code>recon/root-domains.md</code>.</div>')
    else:
        domains.append("<h2>Root domains</h2>")
        domains.append('<div class="banner bad">No apex has been recorded with evidence yet. '
                       '<code>organization-and-roots</code> writes '
                       '<code>recon/root-domains.md</code>; a domain that merely carries the '
                       'company name is not a root.</div>')

    # ---- takeover candidates ------------------------------------------
    dns_text = read(tdir / "recon" / "dns.md")
    thdr, tkrws = table_with(dns_text, "host", "takeover_candidate")
    cand = []
    for r in tkrws:
        val = ""
        for i, h in enumerate(thdr):
            if "takeover_candidate" in h.lower():
                val = (r[i] if i < len(r) else "").strip().lower()
        if val and val not in ("no", "-", "—", "n/a", ""):
            cand.append(r)
    takeover = []
    if tkrws:
        takeover.append(f"<h2>Takeover candidates — {len(cand)} of {len(tkrws)} DNS "
                        "record(s)</h2>")
        if cand:
            takeover.append('<div class="banner warn"><b>A dangling record is a CANDIDATE, '
                            'never a confirmed takeover.</b> Confirming one means claiming the '
                            'third-party resource — intrusive, and only on explicit '
                            'authorisation.</div>')
            takeover.append("<table><tr>" + "".join(f"<th>{e(h)}</th>" for h in thdr) + "</tr>")
            for r in cand:
                cells = "".join(f"<td>{md_inline(r[i] if i < len(r) else '')}</td>"
                                for i in range(len(thdr)))
                takeover.append(f'<tr class="is-prose">{cells}</tr>')
            takeover.append("</table>")
        else:
            takeover.append('<div class="banner">DNS records recorded, none flagged as a '
                            'takeover candidate.</div>')

    # ---- data inventory ------------------------------------------------
    drift = []
    inventory = ["<h2>Data inventory — computed, not copied</h2>"
                 "<table><tr><th>file</th><th>what</th><th class=num>on disk</th>"
                 "<th class=num>index.md claims</th><th></th></tr>"]
    for relp, label, _ in DATA_FILES:
        st, n = state_of(tdir / relp)
        shown = {"missing": '<span class="miss">missing</span>',
                 "empty": '<span class="zero">0</span>',
                 "prose": '<span class="prose">prose</span>',
                 "demoted": (f'{n:,} <span class="demoted" title="on the VPS">⇡</span>'
                             if n is not None else '<span class="demoted">on VPS</span>'),
                 }.get(st, f"{n:,}" if n is not None else "?")
        claim = claims.get(relp, "—")
        note = ""
        norm_disk = {"missing": "missing", "empty": "0", "prose": "prose"}.get(st, str(n))
        if claim not in ("—", "") and re.sub(r"[^\w]", "", claim.lower()) != \
                re.sub(r"[^\w]", "", norm_disk.lower()):
            note = ('<span class="prose">⚠ unverifiable — prose</span>' if st == "prose"
                    else '<span class="flag">⚠ disagrees</span>')
            drift.append((relp, norm_disk, claim))
        inventory.append(f"<tr><td><code>{e(relp)}</code></td><td>{e(label)}</td>"
                         f"<td class=num>{shown}</td><td class=num>{e(claim)}</td>"
                         f"<td>{note}</td></tr>")
    inventory.append("</table>")
    if drift:
        inventory.append(f'<div class="banner warn">{len(drift)} file(s) disagree with the '
                         'manifest. The <b>on disk</b> column is the fact; index.md holds '
                         'decisions, not counts, so delete the stale number rather than '
                         'refreshing it.</div>')

    # ---- where the data lives -----------------------------------------
    where = ["<h2>Where the data lives</h2>",
             '<div class="banner">Bulk lists live on the VPS; the brain keeps a count and a '
             'pointer. <code>tools/vps-sync.py pull &lt;target&gt;</code> brings one back.</div>',
             "<table><tr><th>file</th><th>state</th><th>location</th></tr>"]
    for relp, label, _ in DATA_FILES:
        st, n = state_of(tdir / relp)
        if st == "missing":
            continue
        if st == "demoted":
            ptr = pointer_for(tdir / relp)
            m = re.search(r"^\s{2,}(\S+)\s*$", read(ptr), re.M) if ptr else None
            loc = m.group(1) if m else "on the VPS"
            w = f'<span class="demoted">{e(loc)}</span>'
        else:
            w = f"<code>{e(str(relp))}</code> (local)"
        where.append(f"<tr><td>{e(label)}</td><td class=num>"
                     f"{n if n is not None else st}</td><td>{w}</td></tr>")
    where.append("</table>")

    # ---- blockers ------------------------------------------------------
    blk = [m.group(0).strip() for m in re.finditer(r"TBD\s*—\s*blocking:[^\n|]*", idx)]
    sec = re.search(r"^##+\s*Blocking\s*/?\s*TBD.*?$(.*?)(?=^##|\Z)", idx, re.M | re.S)
    if sec:
        blk += [l.strip(" -*\t") for l in sec.group(1).splitlines()
                if l.strip(" -*\t") and not l.strip(" -*\t").startswith("<")]
    blocking = []
    if blk:
        blocking.append("<h2>Blocking</h2><ul>")
        blocking += [f"<li>{md_inline(b)}</li>" for b in blk]
        blocking.append("</ul>")

    out += funnel
    out.append(running_section(tdir))          # what is running — before anything else
    out.append(history_section(tdir))          # what has been run
    out += surface
    out += testing
    out.append(progress_section(tdir))
    out += domains
    out += takeover
    out += inventory
    out += where
    out.append(files_section(tdir))
    out += blocking

    out.append(f'<p class="foot">Generated {now} by <code>tools/dashboard.py</code> from '
               f'<code>targets/{e(name)}/</code>. Read-only view — the markdown is the source of '
               f'truth. Counts in the <b>on disk</b> column are computed from the files at '
               f'generation time; raw bulk output lives on the VPS and is not counted here.</p>')
    return "\n".join(out)


# ---------------------------------------------------------------- render: the SPA

def discover(root=None):
    """Every usable target brain, most recently touched first — the sidebar's order."""
    base = Path(root) if root else ROOT / "targets"
    out = []
    if not base.is_dir():
        return out
    for d in base.iterdir():
        if not d.is_dir() or d.name.startswith(("_", ".")):
            continue
        if (d / "index.md").exists():
            out.append(d)
    return sorted(out, key=lambda d: (d / "index.md").stat().st_mtime, reverse=True)


def _view_id(name):
    return "tv-" + name.lower().replace(" ", "-")


def render_spa(tdirs):
    """One self-contained page: sidebar of targets, click to load a target's view, no reload."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    items, views = [], []
    for i, tdir in enumerate(tdirs):
        meta = collect_meta(tdir)
        frag = render(tdir, search=False)
        body = tabify(frag, prefix=f"t{i}_", include_tab_js=False)
        vid = _view_id(meta["name"])
        sub = meta["program"] or meta["updated"] or ""
        items.append(f'<a class="titem" href="#/{e(meta["name"])}" data-hay="'
                     f'{e((meta["name"] + " " + sub).lower())}">'
                     f'{e(meta["name"])}<span class="chips">{_chips(meta)}</span></a>')
        views.append(f'<div class="tview" id="{vid}" data-name="{e(meta["name"])}">'
                     f'{body}</div>')
    page = [
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        "<title>HunterStick — dashboard</title>",
        f"<style>{CSS}{SPA_CSS}</style>",
        '<body class="spa">',
        '<aside id="side">',
        "<h1>HunterStick</h1>",
        '<input id="tq" type="search" autocomplete="off" spellcheck="false" '
        'placeholder="filter targets…">',
        "\n".join(items),
        f'<p class="foot">{len(tdirs)} target(s) · generated {now}</p>',
        "</aside>",
        '<main id="main">',
        '<input id="q" type="search" autocomplete="off" spellcheck="false" '
        'placeholder="filter the selected target\'s tables — host, path, class, tech, anything">',
        '<p class="sub" id="qhint"></p>',
        "\n".join(views),
        "</main>",
        SPA_JS,
        "</body>",
    ]
    return "\n".join(page)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", nargs="?", default=None, help="path to targets/<name>")
    ap.add_argument("--stdout", action="store_true", help="print instead of writing the file")
    ap.add_argument("--all", action="store_true",
                    help="build the workspace SPA: dashboard.html with a sidebar of every target")
    args = ap.parse_args()

    if args.all:
        tdirs = discover()
        if not tdirs:
            print("FAIL — no target brains under targets/ (each needs an index.md).",
                  file=sys.stderr)
            return 2
        page = render_spa(tdirs)
        dest = ROOT / "dashboard.html"
        dest.write_text(page, encoding="utf-8")
        print(f"  wrote {rel(dest)}  ({len(page):,} bytes, {len(tdirs)} target(s))")
        print(f"  open it:  open {dest}")
        return 0

    if not args.target:
        ap.print_help()
        return 2
    tdir = Path(args.target).resolve()
    if not tdir.is_dir():
        print(f"FAIL — no directory {args.target}", file=sys.stderr)
        return 2
    if not (tdir / "index.md").exists():
        print(f"FAIL — {args.target} has no index.md; is it a target brain?", file=sys.stderr)
        return 2

    frag = render(tdir, search=True)
    page = tabify(frag, prefix="", include_tab_js=True) + "\n" + SEARCH_JS
    page = ('<meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>{e(tdir.name)} — attack surface</title>"
            f"<style>{CSS}</style>"
            '<div class="wrap">' + page + "</div>")
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
