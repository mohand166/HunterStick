#!/usr/bin/env python3
"""The brain-parsing library: one reader set over the target-brain markdown/TSV files.

Imported by `tools/dashboard-server.py` (the live console) and `tools/suggest-flows.py`,
so the two can never disagree about what a brain file says. Everything here is read-only
and local; it never opens config.json, renders a credential, or touches the network.

Three rules live here because every consumer of a brain file must apply them identically:

  1. Counts are COMPUTED from the files, never copied from index.md.
  2. `missing` != `0` != `prose` — `state_of()` keeps the three apart.
  3. accounts.md is summarized (`usable_principals`), never rendered row-by-row.

This module was extracted from the retired `tools/dashboard.py` snapshot renderer; the
docstrings record why each rule exists and stay deliberately.
"""
import re
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from scopelib import clean   # noqa: E402  (one normaliser, not three)

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

# Every brain artifact a consumer might wonder about, with state and age. Order is
# reading order, not importance — importance is the consumer's job.
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
        cred = re.sub(r"[`*]", "", cred).strip()
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


def discover(root=None):
    """Every usable target brain, most recently touched first."""
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


def runs_latest(tdir):
    """Latest row per run_id — the open→close pattern appends a closing row with the same id."""
    from kb import read_runs       # one csv schema, one reader
    latest = {}
    for r in read_runs(tdir):
        latest[r["run_id"]] = r
    return list(latest.values())


def e(s):
    import html
    return html.escape(str(s if s is not None else ""))


def md_inline(s):
    """Just enough markdown for table cells: **bold** and `code`."""
    s = e(s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"`(.+?)`", r"<code>\1</code>", s)
    return s


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
