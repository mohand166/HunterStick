#!/usr/bin/env python3
"""Validate the public workspace skeleton without touching a live target."""

import importlib.util
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

PUBLIC_ROOTS = (
    "README.md",
    "AGENTS.md",
    "CLAUDE.md",
    ".mcp.json",
    "config.example.json",
    ".claude/skills",
    ".github/workflows",
    "playbooks",
    "tools",
    "targets/_template",
)
REQUIRED_PATHS = (
    "AGENTS.md",
    "README.md",
    "LICENSE",
    "config.example.json",
    "targets/TARGETS.example.md",
    "targets/_template/scope.md",
    "targets/_template/scope-evidence.md",
    "targets/_template/accounts.md",
    "playbooks/system/phase-routing.md",
    "skills/setup/init-target.md",
)
FORBIDDEN_TEXT = (
    "00-" + "scope-review",
    "phase " + "00",
    "playbooks/" + "reporting/",
    # The manifest has no "current phase" field and the phase log was replaced by runs.tsv.
    # Both kept creeping back into individual phase files, which then told the model to write
    # somewhere that does not exist. The concatenation keeps this file from matching itself.
    "current " + "phase",
    "phase log " + "line",
    "phase-log " + "row",
)

# ...except where the file is explaining why the thing is gone.
FORBIDDEN_TEXT_EXEMPT = {
    "targets/_template/index.md",       # states "There is no 'current phase'" on purpose
    "playbooks/system/phase-routing.md",
    "README.md",
    # these two READ the legacy field as a fallback so an older brain still renders; they never
    # instruct anyone to write it
    "tools/brief.py",
    "tools/dashboard.py",
}


def load_tool(name):
    path = ROOT / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"workspace_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def public_files():
    for relative in PUBLIC_ROOTS:
        path = ROOT / relative
        if path.is_file():
            yield path
        elif path.is_dir():
            yield from (candidate for candidate in path.rglob("*") if candidate.is_file())


def check_required():
    return [f"missing required path: {relative}"
            for relative in REQUIRED_PATHS if not (ROOT / relative).exists()]


def check_cli_modes():
    """A documented `tools/name.py` command must survive a fresh clone as an executable."""
    failures = []
    for path in sorted((ROOT / "tools").glob("*.py")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if 'if __name__ == "__main__"' in text and not os.access(path, os.X_OK):
            failures.append(f"{path.relative_to(ROOT)} is a CLI entrypoint but is not executable")
    shell = ROOT / "tools" / "vps.sh"
    if shell.exists() and not os.access(shell, os.X_OK):
        failures.append("tools/vps.sh is documented as a command but is not executable")
    return failures


def check_forbidden_text():
    failures = []
    for path in public_files():
        if path.resolve() == Path(__file__).resolve():
            continue
        if path.suffix not in {".md", ".py", ".sh", ".json", ".yml", ".yaml", ".html", ".css", ".js"}:
            continue
        rel = str(path.relative_to(ROOT))
        if rel in FORBIDDEN_TEXT_EXEMPT:
            continue
        text = path.read_text(encoding="utf-8-sig", errors="replace").lower()
        for phrase in FORBIDDEN_TEXT:
            if phrase.lower() in text:
                failures.append(f"{path.relative_to(ROOT)} contains stale text: {phrase}")
    return failures



# ─────────────────────────────────────────────────────────────────────────────
# Semantic checks. The structural ones prove the repo is wired together; these
# prove the *prose* has not drifted into telling the model to do something unsafe.
# Every pattern below is here because it was found in a real review.
# ─────────────────────────────────────────────────────────────────────────────

# Recon prose is held to "mapping does not mutate". Hunting prose is NOT: inside a class the
# hunter invoked, re-issuing a route as PUT/PATCH/DELETE is the test, and `playbooks/vulns/`
# discusses exactly that on purpose. Scope decides which body of prose a rule judges — pointing
# these at `playbooks` would fire on eleven legitimate hunting lines.
SEMANTIC = [
    # (regex, where, why it is wrong)
    (r"-follow-redirects\b", "skills",
     "unrestricted redirects can hop to an out-of-scope host — use -follow-host-redirects"),
    # NOT a rule: `--only-verified`. Validating a leaked credential is standard recon and is
    # what makes the finding reportable. The real line is valid -> used, which no regex can see.
    (r"Default:\s*full set", "skills",
     "a loud skill must not default to the whole estate — require a selector or pilot"),
    # class-based, not phrase-based: the earlier exact-phrase rules were bypassed simply by
    # rewording ("submit forms" vs "submit every form"), which is how three instances survived.
    (r"\b(PUT|PATCH|DELETE)\b[^.\n]{0,40}\b(PUT|PATCH|DELETE|OPTIONS)\b", "skills",
     "a method list containing PUT/PATCH/DELETE reads as a discovery sweep — "
     "probe with GET/HEAD/OPTIONS and the Allow header instead"),
    (r"none of them mutating|non-mutating.{0,20}(PUT|PATCH|DELETE)", "playbooks",
     "PUT/PATCH/DELETE mutate; do not describe them as safe probes"),
    (r"\b(submit|fill (in |out )?)\w{0,6}\s*forms?\b|"
     r"\b(complete|run|finish)\s+(every|each|the)\s+(workflow|flow)\b", "skills",
     "submitting a form or completing a flow is ACT mode, not mapping — it sends invites, "
     "emails, purchases and deletions"),
    (r"\bclick every (button|link)\b", "skills",
     "clicking every button triggers actions; navigate and read instead (OBSERVE mode)"),
]


def check_semantics():
    failures = []
    for pattern, subtree, why in SEMANTIC:
        rx = re.compile(pattern, re.I)
        root = ROOT / subtree
        # A rule whose subtree does not exist checks NOTHING, and used to `continue` — so when
        # `playbooks/recon/` was deleted, five safety rules became silent no-ops and the suite
        # still printed PASS. A checker that reports success while validating nothing is the
        # exact failure this workspace tells the model never to produce. Fail loud instead.
        if not root.exists():
            failures.append(
                f"SEMANTIC rule points at {subtree}/, which does not exist — the rule "
                f"({why}) is checking nothing. Repoint it or delete it deliberately.")
            continue
        for path in sorted(root.rglob("*.md")):
            text = path.read_text(encoding="utf-8-sig", errors="replace")
            for i, line in enumerate(text.splitlines(), 1):
                # a line that is explicitly warning about the pattern is not using it
                # A line explaining WHY a pattern is unsafe necessarily contains it. But scanning
                # the WHOLE line for a negation is too loose: "not by reading its JavaScript.**
                # Click every link and button" was exempted by a `not` about something else.
                # Only the 60 characters immediately before the match can excuse it.
                m = rx.search(line)
                if not m:
                    continue
                # ...and it must be in the SAME sentence. "not by reading its JavaScript.
                # Click every button" put a negation 30 characters away that had nothing to do
                # with the instruction that followed it.
                before = line[max(0, m.start() - 90):m.start()]
                before = re.split(r"[.!?;]\s|\*\*\s", before)[-1]
                excused = re.search(
                    r"never|not\b|instead|rather than|do not|avoid|cannot|refuse|wrong|"
                    r"unsafe|hazard|without|reveals|sends? HTTP|outside the program|third part|"
                    r"use -follow-host|--no-verification|is why|would", before, re.I)
                if not excused:
                    failures.append(f"{path.relative_to(ROOT)}:{i} — {why}")
    return failures


def check_class_names():
    """Every `vulns/<name>` referenced in prose must be a real class file."""
    real = {p.stem for p in (ROOT / "playbooks" / "vulns").glob("*.md")}
    failures = []
    for path in sorted((ROOT / "playbooks").rglob("*.md")):
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        for m in re.finditer(r"playbooks/vulns/([a-z][a-z0-9-]+)\.md", text):
            if m.group(1) not in real:
                failures.append(f"{path.relative_to(ROOT)} references a class that does not "
                                f"exist: {m.group(1)}")
    return failures



# REMOVED: check_scope_wiring() and PHASE_PRIMARY_INPUT.
#
# It asserted that a recon skill pipes its host list through `scope-filter.py` into `$SCOPED`
# before any traffic command reads it. Two independent things made that obsolete, and re-arming
# it would have re-imposed both.
#
# 1. The ARCHITECTURE changed. A skill deliberately no longer carries the invocation — no flag
#    lists, no pasted pipelines (`skills/shared/_recon-method.md`, `recon-toolkit.md`). There is no
#    command chain left in the prose for this to inspect, so it was asserting the shape of
#    something the workspace stopped writing on purpose.
# 2. The POLICY changed. Scope does not gate execution here: "Required inputs present -> run it.
#    Nothing else stops you. Not scope, not accounts" (`skills/shared/_recon-method.md`). A check that
#    fails the build when a skill does not scope-filter is a scope gate wearing a test's clothes.
#
# It also never bit in practice: scope-filter passed 35,426 of 35,426 names and 27,220 of 27,220
# addresses on the one real engagement (AGENTS.md) — it filtered nothing.
#
# `tools/scope-filter.py` REMAINS, and is still the right tool when a hunter wants a list
# narrowed. What is gone is the assertion that every skill must route through it.


def check_no_frozen_dates():
    """A hardcoded date in an artifact path means every run overwrites the same file."""
    failures = []
    for path in sorted((ROOT / "playbooks").rglob("*.md")):
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(r"raw/\S*\d{4}-\d{2}-\d{2}", line):
                failures.append(f"{path.relative_to(ROOT)}:{i} frozen date in an artifact path "
                                f"— use $DATE")
    return failures


def markdown_destinations(text):
    for match in re.finditer(r"(?<!!)\[[^\]]+\]\(([^)]+)\)", text):
        destination = match.group(1).strip().strip("<>")
        if any(character in destination for character in ('"', "'", "\\")):
            continue
        if destination and not destination.startswith(("http://", "https://", "mailto:", "#")):
            yield destination.split("#", 1)[0]


def check_markdown_links():
    failures = []
    for path in (candidate for candidate in public_files() if candidate.suffix == ".md"):
        for destination in markdown_destinations(path.read_text(encoding="utf-8-sig", errors="replace")):
            if destination.startswith(("/", "<")) or "://" in destination:
                continue
            resolved = (path.parent / destination).resolve()
            if not resolved.exists():
                failures.append(
                    f"{path.relative_to(ROOT)} has dead local link: {destination}"
                )
    return failures


def check_account_template():
    brief = load_tool("brief")
    state = brief.accounts_state(ROOT / "targets" / "_template")
    if not state.startswith("none"):
        return [f"account template is incorrectly usable: {state}"]
    return []


def check_class_rules():
    coverage = load_tool("coverage")
    loaded = coverage.load_signals()
    if loaded is None:
        return ["class-signals.md did not parse"]
    class_rules, known = loaded
    if not class_rules or not known:
        return ["class-signals.md produced an empty rule set"]
    return []


def check_ignore_policy():
    text = (ROOT / ".gitignore").read_text(encoding="utf-8-sig", errors="replace")
    required = {
        "targets/*",
        "!targets/_template/",
        "!targets/TARGETS.example.md",
        "config.json",
    }
    missing = sorted(required - set(text.splitlines()))
    failures = [f".gitignore is missing: {rule}" for rule in missing]
    if "!targets/TARGETS.md" in text:
        failures.append(".gitignore would publish the live target registry")
    return failures


def check_no_dangling_file_references():
    """A backticked path to a playbook or skill must resolve.

    Retiring the numbered recon tree left ten files pointing at playbooks that no longer
    existed — flows routing to `playbooks/recon/22-monitoring-and-diff.md` and similar. Nothing
    caught it, because a dead path in prose reads exactly like a live one until someone follows
    it mid-hunt and finds nothing there.
    """
    import re as _re
    failures = []
    for p in sorted(ROOT.rglob("*.md")):
        if any(x in p.parts for x in (".git", "knowledge", "targets", "node_modules")):
            continue
        for m in _re.finditer(r"`((?:playbooks|skills)/[A-Za-z0-9_./-]+\.md)`",
                              p.read_text(encoding="utf-8", errors="replace")):
            ref = m.group(1)
            if "<" in ref or "*" in ref:          # a template, not a path
                continue
            if not (ROOT / ref).exists():
                failures.append(f"{p.relative_to(ROOT)} references {ref}, which does not exist")
    return failures


def check_skill_pointers():
    """One body, thin per-runtime pointers — and they must agree.

    The portable layer deliberately has no build step: the nested `skills/<category>/<name>.md`
    file is the single body,
    and `.claude/skills/<name>/SKILL.md` carries only the frontmatter a runtime matches on.
    Nothing regenerates one from the other, so this is what stops them drifting — and a
    pointer whose description has drifted is worse than none, because the runtime triggers on
    the stale text while the body says something else.
    """
    import re as _re
    import skilllib
    sk, cs = ROOT / "skills", ROOT / ".claude" / "skills"
    if not sk.is_dir():
        return []
    failures = []
    bodies, paths = {}, {}
    for f in skilllib.iter_skill_files(sk):
        m = _re.match(r"---\nname: (.+?)\ndescription: (.+?)\n---\n",
                      f.read_text(encoding="utf-8"), _re.S)
        if not m:
            failures.append(f"{f.relative_to(ROOT)}: no name/description frontmatter")
            continue
        slug = m.group(1).strip()
        if slug != f.stem:
            failures.append(f"{f.relative_to(ROOT)}: frontmatter name is '{slug}'")
        if slug in bodies:
            failures.append(f"duplicate skill slug '{slug}': {paths[slug]} and "
                            f"{f.relative_to(ROOT)}")
            continue
        bodies[slug] = m.group(2).strip()
        paths[slug] = f.relative_to(ROOT).as_posix()

    for slug, desc in bodies.items():
        p = cs / slug / "SKILL.md"
        if not p.exists():
            failures.append(f"{paths[slug]} has no runtime pointer at "
                            f".claude/skills/{slug}/SKILL.md")
            continue
        text = p.read_text(encoding="utf-8")
        m = _re.match(r"---\nname: (.+?)\ndescription: (.+?)\n---\n", text, _re.S)
        if not m or m.group(2).strip() != desc:
            failures.append(f".claude/skills/{slug}: description has drifted from the body")
        if paths[slug] not in text:
            failures.append(f".claude/skills/{slug}: does not point at its body")
        after = text.split("---", 2)[-1] if text.count("---") >= 2 else text
        if len(after) > 500:
            failures.append(f".claude/skills/{slug}: pointer body is {len(after)}B — it should "
                            f"be a pointer, not a copy of the body")

    for d in sorted(cs.iterdir()) if cs.is_dir() else []:
        if d.is_dir() and d.name not in bodies:
            failures.append(f".claude/skills/{d.name}: pointer with no body in skills/")
    return failures


def check_skill_graph():
    """The dependency graph is COMPUTED from ## Inputs x the role table. Assert it joins.

    The hand-written graph in phase-routing.md had every single number wrong after a
    renumbering — including one bullet that contradicted itself in a single sentence — and
    nothing could detect it, because prose cannot be executed. This can.
    """
    graph = load_tool("graph")
    sk, prod = graph.skills(), graph.producers()
    known, failures = set(sk), []
    for slug, meta in sorted(sk.items()):
        for role in meta["required"] + meta["optional"]:
            p = prod.get(role)
            if p is None:
                failures.append(f"{slug}: role {role} has no producer in the role table")
            elif p not in known and not graph._resolvable(p):
                failures.append(f"{slug}: role {role} names producer '{p}', which is neither "
                                f"a skill nor a workflow")
    return failures


def check_property_vocabulary():
    """Every token a class rule selects on must exist in the vocabulary table, and every
    producer must emit tokens that exist.

    Found in a real audit: `import-http.py` emitted `xml-parse` while the vocabulary says
    `xml-parser`, so every XML/SOAP import silently poisoned coverage. And three documented
    tokens appeared in no class rule, which made recording them fail the run outright.
    """
    cov = load_tool("coverage")
    vocab = cov.parse_property_vocabulary()
    if not vocab:
        return ["class-signals.md: could not parse the ## Property vocabulary table"]
    loaded = cov.load_signals()
    if not loaded:
        return ["class-signals.md: class->property table did not parse"]
    class_rules, _ = loaded
    rule_tokens = {p for rules in class_rules.values() for rule in rules for p in rule}
    failures = [f"class-signals.md: class rules select on '{tok}', which is not in the "
                f"## Property vocabulary table" for tok in sorted(rule_tokens - vocab)]
    # Producers must emit real tokens. A drifted token is worse than a missing one: it
    # reads as a recorded observation and matches no rule.
    import re as _re
    for producer in ("tools/import-http.py",):
        text = (ROOT / producer).read_text(encoding="utf-8", errors="replace")
        for m in _re.finditer(r'p\.add\("([a-z0-9-]+)"\)', text):
            if m.group(1) not in vocab:
                failures.append(f"{producer} emits '{m.group(1)}', which is not in the "
                                f"## Property vocabulary table")
    return failures


def check_endpoint_contract():
    """Every surface producer and consumer must share the one endpoint-table interface.

    Tool-level tests exercise the import→path chain.  This lightweight repository check also
    catches a documentation/template edit that changes the public schema without changing the
    parser, which is how the two formats diverged originally.
    """
    surface = load_tool("surfacelib")
    expected = "| " + " | ".join(surface.COLUMNS) + " |"
    failures = []
    for relative in (
            "playbooks/system/target-schema.md",
            "targets/_template/recon/endpoints.md"):
        text = (ROOT / relative).read_text(encoding="utf-8-sig", errors="replace")
        if expected not in text:
            failures.append(f"{relative} does not expose surfacelib.py's canonical endpoint "
                            f"schema: {expected}")
    for relative in ("tools/import-http.py", "tools/paths.py"):
        text = (ROOT / relative).read_text(encoding="utf-8", errors="replace")
        if "from surfacelib import" not in text:
            failures.append(f"{relative} bypasses the canonical endpoint reader/writer")
    return failures


def check_no_example_rows_in_tables():
    """A `| <example> |` row inside a markdown table is indistinguishable from data.

    Tables here are parsed by counting rows. `brief.py` happened to special-case `| <`, but that
    is one reader defending itself by string prefix — every other parser would have counted the
    example as a standing decision, a user flow or a confirmed pattern. Examples belong in a
    comment beneath the header, where nothing can mistake them for a fact about the target.
    """
    failures = []
    for f in sorted((ROOT / "targets" / "_template").rglob("*.md")):
        for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if line.startswith("| <"):
                rel = f.relative_to(ROOT)
                failures.append(f"{rel}:{i} has an example row inside a table — move it into an "
                                f"HTML comment; a parser cannot tell it from data")
    return failures


def check_template_is_virgin():
    """The shipped template must carry no run data — not one row.

    Running any tool against `targets/_template` appends to its ledgers, and the template is the
    one target directory that IS committed. A single line of someone else's testing shipped in the
    initial commit this way: `suggest-flows.py 0 targets/_template --why`. It is harmless in
    content and wrong in principle — a fresh clone must start empty, and `dashboard.py` counts
    those rows.
    """
    failures = []
    tpl = ROOT / "targets" / "_template"
    for rel in ("logs/tools.tsv", "runs.tsv", "observations.tsv"):
        f = tpl / rel
        if not f.exists():
            continue
        rows = [l for l in f.read_text(encoding="utf-8-sig").splitlines() if l.strip()]
        if len(rows) > 1:
            failures.append(f"targets/_template/{rel} has {len(rows) - 1} data row(s) — the "
                            f"template ships empty. Reset it to the header line.")
    html = list(tpl.glob("*.html"))
    if html:
        failures.append(f"targets/_template/ contains generated view(s): "
                        f"{', '.join(h.name for h in html)} — regenerate, never commit")
    return failures


def check_catalogue_agreement():
    """The resident catalogue must name every flow and workflow that exists — and no ghosts.

    `class-signals.md` is loaded every session; `flows/_index.md` is opened on demand. They list
    the same things, which means they can disagree, and the resident one wins by default — so a
    flow that exists but is missing from the catalogue is a flow the model will never suggest.
    That is invisible: nothing errors, the capability simply never comes up.
    """
    failures = []
    signals = (ROOT / "playbooks/system/class-signals.md").read_text(encoding="utf-8")
    for kind, folder in (("flow", "flows"), ("workflow", "workflows"), ("tech file", "tech")):
        d = ROOT / "playbooks" / folder
        on_disk = {p.stem for p in d.glob("*.md") if not p.stem.startswith("_")}
        for name in sorted(on_disk):
            if name not in signals:
                failures.append(f"{kind} `{name}` exists in playbooks/{folder}/ but is not in "
                                f"class-signals.md — the model will never suggest it")
        idx = d / "_index.md"
        if idx.exists():
            listed = idx.read_text(encoding="utf-8")
            for name in sorted(on_disk):
                # an entry counts however it is written — backticked name, or a link to the file.
                # Checking only one spelling reports a dozen files that are in fact listed.
                if name not in listed:
                    failures.append(f"{kind} `{name}` is missing from playbooks/{folder}/_index.md")
            for m in re.finditer(r"`([a-z0-9-]{4,})`", listed):
                cand = m.group(1)
                if (d / f"{cand}.md").exists() or cand in on_disk:
                    continue
                if cand.endswith(".md") or "/" in cand or "." in cand:
                    continue
                if cand in {"tested", "scope", "accounts", "index", "blocked"}:
                    continue
                # a named-but-absent entry sends the model to a file that is not there
                if f"playbooks/{folder}/{cand}.md" in listed:
                    failures.append(f"playbooks/{folder}/_index.md names `{cand}`, which does not exist")
    return failures


def _command_snippets(text):
    """Command lines from EXPLICIT snippets only — fenced code blocks and inline code spans — so a
    double-dash in ordinary prose is never mistaken for a flag. Backslash continuations are joined."""
    out = []
    parts = text.split("```")
    for i in range(1, len(parts), 2):                 # odd segments are fenced code
        lines = parts[i].splitlines()
        if lines and re.fullmatch(r"[a-z][a-z0-9_+-]{0,11}", lines[0].strip()) and len(lines) > 1:
            lines = lines[1:]                         # drop a language tag (```bash)
        buf = ""
        for ln in lines:
            if ln.rstrip().endswith("\\"):
                buf += ln.rstrip()[:-1] + " "
            else:
                out.append(buf + ln); buf = ""
        if buf:
            out.append(buf)
    out += [m.group(1) for m in re.finditer(r"`([^`\n]+)`", text)]
    return out


def _tool_reference_failures(docs, tools_dir):
    """The coherence linter, factored out so it can be tested against a fixed doc list.

    (A) every `tools/<name>.(py|sh)` a doc names must exist; (B) every long `--flag` in a command
    snippet must be a real option of that tool (and subcommand). (B) is what would have caught
    `monitor.py enable --active`'s help drifting from its behaviour. Only long options in explicit
    snippets are checked — short flags and prose are deliberately out of scope (stated, not silent).
    """
    import subprocess
    failures = []
    # `knowledge/tools/` is the build-time corpus pipeline, a real dir with its own tools; the
    # lookbehind stops a bare-`tools/` match from firing inside it and reporting a false miss.
    ref_re = re.compile(r"(?<![\w/-])(knowledge/tools|tools)/([a-z0-9][a-z0-9_-]*)\.(py|sh)\b")
    inv_re = re.compile(r"(?:python3?\s+)?(?<![\w/-])tools/([a-z0-9][a-z0-9_-]*)\.py\b(.*)")
    sep_re = re.compile(r"\s(?:--|\||&&|\|\||;|>|>>)\s")   # a tool's own args end at any of these

    help_cache = {}

    def help_text(*args):
        if args not in help_cache:
            try:
                r = subprocess.run([sys.executable, str(tools_dir / args[0])] + list(args[1:]) + ["--help"],
                                   capture_output=True, text=True, timeout=20)
                help_cache[args] = (r.stdout or "") + "\n" + (r.stderr or "")
            except Exception:
                help_cache[args] = ""
        return help_cache[args]

    def long_flags(tool_file, sub=None):
        txt = help_text(tool_file, sub) if sub else help_text(tool_file)
        return set(re.findall(r"--[a-z][a-z0-9-]*", txt))

    def subcommands(tool_file):
        usage = help_text(tool_file).split("\n\n", 1)[0]      # the usage line names subparsers
        m = re.search(r"\{([a-z][a-z0-9,_-]+)\}", usage)
        return set(m.group(1).split(",")) if m else set()

    for p in docs:
        text = p.read_text(encoding="utf-8", errors="replace")
        rel = p.relative_to(ROOT) if str(p).startswith(str(ROOT)) else p
        # (A) existence — resolve against the referenced dir (tools/ or knowledge/tools/)
        for m in ref_re.finditer(text):
            subdir, name, ext = m.group(1), m.group(2), m.group(3)
            if "<" in name or "*" in name:
                continue
            if not (ROOT / subdir / f"{name}.{ext}").exists():
                failures.append(f"{rel} references {subdir}/{name}.{ext}, which does not exist")
        # (B) flags in command snippets
        for snip in _command_snippets(text):
            m = inv_re.search(snip)
            if not m:
                continue
            tool_file = f"{m.group(1)}.py"
            if not (tools_dir / tool_file).exists():
                continue                                       # (A) already reports this
            rest = sep_re.split(m.group(2), 1)[0]
            subs = subcommands(tool_file)
            # the subcommand is the first bareword; ignore bracket/paren decoration like [--x]
            positionals = [t for t in rest.split() if not t.lstrip("[(") .startswith("-")]
            sub = positionals[0] if (subs and positionals and positionals[0] in subs) else None
            valid = long_flags(tool_file, sub) | long_flags(tool_file)
            # Extract long flags with a boundary-aware regex (not whitespace-split tokens) so
            # documented `[--flag]`, `--flag=value` and trailing punctuation are all seen; strip
            # quoted values first so a `--dash` inside an argument string is not mistaken for a flag.
            dequoted = re.sub(r"\"[^\"]*\"|'[^']*'", " ", rest)
            for flag in sorted(set(re.findall(r"--[a-z][a-z0-9-]*", dequoted))):
                if flag not in valid:
                    failures.append(f"{rel}: `tools/{tool_file}"
                                    f"{(' ' + sub) if sub else ''}` snippet uses {flag}, "
                                    f"not one of its options (skill/tool drift)")
    return failures


def _router_agreement_failures(agents_text, skills_dir, dispatch_dir):
    """The AGENTS.md router is the cross-model dispatch table; nothing mechanical kept it honest.
    Two invariants: (1) every `skills/<path>/<name>.md` a router row NAMES must exist — a dangling router
    entry sends the model to a file that is not there; (2) the skill count AGENTS.md ADVERTISES must
    equal the dispatchers the runtime actually exposes (`.claude/skills/*/SKILL.md`), or the model
    reads a headline number that is a lie. `<...>` template rows (e.g. `skills/<objective>.md`) are
    not real references and are skipped by the character class."""
    failures = []
    for m in re.finditer(r"`skills/([a-z0-9_./-]+\.md)`", agents_text):
        relative = m.group(1)
        if not (skills_dir / relative).exists():
            failures.append(f"AGENTS.md router names skills/{relative}, which does not exist")
    dispatchers = ([d.name for d in dispatch_dir.iterdir() if d.is_dir() and (d / "SKILL.md").exists()]
                   if dispatch_dir.exists() else [])
    m = re.search(r"exposes all \*\*(\d+)\*\* skills", agents_text)
    if not m:
        failures.append("AGENTS.md no longer states the skill count as 'exposes all **N** skills' — "
                        "the router-count agreement check cannot run")
    elif int(m.group(1)) != len(dispatchers):
        failures.append(f"AGENTS.md advertises {m.group(1)} skills, but the runtime exposes "
                        f"{len(dispatchers)} dispatchers in .claude/skills/")
    return failures


def check_router_agreement():
    """Mechanically enforce that the AGENTS.md router agrees with the dispatchers the runtime
    exposes — the coherence gap that was documentary until now."""
    return _router_agreement_failures((ROOT / "AGENTS.md").read_text(encoding="utf-8"),
                                      ROOT / "skills", ROOT / ".claude" / "skills")


def check_tool_references():
    """Close the coherence gap the other checks miss: a skill or doc that names a tool that was
    renamed/deleted, or a command example whose flag drifted from the tool. Scans skills, playbooks
    and top-level docs."""
    docs = sorted(set(
        list((ROOT / "skills").rglob("*.md"))
        + list((ROOT / "playbooks").rglob("*.md"))
        + list(ROOT.glob("*.md"))
    ))
    return _tool_reference_failures(docs, ROOT / "tools")


def main():
    if "--help" in sys.argv or "-h" in sys.argv:
        print(__doc__.strip())
        print("\n  usage: tools/self-check.py        # no options; exits 1 on any integrity issue")
        return 0

    checks = (
        check_required,
        check_cli_modes,
        check_forbidden_text,
        check_semantics,
        check_class_names,
        check_no_frozen_dates,
        check_markdown_links,
        check_account_template,
        check_class_rules,
        check_ignore_policy,
        check_catalogue_agreement,
        check_template_is_virgin,
        check_no_dangling_file_references,
        check_skill_pointers,
        check_skill_graph,
        check_property_vocabulary,
        check_endpoint_contract,
        check_no_example_rows_in_tables,
        check_tool_references,
        check_router_agreement,
    )
    failures = [failure for check in checks for failure in check()]
    if failures:
        print(f"FAIL — {len(failures)} workspace integrity issue(s):", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("PASS — public workspace structure, links, account template, and class rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
