#!/usr/bin/env python3
"""Compute what has NOT been tested on a target.

    tools/coverage.py targets/acme
    tools/coverage.py targets/acme --entrypoint profile

Reads three files and subtracts:

  playbooks/system/class-signals.md   property -> vuln_class map (the applicability rules)
  <target>/attack-surface.md          the PROPOSED cells + properties + required principals
  <target>/tested.md                  the DONE (entrypoint x vuln_class x principal) cells

and reports, per entrypoint:

  UNTESTED      proposed or implied by properties, with no row in tested.md
  NOT-PROPOSED  implied by the recorded properties but absent from attack-surface.md
                -- the silent miss this tool exists to catch
  BLOCKED       tested.md says blocked (e.g. needs-account); NOT the same as untested
  PARTIAL       tested.md says partial
  DEFERRED      deliberately postponed; still unresolved

A missing file, a table that does not match the schema, and a table with zero rows are three
different outcomes and are reported as three different things. This tool never prints a
confident zero for an input it could not read.

Exit: 0 = no gaps · 1 = gaps found · 2 = could not read an input (schema drift / missing file).
"""
import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runlog   # noqa: E402
ROOT = Path(__file__).resolve().parent.parent
SIGNALS = ROOT / "playbooks" / "system" / "class-signals.md"

# Header aliases. The resolved choice is always printed so the mapping is auditable.
ENTRYPOINT_COLS = ("entrypoint", "target", "endpoint", "cluster", "surface")
CLASS_COLS = ("vuln_class", "class", "vuln class")
PROPERTY_COLS = ("properties", "props")
PRINCIPAL_COLS = ("principal", "principals", "required_principals", "required principals")
PLAN_VARIANT_COLS = ("variants", "variant", "planned_variants", "inputs")
VARIANT_COLS = ("variant", "input", "parameter", "param", "sink", "case")
ARTIFACT_COLS = ("artifact_ptr", "artifact", "evidence", "evidence_ptr")
METHOD_COLS = ("method", "how", "technique")
COVERAGE_COLS = ("coverage",)
RESULT_COLS = ("result",)
RESOLVED_RESULTS = {"not-vuln", "vuln", "out-of-scope", "not-applicable"}


def norm(cell):
    """Normalize a table cell for matching: drop markdown emphasis and collapse space."""
    s = re.sub(r"[*`]", "", cell)
    s = re.sub(r"\s+", " ", s).strip().lower()
    return s


def split_list(cell):
    """A comma- or middot-separated list inside an optionally-backticked cell."""
    return [p for p in (x.strip() for x in re.split(r"[,·;]", re.sub(r"[`*]", "", cell))) if p]


def parse_property_rules(cell):
    """Parse `a, b+c` as two alternatives: {a} OR ({b} AND {c})."""
    rules = []
    for alternative in split_list(cell):
        properties = frozenset(norm(value) for value in alternative.split("+") if norm(value))
        if properties:
            rules.append(properties)
    return rules


def parse_tables(path):
    """Every markdown table in the file as (headers, [row-dicts]). Separator rows dropped."""
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    tables, block = [], []
    for line in lines + [""]:
        if line.lstrip().startswith("|"):
            block.append(line)
            continue
        if len(block) >= 2:
            cells = [[c.strip() for c in b.strip().strip("|").split("|")] for b in block]
            headers = [norm(h) for h in cells[0]]
            rows = [dict(zip(headers, r)) for r in cells[2:]
                    if not all(re.fullmatch(r":?-{2,}:?", c) for c in r)]
            tables.append((headers, rows))
        block = []
    return tables


def pick_column(headers, aliases):
    """Exact match first, then 'alias followed by a non-word char' so real headers like
    `target (url / param / function)` resolve without matching `targeted_thing`."""
    for a in aliases:
        if a in headers:
            return a
    for a in aliases:
        for h in headers:
            if h.startswith(a) and (len(h) == len(a) or not h[len(a)].isalnum()):
                return h
    return None


def find_table(tables, required, path, what):
    """The first table carrying every required alias-group. Fails loud, never guesses."""
    for headers, rows in tables:
        resolved = {name: pick_column(headers, aliases) for name, aliases in required.items()}
        if all(resolved.values()):
            return resolved, rows, headers
    print(f"FAIL — {path}: no table with the columns needed for {what}.", file=sys.stderr)
    print(f"       needed (any alias per group): "
          + " · ".join(f"{k}={'/'.join(v)}" for k, v in required.items()), file=sys.stderr)
    for headers, rows in tables:
        print(f"       found instead: {headers} ({len(rows)} rows)", file=sys.stderr)
    if not tables:
        print("       found instead: no markdown tables at all", file=sys.stderr)
    return None, None, None


def load_signals():
    if not SIGNALS.exists():
        print(f"FAIL — missing {SIGNALS.relative_to(ROOT)}", file=sys.stderr)
        return None
    required = {"class": CLASS_COLS, "properties": PROPERTY_COLS}
    resolved, rows, _ = find_table(parse_tables(SIGNALS), required, SIGNALS,
                                   "the class->property map")
    if rows is None:
        return None
    class_rules = {}
    for r in rows:
        cls = norm(r[resolved["class"]])
        if not cls:
            continue
        rules = parse_property_rules(r[resolved["properties"]])
        if rules:
            class_rules.setdefault(cls, []).extend(rules)
    if not class_rules:
        print(f"FAIL — {SIGNALS.name} parsed but yielded 0 class predicates.", file=sys.stderr)
        return None
    # The vocabulary table is the authority for which tokens EXIST; the class table only
    # says which of them SELECT something. A documented-but-unreferenced token must be
    # recordable — `graphql` and `grpc` are transport lenses that class-signals explicitly
    # tells you to record, and inferring the vocabulary from class rules alone made them
    # unknown tokens that failed the run.
    vocab = parse_property_vocabulary()
    rule_tokens = {p for rules in class_rules.values() for rule in rules for p in rule}
    known_properties = vocab | rule_tokens
    return class_rules, known_properties


def parse_property_vocabulary():
    """Tokens from the `## Property vocabulary` table — the closed list of what may be recorded."""
    text = SIGNALS.read_text(encoding="utf-8", errors="replace")
    sec = re.search(r"^## Property vocabulary\b(.*?)(?=^## )", text, re.M | re.S)
    if not sec:
        return set()
    out = set()
    for line in sec.group(1).splitlines():
        m = re.match(r"\s*\|\s*(.+?)\s*\|", line)
        if not m or m.group(1).strip().lower() in {"property", "---"}:
            continue
        # a cell may carry several tokens: `graphql` `grpc` `websocket`
        out.update(tok for tok in re.findall(r"`([a-z0-9-]+)`", m.group(1)))
    return out


def implied_classes(properties, class_rules):
    return {
        cls for cls, rules in class_rules.items()
        if any(required.issubset(properties) for required in rules)
    }


def expected_cells(entrypoint):
    """Every class × principal × variant the plan says must be resolved.

    A variant is only expected if the PLAN named it. Coverage can see which variants were logged;
    it cannot invent the ones nobody proposed — so an entrypoint with no planned variants yields
    one coarse cell per (class, principal) and is reported as coarse rather than counted complete.
    """
    applicable = entrypoint["proposed"] | entrypoint["implied"]
    fallback = {
        principal
        for principals in entrypoint["principals"].values()
        for principal in principals
    } or {"unspecified"}
    out = set()
    for cls in applicable:
        variants = entrypoint.get("variants", {}).get(cls) or {""}
        for principal in (entrypoint["principals"].get(cls) or fallback):
            for variant in variants:
                out.add((cls, principal, variant))
    return out


def fmt(cell):
    """class@principal, plus the variant when the plan named one."""
    cls, principal, variant = cell
    return f"{cls}@{principal}" + (f"[{variant}]" if variant else "")


def cell_states(expected, logged):
    """Map each expected (class, principal, variant) cell to its tested state.

    An expected cell with a named variant is satisfied only by a row logging THAT variant. An
    expected cell with no variant ("") is satisfied by any row for that principal — and the caller
    reports it as coarse, because a coarse plan cannot produce precise coverage.
    """
    out = {}
    for cls, principal, variant in expected:
        by_key = logged.get(cls, {})
        states = []
        for k, s in by_key.items():
            kp, kv = (k if isinstance(k, tuple) else (k, ""))
            if kp != principal:
                continue
            if variant and kv != variant:
                continue
            states.append(s)
        if not states:
            out[(cls, principal, variant)] = None
        elif any(s == "partial" for s in states) or len(set(states)) > 1:
            out[(cls, principal, variant)] = "partial"
        else:
            out[(cls, principal, variant)] = states[0]
    return out

def coverage_state(coverage, result):
    """Normalize a tested row. `coverage=tested` must be BACKED by a resolved result.

    The column used to be trusted on its own, so `coverage=tested, result=<blank>` and
    `coverage=tested, result=inconclusive` both counted as finished work — which removed the cell
    from the untested list and made unfinished testing invisible. The result column is the
    evidence; the coverage column is a label, and a label cannot outrank its evidence.
    """
    if coverage.startswith("blocked") or coverage == "deferred":
        return coverage
    if result == "inconclusive":
        return "partial"                      # never resolved, whatever the label claims
    if coverage == "tested":
        return "tested" if result in RESOLVED_RESULTS else "partial"
    if coverage == "partial":
        return "partial"
    if not coverage and result in RESOLVED_RESULTS:
        return "tested"
    return None


def load_proposed(target, class_rules, known_properties):
    """Load proposed classes, observed properties, and required principals per entrypoint."""
    path = target / "attack-surface.md"
    if not path.exists():
        print(f"FAIL — {path} missing. Run skills/attack-surface-prioritization.md "
              f"before asking for coverage.", file=sys.stderr)
        return None
    tables = parse_tables(path)
    required = {
        "entrypoint": ENTRYPOINT_COLS,
        "class": CLASS_COLS,
        "principals": PRINCIPAL_COLS,
    }
    resolved, rows, headers = find_table(tables, required, path,
                                         "the proposed (entrypoint x class) matrix")
    if rows is None:
        print("       -> attack-surface.md predates the (entrypoint x vuln_class) schema in "
              "playbooks/system/target-schema.md. Coverage is NOT computable until "
              "`attack-surface-prioritization` re-emits it. Reporting nothing rather than "
              "reporting zero.", file=sys.stderr)
        return None
    prop_col = pick_column(headers, PROPERTY_COLS)
    plan_var_col = pick_column(headers, PLAN_VARIANT_COLS)
    out = {}
    missing_principals = []
    for r in rows:
        ep = norm(r[resolved["entrypoint"]])
        cls = norm(r[resolved["class"]])
        if not ep:
            continue
        e = out.setdefault(
            ep,
            {"proposed": set(), "implied": set(), "props": set(), "principals": {},
             "variants": {}},
        )
        if cls:
            e["proposed"].add(cls)
            principal_cell = r.get(resolved["principals"], "")
            principals = {
                norm(principal) for principal in split_list(principal_cell) if norm(principal)
            }
            if not principals:
                missing_principals.append(f"{ep} × {cls}")
            e["principals"].setdefault(cls, set()).update(principals)
            # variants are OPTIONAL. Declared -> each one is its own expected cell. Absent ->
            # a single coarse cell, reported as coarse rather than counted complete.
            if plan_var_col:
                planned = {norm(v) for v in split_list(r.get(plan_var_col, "")) if norm(v)}
                if planned:
                    e["variants"].setdefault(cls, set()).update(planned)
        if prop_col:
            # A SURFACE row lists the properties an entrypoint HAS — a flat set. The class
            # table uses `+` to mean AND, and people write surface cells the same way, so a
            # cell reading `cacheable+unkeyed-input` arrived as one unknown token and failed
            # the whole run. Split it here; `split_list` must NOT, because the class table
            # depends on `+` surviving to build its AND-groups.
            for chunk in split_list(r.get(prop_col, "")):
                for p in (x.strip() for x in chunk.split("+")):
                    if p:
                        e["props"].add(p.lower())
    if missing_principals:
        print(
            f"FAIL — {path}: {len(missing_principals)} candidate row(s) have no required principal.",
            file=sys.stderr,
        )
        for cell in missing_principals[:10]:
            print(f"       {cell}", file=sys.stderr)
        return None
    for entrypoint in out.values():
        entrypoint["implied"] = implied_classes(entrypoint["props"], class_rules)
    observed_properties = {prop for entrypoint in out.values() for prop in entrypoint["props"]}
    unknown = observed_properties - known_properties
    return out, prop_col, unknown


def load_tested(target):
    path = target / "tested.md"
    if not path.exists():
        print(f"FAIL — {path} missing.", file=sys.stderr)
        return None
    required = {
        "entrypoint": ENTRYPOINT_COLS,
        "class": CLASS_COLS,
        "principal": PRINCIPAL_COLS,
    }
    # `variant` is what stops one row clearing a whole class on an entrypoint. `POST /search`
    # SQLi tested on `q` says nothing about `filters[name]`, about an XML body reaching a
    # different parser, or about the `/v1` handler. Optional — but when it is absent the cell is
    # reported as coarse rather than silently counted as complete.
    resolved, rows, headers = find_table(parse_tables(path), required, path, "the tested ledger")
    if rows is None:
        return None
    cov_col = pick_column(headers, COVERAGE_COLS)
    res_col = pick_column(headers, RESULT_COLS)
    var_col = pick_column(headers, VARIANT_COLS)
    art_col = pick_column(headers, ARTIFACT_COLS)
    met_col = pick_column(headers, METHOD_COLS)
    done = {}
    invalid_rows, unevidenced, conflicts, coarse = [], [], [], set()
    for r in rows:
        ep = norm(r[resolved["entrypoint"]])
        cls = norm(r[resolved["class"]])
        if not ep or not cls:
            continue  # the template's empty placeholder row
        principal = norm(r[resolved["principal"]]) or "unspecified"
        variant = norm(r.get(var_col, "")) if var_col else ""
        raw_coverage = norm(r.get(cov_col, "")) if cov_col else ""
        result = norm(r.get(res_col, "")) if res_col else ""
        artifact = norm(r.get(art_col, "")) if art_col else ""
        method = norm(r.get(met_col, "")) if met_col else ""
        state = coverage_state(raw_coverage, result)
        if state is None:
            invalid_rows.append(f"{ep} × {cls} × {principal}")
            continue

        # A resolved NEGATIVE is the strongest claim in the ledger — "I checked, it is fine" —
        # and it is the one that removes work from the list. It has to be backed. A row that
        # says not-vuln with no artifact and no method is an assertion, not a result.
        if state == "tested" and result in ("not-vuln", "not-applicable"):
            if not artifact or not method:
                why = ("the ledger has no artifact_ptr/method column at all"
                       if not (art_col and met_col)
                       else ("no artifact" if not artifact else "no method"))
                unevidenced.append((f"{ep} × {cls} × {principal}", why))
                state = "partial"

        key = (principal, variant)
        prior = done.setdefault(ep, {}).setdefault(cls, {}).get(key)
        # Never let a later row silently overwrite a stronger earlier one. Downgrades (a reopen)
        # are legitimate and recorded; a silent upgrade is how an unevidenced row erases a
        # careful one.
        if prior and prior != state:
            conflicts.append(f"{ep} × {cls} × {principal}"
                             + (f" × {variant}" if variant else "")
                             + f": {prior} then {state}")
        done[ep][cls][key] = state
        if not variant:
            coarse.add((ep, cls))
    if invalid_rows:
        print(
            f"FAIL — {path}: {len(invalid_rows)} tested row(s) have no valid result/coverage.",
            file=sys.stderr,
        )
        for cell in invalid_rows[:10]:
            print(f"       {cell}", file=sys.stderr)
        return None

    if unevidenced:
        if not (art_col and met_col):
            print(f"\n  ⚠ This tested.md predates the evidence columns, so all "
                  f"{len(unevidenced)} resolved\n    negative(s) read as PARTIAL — not because the "
                  f"work was sloppy, but because the file\n    cannot show whether it was "
                  f"evidenced. Add `method` and `artifact_ptr` columns and\n    backfill the rows "
                  f"you still trust; leave the rest open.")
            return done
        print(f"\n  ⚠ {len(unevidenced)} resolved negative(s) DOWNGRADED to partial — a "
              f"'not-vuln' with no\n    evidence is an assertion, not a result:")
        for cell, why in unevidenced[:8]:
            print(f"      {cell}  ({why})")
        print("    Add the artifact pointer and the method, or leave the cell open.")

    if conflicts:
        print(f"\n  ⚠ {len(conflicts)} cell(s) have conflicting rows. Later rows no longer "
              f"silently win —\n    reconcile them, or add a `variant` so they are different "
              f"cells:")
        for c in conflicts[:8]:
            print(f"      {c}")

    if coarse:
        print(f"\n  ⚠ {len(coarse)} cell(s) were cleared WITHOUT naming a variant. Coverage for "
              f"those is\n    as coarse as the row: 'SQLi on POST /search' says nothing about "
              f"which parameter,\n    body format, or handler version was actually reached.")
        for ep, cls in sorted(coarse)[:6]:
            print(f"      {ep} × {cls}")
        print("    Add a `variant` column (parameter · input location · parser · handler) to make\n"
              "    these separate cells instead of one broad claim.")
    return done


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="path to targets/<slug>")
    ap.add_argument("--entrypoint", help="only entrypoints whose name contains this substring")
    args = ap.parse_args()

    target = Path(args.target).resolve()
    if not target.is_dir():
        print(f"FAIL — {args.target} is not a directory", file=sys.stderr)
        return 2

    signals = load_signals()
    if signals is None:
        return 2
    class_rules, known_properties = signals
    proposed = load_proposed(target, class_rules, known_properties)
    if proposed is None:
        return 2
    surface, prop_col, unknown_props = proposed
    done = load_tested(target)
    if done is None:
        return 2

    print(f"# coverage — {target.name}")
    predicate_count = sum(len(rules) for rules in class_rules.values())
    print(f"  rules: {len(known_properties)} properties · {predicate_count} class predicates"
          f"  ({SIGNALS.name})")
    print(f"  attack-surface.md: {len(surface)} entrypoints"
          + ("" if prop_col else "  ⚠ no `properties` column — NOT-PROPOSED cannot be computed"))
    logged_cells = sum(
        len(principals)
        for classes in done.values()
        for principals in classes.values()
    )
    print(f"  tested.md: {logged_cells} logged cells")
    if not surface:
        print("  ⚠ attack-surface.md has the right columns but ZERO rows — nothing is proposed, "
              "so 'no gaps' would be meaningless. Run `attack-surface-prioritization`.")
        return 2
    if unknown_props:
        print(f"  ⚠ properties not in the vocabulary; coverage cannot be trusted: "
              f"{', '.join(sorted(unknown_props))}")

    orphans = {ep for ep in done if ep not in surface}
    gaps = 0
    mismatched_cells = 0
    for ep in sorted(surface):
        if args.entrypoint and args.entrypoint.lower() not in ep:
            continue
        e = surface[ep]
        applicable = e["proposed"] | e["implied"]
        logged = done.get(ep, {})
        not_proposed = sorted(e["implied"] - e["proposed"])
        expected = expected_cells(e)
        states = cell_states(expected, logged)
        untested = sorted(cell for cell, state in states.items() if state is None)
        blocked = sorted(cell for cell, state in states.items()
                         if state and state.startswith("blocked"))
        partial = sorted(cell for cell, state in states.items() if state == "partial")
        deferred = sorted(cell for cell, state in states.items() if state == "deferred")
        # logged is keyed by (principal, variant); `expected` names principals only. A row is
        # unplanned when its PRINCIPAL is not in the proposed cells — a new variant under a
        # planned principal is extra depth, not a schema mismatch.
        planned_principals = {(c, p) for c, p, _ in expected}
        unexpected = sorted(
            (cls, principal)
            for cls, keys in logged.items()
            for principal in ((k[0] if isinstance(k, tuple) else k) for k in keys)
            if (cls, principal) not in planned_principals
        )
        # a cell the plan left variant-less can never be more precise than the plan
        coarse_cells = sorted(c for c in expected if not c[2])

        print(f"\n## {ep}")
        n_var = len({c[2] for c in expected if c[2]})
        print(f"   applicable {len(applicable)} classes / {len(expected)} cells"
              f"{f' ({n_var} planned variants)' if n_var else ''}"
              f" · logged {sum(len(v) for v in logged.values())} · untested {len(untested)}")
        if e["props"]:
            print(f"   properties : {', '.join(sorted(e['props']))}")
        if untested:
            gaps += len(untested)
            marked = [fmt(c) + (" *" if c[0] in not_proposed else "") for c in untested]
            print(f"   UNTESTED   : {', '.join(marked)}")
        only_np = sorted(cls for cls in not_proposed if cls in logged)
        if only_np:
            print(f"   NOT-PROPOSED but already tested: {', '.join(only_np)}")
        if blocked:
            cells = ", ".join(fmt(c) for c in blocked)
            print(f"   BLOCKED    : {cells}  (not the same as untested)")
        if partial:
            print("   PARTIAL    : "
                  + ", ".join(fmt(c) for c in partial))
        if deferred:
            print("   DEFERRED   : "
                  + ", ".join(fmt(c) for c in deferred))
        if unexpected:
            mismatched_cells += len(unexpected)
            print("   UNPLANNED  : "
                  + ", ".join(f"{cls}@{principal}" for cls, principal in unexpected))
            print("                add/fix the attack-surface principal cell before trusting coverage")
        if coarse_cells:
            print(f"   COARSE     : {len(coarse_cells)} cell(s) have no planned variant — "
                  f"resolving one\n                input does not resolve the class. Add a "
                  f"`variants` value in attack-surface.md.")
        gaps += len(blocked) + len(partial) + len(deferred)
        if not untested and not blocked and not partial and not deferred:
            print("   complete   : every required class/principal cell is resolved")

    if orphans:
        print(f"\n⚠ {len(orphans)} tested.md entrypoint(s) match nothing in attack-surface.md — "
              f"either a naming drift or testing outside the ranked surface:")
        for o in sorted(orphans):
            print(f"   {o}")
    print(f"\ntotal unresolved cells: {gaps}"
          + ("  (* = implied by properties but never proposed in attack-surface.md)"
             if gaps else ""))
    if unknown_props:
        return 2
    return 1 if gaps or orphans or mismatched_cells else 0


if __name__ == "__main__":
    sys.exit(runlog.wrap()(main)())
