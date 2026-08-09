#!/usr/bin/env python3
"""Verify every `#<id>` citation in a class's playbook files resolves to a real,
fetched report — and say which ones were actually in the mined (rendered) sample.

Generic: takes class slugs, derives every path from them, and fails loud if an
input directory is missing rather than reporting a confident zero.

    knowledge/tools/check-citations.py xss ssrf ...
    knowledge/tools/check-citations.py --all

Exit 0 = clean, 1 = orphans/unfetched citations found, 2 = bad input.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VULNS = ROOT / "playbooks" / "vulns"
CORPUS = ROOT / "knowledge" / "reports"
CITE = re.compile(r"#(\d{4,9})\b")


def files_for(cls):
    return [p for p in (VULNS / f"{cls}.md", VULNS / "ref" / f"{cls}.md") if p.exists()]


def check(cls):
    corpus_dir = CORPUS / cls
    if not corpus_dir.is_dir():
        print(f"{cls}: FAIL — no corpus at {corpus_dir.relative_to(ROOT)}")
        return 2
    docs = files_for(cls)
    if not docs:
        print(f"{cls}: FAIL — no playbook file at playbooks/vulns/{cls}.md")
        return 2

    fetched = {p.stem for p in corpus_dir.glob("*.json")}
    md_dir = corpus_dir / "md"
    rendered = {p.stem for p in md_dir.glob("*.md")} if md_dir.is_dir() else set()
    if not fetched:
        print(f"{cls}: FAIL — corpus dir exists but holds 0 *.json")
        return 2

    cites = {}
    for doc in docs:
        for m in CITE.finditer(doc.read_text(encoding="utf-8")):
            cites.setdefault(m.group(1), []).append(doc.name)

    unfetched = sorted(i for i in cites if i not in fetched)
    unrendered = sorted(i for i in cites if i in fetched and i not in rendered)

    print(f"{cls}: {len(cites)} distinct citations across {', '.join(d.name for d in docs)}")
    print(f"  corpus: {len(fetched)} fetched · {len(rendered)} rendered/sampled")
    print(f"  cited but NEVER FETCHED (possible fabrication): {len(unfetched)}"
          + ("" if not unfetched else " -> " + ", ".join("#" + i for i in unfetched)))
    print(f"  cited, fetched, but outside the rendered sample: {len(unrendered)}"
          + ("" if not unrendered else " -> " + ", ".join("#" + i for i in unrendered)))
    return 1 if unfetched else 0


def main(argv):
    classes = argv[1:]
    if not classes:
        print(__doc__)
        return 2
    if classes == ["--all"]:
        classes = sorted(p.name for p in CORPUS.iterdir()
                         if p.is_dir() and files_for(p.name))
        if not classes:
            print("FAIL — --all matched no class with both a corpus and a playbook")
            return 2
    return max(check(c) for c in classes)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
