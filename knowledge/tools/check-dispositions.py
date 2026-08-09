#!/usr/bin/env python3
"""check-dispositions.py — audit a grounded playbook's citations against report dispositions.

    knowledge/tools/check-dispositions.py <class-slug> [--quiet]

Every cached HackerOne report carries a `substate` (resolved / informative /
not-applicable / duplicate / spam). **Presence in a corpus is not acceptance.**
A playbook that cites an informative or N/A report as a working technique is
teaching something a program explicitly declined.

For the given class this reports, per citation:
  - the report's substate
  - whether the citation is flagged inline (a disposition word within +/-260
    chars of the citation, matching how the reference layers annotate)

Exit 1 if any non-resolved citation is unflagged, so it can gate a build.
Generic: no class-specific paths, works for any class under knowledge/reports/.
"""
import json, os, re, sys
from pathlib import Path
from collections import Counter

# Deliberately narrow. "closed" was in this list and matched ordinary prose
# ("closed as", "the program closed"), silently passing unflagged citations.
FLAG_WORDS = ("informative", "not-applicable", "not applicable", "duplicate",
              "spam", "declined", "n/a")
WINDOW = 200  # chars either side of the citation to search for a flag
ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    quiet = "--quiet" in sys.argv
    if len(args) != 1:
        print(__doc__.strip().split("\n\n")[1], file=sys.stderr)
        return 2
    cls = args[0]

    ref = os.path.join(ROOT, "playbooks", "vulns", "ref", f"{cls}.md")
    corpus = os.path.join(ROOT, "knowledge", "reports", cls)

    if not os.path.isfile(ref):
        print(f"FAIL: no reference layer at playbooks/vulns/ref/{cls}.md", file=sys.stderr)
        return 2
    if not os.path.isdir(corpus):
        print(f"FAIL: no corpus at knowledge/reports/{cls}/", file=sys.stderr)
        return 2

    text = open(ref, encoding="utf-8").read()
    ids = sorted(set(re.findall(r"#(\d{4,8})", text)))
    if not ids:
        print(f"FAIL: no citations found in {ref}", file=sys.stderr)
        return 1

    counts, missing, unflagged, flagged = Counter(), [], [], []
    for rid in ids:
        path = os.path.join(corpus, f"{rid}.json")
        if not os.path.isfile(path):
            missing.append(rid)
            continue
        try:
            sub = json.load(open(path, encoding="utf-8")).get("substate")
        except Exception as exc:                      # corrupt cache -> loud, not silent
            print(f"  READ-FAIL {rid}: {exc}")
            missing.append(rid)
            continue
        counts[sub] += 1
        if sub == "resolved":
            continue
        # EVERY occurrence must be flagged, not just one. A citation marked in
        # section A and reused bare in section B is unflagged where it is reused.
        occurrences = list(re.finditer(r"#" + rid + r"\b", text))
        bare = [
            m for m in occurrences
            if not any(w in text[max(0, m.start() - WINDOW): m.start() + WINDOW].lower()
                       for w in FLAG_WORDS)
        ]
        if bare:
            unflagged.append((rid, f"{sub} ({len(bare)}/{len(occurrences)} occurrences bare)"))
        else:
            flagged.append((rid, sub))

    print(f"{cls}: {len(ids)} citations · {dict(counts)}")
    if missing:
        print(f"  ORPHANED (no corpus file): {', '.join(missing)}")
    print(f"  non-resolved: {len(flagged) + len(unflagged)} · flagged inline: {len(flagged)}"
          f" · UNFLAGGED: {len(unflagged)}")

    if unflagged and not quiet:
        for rid, sub in unflagged:
            line = next((l.strip() for l in text.split("\n") if "#" + rid in l), "")
            print(f"    [{sub:<14}] #{rid}  {line[:120]}")

    return 1 if (unflagged or missing) else 0


if __name__ == "__main__":
    sys.exit(main())
