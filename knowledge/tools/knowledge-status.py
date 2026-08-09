#!/usr/bin/env python3
"""Show which local knowledge files have not been evaluated against a skill or playbook.

Preferred layout:

    knowledge/<subject>/...any user-supplied reports, notes, or research...

For compatibility, knowledge/reports/<subject>/ is also accepted. A rendered md/<id>.md wins over
the matching raw <id>.json; raw-only and other non-hidden files remain visible.

Examples:

    knowledge/tools/knowledge-status.py javascript-analysis
    knowledge/tools/knowledge-status.py idor-bola
    knowledge/tools/knowledge-status.py oauth-notes --destination playbooks/vulns/oauth-oidc.md
    knowledge/tools/knowledge-status.py javascript-analysis --record

Files are NEW, CHANGED, EVALUATED, or STALE. ``--record`` is only for after the named destination
was deliberately kept or improved. The local manifest is gitignored.

Exit: 0 = no new/changed knowledge · 1 = evaluation needed · 2 = could not answer.
"""
import argparse
import hashlib
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
KNOWLEDGE = ROOT / "knowledge"
MANIFEST = KNOWLEDGE / "MINED.tsv"
HEADER = ["subject", "file", "sha256", "evaluated_utc", "destination", "destination_sha256"]
LEGACY_HEADER = ["class", "file", "sha256", "mined_utc", "playbook_sha256"]
DESTINATION_DIRS = (
    ROOT / "skills",
    ROOT / "playbooks" / "vulns",
    ROOT / "playbooks" / "tech",
    ROOT / "playbooks" / "flows",
    ROOT / "playbooks" / "workflows",
)
SUBJECT_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]*$")


@dataclass(frozen=True)
class Evaluation:
    subject: str
    files: tuple
    buckets: dict
    destination: str
    destination_sha256: str


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _legacy_row(parts):
    old = dict(zip(LEGACY_HEADER, parts))
    subject = old["class"]
    return {
        "subject": subject,
        "file": f"reports/{subject}/{old['file']}",
        "sha256": old["sha256"],
        "evaluated_utc": old["mined_utc"],
        "destination": f"playbooks/vulns/{subject}.md",
        "destination_sha256": old["playbook_sha256"],
    }


def load_manifest():
    if not MANIFEST.exists():
        return {}
    rows = {}
    seen_header = None
    for number, line in enumerate(MANIFEST.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        if parts in (HEADER, LEGACY_HEADER):
            seen_header = parts
            continue
        active = seen_header or HEADER
        if len(parts) != len(active):
            print(
                f"FAIL — {MANIFEST.name} line {number}: expected {len(active)} columns, "
                f"got {len(parts)}. Refusing to guess.",
                file=sys.stderr,
            )
            raise SystemExit(2)
        row = _legacy_row(parts) if active == LEGACY_HEADER else dict(zip(HEADER, parts))
        rows[(row["subject"], row["file"])] = row
    return rows


def write_manifest(rows):
    lines = ["\t".join(HEADER)]
    for key in sorted(rows):
        lines.append("\t".join(rows[key][column] for column in HEADER))
    MANIFEST.write_text("\n".join(lines) + "\n", encoding="utf-8")


def source_dir(subject):
    if not SUBJECT_SLUG.fullmatch(subject):
        print(
            f"FAIL — invalid subject {subject!r}; use a lowercase skill-style slug.",
            file=sys.stderr,
        )
        return None
    direct = KNOWLEDGE / subject
    legacy = KNOWLEDGE / "reports" / subject
    found = [path for path in (direct, legacy) if path.is_dir()]
    if len(found) > 1:
        print(
            f"FAIL — knowledge for {subject!r} exists in both {direct.relative_to(ROOT)}/ and "
            f"{legacy.relative_to(ROOT)}/. Keep one source directory so no file is silently skipped.",
            file=sys.stderr,
        )
        return None
    if not found:
        print(
            f"FAIL — no knowledge directory for {subject!r}.\n"
            f"       Put source material in knowledge/{subject}/ and run this again.",
            file=sys.stderr,
        )
        return None
    return found[0]


def source_files(subject):
    base = source_dir(subject)
    if base is None:
        return None
    files = [
        path
        for path in sorted(base.rglob("*"))
        if path.is_file()
        and not path.is_symlink()
        and not any(part.startswith(".") for part in path.relative_to(base).parts)
    ]
    # A legacy HackerOne corpus may hold raw <id>.json plus a richer md/<id>.md rendering.
    # Prefer the rendering when both exist, but keep raw-only reports visible to evaluation.
    if base.parent == KNOWLEDGE / "reports":
        rendered = {path.stem for path in files if path.parent == base / "md" and path.suffix == ".md"}
        files = [
            path
            for path in files
            if not (path.parent == base and path.suffix == ".json" and path.stem in rendered)
        ]
    return files


def explicit_destination(raw_path):
    candidate = Path(raw_path)
    path = (ROOT / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    try:
        path.relative_to(ROOT.resolve())
    except ValueError:
        print("FAIL — --destination must stay inside this workspace.", file=sys.stderr)
        return None
    if not path.is_file():
        print(f"FAIL — destination does not exist: {path}", file=sys.stderr)
        return None
    return path


def destination_for(subject, explicit=None):
    if explicit:
        return explicit_destination(explicit)

    candidates = [directory / f"{subject}.md" for directory in DESTINATION_DIRS]
    candidates = [path for path in candidates if path.is_file()]
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        print(
            f"FAIL — no skill or playbook named {subject!r}. Use --destination <repo-relative-file>.",
            file=sys.stderr,
        )
    else:
        names = ", ".join(str(path.relative_to(ROOT)) for path in candidates)
        print(
            f"FAIL — {subject!r} matches more than one destination: {names}. Use --destination.",
            file=sys.stderr,
        )
    return None


def classify(subject, files, destination, manifest):
    destination_hash = sha(destination)
    destination_rel = destination.relative_to(ROOT).as_posix()
    buckets = {"NEW": [], "CHANGED": [], "EVALUATED": [], "STALE": []}
    for path in files:
        rel = path.relative_to(KNOWLEDGE).as_posix()
        digest = sha(path)
        recorded = manifest.get((subject, rel))
        if recorded is None:
            buckets["NEW"].append((rel, digest))
        elif recorded["sha256"] != digest:
            buckets["CHANGED"].append((rel, digest))
        elif recorded["destination"] != destination_rel or recorded["destination_sha256"] not in (
            "-",
            destination_hash,
        ):
            buckets["STALE"].append((rel, digest))
        else:
            buckets["EVALUATED"].append((rel, digest))
    return Evaluation(subject, tuple(files), buckets, destination_rel, destination_hash)


def print_changed_paths(evaluation, limit):
    for state in ("NEW", "CHANGED"):
        entries = evaluation.buckets[state]
        visible = entries if limit == 0 else entries[:limit]
        for rel, _ in visible:
            print(f"     {state:<8} {rel}")
        remaining = len(entries) - len(visible)
        if remaining:
            print(f"              … and {remaining} more (use --list 0 to show all)")


def report(evaluation, show):
    counts = {name: len(entries) for name, entries in evaluation.buckets.items()}
    todo = counts["NEW"] + counts["CHANGED"]
    print(f"\n{evaluation.subject}: {len(evaluation.files)} knowledge file(s) -> {evaluation.destination}")
    print(f"  NEW        {counts['NEW']:>5}   never evaluated")
    print(f"  CHANGED    {counts['CHANGED']:>5}   content differs from the recorded hash")
    print(f"  EVALUATED  {counts['EVALUATED']:>5}   already considered — skip")
    print(f"  STALE      {counts['STALE']:>5}   destination changed since evaluation")
    if todo:
        print(f"  -> read {todo} new or changed file(s), then keep or improve the destination.")
        print_changed_paths(evaluation, show)
    else:
        print("  -> no new or changed knowledge to evaluate.")
    return todo


def subjects_on_disk():
    direct = {
        path.name
        for path in KNOWLEDGE.iterdir()
        if path.is_dir()
        and path.name not in {"tools", "reports"}
        and SUBJECT_SLUG.fullmatch(path.name)
    }
    reports = KNOWLEDGE / "reports"
    legacy = (
        {path.name for path in reports.iterdir() if path.is_dir() and SUBJECT_SLUG.fullmatch(path.name)}
        if reports.is_dir()
        else set()
    )
    return sorted(direct | legacy)


def nonnegative_int(raw):
    value = int(raw)
    if value < 0:
        raise argparse.ArgumentTypeError("must be 0 or greater")
    return value


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("subjects", nargs="*", help="knowledge subject, usually a skill/playbook slug")
    parser.add_argument("--all", action="store_true", help="every subject directory under knowledge/")
    parser.add_argument("--destination", help="repo-relative destination; valid with one subject only")
    parser.add_argument(
        "--record",
        action="store_true",
        help="record hashes only after the destination was deliberately kept or improved",
    )
    parser.add_argument(
        "--list",
        type=nonnegative_int,
        default=10,
        metavar="N",
        help="show up to N changed paths (default 10; 0 = all)",
    )
    args = parser.parse_args()
    if args.destination and (args.all or len(args.subjects) != 1):
        parser.error("--destination requires exactly one named subject")
    return parser, args


def evaluate_subject(subject, explicit, manifest, show):
    files = source_files(subject)
    destination = destination_for(subject, explicit)
    if files is None or destination is None:
        return None, 0
    if not files:
        print(
            f"FAIL — the knowledge directory for {subject!r} is empty. Add source material first.",
            file=sys.stderr,
        )
        return None, 0
    evaluation = classify(subject, files, destination, manifest)
    return evaluation, report(evaluation, show)


def record_evaluations(manifest, evaluations):
    evaluated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for evaluation in evaluations:
        for state, entries in evaluation.buckets.items():
            for rel, digest in entries:
                previous = manifest.get((evaluation.subject, rel))
                manifest[(evaluation.subject, rel)] = {
                    "subject": evaluation.subject,
                    "file": rel,
                    "sha256": digest,
                    "evaluated_utc": (
                        previous["evaluated_utc"]
                        if previous and state == "EVALUATED"
                        else evaluated_at
                    ),
                    "destination": evaluation.destination,
                    "destination_sha256": evaluation.destination_sha256,
                }
    write_manifest(manifest)
    print(f"\nrecorded {len(manifest)} file hashes -> {MANIFEST.relative_to(ROOT)}")


def run(parser, args):
    subjects = subjects_on_disk() if args.all else args.subjects
    if not subjects:
        parser.print_help()
        return 2

    manifest = load_manifest()
    evaluations = []
    failed = 0
    total_todo = 0
    for subject in subjects:
        evaluation, todo = evaluate_subject(subject, args.destination, manifest, args.list)
        if evaluation is None:
            failed += 1
            continue
        total_todo += todo
        evaluations.append(evaluation)

    if args.record:
        if failed:
            print(
                "\nREFUSING to --record because at least one subject could not be evaluated.",
                file=sys.stderr,
            )
            return 2
        record_evaluations(manifest, evaluations)

    if failed:
        return 2
    print(f"\ntotal requiring evaluation: {total_todo}")
    if args.record:
        return 0
    return 1 if total_todo else 0


def main():
    parser, args = parse_args()
    return run(parser, args)


if __name__ == "__main__":
    sys.exit(main())
