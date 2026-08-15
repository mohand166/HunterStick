#!/usr/bin/env python3
"""Build the human-readable target progress view from durable ledgers.

    tools/progress.py targets/acme            # write targets/acme/progress.md
    tools/progress.py targets/acme --stdout   # preview without writing

The view joins three authorities rather than asking a model to maintain duplicate history:
`runs.tsv` for bounded objectives, `tested.md` for vulnerability probes, and pulled
`logs/exec/*.json` records for exact redacted commands, options, inputs, and artifacts.

Commands whose target cannot be proved from their argv or run selector remain in the
multi-asset/unresolved table. They are never guessed onto every host in an input file.

Exit: 0 rendered · 2 malformed/missing source data or unusable target.
"""
import argparse
import csv
import ipaddress
import json
import re
import shlex
import sys
from collections import Counter
from itertools import groupby
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runlog                                                   # noqa: E402


RUN_COLUMNS = ["run_id", "date", "phase", "selector", "sources", "budget",
               "status", "result", "output_ptr", "limitations", "resume_from", "scope_sha"]
DOMAIN = re.compile(r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_-])")
URL = re.compile(r"https?://[^\s'\"<>]+", re.I)
TARGET_FLAGS = {"-u", "--url", "--host", "--target", "-target"}
BROAD_SELECTOR = re.compile(
    r"(?:\*\.|\b(?:all|apex|wildcard|hosts|names|estate|scope|candidates|subdomains|"
    r"resolved|enumerated|cohort|set)\b)", re.I)


class ProgressError(ValueError):
    pass


def cell(value):
    text = " ".join(str(value or "").split()) or "—"
    return text.replace("|", "\\|")


def markdown_table(headers, rows):
    lines = ["| " + " | ".join(headers) + " |",
             "|" + "|".join("---" for _ in headers) + "|"]
    lines.extend("| " + " | ".join(cell(value) for value in row) + " |" for row in rows)
    return "\n".join(lines)


def read_runs(target):
    path = target / "runs.tsv"
    if not path.exists():
        return []
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        if not reader.fieldnames or not {"run_id", "phase", "selector", "status"}.issubset(reader.fieldnames):
            raise ProgressError(f"{path}: invalid runs.tsv header")
        rows = [{key: (row.get(key) or "").strip() for key in RUN_COLUMNS}
                for row in reader if (row.get("run_id") or "").strip()]
    latest = {}
    for row in rows:
        latest[row["run_id"]] = row
    return list(latest.values())


def markdown_rows(path):
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    tables, block = [], []
    for line in lines + [""]:
        if line.lstrip().startswith("|"):
            block.append(line)
            continue
        if len(block) >= 2:
            parsed = [[part.strip() for part in row.strip().strip("|").split("|")]
                      for row in block]
            headers = [re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
                       for value in parsed[0]]
            for values in parsed[2:]:
                if any(values) and not all(re.fullmatch(r":?-{2,}:?", value) for value in values):
                    tables.append(dict(zip(headers, values)))
        block = []
    return tables


def asset(value):
    candidate = (value or "").strip().strip("(),;`'\"")
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1:candidate.index("]")]
    else:
        candidate = candidate.strip("[]")
    if not candidate or candidate.startswith("*."):
        return None
    if candidate.count(":") == 1:
        host, port = candidate.rsplit(":", 1)
        if port.isdigit():
            candidate = host
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass
    if re.fullmatch(r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}", candidate):
        return candidate.lower().rstrip(".")
    return None


def assets_in_text(text):
    found = set()
    without_urls = text or ""
    for match in URL.finditer(without_urls):
        host = urlsplit(match.group(0).rstrip(".,);]")).hostname
        if host and asset(host):
            found.add(asset(host))
    without_urls = URL.sub(" ", without_urls)
    for match in DOMAIN.finditer(without_urls):
        value = asset(match.group(0))
        if value:
            found.add(value)
    for token in re.split(r"[\s,;]+", without_urls):
        value = asset(token)
        if value:
            found.add(value)
    return sorted(found)


def exact_selector_asset(selector):
    """Return one asset only when the selector itself names exactly that asset."""
    value = (selector or "").strip().strip("`'\"")
    if asset(value):
        return asset(value)
    if re.fullmatch(r"https?://[^\s]+", value, re.I):
        return asset(urlsplit(value).hostname or "")
    candidates = assets_in_text(value)
    if len(candidates) == 1 and not BROAD_SELECTOR.search(value):
        return candidates[0]
    return None


def target_value_asset(value):
    """Extract an asset from a value explicitly used as a command target."""
    candidate = str(value).strip()
    if re.fullmatch(r"https?://[^\s]+", candidate, re.I):
        return asset(urlsplit(candidate).hostname or "")
    return asset(candidate)


def command_assets(argv):
    """Assets named by target flags, excluding URLs carried in headers or payloads."""
    found = set()
    for index, token in enumerate(argv[:-1]):
        if token in TARGET_FLAGS:
            value = target_value_asset(argv[index + 1])
            if value:
                found.add(value)
    for token in argv:
        option, separator, option_value = str(token).partition("=")
        if separator and option in TARGET_FLAGS:
            value = target_value_asset(option_value)
            if value:
                found.add(value)
    return sorted(found)


def read_exec_records(target):
    records = []
    for path in sorted((target / "logs" / "exec").glob("*.json")):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ProgressError(f"{path}: unreadable execution record ({error})") from error
        required = {"ts", "skill", "tool", "argv", "exit"}
        if not required.issubset(record) or not isinstance(record["argv"], list):
            raise ProgressError(f"{path}: execution record is missing {sorted(required)}")
        record["_path"] = path.relative_to(target).as_posix()
        records.append(record)
    return records


def field(row, *names):
    for name in names:
        if row.get(name):
            return row[name]
    return ""


def record_inputs(record):
    values = []
    for item in record.get("inputs") or []:
        if not isinstance(item, dict) or not item.get("path"):
            continue
        digest = item.get("sha256_16")
        values.append(f"{item['path']} ({digest})" if digest else str(item["path"]))
    return "; ".join(values) or "—"


def record_evidence(record):
    pointers = [record["_path"]]
    artifact = record.get("artifact")
    if isinstance(artifact, dict) and artifact.get("path"):
        pointers.append(str(artifact["path"]))
    return "; ".join(pointers)


def record_date(record):
    started = str(record.get("started") or "")
    if started:
        return started[:19].replace("T", " ")
    stamp = str(record.get("ts") or "")
    return stamp[:8] if len(stamp) >= 8 else stamp


def scope_progress_rows(runs, records):
    counts = Counter(str(record.get("run_id") or "") for record in records)
    return [[row["date"], row["run_id"], row["phase"], row["selector"],
             row["sources"], row["budget"], row["status"],
             f"{row['result'] or '—'}" + (f" · {counts[row['run_id']]} command(s)"
                                          if counts[row["run_id"]] else ""),
             row["limitations"]]
            for row in sorted(runs, key=lambda run: (run["date"], run["run_id"]))]


def bounded_host_rows(runs):
    rows = []
    for row in runs:
        selected = exact_selector_asset(row["selector"])
        if selected:
            rows.append([selected, row["date"], row["run_id"], row["phase"],
                         "bounded run", "—", "—", row["status"],
                         row["output_ptr"] or "runs.tsv"])
    return rows


def command_progress_rows(records, runs_by_id):
    host_rows, unresolved_rows = [], []
    for record in records:
        run = runs_by_id.get(str(record.get("run_id") or ""), {})
        assigned = command_assets(record["argv"])
        if not assigned:
            selected = exact_selector_asset(run.get("selector", ""))
            assigned = [selected] if selected else []
        command = shlex.join(str(token) for token in record["argv"])
        status = "success" if record["exit"] == 0 else f"failed (exit {record['exit']})"
        common = [record_date(record), record.get("run_id") or "—", record["skill"],
                  Path(str(record["tool"])).name, command, record_inputs(record), status,
                  record_evidence(record)]
        if assigned:
            for name in assigned:
                host_rows.append([name, *common])
        else:
            unresolved_rows.append(
                [*common[:2], run.get("selector") or "unresolved", *common[2:]])
    return host_rows, unresolved_rows


def probe_progress_rows(tests):
    host_rows, unresolved_rows = [], []
    for row in tests:
        entrypoint = field(row, "entrypoint", "entrypoint_url_param_func")
        vuln_class = field(row, "class", "vuln_class")
        if not entrypoint or not vuln_class:
            continue
        assigned = assets_in_text(entrypoint)
        activity = f"{vuln_class} / {field(row, 'variant') or 'coarse'}"
        evidence = field(row, "artifact_ptr") or "tested.md"
        method = field(row, "method", "method_what_you_did") or "—"
        outcome = f"{field(row, 'result') or '—'} / {field(row, 'coverage') or '—'}"
        for name in assigned:
            host_rows.append([name, field(row, "date") or "—", field(row, "run_id") or "—",
                              activity, "vulnerability probe", method, "—", outcome,
                              evidence])
        if not assigned:
            unresolved_rows.append(
                [field(row, "date") or "—", field(row, "run_id") or "—", entrypoint,
                 activity, "vulnerability probe", method, "—", outcome, evidence])
    return host_rows, unresolved_rows


def progress_data(target):
    runs = read_runs(target)
    records = read_exec_records(target)
    host_rows = bounded_host_rows(runs)
    command_rows, unresolved = command_progress_rows(
        records, {row["run_id"]: row for row in runs})
    probe_rows, unresolved_probes = probe_progress_rows(markdown_rows(target / "tested.md"))
    host_rows.extend(command_rows + probe_rows)
    unresolved.extend(unresolved_probes)
    host_rows.sort(key=lambda row: (row[0], row[1], row[2], row[4]))
    unresolved.sort(key=lambda row: (row[0], row[1], row[4]))
    return scope_progress_rows(runs, records), host_rows, unresolved


def host_sections(host_rows, headers):
    if not host_rows:
        return ["_No exact host/IP activity can be derived from the available records._", ""]
    sections = []
    for name, grouped in groupby(host_rows, key=lambda row: row[0]):
        sections.extend([f"### `{name}`", "",
                         markdown_table(headers, [row[1:] for row in grouped]), ""])
    return sections


def render(target):
    scope_rows, host_rows, unresolved = progress_data(target)
    generated = datetime.now().isoformat(timespec="seconds")
    parts = [
        f"# {target.name} — Progress",
        "",
        "> Generated from `runs.tsv`, `tested.md`, and locally available `logs/exec/*.json`.",
        "> Do not edit these tables by hand. Run `tools/progress.py targets/"
        f"{target.name}` after a unit of work, and `tools/vps-sync.py pull targets/{target.name}` "
        "first when VPS command records have not been pulled yet.",
        "",
        f"- **Generated:** {generated}",
        "",
        "## Scope-wide progress",
        "",
        markdown_table(["date", "run", "skill / objective", "selector", "sources / tools",
                        "budget", "status", "result / command count", "limitations"],
                       scope_rows),
        "",
        "## Per-host / IP progress",
        "",
    ]
    host_headers = ["date", "run", "skill / class", "tool / activity",
                    "exact redacted command / method", "inputs / wordlists (hash)",
                    "status / result", "evidence / artifact"]
    parts.extend(host_sections(host_rows, host_headers))
    parts.extend([
        "## Multi-asset or unresolved commands", "",
        "> These commands are kept here because their exact target set lives in an input file or "
        "cannot be proved from the command and run selector. They are not copied onto individual "
        "hosts as guessed coverage.", "",
        markdown_table(["date", "run", "selector / entrypoint", "skill", "tool / activity",
                        "exact redacted command / method", "inputs / wordlists (hash)",
                        "status / result", "evidence / artifact"], unresolved), "",
    ])
    return "\n".join(parts)


@runlog.wrap(0)
def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target")
    parser.add_argument("--stdout", action="store_true", help="print without writing progress.md")
    args = parser.parse_args()
    target = Path(args.target).resolve()
    if not (target / "index.md").exists():
        print(f"FAIL — {args.target} is not a target brain", file=sys.stderr)
        return 2
    try:
        body = render(target)
    except ProgressError as error:
        print(f"FAIL — {error}", file=sys.stderr)
        return 2
    if args.stdout:
        print(body, end="")
    else:
        path = target / "progress.md"
        path.write_text(body, encoding="utf-8")
        print(f"  wrote {path} — scope runs, per-host/IP activity, and exact redacted commands")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
