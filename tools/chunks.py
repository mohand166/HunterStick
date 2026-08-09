#!/usr/bin/env python3
"""Recover lazy JavaScript chunks from artifacts without executing target code.

    tools/chunks.py targets/acme raw/js/js-sources.tsv --out-dir raw/js

The source ledger is TSV with four columns:

    url    artifact    depth    fetch_status

`artifact` is relative to the ledger unless absolute. A fetched row must name a real file;
failed, blocked and skipped rows use `-`. The tool writes:

* chunk-graph.tsv      parent -> child evidence and provenance
* chunk-frontier.tsv   one row per discovered child and its current fetch state
* chunk-candidates.txt high-confidence, in-scope, still-pending URLs only

This tool sends no traffic and never evaluates JavaScript. Fetch candidates separately through
the scoped runner, update the source ledger, then rerun until the authorized frontier is empty.

Exit: 0 analyzed · 1 no fetched source to analyze · 2 malformed/refused.
"""
import argparse
import csv
import hashlib
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runlog                                                     # noqa: E402
from scopelib import in_scope, require_scope                       # noqa: E402

LEDGER_COLUMNS = ("url", "artifact", "depth", "fetch_status")
FETCH_STATES = {"fetched", "failed", "blocked", "skipped"}
CONFIDENCE_RANK = {"medium": 1, "high": 2}

SCRIPT_LITERAL = re.compile(
    r'''(?P<quote>["'])(?P<reference>(?:(?:https?:)?//|/|\./|\.\./)?'''
    r'''[^"'\s]*[A-Za-z0-9_-]\.(?:m?js|js\.map)(?:[?#][^"']*)?)(?P=quote)'''
)
SOURCE_MAP = re.compile(r"(?:\/\/[#@]|\/\*)\s*sourceMappingURL\s*=\s*([^\s*]+)")
WEBPACK_HASH_ARROW = re.compile(
    r'''(?P<chunk>[A-Za-z_$][\w$]*)\s*=>\s*'''
    r'''(?:["'](?P<prefix>[^"']*)["']\s*\+\s*)?'''
    r'''(?P=chunk)\s*\+\s*["'](?P<separator>[^"']*)["']\s*\+\s*'''
    r'''\{(?P<mapping>(?:\s*\d+\s*:\s*["'][^"']+["']\s*,?)+)\}'''
    r'''\[(?P=chunk)\]\s*\+\s*["'](?P<suffix>[^"']*\.m?js)["']'''
)
MAP_ENTRY = re.compile(r'''(\d+)\s*:\s*["']([^"']+)["']''')
WEBPACK_OBJECT_MAP = re.compile(
    r'''\{(?P<mapping>(?:\s*\d+\s*:\s*["'][0-9a-fA-F]{6,32}["']\s*,?){2,})\}''')


@dataclass(frozen=True)
class SourceRecord:
    url: str
    artifact: Path | None
    depth: int
    fetch_status: str


@dataclass(frozen=True)
class Reference:
    raw: str
    method: str
    confidence: str


@dataclass(frozen=True)
class GraphEdge:
    parent_url: str
    child_url: str
    method: str
    bundler: str
    depth: int
    confidence: str
    scope_status: str
    fetch_status: str
    source_sha256: str
    raw_reference: str


@dataclass(frozen=True)
class EdgeContext:
    bundler: str
    source_sha256: str
    scope: dict
    known_status: dict


@dataclass(frozen=True)
class ChunkGraph:
    edges: tuple
    unique_content_hashes: int


def die(message, code=2):
    print(f"FAIL — {message}", file=sys.stderr)
    raise SystemExit(code)


def normalized_http_url(parent_url, raw_reference):
    reference = (raw_reference or "").replace(r"\/", "/").strip(" \t\r\n\"'")
    joined = urljoin(parent_url, reference)
    parsed = urlsplit(joined)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path,
                       parsed.query, ""))


def resolved_child_url(parent_url, reference, bundler):
    raw_reference = reference.raw.replace(r"\/", "/")
    normalized_reference = raw_reference.lstrip("./")
    parent = urlsplit(parent_url)
    marker = "/_next/static/"
    if bundler == "nextjs" and marker in parent.path and normalized_reference.startswith("static/"):
        application_root = parent.path.split(marker, 1)[0]
        child_path = f"{application_root}/_next/{normalized_reference}"
        return normalized_http_url(parent_url, child_path)
    if bundler == "vite" and normalized_reference.startswith("assets/") \
            and "/assets/" in parent.path:
        application_root = parent.path.split("/assets/", 1)[0]
        return normalized_http_url(parent_url, f"{application_root}/{normalized_reference}")
    return normalized_http_url(parent_url, raw_reference)


def resolved_artifact(ledger_path, artifact_text):
    if not artifact_text or artifact_text == "-":
        return None
    artifact = Path(artifact_text)
    return artifact if artifact.is_absolute() else (ledger_path.parent / artifact).resolve()


def parsed_depth(row_number, depth_text):
    try:
        depth = int(depth_text)
    except ValueError:
        die(f"source ledger row {row_number}: depth is not an integer: {depth_text!r}")
    if depth < 0:
        die(f"source ledger row {row_number}: depth cannot be negative")
    return depth


def validated_source(row, row_number, ledger_path):
    missing = [column for column in LEDGER_COLUMNS if not (row.get(column) or "").strip()]
    if missing:
        die(f"source ledger row {row_number}: missing {', '.join(missing)}")
    url = normalized_http_url(row["url"], row["url"])
    if not url:
        die(f"source ledger row {row_number}: URL must be absolute HTTP(S)")
    status = row["fetch_status"].strip().lower()
    if status not in FETCH_STATES:
        die(f"source ledger row {row_number}: fetch_status must be one of "
            f"{', '.join(sorted(FETCH_STATES))}")
    artifact = resolved_artifact(ledger_path, row["artifact"].strip())
    if status == "fetched" and (not artifact or not artifact.is_file()):
        die(f"source ledger row {row_number}: fetched artifact does not exist: {artifact}")
    return SourceRecord(url, artifact, parsed_depth(row_number, row["depth"].strip()), status)


def load_sources(ledger_path):
    if not ledger_path.is_file():
        die(f"source ledger does not exist: {ledger_path}")
    with ledger_path.open(encoding="utf-8-sig", newline="") as ledger_file:
        reader = csv.DictReader(ledger_file, delimiter="\t")
        if tuple(reader.fieldnames or ()) != LEDGER_COLUMNS:
            die(f"source ledger header must be exactly: {'  '.join(LEDGER_COLUMNS)}")
        sources = [validated_source(row, number, ledger_path)
                   for number, row in enumerate(reader, 2)]
    url_counts = Counter(source.url for source in sources)
    duplicate_urls = sorted(url for url, count in url_counts.items() if count > 1)
    if duplicate_urls:
        die(f"source ledger contains duplicate URL(s): {', '.join(duplicate_urls[:5])}")
    return sources


def bundler_name(script_text):
    signatures = (
        ("nextjs", ("__BUILD_MANIFEST", "__NEXT_DATA__", "_next/static")),
        ("vite", ("__vite__mapDeps", "vite/preload-helper")),
        ("webpack", ("__webpack_require__", "webpackChunk", "webpackJsonp")),
        ("parcel", ("parcelRequire",)),
    )
    for name, markers in signatures:
        if any(marker in script_text for marker in markers):
            return name
    return "javascript"


def literal_references(script_text, bundler):
    method = {
        "nextjs": "next-manifest-literal",
        "vite": "vite-dependency-literal",
    }.get(bundler, "script-literal")
    return [Reference(match.group("reference"), method, "high")
            for match in SCRIPT_LITERAL.finditer(script_text)]


def source_map_references(script_text):
    return [Reference(match.group(1).rstrip("*/"), "source-map", "high")
            for match in SOURCE_MAP.finditer(script_text)]


def webpack_runtime_references(script_text):
    references = []
    for match in WEBPACK_HASH_ARROW.finditer(script_text):
        prefix = match.group("prefix") or ""
        separator, suffix = match.group("separator"), match.group("suffix")
        for chunk_id, chunk_hash in MAP_ENTRY.findall(match.group("mapping")):
            references.append(Reference(
                f"{prefix}{chunk_id}{separator}{chunk_hash}{suffix}",
                "webpack-runtime-map", "high"))
    return references


def webpack_heuristic_references(script_text):
    references = []
    for match in WEBPACK_OBJECT_MAP.finditer(script_text):
        nearby = script_text[max(0, match.start() - 300):match.end() + 300]
        if "__webpack_require__" not in nearby or ".js" not in nearby:
            continue
        references.extend(Reference(f"{chunk_id}.{chunk_hash}.js",
                                    "webpack-hash-map-heuristic", "medium")
                          for chunk_id, chunk_hash in MAP_ENTRY.findall(match.group("mapping")))
    return references


def unique_references(script_text, bundler):
    discovered = literal_references(script_text, bundler)
    discovered += source_map_references(script_text)
    discovered += webpack_runtime_references(script_text)
    discovered += webpack_heuristic_references(script_text)
    unique = {(reference.raw, reference.method): reference for reference in discovered}
    return sorted(unique.values(), key=lambda reference: (reference.raw, reference.method))


def edge_for(source, reference, context):
    child_url = resolved_child_url(source.url, reference, context.bundler)
    if not child_url or child_url == source.url:
        return None
    hostname = urlsplit(child_url).hostname
    scope_status = "in-scope" if in_scope(hostname, context.scope) else "blocked-by-scope"
    fetch_status = context.known_status.get(child_url, "pending")
    if scope_status != "in-scope" and fetch_status == "pending":
        fetch_status = "blocked"
    return GraphEdge(source.url, child_url, reference.method, context.bundler, source.depth + 1,
                     reference.confidence, scope_status, fetch_status, context.source_sha256,
                     reference.raw)


def discover_graph(sources, scope):
    fetched = [source for source in sources if source.fetch_status == "fetched"]
    if not fetched:
        die("source ledger contains no fetched artifact to analyze", 1)
    known_status = {source.url: source.fetch_status for source in sources}
    parsed_by_hash = {}
    edges = []
    for source in fetched:
        script_bytes = source.artifact.read_bytes()
        digest = hashlib.sha256(script_bytes).hexdigest()
        if digest not in parsed_by_hash:
            script_text = script_bytes.decode("utf-8", "replace")
            bundler = bundler_name(script_text)
            parsed_by_hash[digest] = (bundler, unique_references(script_text, bundler))
        bundler, references = parsed_by_hash[digest]
        context = EdgeContext(bundler, digest, scope, known_status)
        for reference in references:
            edge = edge_for(source, reference, context)
            if edge:
                edges.append(edge)
    ordered_edges = tuple(sorted(set(edges),
                                key=lambda edge: (edge.parent_url, edge.child_url, edge.method)))
    return ChunkGraph(ordered_edges, len(parsed_by_hash))


def frontier_rows(edges):
    grouped = {}
    for edge in edges:
        current = grouped.get(edge.child_url)
        if not current or (-CONFIDENCE_RANK[edge.confidence], edge.depth) < \
                (-CONFIDENCE_RANK[current.confidence], current.depth):
            grouped[edge.child_url] = edge
    return sorted(grouped.values(), key=lambda edge: (edge.depth, edge.child_url))


def tsv_cell(text):
    return str(text).replace("\t", "\\t").replace("\r", "\\r").replace("\n", "\\n")


def write_tsv(path, columns, rows):
    temporary_path = path.with_name(f".{path.name}.tmp")
    with temporary_path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.writer(output, delimiter="\t", lineterminator="\n")
        writer.writerow(columns)
        writer.writerows([[tsv_cell(cell) for cell in row] for row in rows])
    temporary_path.replace(path)


def write_text(path, content):
    temporary_path = path.with_name(f".{path.name}.tmp")
    temporary_path.write_text(content, encoding="utf-8")
    temporary_path.replace(path)


def write_graph(path, edges):
    columns = ("parent_url", "child_url", "discovery_method", "bundler", "depth",
               "confidence", "scope_status", "fetch_status", "source_sha256", "raw_reference")
    rows = ((edge.parent_url, edge.child_url, edge.method, edge.bundler, edge.depth,
             edge.confidence, edge.scope_status, edge.fetch_status, edge.source_sha256,
             edge.raw_reference) for edge in edges)
    write_tsv(path, columns, rows)


def write_frontier(path, frontier):
    columns = ("child_url", "depth", "confidence", "scope_status", "fetch_status",
               "discovery_method", "parent_url")
    rows = ((edge.child_url, edge.depth, edge.confidence, edge.scope_status, edge.fetch_status,
             edge.method, edge.parent_url) for edge in frontier)
    write_tsv(path, columns, rows)


def candidate_urls(frontier):
    return [edge.child_url for edge in frontier if edge.confidence == "high"
            and edge.scope_status == "in-scope" and edge.fetch_status == "pending"]


def write_outputs(output_dir, edges):
    output_dir.mkdir(parents=True, exist_ok=True)
    frontier = frontier_rows(edges)
    candidates = candidate_urls(frontier)
    write_graph(output_dir / "chunk-graph.tsv", edges)
    write_frontier(output_dir / "chunk-frontier.tsv", frontier)
    write_text(output_dir / "chunk-candidates.txt", "".join(f"{url}\n" for url in candidates))
    return frontier


def print_summary(sources, graph, frontier, output_dir):
    fetched = sum(source.fetch_status == "fetched" for source in sources)
    blocked = sum(edge.scope_status != "in-scope" for edge in frontier)
    terminal = sum(edge.fetch_status in {"fetched", "failed", "skipped"} for edge in frontier)
    candidates = candidate_urls(frontier)
    print(f"Analyzed {fetched} fetched source(s), {graph.unique_content_hashes} unique content "
          "hash(es).")
    print(f"Discovered {len(frontier)} unique child asset(s): {len(candidates)} authorized pending, "
          f"{blocked} blocked by scope, {terminal} already terminal.")
    print(f"Wrote {output_dir / 'chunk-graph.tsv'}, {output_dir / 'chunk-frontier.tsv'}, and "
          f"{output_dir / 'chunk-candidates.txt'}.")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", help="target brain containing scope.md")
    parser.add_argument("sources", type=Path, help="URL-to-artifact TSV source ledger")
    parser.add_argument("--out-dir", type=Path, required=True,
                        help="directory for graph, frontier and candidate outputs")
    args = parser.parse_args()

    target = Path(args.target).resolve()
    scope = require_scope(target, die)
    sources = load_sources(args.sources.resolve())
    graph = discover_graph(sources, scope)
    frontier = write_outputs(args.out_dir.resolve(), graph.edges)
    print_summary(sources, graph, frontier, args.out_dir.resolve())
    return 0


if __name__ == "__main__":
    sys.exit(runlog.wrap()(main)())
