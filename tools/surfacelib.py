#!/usr/bin/env python3
"""Canonical endpoint-table reader/writer shared by every surface producer.

This is a library, not a scanner.  The target schema defines one endpoint row and several tools
consume it.  Keeping a parser in each producer caused a real split: import-http.py wrote
``method | host | endpoint`` while paths.py only understood ``url | method | ...``.  Both tools
worked in isolation and the chain between them was empty.

Readers accept the canonical schema and the one legacy import schema so existing private brains
remain usable.  Writers emit only the canonical schema from target-schema.md.
"""

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


COLUMNS = (
    "url", "method", "params", "auth_required", "content_type", "tech/app",
    "interesting_why", "source",
)


@dataclass(frozen=True)
class Endpoint:
    url: str
    method: str = "GET"
    params: tuple = ()
    auth_required: str = "unknown"
    content_type: str = ""
    tech_app: str = ""
    interesting_why: str = ""
    source: str = ""


def _cell(cell_value):
    """Make target-controlled text safe inside a Markdown table cell."""
    return str(cell_value or "").replace("\r", " ").replace("\n", " ").replace("|", "&#124;").strip()


def _split_row(line):
    return [_cell(part).strip("`") for part in line.strip().strip("|").split("|")]


def _is_separator(cells):
    return bool(cells) and all(cell and set(cell) <= {"-", ":"} for cell in cells)


def header():
    return "| " + " | ".join(COLUMNS) + " |\n|" + "|".join("---" for _ in COLUMNS) + "|\n"


def normalize_url(url_text, default_scheme="https"):
    url_text = _cell(url_text).strip("`")
    if not url_text:
        return ""
    if "://" not in url_text:
        url_text = f"{default_scheme}://{url_text.lstrip('/')}"
    parsed = urlsplit(url_text)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return ""
    hostname = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    try:
        port = f":{parsed.port}" if parsed.port is not None else ""
    except ValueError:
        return ""
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), f"{hostname.lower()}{port}", path, parsed.query, ""))


def key(endpoint):
    return normalize_url(endpoint.url), endpoint.method.upper()


def _canonical(record):
    params = tuple(sorted({p.strip() for p in record.get("params", "").split(",") if p.strip()}))
    url = normalize_url(record.get("url", ""))
    if not url:
        return None
    return Endpoint(
        url=url,
        method=(record.get("method") or "GET").upper(),
        params=params,
        auth_required=record.get("auth_required") or "unknown",
        content_type=record.get("content_type") or "",
        tech_app=record.get("tech/app") or "",
        interesting_why=record.get("interesting_why") or "",
        source=record.get("source") or "",
    )


def _legacy_import(record):
    """Read import-http.py's pre-canonical table without making old target brains unusable."""
    host, endpoint = record.get("host", ""), record.get("endpoint", "")
    url = normalize_url(endpoint if "://" in endpoint else f"https://{host}{endpoint}")
    if not url:
        return None
    statuses = {s.strip() for s in record.get("status", "").split(",")}
    props = record.get("properties", "")
    why = f"legacy traffic import; seen={record.get('seen', '?')}; status={record.get('status', '?')}"
    if props and props != "—":
        why += f"; properties={props}"
    return Endpoint(
        url=url,
        method=(record.get("method") or "GET").upper(),
        params=tuple(sorted({p.strip() for p in record.get("params", "").split(",") if p.strip()})),
        auth_required="yes" if {"401", "403"} & statuses else "unknown",
        interesting_why=why,
        source="legacy import-http",
    )


def read(path):
    """Read every endpoint table in *path*, deduped by normalized URL and method."""
    path = Path(path)
    if not path.is_file():
        return []
    active_columns = None
    expecting_separator = False
    found = {}
    for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        if not line.lstrip().startswith("|"):
            active_columns = None
            expecting_separator = False
            continue
        cells = _split_row(line)
        lowered = tuple(cell.lower() for cell in cells)
        if lowered == COLUMNS or lowered == (
                "method", "host", "endpoint", "seen", "status", "params", "properties"):
            active_columns = lowered
            expecting_separator = True
            continue
        if active_columns is None:
            continue
        if expecting_separator:
            if _is_separator(cells):
                expecting_separator = False
                continue
            active_columns = None
            continue
        if len(cells) != len(active_columns):
            continue
        record = dict(zip(active_columns, cells))
        endpoint = (_canonical(record) if active_columns == COLUMNS else _legacy_import(record))
        if endpoint:
            found[key(endpoint)] = endpoint
    return list(found.values())


def row(endpoint):
    normalized_url = normalize_url(endpoint.url)
    if not normalized_url:
        raise ValueError(f"invalid endpoint URL: {endpoint.url!r}")
    values = (
        normalized_url,
        endpoint.method.upper(),
        ", ".join(sorted(set(endpoint.params))),
        endpoint.auth_required,
        endpoint.content_type,
        endpoint.tech_app,
        endpoint.interesting_why,
        endpoint.source,
    )
    return "| " + " | ".join(_cell(value) for value in values) + " |\n"


def append(path, endpoints, title=None):
    """Append canonical rows and return the number written.

    Deduplication includes canonical and legacy rows already present.  A titled section keeps
    provenance readable without inventing a second table shape.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    known = {key(endpoint) for endpoint in read(path)}
    fresh_by_key = {}
    for endpoint in endpoints:
        endpoint_key = key(endpoint)
        if endpoint_key[0] and endpoint_key not in known:
            fresh_by_key[endpoint_key] = endpoint
    fresh = list(fresh_by_key.values())
    if not fresh:
        return 0
    with path.open("a", encoding="utf-8") as stream:
        if path.stat().st_size:
            stream.write("\n")
        if title:
            stream.write(f"## {_cell(title)}\n\n")
        stream.write(header())
        for endpoint in sorted(fresh, key=lambda item: (item.url, item.method)):
            stream.write(row(endpoint))
    return len(fresh)


def merge_values(path, values):
    """Merge a flat corpus such as parameters.txt, sorted and deduplicated."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = set()
    if path.is_file():
        existing = {line.strip() for line in path.read_text(
            encoding="utf-8-sig", errors="replace").splitlines() if line.strip()}
    incoming = {_cell(value) for value in values if _cell(value)}
    fresh = incoming - existing
    if fresh:
        path.write_text("".join(f"{value}\n" for value in sorted(existing | incoming)),
                        encoding="utf-8")
    return len(fresh)
