#!/usr/bin/env python3
"""Normalize offline JS extraction or API specs into the canonical target surface.

    tools/surface.py targets/acme js raw/js/app-urls.jsonl \
        --secrets-file raw/js/app-secrets.jsonl --base-url https://app.acme.com \
        --source-url https://app.acme.com/assets/app.js --write
    tools/surface.py targets/acme spec raw/api/openapi.json --base-url https://api.acme.com --write

The tool sends no traffic. It consumes saved artifacts and writes only with --write. JavaScript
URLs become canonical endpoint and parameter rows plus a redacted `js-findings.md` handoff.
Optional jsluice secret output is reduced without ever copying secret values or context into the
brain. JavaScript strings without an explicit method remain `UNKNOWN`; it never invents GET.
OpenAPI/Swagger JSON is supported without dependencies; YAML works when PyYAML is installed and
otherwise fails with the exact missing input.

Exit: 0 parsed/written · 1 no new operations · 2 invalid input or unsafe target brain.
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runlog                                                     # noqa: E402
from scopelib import in_scope, require_scope                      # noqa: E402
from surfacelib import Endpoint, append, key, merge_values, read  # noqa: E402


HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}
JS_FINDING_COLUMNS = ("js_url", "finding_type", "value", "severity_hint", "verified", "source")
USE_SITE_TYPES = ("fetch", "xmlhttprequest", "$.ajax", "$.get", "$.post", "axios")


def die(message, code=2):
    print(f"FAIL — {message}", file=sys.stderr)
    raise SystemExit(code)


def load_jsonish(path):
    text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    try:
        value = json.loads(text)
        return value if isinstance(value, list) else [value]
    except json.JSONDecodeError:
        rows = []
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                die(f"{path}:{number} is not JSON: {error}")
            rows.extend(value if isinstance(value, list) else [value])
        return rows


def params_from(raw_params):
    out = set()
    if isinstance(raw_params, dict):
        out.update(str(item) for item in raw_params)
    elif isinstance(raw_params, list):
        for item in raw_params:
            if isinstance(item, str):
                out.add(item)
            elif isinstance(item, dict):
                name = item.get("name") or item.get("key")
                if name:
                    out.add(str(name))
    elif isinstance(raw_params, str):
        out.update(part.strip() for part in raw_params.split(",") if part.strip())
    return out


def public_url(url_text):
    """Drop userinfo, query values and fragments from a URL before storing provenance/surface."""
    parsed = urlsplit(url_text)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    hostname = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    try:
        port = f":{parsed.port}" if parsed.port is not None else ""
    except ValueError:
        return ""
    return urlunsplit((parsed.scheme.lower(), f"{hostname.lower()}{port}", parsed.path or "/", "", ""))


def table_cell(cell_value):
    """Keep target-controlled values inside one Markdown table cell."""
    return str(cell_value or "").replace("\r", " ").replace("\n", " ").replace("|", "&#124;").strip()


def bundle_reference(record, source_url, input_path):
    """Prefer a public bundle URL; never persist a local absolute path."""
    filename = record.get("filename")
    if isinstance(filename, str) and public_url(filename):
        return public_url(filename)
    if source_url and public_url(source_url):
        return public_url(source_url)
    if isinstance(filename, str) and filename.strip():
        return Path(filename).name
    return Path(input_path).name


def secret_finding_type(kind):
    lowered = kind.lower()
    if any(name in lowered for name in ("aws", "gcp", "google", "firebase", "cloud")):
        return "cloud-key"
    if any(name in lowered for name in ("token", "jwt", "github")):
        return "token"
    return "secret"


def safe_field_names(data):
    if not isinstance(data, dict):
        return ("match",)
    fields = []
    for name in data:
        clean = re.sub(r"[^A-Za-z0-9_.:-]", "", str(name))[:40]
        fields.append(clean or "field")
    return tuple(sorted(set(fields))) or ("match",)


def secret_group_key(record, source_url, artifact_path):
    if not isinstance(record, dict) or not record.get("kind") \
            or not isinstance(record.get("data"), dict):
        return None
    kind = table_cell(record["kind"])[:80]
    severity = str(record.get("severity") or "unknown").lower()
    if severity not in {"info", "low", "medium", "high"}:
        severity = "unknown"
    return (bundle_reference(record, source_url, artifact_path), kind, severity,
            safe_field_names(record["data"]))


def redacted_secret_finding(group, indexes, artifact_path):
    bundle, kind, severity, fields = group
    return {
        "js_url": bundle,
        "finding_type": secret_finding_type(kind),
        "value": f"{kind}: [REDACTED; fields={','.join(fields)}; matches={len(indexes)}]",
        "severity_hint": f"untriaged (scanner:{severity})",
        "verified": "no",
        "source": f"jsluice-secrets:{Path(artifact_path).name}; records={','.join(map(str, indexes))}",
    }


def secret_findings(path, source_url):
    """Reduce jsluice secret JSONL without retaining values, contexts, or value-derived hashes."""
    grouped = defaultdict(list)
    for index, record in enumerate(load_jsonish(path), 1):
        group = secret_group_key(record, source_url, path)
        if group:
            grouped[group].append(index)
    return [redacted_secret_finding(group, indexes, path)
            for group, indexes in grouped.items()]


def js_record_params(record, parsed_url):
    names = {name for name, _ in parse_qsl(parsed_url.query, keep_blank_values=True)}
    for field in ("queryParams", "query_params", "bodyParams", "body_params", "params"):
        names.update(params_from(record.get(field)))
    return tuple(sorted(names))


def js_endpoint_finding(endpoint, bundle, use_kind):
    candidate_description = f"{endpoint.method} {endpoint.url}"
    if endpoint.params:
        candidate_description += f"; params={','.join(endpoint.params)}"
    is_use_site = any(marker in str(use_kind).lower() for marker in USE_SITE_TYPES)
    return {
        "js_url": bundle,
        "finding_type": "api-endpoint" if is_use_site else "route",
        "value": candidate_description,
        "severity_hint": "n/a",
        "verified": "no (static extraction)",
        "source": endpoint.source,
        "_endpoint_key": key(endpoint),
    }


def js_record_surface(record, base_url, source_url, artifact_path):
    raw_url = record.get("url") or record.get("path") or record.get("value")
    if not isinstance(raw_url, str) or not raw_url.strip():
        return None
    absolute_url = urljoin(base_url, raw_url.strip())
    parsed_url = urlsplit(absolute_url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        return None
    method = str(record.get("method") or "UNKNOWN").upper()
    method = method if method in HTTP_METHODS else "UNKNOWN"
    use_kind = record.get("type") or record.get("kind") or "URL use/string"
    bundle = bundle_reference(record, source_url, artifact_path)
    endpoint = Endpoint(
        url=public_url(absolute_url), method=method,
        params=js_record_params(record, parsed_url),
        content_type=str(record.get("content_type") or ""),
        interesting_why=f"JavaScript extraction: {use_kind}; "
                        f"method={'explicit' if method != 'UNKNOWN' else 'not established'}",
        source=f"js:{bundle}",
    )
    return endpoint, js_endpoint_finding(endpoint, bundle, use_kind)


def js_surface(path, base_url, source_url):
    base = base_url.rstrip("/") + "/"
    endpoints, findings = [], []
    for record in load_jsonish(path):
        if not isinstance(record, dict):
            continue
        reduced = js_record_surface(record, base, source_url, path)
        if reduced:
            endpoint, finding = reduced
            endpoints.append(endpoint)
            findings.append(finding)
    return endpoints, findings


def js_endpoints(path, base_url, source_url):
    """Compatibility entrypoint used by callers that only need canonical operations."""
    return js_surface(path, base_url, source_url)[0]


def finding_key(finding):
    return tuple(table_cell(finding.get(column, "")) for column in JS_FINDING_COLUMNS)


def read_finding_keys(path):
    path = Path(path)
    if not path.is_file():
        return set()
    known, columns = set(), None
    for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        if not line.lstrip().startswith("|"):
            columns = None
            continue
        cells = [part.strip() for part in line.strip().strip("|").split("|")]
        lowered = tuple(cell.lower() for cell in cells)
        if lowered == JS_FINDING_COLUMNS:
            columns = lowered
            continue
        if columns and cells and all(set(cell) <= {"-", ":"} for cell in cells):
            continue
        if columns and len(cells) == len(columns):
            known.add(tuple(cells))
    return known


def append_findings(path, findings, title):
    path = Path(path)
    known = read_finding_keys(path)
    fresh = {finding_key(finding): finding for finding in findings
             if finding_key(finding) not in known}
    if not fresh:
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        if path.stat().st_size:
            stream.write("\n")
        stream.write(f"## {table_cell(title)}\n\n")
        stream.write("| " + " | ".join(JS_FINDING_COLUMNS) + " |\n")
        stream.write("|" + "|".join("---" for _ in JS_FINDING_COLUMNS) + "|\n")
        for values in sorted(fresh):
            stream.write("| " + " | ".join(values) + " |\n")
    return len(fresh)


def load_spec(path):
    text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError as json_error:
        try:
            import yaml  # type: ignore
        except ImportError:
            die(f"{path} is not JSON ({json_error}). YAML requires PyYAML on this machine")
        try:
            return yaml.safe_load(text)
        except yaml.YAMLError as yaml_error:
            die(f"cannot parse {path} as JSON or YAML: {yaml_error}")


def spec_base(spec, supplied):
    if supplied:
        return supplied.rstrip("/") + "/"
    servers = spec.get("servers") if isinstance(spec, dict) else None
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        value = servers[0].get("url", "")
        for name, meta in (servers[0].get("variables") or {}).items():
            if isinstance(meta, dict):
                value = value.replace("{" + name + "}", str(meta.get("default", "")))
        if urlsplit(value).netloc:
            return value.rstrip("/") + "/"
    if isinstance(spec, dict) and spec.get("host"):
        scheme = (spec.get("schemes") or ["https"])[0]
        return f"{scheme}://{spec['host']}{spec.get('basePath', '')}".rstrip("/") + "/"
    die("spec has no absolute server/host; supply --base-url")


def local_reference(document, reference):
    if not isinstance(reference, str) or not reference.startswith("#/"):
        return None
    current = document
    for token in reference[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or token not in current:
            return None
        current = current[token]
    return current


def schema_names(schema, document):
    names, pending, visited = set(), [schema], set()
    while pending:
        current = pending.pop()
        if not isinstance(current, dict):
            continue
        reference = current.get("$ref")
        if reference and reference not in visited:
            visited.add(reference)
            pending.append(local_reference(document, reference))
        names.update((current.get("properties") or {}).keys())
        pending.extend(current.get("allOf") or [])
        pending.extend(current.get("anyOf") or [])
        pending.extend(current.get("oneOf") or [])
        if current.get("items"):
            pending.append(current["items"])
    return names


def spec_endpoints(path, base_url):
    spec = load_spec(path)
    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
        die(f"{path} has no object-valued paths section")
    base = spec_base(spec, base_url)
    global_security = spec.get("security", None)
    endpoints = []
    for route, path_item in spec["paths"].items():
        if not isinstance(path_item, dict):
            continue
        shared_params = path_item.get("parameters") or []
        for method, operation in path_item.items():
            method_upper = method.upper()
            if method_upper not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            params = set()
            for parameter in list(shared_params) + list(operation.get("parameters") or []):
                if isinstance(parameter, dict) and parameter.get("$ref"):
                    parameter = local_reference(spec, parameter["$ref"])
                if isinstance(parameter, dict) and parameter.get("name"):
                    params.add(str(parameter["name"]))
                if isinstance(parameter, dict) and parameter.get("in") == "body":
                    params.update(schema_names(parameter.get("schema"), spec))
            content_types = set(operation.get("consumes") or spec.get("consumes") or [])
            body = operation.get("requestBody") or {}
            if isinstance(body, dict) and body.get("$ref"):
                body = local_reference(spec, body["$ref"]) or {}
            for content_type, media in (body.get("content") or {}).items():
                content_types.add(content_type)
                params.update(schema_names((media or {}).get("schema"), spec))
            security = operation.get("security", global_security)
            auth = "no" if security == [] else "yes" if security else "unknown"
            label = operation.get("operationId") or operation.get("summary") or "declared operation"
            endpoints.append(Endpoint(
                url=urljoin(base, str(route).lstrip("/")), method=method_upper,
                params=tuple(sorted(params)), auth_required=auth,
                content_type=", ".join(sorted(content_types)),
                interesting_why=f"API spec: {label}", source=f"spec:{Path(path).name}",
            ))
    return endpoints


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target")
    sub = parser.add_subparsers(dest="kind", required=True)
    for kind in ("js", "spec"):
        command = sub.add_parser(kind)
        command.add_argument("input")
        command.add_argument("--base-url", help="origin for relative URLs (required if absent in spec)")
        command.add_argument("--write", action="store_true", help="merge into the target brain")
        command.add_argument("--allow-unscoped", action="store_true",
                             help="keep extracted candidate URLs outside scope.md")
        if kind == "js":
            command.add_argument("--source-url", help="bundle URL recorded as provenance")
            command.add_argument("--secrets-file",
                                 help="saved `jsluice secrets` JSONL to reduce without values")
    args = parser.parse_args()

    target = Path(args.target).resolve()
    if not (target / "index.md").is_file():
        die(f"{args.target} is not a target brain (no index.md)")
    input_path = Path(args.input)
    if not input_path.is_file():
        die(f"input does not exist: {args.input}")
    if args.kind == "js" and not args.base_url:
        die("JS extraction requires --base-url so relative routes have an application origin")
    secrets_path = Path(args.secrets_file) if getattr(args, "secrets_file", None) else None
    if secrets_path and not secrets_path.is_file():
        die(f"secrets input does not exist: {secrets_path}")

    if args.kind == "js":
        endpoints, findings = js_surface(input_path, args.base_url, args.source_url)
        if secrets_path:
            findings.extend(secret_findings(secrets_path, args.source_url))
    else:
        endpoints, findings = spec_endpoints(input_path, args.base_url), []
    scope = require_scope(target, die)
    outside = [endpoint for endpoint in endpoints
               if not in_scope(urlsplit(endpoint.url).hostname or "", scope)]
    if outside and not args.allow_unscoped:
        print(f"  skipped {len(outside)} out-of-scope extracted candidate(s); use --allow-unscoped "
              "only when they belong in this brain")
        endpoints = [endpoint for endpoint in endpoints if endpoint not in outside]
        outside_keys = {key(endpoint) for endpoint in outside}
        findings = [finding for finding in findings
                    if finding.get("_endpoint_key") not in outside_keys]
    if not args.allow_unscoped:
        outside_findings = []
        for finding in findings:
            bundle_host = urlsplit(str(finding.get("js_url") or "")).hostname
            if bundle_host and not in_scope(bundle_host, scope):
                outside_findings.append(finding)
        if outside_findings:
            print(f"  skipped {len(outside_findings)} finding(s) from out-of-scope bundles")
            findings = [finding for finding in findings if finding not in outside_findings]

    known = {key(endpoint) for endpoint in read(target / "recon" / "endpoints.md")}
    fresh = [endpoint for endpoint in endpoints if key(endpoint) not in known]
    params = sorted({param for endpoint in endpoints for param in endpoint.params})
    param_file = target / "recon" / "parameters.txt"
    known_params = ({line.strip() for line in param_file.read_text(
        encoding="utf-8-sig", errors="replace").splitlines() if line.strip()}
                    if param_file.is_file() else set())
    new_params = set(params) - known_params
    findings_path = target / "recon" / "js-findings.md"
    known_findings = read_finding_keys(findings_path)
    fresh_findings = [finding for finding in findings
                      if finding_key(finding) not in known_findings]
    print(f"  parsed {len(endpoints)} operation(s); {len(fresh)} new; "
          f"{len(new_params)} new parameter name(s); {len(fresh_findings)} new JS finding row(s)")
    for endpoint in fresh[:30]:
        print(f"  {endpoint.method:<7} {endpoint.url}")
    if len(fresh) > 30:
        print(f"  … {len(fresh) - 30} more")
    if not fresh and not new_params and not fresh_findings:
        return 1
    if not args.write:
        print("  dry run — add --write to merge the delta")
        return 0

    written = append(target / "recon" / "endpoints.md", fresh,
                     title=f"Normalized from {args.kind}: {input_path.name}")
    param_count = merge_values(param_file, params)
    finding_count = (append_findings(findings_path, fresh_findings,
                                     f"Reduced from jsluice: {input_path.name}")
                     if args.kind == "js" else 0)
    print(f"  wrote {written} endpoint(s); added {param_count} parameter name(s); "
          f"wrote {finding_count} redacted JS finding row(s)")
    if args.kind == "js" and (written or finding_count):
        print("  handoff ready — @endpoints and @js now feed derive-properties; "
              "the reducer did not invent vulnerability classes")
    return 0


if __name__ == "__main__":
    sys.exit(runlog.wrap()(main)())
