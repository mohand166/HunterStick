#!/usr/bin/env python3
"""Import captured HTTP traffic — HAR, Burp XML, Burp sitemap — into a target brain.

    tools/import-http.py targets/acme capture.har              # dry run: what would change
    tools/import-http.py targets/acme burp-export.xml --write  # apply it

Manual browsing is the one input that never becomes structured surface. You click through an app
for an hour, Burp records 900 requests, and none of it reaches `attack-surface.md` — so
`coverage.py` keeps describing a surface that is missing everything you actually looked at.

What it does
------------
parse → strip credentials → reconcile against scope.md → derive properties → dedup against what
the brain already knows → report **what is new**.

Four rules it will not bend:

* **Scope refuses, it does not warn.** Any host in the capture that is not in `scope.md` blocks
  the import until you decide. Out-of-scope traffic in a capture is normal (you had other tabs
  open); silently importing it is not.
* **No credential is ever written.** Session cookies, bearer tokens, API keys and Basic auth are
  replaced with `<accounts.md:...>` pointers before anything touches disk, and the values are
  never printed. The principals they represent are reported so you can record them yourself.
* **Dry run by default.** Nothing is written without `--write`.
* **Endpoints are templated.** `/orders/1837` and `/orders/9921` are ONE endpoint,
  `/orders/{id}`, or a 900-request capture becomes 900 rows of noise. Numeric, UUID, hash and
  date segments collapse; the observed values are kept as evidence that the parameter is an
  object reference.

Import is not a test. Nothing lands in `tested.md`.

Exit: 0 ok · 1 nothing new · 2 refused / failed.
"""
import argparse
import base64
import json
import re
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runlog   # noqa: E402
from scopelib import in_scope, matches, require_scope   # noqa: E402
from surfacelib import Endpoint, append as append_endpoints, key as endpoint_key, read as read_endpoints  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

# headers whose VALUE is a credential — never printed, never written
SECRET_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
                  "proxy-authorization", "x-csrf-token", "x-xsrf-token", "authentication"}
SECRET_PARAM = re.compile(r"(token|passw|secret|api[-_]?key|session|auth|bearer|sig|hmac)", re.I)

# path segments that are values, not routes
SEG_RULES = [
    (re.compile(r"^\d+$"), "{id}"),
    (re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I), "{uuid}"),
    (re.compile(r"^[0-9a-f]{32,64}$", re.I), "{hash}"),
    (re.compile(r"^\d{4}-\d{2}-\d{2}$"), "{date}"),
    (re.compile(r"^[A-Za-z0-9_-]{20,}$"), "{opaque}"),
]



def rel(p):
    """Path relative to the workspace when it is inside it, absolute when it is not.

    A target brain may legitimately live outside this repo (a scratch dir, a mounted volume).
    `Path.relative_to` raises ValueError there, which crashed the tool at the very last line —
    after all the real work had already succeeded.
    """
    try:
        return p.relative_to(ROOT)
    except ValueError:
        return p

def die(msg, code=2):
    print(f"FAIL — {msg}", file=sys.stderr)
    raise SystemExit(code)


def target_of(arg):
    p = Path(arg).resolve()
    if not p.is_dir() or not (p / "index.md").exists():
        die(f"{arg} is not a target brain (no index.md)")
    return p


# ---------------------------------------------------------------- parsing

def parse_har(text):
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        die(f"not valid JSON: {e}")
    entries = data.get("log", {}).get("entries")
    if entries is None:
        die("JSON parsed but has no log.entries — is this really a HAR?")
    out = []
    for e in entries:
        req, res = e.get("request", {}), e.get("response", {})
        if not req.get("url"):
            continue
        out.append({
            "method": (req.get("method") or "GET").upper(),
            "url": req["url"],
            "req_headers": {h.get("name", "").lower(): h.get("value", "")
                            for h in req.get("headers", [])},
            "res_headers": {h.get("name", "").lower(): h.get("value", "")
                            for h in res.get("headers", [])},
            "status": res.get("status") or 0,
            "req_ct": (req.get("postData") or {}).get("mimeType", ""),
            "res_ct": (res.get("content") or {}).get("mimeType", ""),
            "body": ((req.get("postData") or {}).get("text") or "")[:20000],
            "res_body": ((res.get("content") or {}).get("text") or "")[:20000],
        })
    return out


def _b64(s):
    try:
        return base64.b64decode(s or "").decode("utf-8", "replace")
    except Exception:
        return s or ""


def parse_burp_xml(text):
    """Burp 'Save items' export and sitemap export share this shape."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        die(f"not valid XML: {e}")
    items = root.findall(".//item")
    if not items:
        die("XML parsed but contains no <item> elements — is this a Burp export?")
    out = []
    for it in items:
        def txt(tag):
            n = it.find(tag)
            return (n.text or "") if n is not None else ""

        def blob(tag):
            n = it.find(tag)
            if n is None:
                return ""
            raw = n.text or ""
            return _b64(raw) if (n.get("base64") == "true") else raw

        url = txt("url")
        if not url:
            continue
        raw_req, raw_res = blob("request"), blob("response")
        head, _, body = raw_req.partition("\r\n\r\n") if "\r\n\r\n" in raw_req \
            else raw_req.partition("\n\n")
        rh = {}
        for line in head.splitlines()[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                rh[k.strip().lower()] = v.strip()
        sh = {}
        for line in raw_res.split("\n\n", 1)[0].splitlines()[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                sh[k.strip().lower()] = v.strip()
        try:
            status = int(txt("status") or 0)
        except ValueError:
            status = 0
        out.append({"method": (txt("method") or "GET").upper(), "url": url,
                    "req_headers": rh, "res_headers": sh, "status": status,
                    "req_ct": rh.get("content-type", ""),
                    "res_ct": sh.get("content-type", txt("mimetype")),
                    "body": body[:20000],
                    "res_body": (raw_res.split("\n\n", 1)[1][:20000]
                                 if "\n\n" in raw_res else "")})
    return out


def load(path):
    p = Path(path)
    if not p.exists():
        die(f"no such file: {path}")
    text = p.read_text(encoding="utf-8-sig", errors="replace")
    head = text.lstrip()[:200].lower()
    if head.startswith("{"):
        return parse_har(text), "HAR"
    if head.startswith("<?xml") or head.startswith("<items"):
        return parse_burp_xml(text), "Burp XML"
    die("unrecognized format — expected a HAR (JSON) or a Burp XML export")


# ---------------------------------------------------------------- normalize

def template_path(path):
    segs, values = [], []
    for s in path.split("/"):
        if not s:
            segs.append(s)
            continue
        for rx, repl in SEG_RULES:
            if rx.match(s):
                segs.append(repl)
                values.append(s)
                break
        else:
            segs.append(s)
    return "/".join(segs) or "/", values


def creds_in(entry):
    """Named credential kinds present. Values are never returned."""
    kinds = set()
    for h, v in entry["req_headers"].items():
        if h in SECRET_HEADERS and v:
            if h == "authorization":
                kinds.add("bearer" if v.lower().startswith("bearer") else
                          "basic" if v.lower().startswith("basic") else "authorization")
            elif h == "cookie":
                for c in v.split(";"):
                    n = c.split("=")[0].strip()
                    if n and SECRET_PARAM.search(n):
                        kinds.add(f"cookie:{n}")
                kinds.add("cookie")
            else:
                kinds.add(h)
    if entry["res_headers"].get("set-cookie"):
        kinds.add("set-cookie (session issued here)")
    return kinds


def request_has_auth(entry):
    """Whether the captured request carried a principal, without returning any secret value."""
    return any(entry["req_headers"].get(name) for name in
               ("authorization", "cookie", "x-api-key", "x-auth-token", "authentication"))


def origin_of(parsed_url):
    """Scheme + host + port, with URL userinfo discarded before anything reaches the brain."""
    if not parsed_url.hostname:
        return ""
    hostname = f"[{parsed_url.hostname}]" if ":" in parsed_url.hostname else parsed_url.hostname
    try:
        port = f":{parsed_url.port}" if parsed_url.port is not None else ""
    except ValueError:
        die(f"invalid port in captured URL for {parsed_url.hostname}")
    return f"{parsed_url.scheme.lower()}://{hostname.lower()}{port}"


def tokens(*strings):
    """Split names into words across _ - . / and camelCase.

    `to_org`, `orgId` and `organization-id` must all yield `org`-ish tokens. A plain \\b regex
    does not: `_` is a word character, so \\borg\\b never matches inside `to_org`. Every property
    below was silently under-detected until this existed.
    """
    out = set()
    for s in strings:
        for part in re.split(r"[^A-Za-z0-9]+", s or ""):
            if not part:
                continue
            for w in re.findall(r"[A-Z]+(?![a-z])|[A-Z][a-z]+|[a-z]+|\d+", part):
                out.add(w.lower())
    return out


# token → property. Deliberately about the *shape* of a name, not a wordlist of parameters to try.
TOKEN_PROPS = {
    "multi-tenant":    {"org", "organization", "tenant", "workspace", "account", "company", "team"},
    "fetches-url":     {"url", "uri", "callback", "webhook", "src", "dest", "destination",
                        "feed", "endpoint", "proxy", "fetch", "import", "avatar"},
    "redirect":        {"next", "return", "returnto", "redirect", "continue", "back", "goto"},
    "file-path":       {"file", "path", "doc", "document", "attachment", "download", "template",
                        "filename", "dir", "folder"},
    "db-query":        {"q", "query", "search", "filter", "sort", "order", "where", "select",
                        "limit", "offset", "page"},
    "identity-input":  {"email", "user", "username", "phone", "login", "mail", "handle"},
    "money":           {"price", "amount", "qty", "quantity", "currency", "coupon", "discount",
                        "balance", "total", "cost", "fee", "refund", "payment"},
    "state-machine":   {"status", "state", "step", "stage", "phase", "approve", "confirm",
                        "publish", "cancel", "transition"},
}


def properties_of(entry, tmpl, values, params):
    """Observable surface properties, from playbooks/system/class-signals.md vocabulary."""
    p = set()
    if values or re.search(r"\{(id|uuid|hash|opaque)\}", tmpl):
        p.add("object-ref")
    if len(re.findall(r"\{(id|uuid|hash|opaque)\}", tmpl)) >= 2:
        p.add("two-object")
    toks = tokens(tmpl, *params)
    for prop, vocab in TOKEN_PROPS.items():
        if toks & vocab:
            p.add(prop)
    if entry["method"] in ("POST", "PUT", "PATCH") and entry["body"]:
        p.add("mass-bind")
    if entry["res_headers"].get("set-cookie"):
        p.add("session-issue")
    if any(h in entry["res_headers"] for h in ("age", "x-cache", "cf-cache-status")):
        p.add("cacheable")
    if "origin" in entry["req_headers"] or "access-control-allow-origin" in entry["res_headers"]:
        p.add("cross-origin")
    if "multipart/form-data" in (entry["req_ct"] or "").lower():
        p.add("file-upload")
    if re.search(r"\b(xml|soap)\b", (entry["req_ct"] or "").lower()):
        p.add("xml-parser")

    res_body = entry.get("res_body") or ""
    body = res_body + " " + (entry.get("body") or "")
    auth = " ".join(str(v) for k, v in entry["req_headers"].items()
                    if k in ("authorization", "cookie")) + " " + body

    # role-gated had NO producer anywhere in the workspace, which made
    # function-level-authorization unreachable in practice. The one-response path: a bootstrap
    # payload that ENUMERATES roles/permissions/flags the caller does not hold is an
    # observation, and it does not need a second principal to see.
    if re.search(r'"(is_?admin|isAdmin|role|roles|permissions|scopes|features|entitlements)"\s*:',
                 res_body) or re.search(r"\b(launchdarkly|statsig|split\.io|optimizely)\b",
                                        res_body, re.I):
        p.add("role-gated")

    # A JWT is the most reliably observable credential shape there is: three base64url segments
    # whose header names its own verification key.
    if re.search(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.", auth):
        p.add("jwt")

    # N operations or N ids in one request — the property `limit-bypass` already promised
    # ("defeated by batching") but had no token for.
    if re.search(r"/(bulk|batch|import)\b", tmpl, re.I) or \
       re.search(r'"(ids|items|operations|records|entries)"\s*:\s*\[', entry.get("body") or ""):
        p.add("bulk-operation")

    # A handle now, the real result later — relocates the oracle for every blind class.
    if entry.get("status") == 202 or "location" in entry["res_headers"] and entry.get("status") in (201, 202) or \
       re.search(r'"(job_?id|task_?id|operation_?id|export_?id)"\s*:', entry.get("res_body") or ""):
        p.add("async-job")

    # Server-side render of user content — the highest hit-rate single feature type.
    res_ct = (entry.get("res_ct") or "").lower()
    if re.search(r"application/pdf|spreadsheetml|application/vnd\.ms-excel|text/csv", res_ct) or \
       re.search(r"/(export|render|report|invoice|screenshot|thumbnail)\b", tmpl, re.I):
        p.add("renders-document")

    # Acting as someone else without re-authenticating.
    if re.search(r"/(impersonate|switch[-_]?(user|org|tenant|workspace)|assume|su)\b", tmpl, re.I) or \
       any(h in entry["req_headers"] for h in ("x-org-id", "x-tenant-id", "x-workspace-id")):
        p.add("principal-switch")
    return p


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target")
    ap.add_argument("capture", help="a .har or a Burp XML export")
    ap.add_argument("--write", action="store_true", help="apply; default is a dry run")
    ap.add_argument("--allow-unscoped", action="store_true",
                    help="import in-scope entries and SKIP the rest instead of refusing")
    args = ap.parse_args()

    tdir = target_of(args.target)
    entries, kind = load(args.capture)
    print(f"\n# import {Path(args.capture).name} → {tdir.name}   ({kind}, {len(entries)} entries)")

    scope = require_scope(tdir, die)

    # ---- scope reconciliation, before anything else -------------------------
    hosts = defaultdict(int)
    for e in entries:
        hosts[(urlparse(e["url"]).hostname or "?").lower()] += 1
    unscoped = {h: n for h, n in hosts.items() if not in_scope(h, scope)}
    in_hosts = {h: n for h, n in hosts.items() if h not in unscoped}

    print(f"\n## Scope   {len(in_hosts)} in scope · {len(unscoped)} not")
    for h, n in sorted(in_hosts.items(), key=lambda x: -x[1])[:12]:
        print(f"  ok   {h:<44} {n:>5} entries")
    for h, n in sorted(unscoped.items(), key=lambda x: -x[1])[:12]:
        why = ("explicitly out of scope" if matches(h, scope["out_of_scope"])
               else "not in scope.md")
        print(f"  --   {h:<44} {n:>5} entries   ({why})")
    if unscoped and not args.allow_unscoped:
        print(f"\nFAIL — {len(unscoped)} host(s) in this capture are not in scope. Nothing imported.",
              file=sys.stderr)
        print("       A capture normally contains other tabs; that is fine. Decide explicitly:",
              file=sys.stderr)
        print("       add them to scope.md if authorized, or re-run with --allow-unscoped to skip",
              file=sys.stderr)
        print("       them. This refuses rather than warns because scope is a legal boundary.",
              file=sys.stderr)
        return 2
    entries = [e for e in entries if (urlparse(e["url"]).hostname or "").lower() in in_hosts]
    if not entries:
        print("\n  nothing in scope to import")
        return 1

    # ---- credentials --------------------------------------------------------
    cred_kinds = set()
    for e in entries:
        cred_kinds |= creds_in(e)
    if cred_kinds:
        print(f"\n## Credentials   {len(cred_kinds)} kind(s) — values stripped, never written")
        for k in sorted(cred_kinds):
            print(f"  {k}")
        print("  Record the PRINCIPAL these represent in accounts.md yourself. Everything written\n"
              "  below stores `<accounts.md:principal>` in their place.")

    # ---- fold into endpoints -------------------------------------------------
    eps = {}
    for e in entries:
        u = urlparse(e["url"])
        tmpl, values = template_path(u.path)
        params = sorted(set(parse_qs(u.query).keys()))
        if e["body"] and "json" in (e["req_ct"] or "").lower():
            try:
                b = json.loads(e["body"])
                if isinstance(b, dict):
                    params += sorted(b.keys())
            except Exception:
                pass
        elif e["body"] and "form" in (e["req_ct"] or "").lower():
            params += sorted(set(parse_qs(e["body"]).keys()))
        origin = origin_of(u)
        if not origin:
            continue
        key = (origin, e["method"], tmpl)
        rec = eps.setdefault(key, {"n": 0, "params": set(), "status": set(),
                                   "props": set(), "values": set(), "ct": set(),
                                   "authenticated": False})
        rec["n"] += 1
        rec["params"] |= {p for p in params if p}
        rec["status"].add(e["status"])
        rec["values"] |= set(values[:3])
        if e["res_ct"]:
            rec["ct"].add(e["res_ct"].split(";")[0])
        rec["authenticated"] = rec["authenticated"] or request_has_auth(e)
        rec["props"] |= properties_of(e, tmpl, values, list(rec["params"]))

    # ---- dedup against what the brain already has ---------------------------
    # There is one endpoint schema and one parser for it. The old importer wrote a private
    # `(method, host, path)` table which paths.py could not consume; surfacelib reads that legacy
    # shape for compatibility but every new row below is canonical.
    ep_file = tdir / "recon" / "endpoints.md"
    known = {endpoint_key(endpoint) for endpoint in read_endpoints(ep_file)}
    fresh = {}
    for (origin, method, tmpl), value in eps.items():
        endpoint = Endpoint(url=f"{origin}{tmpl}", method=method)
        if endpoint_key(endpoint) not in known:
            fresh[(origin, method, tmpl)] = value

    print(f"\n## Endpoints   {len(eps)} distinct  ({len(entries)} requests collapsed) · "
          f"{len(fresh)} not already in the brain")
    for (origin, meth, tmpl), v in sorted(fresh.items(), key=lambda x: -len(x[1]["props"]))[:25]:
        props = ",".join(sorted(v["props"])) or "—"
        st = ",".join(str(s) for s in sorted(v["status"]) if s)
        print(f"  {meth:<6} {origin}{tmpl}")
        print(f"         x{v['n']}  status {st or '?'}  props: {props}")
        if v["params"]:
            ps = sorted(v["params"])
            print(f"         params: {', '.join(ps[:10])}{' …' if len(ps) > 10 else ''}")
    if len(fresh) > 25:
        print(f"  … {len(fresh) - 25} more (all written with --write; this list is capped at 25)")

    if not fresh:
        print("\n  nothing new — the brain already knows every endpoint in this capture")
        return 1

    if not args.write:
        print("\n  DRY RUN — nothing written. Re-run with --write to apply.")
        return 0

    # ---- write --------------------------------------------------------------
    today = date.today().isoformat()
    rows = []
    for (origin, meth, tmpl), v in sorted(fresh.items()):
        statuses = ",".join(str(s) for s in sorted(v["status"]) if s) or "?"
        props = ",".join(sorted(v["props"])) or "none-derived"
        auth = "yes" if v["authenticated"] or ({401, 403} & v["status"]) else "unknown"
        rows.append(Endpoint(
            url=f"{origin}{tmpl}", method=meth,
            params=tuple(sorted(v["params"])), auth_required=auth,
            content_type=", ".join(sorted(v["ct"])),
            interesting_why=f"captured x{v['n']}; status={statuses}; properties={props}",
            source=f"traffic:{Path(args.capture).name}",
        ))
    written = append_endpoints(
        ep_file, rows, title=f"Imported from {Path(args.capture).name} — {today}")
    if written != len(rows):
        die(f"endpoint writer accepted {written} of {len(rows)} fresh rows — contract drift")

    led = tdir / "observations.tsv"
    if not led.exists():
        led.write_text("date\tsubject\tpredicate\tobject\tconfidence\tsource\tevidence\n",
                       encoding="utf-8")
    with led.open("a", encoding="utf-8") as fh:
        for host in sorted(in_hosts):
            cts = {c for k, v in eps.items()
                   if urlparse(k[0]).hostname == host for c in v["ct"]}
            if any("json" in c for c in cts):
                fh.write(f"{today}\t{host}\tserves\tapi\tobserved\timport-http\t"
                         f"{Path(args.capture).name}\n")
            if any("html" in c for c in cts):
                fh.write(f"{today}\t{host}\tserves\tapp\tobserved\timport-http\t"
                         f"{Path(args.capture).name}\n")
        for (origin, meth, tmpl), v in fresh.items():
            if "session-issue" in v["props"]:
                fh.write(f"{today}\t{urlparse(origin).hostname}\tauth\tsession-cookie\tobserved\timport-http\t"
                         f"{Path(args.capture).name}\n")
                break

    print(f"\n  wrote  {rel(ep_file)}   ({len(fresh)} endpoints)")
    print(f"  wrote  {rel(led)}         (host-level observations)")
    print("\n  NOT written, on purpose:")
    print("    accounts.md   — record the principal yourself; the tool never stores a credential")
    print("    attack-surface.md — scoring is `attack-surface-prioritization`'s job, on "
          "evidence, not an import's guess")
    print("    tested.md     — an import is not a test")
    print(f"\n  Next: tools/kb.py reassess {args.target}")
    return 0


if __name__ == "__main__":
    sys.exit(runlog.wrap()(main)())
