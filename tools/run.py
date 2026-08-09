#!/usr/bin/env python3
"""Execute a command, validate its output contract, and record what makes it reproducible.

    tools/run.py targets/acme --skill content-discovery \\
        --expect-file raw/content/app-acme.json \\
        -- ffuf -u https://app.acme.com/FUZZ -w recon/wordlists/app-java.txt -of json \\
                -o raw/content/app-acme.json

What it does
------------
Runs your command, then writes a record that answers *"why that flag, three weeks ago?"* —
tool version, **redacted** argv plus a hash of the real one, sha256 of every input file, the
host it ran on, duration, exit code, and the artifact's size and hash. Stdout and stderr go to
files beside the record, never into the log.

And it judges success on the **artifact and its declared structure**, not on what the tool printed.
`ffuf -o` can exit 0, print a banner, and leave an empty file; jsluice can exit cleanly after a
malformed `-R`; a stale file can make both look successful. Missing, empty, unchanged and
structurally invalid output all fail loudly.

Two things it WILL refuse, both before sending: (1) the researcher's own PRIVATE identity (contact
email, configured name aliases) as payload, anywhere — unconditionally, no override flag, because
the model that built the unsafe command is the one that would set it; (2) the PUBLIC attribution
value (your handle / `header_value`) placed anywhere other than its one designated attribution
header — public is not licence to use your identity as application data. Credentials are `<redacted>`
in the record.

Scope of the "no PII at rest" guarantee, stated exactly: only the JSON **metadata** is category-only.
The raw stdout/stderr (`*.out`/`*.err`) and the artifact are the response verbatim — if the target
echoed a private value back, it lands in those files, which the scan cannot prevent (it runs after
they are written). What the scan does is flag the category so a human scrubs the raw evidence before
sharing it. The record never stores the value; the evidence file might, and you are told when.

**Reach and limits, stated plainly so no one over-trusts it.** This is a *local defense-in-depth*
net, not the primary control. It reads `config.json` for the values to refuse, and config is not on
the VPS where traffic egresses — so on the VPS it refuses nothing. The real guarantee is EXPOSURE
MINIMISATION: `config.py` hides these values from check/get/env and nothing writes them into the
brain, so the model never holds them. This net catches only the EXACT configured string — not
word-parts, not `first=Jane&last=Hunter` from an alias `Jane Hunter`, not arbitrary PII, not a value
from stdin/a file/an env var, not one a transformation derived. It is a privacy backstop, not a
scope gate.

What it deliberately does NOT do any more
-----------------------------------------
This used to be a policy engine: ~310 lines checking scope, rate limits, HTTP methods,
calibration evidence, flag advertisement, egress host and the run ledger.

Two things were wrong with that. **It never ran** — `logs/exec/` held zero records for an
entire engagement, because the brain wrongly recorded that the VPS had no checkout of this
repo, so every remote command went through a hand-rolled script and none of the checking
applied. (The checkout was there the whole time; nobody re-verified the claim.) And the checks
encoded judgements that belong to the hunter: which packets to send, from where, at what rate.

So the responsibilities split where they belong. **The model owns command choice** — read the
installed binary's help, pilot, verify the output shape, adapt (`skills/_recon-method.md`).
**This owns the mechanically assertable edge**: known invocation traps, fresh output and declared
JSON/JSONL shape, plus the evidence record. It does not choose scope, methods, rates or what to hunt.

Exit: 0 the command succeeded and satisfied its output contract · 1 exit 0 but output was missing,
empty, stale or structurally invalid · 2 the command itself failed or its invocation was known-bad.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# Tools for which the installed CLI has a verified inline header flag.  This is intentionally
# narrower than TARGET_HTTP_TOOLS: some HTTP clients accept a header file, `name=value`, or no
# arbitrary header at all.  Guessing their syntax would make a command look attributed when it is
# not.  vps-run.py injects only this verified subset.
ATTRIBUTION_TOOLS = {
    "curl": "-H", "httpx": "-H", "nuclei": "-H", "ffuf": "-H",
    "feroxbuster": "-H", "katana": "-H", "dalfox": "-H", "wget": "--header",
    "arjun": "--headers", "gowitness": "--chrome-header", "grpcurl": "-H",
    "clairvoyance": "-H", "sourcemapper": "-header", "x8": "-H", "graphw00f": "-H",
    "whatweb": "-H",
}

# Tools documented by this repository that can send requests to the selected target.  Every one
# must cross the local vps-run privacy/recording boundary even when its attribution syntax cannot
# be injected automatically.  Keep this separate from ATTRIBUTION_TOOLS: gate coverage and header
# support are different facts.
TARGET_HTTP_TOOLS = frozenset(ATTRIBUTION_TOOLS) | {
    "wafw00f", "git-dumper", "s3scanner", "subzy",
    "waymore", "bbot",
}
# Set by vps-run.py when it dispatches, proving the LOCAL identity gate ran (run.py cannot run that
# gate on the VPS — no config there). Its absence on an HTTP-tool command means the gate was skipped.
GATE_ENV = "HUNTERSTICK_VPSRUN"

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runlog                                                     # noqa: E402

URLISH = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
VERSIONISH = re.compile(r"\d+\.\d+")
SECRET_VALUE = re.compile(r"(?:authorization|cookie|x-api-key|bearer\s|token\s*[:=]|"
                          r"api[_-]?key\s*[:=]|password\s*[:=])", re.I)
EMAIL = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.I)


# Machine-checkable output contracts for the external tools where a nonempty-but-wrong artifact
# has already cost real coverage. The entries deliberately assert only stable interface fields;
# hunting judgements (which flags, selectors, rates or optional signals matter) remain with the
# model and the skill. `--expect-fields` extends a contract for the exact downstream parser.
STRUCTURED_CONTRACTS = {
    "jsluice-urls": {
        "format": "jsonl",
        "fields": {"url": str, "queryParams": list, "bodyParams": list,
                   "method": str, "type": str, "filename": str},
    },
    "jsluice-secrets": {
        "format": "jsonl",
        "fields": {"kind": str, "data": dict, "filename": str, "severity": str},
    },
    "httpx-jsonl": {"format": "jsonl", "fields": {"url": str}},
    "subfinder-jsonl": {"format": "jsonl", "fields": {"host": str}},
    "dnsx-jsonl": {"format": "jsonl", "fields": {"host": str}},
    "naabu-jsonl": {"format": "jsonl", "fields": {"host": str, "port": int}},
    "katana-jsonl": {"format": "jsonl", "fields": {}},
    "nuclei-jsonl": {"format": "jsonl", "fields": {}},
    "nuclei-json": {"format": "json", "fields": {}},
    "ffuf-jsonl": {"format": "jsonl", "fields": {}},
    "ffuf-json": {"format": "json", "fields": {}, "root_list": "results"},
    "whatweb-json": {"format": "json", "fields": {}},
    "arjun-json": {"format": "json", "fields": {}},
}

FLAG_CONTRACTS = {
    "httpx": (("httpx-jsonl", ("-j", "-json")),),
    "subfinder": (("subfinder-jsonl", ("-json", "-oJ")),),
    "dnsx": (("dnsx-jsonl", ("-j", "-json")),),
    "naabu": (("naabu-jsonl", ("-j", "-json")),),
    "katana": (("katana-jsonl", ("-j", "-jsonl")),),
    "whatweb": (("whatweb-json", ("--log-json",)),),
    "arjun": (("arjun-json", ("-o", "-oJ")),),
}


def _option_value(argv, names):
    """Return the last value supplied to one of `names`, accepting --flag=value."""
    found = None
    for i, token in enumerate(argv[1:], 1):
        for name in names:
            if token == name and i + 1 < len(argv):
                found = argv[i + 1]
            elif token.startswith(name + "="):
                found = token.split("=", 1)[1]
    return found


def _has_option(argv, names):
    return any(token in names or any(token.startswith(n + "=") for n in names)
               for token in argv[1:])


def _jsluice_resolve_error(argv):
    if len(argv) < 2 or argv[1] != "urls" or not _has_option(argv, ("-R", "--resolve-paths")):
        return ""
    base_url = _option_value(argv, ("-R", "--resolve-paths"))
    if not base_url:
        return "jsluice -R/--resolve-paths requires an absolute HTTP(S) base URL"
    if re.match(r"^https?://[^/\s]+(?:/.*)?$", base_url, re.I):
        return ""
    return ("jsluice -R/--resolve-paths takes an absolute HTTP(S) base URL, not an input "
            f"file ('{base_url}'). Pass JavaScript files as positional inputs; omit -R unless "
            "you have the bundle's source URL.")


def invocation_errors(argv):
    """Stable semantic invocation failures that can exit 0 and erase coverage."""
    if not argv:
        return ["empty command"]
    if Path(argv[0]).name.lower() != "jsluice":
        return []
    message = _jsluice_resolve_error(argv)
    return [message] if message else []


def inferred_contract(argv):
    """Infer a stable structured-output contract from a direct external-tool invocation."""
    if not argv:
        return None
    tool = Path(argv[0]).name.lower()
    if tool == "jsluice" and len(argv) > 1 and argv[1] in ("urls", "secrets"):
        return f"jsluice-{argv[1]}"
    if tool == "nuclei":
        if _has_option(argv, ("-je", "-json-export")):
            return "nuclei-json"
        if _has_option(argv, ("-j", "-jsonl", "-jle", "-jsonl-export")):
            return "nuclei-jsonl"
    if tool == "ffuf":
        output_format = _option_value(argv, ("-of",))
        if _has_option(argv, ("-o",)):
            return "ffuf-json" if (output_format or "json").lower() == "json" else None
        if _has_option(argv, ("-json",)):
            return "ffuf-jsonl"
    for contract_name, flags in FLAG_CONTRACTS.get(tool, ()):
        if _has_option(argv, flags):
            return contract_name
    return None


def inferred_output_file(argv):
    """Read the artifact path from stable output flags so forgetting --expect-file cannot hide it."""
    if not argv:
        return None
    tool = Path(argv[0]).name.lower()
    flags = {
        "httpx": ("-o", "-output"), "subfinder": ("-o", "-output"),
        "dnsx": ("-o", "-output"), "naabu": ("-o", "-output"),
        "katana": ("-o", "-output"),
        "nuclei": ("-o", "-output", "-je", "-json-export",
                    "-jle", "-jsonl-export"),
        "ffuf": ("-o",), "whatweb": ("--log-json",),
        "arjun": ("-o", "-oJ"),
    }
    return _option_value(argv, flags.get(tool, ()))


def output_contract(name=None, fmt=None, extra_fields=()):
    """Build one contract without allowing a generic flag to weaken a known tool contract."""
    base = STRUCTURED_CONTRACTS.get(name, {})
    inferred_format = base.get("format")
    if fmt and inferred_format and fmt != inferred_format:
        raise ValueError(f"declared --expect-format {fmt} conflicts with inferred "
                         f"{name} format {inferred_format}")
    actual = inferred_format or fmt
    if not actual:
        if extra_fields:
            raise ValueError("--expect-fields requires JSON or JSONL output")
        return None
    fields = dict(base.get("fields", {}))
    for field in extra_fields:
        fields.setdefault(field, None)
    return {"name": name or f"declared-{actual}", "format": actual, "fields": fields,
            "root_list": base.get("root_list")}


def _row_contract_error(row, label, fields):
    if not isinstance(row, dict):
        return f"{label} is {type(row).__name__}, expected an object"
    for field, kind in fields.items():
        if field not in row:
            return f"{label} is missing required field '{field}'"
        if kind is not None and not isinstance(row[field], kind):
            return f"{label}.{field} is {type(row[field]).__name__}, expected {kind.__name__}"
    return ""


def _validate_jsonl_rows(path, fields):
    records = 0
    with Path(path).open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            error = _row_contract_error(json.loads(line), f"line {line_number}", fields)
            if error:
                return records, error
            records += 1
    return records, ""


def _json_rows(path, root_list):
    with Path(path).open(encoding="utf-8") as stream:
        document = json.load(stream)
    if root_list:
        if not isinstance(document, dict) or not isinstance(document.get(root_list), list):
            return [], f"root must contain list field '{root_list}'"
        return document[root_list], ""
    return (document if isinstance(document, list) else [document]), ""


def _validate_json_rows(path, contract):
    rows, error = _json_rows(path, contract.get("root_list"))
    if error:
        return 0, error
    for index, row in enumerate(rows, 1):
        error = _row_contract_error(row, f"record {index}", contract["fields"])
        if error:
            return index - 1, error
    return len(rows), ""


def validate_output(path, contract):
    """Validate every structured record without loading a JSONL result set into memory."""
    validation = {"contract": contract["name"], "format": contract["format"],
                  "ok": False, "records": 0, "error": ""}
    try:
        if contract["format"] == "jsonl":
            records, error = _validate_jsonl_rows(path, contract["fields"])
        else:
            records, error = _validate_json_rows(path, contract)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        validation["error"] = f"{type(error).__name__}: {error}"
        return validation
    validation.update(records=records, error=error)
    if not error and records:
        validation["ok"] = True
    elif not error:
        validation["error"] = "structured output contains zero records"
    return validation


def private_values():
    """The researcher's PRIVATE identity — a contact email and any configured name aliases. Returns
    [(category, value)]; only the category ('researcher.contact_email') is ever persisted, never the
    value.

    Deliberately NOT included: the attribution handle / header value. Those are public by design —
    sent to every program on every request — so refusing them trained the model to bypass the guard
    during normal work. Only genuinely private values are refusable here; the public attribution
    channel is separate and always permitted.

    IMPORTANT — this is defense-in-depth, not the primary control, and its reach is narrow. It reads
    config, which is LOCAL; on a host without config (the VPS, where traffic actually egresses) it
    returns [] and this check does nothing. The real guarantee is EXPOSURE MINIMISATION: `config.py`
    hides these values from check/get/env and nothing writes them into the brain, so the model never
    holds them and cannot leak what it never saw. When it does fire, it matches only the EXACT
    configured string — not word-parts, not `first=Jane&last=Hunter` from an alias `Jane Hunter`,
    not arbitrary PII, not a value read from stdin/a file/an env var, not one a transformation
    derived. Splitting a name across fields is the model's rule to keep, not this net's to catch.

    Fail-open is the one thing it must not do: absent config (VPS) is a quiet [], but a config that
    EXISTS and fails to load is a loud failure, not a silent disabling of the guard.
    """
    out = []
    # Absent config (the VPS: only tools/ is deployed) → nothing to protect, net inactive, quiet [].
    # A config that is PRESENT and unreadable, OR a config module that will not import, is a LOUD
    # failure — not a silent fail-open. `_load_researcher` swallows neither.
    flat, is_set = _load_researcher()
    if flat is None:
        return out

    def add(cat, v):
        if isinstance(v, str) and v.strip() and is_set(v):
            out.append((cat, v.strip()))

    add("researcher.contact_email", flat.get("researcher.contact_email"))
    aliases = flat.get("researcher.protected_aliases")
    if isinstance(aliases, list):
        for i, a in enumerate(aliases):
            add(f"researcher.protected_aliases[{i}]", a)
    return out


def refusable(private):
    """Values (not categories) whose appearance ANYWHERE in an outbound command is refused."""
    return [v for _cat, v in private]


def http_gate_blocks(argv, env):
    """True if this is an HTTP-tool command that did NOT come through vps-run.py (no gate marker).
    Non-HTTP tools are never blocked. Extracted so the decision is testable without a live tool."""
    return bool(argv) and Path(argv[0]).name.lower() in TARGET_HTTP_TOOLS \
        and env.get(GATE_ENV) != "1"


# Flags a tool takes an HTTP request header on. `-H` is near-universal; wget uses `--header`;
# nuclei/others accept `-header`. The separated form is `<flag> "Name: value"`; the combined form
# is `--header=Name: value`.
HEADER_FLAGS = {"-H", "--header", "-header", "--headers"}


def _load_researcher():
    """(flat_config, is_set) locally, or (None, None) where there is no config (the VPS). The import
    is NOT swallowed: config.py sits beside this file, so a failed import is a real, loud error —
    not a reason to silently disable the policy."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import config as _cfg                                          # noqa: E402  (loud if it fails)
    if not _cfg.CONFIG.exists() and not _cfg.EXAMPLE.exists():
        return None, None
    return _cfg.load(), _cfg.is_set


def attribution_header():
    """(header_name, header_value) — the header to INJECT, and its one permitted placement."""
    flat, is_set = _load_researcher()
    if flat is None:
        return None, None
    name, val = flat.get("researcher.header_name"), flat.get("researcher.header_value")
    return (str(name).strip() if is_set(name) else None,
            str(val).strip() if is_set(val) else None)


def attribution_values():
    """Every researcher attribution string that must appear ONLY in the attribution header —
    `header_value` AND `handle`. Both are your identity; the earlier check protected only the first,
    so the handle in a query parameter slipped through."""
    flat, is_set = _load_researcher()
    if flat is None:
        return []
    return [str(flat.get(k)).strip() for k in ("researcher.header_value", "researcher.handle")
            if is_set(flat.get(k))]


def attribution_header_indices(argv, header_name):
    """Indices of args that ARE the attribution header, decided by ARGUMENT STRUCTURE, not text
    shape. A value only counts as the header if the previous arg is a header flag (`-H "Name: v"`)
    or it is the combined `--header=Name: v` form. Header-shaped text in a `-d` body, a `-b` cookie,
    or a positional argument does NOT count — that was the bypass."""
    if not header_name:
        return set()
    name_re = re.compile(rf"^\s*{re.escape(header_name)}\s*:", re.I)
    idx = set()
    for i, a in enumerate(argv):
        flag, _, inline = a.partition("=")
        if flag in HEADER_FLAGS and inline and name_re.match(inline):
            idx.add(i)                                             # --header=Name: value
        if i > 0 and argv[i - 1] in HEADER_FLAGS and name_re.match(a):
            idx.add(i)                                             # -H  Name: value
    return idx


def attribution_misplaced(argv, header_name, values):
    """True if any attribution value appears OUTSIDE a *structurally real* attribution header. A
    `-H "X-Bug-Bounty: h"` is allowed; the same value in `-d '…'`, `-b '…'`, a different header, or a
    bare positional is refused. Structure, not string shape."""
    values = [v for v in values if v]
    if not values:
        return False
    permitted = attribution_header_indices(argv, header_name)
    for i, a in enumerate(argv):
        if i in permitted:
            continue
        if any(v in a for v in values):
            return True
    return False


def die(msg, code=2):
    print(f"FAIL — {msg}", file=sys.stderr)
    raise SystemExit(code)


def sha(p):
    try:
        return hashlib.sha256(Path(p).read_bytes()).hexdigest()[:16]
    except Exception:
        return ""


def redact_argv(argv, protected=()):
    """Never persist a secret-bearing OR researcher-identity argument.

    The JSON record outlives the session, and argv was being written verbatim — so
    `-H "Authorization: Bearer …"`, `-u user:pass` and credentials inside a URL all survived
    in a file nobody thought of as sensitive. Keep the shape, drop the value. `protected` adds the
    researcher's own configured identity (name/email/handle) by exact substring — those are never
    legitimate payload, so they are replaced with `<researcher-redacted>` wherever they appear.
    Target-account emails are deliberately NOT redacted here: they are valid payload and the
    record is provenance. Their transmission is *detected* (see scan_private) rather than hidden.
    """
    def strip_protected(s):
        for v in protected:
            if v and v in s:
                s = s.replace(v, "<researcher-redacted>")
        return s
    out, skip = [], False
    for i, a in enumerate(argv):
        if skip:
            out.append("<redacted>")
            skip = False
            continue
        a = strip_protected(a)
        flag = a.split("=", 1)[0]
        if flag.lstrip("-").lower() in {s.lstrip("-").lower() for s in runlog.SECRETISH}:
            out.append(flag + "=<redacted>" if "=" in a else flag)
            skip = "=" not in a
            continue
        # `-u` is credentials in curl and a URL in httpx/nuclei — the value says which
        if flag in ("-u", "--user") and i + 1 < len(argv) and not URLISH.match(argv[i + 1]) \
                and ":" in argv[i + 1]:
            out.append(flag)
            skip = True
            continue
        if URLISH.match(a) and "@" in a.split("://", 1)[1].split("/", 1)[0]:
            scheme, rest = a.split("://", 1)
            out.append(f"{scheme}://<redacted>@{rest.split('@', 1)[1]}")
            continue
        if SECRET_VALUE.search(a):
            out.append("<redacted>")
            continue
        out.append(a)
    return out


def identity_in_argv(argv, private):
    """The CATEGORIES of private identity that appear anywhere in the outbound command. Takes the
    (category, value) pairs and returns matching categories — never the values, so a caller can
    refuse and report without ever handling or persisting the raw PII. Exact substring: names split
    across fields are the model's to catch (the always-loaded rule); this catches the reliable case,
    your own email or a configured alias sent verbatim."""
    return sorted({cat for cat, v in private if v and any(v in a for a in argv)})


def scan_private(text, private, where):
    """Fail loud when private data lands in a captured response — reporting CATEGORIES, not values.

    Two levels, on purpose:
      * a configured PRIVATE value (your email/alias) echoed in the response is a real leak — the
        model should never have spent your identity. Loud, by category.
      * a bare email that is NOT one of yours is only flagged, not condemned: it may be the target
        account's, which is legitimate. The human confirms; the tool does not guess — and the email
        itself is a target value, so naming it here is fine (it is not YOUR PII).
    Returns (leaks, notes): leaks name the category; notes name the non-researcher email.
    """
    if not text:
        return [], []
    mine = {v for _c, v in private if v}
    leaks = sorted({cat for cat, v in private if v and v in text})
    others = sorted({m.group(0) for m in EMAIL.finditer(text)} - mine)
    return ([f"{where}: a configured private value ({cat}) appears in the response" for cat in leaks],
            [f"{where}: email {e} — confirm it is the TARGET account's, not yours" for e in others])


def execution_env():
    """Include user-installed tool locations even when SSH starts a non-login shell."""
    env = os.environ.copy()
    home = Path.home()
    preferred = [home / ".local" / "bin", home / "go" / "bin", Path("/usr/local/go/bin")]
    current = env.get("PATH", "").split(os.pathsep)
    env["PATH"] = os.pathsep.join(dict.fromkeys([str(path) for path in preferred] + current))
    return env


def tool_version(binary, env=None):
    # Take the first flag returning something that LOOKS like a version. Accepting any output
    # recorded curl's "curl: (2) no URL specified" as its version, in every record.
    for flag in ("--version", "-version", "version", "-V"):
        try:
            r = subprocess.run([binary, flag], capture_output=True, text=True, timeout=15, env=env)
            for line in (r.stdout + r.stderr).strip().splitlines():
                if VERSIONISH.search(line):
                    return line.strip()[:120]
        except Exception:
            continue
    return "unknown"


def input_hashes(tdir, argv):
    """sha256 of every argv token that is an existing file — the other half of reproducibility.

    "Why did that wordlist yield nothing?" is unanswerable later unless you know which bytes it
    held at the time. Directories are skipped; they are not a fixed input.
    """
    seen, out = set(), []
    for a in argv[1:]:
        if a in seen:
            continue
        for cand in (Path(a), tdir / a):
            if cand.is_file():
                seen.add(a)
                out.append((a, sha(cand)))
                break
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target")
    ap.add_argument("--skill", "--phase", dest="skill", required=True,
                    help="which skill this run belongs to")
    ap.add_argument("--run-id", help="the runs.tsv row this belongs to")
    ap.add_argument("--timeout", type=int, default=1800, help="hard kill, seconds (default 1800)")
    ap.add_argument("--expect-file", metavar="PATH",
                    help="the artifact the tool should produce; success is judged on THIS, "
                         "not on whatever the tool printed")
    ap.add_argument("--stdout-file", metavar="PATH",
                    help="copy captured stdout to this artifact, then validate it; use for direct "
                         "structured tools such as jsluice that have no output-file flag")
    ap.add_argument("--expect-format", choices=("json", "jsonl"),
                    help="validate the artifact (or captured stdout) as JSON/JSONL; known tools "
                         "are inferred automatically")
    ap.add_argument("--expect-fields", metavar="A,B,...",
                    help="top-level fields required in every JSON/JSONL record; use for the exact "
                         "fields a downstream parser will consume")
    ap.add_argument("--note", help="anything worth attaching to the record")
    ap.add_argument("--dry-run", action="store_true",
                    help="resolve the tool and inputs, do not execute")
    # argparse's REMAINDER swallows every flag after the positional, so the command is split off
    # before argparse ever sees it.
    argv_all = sys.argv[1:]
    # `--help` must work before the `--` split, or asking a tool what it does exits 2. This
    # workspace tells the model to read --help before using anything; its own tools have to
    # honour that.
    if not argv_all or argv_all[0] in ("-h", "--help"):
        ap.print_help()
        return 0
    if "--" not in argv_all:
        die("give the command after `--`, e.g. ... --skill http-probing -- httpx -l hosts.txt")
    cut = argv_all.index("--")
    args = ap.parse_args(argv_all[:cut])
    argv = argv_all[cut + 1:]

    tdir = Path(args.target).resolve()
    if not (tdir / "index.md").exists():
        die(f"{args.target} is not a target brain")
    if not argv:
        die("nothing after `--`")

    bad_invocation = invocation_errors(argv)
    if bad_invocation:
        die("known-bad command contract:\n       " + "\n       ".join(bad_invocation))
    inferred = inferred_contract(argv)
    requested_fields = tuple(f.strip() for f in (args.expect_fields or "").split(",") if f.strip())
    try:
        contract = output_contract(inferred, args.expect_format, requested_fields)
    except ValueError as error:
        die(str(error))
    if args.stdout_file and args.expect_file and args.stdout_file != args.expect_file:
        die("--stdout-file and --expect-file must name the same artifact when both are supplied")

    # A scanner that declares its own output file is still artifact-producing even when the model
    # forgot `--expect-file`. Infer stable output flags so the runner, not human memory, owns this.
    expect_file = args.stdout_file or args.expect_file or inferred_output_file(argv)
    expect_origin = ("--stdout-file" if args.stdout_file else
                     ("--expect-file" if args.expect_file else
                      ("tool output flag" if expect_file else None)))

    # Privacy backstop, before anything is sent. Two classes, one placement rule each:
    #   PRIVATE (email, name aliases) — refused ANYWHERE. Unconditional, no override: the model that
    #     built the unsafe command is the one that would set an override, so an override is not human
    #     authorisation. If a program truly needs a private value, a human sends it, out of band.
    #   PUBLIC attribution (your handle / header_value) — permitted in ONLY the configured
    #     attribution header; refused as application data anywhere else (a URL, body, cookie, or a
    #     different header). "Public" is not licence to use your identity as payload.
    # Local-only by nature: both read config, which is not on the VPS — the real guarantee is that
    # the model never holds these values (config.py hides them); this is the local net beneath that.
    private = private_values()
    hit_categories = identity_in_argv(argv, private)
    if hit_categories:
        die("this command carries your OWN private identity — category: "
            + ", ".join(hit_categories)
            + ".\n       Private identity is never payload; a page asking for a name does not "
              "authorise spending\n       yours. Use the target account's recorded profile, or a "
              "synthetic value (e.g.\n       canary@example.test). There is no override — if a "
              "program truly requires your\n       identity in a request, a human sends it, not this "
              "run.", 2)
    attr_name, _ = attribution_header()
    if attribution_misplaced(argv, attr_name, attribution_values()):
        die(f"your PUBLIC attribution identity (handle / header value) appears outside its one "
            f"permitted home, the\n       '{attr_name}' header. It identifies you as the tester — it "
            f"is not application data, so it must\n       not be a URL, body, cookie or a different "
            f"header. Let vps-run.py inject it, or put it in\n       '-H \"{attr_name}: <value>\"' "
            f"and nowhere else.", 2)
    # Transparency: when config is present but no private value is configured, say the local net is
    # inactive so no one mistakes silence for protection. The always-loaded rule is still the control.
    if attr_name is not None and not private:
        print("  note: private-value backstop inactive — no contact_email/aliases configured. "
              "The always-loaded privacy rule remains the control.")

    # The gate: a tool that sends HTTP to a target must come through vps-run.py, which runs the
    # local identity check this recorder CANNOT run on the VPS (no config there) and injects the
    # attribution header. Its absence means the local gate was skipped. This is a steer against
    # ACCIDENTAL bypass, not a boundary against a model that deliberately sets the marker — on
    # shared infra nothing at this layer can be — but a deliberate bypass is then visible.
    if http_gate_blocks(argv, os.environ):
        die(f"'{Path(argv[0]).name}' sends HTTP to the target, so it must go through the local "
            f"identity gate.\n       Run it as:  tools/vps-run.py {args.target} --skill "
            f"{args.skill} … -- {Path(argv[0]).name} …\n       That refuses your identity in a "
            f"payload (this recorder cannot check that on the VPS) and injects the\n       "
            f"attribution header. Non-HTTP tools (dnsx, naabu) may run here directly.", 2)

    command_env = execution_env()
    version = tool_version(argv[0], command_env)
    inputs = input_hashes(tdir, argv)

    print(f"\n  tool      {argv[0]}  {version}")
    print(f"  skill     {args.skill}")
    for path, digest in inputs:
        print(f"  input     {path}  ({digest})")

    if contract:
        print(f"  contract  {contract['name']} ({contract['format']}; "
              f"fields={','.join(contract['fields']) or 'object'})")
    if expect_origin == "--stdout-file":
        print(f"  artifact  {expect_file} (captured stdout)")
    elif expect_origin == "tool output flag":
        print(f"  artifact  {expect_file} (inferred from tool output flag)")

    if args.dry_run:
        print("\n  dry run — nothing executed.\n")
        return 0

    execdir = tdir / "logs" / "exec"
    execdir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%dT%H%M%S")
    base = execdir / f"{stamp}-{args.skill}-{Path(argv[0]).name}"

    exp = None
    before_artifact = None
    if expect_file:
        exp = Path(expect_file)
        if not exp.is_absolute():
            exp = tdir / expect_file
        exp = exp.resolve()
        if args.stdout_file:
            try:
                exp.relative_to(tdir)
            except ValueError:
                die("--stdout-file must stay inside the named target directory")
        if exp.exists():
            stat = exp.stat()
            before_artifact = {"exists": True, "bytes": stat.st_size,
                               "mtime_ns": stat.st_mtime_ns}
        else:
            before_artifact = {"exists": False, "bytes": 0, "mtime_ns": 0}

    started = time.time()
    try:
        with open(f"{base}.out", "w") as so, open(f"{base}.err", "w") as se:
            r = subprocess.run(argv, cwd=tdir, stdout=so, stderr=se, timeout=args.timeout,
                               env=command_env)
        code, why = r.returncode, ""
    except subprocess.TimeoutExpired:
        # A stage killed by its own timeout is a FAILURE, not an empty result. Recording it as
        # 124 with the reason is what stops "0 findings" being written down later.
        code, why = 124, f"killed at --timeout {args.timeout}s"
    except Exception as e:
        code, why = 2, f"{type(e).__name__}: {e}"
    elapsed = round(time.time() - started, 1)

    # Keep the external tool direct so its invocation can be inspected. Some tools (notably
    # jsluice) only emit structured data on stdout; wrapping them in `sh -c '... > file'` would hide
    # the real argv from the known-trap validator. Copy the already-captured bytes instead.
    if args.stdout_file and code == 0:
        try:
            exp.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(f"{base}.out", exp)
        except OSError as error:
            why = (why + "; " if why else "") + \
                f"could not copy stdout to {args.stdout_file}: {type(error).__name__}: {error}"

    outsize = Path(f"{base}.out").stat().st_size
    artifact = None
    if expect_file:
        artifact = {"path": expect_file, "source": expect_origin, "exists": exp.exists(),
                    "bytes": exp.stat().st_size if exp.exists() else 0,
                    "sha256_16": sha(exp) if exp.exists() else ""}
        if exp.exists():
            stat = exp.stat()
            artifact["fresh"] = not before_artifact["exists"] or \
                (stat.st_mtime_ns, stat.st_size) != \
                (before_artifact["mtime_ns"], before_artifact["bytes"])
        else:
            artifact["fresh"] = False

    validation = None
    validation_path = exp if exp is not None else Path(f"{base}.out")
    if code == 0 and contract and validation_path.exists() and validation_path.stat().st_size:
        validation = validate_output(validation_path, contract)
        validation["source"] = expect_file or f"{base.name}.out"
        if artifact is not None:
            artifact["validation"] = validation

    # Did private identity land in the RESPONSE? Cannot un-send it, but it must not go unnoticed —
    # reported by CATEGORY, never value, so the record never becomes a PII store. A stray non-yours
    # email is only a note. Scans stdout, STDERR and the artifact (a tool may echo to any of them).
    SCAN_CAP = 4_000_000
    leaks, notes, truncated = [], [], []

    def _slice(p):
        try:
            b = Path(p).read_text(errors="replace")
        except Exception:
            return ""
        if len(b) > SCAN_CAP:
            truncated.append(p)
            return b[:SCAN_CAP]
        return b
    sources = [("stdout", _slice(f"{base}.out")), ("stderr", _slice(f"{base}.err"))]
    if exp and exp.exists():
        sources.append(("artifact", _slice(exp)))
    for label, blob in sources:
        lk, nt = scan_private(blob, private, label)
        leaks += lk
        notes += nt

    # The private-value CATEGORIES seen in the response — categories only, so a durable record is
    # never a copy of the PII it is warning about. (argv cannot contain a private value here: the
    # run is refused before it starts if it does.)
    leak_categories = sorted({l.split("(", 1)[1].split(")", 1)[0] for l in leaks if "(" in l})
    record = {
        "ts": stamp, "skill": args.skill, "run_id": args.run_id,
        "tool": argv[0], "tool_version": version, "argv": redact_argv(argv, refusable(private)),
        "argv_sha256_16": hashlib.sha256("\x00".join(argv).encode()).hexdigest()[:16],
        "cwd": str(tdir), "inputs": [{"path": p, "sha256_16": s} for p, s in inputs],
        "timeout": args.timeout, "note": args.note,
        "ran_on": socket.gethostname(),
        "started": datetime.fromtimestamp(started).isoformat(timespec="seconds"),
        "seconds": elapsed, "exit": code, "exit_note": why,
        "stdout": f"{base.name}.out", "stderr": f"{base.name}.err", "stdout_bytes": outsize,
        "artifact": artifact,
        "output_validation": validation if artifact is None else None,
        "private_leak_categories": leak_categories,   # CATEGORIES only — never the value
    }
    Path(f"{base}.json").write_text(json.dumps(record, indent=2), encoding="utf-8")

    if leaks:
        print("\n  ⚠ PRIVATE DATA IN THE RESPONSE:")
        for l in leaks:
            print(f"      {l}")
        print("      A configured identity value came back in the output. The JSON record stores only\n"
              "      the category, but the raw .out/.err and the artifact hold the response verbatim —\n"
              "      SCRUB those before sharing. If you sent it, stop and reconsider.")
    elif notes:
        print(f"\n  note: {len(notes)} email(s) in the response — confirm they are the target's:")
        for n in notes[:3]:
            print(f"      {n}")
    if truncated:
        # No silent cap: a leak past the scanned window would be missed, so say the scan was bounded.
        print(f"\n  note: private-data scan read only the first {SCAN_CAP // 1_000_000} MB of "
              f"{', '.join(sorted({Path(p).name for p in truncated}))} — a value past that was not "
              f"checked.")

    print(f"\n  exit      {code}{'  (' + why + ')' if why else ''}   in {elapsed}s")
    print(f"  output    {outsize:,} bytes -> {base.name}.out")
    print(f"  record    {base.name}.json")

    if code != 0:
        err = Path(f"{base}.err").read_text(errors="replace").strip().splitlines()
        if err:
            print(f"  stderr    {err[-1][:100]}")
        print("\n  FAILED. The output is not a result set — do not normalize it into the brain.\n")
        return 2

    # What the tool WROTE is the result; what it printed is a banner.
    if artifact is not None:
        if not artifact["exists"]:
            print(f"\n  Exit 0 but {expect_file} was NOT created. The tool printed "
                  f"{outsize:,} bytes and produced no artifact — that is a failure wearing a\n"
                  f"  success exit code.\n")
            return 1
        if artifact["bytes"] == 0:
            print(f"\n  Exit 0 and {expect_file} is EMPTY. Not 'no findings' until the input\n"
                  f"  and the filter have been re-checked.\n")
            return 1
        if not artifact["fresh"]:
            print(f"\n  Exit 0 but {expect_file} was NOT rewritten. This is a stale artifact, not\n"
                  f"  evidence from this run. Use a run-specific output path and re-run.\n")
            return 1
        print(f"  artifact  {expect_file}  {artifact['bytes']:,} bytes "
              f"({artifact['sha256_16']})")
    elif outsize == 0:
        print("\n  Exit 0 with EMPTY output. That is not 'no findings' until you have checked the\n"
              "  input was right and the filter was not too aggressive.\n")
        return 1
    if contract:
        if not validation or not validation["ok"]:
            reason = validation["error"] if validation else "output was unavailable for validation"
            print(f"\n  Exit 0 but output FAILED contract {contract['name']}: {reason}.\n"
                  f"  Do not normalize it into the brain; inspect the installed help, input and\n"
                  f"  one pilot record, then adapt and re-run.\n")
            return 1
        print(f"  validated {validation['records']:,} {contract['format']} record(s) against "
              f"{contract['name']}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(runlog.wrap()(main)())
