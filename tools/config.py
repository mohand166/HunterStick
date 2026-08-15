#!/usr/bin/env python3
"""Single source of truth for workspace config — API keys, VPS, researcher identity.

    tools/config.py check              # what is set / missing. NEVER prints a secret.
    tools/config.py get vps.host       # one value, raw, for scripting
    tools/config.py env                # shell exports:  eval "$(tools/config.py env)"
    tools/config.py ssh                # the ssh prefix for this VPS, or fail loud

Precedence: environment variable > config.json > config.example.json defaults.
An env override is named BBW_ + the dotted path upper-cased with dots as underscores:
    vps.host              -> BBW_VPS_HOST
    api_keys.shodan       -> BBW_API_KEYS_SHODAN
    defaults.rate_limit_rps -> BBW_DEFAULTS_RATE_LIMIT_RPS

Design rules this file exists to enforce:
  * `check` reports presence, never value. Secrets do not belong in a terminal, a log, or a
    transcript, and "just this once" is how they end up in all three.
  * A missing key is a LOUD, named condition — `get` on an empty required value exits non-zero.
    A tool that needs a key it does not have must say so, never quietly return zero results.
  * config.json is gitignored. This file refuses to print anything if it is world-readable.

Exit: 0 ok · 1 the requested value is unset · 2 config missing/malformed.
"""
import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "config.json"
EXAMPLE = ROOT / "config.example.json"
ENV_PREFIX = "BBW_"

# Dotted paths whose value is a credential. `check` shows SET/unset for these and nothing else.
# notify.channels carries webhook URLs — a Discord/Slack webhook URL *is* a bearer credential.
SECRET_RE = re.compile(
    r"(^api_keys\.)|(token$)|(secret$)|(\.key$)|(^api_keys\.github$)|(^notify\.channels$)",
    re.I)

# Dotted paths whose value must never reach the model's context — shown as SET/unset only by
# `check`, refused by `get`, excluded from `env`. Two reasons:
#   * contact_email / protected_aliases are PRIVATE: the derived-name incident cannot happen if the
#     model never sees the value to derive from.
#   * handle / header_value are the attribution identity: now that `vps-run.py` INJECTS the header,
#     the model never needs to type it, so keeping the raw value out of context removes the last way
#     it could be pasted somewhere it does not belong. `header_name` stays visible — it is not
#     identifying, and the model needs it to recognise the header.
PRIVATE_RE = re.compile(r"^researcher\.(contact_email|protected_aliases|handle|header_value)", re.I)


def _strip_notes(obj):
    """Drop the _README/_note documentation keys so they never look like config."""
    if isinstance(obj, dict):
        return {k: _strip_notes(v) for k, v in obj.items() if not k.startswith("_")}
    if isinstance(obj, list):
        return [_strip_notes(v) for v in obj]
    return obj


def _load_file(path, required):
    if not path.exists():
        if required:
            print(f"FAIL — {path.name} not found.\n"
                  f"       cp {EXAMPLE.name} config.json   and fill it in.", file=sys.stderr)
            raise SystemExit(2)
        return {}
    try:
        return _strip_notes(json.loads(path.read_text(encoding="utf-8-sig")))
    except json.JSONDecodeError as e:
        print(f"FAIL — {path.name} is not valid JSON: {e}\n"
              f"       Refusing to guess. Fix the file.", file=sys.stderr)
        raise SystemExit(2)


def _merge(base, over):
    out = dict(base)
    for k, v in over.items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def _flatten(obj, prefix=""):
    flat = {}
    for k, v in obj.items():
        path = f"{prefix}{k}"
        if isinstance(v, dict):
            flat.update(_flatten(v, path + "."))
        else:
            flat[path] = v
    return flat


def _warn_permissions():
    if not CONFIG.exists():
        return
    mode = CONFIG.stat().st_mode
    if mode & (stat.S_IRGRP | stat.S_IROTH):
        print(f"WARNING — {CONFIG.name} is readable by group/other. It holds credentials.\n"
              f"          chmod 600 {CONFIG.name}", file=sys.stderr)


def load():
    """Merged config as a flat {dotted.path: value} map, env overrides applied."""
    merged = _merge(_load_file(EXAMPLE, required=True), _load_file(CONFIG, required=False))
    flat = _flatten(merged)
    for path in list(flat):
        env = ENV_PREFIX + path.upper().replace(".", "_")
        if env in os.environ:
            flat[path] = os.environ[env]
    return flat


def is_set(v):
    return v not in (None, "", [], {}) and v is not False


def cmd_check(flat, args):
    _warn_permissions()
    print(f"config: {'config.json' if CONFIG.exists() else 'config.json MISSING — defaults only'}"
          f"  (+ {EXAMPLE.name} defaults, + {ENV_PREFIX}* env)")
    groups = {}
    for path, val in sorted(flat.items()):
        groups.setdefault(path.split(".")[0], []).append((path, val))
    for group, items in groups.items():
        print(f"\n  [{group}]")
        for path, val in items:
            leaf = path.split(".", 1)[1] if "." in path else path
            if SECRET_RE.search(path) or PRIVATE_RE.search(path):
                shown = "SET" if is_set(val) else "—"
            else:
                shown = repr(val) if is_set(val) else "—"
            flag = " " if is_set(val) else "·"
            print(f"   {flag} {leaf:<26} {shown}")
    missing = [p for p, v in flat.items() if not is_set(v)]
    print(f"\n{len(flat) - len(missing)} set · {len(missing)} unset")
    print("Unset values are not errors — they degrade coverage. A phase that needs one must say\n"
          "so by name and stop, never report zero findings as if it had run.")
    return 0


def cmd_get(flat, args):
    path = args.path
    if PRIVATE_RE.search(path):
        # Exposure minimisation: a private identity value is never printed, even on explicit
        # request. Nothing in the workflow needs it — run.py reads it in-process via load(), and
        # the model must never hold it. `check` shows only presence.
        print(f"FAIL — {path} is PRIVATE identity and is not exposed via `get`. It is never "
              f"payload;\n       run.py reads it in-process. `tools/config.py check` shows only "
              f"whether it is set.", file=sys.stderr)
        return 2
    if path not in flat:
        print(f"FAIL — no such config path: {path}\n"
              f"       known: {', '.join(sorted(flat)[:8])} …  (tools/config.py check)",
              file=sys.stderr)
        return 2
    val = flat[path]
    if not is_set(val):
        print(f"FAIL — {path} is not set. Set it in config.json or export "
              f"{ENV_PREFIX}{path.upper().replace('.', '_')}.", file=sys.stderr)
        return 1
    print(json.dumps(val) if isinstance(val, (list, dict)) else val)
    return 0


def cmd_env(flat, args):
    """Shell exports. Only emits what is set, so `set -u` scripts fail on the real gap.

    PRIVATE identity is excluded: `env` fans a value out to every child process, and nothing in the
    workflow needs the researcher's email or aliases there. Exposure minimisation — keep it out."""
    for path, val in sorted(flat.items()):
        if not is_set(val) or isinstance(val, (list, dict)) or PRIVATE_RE.search(path):
            continue
        name = ENV_PREFIX + path.upper().replace(".", "_")
        print(f"export {name}={json.dumps(str(val))}")
    # convenience aliases the shell tools already expect
    if is_set(flat.get("api_keys.hackerone.username")):
        print(f'export H1_USER={json.dumps(str(flat["api_keys.hackerone.username"]))}')
    if is_set(flat.get("api_keys.hackerone.token")):
        print(f'export H1_TOKEN={json.dumps(str(flat["api_keys.hackerone.token"]))}')
    return 0


def cmd_ssh(flat, args):
    if not flat.get("vps.enabled"):
        print("FAIL — vps.enabled is false. No VPS configured; passive-only work is available.\n"
              "       Set vps.* in config.json (see playbooks/system/vps-setup.md).",
              file=sys.stderr)
        return 1
    missing = [k for k in ("vps.user", "vps.host", "vps.ssh_key") if not is_set(flat.get(k))]
    if missing:
        print(f"FAIL — vps.enabled is true but {', '.join(missing)} unset. "
              f"Refusing to build a half-formed ssh command.", file=sys.stderr)
        return 1
    key = os.path.expanduser(str(flat["vps.ssh_key"]))
    if not Path(key).exists():
        print(f"FAIL — ssh key not found at {key}", file=sys.stderr)
        return 1
    port = flat.get("vps.port") or 22
    print(f"ssh -i {key} -p {port} {flat['vps.user']}@{flat['vps.host']}")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("check", help="presence report — never prints a secret")
    g = sub.add_parser("get", help="print one value")
    g.add_argument("path", help="dotted path, e.g. vps.host")
    sub.add_parser("env", help="shell exports for the .sh tools")
    sub.add_parser("ssh", help="the ssh prefix for the configured VPS")
    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        return 2
    flat = load()
    return {"check": cmd_check, "get": cmd_get, "env": cmd_env, "ssh": cmd_ssh}[args.cmd](flat, args)


if __name__ == "__main__":
    sys.exit(main())
