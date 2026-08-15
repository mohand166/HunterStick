#!/usr/bin/env python3
"""Resolve or create the per-application brain for one exact host/URL.

Usage:
    tools/app-context.py resolve targets/acme app.acme.com
    tools/app-context.py resolve targets/acme https://app.acme.com:8443/path
    tools/app-context.py ensure  targets/acme app.acme.com

``resolve`` is read-only and prints the exact files a model should load. ``ensure`` atomically
copies the target's application template when no matching brain exists.  The template directory
is never considered an application and one host can never satisfy another host's preflight.

Exit: 0 resolved/created · 1 no app brain yet or ambiguous without a port · 2 invalid invocation.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import applib  # noqa: E402


def show(target, resolution):
    print(f"# application context — {resolution.subject.display}")
    print(f"  target  {target}")
    print(f"  state   {resolution.state}")
    if resolution.path:
        print(f"  brain   {resolution.path}")
        print("  load")
        for path in resolution.files():
            print(f"    {path}")
    elif resolution.candidates:
        print("  candidates")
        for path in resolution.candidates:
            print(f"    {path}")
        print("  action  supply an explicit port; no application was selected")
    else:
        print("  action  no app brain exists yet; run application-mapping or `ensure`")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=("resolve", "ensure"))
    parser.add_argument("target", type=Path)
    parser.add_argument("subject", help="URL, hostname, IP, or host:port")
    args = parser.parse_args()

    target = args.target.resolve()
    if not (target / "index.md").is_file():
        print(f"FAIL — {target} is not a target brain (no index.md)", file=sys.stderr)
        return 2
    try:
        command = applib.ensure if args.action == "ensure" else applib.resolve
        resolution = command(target, args.subject)
    except ValueError as error:
        print(f"FAIL — {error}", file=sys.stderr)
        return 2
    show(target, resolution)
    return 0 if resolution.status == "found" else 1


if __name__ == "__main__":
    raise SystemExit(main())
