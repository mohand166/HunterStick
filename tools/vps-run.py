#!/usr/bin/env python3
"""Local pre-dispatch layer for VPS commands: inspect for identity, inject attribution, dispatch.

    tools/vps-run.py targets/acme --skill http-probing --expect-file raw/probe.json \
        -- httpx -l recon/live-hosts.txt -json -o raw/probe.json

Why this exists
---------------
`run.py` is the recorder, and it runs ON the VPS. But the VPS has no `config.json`, so run.py's
privacy backstop is inert exactly where traffic egresses — it cannot know the researcher's identity
to refuse it. This wrapper closes that gap by doing the privacy work HERE, locally, where config
lives, *before* the command is ever dispatched:

  1. **Refuse** the researcher's PRIVATE identity (email, aliases) anywhere in the command.
  2. **Refuse** the PUBLIC attribution value placed anywhere but its designated header.
  3. **Inject** the attribution header for known HTTP tools, so you never type it (and never
     misplace it). `--no-inject` opts out; a tool that already carries the header is left alone.
  4. **Reject known-bad command contracts** before SSH, then dispatch `run.py` on the VPS. The
     remote runner verifies fresh artifacts and structured output before reporting success.

So the guarantee holds where it matters: the check fires local-side, on every command, with the
config it needs — not on the VPS where it would see nothing. The always-loaded rule remains the
primary control; this is the mechanical net beneath it, now actually active.

`--print` shows the exact remote command without sending it — a dry run you can read.
`--detach <session>` starts that same direct runner command inside VPS tmux for long work; it does
not wrap the scanner in an opaque job script, so privacy and output contracts remain active.

Exit: passes through run.py's code (0 ok · 1 output contract failed · 2 refused / could not run).
"""
import argparse
import re
import shlex
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run as _run                                                # noqa: E402  (reuse its helpers)

# The HTTP-tool registry lives once, in run.py (which also uses it for the direct-bypass gate).
# Injection maps each tool to the flag it takes a request header on.
HTTP_INJECT = _run.ATTRIBUTION_TOOLS
TARGET_HTTP_TOOLS = _run.TARGET_HTTP_TOOLS


def die(msg, code=2):
    print(f"FAIL — {msg}", file=sys.stderr)
    raise SystemExit(code)


def _cfg():
    try:
        import config as c                                        # noqa: E402
    except Exception as e:                                        # pragma: no cover
        die(f"cannot import config: {e}")
    if not c.CONFIG.exists() and not c.EXAMPLE.exists():
        die("no config.json — this wrapper needs local config to inspect identity and reach the VPS")
    return c, c.load()


def already_has_attribution(argv, header_name):
    """True if the command already carries a STRUCTURALLY REAL attribution header, so we do not
    duplicate it. Decided by argument structure (`-H "Name: v"` / `--header=Name: v`), not by any
    string that merely looks header-shaped — a `-d 'X-Bug-Bounty: …'` body must not suppress a real
    injection."""
    return bool(_run.attribution_header_indices(argv, header_name))


def inject_attribution(argv, header_name, header_value):
    """Append the attribution header for a known HTTP tool. Returns (new_argv, injected?)."""
    if not (header_name and header_value) or not argv:
        return argv, False
    flag = HTTP_INJECT.get(Path(argv[0]).name.lower())
    if not flag or already_has_attribution(argv, header_name):
        return argv, False
    return argv + [flag, f"{header_name}: {header_value}"], True


def remote_target(flat, local_target):
    """Map a local target dir to its path on the VPS: <vps.workdir>/<basename>."""
    workdir = flat.get("vps.workdir") or "~/targets"
    return f"{str(workdir).rstrip('/')}/{Path(local_target).resolve().name}"


def build_remote_command(flat, args, argv):
    """The exact `run.py ... -- <cmd>` to run on the VPS, for a remote shell.

    The two config-controlled paths — the run.py location and the target dir — are left UNQUOTED so
    the remote shell expands a leading `~` (single-quoting it, as `shlex.quote` would, makes the
    tilde literal and run.py is never found — the same trap `vps.sh` documents). They are slugs /
    fixed config paths, so they carry no spaces or metacharacters. EVERYTHING else — the skill,
    run-id, expect-file, and every token of the user command — is `shlex.quote`d, because those can
    contain anything.
    """
    codedir = str(flat.get("vps.codedir") or "~/hunterstick").rstrip("/")
    rt = remote_target(flat, args.target)
    # Set the gate marker so the VPS-side run.py knows this command passed the LOCAL identity check.
    # A direct `run.py -- curl …` (no marker) is refused there; only this path sets it.
    cmd = f"{_run.GATE_ENV}=1 python3 {codedir}/tools/run.py {rt} --skill {shlex.quote(args.skill)}"
    if args.run_id:
        cmd += f" --run-id {shlex.quote(args.run_id)}"
    if args.expect_file:
        cmd += f" --expect-file {shlex.quote(args.expect_file)}"
    if getattr(args, "stdout_file", None):
        cmd += f" --stdout-file {shlex.quote(args.stdout_file)}"
    if getattr(args, "expect_format", None):
        cmd += f" --expect-format {shlex.quote(args.expect_format)}"
    if getattr(args, "expect_fields", None):
        cmd += f" --expect-fields {shlex.quote(args.expect_fields)}"
    if args.timeout:
        cmd += f" --timeout {int(args.timeout)}"
    cmd += " -- " + " ".join(shlex.quote(a) for a in argv)
    return cmd


def detached_remote_command(session, remote_command):
    """Wrap the already-gated runner command in tmux without hiding its scanner argv."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", session):
        die("--detach session must be 1–64 letters, digits, underscores or hyphens")
    return f"tmux new-session -d -s {shlex.quote(session)} {shlex.quote(remote_command)}"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target")
    ap.add_argument("--skill", "--phase", dest="skill", required=True)
    ap.add_argument("--run-id")
    ap.add_argument("--expect-file", metavar="PATH")
    ap.add_argument("--stdout-file", metavar="PATH",
                    help="save the command's captured stdout as this validated artifact")
    ap.add_argument("--expect-format", choices=("json", "jsonl"))
    ap.add_argument("--expect-fields", metavar="A,B,...",
                    help="fields every JSON/JSONL record must contain")
    ap.add_argument("--timeout", type=int)
    ap.add_argument("--no-inject", action="store_true",
                    help="do not auto-add the attribution header (you are adding it yourself)")
    ap.add_argument("--detach", metavar="SESSION",
                    help="start the direct runner command in a named VPS tmux session")
    ap.add_argument("--print", dest="print_only", action="store_true",
                    help="print the remote command that WOULD run, and stop — no SSH")

    argv_all = sys.argv[1:]
    if not argv_all or argv_all[0] in ("-h", "--help"):
        ap.print_help()
        return 0
    if "--" not in argv_all:
        die("give the command after `--`, e.g. ... --skill http-probing -- httpx -l hosts.txt")
    cut = argv_all.index("--")
    args = ap.parse_args(argv_all[:cut])
    argv = argv_all[cut + 1:]
    if not argv:
        die("nothing after `--`")

    bad_invocation = _run.invocation_errors(argv)
    if bad_invocation:
        die("known-bad command contract:\n       " + "\n       ".join(bad_invocation))

    c, flat = _cfg()

    # --- the privacy gate, local, before dispatch -----------------------------------------------
    private = _run.private_values()
    hits = _run.identity_in_argv(argv, private)
    if hits:
        die("this command carries your OWN private identity — category: " + ", ".join(hits)
            + ".\n       Private identity is never payload. Use the target account's profile or a "
              "synthetic value; there is no override.")
    attr_name, attr_val = _run.attribution_header()
    if _run.attribution_misplaced(argv, attr_name, _run.attribution_values()):
        die(f"your PUBLIC attribution identity (handle / header value) appears outside its one home, "
            f"the '{attr_name}' header. It is not application data — let this wrapper inject it, or "
            f"put it in -H \"{attr_name}: <value>\" and nowhere else.")

    # --- inject attribution for known HTTP tools ------------------------------------------------
    injected = False
    if not args.no_inject:
        argv, injected = inject_attribution(argv, attr_name, attr_val)
    tool_name = Path(argv[0]).name.lower()
    if attr_name and attr_val and tool_name in TARGET_HTTP_TOOLS and not injected \
            and not already_has_attribution(argv, attr_name) and not args.no_inject:
        print(f"  warning: {tool_name} sends target traffic, but its installed CLI has no "
              f"verified inline-header adapter; attribution was not auto-injected. Verify its "
              f"header syntax before running if the program requires '{attr_name}'.",
              file=sys.stderr)

    remote_cmd = build_remote_command(flat, args, argv)
    if args.detach:
        remote_cmd = detached_remote_command(args.detach, remote_cmd)

    if args.print_only:
        print(remote_cmd)
        if injected:
            print(f"# (attribution header '{attr_name}' injected for {Path(argv[0]).name})",
                  file=sys.stderr)
        return 0

    # --- dispatch to the VPS --------------------------------------------------------------------
    # Enablement gates DISPATCH, not the --print dry run above: previewing the composed command
    # needs no VPS (and no config.json, as CI has none), but actually sending it does.
    if not flat.get("vps.enabled"):
        die("vps.enabled is false — this wrapper dispatches to the VPS. Enable it in config.json.")
    ssh = subprocess.run([sys.executable, str(HERE / "config.py"), "ssh"],
                         capture_output=True, text=True)
    if ssh.returncode != 0:
        die("no usable VPS ssh in config.json:\n       " + ssh.stderr.strip())
    prefix = shlex.split(ssh.stdout.strip())
    if injected:
        print(f"  attribution '{attr_name}' injected for {Path(argv[0]).name}", file=sys.stderr)
    proc = subprocess.run(prefix + [remote_cmd])
    if args.detach and proc.returncode == 0:
        print(f"  detached in VPS tmux session '{args.detach}'; inspect with "
              f"tmux capture-pane -pt {args.detach}")
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
