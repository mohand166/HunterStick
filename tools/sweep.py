#!/usr/bin/env python3
"""Run one n-day check across a tech cohort — pilot first, always.

    # 1. select (no traffic)
    tools/kb.py cohort targets/acme --tech "Ruby on Rails" --version-lt 7.0.5 --out /tmp/c.txt

    # 2. pilot — ONE host, full output shown
    tools/sweep.py targets/acme --cohort /tmp/c.txt --rate 20 \
        --header 'X-Bug-Bounty: handle' --nuclei CVE-2024-XXXXX

    # 3. scale — only after you have read the pilot
    tools/sweep.py targets/acme --cohort /tmp/c.txt --rate 20 \
        --header 'X-Bug-Bounty: handle' --nuclei CVE-2024-XXXXX --scale --yes

A public n-day drops and you want to know which of your cohort is affected. That is legitimate
and standard. It is also the single easiest way in this workspace to send thousands of attack
requests at a target by accident, so the shape is fixed:

    select by fingerprint  →  PILOT one host  →  human reads it  →  scale  →  confirm individually

Non-negotiable, enforced here rather than trusted to memory:

* **Pilot is not optional.** Without `--scale` it runs against exactly one host and prints
  everything. `--scale` additionally requires `--yes`.
* **Rate limit and headers are required.** No `--rate`, no run. The header the program mandates
  travels on every request.
* **Hits are HYPOTHESES.** They land in `hypotheses.md`, never in `tested.md` and never in
  `findings/`. A scanner match is a reason to go look, not a finding — the confirmation is a
  separate, manual, one-host job with a stored artifact.
* **Obvious destructive checks are refused — but a blacklist is a backstop, not a guarantee.**
  `rm`, reverse shells, fork bombs, pipes to a shell, destructive SQL and state-changing HTTP verbs
  are rejected outright. That list cannot be complete: `--curl` takes an arbitrary shell command,
  and no pattern set can prove an arbitrary command is safe. **Making the check non-destructive is
  yours**; this refuses the shapes that are unambiguously wrong, and multiplying any mistake by the
  cohort size is why it refuses loudly rather than warning.
* **Cohort provenance is printed.** If the cohort came from banners rather than behaviour, a
  clean sweep proves less than it looks like it does.

Runs on the VPS (that is where the tools and the authorized egress IP are).

Exit: 0 ran · 1 refused, needs a flag · 2 failed.
"""
import argparse
import re
import shlex
import subprocess
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runlog   # noqa: E402
from scopelib import in_scope, require_scope   # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

DESTRUCTIVE = [
    (re.compile(r"\brm\s+-[rf]", re.I),                "file deletion"),
    (re.compile(r"\bmkfs\b|\bdd\s+if=", re.I),         "disk write"),
    (re.compile(r">\s*/dev/(sd|nvme|disk)", re.I),     "raw device write"),
    (re.compile(r"\b(shutdown|reboot|halt|poweroff)\b", re.I), "host control"),
    (re.compile(r":\(\)\s*\{.*\};\s*:", re.S),         "fork bomb"),
    (re.compile(r"\b(nc|ncat|netcat)\b.*\s-e\b", re.I), "reverse shell"),
    (re.compile(r"bash\s+-i\s*>&", re.I),              "reverse shell"),
    (re.compile(r"\|\s*(sh|bash|zsh)\b", re.I),        "pipe to shell"),
    (re.compile(r"\bDROP\s+(TABLE|DATABASE)\b", re.I), "destructive SQL"),
    (re.compile(r"\b(DELETE|TRUNCATE)\s+FROM\b", re.I), "destructive SQL"),
    (re.compile(r"\bcurl\b.*\|\s*\w+", re.I),          "download-and-execute"),
    # state-changing HTTP verbs: a sweep is a DETECTION pass across many hosts, so a request
    # that mutates is wrong N times over even when nothing on the box is harmed.
    (re.compile(r"-X\s*['\"]?(DELETE|PUT|PATCH)\b", re.I), "state-changing HTTP method"),
    (re.compile(r"--request\s+['\"]?(DELETE|PUT|PATCH)\b", re.I), "state-changing HTTP method"),
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


def ssh_prefix():
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "config.py"), "ssh"],
                       capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        die("no VPS configured (tools/config.py ssh). A sweep runs remotely, not from your IP.")
    return shlex.split(r.stdout.strip())


def remote(cmd, stdin=None, check=False):
    return subprocess.run(ssh_prefix() + [cmd], capture_output=True, text=True, input=stdin,
                          check=check)


def target_of(arg):
    p = Path(arg).resolve()
    if not p.is_dir() or not (p / "index.md").exists():
        die(f"{arg} is not a target brain (no index.md)")
    return p


def check_destructive(text):
    return [why for rx, why in DESTRUCTIVE if rx.search(text)]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target")
    ap.add_argument("--cohort", required=True, help="host list from `kb.py cohort --out`")
    ap.add_argument("--rate", type=int, required=True, metavar="RPS",
                    help="the program's limit; every request is paced under it")
    ap.add_argument("--header", action="append", metavar="H", help="sent on every request; repeatable")
    ap.add_argument("--nuclei", metavar="ID_OR_PATH", help="nuclei template id or file")
    ap.add_argument("--curl", metavar="ONELINER",
                    help="a check to run per host; {host} and {url} are substituted")
    ap.add_argument("--scale", action="store_true", help="run the whole cohort (pilot is default)")
    ap.add_argument("--yes", action="store_true", help="required together with --scale")
    ap.add_argument("--note", default="", help="what this is checking, for hypotheses.md")
    args = ap.parse_args()

    tdir = target_of(args.target)
    if bool(args.nuclei) == bool(args.curl):
        die("give exactly one of --nuclei or --curl")
    if args.rate < 1:
        die("--rate must be at least 1")

    cf = Path(args.cohort)
    if not cf.exists():
        die(f"no cohort file at {args.cohort} — build one with `kb.py cohort … --out`")
    hosts = [h.strip() for h in cf.read_text(encoding="utf-8-sig").splitlines()
             if h.strip() and not h.startswith("#")]
    if not hosts:
        die("cohort file is empty. An empty sweep is not a clean sweep.")

    # ---- destructive check --------------------------------------------------
    payload = args.curl or args.nuclei
    bad = check_destructive(payload)
    if bad:
        print(f"FAIL — refusing this check: {', '.join(sorted(set(bad)))}", file=sys.stderr)
        print("       Non-destructive is absolute, and a cohort sweep multiplies it by "
              f"{len(hosts)}.", file=sys.stderr)
        print("       Use a detection-only discriminator (version, behaviour, out-of-band "
              "callback).", file=sys.stderr)
        return 2

    # ---- scope --------------------------------------------------------------
    scope = require_scope(tdir, die)
    off = [h for h in hosts if not in_scope(h, scope)]
    if off:
        print(f"FAIL — {len(off)} cohort host(s) are not in scope: {', '.join(off[:5])}"
              f"{' …' if len(off) > 5 else ''}", file=sys.stderr)
        print("       The cohort was built from your own data, so this means the ledger holds "
              "a host\n       that scope.md does not. Reconcile before sending anything.",
              file=sys.stderr)
        return 2

    hdrs = args.header or []
    print(f"\n# sweep — {tdir.name}")
    print(f"  cohort      {len(hosts)} host(s) from {cf.name}")
    print(f"  check       {'nuclei ' + args.nuclei if args.nuclei else 'curl one-liner'}")
    print(f"  rate        {args.rate} req/s")
    print(f"  headers     {len(hdrs)}" + ("" if hdrs else "   ⚠ none — is one mandated?"))
    print(f"  mode        {'FULL COHORT' if args.scale else 'PILOT (1 host)'}")
    if not hdrs:
        print("\n  ⚠ No --header. If the program mandates attribution, every request below is "
              "non-compliant.")

    if args.scale and not args.yes:
        print(f"\n  --scale needs --yes. That is {len(hosts)} hosts × this check.")
        print("  Read the pilot output first; a check that is wrong is wrong "
              f"{len(hosts)} times.")
        return 1

    run_hosts = hosts if args.scale else hosts[:1]
    if not args.scale:
        print(f"\n  piloting on {run_hosts[0]} — full output below, nothing else is touched.")

    stamp = date.today().isoformat()
    rdir = f"$HOME/targets/{tdir.name}/raw/sweeps"
    tag = re.sub(r"[^A-Za-z0-9._-]", "_", (args.nuclei or "curl"))[:40]
    out_remote = f"{rdir}/{stamp}-{tag}{'' if args.scale else '-pilot'}.txt"

    remote(f"mkdir -p {rdir}")
    remote(f"cat > {rdir}/.cohort-{tag}.txt", stdin="\n".join(run_hosts) + "\n")

    hflag = " ".join(f"-H {shlex.quote(h)}" for h in hdrs)
    if args.nuclei:
        tpl = f"-t {shlex.quote(args.nuclei)}" if "/" in args.nuclei or args.nuclei.endswith(".yaml") \
            else f"-id {shlex.quote(args.nuclei)}"
        cmd = (f"set -o pipefail; nuclei -l {rdir}/.cohort-{tag}.txt {tpl} -rl {args.rate} "
               f"{hflag} -silent -no-color 2>&1 | tee {out_remote}; "
               f"echo __SWEEP_RC=${{PIPESTATUS[0]}}")
    else:
        curl_hdrs = " ".join(f"-H {shlex.quote(h)}" for h in hdrs)
        one = args.curl.replace("{host}", '"$h"').replace("{url}", '"https://$h"')
        delay = max(1, args.rate) and (1.0 / args.rate)
        cmd = (f"set -uo pipefail; rc=0; while read -r h; do "
               f"printf '=== %s\\n' \"$h\"; "
               f"{one.replace('curl ', f'curl {curl_hdrs} --max-time 15 ', 1)} || rc=$?; "
               f"sleep {delay:.3f}; "
               f"done < {rdir}/.cohort-{tag}.txt 2>&1 | tee {out_remote}; "
               f"echo __SWEEP_RC=$rc")

    # A missing binary must be a FAILURE, not an empty hit list that reads as "clean".
    need = "nuclei" if args.nuclei else "curl"
    if remote(f"command -v {need} >/dev/null && echo yes || echo no").stdout.strip() != "yes":
        die(f"{need} is not on the VPS PATH. Without this check the sweep would report "
            f"'no hits'\n       across {len(hosts)} host(s) and that would be a lie.")

    print(f"\n  running on the VPS …\n")
    r = remote(cmd)
    body = (r.stdout or "").rstrip()

    # `tee` at the end of the pipeline masks a non-zero scanner exit, so the pipeline carries
    # its own status out explicitly. Anything but 0 means the output cannot be read as results.
    m = re.search(r"__SWEEP_RC=(\d+)", body)
    rc = int(m.group(1)) if m else None
    body = re.sub(r"\n?__SWEEP_RC=\d+", "", body)
    if rc is None or rc != 0:
        print(body if body else "  (no output)")
        print(f"\nFAIL — the check exited {rc if rc is not None else 'unknown'} on the VPS. "
              f"Its output is NOT a result set.", file=sys.stderr)
        print("       Nothing was written to hypotheses.md. Fix the check, then re-run the pilot.",
              file=sys.stderr)
        return 2
    print(body if body else "  (no output)")
    if r.stderr.strip():
        print(f"\n  stderr: {r.stderr.strip()[:800]}")

    hits = [l for l in body.splitlines()
            if l.strip() and not l.startswith("===") and "no results" not in l.lower()]
    print(f"\n  raw output kept at {out_remote}")

    if not args.scale:
        print("\n  PILOT ONLY. Read the output above and decide:")
        print("    - did the check actually discriminate, or would it match anything?")
        print("    - is a hit here real, or the app's normal behaviour?")
        print(f"  Then re-run with --scale --yes for the remaining {len(hosts) - 1} host(s).")
        return 0

    if hits:
        hyp = tdir / "hypotheses.md"
        with hyp.open("a", encoding="utf-8") as fh:
            fh.write(f"\n## Sweep {stamp} — {args.nuclei or 'curl check'}"
                     f"{' — ' + args.note if args.note else ''}\n\n")
            fh.write(f"> {len(hits)} hit(s) across {len(run_hosts)} host(s). **HYPOTHESES.** A "
                     f"scanner match is\n> a reason to look, not a finding. Confirm one host at a "
                     f"time with a stored artifact\n> before anything reaches `tested.md`.\n>\n"
                     f"> Raw: VPS `{out_remote}`\n\n")
            for h in hits[:200]:
                fh.write(f"- {h.strip()}\n")
        print(f"\n  {len(hits)} hit(s) -> {rel(hyp)} as HYPOTHESES")
        print("  Nothing was written to tested.md or findings/. Confirm individually.")
    else:
        print(f"\n  no hits across {len(run_hosts)} host(s).")
        print("  That is only as strong as the cohort: if it was built from banners rather than\n"
              "  observed behaviour, a clean sweep has not cleared the hosts whose banner lied.")
    return 0


if __name__ == "__main__":
    sys.exit(runlog.wrap()(main)())
