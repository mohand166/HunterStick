#!/usr/bin/env python3
"""Enforce the local/VPS split for one target, and move files across it.

    tools/vps-sync.py status <target-dir>          # what is where, and what breaks the rule
    tools/vps-sync.py pull   <target-dir>          # bring curated extracts DOWN
    tools/vps-sync.py push   <target-dir>          # send jobs/ UP
    tools/vps-sync.py demote <target-dir> <file>   # oversized local list -> VPS-only + pointer

THE RULE (playbooks/system/target-schema.md):

    Local holds what you need to decide WHAT TO DO NEXT.
    The VPS holds what you need to RE-DERIVE it.

    Test for any ambiguous file: if the VPS died tonight, could you still reason about
    this target tomorrow? The VPS is disposable infrastructure. The brain is not.

So:
  * `*.md` extracts and the target-root state files are ALWAYS local — prioritization,
    coverage.py and every reader of the brain need them, and they must survive the VPS.
  * `*.txt` lists are local only while they are small enough that you would actually
    read one. Above the threshold they live on the VPS and the local side keeps a
    count plus a pointer. A 52 MB urls.txt is not a brain, it is a re-derivable artifact.
  * raw/ is NEVER local. jobs/ and logs/ are NEVER local.

Nothing here deletes remote data. `demote` is the only command that removes a local file,
it verifies the remote copy byte-for-byte first, and it refuses without --yes.

Exit: 0 clean · 1 the rule is violated (status) or work remains · 2 cannot answer.
"""
import argparse
import hashlib
import os
import shlex
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runlog   # noqa: E402
ROOT = Path(__file__).resolve().parent.parent
CONFIG_TOOL = ROOT / "tools" / "config.py"

# A .txt list bigger than this is not something you read — it is an artifact.
DEFAULT_MAX_LIST_BYTES = 256 * 1024

ALWAYS_LOCAL_SUFFIX = (".md",)
# Below this, a logs/ directory is unremarkable. Above it, look at the SHAPE of the logs:
# the usual cause is a tool's stdout being tee'd alongside its own -o artifact.
LOG_BLOAT_BYTES = 5 * 1024 * 1024

NEVER_LOCAL_DIRS = ("jobs", "loot")
# `logs/` means two different things and the rule conflated them: on the VPS it is job output
# (`tee`d tmux logs, bulk), locally it is the evidence trail — `tools.tsv` and `exec/*.json`, which
# exist precisely so a failure outlives the session. Those are local by design and the template
# ships one. Only the bulk job logs are VPS-side.
LOCAL_LOG_OK = ("logs/tools.tsv",)
LOCAL_LOG_DIRS = ("logs/exec",)

# The size rule alone answers "is this too big", never "is this worth having". These are
# ENUMERATION OUTPUT: raw, superseded by a downstream file, and not something anyone reasons over.
# Nobody reads 40,000 subdomains — they read the live-host count and the technology table. Keeping
# the dump locally costs disk and attention and buys a number you already have.
BULK_LISTS = {
    "recon/subdomains.txt":  "recon/live-hosts.txt is the working set — this is its raw input",
    "recon/urls.txt":        "recon/endpoints.md is the curated slice; recon/paths.txt the replay list",
    "recon/parameters.txt":  "the parameters that mattered belong in recon/endpoints.md",
    "recon/resolved.txt":    "superseded by live-hosts.txt",
}
# Below this a bulk list is small enough to be worth keeping whole — a 30-line subdomain list IS
# the working set. The rule is about volume, not about the filename.
BULK_KEEP_LINES = 500


def die(msg, code=2):
    print(f"FAIL — {msg}", file=sys.stderr)
    raise SystemExit(code)


def ssh_prefix():
    r = subprocess.run([sys.executable, str(CONFIG_TOOL), "ssh"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        die("no usable VPS in config.json.\n       " + r.stderr.strip().replace("\n", "\n       "))
    return shlex.split(r.stdout.strip())


def remote(cmd, check=True):
    r = subprocess.run(ssh_prefix() + [cmd], capture_output=True, text=True)
    if check and r.returncode != 0:
        die(f"remote command failed: {cmd}\n       {r.stderr.strip()}")
    return r.stdout


def remote_result(cmd):
    """The full CompletedProcess, so a caller can tell a TRANSPORT failure from a command result.

    `status` and `verify-runner` must distinguish VPS-unreachable, auth-rejected and
    remote-absent. All three used to collapse to empty stdout and read as 'directory missing' —
    the confident-zero this workspace exists to prevent. Every command these callers send is
    wrapped to exit 0 on connect, so a non-zero code here is always the transport, never the job.
    """
    return subprocess.run(ssh_prefix() + [cmd], capture_output=True, text=True)


def ssh_transport_error(r):
    """None if SSH connected (the remote command ran, whatever it printed); else a human reason.

    ssh uses 255 for its own failures. Because our probe commands always end in a zero-exit
    statement, a non-zero return here means the connection itself never carried the command.
    """
    if r.returncode == 0:
        return None
    err = (r.stderr or "").lower()
    if any(s in err for s in ("permission denied", "publickey", "authentication failure",
                              "password", "too many authentication")):
        return "AUTH FAILED — the VPS answered but rejected the key/credentials in config.json"
    if any(s in err for s in ("connection refused", "timed out", "timeout", "no route",
                              "could not resolve", "name or service not known",
                              "network is unreachable", "operation timed out",
                              "connection closed", "host key verification")):
        last = (r.stderr or "").strip().splitlines()
        return ("UNREACHABLE — could not open an SSH connection to the VPS"
                + (f" ({last[-1].strip()})" if last else ""))
    last = (r.stderr or "").strip().splitlines()
    return (f"SSH FAILED (exit {r.returncode}) — "
            + (last[-1].strip() if last else "no stderr; check config.json vps.*"))


def rsync_env():
    """(host, rsh-string) derived from the same ssh invocation config uses — for redeploy hints
    and the evidence pull."""
    pre = ssh_prefix()
    port = pre[pre.index("-p") + 1] if "-p" in pre else "22"
    key = pre[pre.index("-i") + 1] if "-i" in pre else None
    host = pre[-1]
    return host, f"ssh -p {port}" + (f" -i {key}" if key else "")


CODEDIR_DEFAULT = "~/hunterstick"


def codedir():
    """Where the HunterStick checkout (tools/, playbooks/) is deployed on the VPS — distinct from
    the per-target workdir. `run.py` lives under here, not under targets/."""
    r = subprocess.run([sys.executable, str(CONFIG_TOOL), "get", "vps.codedir"],
                       capture_output=True, text=True)
    return (r.stdout.strip() or CODEDIR_DEFAULT) if r.returncode == 0 else CODEDIR_DEFAULT


def workdir():
    r = subprocess.run([sys.executable, str(CONFIG_TOOL), "get", "vps.workdir"],
                       capture_output=True, text=True)
    return (r.stdout.strip() or "~/targets") if r.returncode == 0 else "~/targets"


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for c in iter(lambda: fh.read(65536), b""):
            h.update(c)
    return h.hexdigest()


def human(n):
    for u in ("B", "K", "M", "G"):
        if n < 1024 or u == "G":
            return f"{n:.0f}{u}" if u == "B" else f"{n/1:.0f}{u}" if False else f"{n:,.0f}{u}"
        n /= 1024
    return str(n)


def size_str(n):
    for u, d in (("G", 1 << 30), ("M", 1 << 20), ("K", 1 << 10)):
        if n >= d:
            return f"{n/d:.1f}{u}"
    return f"{n}B"



def need_rsync():
    from shutil import which
    if not which("rsync"):
        die("rsync not found on this machine. Install it (brew install rsync) or copy files\n"
            "       manually — this tool will not silently fall back to something lossier.")

def local_target(arg):
    p = Path(arg).resolve()
    if not p.is_dir():
        die(f"{arg} is not a directory")
    if not (p / "index.md").exists():
        die(f"{arg} has no index.md — is it a target brain?")
    return p


def noisy_logs(probe_output):
    """[(name, total_lines, record_lines)] for logs that are mostly serialised records.

    Pure so the decision is testable without a VPS. The threshold is "over half", not a tuned
    number: a log where most lines are JSON/array records is not a log with some data in it, it is
    a dataset with some log around it.
    """
    out = []
    for line in (probe_output or "").splitlines():
        parts = line.split(None, 2)
        if len(parts) != 3 or not parts[0].isdigit() or not parts[1].isdigit():
            continue
        total, records = int(parts[0]), int(parts[1])
        if total and records and records * 2 > total:
            out.append((Path(parts[2]).name, total, records))
    return out


def cmd_status(args):
    t = local_target(args.target)
    rt = f"{workdir()}/{t.name}"
    print(f"# {t.name}   local: {t}\n#            vps:   {rt}")

    # ---- remote inventory (one round trip) ----
    # The trailing `printf DONE` guarantees exit 0 on connect, so a non-zero return is always the
    # transport failing — not an absent directory. Collapsing those two was the fail-loud
    # violation: a network-restricted runtime reported "no remote directory" for a directory that
    # provably existed, because status discarded stderr and read empty stdout as 'missing'.
    r = remote_result(f"if [ -d {rt} ]; then du -sb {rt}/* 2>/dev/null; else printf MISSING; "
                       f"fi; printf '\\nDONE\\n'")
    terr = ssh_transport_error(r)
    if terr:
        die(f"{terr}\n       Could not reach the VPS to check {rt}. This is NOT 'nothing has "
            f"run' — the connection failed. Check `tools/config.py check` and the vps.* keys.")
    out = r.stdout
    if "MISSING" in out:
        print(f"\n  ⚠ VPS reachable, but no directory at {rt} — nothing has run on the VPS for\n"
              f"    this target yet, or vps.workdir is wrong. (Connection is fine.)")
        remote_sizes = {}
    else:
        remote_sizes = {}
        for line in out.splitlines():
            if line.strip() == "DONE":
                continue
            parts = line.split("\t")
            if len(parts) == 2 and parts[0].isdigit():
                remote_sizes[Path(parts[1]).name] = int(parts[0])

    print("\n  ON THE VPS")
    if remote_sizes:
        for k, v in sorted(remote_sizes.items(), key=lambda x: -x[1]):
            tag = "  (VPS-side by rule)" if k in NEVER_LOCAL_DIRS else ""
            print(f"    {size_str(v):>7}  {k}/{tag}")
    else:
        print("    (nothing)")

    # ---- logs that swallowed their own dataset ----------------------------
    # `-o <file>` on most projectdiscovery tools writes the file AND prints every record, so the
    # standard `… | tee $T/logs/<name>.log` wrapper copies the whole dataset into the log. Seen
    # for real: a 10.8 MB phase log holding 35,426 duplicated JSON records around 3,991 lines of
    # actual log, while every other phase log was 1-2 KB.
    #
    # Detected by SHAPE, not by size alone: a big log is fine, a log that is mostly serialised
    # records is a redirect that was never written. Nothing is deleted here — the job may still
    # be running — it is named so it stops being invisible.
    if remote_sizes.get("logs", 0) > LOG_BLOAT_BYTES:
        probe = remote(
            f"for f in {rt}/logs/*; do [ -f \"$f\" ] || continue; "
            f"tot=$(wc -l < \"$f\"); [ \"$tot\" -lt 500 ] && continue; "
            f"rec=$(grep -c '^[{{[]' \"$f\" 2>/dev/null || echo 0); "
            f"echo \"$tot $rec $f\"; done", check=False)
        noisy = noisy_logs(probe)
        if noisy:
            print("\n  ⚠ LOG(S) CONTAINING THEIR OWN DATASET")
            for name, tot, rec in noisy:
                print(f"    {name}: {tot:,} lines, {rec:,} are records ({rec * 100 // tot}%)")
            print("    A tool's `-o <file>` does not replace stdout. Send stdout to /dev/null when")
            print("    `-o` already captures it — the log is for what happened, not what was found.")

    # ---- local inventory + rule check ----
    print("\n  LOCAL")
    violations, ok = [], 0
    for p in sorted(t.rglob("*")):
        if p.is_dir() or p.name.startswith("."):
            continue
        rel = p.relative_to(t)
        key = rel.as_posix()
        if rel.parts[0] in NEVER_LOCAL_DIRS:
            violations.append((rel, p.stat().st_size, f"{rel.parts[0]}/ belongs on the VPS only"))
            continue
        if rel.parts[0] == "logs":
            if key in LOCAL_LOG_OK or any(key.startswith(d) for d in LOCAL_LOG_DIRS):
                ok += 1                       # the evidence trail — local on purpose
            else:
                violations.append((rel, p.stat().st_size,
                                   "job output belongs on the VPS; only tools.tsv and exec/ "
                                   "records are local"))
            continue
        n = p.stat().st_size
        if p.suffix in ALWAYS_LOCAL_SUFFIX:
            ok += 1
            continue
        if key in BULK_LISTS:
            try:
                lines = sum(1 for _ in p.open("rb"))
            except OSError:
                lines = 0
            if lines > BULK_KEEP_LINES:
                violations.append((rel, n, f"{lines:,} lines of enumeration output — "
                                           f"{BULK_LISTS[key]}"))
                continue
            ok += 1
            continue
        if p.suffix == ".txt" and n > args.max_list:
            violations.append((rel, n, f"list > {size_str(args.max_list)} — keep count+pointer locally"))
        else:
            ok += 1
    print(f"    {ok} file(s) within the rule")
    if violations:
        print(f"\n  ✗ {len(violations)} FILE(S) BREAK THE SPLIT RULE")
        for rel, n, why in sorted(violations, key=lambda x: -x[1]):
            print(f"    {size_str(n):>7}  {rel}")
            print(f"             {why}")
        print(f"\n    Fix:  tools/vps-sync.py demote {args.target} <file> --yes")
        print(f"    (verifies the remote copy matches byte-for-byte, then replaces the local\n"
              f"     file with a pointer. It never deletes anything on the VPS.)")
    else:
        print("\n  ✓ split rule satisfied — nothing oversized or misplaced locally")
    return 1 if violations else 0


def _pull_evidence(t, rt, host, rsh, dry_run):
    """Bring run.py's execution records home. They are the ONE thing under logs/ that is local by
    rule (target-schema.md): the VPS writes logs/exec/*.json, and if we never pull them the proof
    of what ran dies with the disposable box. Small JSON — always worth retrieving."""
    # Fail loud on a transport failure: an unreachable VPS must not read as "no evidence" — that is
    # the confident-zero this workspace forbids. Distinguish the connection dying from the dir being
    # absent, exactly as `status` does.
    r = remote_result(f"[ -d {rt}/logs/exec ] && printf yes || printf no; printf '\\nDONE\\n'")
    terr = ssh_transport_error(r)
    if terr:
        die(f"{terr}\n       Could not reach the VPS to pull evidence for {rt}. This is NOT "
            f"'no records' — the connection failed.")
    if "yes" not in r.stdout:
        print("  evidence records: none on the VPS yet (logs/exec/ absent).")
        return 0
    (t / "logs" / "exec").mkdir(parents=True, exist_ok=True)
    ecmd = ["rsync", "-az", "-v", "-e", rsh, "--include=*.json", "--exclude=*",
            f"{host}:{rt}/logs/exec/", str(t / "logs" / "exec") + "/"]
    if dry_run:
        ecmd.insert(1, "--dry-run")
    er = subprocess.run(ecmd, capture_output=True, text=True)
    if er.returncode != 0:
        die(f"evidence pull failed:\n       {er.stderr.strip()}", 2)
    recs = [l for l in er.stdout.splitlines() if l.strip().endswith(".json")]
    print(f"  evidence records: {'pulled ' + str(len(recs)) if recs else 'none new'} "
          f"-> logs/exec/  (run.py's proof of what executed)")
    if not dry_run:
        try:
            sys.path.insert(0, str(ROOT / "tools"))
            import progress
            (t / "progress.md").write_text(progress.render(t), encoding="utf-8")
            print("  progress view: regenerated -> progress.md")
        except Exception as exc:                               # noqa: BLE001 - pull still succeeded
            print(f"  warning: progress.md was not regenerated ({type(exc).__name__}: {exc}); "
                  f"run tools/progress.py {t}")
    return 0


def cmd_pull(args):
    """Bring down exactly what the rule says belongs local: curated *.md, plus *.txt
    lists small enough to reason over. Oversized lists are named and left on the VPS —
    silently skipping them would be the same lie as silently copying them."""
    need_rsync()
    t = local_target(args.target)
    rt = f"{workdir()}/{t.name}"
    # Fail loud on a dead connection — "no recon" must mean the dir is absent, not that SSH failed.
    rr = remote_result(f"[ -d {rt}/recon ] && printf yes || printf no; printf '\\nDONE\\n'")
    rterr = ssh_transport_error(rr)
    if rterr:
        die(f"{rterr}\n       Could not reach the VPS to pull {rt}. This is NOT 'nothing to "
            f"pull' — the connection failed. Check `tools/config.py check` and the vps.* keys.")
    have_recon = "yes" in rr.stdout
    if not have_recon:
        # Evidence records live under logs/exec/, not recon/. A target that has run commands but
        # produced no recon extract still has evidence to bring home — bailing here would strand
        # it on the VPS, the exact durability hole this path exists to close. Skip the recon pull,
        # fall through to the evidence pull.
        print(f"  no remote {rt}/recon — skipping recon extract; still checking for evidence.")
        pre = ssh_prefix()
        port = pre[pre.index("-p") + 1] if "-p" in pre else "22"
        key = pre[pre.index("-i") + 1] if "-i" in pre else None
        host = pre[-1]
        rsh = f"ssh -p {port}" + (f" -i {key}" if key else "")
        return _pull_evidence(t, rt, host, rsh, args.dry_run)

    # name the oversized lists BEFORE transferring, so the skip is visible not silent
    big = remote(
        "find %s/recon -maxdepth 1 -type f -name '*.txt' -size +%dc "
        "-exec sh -c 'printf \"%%s\\t%%s\\n\" \"$(wc -c < \"$1\")\" \"$1\"' _ {} \\;"
        % (rt, args.max_list), check=False)

    pre = ssh_prefix()
    port = pre[pre.index("-p") + 1] if "-p" in pre else "22"
    key = pre[pre.index("-i") + 1] if "-i" in pre else None
    host = pre[-1]
    rsh = f"ssh -p {port}" + (f" -i {key}" if key else "")
    cmd = ["rsync", "-az", "-v", f"--max-size={args.max_list}", "-e", rsh,
           "--include=*/", "--include=*.md", "--include=*.txt", "--exclude=*",
           f"{host}:{rt}/recon/", str(t / "recon") + "/"]
    if args.dry_run:
        cmd.insert(1, "--dry-run")
        print("  DRY RUN — nothing written")
    print(f"  pulling *.md and *.txt <= {size_str(args.max_list)} from {rt}/recon/ …")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        die(f"rsync failed:\n       {r.stderr.strip()}", 2)
    moved = [l for l in r.stdout.splitlines()
             if l.strip() and not l.startswith(("sent ", "total size", "Transfer starting", "./"))]
    print("\n".join("    " + l for l in moved) if moved else "    (nothing new)")

    skipped = [l.split("\t") for l in big.strip().splitlines() if "\t" in l]
    if skipped:
        print(f"\n  left on the VPS — over the {size_str(args.max_list)} list threshold:")
        for s, path in sorted(skipped, key=lambda x: -int(x[0])):
            print(f"    {size_str(int(s)):>7}  {Path(path).name}")
        print("    These are re-derivable artifacts, not brain. Record their counts in index.md.")

    _pull_evidence(t, rt, host, rsh, args.dry_run)
    print("\n  raw/, jobs/, bulk logs/, loot/ are never pulled — VPS-side by rule.")
    return 0


def cmd_push(args):
    need_rsync()
    t = local_target(args.target)
    rt = f"{workdir()}/{t.name}"
    jobs = t / "jobs"
    if not jobs.is_dir() or not any(jobs.iterdir()):
        print(f"  nothing to push: {jobs.relative_to(ROOT) if ROOT in jobs.parents else jobs} "
              f"is absent or empty.")
        print("  (Job scripts are authored locally then pushed; they RUN from "
              f"{rt}/jobs/ — see playbooks/system/vps-execution.md)")
        return 0
    pre = ssh_prefix()
    port = pre[pre.index("-p") + 1] if "-p" in pre else "22"
    key = pre[pre.index("-i") + 1] if "-i" in pre else None
    host = pre[-1]
    rsh = f"ssh -p {port}" + (f" -i {key}" if key else "")
    remote(f"mkdir -p {rt}/jobs {rt}/logs")
    cmd = ["rsync", "-az", "-v", "-e", rsh, str(jobs) + "/", f"{host}:{rt}/jobs/"]
    if args.dry_run:
        cmd.insert(1, "--dry-run")
        print("  DRY RUN — nothing written")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        die(f"rsync failed:\n       {r.stderr.strip()}", 2)
    print(f"  pushed jobs/ -> {rt}/jobs/")
    print("\n".join("    " + l for l in r.stdout.strip().splitlines() if l.strip()))
    return 0


def cmd_demote(args):
    t = local_target(args.target)
    rt = f"{workdir()}/{t.name}"
    lp = (t / args.file).resolve()
    if not lp.is_file():
        die(f"{args.file} is not a file under {t}")
    rel = lp.relative_to(t)
    lines = sum(1 for _ in open(lp, "rb"))
    lsha = sha(lp)

    # find the remote counterpart; verify byte-identical before touching anything local
    out = remote(f"for p in {rt}/{rel} {rt}/raw/*/{lp.name}; do "
                 f"[ -f \"$p\" ] && printf '%s %s\\n' \"$(sha256sum \"$p\" | cut -d' ' -f1)\" \"$p\"; "
                 f"done", check=False)
    matches = [l.split(None, 1) for l in out.strip().splitlines() if l.strip()]
    same = [p for h, p in matches if h == lsha]
    if not same:
        print(f"FAIL — no byte-identical copy of {rel} found on the VPS.", file=sys.stderr)
        if matches:
            print("       Remote candidates exist but their hashes DIFFER:", file=sys.stderr)
            for h, p in matches:
                print(f"         {p}", file=sys.stderr)
            print("       Refusing to delete a local file whose remote copy is not the same "
                  "file.", file=sys.stderr)
        else:
            print(f"       Push it first, or leave it local. Refusing to delete the only copy.",
                  file=sys.stderr)
        return 2
    rpath = same[0]

    if not args.yes:
        print(f"  would replace  {rel}  ({size_str(lp.stat().st_size)}, {lines:,} lines)")
        print(f"  verified copy  {rpath}  (sha256 matches)")
        print("  re-run with --yes to do it")
        return 1

    pointer = (f"# {rel.name} — moved to the VPS\n\n"
               f"{lines} lines, {size_str(lp.stat().st_size)}. Too large to reason over locally, so it\n"
               f"lives on the VPS per the split rule in `playbooks/system/target-schema.md`.\n\n"
               f"    {rpath}\n\n"
               f"Read it there:  $(tools/config.py ssh) 'wc -l {rpath}'\n"
               f"sha256: {lsha}\n")
    lp.unlink()
    (lp.parent / (lp.name + ".pointer.md")).write_text(pointer, encoding="utf-8")
    print(f"  {rel} -> {rel}.pointer.md   (remote copy verified, {lines:,} lines)")
    print("  nothing was deleted on the VPS.")
    return 0


def cmd_verify_runner(args):
    """The deployed run.py must be byte-identical to this checkout's, or a record you trust
    locally was written by code you never read. Fail loud on mismatch, absence, or unreachable —
    and print the exact redeploy line."""
    local = ROOT / "tools" / "run.py"
    if not local.is_file():
        die("local tools/run.py is missing — nothing to verify against")
    lsha = sha(local)
    remote_path = args.remote_path or f"{codedir()}/tools/run.py"
    host, rsh = rsync_env()
    redeploy = (f"rsync -az --exclude __pycache__ --exclude '*.pyc' -e \"{rsh}\" "
                f"tools/ {host}:{codedir()}/tools/")

    r = remote_result(f"if [ -f {remote_path} ]; then sha256sum {remote_path}; "
                      f"else printf ABSENT; fi; printf '\\nDONE\\n'")
    terr = ssh_transport_error(r)
    if terr:
        die(f"{terr}\n       Could not verify the deployed runner at {remote_path}.")
    out = r.stdout
    if "ABSENT" in out:
        print(f"  ABSENT — no run.py at {remote_path} on the VPS.")
        print(f"  Deploy it before running any skill:\n      {redeploy}")
        return 1
    rsha = next((l.split()[0] for l in out.splitlines()
                 if l.strip() and l.strip() != "DONE" and len(l.split()[0]) >= 32), "")
    if rsha == lsha:
        print(f"  MATCH — deployed run.py == local (sha256 {lsha[:16]}…).")
        print("  The evidence you pull home was written by the code you can read.")
        return 0
    print(f"  MISMATCH — local {lsha[:16]}…  vs  deployed {rsha[:16] if rsha else '??'}…")
    print("  The VPS is running a DIFFERENT recorder. Redeploy before a skill runs:")
    print(f"      {redeploy}")
    return 1


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")
    for name, helptext in (("status", "what is where, and what breaks the rule"),
                           ("pull", "bring curated *.md extracts + evidence records down"),
                           ("push", "send jobs/ up")):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("target")
        s.add_argument("--max-list", type=int, default=DEFAULT_MAX_LIST_BYTES,
                       help="bytes above which a .txt belongs on the VPS (default 256K)")
        if name in ("pull", "push"):
            s.add_argument("--dry-run", action="store_true")
    d = sub.add_parser("demote", help="oversized local list -> VPS-only + pointer")
    d.add_argument("target"); d.add_argument("file")
    d.add_argument("--yes", action="store_true", help="actually do it")
    d.add_argument("--max-list", type=int, default=DEFAULT_MAX_LIST_BYTES)
    v = sub.add_parser("verify-runner",
                       help="deployed run.py must match this checkout's before a skill runs")
    v.add_argument("--remote-path", help="override the deployed run.py path "
                                         "(default <vps.codedir>/tools/run.py)")
    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        return 2
    return {"status": cmd_status, "pull": cmd_pull, "push": cmd_push,
            "demote": cmd_demote, "verify-runner": cmd_verify_runner}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(runlog.wrap()(main)())
