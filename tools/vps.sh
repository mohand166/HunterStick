#!/usr/bin/env bash
# Run a command on the target VPS, or move a file across the boundary.
#
# Why this exists
# ---------------
# `tools/config.py ssh` prints a connection STRING. Holding that string in a variable and
# invoking it works in bash and silently fails in zsh, which does not word-split — the whole
# string becomes one command name (`command not found`), and every caller reads that as "the
# VPS is unreachable" and takes the wrong branch. `playbooks/system/vps-execution.md` records
# this biting twice in one session; it bit a third time on 2026-08-04.
#
# The documented workaround was to define a shell function inline in every Bash call. That
# works, but it makes each invocation a novel command string, so it can never be allowlisted
# and re-prompts forever. A script has a stable argv[0]: allowlist `tools/vps.sh` once.
#
# Usage
#   tools/vps.sh '<remote command>'              run it on the VPS (single-quote it — the
#                                                remote shell does the expanding, not yours)
#   tools/vps.sh --push <local> <remote>         copy up   (remote path is relative to $HOME)
#   tools/vps.sh --pull <remote> <local>         copy down
#   tools/vps.sh --check                         print the resolved endpoint and test reachability
set -u

# --help must work locally, with no config.json and no network — this workspace tells the model to
# read a tool's help before using it, and `*)` below would otherwise SSH `--help` to the VPS.
case "${1-}" in
  -h|--help)
    cat <<'USAGE'
tools/vps.sh — run a command on the target VPS, or move a file across the boundary.

  tools/vps.sh '<remote command>'          run it on the VPS (single-quote it — the remote
                                           shell expands, not yours)
  tools/vps.sh --push <local> <remote>     copy up   (remote path relative to $HOME)
  tools/vps.sh --pull <remote> <local>     copy down
  tools/vps.sh --check                     print the resolved endpoint and test reachability
  tools/vps.sh --help                      this text

Connection settings come from the `vps` block of config.json. Exists so `tools/vps.sh` has a
stable argv[0] that can be allowlisted once, instead of a novel inline ssh string every call.
USAGE
    exit 0
    ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG="$ROOT/config.json"

if [ ! -f "$CFG" ]; then
  echo "vps.sh: $CFG not found — connection settings are machine-level and live there" >&2
  exit 2
fi

# Read the four fields we need. Fail loud on a disabled or half-filled vps block rather than
# emitting a connection that will hang.
eval "$(python3 - "$CFG" <<'PY'
import json, shlex, sys
try:
    v = json.load(open(sys.argv[1])).get("vps", {})
except Exception as e:
    print(f'echo "vps.sh: cannot parse config.json: {e}" >&2; exit 2'); sys.exit(0)
if not v.get("enabled"):
    print('echo "vps.sh: vps.enabled is false in config.json — passive-only work until one exists" >&2; exit 2')
    sys.exit(0)
missing = [k for k in ("user", "host", "ssh_key") if not v.get(k)]
if missing:
    print(f'echo "vps.sh: config.json vps block is missing: {", ".join(missing)}" >&2; exit 2')
    sys.exit(0)
for k, d in (("user", ""), ("host", ""), ("port", 22), ("ssh_key", "")):
    print(f"VPS_{k.upper()}={shlex.quote(str(v.get(k, d)))}")
PY
)"

# Expand a leading ~ in the key path; ssh -i does not do it for you.
case "$VPS_SSH_KEY" in "~"*) VPS_SSH_KEY="$HOME${VPS_SSH_KEY#\~}" ;; esac
if [ ! -f "$VPS_SSH_KEY" ]; then
  echo "vps.sh: ssh key not found at $VPS_SSH_KEY" >&2
  exit 2
fi

# ssh takes the port as -p; scp takes it as -P, and treats a bare -p as "preserve times". Sharing
# one option array between them makes scp read the port number as a FILE OPERAND — it then fails
# with a "No such file or directory" naming the remote path, which reads exactly like the remote
# file being absent. Two arrays, because the two commands genuinely disagree.
COMMON_OPTS=(-i "$VPS_SSH_KEY" -o BatchMode=yes -o ConnectTimeout=20
             -o StrictHostKeyChecking=accept-new)
SSH_OPTS=("${COMMON_OPTS[@]}" -p "$VPS_PORT")
SCP_OPTS=("${COMMON_OPTS[@]}" -P "$VPS_PORT")
DEST="$VPS_USER@$VPS_HOST"

# OpenSSH 9 runs `scp` over SFTP, and SFTP has no shell, so it never expands `~`. A remote path
# written as `~/targets/x/f.txt` fails with "No such file or directory" while the identical path
# works fine over `ssh`. Stripping the `~/` and relying on SFTP starting in the login directory is
# NOT reliable either — verified against this VPS, where the relative form also failed. The only
# form SFTP resolves everywhere is absolute, so ask the remote what its home is (one extra round
# trip, and only when a path actually needs it) and build an absolute path from the answer.
remote_path () {
  case "$1" in
    "~/"*|"~")
      if [ -z "${REMOTE_HOME:-}" ]; then
        REMOTE_HOME=$(ssh "${SSH_OPTS[@]}" "$DEST" 'printf %s "$HOME"') || {
          echo "vps.sh: could not resolve the remote home directory" >&2; exit 2; }
      fi
      [ "$1" = "~" ] && printf '%s' "$REMOTE_HOME" || printf '%s/%s' "$REMOTE_HOME" "${1#\~/}"
      ;;
    *) printf '%s' "$1" ;;
  esac
}

case "${1-}" in
  --check)
    echo "vps.sh: $DEST:$VPS_PORT  key=$VPS_SSH_KEY"
    ssh "${SSH_OPTS[@]}" "$DEST" 'echo reachable: $(hostname) uptime:$(uptime -p)'
    ;;
  --push)
    [ $# -eq 3 ] || { echo "vps.sh --push <local> <remote>" >&2; exit 2; }
    [ -e "$2" ] || { echo "vps.sh: local path does not exist: $2" >&2; exit 2; }
    scp "${SCP_OPTS[@]}" -q -r "$2" "$DEST:$(remote_path "$3")" && echo "pushed: $2 -> $3"
    ;;
  --pull)
    [ $# -eq 3 ] || { echo "vps.sh --pull <remote> <local>" >&2; exit 2; }
    mkdir -p "$(dirname "$3")"
    scp "${SCP_OPTS[@]}" -q -r "$DEST:$(remote_path "$2")" "$3" && echo "pulled: $2 -> $3"
    ;;
  "")
    echo "vps.sh: no command given. See the header for usage." >&2
    exit 2
    ;;
  *)
    ssh "${SSH_OPTS[@]}" "$DEST" "$@"
    ;;
esac
