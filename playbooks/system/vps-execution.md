# VPS Execution Model

Active recon and testing tools run on a remote VPS over SSH. The VPS is the **compute
engine**; the local `targets/<target>/` folder is the **brain / source of truth**.
This keeps the human's laptop and home IP out of the engagement and gives heavy scans
a proper Linux host.

---

## Connection

The SSH key path and VPS endpoint are machine-level settings in the gitignored `config.json`.
Never copy them into a target brain. Standard invocation:

```
$(tools/config.py ssh) '<command>'      # resolves vps.{user,host,port,ssh_key} from config.json
```

**Always run any task that may take time inside a named `tmux` session** on the VPS (not
`nohup`) — it survives disconnects, is reattachable, and can be inspected pane-by-pane.
Moving anything across the local/VPS boundary goes through `tools/vps-sync.py`
(`status` · `pull` · `push` · `demote`) — it knows the split rule and refuses to break it.

**Everything a job produces is scoped to its target — nothing is written to `~`.** Raw output and
logs live under `~/targets/<target>/`. The home directory is not a scratchpad: artifacts dropped
there lose the one thing that makes them useful later, which is *which engagement they belong to*.

For a long external-tool run, use the existing harness in detached mode:

```sh
tools/vps-run.py targets/<target> --skill <skill> --detach <session> \
  --expect-file <artifact> -- <external-tool> <args>
```

`--detach` starts the **same direct `run.py -- <external-tool>` command** inside VPS tmux after the
local privacy/attribution check. Do not replace it with `bash job.sh`: an opaque wrapper hides the
scanner argv and defeats the exact invocation check that catches malformed jsluice `-R`. A script
under `jobs/` may orchestrate offline first-party reducers, but every external scanner remains its
own harness invocation and output contract.

Then poll the log in bounded chunks (never hold one SSH connection open for the whole scan — it
drops). `tmux ls` to list, `tmux capture-pane -pt <name>` to peek. Never block a session waiting on
a multi-hour scan — kick it off in tmux, record where output lands, and stop; the human resumes you
when it's done.

**Security:** the VPS is a least-privilege sandbox. Never store production creds,
personal accounts, or the human's secrets on it. Treat anything the VPS pulls from a
target as untrusted (see system prompt §4).

**Artifact hygiene:** when saving request/response artifacts for a finding, **redact secrets not
needed for the proof** — session cookies, bearer/JWT, API keys, passwords, CSRF tokens, and
third-party PII — keep only what demonstrates the bug. Test-account creds may live in the local
`accounts.md` (the tree isn't committed to a repo), but never echo them into shared
artifacts/reports.

---

## VPS directory layout (the heavy store)

```
~/targets/<target>/
  raw/
    subdomains/       raw tool output (subfinder, amass, assetfinder, ...)
    dns/              dnsx, massdns output
    ports/            nmap, naabu, masscan output
    http/             httpx JSON, screenshots
    urls/             gau, katana, waybackurls, gospider output
    content/          ffuf/feroxbuster output per host
    js/               downloaded JS bundles
    nuclei/           nuclei results
    snapshots/        timestamped snapshots for the monitoring/diff skill
  wordlists/          SecLists + target-specific generated lists
  loot/               anything sensitive found (kept on VPS, never synced casually)
```

Naming: prefix outputs with an ISO date so the monitoring/diff skill can compare
snapshots, e.g. `raw/subdomains/$DATE-subfinder.txt`.

---

## The normalize-and-sync loop (every recon skill)

1. **Run** the tool on the VPS; write raw output to the right `raw/` subdir.
2. **Normalize** on the VPS with shell (sort -u, cut, jq, anew) into the clean form.
3. **Pull back** only the normalized extract into the local `recon/` file
   (`scp` or `ssh ... 'cat ...'`), matching the schema in `target-schema.md`.
4. **Update** local `index.md`: new counts, pointer to the VPS raw path, timestamp.
5. **Summarize** for the human and **stop**.

So the local brain holds clean, structured, reviewable data + pointers; the bulky raw
telemetry stays on the VPS and is re-fetched on demand. This directly targets the
measured failure mode — LLMs choke on raw verbose scan output — by doing the
normalization at the shell layer before you reason over it.

---

## Command robustness — every tool call, every target (fail loud, never patch-per-task)

A tool that silently runs on an empty/missing input or a malformed flag wastes an entire scan and —
worse — records a **false success**. Fixes must be **generic**: make the command correct for *any
input on any target*, then verify once. **Never patch an invocation for the current task** only to
have it break on the next target. Guard **every** tool call in three beats:

**1. Preflight (before the run).**
- **Input exists and is non-empty** → a *loud skip*, not a silent 0-result:
  `[ -s "$IN" ] || { echo "SKIP <phase>: $IN empty/missing"; continue; }`.
  *(Seen: a job ran on a non-existent `recon/live-hosts.txt` and reported "DONE", 0 findings.)*
- **Verify the invocation on a tiny sample first** — confirm the subcommand/flag against `--help`
  before running at fleet scale; don't guess flags. *(Seen: `jsluice urls -R <file> <file>` was
  malformed → empty; `-R` requires an absolute source URL, while files are positional inputs.)*
- **Make output shape executable.** Keep the scanner as the direct command after `run.py --` and
  use `--expect-format json|jsonl --expect-fields a,b` for the fields the next parser consumes.
  Known JSON tools are inferred. For stdout-only tools use `--stdout-file <artifact>` instead of a
  shell redirection wrapper, or the harness cannot see the real argv. A nonempty malformed record
  and an artifact left over from an earlier run both fail.
- **Derive all values from inputs** — no target-specific constants baked into the command, so the
  same line works on the next target unchanged.

**2. Guard (during the run).**
- **`</dev/null`** on any tool that reads stdin when given no file (jsluice, arjun, many Go CLIs) or
  it hangs forever. **`timeout <n>`** on every call so one stuck host can't wedge the pipeline.
- **Portable shell:** quote every expansion (`"$f"`), use arrays for lists — zsh doesn't word-split
  unguarded vars, bash does; write it to work in both. Use `set -u`, **not** `set -e`, in multi-phase
  scripts (one phase failing must not abort the rest — but each phase must be independently guarded).
- **Never hold a command in a string variable.** `SSH="ssh -i key user@host"` then `$SSH true`
  works in bash and **silently fails in zsh**, which does not word-split — the whole string becomes
  one command name, `command not found`, non-zero. Every caller then reads that as "the remote
  check failed" and takes the wrong branch. Bitten twice in one session: a tool-regression loop
  reported `rc=127` for every tool, and a completion watcher polled for two hours without ever
  being able to fire. **Use a function**, which is portable and quotes correctly:
  ```sh
  ssh_vps () { ssh -i "$KEY" -p "$PORT" -o BatchMode=yes "$USER@$HOST" "$@"; }
  ```
- **Watch the EXACT log file for this run, never a glob.** `grep -l DONE logs/asn-*.log` also
  reads every earlier attempt, and a previous *failed* run that printed the completion marker on
  its way out fires the watcher instantly — reporting success while the real job is still on
  stage 4. Capture the stamped path when you launch and poll that one file. Seen for real: a
  67-byte log from a run that aborted in its first second satisfied the glob two minutes after a
  fresh run started.
- **`~` and `$VAR` inside double quotes expand LOCALLY, before ssh sees them.**
  `L=~/targets/x/log; ssh host "grep -q done $L"` greps `/Users/you/targets/x/log` **on the remote
  box** — a path that does not exist there, so the grep always fails and the caller concludes the
  job never finished. Single-quote anything the remote shell must expand:
  `ssh_vps 'grep -q done ~/targets/x/log'`.

**3. Assert (after the run) — this is what catches the silent failure.**
- Check the output is non-empty and correctly shaped; if a phase yields nothing where it should,
  **log a FAILURE, not a completion**: `n=$(wc -l < "$OUT"); echo "<phase>: $n rows"` and flag
  `$n -eq 0` loudly. A "DONE" must mean *produced real data*, not *exited 0*.
- **Count with `wc -l`, never `grep -c … || echo 0`.** `grep -c` **exits 1 when the count is zero**,
  so the `||` fires *in addition to* grep's own `0` and the variable gets `"0\n0"` — every later
  `[ "$n" -eq 0 ]` then dies with `integer expected`, and the guard you wrote to catch the empty
  case is the thing that breaks on it. Seen for real: an assert helper printed
  `[: 0\n0: integer expected` and the stage it was guarding was reported `OK`.
  Use `n=$(wc -l < "$f" 2>/dev/null || echo 0)`.
- **A stage killed by its own `timeout` is a FAILURE, not an empty result.** Check for it
  explicitly — `timeout` exits `124` — or the log reads "0 results" when the truth is "never
  finished". Seen for real: `alterx` was killed at 1800s having emitted nothing, and only the
  30-minute gap between two timestamps in the log revealed it.
- **In a pipeline, `$?` is the LAST command's status.** `timeout … | sort -u > out` followed by
  `$?` reads *sort*, so a killed producer looks like success. Use `${PIPESTATUS[0]}` in bash.

**Disk hygiene — stream into the reducer, never land the raw output.**

A generator's raw output is usually several times its deduped form, and once you have written the
deduped file the raw one holds nothing you do not already have. `alterx` on one target emitted
4,558,035 lines (143 MB) that reduced to 1,990,472 (62 MB) — writing raw first cost 143 MB to
store a strict subset of the next file.

```sh
producer | LC_ALL=C sort -u > out.txt      # yes
producer > raw.txt; sort -u raw.txt > out.txt   # no — raw.txt is dead weight the moment sort ends
```

Keep one raw artifact **per distinct source** (subfinder, amass, crt.sh) — those are provenance
and feed the monitoring diff. Do not keep intermediates that are merely an earlier, messier
representation of a file you also kept. Check with `du -sh ~/targets/<t>` after any phase that
generates candidates in the millions.

**`-o <file>` does not mean "instead of stdout".** Most projectdiscovery tools write the file *and*
print every record, so the standard `… 2>&1 | tee $T/logs/<name>.log` wrapper copies the whole
dataset into the log. Seen for real: a live-host-validation log came to **10.8 MB — 35,426 duplicated JSON
lines around 3,991 lines of actual log**, while every other phase log was 1–2 KB. Send stdout to
`/dev/null` whenever `-o` already captures it:

```sh
dnsx -l "$IN" -json -o raw/dns/$DATE-resolved.json </dev/null >/dev/null 2>"$D/.err"
```

The log is for **what happened**; the artifact is for **what was found**. A log that contains the
dataset is neither.
- Reject data-quality traps that fake success: soft-404 (200-for-everything) **and** catch-all
  redirect (301-for-everything, same length) — discriminate on length/words/redirect, not status.

One line: **preflight the input, verify the invocation generically, guard stdin+time, assert the
output** — so a broken run fails loudly instead of poisoning the dataset with a confident zero.

---

## Dispatch through `tools/vps-run.py` — inspect + inject locally, record on the VPS

**Use `tools/vps-run.py` for any command that reaches a target over HTTP.** It runs *locally*,
where `config.json` is, and does the two things `run.py` cannot do on the VPS (which has no config):

- **inspects the command for your identity before it is sent** — refuses your PRIVATE identity
  (email, aliases) anywhere, and refuses your PUBLIC attribution value placed anywhere but its
  header. This is the privacy backstop actually *firing*, at the one place it can.
- **injects the attribution header** (`researcher.header_name: header_value`) only for tools whose
  installed inline-header syntax has been verified. Other known target-HTTP tools still must cross
  this boundary and produce a visible warning until their adapter is verified; never guess a flag.

It then dispatches `run.py` on the VPS and relays the result. `--print` shows the exact remote
command without sending it; `--detach <session>` starts that command inside tmux for long work;
`--no-inject` is for a header you are adding yourself.

```
tools/vps-run.py targets/<t> --skill content-discovery --run-id R-014 \
    --expect-file raw/content/<host>.json \
    -- ffuf -u 'https://<host>/FUZZ' -w recon/wordlists/<host>-derived.txt -fs 2048 -of json \
       -o raw/content/<host>.json
```

For non-HTTP work (dnsx, naabu, subfinder) it simply passes through — no header, same recording. If
you invoke `run.py` on the VPS directly, you bypass the local privacy inspection and the attribution
injection; do that only for commands that send nothing to a target.

### The recorder underneath: `tools/run.py`

`tools/run.py` is an **interface validator and evidence recorder**, not a policy engine. It runs your command and writes a
record that answers *"why that flag, three weeks ago?"* — tool version, redacted argv plus a hash
of the real one, sha256 of every input file, host, duration, exit code, and the artifact's size and
hash. It judges success on the **artifact**, not on what the tool printed: an `ffuf -o` that exits
0 and leaves an empty file is a failure wearing a success code, and this catches it.

SSH often starts a non-login shell whose default `PATH` omits user-installed binaries. Before
version detection and execution, the recorder prepends `~/.local/bin`, `~/go/bin` and
`/usr/local/go/bin` while preserving the inherited path. This is why a verified pipx/Go/upstream
install is the binary the harness actually runs, not a stale system package with the same name.

**It refuses documented target-HTTP tools directly.** The registry includes the core scanners and
specialized HTTP tools used by this workspace; they must come through `vps-run.py`, which runs the
identity check `run.py` cannot run on the VPS (no config there) and injects attribution where its
syntax is verified. Calling
`run.py -- curl …` directly is refused, pointing you at the wrapper. Non-HTTP tools (dnsx, naabu,
subfinder) run through `run.py` directly, as before. The gate is a steer against *accidental*
bypass — a marker `vps-run.py` sets — not a boundary against a deliberately-set one; on shared infra
nothing at this layer can be, but a deliberate bypass is then visible in the record.

```
tools/run.py targets/<t> --skill live-host-validation --run-id R-014 \
    --expect-file raw/dns/resolved.txt \
    -- dnsx -l raw/subdomains/candidates.txt -silent -o raw/dns/resolved.txt
```

The relevant flags are: `--skill` (required), `--run-id`, `--timeout` (default 1800s, a hard kill),
`--expect-file`, `--stdout-file`, `--expect-format`, `--expect-fields`, `--note`, `--dry-run`.
**Run `tools/run.py --help` and trust that over this paragraph.** It does *not* take
`--max-rps`, `--calibration`, `--strict` or `--local-egress`; those belonged to a ~310-line policy
engine that was deleted, because it encoded judgements that are the hunter's (which packets, from
where, at what rate). Command choice remains the model's; mechanically assertable invocation and
output contracts belong to the runner (`skills/_recon-method.md`).

**It does not build the command — you do, from what you observed.** `-fs 2048` comes from your
calibration, the rate from the program, the wordlist from this target's own vocabulary. Correctness
is on you, every run, against the binary actually installed — because a flag list pasted into a
playbook is `--help` with a shelf life, and two `httpx` flags that did not exist in the installed
build once turned into a confident zero across 62,646 targets.

Run it **on the VPS**, so traffic egresses from the research box, not your laptop. `run.py` records
the host it ran on (`ran_on`) in every record, so a command that accidentally ran locally is
visible after the fact. Exit codes: **0** the command satisfied its output contract · **1** exit 0
but output is missing, empty, stale or structurally invalid · **2** the command failed or a known-
bad invocation was refused before execution.

### Deploy the recorder, and verify it before a skill runs

The VPS must carry the **same** `run.py` as this checkout, or the record you trust locally was
written by code you did not read. Deploy and verify in one step:

```
tools/vps-sync.py verify-runner        # sha256(local tools/run.py) vs the deployed copy
```

It prints `MATCH`, or `MISMATCH`/`ABSENT` with the exact `rsync` line to redeploy `tools/` — and
exits non-zero so a wrapper script stops rather than running against a stale engine. The evidence
records `run.py` writes under the VPS's `logs/exec/` are pulled home by `tools/vps-sync.py pull`
(they are small JSON, local by rule — `target-schema.md`), so proof of what ran ends up in the
durable brain and not on disposable infrastructure.

And it records what makes a run reproducible: tool **version**, the argv with every
secret-bearing *or researcher-identity* argument redacted plus a hash of the real one, sha256 of
every input, the host it ran on, duration, exit code, and the **artifact's** size and hash — to
`logs/exec/<stamp>-<skill>-<tool>.json`. It does **not** record a scope hash, calibration pointer or
budget: those were fields of the deleted policy engine, not the recorder. It also flags, by
**category** (`private_leak_categories` — never the value), any configured private identity that
appears in the response. That is what answers *"why `-fs 2048`, three weeks ago?"* when the answer
is no longer in anyone's head.

Pass `--expect-file` and success is judged on the artifact, not on what the tool printed. `ffuf` can
exit 0, print a banner and leave an empty file; measuring stdout called that a success.

**Exit 1 means it ran and the output is suspect** — exit 0 with an empty file is not "no findings"
until you have re-checked the input and the filter. Exit 2 means nothing ran.

## Loud-phase envelope — choose and disclose the bound

Expensive/active objectives (URL collection, content discovery, API discovery, parameter
discovery, nuclei sweeps, fuzzing) must **never treat an omitted selector as "the whole
inventory."** On a 55k-subdomain / 4k-host target, "all" is a multi-day, ROE-risking run.
**Invocation stays free-text** (the human says e.g. "content-discovery on the auth cluster") —
the skill's **preflight resolves** it into the envelope below from the command + `scope.md` ROE;
the envelope is a preflight *discipline*, not a syntax the human types. Every loud invocation
resolves — or the skill proposes — an envelope:
- **selector** — explicit hosts, a named cluster (host-correlation-and-clustering), or a derived slice. **No default "all".**
- **authorization + scope snapshot** — the ROE mode and the `scope.md` state it was checked against.
- **budget** — `max_requests`, `max_rps` (≤ the program limit), `concurrency`, `max_duration`.
- **required headers** — you do **not** type these for a verified adapter. `vps-run.py` injects the
  attribution header (`researcher.header_name: header_value`) from config at dispatch. For a
  target-HTTP tool whose inline-header syntax is not verified, it warns instead of pretending;
  inspect that installed CLI before proceeding. Never hardcode a handle into application data.

If the human did not name a selector or budget, choose a defensible bound, state it, pilot, and
continue the invoked objective without asking again. Scale while output remains trustworthy; record
exactly what the chosen bound excluded. A missing bound narrows coverage—it is not a second
admission gate. Only a missing input declared by the skill stops the run.

---

## Passive vs active — what needs the VPS

- **Passive / OSINT** (crt.sh, GitHub, Wayback lookups, reading a single JS file): can
  be done with the built-in WebFetch/WebSearch tools, no VPS needed. Good for quiet,
  low-footprint discovery.
- **Active / tool-driven** (subfinder, dnsx, naabu/nmap, httpx, ffuf, katana, nuclei,
  masscan): runs via Bash → SSH on the VPS. Each recon skill marks which mode it uses.

---

## Bootstrapping a fresh VPS

See `playbooks/system/vps-setup.md` for the one-time install of tools, wordlists, and
directory layout. Run it once per VPS; a target index records tool readiness and the target's
remote working directory, never the connection credentials.
