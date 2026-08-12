# Tool reference


You normally do not type these commands during a hunt. **You describe the outcome; the model invokes
the tool.** This reference exists so you can audit what is available, what changes files and what
can send traffic.

The separation is intentional:

- **Playbooks think.** They contain reconnaissance and vulnerability-research methods.
- **Tools compute and refuse.** They handle arithmetic, parsing, repeatable writes and inspectable
  safety checks.
- **The model adapts.** It chooses tools and constructs commands from the target's current evidence.
- **The hunter authorizes.** The next bounded unit and any meaningful traffic remain human choices.

Most first-party tools exit `2` when they cannot complete their contract. `run.py` does not decide
scope, methods, rates or what to hunt; those remain the hunter's choices. It does reject a small
set of evidence-backed invocation traps and fails output that is missing, empty, stale or violates
its declared JSON/JSONL contract. Everything it noticed is recorded with the run. They append their
invocation and exit code to the target's tool log where a target is available.

---

## Tools by hunting question

| what you want | what you say | primary tool |
|---|---|---|
| understand current state | “Where are we on acme?” | `brief.py` |
| initialize safely | “Initialize acme with this scope…” | `init-target.py` |
| choose a bounded next move | “What should I run, and why?” | `suggest-flows.py` |
| check a skill has its inputs | invoked automatically before recon | `preflight.py` |
| execute one HTTP recon command | “Run HTTP probing on these hosts.” | `vps-run.py` → VPS `run.py` |
| execute one non-HTTP command | “Resolve these names.” | VPS `run.py` |
| calculate untested work | “What have we not tested?” | `coverage.py` |
| record and connect facts | “What changed?” / “Show chains.” | `kb.py` |
| import browsing traffic | “Import this Burp/HAR export.” | `import-http.py` |
| recover lazy JavaScript | “Find every authorized lazy chunk in these bundles.” | `chunks.py` |
| normalize JS/spec surface | “Reduce these saved jsluice URL/secret or OpenAPI artifacts into the brain.” | `surface.py` |
| render a human review page | “Generate the target dashboard.” | `dashboard.py` |
| watch for new assets | “Monitor subdomains every 12 hours.” | `monitor.py` |
| pilot an n-day check | “Check this affected cohort.” | `sweep.py` |
| audit failures | “What failed?” | `runlog.py` |

---

## Side-effect legend

| label | meaning |
|---|---|
| **local** | reads or changes repository/target files only |
| **target traffic** | may send requests to an authorized target |
| **VPS control** | uses SSH, cron or file transfer but is not itself a target probe |
| **library** | imported by other tools; not normally invoked directly |

`vps-run.py` is the required local boundary for target-HTTP CLIs: it checks identity placement and
injects attribution where the installed syntax is verified. VPS `run.py` then executes and records
the model-supplied command. `--detach <session>` starts that same direct runner command in VPS tmux
for long work; an opaque `bash job.sh` must not replace it because the scanner's invocation and
output contract would disappear from the harness. Non-HTTP tools can use the recorder directly.

---

## The complete catalogue lives in FILEMAP.md

There used to be a full per-tool table here. It was a **second copy of what `FILEMAP.md`
already documents**, and it did what second copies do: at the time of writing it named
**15 tools while FILEMAP named 29** at that time — every one of the 15 already in FILEMAP, and 14 missing
entirely, including `graph.py`, `roles.py`, `vps.sh`, `calibrate.py`, `config.py`, `record.py`
and `wildcard-check.py`. Anyone reading this file to learn the toolkit was getting half of it
and had no way to know.

So the split is by **question**, not by content:

- **"what do I want to do?"** → the intent index above, and the sections below.
- **"what is this file and when does it load?"** → `FILEMAP.md`, which is the catalogue.
- **"how do I invoke it?"** → the tool's own `--help`. Every one of them has a docstring that
  explains what it is for and, more usefully, *what went wrong that made it necessary*.

That last one is worth using. `tools/preflight.py --help` and `tools/graph.py --help` each
explain a real failure this workspace hit, which is more use than a table row.

## Dynamic command construction

The workspace does not maintain a hard-coded command template for every scanner. Tool versions and
flags change, and target behavior should change the command. Instead:

1. The skill declares its objective, inputs, signals and known traps.
2. The model reads current target evidence and the **installed** binary's help.
3. The model pilots on a small slice and **declares/verifies the output shape** before scaling.
4. A run row is opened before traffic.
5. Target HTTP goes through local `vps-run.py`; VPS `run.py` executes and records it. Non-HTTP
   commands use the recorder directly.
6. The execution record stores enough to explain and reproduce the choice later.

**`run.py` validates interfaces; it does not choose policy.** It used to be a policy engine — ~310 lines checking
scope, rate, methods, calibration evidence, flag advertisement, egress and the run ledger — and
that was removed for two reasons. It **never ran**: `logs/exec/` held zero records for an entire
engagement, because the existing VPS checkout was never verified and every real command went
through a hand-rolled script, so none of the checking applied. And the checks encoded judgements that
belong to the hunter — which packets to send, from where, at what rate.

So the split moved to where it belongs: **the model owns command choice**
(`skills/shared/_recon-method.md` — read the help, pilot, verify the shape, adapt), and `run.py` owns the
mechanically assertable interface and evidence. It rejects known semantic traps before execution,
infers stable contracts for the structured scanners this project relies on, and lets the caller add
`--expect-format` / `--expect-fields` for the exact downstream consumer.

It records tool version, redacted argv plus a hash of the real argv, the sha256 of every input
file, the host it ran on, timestamps, duration, exit code, stderr tail, and the artifact's size
and hash. Stdout and stderr go to files beside the record, never into the log.

Success is measured on what the tool *wrote*, not what it *printed*. `ffuf -o` can exit 0, emit a
banner and leave an empty file; an older artifact can make a no-op look successful; jsluice can
emit nothing after a malformed `-R`. `run.py` therefore requires a fresh artifact and parses every
declared JSONL record. `--stdout-file` saves stdout-only structured output without hiding the real
tool behind shell redirection. Exit 1 means the output contract failed.

### What the runner cannot prove

- A discovery tool can find and contact a new name internally after the command starts.
- Prose exclusions such as “divested brands” may not be mechanically filterable.
- Binary help may be incomplete.
- A safe-looking read request can still have an unusual application-side effect.
- The model can misinterpret the result after a valid command finishes.

This is why the project says “review active commands,” not “the harness makes autonomous testing
safe.”

---

## Knowledge and coverage commands

The most useful `kb.py` operations are:

```bash
tools/kb.py vocab
tools/kb.py show targets/acme --subject api.acme.com
tools/kb.py reassess targets/acme
tools/kb.py chains targets/acme --depth 3
tools/kb.py runs targets/acme
tools/kb.py cohort targets/acme --tech "Ruby on Rails" --version-lt 7.0.5 --out /tmp/cohort.txt
```

An `observed` fact requires a stored evidence path. Header or scanner output normally begins as
`reported`; model reasoning begins as `inferred`. Provenance, rather than a confidence adjective,
determines how contradictions are resolved.

Coverage is computed from:

```text
attack-surface cells − tested cells = remaining cells
```

The key is `entrypoint × class × principal × variant`. Do not remove dimensions to make the number
look smaller.

---

## Direct use by the hunter

You may invoke any tool to verify the model's work. Safe inspection commands include:

```bash
python3 tools/brief.py acme --resume
python3 tools/suggest-flows.py targets/acme --why
python3 tools/coverage.py targets/acme
python3 tools/runlog.py targets/acme --failures
python3 tools/dashboard.py targets/acme
python3 tools/self-check.py
python3 tools/graph.py --check
python3 -m unittest discover -s tests
```

Commands that can create cron jobs, transfer files or send target traffic deserve the same review
whether a model or a person typed them.
