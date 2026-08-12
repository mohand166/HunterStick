# Extending the workspace


This is the maintainer guide for adding capabilities without bloating runtime context or weakening
the safety contracts. Hunters using the existing workspace normally do not need this document.

Run after every change:

```bash
python3 tools/self-check.py
python3 -m unittest discover -s tests -q
```

## Place information in the right context tier

| tier | cost | examples |
|---|---|---|
| always resident | every session and prompt | `AGENTS.md`, `orchestrator.md` |
| orient | when the task is to orient or recommend, not for an exactly named skill | `class-signals.md` |
| trigger | only when a skill matches | `.claude/skills/*/SKILL.md`, one invoked playbook |
| on demand | only when an active method names it | supporting files under `playbooks/` |

Put procedures in on-demand files and only a one-line routing signal in the resident catalogue.
Adding forty phase lines costs nothing until that phase runs; adding four catalogue lines costs them
on every session.

## Configuration and integrations

Copy `config.example.json` to the gitignored `config.json`. Models and tools must access it through
`tools/config.py`; do not add direct readers that can leak credentials.

The optional `.mcp.json` integrations expose a browser and Burp. The workspace must remain usable
without either. Browser automation is justified when rendering, client state or authenticated flows
matter; it is overhead for passive sources and simple HTTP responses.

## Add a vulnerability class

1. Copy the six-section spine from `playbooks/vulns/_playbook-shape.md`.
2. Create `playbooks/vulns/<class>.md`.
3. Add one surface-property mapping to `playbooks/system/class-signals.md`.
4. Add the canonical class to `playbooks/vulns/_index.md`.
5. Add tests for any new deterministic behavior.
6. Run `self-check.py` and the test suite.

Do not create a class for a transport. IDOR remains IDOR over REST, GraphQL or gRPC. Transport
contract recovery belongs in an investigation lens or workflow. Shared root cause means one class;
shared plumbing means a lens.

## Add a tech file

A tech file says what a stack changes that is **not** true of web apps generally. If a line would be
equally true of a Django app, it belongs in a class playbook, not here.

1. Copy the eight-section spine from `playbooks/tech/_shape.md`.
2. Create `playbooks/tech/<stack>.md`. Keep it under ~120 lines — longer means it has stopped being
   stack-specific.
3. Fill **both** directions: what the stack makes more likely *and* less likely. The second is the
   half everyone omits and it saves the most time.
4. Add one row to `playbooks/tech/_index.md` (written table) and one to `class-signals.md`.
5. Remove the stack from the `_index.md` backlog.
6. `python3 tools/self-check.py` — it verifies every tech file is named in both catalogues.

**No CVE lists and no payload dumps.** Point at where advisories are published;
`research-component` does the lookup, and payloads live in `playbooks/vulns/ref/`.

## Add a recon skill

1. Choose the narrowest category in `skills/README.md`, then create
   `skills/<category>/<name>.md`. Use `skills/know-your-target/http-probing.md` as the model and follow the shape the
   tests enforce: framing blockquote → `## Objective` → `## Inputs` → `## Signals` →
   `## Known traps` → `## Outputs` → `## Exit criteria` → `## Next`.
2. Add YAML frontmatter (`name`, `description`) — the description is what a runtime matches on.
3. Write a real `## Inputs` section naming **`@roles`, never literal paths**. `preflight.py`
   parses it; hedge optional inputs with "optional" or "if" **inside the role's own qualifier**,
   because the hedge is scoped to the clause, not the bullet.
4. If the skill produces a new artifact, add its role to the `## Input roles` table in
   `target-schema.md` — that table is the authority for what a path is called, and the only
   place it is named.
5. Add the template stub under `targets/_template/recon/` if it emits one.
6. Add one routing signal to `class-signals.md`. **Do not touch a dependency graph** — there
   isn't one to edit; `tools/graph.py` computes it from your `## Inputs`.
7. Create the runtime pointer at `.claude/skills/<name>/SKILL.md` — frontmatter plus one line
   pointing at the categorized body. `self-check.py` asserts the two agree and rejects duplicate
   slugs anywhere in the nested tree.
8. **No flag lists, no invocation templates.** `skills/shared/_recon-method.md` owns tool correctness;
   your file owns the objective, the signals and the traps. A test enforces this.
9. Run `python3 -m unittest discover -s tests` and `tools/self-check.py`.

The slug is the identity; there is no numbering. The new skill must be reachable from evidence and inputs,
not simply appended as “the next step.”

## Add a flow

A flow answers “I am looking at this situation—what now?” It references existing phase/workflow
procedures and does not duplicate them.

1. Create `playbooks/flows/<name>.md` with all seven sections: Situation, Preconditions, Steps,
   Aborts, Cost, Output and Exit.
2. Add one row to `playbooks/flows/_index.md` and `class-signals.md`.
3. If structured evidence can prove the situation, teach `suggest-flows.py` to detect it.
4. If it cannot be proven mechanically, name the human observation that would settle it instead of
   adding a guess.
5. Confirm the flow never sends a vulnerability payload and stops when its premise becomes false.

## Tune scope behavior carefully

`tools/scopelib.py` is the shared parser. Keep these concepts separate:

- `enumeration_roots()` returns assets that may be widened through discovery;
- `authorises()` decides whether a concrete asset may be touched.

An exact host authorizes itself; it must not silently become an estate root. Platform domains belong
in `PLATFORMS` so a program URL is not mistaken for the program's asset.

These answer *what did the hunter name?* — they do not gate execution. Nothing in this workspace
refuses a skill because scope looks ambiguous (`AGENTS.md` §*Scope is the hunter's*); a tool that
did would be re-adding the policy engine `run.py` deliberately dropped.

What must not soften is the **unresolved** state. If a new input shape cannot be classified, say so
explicitly and let the hunter decide — never guess a default and never report a confident zero. The
rule is *fail loud*, not *refuse*.

## Re-evaluate a skill from local knowledge

`knowledge/` is a simple, gitignored input directory. Put reports, research, notes, experiments, or
other useful material under a subject matching the skill/playbook you want to review:

```text
knowledge/javascript-analysis/research.md
knowledge/idor-bola/report-123.md
```

Then say *"Re-evaluate the javascript-analysis skill using knowledge/javascript-analysis"* or
*"Re-evaluate the IDOR playbook using knowledge/idor-bola."* That invokes
`skills/maintenance/ground-a-playbook.md` and performs one bounded loop:

```text
new/changed knowledge -> compare with one destination -> KEEP or IMPROVE -> verify -> record -> STOP
```

The model reads only new or changed files, keeps the existing method when the material adds nothing
reliable, and edits only when it finds a transferable improvement. `knowledge/MINED.tsv` stores the
local source and destination hashes so later passes read only the delta. The sources and manifest
remain gitignored and are never loaded during a hunt.

See `knowledge/README.md` for the two user commands. Source-specific HackerOne fetching and citation
checks are optional helpers under `knowledge/tools/`; they are not required to use this feature.

## Preserve these invariants

| invariant | why |
|---|---|
| `missing` ≠ `0` ≠ `prose` | collapsing them creates confident false negatives |
| append-only evidence and run ledgers | overwriting destroys contradictions and limitations |
| coverage includes principal and variant | one probe must not mark a class complete |
| run opens before traffic | interruptions remain visible |
| `CLAUDE.md` only points to `AGENTS.md` | duplicated rules drift |
| raw bulk remains remote; curated brain remains local | context stays usable without losing reproducibility |
| tools compute/refuse; playbooks reason | deterministic and judgment layers remain auditable |

## Documentation responsibilities

- Update [TOOLS.md](TOOLS.md) for a new or changed executable.
- Update [FILEMAP.md](FILEMAP.md) for every new file and load tier.
- Update [README.md](README.md) when setup, daily hunter behavior, or a public architectural
  explanation changes.
- Update [AGENTS.md](AGENTS.md) only when the runtime contract or router changes; do not duplicate
  its rules in another document.
- Run `python3 tools/self-check.py`, `python3 tools/graph.py --check`, and the regression suite
  before publishing a change. Repeat the verification section in `vps-setup.md` when the VPS
  toolchain or execution harness changed.
