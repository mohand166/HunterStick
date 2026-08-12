---
name: init-target
description: Scaffold a target brain from the hunter's verbatim scope statement. Use for "initialize a new target", "start a new program", or any requested work naming a target that has no directory yet. Records the scope verbatim, never expands a company name into domains, then STOPS.
---

# init — Target Initialization (the entry to the graph)

> **This is a test of your ability to stand up a complete, schema-correct engagement brain and
> collect every input the rest of the graph depends on — before a single packet is sent.** From
> first principles: a target folder is the memory that survives context loss, so every path it
> promises must exist and every unknown must be *visible* rather than blank. The value is a
> knowledge base a cold session can read and act on — not a folder that looks right.
> Bootstrap phase. Do exactly this, then write outputs → append to `targets/TARGETS.md` → summarize
> → **STOP**. You send **no traffic to the target**, and you do not run the recon phase you just
> identified — you name it and let the human choose.

## Objective
Turn "Initialize a new target XYZ" into `targets/<slug>/`: a full copy of the template that matches
`playbooks/system/target-schema.md`, seeded with the program, scope, ROE, and account facts every later
phase reconciles against, with all unknowns recorded as explicit blockers.

## Mode
Local filesystem + one interview round. **No target traffic. No VPS provisioning.** WebFetch of the
public program page is allowed only if the human asks you to pull the scope now.

## Inputs
- The target name the human said (`XYZ`).
- `targets/_template/` (the canonical skeleton).
- Whatever the human volunteers up front (scope, program URL, ROE, accounts) — do not re-ask for it.

## Process

**1. Preflight — fail loud, never overwrite.**
- Slugify: lowercase, spaces/dots → `-`, keep `[a-z0-9-]`. `Acme Corp.` → `acme-corp`.
- If `targets/<slug>/` **already exists**: STOP. Say so, show its `index.md` Status block, and offer
  *resume* (read the manifest) or *a different slug*. Never merge into or clobber an existing brain.
- Confirm `targets/_template/` exists and is non-empty. If not, STOP — nothing downstream is valid.

**2. Scaffold.**
```
cp -R targets/_template/ targets/<slug>/
```
Then **assert** the copy: every static file and directory named in `target-schema.md` §Local layout
is present (`scope-evidence.md`, `recon/*.md` stubs, `clusters.md`, `attack-surface.md`,
`hypotheses.md`, `tested.md`, `applications/`, `investigations/`, `findings/{draft,confirmed,rejected}/`,
`raw/`). A partial copy is a **failure**, not a warning — report and stop.

*The `recon/*.txt` list files (`subdomains`, `live-hosts`, `urls`, `parameters`) are deliberately
**absent**: a missing input file must stay a loud preflight failure for the phase that needs it. Do
not create empty placeholders (`vps-execution.md` §Command robustness).*

**3. Interview — one batched round, then stop asking.**
Ask only for what later phases genuinely block on. Use the runtime's structured question tool when
one exists; otherwise ask the same batch in one chat message:
- **The scope itself** — whatever form they have it in: a company name, a wildcard, a host list, a
  pasted scope table, a URL. **Do not ask them to restate it in your format.** What they say goes
  into `scope.md` verbatim, and its *shape* decides where the graph starts —
  `phase-routing.md` §1. Also ask for exclusions and out-of-scope classes if they have them;
  record `exclusions: none stated` if they do not, which is a different fact from `none`.
- **Program URL** — so the scope can be re-checked later against the source.
- **ROE knowns** — the program's rate limit, and the required header **if this program differs**
  from the workspace default. Identity and VPS are *machine-level*, not per-target: they live in
  `config.json` (`researcher.*`, `vps.*`). Do **not** re-ask for them — run
  `tools/config.py check` and report anything unset as a blocker instead.
- **Accounts** — self-register allowed · provided · none. `none` **blocks** authz/IDOR/multi-tenant
  /privesc testing (`phase-routing.md` §3 accounts gate) — record that consequence, don't just note it.

If the human answers "I don't know" / skips, that is a legitimate answer — record it as a blocker.

**3b. Classify the scope, and disambiguate before you write it.**
The shape of the scope statement decides the entry point, so a misread here mis-routes everything
after it. Run the classification in `phase-routing.md` §1 and act on the result:

- **One reading fits** → write it and **state the reading**: *"Reading `*.acme.com` as a wildcard
  apex → entry point `subdomain-enumeration`."* One sentence, in the exit summary.
- **Two readings would send different traffic** → **ask, before writing `scope.md`.** The common
  ones, with the question to ask:
  - a bare domain (`acme.com`) → *apex to enumerate, or that one host?*
  - a brand name → *the whole company including acquisitions, or one application?*
  - a program URL → the platform is **not** the target. Read the scope from that page, or ask them
    to paste the in-scope table. **Never enumerate `hackerone.com` / `intigriti.com`.**
  - a URL with a path → *this endpoint only, or map the app around it?*
  - "everything they own" → confirm ownership is the test, and that each discovered domain needs
    proven ownership before it counts.
- **No scope at all** → ask once, to *record* the subject — not to authorise it. A target whose
  `scope.md` is an empty placeholder is worse than no target, because it looks ready while carrying
  no record of what the hunter is actually testing; that record is what later sessions route and
  reason on, and where standing constraints live.

**Ownership-based and prose scopes are legitimate** — write them verbatim rather than reducing them
to a domain list. `scope.md` is read by a human and a model, not parsed by a regex; the tools that
do parse it (`monitor.py`, `import-http.py`, `sweep.py`) say plainly which exclusions they cannot
enforce.

**4. Seed the files.** Write what you were told, verbatim where it matters:
- `index.md` — Program · Scope type · Archetype · ROE quick card · Engagement started
  (today) · **Last activity** = `init-target — scaffolded` · **Awaiting** = `hunter choice`
  · a row in the Bounded runs table for `init`.
  **Do not write "phase X pending".** Name the derived entry phase in the exit summary as a
  *conditional next action*; the manifest records what happened, not a queue position.
- `scope.md` — **the scope they gave you, verbatim**, plus exclusions, out-of-scope classes, the
  program URL and today's date under Source. This is the authority every later phase reconciles
  against; there is no separate review step that fills it in later.
- `scope-evidence.md` — who supplied the statement and when; the program URL; and, if the human
  pasted policy text or asked you to fetch it, the exact captured text plus its SHA-256. If no
  policy snapshot exists, record that plainly. The human's statement remains the authority.
- `accounts.md` — the registration policy and what it blocks.
- `target.md` — org name and business if known, tagged `[ASSUMPTION]` until confirmed.

**Unknowns are written as `TBD — blocking: <what it blocks>`, never left blank or invented**, and
every one is also listed under `index.md` §Blocking/TBD. A blank field silently reads as "fine";
a named blocker doesn't.

**4b. Derive the mechanical allowlist — tools refuse without it.**
The verbatim statement is the authority, but no tool can match a sentence. Under
`## Mechanical allowlist` in `scope.md`, fill `### In scope` and `### Out of scope` with one
domain per line, derived *visibly* from what they told you:

```
### In scope
- *.acme.com
### Out of scope
- admin.acme.com
```

- **Derive, never invent.** Only hosts the statement actually covers. A company name yields **no**
  entries until `01` discovers roots and the human confirms ownership — leave the placeholder
  and record it as a blocker.
- **Never collapse an exclusion to its apex.** `admin.acme.com` excluded means that host, not
  `acme.com`.
- **Non-domain exclusions** ("divested brands") go in as prose. `monitor.py` names them and refuses
  to probe actively until you acknowledge no job can enforce them.
- Verify with `tools/scopelib.py`-backed tools: `tools/suggest-flows.py targets/<t>` will say
  plainly if the section is still a placeholder.

**Leaving it unfilled is a legitimate outcome** when the scope is a company name — say so as a
blocker. What is not legitimate is filling it with a guess.

**4c. Let the tool do the writing.** You conduct the interview; `tools/init-target.py` performs
the scaffold. Asking good questions is judgement; copying a directory and editing nine files
correctly is not, and a half-finished brain reads as a complete one.

```
tools/init-target.py "<name>" --scope '<verbatim statement>' \
    [--exclude <host>]... [--program <url>] [--accounts self-register|provided|none] --dry-run
# read what it will write, then re-run with --yes
```

It is **atomic** (builds in a temp dir, renames into place — an interrupted run leaves nothing),
**refuses to overwrite** an existing target, stores the scope **verbatim**, derives the mechanical
allowlist *only* from a domain-shaped statement, records the missing answers as
`TBD — blocking:` and appends the registry row. It sends no traffic.

If the scope is a company name it deliberately leaves the allowlist a placeholder — and
`preflight.py` then blocks every phase until you fill it. That refusal is correct: inventing
hostnames from a brand name is exactly the inference this workspace forbids.

**5. Register.** If `targets/TARGETS.md` does not exist, copy
`targets/TARGETS.example.md` to it. Append one row (target · program · archetype · status ·
last touched). **There is no active-target pointer to flip** — every other target stays exactly as
it was, and the next skill runs against whichever target the human names.

**6. Sanity-check the brain, then stop.** Re-read the new `index.md` cold: does it alone answer
*which target, which phase, what's blocking, what to run next*? If not, fix it before summarizing.

## Outputs
- `targets/<slug>/` — complete, schema-matching, seeded with the interview answers.
- `targets/TARGETS.md` — one registry row appended. Nothing else changes.
- A summary: what was created, what is `TBD — blocking`, and the conditional next actions.

## Exit criteria / handoff
- Every schema path exists; no invented facts; every gap is a named blocker.
- Return **2–3 conditional next actions** (cost · risk/ROE · prerequisite · expected gain) per
  `phase-routing.md` §4 — normally:
  - **The entry phase you derived from the scope shape** (`phase-routing.md` §1) — a company name
    starts at `organization-and-roots`; a wildcard apex at `subdomain-enumeration`; one host at
    `07` then `17`/`12`. Name it, with its cost and prerequisites.
  - **The account work**, if `accounts.md` says none — it blocks every two-principal class, so it is
    often the highest-value thing to do before any scanning.
  - **A cheap orientation pass** if the scope is a single app — `application-mapping` needs a
    browser and accounts; `api-discovery` may hand you the whole contract for free.
- Then **STOP.** Do not run the phase you named. The human picks.
