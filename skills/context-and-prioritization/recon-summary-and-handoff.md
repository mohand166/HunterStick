---
name: recon-summary-and-handoff
description: What changed, what it covered, and what it could not see. Use for "recon summary and handoff" and closely related asks.
---

# recon-summary-and-handoff — what changed, what it covered, and what it could not see

> Read `skills/shared/_recon-method.md` first. This skill sends **no traffic**: it reconciles the brain
> against itself and writes the handoff.
>
> **This is a test of your ability to state coverage honestly under pressure to sound finished.**
> Summarise **what changed, not what exists** — a restatement of totals is bookkeeping and reads as
> progress, which is worse than saying nothing.
>
> The value is that the next skill can write its own `--limitations` from something *observed*
> here. A handoff that leaves the next run guessing at its own blind spots has done nothing.

## Objective

Turn the accumulated corpus into one coherent picture: the delta since the last handoff, every
claim carrying its coverage qualifier, an explicit statement of the dimensions the evidence could
not speak to, and a shortlist of where testing should start with a pointer for each.

## Inputs

The whole brain, not one file — and **this skill degrades rather than blocking**: run it on
whatever exists and say what was thin.

- `@target` and `@scope` — the narrative to update and the boundary every claim sits inside.
- `@surface` (optional, from `derive-properties`, ranked by `attack-surface-prioritization` if it
  ran) — the testable inventory, and its `undetermined` columns, which are half of this skill's raw
  material. Absent, the honest headline is that no testable surface exists yet.
- `@clusters` (optional, from `host-correlation-and-clustering`) — so counts are stated in assets as
  well as in names.
- `@hypotheses` (optional, from `generate-hypotheses`) and `@tested` (optional, from `vuln-hunt`) —
  the backlog and what is already resolved.
- The run ledger and the observation ledger via `kb.py` — selectors, statuses, limitations and
  resume-from pointers. **This is the only place the coverage qualifiers actually live**; a summary
  written from the data files alone will invent them.
- The `index.md` manifest — the counts to reconcile the files against.

## Signals — what to come back with

1. **The delta since the last handoff.** New assets, resolved gaps, contradicted facts, runs that
   failed. On an estate handed off before, the delta is the finding and the total is bookkeeping.
2. **Every count with its denominator, its selector and its date.** A run that covered 5,993 of
   35,426 hosts and says so is good work; the same run reported as "the estate" is a false claim of
   coverage that every later decision inherits, silently, forever.
3. **The blind dimensions, stated as such.** "No authenticated session exists, so role, tenancy and
   state-machine properties are undetermined across the whole surface." "No request bodies were
   captured, so mass-assignment could not be assessed anywhere." These sentences are the difference
   between a thin picture a hunter reads correctly and a thin picture that looks complete.
4. **Which sources ran and which could not.** Key-gated sources carry a measurable share of the
   yield — on one apex, dropping three of them took the result from 854 names to 559, a 34.5% loss.
   That gap is knowable, so it belongs in the limitations rather than in the unknown.
5. **Runs that ended partial or failed, with their resume-from pointers.** A run is never globally
   done; it completes for its selector. An unclosed run is a hole in the coverage story.
6. **Contradictions between artifacts**, flagged rather than reconciled silently — manifest counts
   that disagree with the files, an orphan pointer, an in-scope host with no coverage at all.
7. **The shortlist handoff.** Where testing should start and why, each entry pointing at a
   hypothesis id and the skill that would test it.
8. **The `--limitations` sentence itself**, written out verbatim so the next run can paste it. If
   you cannot write that sentence from something observed, this skill has not finished.

## Known traps — each of these turns an honest run into a false claim

- **"The estate."** The single most expensive phrase available here. Every later decision inherits
  an unqualified count as though it were coverage, and nothing downstream can recover the
  qualifier once it is dropped.
- **`missing`, `0` and prose are three different states.** A missing file is a precondition failure
  for whatever needs it; an empty one is a real, disappointing result; a prose note is neither.
  Rendering them the same way is how a gap becomes a fact.
- **A stage killed by its own timeout reads as success.** In a pipeline the exit status belongs to
  the last command, so a killed producer feeding a happy consumer reports zero and exits clean.
  Check for it explicitly before summarising any zero.
- **Silent caps in the standard tools become silent caps in your summary.** subfinder's overall
  time limit truncates a large enumeration and exits cleanly; httpx's HTTPS-to-HTTP fallback yields
  one scheme per host, so an HTTP-only admin panel on a dual-scheme host is simply absent; a
  resolve-and-discard inside enumeration deletes the non-resolving names that are the takeover
  signal. If a cap ran, the number it produced is a sample and must be labelled one.
- **This skill produces no new facts about vulnerabilities.** It organises existing ones. A
  well-argued hypothesis is still a hypothesis, and the evidence gate is unchanged.
- **Do not hand-copy counts.** Derive every number from the files (as `tools/brainlib.py` and the
  live console do) and stamp the summary with its generation time. Hand-copying counts
  reintroduces exactly the drift the parsers exist to catch.
- **A confident summary is not a source.** Where the underlying research is unsourced or two
  sources disagree, carry the disagreement forward. A handoff that reads as unanimous when its
  inputs were not is more dangerous than one that shows its seams.
- **Do not launder a lead into a finding by summarising it.** Prose compresses "an unauthenticated
  endpoint was observed" into "an unauthenticated endpoint exists" without anyone deciding to.

## Outputs

- `@target` — the coherent picture: architecture, stack, auth model, tenancy, the anomalous
  surfaces, each claim tagged as observed or inferred.
- `index.md` — a true manifest: counts that match the files, no orphan pointers, the VPS location,
  the last-updated stamp.
- A **handoff block** — the top leads, each with its hypothesis id and the skill that tests it, and
  the explicit list of dimensions no evidence could speak to.
- `@hypotheses` tidied: every lead has a class, a rationale and a status.
- The run closed via `kb.py` with `--sources`, `--result` and `--limitations`, plus a `--resume-from`
  pointer wherever something ended incomplete.

## Exit criteria

Every count in the summary carries a denominator, a selector and a date. The blind dimensions are
stated explicitly, not implied by omission. Every open run is closed or has a resume-from pointer.
The manifest and the files agree, or the disagreement is written down. The next skill's
`--limitations` sentence exists verbatim in the handoff. Gaps are handed off as gaps. No testing
was started: the hunter picks what happens next.

## Next

Offer: `attack-surface-prioritization` (rank the picture, only if the hunter wants the model to
choose) · `vuln-hunt` on one shortlisted lead · whichever recon skill the blind dimensions named —
usually `application-mapping` for the role and tenancy dimensions, or `api-discovery` for operation
granularity · `monitoring-and-diff` (cheap, unattended, so the estate stops going stale between
sessions).
