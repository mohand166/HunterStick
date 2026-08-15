---
name: runbook
description: Execute the target's saved standing order — the hunter's pre-approved evening (or morning) sequence in runbook.md — as ONE authorized bundle ending in a single consolidated brief. Use for "run the runbook on acme", "run my evening runbook", "execute the standing order", "do the usual pass", or any request to run the target's saved recurring bundle. The sequence is pre-authorized; each step still runs its own lifecycle; it proposes hunts, never starts one.
---

# Run the standing order — one bundle, one brief

> The difference from `run-flow`: a **flow** is the workspace's response to a *situation*; a
> **runbook** is *the hunter's own* saved sequence for this target, edited over time in
> `runbook.md`. The difference from `compose-task`: compose decomposes a novel one-off; a
> runbook is persistent and re-runnable. What all three share: one human decision authorizing a
> bundle, steps that keep their own contracts, and a STOP at the end.

## Inputs

- `@scope` — the runbook's steps run against this target's brain.
- `targets/<t>/runbook.md` — **the standing order itself.** If it does not exist, say so and
  stop; a runbook is written by the hunter (copy `targets/_template/runbook.md`), never
  generated mid-run. Offer to help draft one from what the brain shows is stale — drafting is
  proposing, and they approve the file before it ever runs.

## First command, always

```
tools/runbook.py targets/<t>
```

It validates the file (every step names a real skill, flow, tool step, or the closing action) and
prints the ordered plan **with live state** — which steps are ready, which are blocked on a
required input, which mechanical conditions (`components-present`) are not met and will be
skipped. A runbook that fails validation stops here: the hunter edits the file; you do not
improvise a substitute step.

## The contract

1. **The sequence is pre-authorized; nothing else is.** Run the steps in order. You may not add,
   reorder, or drop steps mid-run — a step that should change is a hunter edit to `runbook.md`.
2. **Each step keeps its own contract.** Open its run, work it to its exit criteria, persist its
   delta, exactly as if it had been invoked alone. A step blocked on a required input stops that
   step — name the producer, record it, continue with the rest, and say it in the brief.
3. **A skipped condition is stated, not silent.** `when` not met → the step is skipped and the
   brief says which and why.
4. **Never start a hunt.** Recon, analysis, prioritization, monitoring reconciliation — yes.
   `vuln-hunt` appears in the closing brief as a *proposal* with cost and expected gain, or the
   runbook's purpose has been exceeded.

## The closing brief — the deliverable

One consolidated report, written as the final step:

- **What changed since the last runbook run** — merged deltas from every step, not per-step
  restatements. Monitor deltas reconciled, advisories found, surfaces re-ranked.
- **The re-ranked top entrypoints** with staleness — what is worth hunting, with the age of the
  recon behind each.
- **Decisions worth the hunter's time** — 2–3 conditional next actions, each with cost, risk,
  prerequisite and expected gain. This is where a hunt is *proposed*.
- **One digest notification** — `tools/notify.py send <t> --event runbook-digest --title ...`
  with the brief's first line. One ping, never one per step.

## Exit criteria

Every step ran, was skipped-with-condition, or stopped-blocked — the three-way split is stated.
The consolidated brief exists with the re-ranked surface and the proposed (not started) hunts.
The digest was sent or its absence stated. Then **STOP**.

## Next

Offer, do not choose: the brief's own 2–3 proposals · `vuln-hunt` on the top-ranked entrypoint if
the hunter picks one · editing `runbook.md` if tonight's run showed a step that no longer earns
its place — the runbook should be tuned, not endured.
