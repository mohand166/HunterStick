---
name: run-flow
description: Run a named flow — a bundled response to a situation — against the bug bounty target the human names. Use for "what should I run on X", "what now", "suggest a flow", "this host returns 404 on everything", "the host is a dead end", "no signup on this target", "this is a JS app / SPA", "there's an OpenAPI spec", "we have thousands of hosts", "this looks like a static site", "I'm coming back to this target after a while", "everything returns 200 / soft-404", or any request to run a multi-step recon bundle in one command. Two intents: "what should I run?" recommends and stops; a named flow runs without asking again. Always declares steps and cost first; a missing required input is the one hard stop; never sends a payload.
---

# Run one flow

A **flow** is a named response to a *situation*, not a phase sequence. Read
**`playbooks/flows/_index.md`** for the contract and the situation table, then the ONE flow file.

## Inputs

- `@hunter.flow` — **the flow to run**, when they named one. If they described a *situation*
  instead, this is absent by design: match the situation, recommend a flow, and stop.
- `@scope` — the flow's steps run against this target's brain.
- Every input of the skills the flow bundles. A flow does not exempt a step from its own
  contract: a step whose required input is missing stops there and names the skill that produces
  it, rather than silently skipping.

## Which flow

```
tools/suggest-flows.py targets/<t> --why
```

It proves the situations it can from structured data and **names the ones it cannot** — four of the
ten need someone to look at a live response. Take its `START HERE` unless the human named a flow;
they may always override, and their choice wins without argument.

If the human describes a situation in their own words, match it against the table in `_index.md`.
If nothing matches, say so and run the single phase that fits — **do not stretch a flow to cover a
situation it wasn't written for.**

## The contract — this is why a flow doesn't break "one skill, then stop"

1. **Two intents, two behaviours — read which one you were given.**
   - *"What should I run on acme?"* · *"this host 404s everything"* — they are asking for a
     recommendation. **Name the flow, print its steps, cost and abort points, and stop.** Choosing
     is theirs.
   - *"Run the dead-end flow"* · *"run first-look on acme"* — **they already authorised that
     bundle.** Print what it will do, then **run it**. Asking again for permission they just gave
     is friction, not safety, and it trains a hunter to ignore the confirmation that matters.

   Either way, print the steps first. A flow that starts *while* describing itself is a pipeline;
   a flow that describes itself and then runs what was named is the bundle they asked for.
2. **Abort points**, mid-flow, not just at the end — one is a hard stop, the rest are carried
   forward, not vetoes:
   - **a required input missing** — the one **hard stop** (the admission gate): name it, name the
     skill that produces it, stop. An *optional* input missing just narrows that step.
   - **calibration** — soft-404/catch-all makes every count downstream fiction. Repair it, or
     carry the limitation forward explicitly onto every number the flow reports.
   - **accounts** — a step needing ≥2 usable principals with fewer available parks the rest as
     `coverage = blocked (needs-account)`; it never substitutes a one-account test, because a
     single-account "no finding" on an authz class is a false negative dressed as a result.
   - **cost** — a fan-out step with no selector runs a pilot, reports yield and projected cost,
     and lets them choose "all" with their eyes open.
   - **premise falsified** — you entered `dead-end-host` and found a sitemap. **Stop.** The
     situation changed, so the flow is the wrong one. This is the abort that gets skipped.
3. **No flow sends a payload.** Flows do recon, mapping and triage, then hand entrypoints to
   `vuln-hunt` — one entrypoint, one class, human in the loop. Testing is where the traffic is.
4. **Report per step, not just at the end.** Each step says what it found and what it changed about
   the plan. A flow that goes quiet for six steps is indistinguishable from a scanner.

## After
Write outputs into the brain as each step's own skill file specifies, update `index.md` (counts,
VPS raw pointer, timestamp, one bounded run in `runs.tsv` per step), then **STOP** with at most 3
next actions, each citing a fact from this run. The flow's own sequence is already authorized, so
these are **deviations the hunter should hear** — a premise that aged, a step that no longer earns
its place — not a restatement of the flow's next step. `tools/dashboard.py targets/<t>`
regenerates the one-screen view.

**Report the compression, not the volume.** "3,918 hosts → 6 clusters → these 3" is the useful
sentence; a list of everything found is the thing the human already could not read.
