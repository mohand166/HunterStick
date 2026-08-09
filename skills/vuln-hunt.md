---
name: vuln-hunt
description: Hunt a specific vulnerability class (or family) on one entrypoint of the bug bounty target the human names. Use for "test for SQLi/XSS/IDOR/SSRF/XXE/CSRF/SSTI/RCE", "hunt <class> on <url>", "check access control / authz / BOLA", "look for business logic bugs", "test the login/password reset/OAuth flow", "race condition", "prototype pollution", "cache poisoning", "subdomain takeover", "GraphQL/API testing", "client-side injections", "server-side bugs", or any request to actively test a target for a vuln class. One entrypoint, one class at a time, evidence-backed.
---

# Hunt one vuln class on one entrypoint

## Inputs

- `@hunter.class` — **the vuln class or family to test.** A family selects the classes inside it
  whose surface is present; it is not licence to sweep everything applicable.
- `@hunter.entrypoint` — **the one entrypoint to test it on.** "The whole estate" is not an
  entrypoint; ask which one.
- `@accounts` (optional, from `init-target`) — required *by specific classes*, not by this skill.
  An authz class comparing two principals says so at the moment it needs them and stops there; a
  single-account "no finding" on BOLA is a false negative dressed as a result.
- `@surface` (optional, from `derive-properties`) — the entrypoint's observed properties, which
  say which other classes apply. Used to **suggest**, never to widen what you test.
- `@tested` (optional) — so a variant already resolved is not re-run as if new.

## What to read, in this order

1. **`playbooks/vulns/_master-vuln-hunting.md`** — the reasoning loop. Always, for every class.
   **It carries the whole procedure**: orient from the brain, enumerate every class the surface
   fits, understand the function, form a hypothesis, design the minimal test, capture evidence,
   filter false positives, assess impact and chaining, run the novelty gate, record and stop.
   *This file does not repeat any of that* — a summary in front of the real thing is just a worse
   copy of it.
2. **`playbooks/vulns/<class>.md`** — the one class. Read in full.
3. **`playbooks/vulns/ref/<class>.md`** — *only if it exists, and only one section at a time.*

If the human named a **family** ("access control", "client-side injections", "business logic"),
resolve it via `playbooks/vulns/_index.md` and work the applicable classes **one at a time**. A
family command means "test the applicable ones", never "spray all of them". Skip classes whose
surface is not present — and say that you skipped them.

## The two-file rule

Where `ref/<class>.md` exists, the class file is the **method** and the ref is a **lookup layer**:
technique catalogues, payload shapes, disclosed-report evidence. **Do not read it up front.** The
method file carries a trigger table; open one section when the target shows you that section's
trigger. `ref/idor-bola.md` is 7,565 tokens — reading it speculatively costs attention and buys
nothing.

A ref file marked *NOT corpus-grounded* holds unverified domain knowledge: treat it as HYPOTHESIS
to check against the target, not as observed fact.

## Three things the master loop does not cover

**Suggest the classes they didn't name.** Read the entrypoint's `properties` in `attack-surface.md`,
resolve them through `class-signals.md`, and run `tools/coverage.py targets/<t> --entrypoint <ep>`
rather than eyeballing the ledger. A class marked `*` is one the observed properties imply that
attack-surface-prioritization never proposed — that is the miss worth flagging. Do the class they asked for; name the
others in your closing next actions. **Suggest, never substitute.**

**Open the run before you send anything, close it however it ends.**
```
tools/kb.py run targets/<t> --phase vuln-hunt:<class> --selector <entrypoint> --status running
tools/kb.py run targets/<t> --finish R-0NN --status complete-for-this-run|partial|failed \
    --result "<one line>" --resume-from "<exact state, if incomplete>"
```
An interrupted test that sent traffic and left no record is the one thing a later session cannot
reconstruct.

**Name the variant.** A `tested.md` row without one claims the whole class on that entrypoint —
`SQLi on POST /search` tested against `q` says nothing about `filters[name]`, an XML body hitting a
different parser, or a `/v1` handler still mounted. For authz the variant is the *relationship*
(`user-b → user-a's object`), not the account. And a resolved `not-vuln` needs an `artifact_ptr`
and a `method`, or coverage downgrades it to `partial`.

**Write the lesson, not just the result.** `tested.md` records that a probe happened, keyed by
`(entrypoint × class × principal × variant)` with its `fix_locus` — negatives included, so nothing is
re-chased. But if the outcome taught you something about the *estate* — a framework-level guard
that rules out a whole family, an auth pattern that repeats — that goes in `target.md`
§What testing taught us, plus `tools/kb.py add` for anything host-specific. `target.md` is loaded
every session; `tested.md` is not.

Then **STOP** with 2–3 conditional next actions.

## Check the stack first

If `recon/technologies.md` names a stack for this entrypoint's host, look it up in
`playbooks/tech/_index.md` before choosing how to test. A tech file changes which classes are worth
the time — and, as often, which are **not**. Testing blind SQLi against an Eloquent app or
server-side template injection against a React SPA is time the file would have saved you.

Read it in addition to the class playbook, never instead of it.

## How deep — and how you know you are done

**Not by time.** A minimum test duration rewards stalling and tells you nothing: an hour spent
resending the same payload is not deeper than five minutes spent on the right one.

A class is finished on this entrypoint when **every variant the plan named is resolved or parked**,
which is a thing `attack-surface.md` records and `tools/coverage.py <t>` computes. The coverage
cell is `entrypoint × class × principal × variant`, so:

- **naming the variants is the depth decision**, and it happens before probing, in the plan. One
  input tried against one parameter is one variant, not a tested class — that is the failure the
  `variants` column exists to prevent.
- a variant you chose not to test is **parked with a reason**, not silently dropped. Parked is a
  state; forgotten is not.
- a new technique — a bypass that worked elsewhere, a different encoding, a second parser — is a
  **new variant**, so re-running a class you already tested is not repetition. `tested.md` records
  what was probed; it never forbids probing again.

Report the resolved/parked split when you stop. "3 of 5 variants resolved, 2 parked — needs a
second principal" is a finishable state. "Tested for SQLi" is not.

