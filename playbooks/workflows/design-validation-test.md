# Design Validation Test

> Process helper. Before sending a single crafted request, design the **smallest safe
> experiment** that will prove or kill one hypothesis — and define the discriminator
> *first*. A test you can't interpret in advance is not a test; it's noise that invites
> fabricated conclusions. This is the plan; execution follows the master loop.

## Objective
Turn one hypothesis into a concrete, minimal, non-destructive experiment with a
pre-declared pass/fail signal, so the result is unambiguous and the artifact is decisive.

## When to use
- Before actively testing any hypothesis (the design step of the master vuln loop, §3–§4).
- When a prior test came back inconclusive and you need a sharper discriminator.

## Inputs
- The hypothesis from `hypotheses.md` (target, class, mechanism).
- The relevant class file (`playbooks/vulns/<class>.md`) — its "Minimal safe validation"
  and "False-positive traps" define the safe discriminating signal for this class.
- `applications/<host>/map.md`, `accounts.md`, `target.md` — the function and vantage points.
- `scope.md` — confirm in-scope and within ROE.

## Process
1. **Restate the hypothesis as if/then.** "If `sort` is concatenated into ORDER BY, then a
   benign `sort=(select 1)` reorders results without an error." No mechanism → no test.
2. **Pick the discriminating signal** — the class file names it: differential, boolean,
   timing, or out-of-band. Prefer the signal that separates true from false most cleanly
   with the least intrusion. Avoid signals a WAF/cache/jitter could fake.
3. **Define the discriminator BEFORE testing.** Write down exactly what you expect to
   observe if the hypothesis is TRUE and what you'd see if FALSE — and what a *false
   positive* would look like (reflected-but-not-executed, generic error, jitter, cache
   hit). Commit to it so you can't rationalize an ambiguous result afterward.
4. **Choose the smallest safe probe.** Non-destructive by construction: read a benign
   value, trigger a measurable-but-harmless side effect, hit your own OOB listener. Never
   DROP/DELETE, never mass/flood, never resource exhaustion, never real money/inventory.
   The minimal probe that answers the question — nothing more.
5. **Plan the exact request(s)** and how you'll capture the artifact (request + response,
   or the OOB callback log with source IP / token / timestamp). A control request is often
   worth planning too, so the diff is clean.
6. **Pre-mortem the false positives.** For each way this class fools you (from the class
   file), decide how the design rules it out — a second confirming request, a differential
   control, a unique per-test token.

## Output
- A written test plan (in the hypothesis' `investigations/<lead>/notes.md`): the if/then,
  the discriminator (true vs. false vs. false-positive), the exact request(s), the
  non-destructive rationale, and the capture method.
- No target traffic yet — this is design. Hand off to the master loop / class file to
  execute, which will send the request, observe the *real* response, and save the artifact.
- Summarize the plan and the discriminator, then proceed to execute (if the human has
  authorized active testing on this target) or **STOP** for approval.
