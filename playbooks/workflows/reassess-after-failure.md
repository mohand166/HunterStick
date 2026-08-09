# Reassess After Failure

> Process helper. A test failed, or came back inconclusive. Record it honestly, then make
> a clean-headed call: go deeper on the same lead, or pivot. The enemy here is sunk cost —
> hours already spent are not evidence the bug exists. A negative result is a *real
> result*; log it so you never re-chase it.

## Objective
Update the brain with the failed/inconclusive result and make an evidence-based decision:
sharpen and retry, escalate to a deeper investigation, or pivot to a higher-value lead.

## When to use
- Immediately after any active test that returned not-vuln, inconclusive, or a false
  positive you filtered out.
- When you notice you're grinding one lead past the point of diminishing returns.

## Inputs
- What you just did and actually observed (the real response — no narrated output).
- The hypothesis from `hypotheses.md` and its discriminator from the test design.
- `tested.md` — the running dedup log.
- `attack-surface.md` / `hypotheses.md` — the other open leads competing for your time.

## Process
1. **Record the result first, honestly.** Write the `tested.md` row: date, target,
   class, method (what you actually did), `result` (not-vuln / inconclusive / out-of-scope),
   `fix_locus`, and `artifact_ptr`. If nothing was proven, it is not a FACT-of-vuln — say so.
2. **Classify the failure.** Which was it?
   - **Disproven** — the discriminator said FALSE cleanly. The hypothesis is dead. Note it
     in `findings/rejected/` so it's never re-chased. Set `hypotheses.md` status = rejected.
   - **Inconclusive** — the signal was ambiguous (WAF, jitter, cache, partial data). The
     *test* was weak, not necessarily the hypothesis. Candidate for a sharper retry.
   - **Wrong assumption** — an ASSUMPTION the test rested on was false (ids weren't
     sequential, the role wasn't what you thought). The hypothesis may need reframing.
3. **Decide: go deeper or pivot** — on evidence, not on time invested.
   - **Go deeper** only if there's a concrete reason: a specific untested variant, a
     sharper discriminator (`design-validation-test`), or a nearby sink the failure
     revealed. Name the *new* thing you'd do — "try again harder" is not a reason.
   - **Pivot** if the lead is disproven, if going deeper is just repetition, or if a
     higher-value / more-novel lead is waiting. Cheap to abandon a dead lead; expensive to
     marry it.
4. **Watch for sunk cost.** If your only argument for continuing is effort already spent,
   pivot. If the hypothesis keeps needing new assumptions to stay alive, it's probably dead.
5. **Salvage the by-catch.** A failed test often reveals real facts (a new param, an error
   format, an unexpected behavior). Promote those to the brain / new hypotheses even when
   the original lead dies.

## Output
- `tested.md` — the honest result row with `fix_locus`.
- `hypotheses.md` — status updated (rejected / back to open with a sharper note).
- `findings/rejected/` — a short note for cleanly disproven leads, so they stay dead.
- Any by-catch promoted to `hypotheses.md` / the app map / `target.md`.
- `index.md` — counts + phase log + timestamp.
- Summarize: what failed and why, the decision (deeper vs. pivot) with its reason, and the
  next lead you'd pick. Then **STOP** — the human confirms the next move.
