# Generate Hypotheses

> Process helper. Turn recon / attack-surface into **specific, testable** hypotheses in
> `hypotheses.md` — then STOP for the human to pick what gets tested. You are converting
> "this looks interesting" into "if X, then observing Y proves it." A vague hypothesis
> can't be tested and can't be deduped; a specific one can.

## Objective
Produce a ranked backlog of concrete, falsifiable hypotheses in `hypotheses.md`, biased
toward business-logic / novel / deep-understanding angles, each one naming a specific
target, a vuln class, and a rationale tied to an observed FACT.

## When to use
- After `attack-surface-prioritization` when you want more (or deeper) hypotheses than
  the top-slice it seeded.
- After an `investigate-endpoint` / `investigate-asset` / `read-response-signals` pass
  that surfaced new leads worth writing down as testable ideas.
- Any time the backlog is thin, stale, or scanner-shaped and you need better leads before
  active testing.

## Inputs
- `attack-surface.md` — the ranked inventory (start from the top).
- `recon/endpoints.md`, `recon/parameters.txt`, `recon/js-findings.md` — the surface.
- `applications/<host>/map.md` — roles, trust boundaries, workflows (the richest source).
- `target.md` — architecture, stack, acquisitions, known auth model.
- `tested.md` — what's already been tried (don't re-seed a dead lead).
- `scope.md` — in-scope classes and out-of-scope noise to skip. Rank on reachability, impact and
  novelty — **never on bounty**.

## Process
1. **Orient from the brain.** Read the inputs above. You are not starting cold — the
   ranked surface and app map already tell you where the value is.
2. **For each high-value asset, ask "what could go wrong here?" per class** — but only
   where the *surface for that class is actually present*. A tenant boundary invites
   IDOR/authz; a URL-fetch feature invites SSRF; a multi-step flow invites workflow abuse.
   Don't enumerate every class against every param — that's scanner thinking.
3. **Write each hypothesis specific and falsifiable.** Not "maybe IDOR." Rather: "H-007 ·
   `GET /api/v2/org/{id}/invoices` · IDOR · `id` is a sequential tenant identifier and per
   the app map authz is self-built; if the check is missing, requesting another org's id
   with account A's token returns account B's invoice." State the target, the class, the
   mechanism, and — implicitly — the discriminator you'd look for.
4. **Bias to depth and novelty.** Prefer business-logic, chained, and
   deep-app-understanding hypotheses over scanner-class fruit. A hypothesis nobody else
   modeled (because it requires understanding *this* app's flow) is worth ten "missing
   header" leads. Deprioritize classes the program lists as low-value or out-of-scope.
5. **Dedup against `tested.md` by fix-locus.** If a hypothesis would be fixed by the same
   code change as something already tested, don't re-seed it — go deeper or drop it.
6. **Tag your reasoning.** The rationale rests on FACTs (observed in recon) plus
   HYPOTHESIS (the untested mechanism); keep ASSUMPTIONs explicit so they can be challenged
   during testing.

## Output
- `hypotheses.md` — new rows appended, schema `id | target | vuln_class | rationale |
  status | evidence_ptr`, `id` continuing the H-NNN sequence, `status = open`,
  `evidence_ptr` empty until tested. Ordered so the human reads the highest-value,
  most-novel leads first.
- `index.md` — updated hypotheses count and bounded run in `runs.tsv`, timestamp.
- Summarize: how many hypotheses added, the top few you'd test first and *why* (lead with
  the novel/deep angle), and any surface you deliberately skipped. Then **STOP** — the
  human picks which hypothesis becomes an active test.
