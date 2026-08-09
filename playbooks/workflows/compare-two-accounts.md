# Compare Two Accounts (differential method)

> Process helper. The two-account differential is the cleanest, safest way to prove
> authorization, IDOR/BOLA, and tenant-isolation bugs: hold everything constant except
> *who is asking*, and read what changes. This is active testing — run it only when the
> human has pointed you at a specific target. It is non-destructive by construction: you
> only ever *read* one account's data from the other's session.

## Objective
Use two controlled accounts to isolate authorization behavior — request the same resource
as different principals and determine, with a saved artifact, whether the server enforces
the boundary it should.

## When to use
- Testing IDOR/BOLA, function-level authorization, privilege escalation, or multi-tenant
  isolation on a specific endpoint the human authorized.
- Any time a hypothesis' discriminator is "does identity actually gate this?"

## Inputs
- `accounts.md` — at least two accounts. Ideal: same privilege level in *different* tenants
  (for isolation/IDOR) or *different* privilege levels in the same tenant (for privesc).
- The target endpoint and the hypothesis from `hypotheses.md`.
- `applications/<host>/map.md` — the trust boundary being tested.
- `scope.md` — confirm in-scope; confirm using test accounts is permitted by ROE.

## Process
1. **Set up the vantage points.** Authenticate both accounts (A and B) independently and
   capture a valid, current session/token for each. Never mix a real user's data in — use
   only the provided test accounts.
2. **Baseline as the owner.** As account A, perform the legitimate request and capture the
   resource identifier (id / slug / object ref) and the normal response. This is your
   control.
3. **Define the discriminator before you swap.** Decide *now* what a true positive looks
   like (B receives A's data / performs A's action) vs. a false positive (B gets 403/404/
   empty/filtered). Write it down so you don't rationalize an ambiguous result later.
4. **Diff by swapping identity only.** Replay A's exact request but with B's session/token
   — change nothing else. Then, where relevant, the reverse. Optionally a third
   unauthenticated request. The *only* variable is who's asking.
5. **Read the result against the discriminator.**
   - B gets A's resource → broken object/tenant authorization (a FACT — save it).
   - B gets 403/404/empty → boundary enforced for this object (a real negative result).
   - Ambiguous (partial data, different-but-not-A's) → inconclusive; note and design a
     sharper test (`design-validation-test`).
6. **Non-destructive discipline.** Read-only proofs. If the hypothesis is about a
   *write/action* boundary, use the smallest safe action on a sandbox/own object and
   confirm the *effect*, never destructive changes to real data. One controlled attempt,
   no enumeration loops across real users' ids.
7. **Filter false positives.** Was the id actually A's and not something both accounts can
   see by design (public resource)? Is B's "success" real data or a generic echo? Did a
   cache serve A's response to B? Re-run to confirm reproducibility.

## Output
- `raw/` or `investigations/<lead>/` — both requests + both responses saved as the
  artifact (identity swapped, everything else identical), plus which account owns the id.
- `tested.md` — one row for each account in the diff, with the same `run_id`, `method` =
  "two-account diff", `result`, and `fix_locus` = the specific missing authorization check
  (each unguarded object/endpoint is its own fix).
- `hypotheses.md` — status updated (confirmed / rejected / inconclusive).
- `findings/draft/` if confirmed; `findings/rejected/` if the boundary held.
- `index.md` — counts + phase log + timestamp.
- Summarize the diff, the discriminator, the result, and the fix-locus. If confirmed, state
  whether its artifacts, impact argument, and novelty gate are complete; otherwise leave it as
  a draft. Then **STOP**.
