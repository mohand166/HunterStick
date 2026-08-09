# Flow — authenticated application

> Login exists and you can obtain accounts. This is the richest situation in bug bounty and the one
> where scanners are useless: **the bugs are in what one principal may do to another's objects**, and
> only a two-account diff can see them.

## Situation
- A login exists, and
- registration is open, or the program supplies credentials.

## Preconditions
- Host in `scope.md`; program ROE permits account creation (check the test-email format — many
  programs mandate one).
- A browser for step 2, or a HAR/Burp export.

## Steps

1. **Create ≥2 principals, in the same tenant and in different tenants if the app is multi-tenant.**
   Record them in `accounts.md` as named principals. Credentials never leave that file — every
   artifact stores a placeholder plus a pointer.
   **Two accounts is the floor, not a nicety.** With one you cannot distinguish "authorized" from
   "unauthorized but unchecked."
2. **Map the auth mechanics.** → `skills/authentication-surface-mapping.md` — how the
   session is issued, carried, refreshed and revoked; what the token actually contains.
3. **Map the application as a real user.** Every feature, every role, every state transition.
   → `skills/application-mapping.md`
4. **Write the user-journey table** — `targets/<t>/user-flows.md`: `name · steps · principals ·
   objects · state changes`. This is the artifact that makes business-logic testing possible; a
   feature list is not. *(Named `user-flows` deliberately: `playbooks/flows/` are research flows
   like this one, `user-flows.md` is what a **user** of the target app does.)*
5. **Diff the principals.** Same action, different account: what changes in the request, and what
   *should* change in the response.
   → `playbooks/workflows/compare-two-accounts.md`
6. **Hand off.** The entrypoints are recorded. Ranking them is a separate ask —
   `attack-surface-prioritization` **only if the hunter wants it** — otherwise go
   straight to `vuln-hunt`, one entrypoint and
   one class. Bias to `idor-bola`, `function-level-authorization`, `multi-tenant`, `workflow-abuse`,
   `mass-assignment`, `privilege-escalation` — the classes that *require* what you just built.

## Aborts
- Only one account obtainable → you are in `no-signup` for the authz classes. Park them as
  `blocked (needs-account)` and do not substitute a one-account test.
- MFA blocks automation → note it, work through the browser, say that coverage is manual-only.
- An action would change another user's data or cost money → **stop and ask.** Non-destructive is
  absolute; a proof that breaks something is not a better proof.

## Cost
Low traffic, high time. Days of human attention, not thousands of requests. Deliberately so.

## Output
- `accounts.md` — principals, credential-referenced.
- `applications/<host>/map.md` + `endpoints.md`; `targets/<t>/flows.md`.
- `attack-surface.md` with `object-ref` / `two-object` / `multi-tenant` / `state-machine` properties
  set from what you actually observed — through `skills/derive-properties.md`, which owns the
  closed vocabulary.

## Exit
Report the flows table and the principal pairs available. Name the top three
(entrypoint × class × principal × variant) cells `tools/coverage.py` shows as untested.
