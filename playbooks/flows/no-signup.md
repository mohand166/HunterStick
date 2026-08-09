# Flow — no signup available

> No self-registration, no provided credentials, no way in. Two failure modes follow, and both are
> common: quietly testing authz with one account and calling it clean, or declaring the target dead.
> Neither is right. **There is a full day of legitimate unauth work here** — and the authz classes
> must be recorded as *blocked*, which is not the same as *tested*.

## Situation
`accounts.md` has zero usable principals — no row whose credential is real — and registration is
closed, invite-only, or requires a relationship you do not have.

## Preconditions
Host in `scope.md`. Nothing else.

## Steps

1. **Record the block as a PLAN, not as a probe.** The authz family — `idor-bola`,
   `function-level-authorization`, `multi-tenant-isolation`, `privilege-escalation` — cannot be
   tested here, and that has to be visible. But it belongs in **`attack-surface.md`**, not
   `tested.md`:
   - `tested.md` is a record of **probes actually sent**. A row there for an entrypoint you never
     touched, in a class you never ran, is fiction — and it makes `coverage.py` count a cell that
     does not exist.
   - `attack-surface.md` is the **plan**. Add the classes with their principals and mark them
     `blocked (needs-account)` there, so coverage shows them as unresolved-and-unreachable rather
     than untested-and-forgotten.
   - **Only once a concrete entrypoint exists** — a real path, a real variant — does a
     `blocked (needs-account)` row in `tested.md` mean anything. Before that there is nothing to
     key it to.

   Use canonical class names from `class-signals.md`. `multi-tenant` is a **property**;
   `multi-tenant-isolation` is the class. A property in a class column is a row no tool can resolve.
2. **Map the auth surface itself — it is the target now.** Login, registration (even if closed),
   password reset, MFA, OAuth/SSO, magic links, session issuance.
   → `skills/authentication-surface-mapping.md`
3. **Work the pre-auth classes.** These need no account by definition:
   `subdomain-takeover` · `cache-poisoning` · `cache-deception` · `cors` · `ssrf` (where an unauth
   entrypoint fetches) · `open-redirect` · `host-header` · `info-disclosure` · `xxe` on unauth
   parsers · `sql-injection` on unauth inputs · `request-smuggling`.
   → `vuln-hunt`, one entrypoint and one class at a time. This flow does not send payloads.
4. **Work the auth flow's own logic** — the richest unauth ground: registration bypass, reset-token
   predictability, user enumeration, OAuth `redirect_uri` handling, state/PKCE, account
   pre-takeover, email-change and verification races.
   → `playbooks/vulns/authentication-bypass.md`, `oauth-oidc.md`, `password-reset.md`
5. **Ask whether the wall can be opened legitimately.** A trial, a public tier, a partner sandbox, a
   program-provided test account on request. Getting one credential unblocks the entire parked set —
   often the highest-value action available.

## Aborts
- A credential becomes available → **stop this flow.** Record the principal in `accounts.md` and
  switch to `auth-app`. The situation changed.
- Program ROE forbids touching the reset/registration flow → respect it, say which clause, skip
  step 4.

## Cost
Moderate and mostly quiet. No account creation, no state changes.

## Output
- `tested.md` — the blocked rows from step 1, then real rows for everything actually probed.
- `applications/<host>/map.md` — the auth surface.
- `hypotheses.md` — pre-auth leads.

## Exit
Report two numbers: classes **tested unauth**, and classes **parked as blocked**. Never merge them.
State what one credential would unlock.
