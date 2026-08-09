# Broken Function-Level Authorization — the method

> **This is a test of your ability to find broken function-level authorization** in the privileged
> endpoint the human names — the chain that reaches an operation the session was never meant to
> invoke. Model the request path to the **authorization check guarding the function**, understand
> how the app decides which role may call this verb/route, and find where that check is missing or
> UI-only. The question is "can a lower-privilege session invoke a function it was never meant
> to?" — proven by forcing user-a into an admin-only *operation* and diffing against the admin
> baseline, not by noting a hidden button. Work this with `playbooks/vulns/_master-vuln-hunting.md`.

## 1. Model the authorization before you touch anything

**PRINCIPAL** — who is calling, and *in which role*? A logged-in standard user reaching an admin
function is the finding; distinguish that from pure unauthenticated access. Is it authentication
that's missing, or **authorization**?

**FUNCTION** — what privileged *operation* does this route perform, and which role is it *meant*
for? Establish the intended trust boundary before testing: user management, config change, data
export, impersonation.

**THE CHECK** — is authorization on the **route/method itself**, or only on the UI element that
calls it? Read the JS / API contract: buttons hidden client-side often hit a backend with no
server-side role gate.

**CONTEXT — which principal, invoking which verb, on which variant of the route.** The gate is
frequently present on one coordinate and absent on its neighbour:

| coordinate | where the gap shows up |
|---|---|
| the **method** | `GET` is authorized, `POST/PUT/PATCH/DELETE` on the same path isn't |
| the **route variant** | `/v1` checked, `/v2` or `/internal` not; web vs mobile API |
| the **content-type** | an alternate encoding takes a different code path |
| the **override** | `X-HTTP-Method-Override` reaching an unguarded handler |
| the **schema** | GraphQL mutations/queries with no field-level guard |

**ROOT CAUSE** — one of: no server-side role check at all · the check lives in the UI and the route
trusts the frontend · it's applied per-path but not per-method · one API version or client edge
enforces it and a sibling doesn't · the service is reachable directly behind a role-based gateway.
**That answer is your `fix_locus`** — the specific route+method missing the check, so two unguarded
verbs are two findings.

## 2. Derive the candidates — enumerate the function surface, don't guess routes

1. **Enumerate from an admin session, or from the app's own artifacts** — JS bundles, OpenAPI,
   mobile APIs. List the privileged routes, methods and params so you know exactly what to replay
   as a standard user. Reasoning, not a `/admin` wordlist.
2. **Hunt the UI-gated routes**: `/admin/*`, `/api/internal/*`, `/api/v1/users/{id}/roles`,
   `/settings/billing`, export/impersonate/config routes a standard user's menu never renders but
   the route still serves.
3. **Hunt the method and version gaps first** — they're where dups are rare (see the CONTEXT table).
   Undocumented actions found only in a JS bundle are the same play.
4. **Read the tech signals** from `technologies.md`: role-based UIs where the backend trusts the
   frontend, admin SPAs sharing an API with the user app, microservices reachable directly,
   feature-flagged routes.

## 3. Determine the context — before you replay anything

- Capture the **exact privileged request from the admin session**: route, method, headers, body.
  That baseline proves the function exists and proves the request shape is valid — without it a
  403 on your replay is ambiguous.
- Decide which coordinate you're varying (method? version? client?) and hold everything else fixed.
- Decide what the *expected deny* looks like for this app, so you can recognise enforcement when
  you see it.

## 4. Test → Confirm → Validate

**Accounts gate:** this class needs **≥2 principals** — an admin (or role-correct) baseline and a
lower-privilege session. Without them the honest result is `coverage = blocked (needs-account)`,
not "not vulnerable". No admin account? Discover the route from JS/OpenAPI and test whether
**user-a** can invoke it at all, comparing against the expected deny.

**TEST — does the route answer user-a at all?** Replay the admin-captured request from user-a's
standard session — same route, method, body — **swapping only the credentials/token**. **Outcome: a
hypothesis.**

**CONFIRM — did a lower-privilege session actually execute the privileged function?** The default
oracle is the **role diff**: the same request under two principals, read at the level of the
*privileged effect*, not the status line.

- **Positive:** user-a's session executes the admin function — 200 plus the privileged
  action/response → no server-side role check.
- **Negative/control:** 401/403 while the admin baseline succeeds → enforcement is present.

Where that oracle inverts or lies:
- **Soft-hidden UI, hard-checked backend:** the route is invisible in the menu but returns 403 when
  called — that's enforced; the hidden button is not the bug.
- 200 with a body that says "forbidden", or a redirect to login — read the payload, not the status.
- The function is **intended** for standard users (you misjudged the required role) — confirm
  against the admin/role model.
- You still carried an admin cookie/token from a prior request — verify the replay uses user-a's
  session only.
- WAF/gateway returning a generic block unrelated to app authz.

**VALIDATE — the least that proves impact.** **Prefer read/inspect functions, or invoke with a
benign no-op payload.** Prove you can *reach and trigger* the function without a damaging state
change — a privileged list/read, or a create with a throwaway value you can identify that harms
nothing. Demonstrate with the least-impactful privileged call and say what you did not do.

**Impact & chaining.** A standard user performing admin operations: user management, config
changes, data export, impersonation. Chains: reach a role-assignment function → vertical privilege
escalation (see `privilege-escalation.md`); an admin export/list function → mass data exposure;
combine with IDOR to act on specific objects. Overlaps priv-esc when the function *is* the
role-change — pick the fix_locus that owns the missing check.

## 5. Safety, artifact, and PoC handoff

- **Never delete or disable real resources to "prove" access.** Destructive privileged verbs
  (delete, revoke, deactivate, impersonate) are irreversible for the victim — use the read-side
  equivalent or your own throwaway object.
- Don't enumerate the privileged surface at scale to size impact; one function proves the missing
  check.
- **Store the artifact**: the admin baseline *and* the user-a replay, as a pair. **No artifact →
  HYPOTHESIS, not FACT.** Redact what the proof doesn't need.
- **Ship a runnable PoC, never a prose description** (`playbooks/system/mcp-tooling.md`): both
  requests to Burp Repeater, or a copy-pasteable `curl` for each principal so the diff is visible
  in one glance. Respect the program's rate limit.

## 6. Log it

`targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` — and here the **principal and the
method carry the weight**: "tested as user-a, POST" and "tested as user-a, GET" are different cells.
Record the `fix_locus` from §1 (route + method missing the check). Log negatives *with their
oracle*. **Novelty:** a bare unauthenticated `/admin` panel on a mature program is usually already
reported. Novelty lives in the **method gap** (unguarded `POST/DELETE` on an otherwise-checked
path), **v2/internal/mobile API variants** the crowd didn't map, **GraphQL mutations** with no field
guard, and privileged actions found only by reading JS/OpenAPI.

## 7. Worked example

*Model:* a JS bundle references `GET /api/admin/users` (list, admin-only); `accounts.md` provides an
admin plus standard user-a; the user menu never renders this route. The button is hidden
client-side, so the real question is whether the *route* has a server-side role gate — ROOT CAUSE
candidate: the route trusts the frontend to hide it.
*Derive:* the route came from reading the JS bundle, not a wordlist; a read/list function is the
safest discriminator because reaching it proves the gap without changing state.
*Context probe:* enumerate the exact request shape from the admin session first.
*Test → confirm:* capture `GET /api/admin/users` from the admin session (the baseline that proves
the function), then replay the identical request swapping in user-a's token only. If user-a gets 200
plus the admin listing rather than 401/403, there's no server-side authz. Read-only, no mutation.
*Artifact:* admin baseline + user-a replay.
*Dedup:* not a bare `/admin` panel — a specific API route found only in JS that the crowd never
mapped; `fix_locus = GET /api/admin/users role gate`.
