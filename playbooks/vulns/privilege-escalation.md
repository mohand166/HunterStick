# Vertical Privilege Escalation — the method

> **This is a test of your ability to find vertical privilege escalation** in the role/permission
> flow the human names — the chain that reaches user → admin. Model the request down to the
> **role-assignment / authorization check**: which principal you are, which capability you are
> trying to gain, and which check was supposed to stand between them — then find the input that
> influences privilege and the write path that honours it. The question is *"can user-a raise
> their own privilege to admin?"*, and it is answered by user-a **acquiring an elevated
> capability**, then diffing user-a's post-state against the admin baseline — never by a `200`.
> Work this with `playbooks/vulns/_master-vuln-hunting.md`.

---

## 1. Model the privilege before you touch anything

**SOURCE** — any input that influences role, permission or tier: `role`, `is_admin`, `isStaff`,
`groupId`, `permissions[]`, `scope`, `plan`, `accountType` — in registration, profile update,
invite-accept or team-membership calls. Also role and claims carried in a client-modifiable place:
a JWT payload whose signature isn't enforced, a cookie, a hidden form field.

**FEED** — the write path that carries it: the request binder, any mass-assignment of a body onto
a model (see `mass-assignment.md`), the token parser, the group/tier selector.

**SINK** — the **authority of record** for privilege. Find it before anything else: is "admin" a
DB column, a JWT claim, a group membership? Then ask which requests can touch it.

**CONTEXT — which principal, which capability, which check.** Name all three explicitly, because
the finding is a statement about all three:

| | write it down |
|---|---|
| **principal** | who you are *before* the write — and prove that starting state is unprivileged |
| **capability** | the one admin-only thing you will try to invoke afterwards — a route, a field, a flag only admins have. This is your baseline, captured *as admin*, before you elevate |
| **check** | what was supposed to gate that capability, and whether it reads the authority of record or something the client influenced |

Separate **vertical** (gain higher privilege) from horizontal — here the target is crossing
user→admin, not user→user. And separate a privilege boundary from a tier a standard user may
legitimately self-select.

**ROOT CAUSE** — one of: a user-reachable write path (register, profile `PATCH`, invite-accept,
settings) lets the client **specify** the authority field directly · it lets the client
**influence** it indirectly, by choosing their own group or tier · the role or scope is read from
a token whose signature isn't actually verified (`alg:none`, a weak key) · a claim is read from
the token and never re-checked server-side · an approval or verification flag can be flipped by
its own subject · an admin function is reachable once you guess the route (see
`function-level-authorization.md`). **That answer is your `fix_locus`** — the specific write path
*plus* the authority field that fails to gate privilege.

## 2. Derive the candidates — reason about which writes can reach the authority

1. **Find the authority of record first** (a column, a claim, a membership), then enumerate every
   request that can write to it. That list is your candidate set; don't start from parameter names.
2. **Hunt mass-assignment on a role field the API accepts but the UI never sends.** This is the
   highest-yield non-obvious vector — see `mass-assignment.md`.
3. **Prioritise the non-obvious write paths**: invite-accept, bulk import, secondary profile
   objects, team-membership calls. The register form is picked over; these aren't. **Look for
   self-service role edit** too — anywhere a user can set their own membership level.
4. **For token-carried roles**, treat the token as a write path: is the signature actually verified,
   is `role`/`scope` trusted straight out of the payload, is `alg:none` or a weak key possible?
5. **Tech signals from `technologies.md`**: RBAC where role is a plain column, JWT-based auth,
   team/org invite flows, tiered SaaS plans, self-serve account settings.
6. **Read the schema/descriptor for role-bearing fields the client never sends.** A GraphQL
   mutation input or a protobuf message often declares `role`, `is_admin`, `plan`, `scopes` or
   `tenant_id` even though the UI never populates them — a typed contract advertises exactly the
   fields worth trying, which an HTML form does not.

## 3. Determine the context — capture the baseline before you elevate

- **As admin, capture the baseline capability**: what does one admin-only route, field or flag
  return? You need this recorded *before* you touch user-a, or you will not be able to tell
  elevation from a coincidence.
- **As user-a, confirm the starting state is unprivileged**: the same capability denied, the same
  field absent, the role as issued.
- **Observe what the UI sends** on the candidate write path, so you know which field it *omits* —
  the omitted field is usually the interesting one. Prefer a **disposable test account** for user-a.

## 4. Test → Confirm → Validate

**Accounts gate:** this class needs **≥2 principals** — an admin (for the baseline) and an
unprivileged user-a. Without them the honest result is `coverage = blocked (needs-account)`, not
"not vulnerable".

**TEST — send the write that attempts elevation.** Include the `role`/`is_admin` field the UI
omits, or set your own membership tier, or present the tampered token. **Outcome: a hypothesis.**

**CONFIRM — the default oracle is user-a *gaining the capability*, not the response code.** After
the write, user-a can now invoke the admin-only capability from the §3 baseline, or user-a's own
profile or token reflects the elevated role. The **negative control** is the field being ignored
or stripped, the role unchanged, the admin capability still denied. **The oracle inverts or lies
in these ways:**

- The API **accepts and echoes** `role:admin` but the database or the enforcement layer ignores
  it. A `200` or a reflected field is **not** escalation — you must show a *newly usable* admin
  capability.
- The tier or role you set is one **standard users may legitimately self-select** (free→trial) —
  not a privilege boundary at all.
- **You were already privileged**: a test account seeded as admin, a leftover admin token. Verify
  user-a's *starting* state was unprivileged (§3), or the whole result is void.
- A client-side role flag that changes the UI but not server enforcement.
- JWT "tampering" that the server actually rejects on the **next** request — the signature was
  caught; re-check with a second call.

**VALIDATE — escalate the minimum needed to demonstrate it, then stop.** Reading one admin-only
value proves the boundary fell.

## 5. Safety, artifact, and PoC handoff

- **Do not use the new privilege.** Once elevated, do not touch other users' data and do not change
  global configuration. The single benign admin-only read is the entire demonstration.
- **Test on an account you own and can clean up**; revert the elevation afterwards where you can.
- **Store the artifact**: the elevation request, and the proof-of-capability response — the
  admin-only read succeeding as user-a, next to the pre-elevation denial. **No artifact →
  HYPOTHESIS, not FACT.** Redact any admin data the proof doesn't need.
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): Burp Repeater or copy-pasteable
  `curl` for both principals — the baseline, the elevation write, and the capability check — so a
  triager reproduces the boundary crossing in one action.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the
`fix_locus` from §1 — the write path *and* the authority field. The **principal column carries the
weight** here: "tested as invited member", "tested as free-tier user", "tested as holder of a
tampered token" are different cells with different answers. Log negatives with the oracle used —
specifically, whether you checked a capability or only a status code.

**Novelty.** "I edited the `role` cookie to admin" on a hardened program is usually a dup or a
false positive. Novelty lives in **mass-assignment role fields on non-obvious write paths**
(invite-accept, bulk import, secondary profile objects), **self-service tier/membership logic
flaws**, **JWT claim trust bugs**, and elevation via a **chain** the crowd didn't assemble. Impact:
full vertical escalation user→admin means tenant- or app-wide control and access to every user's
data and admin functions — one of the highest-severity classes — demonstrated with a single benign
admin-only read. Chains: mass-assignment on `role` **is** the escalation vector; broken
function-level authz gives the admin *function* while this gives the admin *identity*; escalate,
then pivot cross-tenant (`multi-tenant-isolation.md`). Chain two or three low findings into
takeover-grade impact rather than reporting each one thin.

**Worked example.** An org invite-accept flow `POST /api/invites/{token}/accept` (from
`endpoints.md`) sets team membership; `accounts.md` has an admin baseline and a disposable user-a;
a `GET` on a member object reveals a `membershipLevel` field. *Model:* invite-accept is a
non-obvious write path the UI drives with a fixed body, and the authority of record for privilege
is `membershipLevel`. *Context:* principal = throwaway user-a, confirmed unprivileged; capability =
one admin-only read captured as admin; check = whatever gates `membershipLevel` on the accept
binder. *Hypothesis:* accept binds the whole body and honours a client-supplied
`"membershipLevel":"admin"` the UI never sends. *Test/confirm:* as admin, note the admin-only
capability (baseline); as user-a, accept the invite with the field added; then re-check user-a's
own membership and try that capability — elevation is confirmed **only** if user-a can now invoke
the admin-only read. Stop there, touch no other users' data, clean up the account; save the
elevation request and the proof-of-capability. *Novelty:* not the register form — a role field on
the invite-accept path the crowd skipped; `fix_locus = invite-accept binder + membershipLevel`.
