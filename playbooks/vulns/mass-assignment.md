# Mass Assignment / Over-Posting — the method

> **This is a test of your ability to find mass assignment / over-posting** in the write the human
> names — the chain that reaches a field you were never meant to set (role/owner/price). Model the
> object the endpoint writes, work out **which fields the binder accepts versus which the UI
> sends**, and find the one that takes effect. The question is "does the server bind request fields
> straight to the model, including ones the UI never sends?" — proven by injecting an extra field
> and confirming it *took effect*, with the two-account/admin baseline defining what the privileged
> field should be. Work it with `playbooks/vulns/_master-vuln-hunting.md`.

---

## 1. Model the binder before you touch anything

**SOURCE** — the request body (or GraphQL input) you control, and specifically the fields you can
*add* to it beyond what the form sends.

**FEED** — the model binder. Any write that **autobinds a request body to an object**:
registration, profile update, `PATCH /users/{id}`, order/cart create, settings, team-member add —
frameworks with bulk binders (Rails `permit`/`update_attributes`, Spring `@ModelAttribute`, ASP.NET
model binding, Mongoose/Sequelize `create(req.body)`, Django `**validated_data`). Does the handler
**allowlist** fields (safe) or bind the whole body (vulnerable)? Where ORM helpers autobind, assume
everything is bindable until proven otherwise.

**SINK** — the persisted object, and the code that later *honours* the field. What object does this
endpoint create or update, and **which of its fields are security- or money-sensitive?** Get the
full model shape from a GET, OpenAPI or the JS models, not from the form.

**CONTEXT** — the discriminator is **which fields the binder accepts versus which the UI sends.**
The gap between those two sets is the attack surface, and the members of the gap that cross a
**trust boundary** decide what class this becomes: privilege (`role`/`is_admin`/`isStaff`),
ownership (`ownerId`/`userId`/`tenantId`), state (`verified`/`emailVerified`/`approved`/`status`),
value (`price`/`balance`/`credit`/`discount`), identity (`id`, overwriting a different record), or
internal flags and `createdAt`. Also ask **where the field is read back** — you need an observable
that confirms it persisted and is honoured, not merely accepted.

**ROOT CAUSE** — one of: the handler binds the whole body with no allowlist · the allowlist exists
on the primary path but not on a sibling/secondary write · a nested or child object is bound
without its own filter · validation exists for the UI-sent fields only. **That answer is your
`fix_locus`** — the specific endpoint + bound field, so distinct binders count separately.

## 2. Derive the candidates — read the model, don't guess field names

1. **Take the field names from the server's own output**: GET responses, OpenAPI, JS models, mobile
   traffic. **Inject the fields the server *reads back*** — a guessed name is silently ignored and
   you will wrongly conclude "safe".
2. **Enumerate every write path to the same object**, not just the one the UI uses: invite-accept,
   bulk import, nested/secondary objects, `PATCH` on child resources, admin and user apps sharing a
   model.
3. **Tech signals from `technologies.md`**: JSON REST APIs, ORMs with bulk-assign helpers,
   admin/user apps sharing a model, GraphQL input types with more fields than the form uses.
4. **Rank the gap by trust boundary** — pick the field whose success is unambiguous and whose blast
   radius is smallest.

## 3. Determine the context — before you inject anything

- **Get the object's real shape**: GET it as user-a and record every field, especially the ones the
  edit form never sends.
- **Record the baseline value of the sensitive field**; if it is admin-controlled, note the **admin**
  baseline for what it is supposed to be.
- **Confirm the legitimate write works unmodified** — otherwise a later failure tells you nothing.

## 4. Test → Confirm → Validate

**Accounts gate:** ownership/tenant fields need a **second principal** (user-b) to reassign to, and
privilege fields need the admin baseline to know what "elevated" looks like. Without them the
honest result is `coverage = blocked (needs-account)` — not "not vulnerable".

**TEST — resend the write with one extra field added** to the JSON body (e.g. `"verified": true`,
`"role": "admin"`, `"ownerId": <user-b's id>`), on an account/object you own. **Outcome: a
hypothesis.**

**CONFIRM — the default oracle is an independent re-read, not the response.** Re-GET in a fresh
request (or exercise the capability) and show the field **changed and is enforced** — user-a is now
verified/elevated, or the object moved owners. Effect, not echo. Run the negative control too: the
field stripped/ignored, value unchanged on re-read. The oracle lies when:
- the server **accepts and echoes** the extra field but never persists or enforces it — a 200 or a
  reflected value is **not** the bug;
- the response echoes your input verbatim (input reflection) rather than stored state — re-GET in a
  fresh request to distinguish;
- the field is one the endpoint **legitimately accepts** from this user — confirm it is actually
  privileged/UI-omitted, not merely undocumented-but-allowed;
- the field name was wrong and was silently ignored, so "safe" is a false negative — source names
  from GET/OpenAPI;
- a validation layer 400s the field — that is enforcement, not a finding.

**VALIDATE — the least that proves impact.** Prove *binding* with the least harmful field that
still demonstrates the gap, then stop. Impact is whichever boundary the field crossed:
`role`/`is_admin` → **privilege escalation**; `ownerId`/`tenantId` → **IDOR / cross-tenant** object
reassignment; `verified`/`status` → workflow/approval bypass; `price`/`credit` → payment /
business-logic abuse. Mass assignment is frequently the *mechanism* behind a priv-esc or tenant
break — decide whether to file it as the binding bug or the downstream impact, and log the
`fix_locus` accordingly.

## 5. Safety, artifact, and PoC handoff

- **Prefer benign fields and your own objects; escalate the minimum.** If you must test `role` or
  `ownerId`, use disposable accounts/objects you can revert, and stop once the effect is shown.
- **Never reassign or corrupt another user's real data to prove it** — a successful `ownerId` write
  takes an object away from whoever held it.
- **Store the artifact**: the injected write **and** the confirming re-read (plus the baseline GET).
  **No artifact → HYPOTHESIS.**
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): Burp Repeater or copy-pasteable
  `curl` for the baseline GET → injected write → re-read, so a triager reproduces it in one action.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the
`fix_locus` from §1 recorded as **endpoint + bound field**. Log negatives with the oracle used —
and record *which field names* you tried, since a negative with guessed names is worthless.
**Dedup:** injecting `is_admin:true` into the main registration form of a popular program is a
well-worn path and often already hardened. Novelty lives in **secondary write paths**
(invite-accept, bulk import, nested/secondary objects, `PATCH` on child resources),
**ownership/tenant fields** rather than just role, **money fields**, and field names found only in
mobile traffic or OpenAPI that the crowd never inspected.

## 7. Worked example — the spine in one pass

*Model:* `PATCH /api/profile` updates a user object; a GET on it (and the OpenAPI noted in
`technologies.md`) shows an `ownerId` field the edit form never sends — the binder accepts more than
the UI sends, and the sensitive field here is ownership, not role. *Derive:* the handler likely uses
an ORM bulk binder; source the exact field name from the GET rather than guessing. *Context:*
`accounts.md` provides user-a and user-b (a different tenant); GET a throwaway object user-a owns and
record its baseline. *Hypothesis:* the endpoint binds the whole body and honours `ownerId`,
reassigning a record across the ownership boundary. *Confirm:* PATCH with `"ownerId":<user-b's id>`
added, then re-GET in a fresh request — the object resolving under user-b confirms binding *and*
enforcement; an echo alone would not. *Safety:* disposable objects, reverted afterwards, user-b's
real data untouched. *PoC:* the injected write plus the confirming re-read. *fix_locus:*
`/api/profile` binder + `ownerId` — not `is_admin` on registration, but an ownership field on a
secondary PATCH path the crowd didn't inspect.
