# Multi-Tenant Isolation Break — the method

> **This is a test of your ability to find a multi-tenant isolation break** in the tenant-scoped
> flow the human names — the chain that reaches another tenant's data or actions. Model **which
> principal, in which tenant, is reaching which tenant's object**, find where the tenant boundary
> is supposed to be re-applied on the lookup, and find where that scoping is skipped. The question
> is "does the server enforce the tenant boundary, or does it trust the tenant identifier the
> client sends?" — proven by user-a (tenant 1) reading tenant 2's data, with user-b as the
> other-tenant control. Work it with `playbooks/vulns/_master-vuln-hunting.md`.

---

## 1. Model the boundary before you touch anything

**PRINCIPAL** — who is acting, and **in which tenant**. Keep the two independent: the session
belongs to user-a in tenant 1, while the tenant identifier travelling in the request is a separate,
client-influenced thing. Most of this class lives in the gap between them.

**REFERENCE** — how the tenant is named in the request: `/orgs/{orgId}/...` in the path, a
`?tenant=` / `?account=` query, an `X-Tenant-ID` / `X-Org-Id` / `X-Account` header, a `tenant`/`org`
claim in the JWT, a subdomain (`acme.app.com`) mapped to a tenant, a `companyId` in a JSON body.

**THE CHECK** — how the **acting tenant is determined**: from the authenticated session
server-side, or from a client-supplied path/header/claim the server trusts? The latter is the bug
surface. Then: is every object lookup scoped by tenant (`WHERE id=? AND tenant_id=session.tenant`),
or does it resolve globally and assume the tenant in the URL is honest?

**CONTEXT** — the discriminator is **which principal, in which tenant, reaching whose object,
through which service.** Which services share a datastore across tenants? Trace whether the
isolation check lives in *each* service or only at the primary API gateway — that is usually where
the answer differs.

**ROOT CAUSE** — one of: the tenant id is trusted from a header or JWT claim while the object lookup
ignores it · a secondary/shared service (search, export, notifications, billing, file storage)
resolves objects globally and forgets the tenant scope · a background/async job or webhook runs
unscoped · an aggregate/report endpoint joins across tenants · a GraphQL resolver scopes the
top-level query but not the nested fields. **That answer is your `fix_locus`** — the specific
service plus where the tenant scope is missing, so distinct services count separately.

## 2. Derive the candidates — enumerate services, not URLs

1. **Find every place a tenant identifier is client-supplied or client-influenced** — path, query,
   header, JWT claim, subdomain, body — and note which the server could be trusting.
2. **Enumerate the secondary and shared services** behind the gateway: search, export,
   notifications, billing, file storage, reporting. That is where scope is most often dropped and
   where dups are rarest. Include the paths with no user in front of them — async jobs, webhooks.
3. **For GraphQL, walk past the root**: a scoped top-level query with unscoped nested fields.
4. **Tech signals from `technologies.md`**: B2B SaaS, an org/workspace model, subdomain-per-tenant,
   a shared database with a `tenant_id` column, per-tenant API keys.

## 3. Determine the context — before you cross anything

- **Establish the two tenants concretely**: as user-b, note a real object in tenant 2 and the tenant
  identifier that scopes it.
- **Baseline the request as user-a with user-a's own tenant id** — it must work, or a later 403
  proves nothing about scoping.
- **Confirm the two tenants have no legitimate shared context** before reading anything into a
  crossing.

## 4. Test → Confirm → Validate

**Accounts gate:** this class needs **≥2 principals in ≥2 tenants** — `accounts.md` provisions
user-b in a different tenant for exactly this. Without them the honest result is `coverage =
blocked (needs-account)` — not "not vulnerable".

**TEST — the mismatch.** As **user-a**, replay a request but substitute tenant 2's identifier (in
the path/header/JWT/body) while keeping user-a's own session. Valid session, foreign tenant id is
often the cleanest signal that the server trusts the header/claim over the session. **Outcome: a
hypothesis.**

**CONFIRM — the default oracle is tenant 2's *content* in user-a's response,** diffed against both
the own-tenant baseline and what user-b legitimately sees. Read the body, not the status. The
oracle lies when:
- the data is **intentionally shared** (public tenant, marketplace listing, cross-org collaboration
  the product supports);
- changing the tenant id returns **your own** tenant's data because the server ignored the param
  entirely — that is not a leak, so diff payloads to be sure it is tenant 2's data;
- a 200 comes back with an empty or redacted body — that is enforcement;
- you accidentally reused **user-b's** session/token instead of user-a's — verify the session is
  user-a's and only the tenant id was swapped;
- subdomain routing 404s an unknown tenant rather than crossing into a real one — test against a
  tenant you know exists (tenant 2).

Negative control: 403/404/empty on the foreign id **while the same request with user-a's own tenant
id works**, proving the endpoint is valid and the block is tenant-scoped.

**VALIDATE — one cross-tenant read is enough.** Cross-tenant data exposure or actions are a
critical isolation failure in B2B SaaS; do **not** enumerate every tenant to size it. Chains: this
overlaps IDOR/BOLA (object-level vs tenant-level — pick the `fix_locus` that owns the missing
scope); combine with privilege escalation to become admin *of another* tenant; a trusted `tenant`
JWT claim ties into token-trust bugs. A single break in a shared service often generalizes — note
that without exploiting it at scale.

## 5. Safety, artifact, and PoC handoff

- **Read one benign cross-tenant value; never write or act across the boundary.** If a cross-tenant
  *action* is suspected, demonstrate the authorization gap with the safest observable — a
  differential read or echo — not by mutating tenant 2's data.
- **Never enumerate tenants.** One crossing proves the bug; a sweep is an incident. Argue scale from
  the identifier structure instead.
- Use tenants you own on both sides wherever the program allows it.
- **Store the artifact**: user-a's own-tenant baseline **and** the cross-tenant read, with the
  bodies diffed. **No artifact → HYPOTHESIS.** Redact the other tenant's data down to the one field
  that proves it.
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): Burp Repeater or copy-pasteable
  `curl` for both requests — same session, only the tenant id changed.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the
`fix_locus` from §1 — record the **service** and where the scope is missing, not just the URL, and
note which tenant each principal belonged to. Log negatives with the oracle used. **Dedup:**
swapping an obvious `orgId` in a REST path on a mature SaaS is often already reported. Novelty lives
in a **tenant id trusted from a header or JWT claim**, **secondary/shared services**
(search/export/billing/files) that forget the scope, **async jobs and webhooks**, **aggregate/report
joins** across tenants, and **nested GraphQL fields** past a scoped root.

## 7. Worked example — the spine in one pass

*Model:* `technologies.md` shows a B2B SaaS with a shared search service;
`GET /api/search/documents?q=` returns results, and `accounts.md` provisions user-a (tenant 1) and
user-b (tenant 2). The gateway scopes by session, but search takes an `X-Tenant-ID` header — the
acting tenant *should* come from user-a's session while the reference travels in a header the
service may trust. *Derive:* search is a secondary shared service, exactly where scope gets dropped.
*Context:* as user-b, index/note a tenant-2 document and tenant 2's id; baseline the same search as
user-a with user-a's own id. *Hypothesis:* search resolves documents globally and filters by the
header value, not the session tenant. *Confirm:* as user-a, send the same search with
`X-Tenant-ID: <tenant2>`, keeping user-a's session — tenant 2's document coming back is the break.
Diff the body; don't trust the status. Read one benign field only; never write across tenants.
*PoC:* the own-tenant baseline plus the cross-tenant read. *fix_locus:* search service tenant scope
(`X-Tenant-ID` trusted) — not an `orgId` path swap, but a secondary shared service trusting a header
the gateway didn't.
