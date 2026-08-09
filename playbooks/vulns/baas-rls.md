# BaaS / Client-Side RLS (Supabase · Firebase · PostgREST · Appwrite) — the method

> **This is a test of your ability to break a backend where the client talks *directly* to the
> database and the only server-side control is a row-level-security policy / security rule.** There
> is **no application server enforcing authz** — the browser holds a key and hits a DB gateway, so
> security rests entirely on RLS/rules being correct on **every table, view, bucket, and write path,
> for every principal**. Model the policy, enumerate the schema, then answer "what does the gateway
> let *this* key/token read or write, table by table?" — proven by a differential sweep, not by
> finding one endpoint. Work it with `playbooks/vulns/_master-vuln-hunting.md`.

## 1. Model the authorization before you touch anything

**SOURCE** — the credential the browser holds: a public/anon key shipped in client JS, a GoTrue /
Identity-Toolkit session token, custom JWT claims (`role`, `user_type`, `tenant_id`), or nothing.

**FEED** — the DB gateway itself, no app handler in between: Supabase `/(kong/)rest/v1`,
`/graphql/v1`, `/auth/v1`, `/storage/v1` (or `*.supabase.co`); Firebase Firestore
`firestore.googleapis.com/v1/projects/<id>/…`, Realtime DB `<proj>.firebaseio.com/<path>.json`,
Identity Toolkit; Appwrite `/v1/databases`, `/v1/account`. Often reached via a same-host
reverse-proxy path (`/kong/`, `/api-gateway/`) rather than the vendor domain — enumerate it in
app-mapping (a feature with no endpoint on the primary API lives here).

**SINK** — the object the gateway acts on: a table, a **view**, a storage bucket/object, an auth
setting.

**CONTEXT** — the discriminator is the triple **principal × object × operation**. The trust boundary
is the *policy*, not a handler: for each table/collection/bucket, which RLS policy / security rule
gates it, and for which role (`anon`, `authenticated`, a custom claim)? And **read ≠ write** —
policies are frequently written for `SELECT` only, so `INSERT`/`UPDATE`/`DELETE` is a separate cell
per object, per principal. That matrix *is* the test plan.

**ROOT CAUSE** — one of: no policy on this table · a **view** that doesn't inherit base-table RLS
(no `security_invoker=on`) · a table the policy author **forgot** while siblings are locked · a
**missing write policy** where read is locked · a **public Storage bucket** (`/object/public/…`)
serving sensitive files · RLS keying off a **custom claim** a low-priv user can obtain or set ·
**open signup** (GoTrue/Identity-Toolkit) provisioning a usable identity · a `service_role`
(full-bypass) key reachable client-side. **That answer is your `fix_locus`** — the exact
policy / table / view / bucket / claim, never "the database", so each missing rule counts separately.

## 2. Derive the candidates — enumerate the schema, don't guess table names

1. **Find the tell:** a public/anon key in client JS + the browser calling a DB gateway directly.
   Grep bundles for `supabaseKey` / `SUPABASE_ANON_KEY` / `apikey` / `REACT_APP_ANON_KEY`; Firebase
   `apiKey`+`authDomain`+`projectId`; `createClient`, `supabase-js`, `gotrue-js`, `postgrest`,
   `firebase/firestore`, `appwrite`.
2. **The schema is self-describing — enumerate it, don't wordlist it.** PostgREST root
   `GET /rest/v1/` returns an OpenAPI listing every table/view + columns; pg_graphql auto-exposes
   `‹table›Collection` **queries** and `insertInto/update/deleteFrom‹table›Collection` **mutations
   even when introspection is disabled**; Firestore/RTDB rules govern paths. That's your full object
   list to sweep.
3. **Non-obvious surface (where dups are rare):** a **view** not inheriting RLS from its base table;
   a forgotten table beside locked siblings; **write** policies missing where read is locked; a
   **public Storage bucket** serving sensitive files; **custom JWT claims** the RLS or client trusts;
   **open signup** that provisions a usable identity.

## 3. Determine the context — before you sweep

Cheap, one request each, none destructive.

- **`GET /auth/v1/settings`** — `disable_signup` / `mailer_autoconfirm`: can you mint a principal
  yourself?
- **Which principals do you hold, and how is a session minted** (GoTrue `signInWithPassword`, a
  bridge from the main app, anon)? Does a **low-priv token carry a claim** RLS keys off, and can that
  user **obtain or set a higher one** (open signup, updatable `profiles.type`, a bridge that mints an
  over-privileged claim for everyone)? Is `service_role` **only** server-side?
- **Clear the session store first.** The token lives in `localStorage` and is often the *only*
  session — is it bound to the primary-app identity and cleared on logout? (`session-management.md`.)

## 4. Test → Confirm → Validate

**Accounts gate:** the differential needs **≥2 principals** (anon + a role). With anon only, run the
anon sweep and log the rest as `coverage = blocked (needs-account)`.

**TEST — anon sweep, no login.** With the key from JS, `GET /rest/v1/‹table›?select=*&limit=1` (and
the GraphQL `‹table›Collection`) for **every** table and view; `GET /object/public/‹bucket›/‹path›`
for one referenced file. **Outcome: a hypothesis.**

**CONFIRM — the default oracle is the returned row set, never the HTTP status.** A **non-empty** body
from a sensitive table/view, or a file served with **no** auth, is the finding; a write is only real
once you read it back (`Prefer: return=representation`). Where that oracle inverts or lies:

- **`200` with `[]` / `affectedCount:0` is enforcement, not a leak** — RLS silently filters.
- **A schema-cache error (`PGRST204` "column … does not exist") is NOT an RLS *allow*** — it fires
  before policy eval; retry with valid columns before concluding anything.
- **The anon key being public is *by design*** — not itself a bug; the bug is what RLS lets it reach.
  Same for a public asset bucket / reference table intended to be world-readable.
- **Your own leftover high-priv token** in `localStorage` makes a low-priv test look privileged
  (that leftover is also its own finding; `session-management.md`).
- **GraphQL "introspection disabled" ≠ operations disabled** — enumerate the collections by name.
- A table that **404s** vs a row that's *unauthorized* — confirm the object exists for another
  principal.

Then the **per-principal differential**: authenticate as each role you own (+ anon) and sweep read
AND write per table. A principal reading/writing a table it shouldn't, beside a locked sibling, is
the RLS/BOLA gap. **Claim escalation:** as a low-priv identity, attempt the privileged field
(`update profiles set type='admin' where id=me`) and re-read — *stuck* = escalation, `0 rows` /
`42501` = enforced.

**VALIDATE — the least that proves impact:** one row from the offending table/view, one file from the
bucket, one stuck write. Impact: unauthenticated / cross-tenant **data read** (PII, answer keys,
secrets, config); **write-RLS gap** → tampering, integrity loss, or **privilege escalation**;
**public Storage** → IP/document disclosure; **open signup + custom claim** → account creation into a
privileged workspace. Chains: over-privileged bridge claim → facilitator/admin over the whole BaaS;
leaked `service_role` key (in JS/CI) → total bypass; cross-backend session inheritance
(`session-management.md`); tenant break (`multi-tenant-isolation.md`).

## 5. Safety, artifact, and PoC handoff

- **Never** delete or overwrite others' rows, and never mass-read PII. Prove writes with **one**
  benign row in a namespace you control (or your own row); read **one** row to prove a leak.
- **Store the artifact:** the exact request(s) + response(s) **with the principal and key used**.
  **No artifact → HYPOTHESIS, not FACT.** Redact row content to what proves cross-boundary access.
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): the gateway request to **Burp
  Repeater**, or a copy-pasteable `curl` carrying the key/token, **with its control request** (the
  locked sibling, or the other principal) so the differential reads in one glance.
- The full-schema sweep is **loud** — one request per object per principal. Budget it against the
  program's rate limit and announce it first.

## 6. Log it

`targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` where the entrypoint is the **object**
and the principal column carries the weight ("as anon", "as authenticated", "as low-priv claim").
Record the `fix_locus` from §1. Log negatives *with the oracle used* — row count, not status.

**Novelty:** "Supabase anon key found in JS" or "Firebase config exposed" as a lone report is a
**dup / non-bug** (both designed-public). Novelty lives in a **specific table/view/bucket the RLS
forgot**, a **missing write policy**, **inconsistent RLS across sibling tables**, a **claim a
low-priv user can obtain or forge**, or a **public bucket with sensitive files** — each proven by a
stored differential.

## 7. Worked example — the spine in one pass

*Model / derive:* a React app ships `SUPABASE_ANON_KEY`; `GET /rest/v1/` (that key) lists `profiles`,
`orders`, and a **view** `orders_summary`. Trust rests entirely on RLS.
*Context:* anon `select` on `profiles`/`orders` returns `[]` (policies on) — but views run as their
**owner** unless `security_invoker=on`, so `orders_summary` may bypass the base policy. The
discriminator is whether the *view* returns rows the anon principal shouldn't see.
*Hypothesis:* `orders_summary` has no RLS of its own and is `anon`-granted, leaking order data.
*Confirm:* one anonymous `GET /rest/v1/orders_summary?select=*&limit=1`; a non-empty body carrying
another tenant's order is the oracle firing, with the `[]` on `orders` as its control. One row, no
scrape. Store both as the pair.
*Dedup:* the crowd noted "anon key exposed" and stopped; the un-scoped *view* is the real bug —
`fix_locus = orders_summary view (missing security_invoker / anon grant)`.
