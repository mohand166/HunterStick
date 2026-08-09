# Investigate a GraphQL Surface — the lens

> *A **lens**, not a vuln class. GraphQL is a transport: it changes how you **see** the surface and
> how you **address** it, not what the bugs are. Every finding here belongs to a class file in
> `playbooks/vulns/`. Formerly the `graphql` **class** file; demoted to a lens because a vuln filed
> under a transport is only findable by someone who already knew to look there.*
>
> **What this file is for:** recovering the schema, enumerating operations, and the three mechanics
> that are genuinely peculiar to GraphQL — **aliasing/batching**, **persisted queries**, and
> **cursor pagination**. Then hand off. Work the actual class with
> `playbooks/vulns/_master-vuln-hunting.md` + that class's file.

---

## 1. Find the surface

Any `/graphql`, `/api/graphql`, `/query`, `/gql`, and embedded flavours (Apollo, Hasura, Relay,
WPGraphQL, storefront APIs). Signals in `technologies.md`: `apollo-server`, `graphql-*` libraries, a
`__schema` reference in a JS bundle. Check the **neighbours** — introspection is often off in prod
and on in staging, `dev`, or an acquired host from recon.

## 2. Recover the contract

- **Introspection on** — `{ __schema { types { name } } }` returns type **names only**. For the
  actual contract you need fields, args and types:
  `{ __schema { queryType { name } mutationType { name } types { name kind fields { name args
  { name type { name kind ofType { name } } } type { name kind ofType { name } } } inputFields
  { name type { name } } } } }` — or run a standard introspection query.
  A name list tells you what exists; only the field/arg layer tells you what you can *call*. This is a *context probe*, not a finding: "introspection enabled" is a near-universal
  duplicate and frequently closed N/A. It locates you; keep going.
- **Introspection off** — infer from JS bundles, persisted-query manifests, `.graphql` files in
  repos (`repository-and-secret-recon`), and error suggestions ("Did you mean…") that leak field
  names one at a time.
- **Persisted queries / allowlisting in force** — the request is `{"id":"<hash>","variables":{…}}`
  and arbitrary queries are rejected outright. A 400 is not a finding. The attackable surface
  collapses to the **`variables` object**, which is still a full input surface.

## 3. What is actually GraphQL-specific

Everything else on this page routes out. These four do not:

| mechanic | why it matters | routes to |
|---|---|---|
| **Aliasing / batching** | many operations in one HTTP request — defeats controls counted *per request*. **Not a race primitive**: top-level mutations execute serially per spec, so aliases queue rather than collide | `limit-bypass.md` · `mfa.md` |
| **Persisted queries** | the operation is a hash; only `variables` is yours | whichever class the variable feeds |
| **Cursor pagination** | `hasNextPage`/`endCursor` turns a one-page leak into a full dump — the exfiltration multiplier, and the reason to stop at one record | `idor-bola.md` §I8 |
| **Depth / cost** | recursive and cyclic types (`user → posts → author → posts …`) | establishing the *missing limit* is the finding; **never** actually exhaust the server |

**Resolvers are the real surface.** One field can be over-privileged on an otherwise-locked schema;
a mutation can wrap a legacy REST/RPC service with weaker checks; a nested resolver can reach a
second service having dropped the caller's identity. Ask per field: *who may call it, and where is
that decided* — HTTP layer only, per-resolver, or per-object.

## 4. Route to the class

The `fix_locus` is the **individual resolver/field**, never "the `/graphql` endpoint" — that is what
makes two authz gaps two findings.

| you observe | class file |
|---|---|
| `node(id:)` or any global-object-identification resolver fetching a typed object by opaque id | `idor-bola.md` (**§I8** covers Relay global ids, persisted queries, cursors) |
| an over-privileged **field** on an otherwise-locked schema | `function-level-authorization.md` |
| the id resolves across an org/workspace boundary | `multi-tenant-isolation.md` |
| a mutation input object binding a field you shouldn't set | `mass-assignment.md` |
| a resolver argument reaching a query, shell, template or URL fetch | `sql-injection.md` · `nosql-injection.md` · `command-injection.md` · `template-injection.md` · `ssrf.md` |
| aliased/batched calls defeating a per-request control | `limit-bypass.md` |
| a genuine check-then-act race | `race-conditions.md` — needs real concurrency, not aliases |
| a value from a resolver rendering as markup | `xss.md` |
| a mutation reachable cross-origin (form-encoded / no CSRF token) | `csrf.md` |

## 5. Safety specific to this transport

- **Never fire a deep recursive query that exhausts the server.** Demonstrating that the server
  *accepts* depth it should reject is the finding; DoS is off-limits.
- **Keep batches tiny** — 3–5 aliases proves the mechanism. You are showing a control is absent, not
  brute-forcing.
- **Never loop pagination to size impact.** One record. The cursor loop is exactly what turns a
  measured probe into a bulk extraction.
- Store the query, the response, **and the role/token used** — with GraphQL the principal is half
  the evidence, because the same query is expected to succeed for someone.

## 6. Log it

Log to `tested.md` under the **class you tested**, with the entrypoint as the **field/mutation** and
the `fix_locus` naming the resolver. Do not log "graphql" as a vuln class — it isn't one, and
`tools/coverage.py` will not count it. Add `graphql` to that entrypoint's `properties` in
`attack-surface.md` so the transport is recorded alongside the classes it carries.
