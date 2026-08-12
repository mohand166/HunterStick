---
name: api-discovery
description: Recover the operation set, then find the two deltas. Use for "api discovery" and closely related asks.
---

# api-discovery — recover the operation set, then find the two deltas

> Read `skills/shared/_recon-method.md` first — it holds the loop, the input rule and the tool contract.
> This file holds what is specific to APIs.
>
> **This is a test of your ability to recover a contract the target did not mean to give you.**
> The value is not "we found `/graphql`" or "there is a swagger file". It is the operation set —
> method, path, body shape, error envelope — and the two places that set disagrees with reality.
> A list of endpoints copied out of a spec is inventory. The delta is the finding.

## Objective

For every host that speaks an API, establish **what protocol it actually is**, recover as much of
its operation set as the target will yield, and record the drift: between versions, between hosts,
between what the spec declares and what the server really accepts.

## Inputs

**Enrichment — each absent one narrows the run, none of them gates it:**

- `@urls` (optional, from `url-collection`) — historical paths carry version prefixes the current UI
  no longer uses. This is where `/v1` survives after the UI moved to `/v3`.
- `@js` (optional, from `javascript-analysis`) — the client's own fetch/XHR call sites and its
  router are a first-party description of the API. Better evidence than anything you can guess.
- `@content` (optional, from `content-discovery`) — spec paths, actuator endpoints, WSDL.
- `@tech` (optional, from `technology-fingerprinting`) — the stack decides which route table exists
  at all: a Spring estate has one, a Connect-RPC service has another.
- `@accounts` (optional, from `init-target`) — not required. Most of this skill runs unauthenticated;
  a session mainly widens which operations answer rather than changing the method.

**As the selector, at least one of the following:**

- `@hunter.host` — an API host or a spec URL the hunter named. A supplied OpenAPI or GraphQL
  endpoint is the richest possible input and needs no prior recon at all.
- `@hosts.live` (from `http-probing`) — find the API surface in the live set. API hosts are usually
  visible by name, content type, or error envelope.

## Signals — what to come back with

1. **Protocol identity, established rather than assumed.** `query{__typename}` identifies any
   GraphQL endpoint definitively, whatever the path is and whatever the framing looks like — a
   GraphQL service mounted on `/api/data` is still GraphQL. For gRPC, reflection being enabled is
   introspection being on; Connect-RPC's unary JSON mode collapses the whole surface to ordinary
   JSON POSTs, which means every technique you already have applies.
2. **The schema — and "introspection is off" treated as a claim to falsify, not a state to
   accept.** The ladder: a newline or comma after `__schema`, a GET request, a form-urlencoded
   POST, and then field suggestions in error messages (Clairvoyance, Nikita Stupin). The evidence
   that this is not a fringe path is that Apollo shipped `hideSchemaDetailsFromClientErrors` in
   4.11.0 *specifically because* introspection-off does not stop schema recovery — and it is
   **default-off**, so most deployments have not turned it on. Accepting the first "introspection
   is disabled" is the single most common way this stage produces nothing.
3. **Alias batching, and what it is next to.** Alias batching defeats per-request rate limiting:
   N logically independent operations inside one HTTP request count as one request to any limiter
   that counts requests. **Alias batching enabled plus a low-entropy-secret mutation — `verifyOtp`,
   `redeemCoupon`, `confirmPasswordReset` — is the highest-confidence pre-test prediction available
   in GraphQL recon, derivable from the schema alone, before a single test payload.** Say it in
   those terms when you see it, and hand it to hunting as a named hypothesis.
4. **The route table, read rather than guessed.** `/actuator/mappings` *is* the route table;
   metrics route labels, gRPC reflection, the spec document and the JS router are the same thing in
   other stacks. **One route-table read beats ten thousand wordlist requests** — and the disclosed
   record backs the actuator family generally: 8 reports, 4 paid, a **$5,000 median** and a $12,500
   maximum, the highest median of any path fragment measured.
5. **Version and host drift, with the error envelope as the tell.** Drift is often **host-level,
   not path-level** — OWASP API9's own scenario is a beta host running the same reset flow *without*
   the rate limiting production had. The strongest discriminator is a **differing error envelope
   between two versions or two hosts: a different envelope means different middleware, which means
   a different auth filter.** Record the envelope shape per version and per host; it is a cheaper
   and more reliable signal than comparing feature lists.
6. **The two deltas that make a spec worth having.** A spec is a map, not a finding. Its value is
   exactly: **in-spec-but-not-in-UI** (declared operations nobody exercises, therefore nobody
   tested) and **in-reality-but-not-in-spec** (the server accepts things the schema does not
   declare, which means no schema validation and no gateway policy in the path). Emit both sets
   explicitly. A run that hands over the spec's endpoint list and neither delta has not finished.
7. **gRPC's free oracle.** `grpc-status: 12` (UNIMPLEMENTED) versus `7` (PERMISSION_DENIED) is a
   **method-existence oracle that needs no authentication** — 7 says the method is real and you are
   not allowed, which is the more interesting answer.
8. **Object-bearing operations, stated as the rule that actually predicts.** Record: an identifier
   appears in the request **and** the object is plausibly reachable by a second principal. That
   conjunction is the BOLA candidate. Note the ID format separately — it sets exploitability at
   scale, i.e. severity, not existence.
9. **`/graphql` seen at all is a priority signal.** In a 14,832-report disclosed corpus it is the
   strongest path fragment measured: **78 reports, 25 paid, $2,000 median, $25,000 maximum**,
   dominated by information disclosure, improper access control and IDOR.

## Known traps

- **"Introspection is disabled" accepted at face value** ends the stage prematurely, and it is
  wrong often enough that Apollo built a mitigation for the case. Work the ladder in signal 2
  before you record the endpoint as opaque.
- **[unsupported] "sequential IDs = IDOR."** The predictor is the **authorization model**, not the
  ID format. A UUIDv4 with no ownership check is equally broken, and the UUID is obtained from a
  share link, a member list, an export or a webhook. Ranking endpoints by "has a numeric ID"
  demotes exactly the endpoints that pay.
- **[unsupported] "`/api/admin/*` returning 200 = BFLA."** OWASP explicitly warns against inferring
  privilege from a URL path. A path segment is a name, not a behaviour; you have observed a string.
- **[unsupported] mass endpoint wordlists.** Blasting a large endpoint list is the expensive way to
  approximate a document the app will hand you. Read the route table first; brute force is what you
  do when there is no route table, against a target-derived list.
- **Swagger's real finding is usually not the endpoint list.** Measured: 13 reports, 1 paid, $500
  median — and **7 of them are XSS in Swagger UI itself** (the `?configUrl=` shape, seen in Adobe,
  Cloudflare and DoD reports). Treat the spec as input to this skill and the UI as its own
  entrypoint.
- **A 200 does not mean the operation exists** where an SPA catch-all routes everything. Confirm a
  candidate route by differencing against a guaranteed-nonexistent sibling under the same prefix and
  requiring a difference in content-type or body hash — not merely status. The best available signal
  is a **401/403 where the soft-404 is a 404**: a route matched and authorization rejected.
- **Method-flip before concluding a route is dead.** Many surviving routes are GET-404 but POST-live.
- **A 500 is louder than a 401.** It means the handler ran before any auth check. Do not filter it
  out as noise.
- **Batched or aliased probing is traffic amplification.** One HTTP request can be a hundred
  operations against the backend. Count what you are actually sending, and say so in the budget.

## Outputs

- `@endpoints` — one row per operation: url · method · params · auth_required · content_type ·
  app · why it is interesting · source.
- The recovered schema or spec artifact on the VPS, pointed at from `index.md`. It is re-read by
  `parameter-discovery` and `derive-properties` rather than re-fetched.
- Normalize a saved OpenAPI/Swagger JSON document with `tools/surface.py`; YAML is accepted when
  PyYAML exists and otherwise fails by naming that dependency. The tool previews both endpoint and
  parameter deltas before `--write` and sends no traffic.
- Facts via `kb.py add`: protocol per host, introspection state and how it was established, batching
  support, error-envelope shape per version and host, which route tables exist.
- Leads into `@target` and `@hypotheses`: the batching + low-entropy-secret pair, each version-drift
  pair, both spec deltas, object-bearing operations with the second-principal note.

## Exit criteria

Every API host has a protocol established by observation, not inference from its path. For each
GraphQL endpoint, the introspection ladder was actually worked and the result stated — "recovered",
"recovered via field suggestions", or "resisted all four, here is what was tried". Where a spec
exists, **both** deltas are computed and written down; a spec restated is not an output. Version and
host drift is recorded with its error-envelope evidence. What was not reached — hosts skipped,
operations behind auth you do not hold — is written next to what was.

## Next

Offer, do not choose: `derive-properties` (an operation set is the single richest input it can get —
it converts host-granularity rows into operation-granularity rows, which is the biggest quality jump
available in the whole chain) · `parameter-discovery` (a recovered schema outranks every guessing
technique it has) · `authentication-surface-mapping` (the auth operations you just enumerated deserve
their own map) · `application-mapping` (to resolve which of these operations the UI actually invokes —
that gap is the BFLA list).
