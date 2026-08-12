# Flow — API surface

> The host speaks JSON, or a machine-readable contract exists. **Take the contract; do not discover
> it.** A spec, an introspection response or a reflection endpoint hands you every operation, every
> parameter and every type — for the cost of one request. Fuzzing an API you could have read is the
> most common waste of an afternoon in this workspace.

> **Not `workflows/investigate-api-surface.md`.** This flow *recovers the contract* — it maps
> operations and hands them to ranking, and it never tests. That one is the **testing lens**: how to
> reason about an API while hunting authz on it. This first, that second.

## Situation
Any one of:
- responses are JSON and there is no HTML app in front, or
- an OpenAPI/Swagger document is reachable, or
- GraphQL introspection answers, or gRPC server reflection answers, or
- a `/v1/`-style path prefix with structured errors.

## Preconditions
- Host in `scope.md`.
- **Verify the spec is real.** A 200 that returns the SPA shell for `/swagger.json` is a soft-404,
  not a spec. Check the body, not the status. This exact false positive has been recorded on a live
  target in this workspace — an "OpenAPI spec" that was a catch-all.

## Steps

1. **Recover the contract.**
   → `skills/surface-discovery/api-discovery.md`, plus `playbooks/workflows/investigate-graphql.md` or
   `investigate-grpc.md` when that is the transport. **Transport is addressing, not the bug** — the
   classes below are identical across REST, GraphQL and gRPC.
2. **Enumerate operations into rows**, not prose: method + path (or query/mutation, or
   service/method), the object it names, the principal it expects.
3. **Derive properties per operation.** → `skills/context-and-prioritization/derive-properties.md` — it owns the closed
   vocabulary from `playbooks/system/class-signals.md`, so one producer applies it consistently:
   does the operation name an object (`object-ref`), name two (`two-object`), bind a body
   (`mass-bind`), take a URL (`fetches-url`), carry a tenant (`multi-tenant`), move money
   (`money`)?
4. **Find the operations the client never calls.** Compare the contract against what the app
   actually uses (from `javascript-analysis` / `application-mapping`). Admin, internal, deprecated
   and v-previous operations are the
   ones nobody tests.
5. **Hand off.** Entrypoints are recorded; ranking is a separate ask —
   `skills/context-and-prioritization/attack-surface-prioritization.md` **only on request**. Otherwise `vuln-hunt`, one operation
   and one class at a time.

## Aborts
- Introspection disabled / no spec → this is not this flow. Fall back to `dead-end-host` step 2 (the
  bundle usually carries the contract) or `spa-frontend`.
- Everything returns 401/403 → the surface is real but gated. Say so plainly, and note that the
  gating itself (`skills/application-understanding/authentication-surface-mapping.md`) is now the target. Do not report "no API".
- Authz classes need ≥2 principals; without them park as `blocked (needs-account)`.

## Cost
One request for a spec. Introspection is one request. This is the highest yield-per-request flow in
the workspace.

## Output
- `recon/endpoints.md` — one row per operation.
- `attack-surface.md` — rows with properties from the contract, written by `derive-properties`.
- The unused-operation set called out explicitly.

## Exit
Report: operations recovered, how many the client never calls, and the top candidates by property.
Name the classes those properties imply that `tested.md` has no row for.
