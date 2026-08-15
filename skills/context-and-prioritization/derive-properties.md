---
name: derive-properties
description: Turn collected evidence into a testable attack surface. Use for "derive properties" and closely related asks.
---

# derive-properties — turn collected evidence into a testable attack surface

> Read `skills/shared/_recon-method.md` first. This skill sends **no traffic**: it reads artifacts that
> earlier skills already paid for.
>
> **This is the bridge.** Recon produces hosts. Hunting consumes *entrypoints with properties* —
> because a property is what selects a vulnerability class. Without this step an estate of 46,358
> hosts and 6,546 live endpoints yields exactly zero testable candidates, which is not a
> hypothetical: it is what happened before this skill existed.

## Objective

Read every artifact the target has accumulated, assemble the **entrypoints**, and assign each one
the observable properties that the evidence actually supports — from the closed vocabulary in
`playbooks/system/class-signals.md`. Emit rows into `@surface`. Say plainly which dimensions the
available evidence could not speak to.

Ranking is not this skill's job. Properties are facts; rank is judgement, and it belongs to
`attack-surface-prioritization` when the hunter asks for it.

## Inputs

At least one of the following. **More artifacts means richer properties, never a different
method** — this skill degrades, it does not fail:

- `@raw.http` (from `http-probing`) — status, headers, cookies, redirects, titles, page types.
- `@hosts.live` (from `http-probing`) — the endpoint spine.
- `@urls` (from `url-collection`) — paths and query shapes.
- `@params` (from `parameter-discovery`) — parameter names and where they live.
- `@js` (from `javascript-analysis`) — client routes, fetch/XHR targets, API contracts.
- `@endpoints` (from `api-discovery`) — operations, methods, body shapes; an OpenAPI or GraphQL
  schema is the single richest input this skill can get.
- `@tech` (from `technology-fingerprinting`) and `@components` — stack and versions.
- `@app.current` (from `application-mapping`) — roles, flows and boundaries for the exact selected
  host. The only source for several
  properties that nothing else can observe.

Nothing at all → say so and name `http-probing` as the cheapest producer.

## The unit is an operation, not a host

`https://api.acme.com` is not an entrypoint. `POST /api/v2/orders/{id}/share` is. An entrypoint is
an **operation**: a host, a path, a method, and the shape of what it accepts. One host carries
many; one operation may be reachable over several transports.

Where the evidence only supports host granularity, record the host and mark the path dimension
undetermined. Do not invent operations that no artifact witnessed.

## Loop

1. **Assemble candidates** from every available artifact, deduped by operation. A path seen in a
   JS bundle, in the URL corpus and in a spec is one entrypoint with three sources, not three.
2. **Gather the evidence** for each — the response headers, the parameter names, the body shape,
   the role that reached it.
3. **Assign properties from the closed vocabulary only.** `class-signals.md` §Property vocabulary
   is the authority and it is closed on purpose: a free-text property matches no rule and silently
   drops every class it should have selected. If something real has no property, that is a
   vocabulary gap worth reporting — not a licence to invent one.
4. **Attach evidence to every property.** A property with no pointer is an assertion. `object-ref`
   because the path ends in a numeric segment is evidence; `object-ref` because it felt like a
   detail endpoint is not.
5. **Record what you could not determine.** This is the step that keeps the surface honest — see
   below.
6. **Write the rows**, leaving `rank`, `score` and the scoring columns empty.
7. **Report the shape of what you produced**, not just the count.

## Assign only what the evidence supports

The discipline is the whole skill. A property asserted from a guess produces a class list that
looks authoritative and is wrong, and the hunter will spend hours on it.

Sound inferences look like this — evidence on the left, and it must be *in an artifact*:

- a `Set-Cookie` on the response → the browser will attach it automatically
- an `Age` / `X-Cache` / `CF-Cache-Status` header → the response is cached
- a numeric, uuid or slug path segment, or an id-shaped parameter → the request names an object
- a parameter carrying a URL, or a spec field typed as a URI → the server may fetch what you give it
- a request body bound to a model in a spec or a JS payload → fields bind to an object
- a 401/403 differing by credential → behaviour depends on the principal
- two object identifiers in one operation → a relationship is being asserted
- a schema field named for money, price, quantity, currency, credit → value is at stake

Unsound, and the reason this skill has a discipline section: assigning `unkeyed-input` because a
page is cached (that needs a cache-key experiment, which is *testing*), `role-gated` because a
path contains `admin` (that is a name, not a behaviour), `multi-tenant` because the product has
organisations (that is marketing, not an observation of this operation).

**When a property needs an experiment rather than a read, do not assign it.** Record it as a
question for the hunting skill that will actually send the request.

## Say what you were blind to

Every row carries what the evidence could not establish, and the run reports it in aggregate:
*"6,546 entrypoints at host granularity; 41 at operation granularity. No request bodies were
available, so `mass-bind` could not be assessed anywhere. No authenticated session exists, so
`role-gated`, `multi-tenant` and `state-machine` are undetermined across the whole surface."*

That sentence is the difference between a thin surface a hunter can read correctly and a thin
surface that looks complete. A row propertied from headers alone is not wrong — it is partial, and
partial is only safe when it is labelled.

## Outputs

- `@surface` — one row per entrypoint: entrypoint · properties · evidence pointers · undetermined ·
  why. `rank`, `score` and the scoring columns stay empty.
- Facts via `kb.py add` for anything that is about the target rather than about one entrypoint.
- Leads promoted into `@hypotheses` where a property set implies a class worth naming — with the
  property that implied it, so the reasoning is visible.

## Exit criteria

Every entrypoint the artifacts support has a row. Every property has evidence. Every row and the
run as a whole state what was undetermined. `tools/coverage.py` can now compute applicable classes
from the surface — run it and report what it says, because that number is the real output of this
skill: *how much testable surface now exists that did not before.*

## Next

Offer: `attack-surface-prioritization` (rank it, when the hunter wants the model to choose) ·
`vuln-hunt` on a specific entrypoint whose properties imply a class · `application-mapping` (the
only way to resolve the role, tenant and state-machine dimensions) · `api-discovery` (a spec turns
host-granularity rows into operation-granularity rows, which is the single biggest quality jump
available here).
