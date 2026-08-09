# Analyze a known or suspected technology stack

> Use technology to ask better questions, not to replace target evidence with a checklist.
> **Observed behavior outranks this library. Current upstream documentation outranks remembered
> defaults.**

## Inputs

- the named target and `scope.md`;
- the entrypoint/host being analyzed;
- `recon/technologies.md`, `recon/components.md`, application map and captured traffic where present;
- source maps, manifests, lockfiles, error pages or headers that support the fingerprint;
- the hunter's actual goal: analyze, prioritize, research an advisory, or hand off to testing.

If the target or authorization boundary is unresolved, stop before any active verification.

## 1. Build a stack graph, not a label

Write one row per observed layer:

| layer | product | mode | version | evidence | confidence | target-owned? |
|---|---|---|---|---|---|---|
| edge/cache |  | managed/self-hosted | exact/bounded/unknown |  | observed/reported/inferred | yes/no/unclear |
| server/meta-framework |  | SSR/API/static/hybrid |  |  |  |  |
| client |  | SPA/hydrated/RSC |  |  |  |  |
| API/gateway |  | REST/GraphQL/gRPC/realtime |  |  |  |  |
| identity |  | OIDC/SAML/session/BaaS |  |  |  |  |
| data/storage |  | ORM/RLS/rules/object storage |  |  |  |  |
| extension/component |  | plugin/package/vendored |  |  |  |  |

Do not collapse `React + Next.js`, `Spring Boot + Spring Security`, or `Supabase + PostgREST` into
one noun. The seams between layers determine control placement.

## 2. Verify identity and mode

For every product claim:

1. Separate positive behavior from self-reported metadata.
2. Find a second independent signal before calling it confirmed.
3. Identify the deployment mode that changes behavior: client-only versus server components,
   managed versus self-hosted, core versus plugin, gateway versus origin.
4. Record version precision as `exact`, `bounded` or `unknown`; never turn a build ID or release date
   into a version.
5. Mark third-party assets and managed services whose behavior is not owned by the program.

If evidence conflicts, preserve both observations. A proxy banner disagreeing with an application
error is an architecture clue, not a reason to overwrite one.

## 3. Load the minimum relevant knowledge

Use [`_index.md`](_index.md):

- load a deep product profile when one exists;
- load the one or two family references matching the stack graph;
- use [`live-research.md`](references/live-research.md) when version/default/advisory currentness
  affects the conclusion or no written lens fits;
- use `playbooks/workflows/research-component.md` only for a pinned component/advisory question.

Never load every family. Never treat a missing deep profile as permission to improvise remembered
facts without checking upstream.

## 4. Map control placement

For this target—not for the framework in theory—locate:

| control plane | questions the evidence must answer |
|---|---|
| routing | which page, API, action, resolver or handler actually receives the request? |
| authentication | which layer establishes identity and which credential reaches downstream? |
| authorization | page, middleware, controller, resolver, policy/RLS, or several? Are all entry modes covered? |
| binding | which path/query/body/header fields become model or function arguments? |
| rendering | client, server template, SSR/RSC stream, markdown/editor or email/PDF? |
| outbound fetch | image, webhook, import, preview, metadata, SSO discovery or proxy? |
| parsing | JSON, XML, YAML, archive, image, PDF or object deserializer—and which component? |
| caching | which layer caches, what is keyed, and can identity/locale/device change the response? |
| file/storage | where upload, transform, metadata, public URL and authorization happen? |
| administration | debug, health, management, plugin, CI or console surfaces—and on which port/host? |
| background work | queues, jobs, webhooks and delayed processors that cross a second trust boundary? |

Unknown is an output. Do not fill a control plane from framework reputation.

## 5. Generate creative, evidence-bound hypotheses

Generate candidates from four angles, but keep only those supported by a real surface:

1. **Native mechanism:** a product-specific action, route, data channel, rule engine or management
   surface creates a distinctive trust boundary.
2. **Configuration deviation:** the target exposes or disables something upstream treats as
   optional, private, development-only or separately secured.
3. **Composition seam:** two layers disagree about path normalization, host/origin, identity,
   caching, method, content type, object ownership or error handling.
4. **Custom-code escape hatch:** the app bypasses a safe default through raw queries, unsafe render
   APIs, wildcard policy, privileged SDK, custom middleware, plugin or direct DOM/filesystem access.

For each surviving candidate write:

```text
FACT signal
→ attacker-controlled input
→ reachable component/control boundary
→ violated invariant
→ minimal positive and negative oracle
→ canonical vulnerability class
```

Creativity means recombining observed facts. It does not mean inventing endpoints, versions or
vulnerabilities. Include at least one cross-layer hypothesis when the stack has two or more layers;
if no evidence supports one, say so rather than forcing a quota.

## 6. Rank without CVE gravity

Rank by:

- reachability from an in-scope entrypoint;
- attacker control over the relevant value;
- strength of the oracle;
- impact if the invariant fails;
- evidence confidence and version precision;
- target-specific novelty;
- test cost, noise and prerequisites.

A famous advisory with unknown version or unreachable code ranks below a target-specific control
seam with a clear oracle. “Framework usually safe” and “large bounty” are not evidence.

## 7. Record and hand off

This analysis skill does not silently test. It writes or proposes:

- corrected stack facts in `recon/technologies.md` / `recon/components.md` and `observations.tsv`;
- target-specific entrypoints/properties in `attack-surface.md`;
- bounded candidates in `hypotheses.md`, each with evidence needed and an oracle;
- reusable architectural lessons in `target.md` when they affect more than one entrypoint.

Then report:

1. confirmed stack graph and uncertainties;
2. newly implicated entrypoints and components;
3. ranked hypotheses, including the mechanism and canonical class;
4. what became lower priority and the evidence supporting that decision;
5. two or three conditional next actions with cost, risk, prerequisites and expected gain.

Stop. Testing requires the normal vulnerability-hunt authorization and class playbook.

## Abort and correction rules

- Fingerprint disproved → remove the technology-derived candidates; preserve the contradiction.
- Version unknown → do not perform broad advisory matching; first seek bounded version evidence.
- Managed third-party behavior → confirm program ownership before treating it as a target surface.
- Only denial-of-service advisories apply → record and stop; do not validate them.
- Profile and official documentation disagree → follow current upstream, record retrieval date and
  flag the profile for maintenance.
- A “less likely” statement rests only on a default → retract it until the target demonstrates the
  control.
