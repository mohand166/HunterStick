# Investigate Asset

> Process helper. Deep-dive **one** host / app: map its features, trust boundaries, and
> data model, then pick the highest-value leads to pursue. This is the app-level companion
> to `investigate-endpoint` — zoom out to the whole application, understand how it hangs
> together, then zoom back in on the few places worth a researcher's time. Passive
> understanding work; testing is a separate, human-invoked step.

## Objective
Produce a working map of one asset — features, roles, trust boundaries, workflows, tech —
and from it select the highest-value, least-duplicate leads to feed into hypotheses and
endpoint-level investigation.

## When to use
- The human points you at a single host/app worth patient study (usually a top-ranked or
  newly-discovered / acquisition asset from `attack-surface.md`).
- When `application-mapping` produced a map but you need a sharper "so where's the
  value here" read before generating hypotheses.

## Inputs
- The host/app the human named.
- `applications/<host>/map.md`, `endpoints.md`, `notes.md` — existing app map (if any).
- `recon/endpoints.md`, `recon/urls.txt`, `recon/js-findings.md` — its surface.
- `recon/technologies.md`, `target.md` — its stack and where it sits in the org.
- `accounts.md` — roles available to explore it from different privilege levels.
- `scope.md` — confirm in-scope; note any per-asset ROE.

## Process
1. **Map the features.** Walk the app (read-only) as the available roles. What does it let
   users *do*? Group into features/workflows. Note anything money-touching, data-touching,
   admin, or multi-tenant — that's where sensitivity lives.
2. **Find the trust boundaries.** Where does privilege change hands? User↔user, tenant↔
   tenant, user↔admin, anonymous↔authenticated, free↔paid. Boundaries are where authz and
   isolation bugs live — mark each explicitly.
3. **Sketch the data model.** What are the core objects (users, orgs, orders, files) and
   how are they identified (sequential ids? UUIDs? slugs?)? Identifier shape decides how
   enumerable the objects are.
4. **Note the stack & audit gaps.** Self-built auth, obscure/legacy frameworks, custom
   session handling — the un-audited code the crowd skipped. High tech-risk raises value.
5. **Pick the highest-value leads.** From the whole map, choose the few
   features/endpoints/boundaries that best reward depth over throughput — biased to
   business-logic, tenant/authz boundaries, and novel/obscure surface, biased *against*
   scanner-class fruit the program already owns. Justify each pick.
6. **Tag everything FACT / HYPOTHESIS / ASSUMPTION.** What you observed vs. what you infer
   about how it works vs. what you're assuming.

## Output
- `applications/<host>/map.md` — features, roles, trust boundaries, data model, workflows,
  tagged; `notes.md` for working observations; `endpoints.md` for the inventory.
- `investigations/<asset-slug>/` — created for any lead you'll pursue deeper, with notes.
- `hypotheses.md` — leads promoted to concrete testable entries (or handed to
  `generate-hypotheses` / `investigate-endpoint` for the highest-value ones).
- `index.md` — updated map/investigation/hypotheses counts, phase log, timestamp.
- Summarize the app in a few lines, the trust boundaries, and the 3–5 highest-value leads
  ranked with reasoning. Then **STOP** — the human picks what to investigate or test next.
