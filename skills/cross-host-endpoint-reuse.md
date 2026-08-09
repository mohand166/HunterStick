---
name: cross-host-endpoint-reuse
description: The routes that still route, on the host nobody rebuilt. Use for "cross host endpoint reuse" and closely related asks.
---

# cross-host-endpoint-reuse — the routes that still route, on the host nobody rebuilt

> Read `skills/_recon-method.md` first — it holds the loop, the input rule and the tool contract.
> This file holds what is specific to reuse and zombie routes.
>
> **This is a test of your ability to compute a set nobody computes, and then to confirm it against
> a baseline instead of a status code.** The deliverable is
> **`historical_shapes − crawled_shapes`** — the zombie-endpoint candidate list. It is a one-line
> set difference, it is the archive's only unique contribution, and every published pipeline
> merges-and-dedupes its sources and throws the difference away.
>
> The value is a short list of routes *confirmed* to still route, plus the replay matrix for every
> control you found. A longer URL corpus is not a result.

## Objective

Two moves against hosts that genuinely share a backend. **One:** subtract what the crawler sees
today from what the archive remembers, and confirm what survives. **Two:** replay the target's own
paths and parameters across the other members of the cluster, because shared code means shared
routes and one member is usually exposed differently. Then take every access control you observed
on a versioned route and replay that operation everywhere the version differs.

## Inputs

- `@clusters` (from `host-correlation-and-clustering`) — replay **inside** a cluster only. Replaying
  across hosts that do not share a backend is noise with a request cost.
- `@urls` (from `url-collection`) — both halves of the difference: the archive-derived shapes and
  the crawl-derived shapes. **They must still carry their provenance.** If the corpus was merged
  and deduped, the difference no longer exists in it and has to be recomputed from the sources.
- `@endpoints` (optional, from `api-discovery`) — operations and versions; a spec makes the version
  axis explicit instead of guessed.
- `@js` (optional, from `javascript-analysis`) — declared client routes with no reachable UI, which
  belong in the same candidate pile.
- `@params` (from `parameter-discovery`) — the parameter half of the corpus.
- `@wordlists` (optional, from `parameter-discovery` / `content-discovery`) — target-derived lists
  already built; reuse them rather than regenerating.
- `@hosts.live` (from `http-probing`) and `@scope` — a sibling host is only replayable if it is
  in scope.

## Signals — what to come back with

1. **The difference set, per host**, with its size stated. Shapes the archive holds that today's
   crawl does not. If provenance was lost and it could not be computed, that is the finding to
   report — not a substitute list.
2. **Confirmed zombies**, each confirmed by **negative-control differencing**: request a
   guaranteed-nonexistent sibling under the same prefix, and require a difference in **content-type
   or body hash**, not merely in status.
3. **A 401 or 403 where the soft-404 is a 404.** This is the best signal in the whole skill: a route
   matched and *authorization* rejected it. Nothing else short of a body diff proves the route
   exists.
4. **Method-flip hits.** Many zombie routes are GET-404 but POST-live. A route that 404s to GET has
   not been ruled out until the other methods have been tried.
5. **Reuse hits** — a route discovered on host A that answers on host B, with *why it is
   interesting there*: same export, but B does not demand the role header; same handler, but B's
   error envelope is different.
6. **The control replay matrix.** For every control you can observe — a rate limiter, a gateway
   policy, a WAF rule scoped to one path prefix — the list of other versions, prefixes and hosts
   where the same operation does **not** traverse it. This is the actual product of this skill.
7. **Error-envelope diffs between versions.** A different envelope means different middleware,
   which means a different auth filter. It is the strongest tell that drift is real and not
   cosmetic.
8. **Distinct parameter names**, not URL counts. On measured corpora 150,000 archived URLs reduce
   to 91 and 174 distinct parameter names. Everything downstream is priced per parameter, so the
   name set *is* the budget.

## Known traps — each of these produces a list that reads like findings and is not

- **A bare 200 is worthless.** An SPA catch-all 200s everything, including paths you invented. Any
  confirmation that rests on status alone has to be redone against a per-host, per-directory
  negative control.
- **The mechanism is not "old code is buggier."** In the disclosed cases the defect is that **the
  security control lives in a newer layer the old route does not traverse** — an edge rate limiter,
  a gateway policy, a ruleset scoped to one version prefix. OWASP API9's own scenario is a beta
  host running the same reset flow *without* the rate limiting production had. So version-downgrade
  is a control-**bypass** technique, not a discovery technique: **when you find any control on a
  versioned route, replay that operation on every other version and host prefix you have evidence
  for.** Hunting old routes for old bugs is the wrong search.
- **Drift is often host-level, not path-level.** `beta.` and `api-2.` are versions. Restricting the
  replay to `/v1/` versus `/v2/` misses the case OWASP actually documents.
- **Auto-calibration by response length can eat exactly the responses you want.** Where the 403
  page and the 404 page share a content length, length-based calibration filters out the gated
  class — this is a filed, reproduced bug in ffuf, not a theory. Calibrate per host *and* per
  directory, then verify the calibration against a path you already know is gated.
- **Ignoring a tool's own abort signal invalidates the run**, it does not make it "mostly fine" —
  a quarantine threshold, an auto-bail, or any 429 mid-run means everything after that point is
  unreliable and must be rerun, not filtered.
- **A burst of 400 or 413 is your request exceeding a URL or header size limit**, not a family of
  interesting responses.
- **Do not extension-multiply the corpus.** Mutating the paths you confirmed is strictly cheaper
  than multiplying every candidate by five backup extensions, and it finds more.
- **The reduction ratio varies about 15× between hosts** (1-in-78 on one apex, 1-in-1,127 on
  another). Budget from the shape count you actually computed for *this* host, never from a
  remembered ratio.
- **A route that exists is not a finding.** It is an entrypoint. The finding needs the class, and
  the class needs `derive-properties` and a hunting skill.

## Outputs

- `@endpoints` — confirmed routes as operations (host · path · method · what confirmed it · which
  negative control it was differenced against).
- `@wordlists` — the target-derived path and parameter corpora, kept so later runs and later hosts
  reuse them instead of rebuilding them.
- Facts via `kb.py add`: the difference-set size per host, the controls observed and where they
  stop applying, error-envelope splits between versions.
- Leads into `@target`, promoted into `@hypotheses` where a control gap names a class outright.
- Coverage: which clusters were replayed, which were not, and which hosts were skipped for scope.

## Exit criteria

The difference set was computed and its size stated per host — or the run says plainly that
provenance was lost and names `url-collection` as the fix. Every route claimed live was confirmed
against a negative control on its own host, by content-type or body hash. Method-flip was attempted
on the GET-404 candidates. Every control found on a versioned route has a recorded replay across
the other versions and prefixes, with the result of each. Hosts and clusters not covered are named.

## Next

Offer: `derive-properties` (turn these confirmed operations into propertied entrypoints — a
confirmed route is not yet testable) · `api-discovery` (a spec or a route table makes the version
axis exact instead of inferred) · `attack-surface-prioritization` (rank the new rows, only if the
hunter asks the model to choose) · `vuln-hunt` on one route where a control demonstrably does not
apply.
