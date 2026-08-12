---
name: content-discovery
description: Find what is routed but unlinked, and prove the baseline you found it against. Use for "content discovery" and closely related asks.
---

# content-discovery — find what is routed but unlinked, and prove the baseline you found it against

> Read `skills/shared/_recon-method.md` first — it holds the loop, the input rule and the tool contract.
> This file holds what is specific to content discovery.
>
> **This is a test of your ability to build a calibrated baseline and then extract transitions
> against it.** The value is not a list of 200s — a bare status code is unauditable three weeks
> later and on a modern SPA it is unauditable immediately. The value is `404→403`, `404→401`,
> `404→500`, and the handful of paths that are route tables rather than guesses.

## Objective

Discover paths that exist but nothing links to, against a baseline you established and can show.
Spend the request budget where the evidence says the money is — route-table endpoints, VCS and
config exposure, gated subtrees — rather than on wordlist volume.

## Inputs

**Enrichment — each absent one narrows the run, none of them gates it:**

- `@tech` (optional, from `technology-fingerprinting`) — decides the wordlist and, in the Java case,
  decides whether you should be running a wordlist at all. If absent on a directly named host,
  establish the minimum stack evidence needed to choose a list before fuzzing; do not pick blindly.
- `@urls` (optional, from `url-collection`) — the target's own vocabulary. A wordlist derived from
  how this application actually names things beats a generic list, and it is free once collected.
- `@wordlists` (optional, from `content-discovery` or `parameter-discovery`) — a curated or
  previously target-derived list.
- `@components` (optional, from `component-inventory`) — named products bring their own known paths;
  guessing at a product whose admin paths are documented is wasted budget.

**As the selector, at least one of the following:**

- `@hunter.host` — one exact host the hunter named. Sufficient on its own; calibrate and discover
  only there, without requiring estate probing or widening to the parent apex.
- `@hosts.live` (from `http-probing`) — the multi-host working set. Prefer the **gated** ones: a
  401/403 host is someone's decision that something is worth protecting.

## Signals — what to come back with

1. **Transitions, not statuses.** `404→403` / `404→401` proves the route exists and is gated;
   `404→500` proves your input reached code that broke — and a 500 is louder than a 401, because the
   handler ran before any auth check. Both are meaningless except relative to a calibrated baseline,
   which is why the baseline is itself an output.
2. **The route table, wherever this stack keeps one.** `/actuator/mappings` **beats any wordlist
   because it *is* the route table**; one route-table read is worth ten thousand wordlist requests.
   Same logic for metrics route labels, a spec, or a JS router.
3. **`/actuator/heapdump` — the highest-EV path in a Java estate.** Impact order for the family:
   heapdump > httptrace > mappings > metrics > env > gateway/routes > jolokia > loggers. Measured:
   `/actuator` sightings carry a **$5,000 median** across disclosed reports, the highest in its table.
4. **VCS and config exposure**, `.git` first — measured median **$3,000**, max **$40,000**. Report
   the extracted tree and the verified secret, not the exposure; see the traps.
5. **The calibration record itself** — per host and per directory: what the soft-404 looks like,
   what length it has, what a known-gated path returns. Without it nobody can re-audit your hits.
6. **Directory listings and 401/403 subtrees.** These, and only these, justify recursion.
7. **Mutations of confirmed hits** — backup, temp, swap and editor artefacts of paths you actually
   found. N confirmed paths × 5 mutations is vastly cheaper than a full wordlist × 5 extensions.
8. **What the budget did not reach** — which hosts, which depth, which wordlist. A partial sweep
   reported as a sweep makes every later "we already looked there" wrong.

## Known traps

- **Auto-calibration by response length can silently eat exactly the responses you want.** When the
  403 page and the 404 page share a Content-Length, length-based auto-calibration filters out the
  403 class — the gated surface, the most valuable thing this skill produces. It fails clean: no
  error, just a thinner result set. **Calibrate per-host AND per-directory, then verify the
  calibration against a path you already know is gated.** If your known-gated path does not survive
  the filter, the run is invalid, not "conservative".
- **Ignoring a tool's own abort signal makes the run invalid, not "mostly fine".** Kiterunner's
  quarantine threshold, feroxbuster's auto-bail, nomore403's instability down-ranking and any
  mid-run 429 all mean the same thing: **everything after that point is unreliable**. Restart with a
  lower rate; do not report the tail.
- **Recursing by default is the biggest single waste of request budget in this skill.**
  feroxbuster's own author set the default depth to **4**, which is a statement about diminishing
  returns, not a starting point to raise. Recursion is mechanistically sound only where authz is
  prefix-scoped — so recurse **selectively** into 401/403 subtrees and directory listings.
- **403 bypasses work through parser disagreement between layers, not through broken auth.** Same
  mechanism as the Apache path-confusion class: one layer decodes once and matches an auth-skip
  rule, the next decodes again and routes to the handler. That reframing tells you which mutations
  are worth trying and which are superstition — blind bypass spraying has **no published hit rate**,
  and most 403s in a modern estate are a CDN denying by policy, which no header changes.
  **A bypass that reaches a page which itself enforces authz is not a finding.**
- **An unextracted `.git` report is probably a duplicate.** GreyNoise observed ~4,800 unique IPs
  crawling `.git/config` in a single April 2025 spike, 95% malicious. You are not first. Dump the
  tree, find the secret, verify it lives — that is the report.
- **A cloud VPS gives you false negatives you cannot see.** Akamai and Cloudflare blocklist major
  cloud ranges outright — blackhole, not rate-limit — and regional apexes are geofenced. A wall of
  timeouts from a DigitalOcean or AWS box is a fact about your source IP, not about the target.
- **"Bigger wordlist = more findings" has no supporting comparison.** No published test shows a
  large generic list beating a small target-derived one, and the cost difference is enormous. Treat
  list size as a budget decision, not a quality decision — and say which list you ran.

## Outputs

- `@content` — per host: the calibrated baseline, the confirmed paths, and the **transition** each
  one represents. A hit without its baseline is not a result.
- `@wordlists` — the target-derived list you built or refined, so the next host and the next run
  start from this target's vocabulary instead of a generic one.
- Facts via `kb.py add`: the soft-404 shape per host, any framework or product whose default paths
  responded, the gated subtrees found, and the request budget actually spent.
- Leads into `@target`: route-table endpoints, heapdump/env/httptrace hits, exposed VCS or config,
  admin-shaped paths behind a 401, and anything whose transition was `404→500`.

## Exit criteria

The calibration is recorded per host and per directory, and was **verified against a known-gated
path** rather than assumed. Every reported hit carries its transition and the baseline it was
measured against. No abort signal was ignored — or if one fired, the affected portion is declared
invalid rather than reported. Recursion, where used, names the subtree and the reason. The wordlist,
the depth, the rate and the hosts covered are all written down, so the coverage claim is bounded.

## Next

Offer, do not choose: `api-discovery` (if a route table or spec turned up, it replaces everything
this skill does by guessing) · `parameter-discovery` (confirmed paths are where parameters are worth
mining) · `javascript-analysis` (the routes an unlinked path belongs to are usually declared in the
bundle) · `derive-properties` (turn these paths into propertied entrypoints — this skill emits no
attack-surface properties itself) · `vuln-hunt` on a specific gated path a bypass actually reached.
