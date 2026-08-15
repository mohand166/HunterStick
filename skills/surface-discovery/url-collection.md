---
name: url-collection
description: Collect and reduce historical and live URLs for one named host or a selected set of live hosts. Use for "url collection" and closely related asks.
---

# url-collection — every path this target ever served, reduced to the few things you can test

> Read `skills/shared/_recon-method.md` first — it holds the loop, the input rule and the tool contract.
> This file holds what is specific to collecting URLs.
>
> **This is a test of your ability to throw away 99.9% of a corpus and keep the right 0.1%.**
> The value is never the corpus. It is three small sets: the **distinct parameter names**, the
> **distinct path shapes**, and the **routes history knows about that the live crawl does not**.
> "Found 400,000 URLs" is not a result — it is a report of your download size.

## Objective

Assemble every URL exposed by one named host or a selected set of hosts, from the archives and from
a live crawl, then reduce it to shapes and names. Compute the set nobody computes — historical
minus crawled — and mine the raw corpus for values before any normalisation destroys them.

## Inputs

**Enrichment — each absent one narrows the run, none of them gates it:**

- `@roots` (optional, from `organization-and-roots`) — apexes for recovering historical names that
  no longer appear in the live set. Without them, collect only the selected host or current hosts.
- `@app.current` (optional, from `application-mapping`) — the UI-reachable route set for the exact
  host selected by `@hunter.host`. Without it the
  crawled side of the zombie diff is whatever your crawler reached, which is weaker but usable.
- `@js` (optional, from `javascript-analysis`) — declared client routes. Strengthens the crawled
  side and catches routes a crawler never clicks its way into.

**As the selector, at least one of the following:**

- `@hunter.host` — one exact host the hunter named. Sufficient on its own; do not require estate
  enumeration first and do not widen it to the parent apex.
- `@hosts.all` (from `subdomain-enumeration`) — all enumerated subdomains. Query archives for every
  selected name; crawl only hosts confirmed live during this run or already represented in
  `@hosts.live`.
- `@hosts.live` (from `http-probing`) — the HTTP-live multi-host working set. Use the whole set when
  the hunter asks for URL collection across the live estate; otherwise apply their named subset.
  Each host is its own archive-query, crawl, reduction, and coverage unit.

## One host and many hosts use the same method

- **One host:** archive-query and crawl only that exact hostname. Record it as the run selector.
  A direct host from the prompt is a complete input even when `@roots` and `@hosts.live` do not yet
  exist.
- **Many hosts:** iterate the selected `@hosts.all` or `@hosts.live` set host by host. Never replace
  that loop with one apex-wide archive query: domain-wide collapse is both less precise and known
  to hang on large estates. Apply budgets per host so one high-volume application cannot starve
  every host after it. An enumerated host that is not HTTP-live still receives archive collection;
  mark its live-crawl side unavailable rather than failed or empty.
- **Both:** preserve the origin on every raw and reduced URL. `/api/users` on `app.acme.com` and the
  same path on `admin.acme.com` are two observations, not one deduplication candidate. Report
  reduction, archive coverage, crawl coverage, failures, and caps per host, plus an aggregate.

If the hunter pastes a host list instead of naming one of the brain's host sets, record it through
`tools/record.py` first: use `recon/subdomains.txt` for names whose liveness was not asserted, and
`recon/live-hosts.txt` only for a list the hunter identified as live. A prompt is a valid source;
an unrecorded prompt is not resumable.

## Signals — what to come back with

1. **The distinct parameter-name set.** 150,000 CDX rows reduce to **91 distinct parameter names**
   on one host and **174** on another. Everything downstream — fuzzing, param mining, DAST — is
   priced per request against parameters, so **this set *is* the budget**. It is the primary output
   of this skill and the one most often buried under the corpus.
2. **The distinct path shapes**, after collapsing ID segments (`/{N}/`, `/{UUID}/`, slugs). One
   measured host went from 1,500 archived rows to **7 path shapes**, one of which was
   `/{ID}/account/customer/api/unstable/graphql`.
3. **The zombie set — `historical_shapes − crawled_shapes`.** A one-line set difference, the
   archive's unique contribution, and every published pipeline merges-and-dedupes and throws it
   away. Confirm members before promoting them; see the traps.
4. **Values, harvested from the raw corpus before you normalise it.** Tokenised single-use links —
   reset, invite, confirm, unsubscribe — are the most under-exploited thing in this stage, and PII
   in confirmation links leaks through the archive the same way.
5. **The version-and-prefix map**: which operation appears under `/v1`, `/v2`, `beta.`, `legacy.`,
   an unversioned path, or a second host. This is a **replay list**, not a discovery list — see the
   traps for why that distinction matters.
6. **High-value shapes by measured payout**, so the ranking is not a guess: `/graphql` (78 reports,
   median $2,000, max $25,000) · `/actuator` (median $5,000) · `.git` (median $3,000, max $40,000) ·
   ops consoles. `.map`, `.svn` and `.well-known` paid **$0 across 35 reports** — they are force
   multipliers to harvest, never findings to report.
7. **Rarity as triage ordering.** A parameter appearing once in a large corpus plausibly marks a
   non-standard code path. This is judgement, not a measured effect — order by it, do not claim it.
8. **The reduction you actually achieved**, stated as both numbers. Real reduction is **99–99.9%**
   and it varies about **15×** between hosts, so a threshold tuned on one host misleads on the next.

## Known traps

- **`collapse=urlkey` on the CDX query is the single highest-leverage step in this skill, and most
  pipelines omit it.** Measured: the first 2,000 rows for one host without it contain **3 distinct
  URLs** (1,207 of them the same homepage). With it: 2,000 rows, 2,000 distinct. That is a **~667×
  improvement in useful rows per request** — and because CDX is the rate-limited resource, it is
  also a 667× improvement in what you can retrieve before you are throttled. Collapse **per host**:
  a domain-wide collapse on a large apex does not return at all. The rest of the query earns its
  keep the same way — host-scoped matching, requesting only the original/status/mimetype fields, and
  filtering to successful non-HTML responses turned one request into the target's whole archived
  API surface with zero packets sent to the target.
- **"Most wayback hits are static assets" is measured FALSE.** Actual: **4 of 29,676** and **62 of
  53,071** — 0.01–0.1%. Static assets live on CDN domains that an apex-scoped query never returns.
  Do not build an image-extension filter to remove 0.01%; spend that effort on **ID-segment
  collapsing, which removes 45–96%**.
- **Normalisation strips values, and the value is often the payload.** One report recovered a live
  Stripe `pk_live_…`, a PayPal clientId and a Sentry DSN **from the CDX index itself, with zero
  requests to the target**, because the app had URL-encoded its runtime config into a path. Grep the
  **raw** corpus for secrets and tokens *before* you reduce it. After reduction that evidence is
  gone and no later skill can recover it.
- **A bare 200 does not confirm a zombie route.** SPA catch-all routing 200s everything. Use
  **negative-control differencing**: request a guaranteed-nonexistent sibling under the same prefix
  and require a difference in **content-type or body hash**, not merely status. The best possible
  signal is a **401/403 where the soft-404 is a 404** — a route matched and authz rejected. Then
  method-flip: many zombie routes are GET-404 but POST-live.
- **Version downgrade is a control-BYPASS technique, not a discovery technique.** The mechanism is
  not "old code is buggier" — in every disclosed case the control lives in a **newer layer the old
  route does not traverse**: an edge rate limiter, a gateway policy, a WAF ruleset scoped to
  `/v3/*`. So the move is: when you find any control on a versioned route, **replay that operation
  on every other version and host prefix you have evidence for.**
- **Widely recommended tools in this stage are archived and still cited daily**: `gauplus` (2022),
  `urldedupe` (2020), `unew` (2022), `Gxss`. Measured alive: `gau`, `waymore`, `katana`,
  `hakrawler`, `uro`. Check before you build a pipeline on a dead binary.
- **"Run nuclei DAST over the corpus" means "run an XSS fuzzer with a thin tail."** Measured: 251
  templates, **194 of them XSS (77%)**, then 24 SSTI and single digits of everything else. It is a
  legitimate use of the corpus; it will not produce SQLi, SSRF or IDOR, and saying so up front stops
  a clean zero being read as coverage.

## Outputs

- `@urls` — the **reduced** set: distinct path shapes with their parameter shapes. The raw corpus
  stays on the VPS with its path recorded; it is large, and later skills re-mine it rather than
  re-download it. Every reduced row retains its host/origin so identical paths on different hosts
  never collapse into one record.
- The parameter-name set, the zombie set and the version/prefix map, written where
  `parameter-discovery` and `derive-properties` will read them.
- Facts via `kb.py add`: the reduction ratio with both numerators, the parameter-name count, the
  zombie count, and any pattern in how this target versions or prefixes its routes.
- Leads into `@target`: tokenised links, secrets found in the raw corpus, zombie routes that
  survived negative-control differencing, and any `/graphql`, `/actuator` or `.git` sighting.

## Exit criteria

Collapsing was set and **verified by counting distinct rows against total rows** — not assumed. The
raw corpus was grepped for values before normalisation, and the run says so explicitly. Every
selected host is marked collected, partial, or failed; one host's failure never becomes a zero for
the set. Reduction is reported as both numbers per host and in aggregate. The zombie set is
computed, or its absence is stated with the reason (no crawled set available) rather than silently
skipped. Every archive or crawl miss, and every budget or row limit, is written next to the host it
qualifies. A one-host run claims only that host; a multi-host run claims only its recorded selector.

## Next

Offer, do not choose: `parameter-discovery` (the name set you just produced is its wordlist, and a
target-derived wordlist is the only kind worth running) · `content-discovery` (the shape set is the
target's own vocabulary — better seed than any generic list) · `javascript-analysis` (historical
`.js` the site no longer references is in this corpus) · `derive-properties` (turn these shapes into
propertied entrypoints — this skill emits no attack-surface properties itself).
