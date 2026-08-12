---
name: javascript-analysis
description: Read the client for what the server will not tell you. Use for "javascript analysis" and closely related asks.
---

# javascript-analysis — read the client for what the server will not tell you

> Read `skills/shared/_recon-method.md` first — it holds the loop, the input rule and the tool contract.
> This file holds what is specific to reading bundles.
>
> **This is a test of your ability to rank correctly against the tooling's own gravity.** The
> conventional ranking — endpoints first, secrets second — is wrong. It is not a judgement about
> value; it is an artifact of what tooling makes easy to grep. The value here is the **route delta**
> handed to authz testing, the **token-leaking sender**, and the **gadget inventory**. The
> non-value is a wall of extracted strings and a key the vendor documents as public.

## Objective

Read the first-party bundles of a live application and come back with the three things below, in
that order. Triage anything secret-shaped against an objective procedure **before** it is written
down as a finding.

## Inputs

**Enrichment — each absent one narrows the run, none of them gates it:**

- `@raw.http` (optional, from `http-probing`) — already-captured responses and script sources. Mine
  these before re-fetching anything; a second fetch of an estate is traffic you already spent.
- `@appmap` (optional, from `application-mapping`) — the UI-reachable route set. This is the other
  half of the route delta and the reason signal 1 is a deliverable rather than a list.
- `@urls` (optional, from `url-collection`) — historical `.js` the site no longer references. The
  archive keeps bundles the application dropped, and old bundles declare routes that still route.
- `@tech` (optional, from `technology-fingerprinting`) — the bundler and framework decide where the
  route table lives and what a chunk manifest looks like on this target.

**As the selector, at least one of the following:**

- `@hunter.host` — one exact application the hunter named. Discover its first-party scripts and
  lazy chunks directly; do not require an estate-wide HTTP inventory first.
- `@hosts.live` (from `http-probing`) — the selected live applications. Analyze each host as its own
  source/provenance and coverage unit.

## Signals — what to come back with

1. **The chunk/route table, reduced to the routes with no reachable UI.** The webpack-style runtime
   chunk maps every lazily-loaded chunk, including admin routes no page links to. **The deliverable
   is the delta between declared routes and UI-reachable routes**, handed straight to authz testing —
   nobody has tested a route the product's own UI never invokes. This is first because it produces a
   worklist, not because it is easiest to extract.
2. **Sender-side `postMessage(token, '*')`.** Microsoft's variant-hunting across Teams, SharePoint
   and Azure calls this *"the most dangerous pattern"*: it leaks JWTs to any framing origin. Real
   hits included an auth JWT in Bing Travel and impersonation tokens in Kusto; peak impact was a
   zero-click cross-tenant XSS at CVSS 9.3. **The community almost universally greps receivers
   instead** — which is why senders are still there to find. While you are in that code, also record
   handlers validating `event.source` instead of `event.origin`, wildcard allowlists, and unanchored
   origin regexes (a pattern anchored only at the start matches `payments.example.com.attacker.io`).
3. **Third-party library inventory — for gadget presence, not for contents.** GTM's `sequence` key
   reaches **eval**; GTM `event_callback` and GA `hitCallback` reach setTimeout; Adobe DTM's
   `cspNonce` and `bodyHiddenStyle` reach innerHTML. **Their presence means a prototype-pollution
   gadget is already loaded on the page and you only need a source.** That inverts the usual
   ordering: the library list is a vulnerability precondition, not an inventory chore.
4. **Sourcemaps, checked on every SPA.** No prevalence statistic exists — see the traps — so the
   honest framing is a **30-second check with a disproportionate payoff**, a cheap lottery ticket
   rather than a yield source. **They pay via undocumented endpoints, not keys**: the canonical case
   is an undocumented `/user/update-user-data` recovered from a map and chained into account
   takeover.
5. **Secret-shaped strings, each already assigned its triage row.** Bugcrowd VRT 1.9 gives an
   objective procedure: `for_publicly_accessible_asset` **P1** · `for_internal_asset` **P3** ·
   `pay_per_use_abuse` **P4** · `intentionally_public_sample_or_invalid` **P5**. **Name the row
   before writing anything down.** The taxonomy exists precisely because researchers mass-reported
   every key as P1.
6. **API contracts at their use sites** — the fetch/XHR/client call, its method, its path template
   and its body shape. A body shape read out of a bundle is the mass-assignment worklist that no
   passive source can give you.
7. **Infrastructure the bundle names and DNS never will** — Lambda Function URLs, BaaS project
   identifiers, internal hostnames, and package identifiers that belong to the target but do not
   exist on the public registry. CT logs and subdomain enumeration structurally cannot reach these.

## Known traps

- **Grepping bundles for `eval` / `innerHTML` / `document.write` is cargo cult.** Any React bundle
  produces hundreds of framework-internal hits, and the ratio of noise to signal does not improve
  with a better regex. Replace it with canary taint-tracking in a browser — you are looking for a
  source that reaches a sink under your control, which is a runtime question, not a text question.
- **Regex endpoint extraction is cargo cult for the same reason.** The most-cited extractor is four
  regexes, one of which matches nearly every dotted string in the file. Replace it with AST-based
  extraction that targets known URL **use sites** — the call, not the string.
- **Scan first-party bundles only.** Analytics, ads and chat SDKs are most of the bytes and nearly
  all of the junk. The single exception is signal 3: for gadget inventory, their **presence** is the
  whole point and you never need to read them.
- **No prevalence statistic for exposed sourcemaps exists anywhere.** Every "they're everywhere"
  article cites nothing. Do not repeat a number you cannot source, and do not budget as if maps were
  common — budget as if the check were free, because it is.
- **The most-recommended sourcemap extractor is archived since 2022 and has a path traversal in the
  extractor itself.** It writes where the map tells it to. Sandbox it or use a maintained one;
  target-controlled data is untrusted, and a sourcemap is target-controlled data.
- **Firebase `apiKey`, Stripe `pk_live_`, Sentry DSN, Algolia search-only keys and Mapbox `pk.` are
  P5 by the vendors' own documentation** — Google says the Firebase key is "OK to include in code",
  Stripe says its publishable key is "safe to embed", Sentry says the DSN carries no read access.
  **The finding is the missing restriction, never the key.** Firebase escalates only through
  permissive rules — classically an `auth != null` rule combined with anonymous auth enabled, since
  anonymous sign-in satisfies it. Reporting the key alone is an instant N/A and a triage-reputation
  hit. Measured context: of 550k candidate Firebase instances, **~900 were actually vulnerable —
  0.16%**.
- **The sleeper is the Algolia *admin* key**, not the search key that everyone greps for: write
  access, and reportedly code execution in the dashboard. Also genuinely payable: an AWS `AKIA`
  **only when paired with its secret**, a Mapbox `sk.`, and a real JWT signing secret. Google Maps
  keys have the only real acceptance data — around **42% acceptance at roughly $200 average**, a
  real but poor and degrading return, and a P4 row.
- **Verified is not the same as reportable.** Verify liveness before reporting, but a verified
  Sentry DSN is still P5.
- **`.map` exposure as a report is worth $0** — three disclosed reports, nothing paid. Harvest the
  route table; never report the exposure.

## Outputs

- `@js` — the route delta, the postMessage findings with their surrounding origin checks, the gadget
  inventory, the extracted endpoints with their use sites and body shapes, and the triaged secrets
  each carrying its VRT row and the reason.
- `@raw.js` — the retrieved bundles and any recovered sources, kept where later skills can re-read
  them instead of re-fetching.
- `@endpoints` — structured operations recovered from fetch/XHR/client use sites, merged into the
  target-wide inventory with URL, observed method, body shape, application, source bundle and why
  the operation matters. A path-like string with no use site remains in `@js`; do not invent GET.
- `@params` — the sorted, deduplicated global parameter-name list for later reuse. Keep each name's
  endpoint and source association in `@endpoints`/`@js`; a flat wordlist cannot carry provenance.
- Run jsluice URL and secret extraction as **direct** runner commands, separately, with
  `run.py --stdout-file <urls.jsonl> -- jsluice urls …` and
  `run.py --stdout-file <secrets.jsonl> -- jsluice secrets …`. Do not put either invocation behind
  a shell/redirection wrapper: the runner automatically rejects a filename supplied to jsluice
  `-R`, validates every emitted row against the installed URL/secret JSONL shape, and refuses an
  empty, stale or malformed artifact. Then normalize both with
  `tools/surface.py ... js <urls.jsonl> --secrets-file <secrets.jsonl>`. It previews the delta,
  preserves an unknown method instead of inventing GET, and on `--write` merges canonical endpoint
  rows, the deduplicated global parameter corpus, and `@js` handoff rows. Secret values and context
  never enter the brain: the reducer retains only kind, field names, count, scanner severity and a
  raw-artifact pointer, marked **untriaged / not verified**. Extraction and normalization are
  offline; fetches still go through the normal HTTP harness.
- Treat the reducer's `@endpoints` + `@js` output as the mechanical candidate handoff to
  `derive-properties`. Do not make the reducer invent a vulnerability class or write directly to
  `attack-surface.md`; property derivation is the reasoning step that promotes supported rows.
- Facts via `kb.py add`: the bundler and route-table location, the third-party libraries present and
  what gadget each implies, and any internal hostname or package name the bundle disclosed.
- Leads into `@target`: declared-but-unreachable routes, token-leaking senders, undocumented
  endpoints recovered from maps, and infrastructure identifiers no DNS source produced.

## Exit criteria

The route delta is computed, or its absence is stated with the reason (no UI-reachable set
available) rather than skipped. Senders were searched, not only receivers. Every secret-shaped
string carries a VRT row assigned before it was written down, and none of the public-by-design ones
are recorded as findings. Which bundles were read, and which were skipped as third-party, is
written down — a "no findings" over an unstated subset is not a result. Extracted operations,
parameter names and redacted candidate records were merged into `@endpoints`, `@params` and `@js`,
or the run names the exact normalization step that remains incomplete. Every untriaged secret
candidate is resolved or explicitly parked before the skill claims completion.

## Next

Offer, do not choose: `api-discovery` (the use sites you extracted are the seed for a real
operation inventory, and a spec beats all of this) · `parameter-discovery` (bundle-derived field
names are the highest-ranked wordlist source there is) · `repository-and-secret-recon` (package
identifiers that belong to the target but 404 on the public registry are a dependency-confusion
lead) · `derive-properties` (turn these operations into propertied entrypoints — this skill emits no
attack-surface properties itself).
