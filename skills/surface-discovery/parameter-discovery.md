---
name: parameter-discovery
description: Read the app before you guess, and measure a delta rather than a presence. Use for "parameter discovery" and closely related asks.
---

# parameter-discovery — read the app before you guess, and measure a delta rather than a presence

> Read `skills/shared/_recon-method.md` first — it holds the loop, the input rule and the tool contract.
> This file holds what is specific to parameters.
>
> **This is a test of your ability to bound a search space and then trust its result.** The value
> is not a long list of accepted names. It is a *defensible* list: every name traced to where it
> came from, every reflection measured against a calibrated baseline, and an honest statement of
> whether the run was still valid when it finished. A parameter list produced by a run the target
> destabilised is not a partial result — it is an invalid one.

## Objective

Recover the parameter names each entrypoint accepts, in cost order — read them out of the
application first, and brute-force only what is left. Distinguish real behaviour change from noise.
Hand forward names with their evidence and their entrypoint.

## Inputs

**Enrichment — each absent one narrows the run, none of them gates it:**

- `@endpoints` (optional, from `api-discovery`) — an OpenAPI document or a recovered GraphQL schema
  is the top of the ordering below. If one exists and you brute-force instead, you spent thousands
  of requests to approximate a file you already had.
- `@js` (optional, from `javascript-analysis`) — bundles and sourcemaps carry the field names the
  client sends, including for operations no screen exposes.
- `@raw.http` (optional, from `http-probing`) — captured requests and responses; response bodies and
  validation errors name fields for free.
- `@wordlists` (optional, from `content-discovery`) — target-derived vocabulary. A generic list is
  the fallback, not the plan.
- `@accounts` (optional, from `init-target`) — a session exposes authenticated-only parameters. Not
  required; the method is identical without one, the surface is smaller.

**As the selector, at least one of the following:**

- `@hunter.entrypoint` — the endpoint to mine. One well-chosen endpoint beats 500 with the
  default list.
- `@urls` (from `url-collection`) — query and historical parameter shapes to derive names from.
- `@hosts.live` (from `http-probing`) — the live set from which to select entrypoints to probe.

## Signals — what to come back with

1. **Names read out of the app, in this order.** Every serious tool does this before it guesses —
   Arjun scrapes inputs, JS variables and object keys and mines validation-error bodies for field
   names; x8 does the same; Param Miner harvests keys from the request, from the response, from a
   **method-flipped copy** (GET↔POST, because the wrong method's error names the fields), and from
   all JSON in captured traffic. The ordering is:
   **OpenAPI > GraphQL introspection > JS bundle + sourcemaps > verbose validation errors >
   captured traffic > mobile decompile > bruteforce.** Bruteforce is last, and its wordlist should
   be target-derived.
2. **The boolean and enum flags — the class bruteforce structurally cannot reach.**
   **`debug=aX9k2p` produces no behaviour change; `debug=true` does.** A random-value run is
   mechanically incapable of discovering a flag whose effect depends on the *value*, and this is
   the highest-impact class in the stage. x8 carries a separate code path that loops a fixed list —
   `admin bot captcha debug disable encryption env show sso test waf` — against non-random values.
   A vanilla run misses all of it, silently, and reports a clean finish. Run the value-driven pass
   explicitly and say that you did.
3. **Reflection as a delta from a calibrated baseline, never as "does it appear".** Learn the
   page's normal variance first — a persistent-diff set (x8 learns it over 9 requests by default)
   subtracts CSRF tokens, timestamps and rotating ads permanently. **When a new diff appears,
   immediately re-request with random parameters and re-diff: if the diff reappears, it was noise.**
   That single loop is the difference between a parameter list and a list of the page's own churn.
4. **The bounded name set, which is the real budget.** Measured: 150,000 archived URLs reduce to
   **91 distinct parameter names** on one host and **174** on another; parameter-bearing shapes
   collapse at 1-in-78 and 1-in-1,127 respectively. **The fuzzable surface is bounded by roughly
   100–200 names, not by the URL count.** Everything downstream is priced per request against
   parameters, so report the name set, not the corpus size. "Found 400k URLs" is a download size.
5. **Rarity over frequency.** A parameter appearing once across a large corpus is a better lead
   than one appearing forty thousand times — rarity approximates a non-standard code path. This is
   practitioner judgement rather than a measured result; use it to order attention, not to discard.
6. **Parser behaviour, which you get for free while probing.** `name[]` array notation is accepted
   by PHP, Spring on POST and Express, but not by Ruby, Go, Flask, Django or Tornado; **Ruby
   uniquely accepts `;` as a delimiter**, which is the basis of Rails cache parameter cloaking.
   Each acceptance is a stack fingerprint at no extra cost.
7. **The scanner-found-nothing inversion.** *"The scanner found nothing on a page you can see
   reflects input"* is itself the signal: an unkeyed query string makes a dynamic page look static
   and silently blinds automated scanning. Record the page, do not close it.

## Known traps

- **An abort message means the results are INVALID, not "mostly fine".** *"The page became
  unstable"*, *"Try decreasing the chunk size"*, and any `429` mid-run invalidate everything after
  the point they appear. Check for them explicitly and re-run the affected slice; do not merge a
  destabilised run's output into the clean set.
- **A burst of `400` or `413` is your chunk exceeding a URL or header size limit**, not a finding
  and not a WAF. Shrink the chunk and re-run that slice.
- **An anomalous status code seen repeatedly is a control-request trigger, not data.** x8 fires a
  control request after ~50 occurrences and aborts as WAF/rate-limit detection — which is the
  correct behaviour to imitate manually.
- **[unsupported] the parameter-family → vulnerability-class mapping.** Measured across **357
  disclosed reports**: `cmd=`/`exec=`/`debug=` produced **zero RCE** (10 reports, 7 paid — but as
  info-disclosure and XSS); `xml=`/`data=` produced **zero XXE and zero deserialization**;
  `file=`/`path=` produced **one traversal in eleven**. Only the redirect family holds up (42
  reports, $5,000 max) — **and it converts to XSS about 1.75× more often than to open redirect**, so
  the ordering there is `javascript:`/`data:` scheme XSS, then OAuth/SAML flow abuse where the
  parameter sits on `/authorize`/`/oauth`/`/sso` (highest paid), then open redirect, then SSRF last.
  **The modal outcome of every family is XSS.** Families are a triage ordering — where to spend
  fuzzing budget — never a probability of a class.
- **[unsupported] `id=` in a query string as the IDOR signal.** IDOR reports are titled by endpoint,
  not by parameter, so the family count is a titling artifact. **The IDOR signal in a URL corpus is
  a path shape with an ID segment — `/{N}/`, `/{UUID}/` — not `id=`.**
- **The HPP precedence table everyone copies is stale.** OWASP WSTG says Node/Express takes the
  **first** parameter; a 2024 re-test of live frameworks found Express **comma-concatenates**. Test
  the target; do not trust the table, including this sentence's version of it.
- **Never probe a cache without a cache-buster.** Poisoning production for real users is a program
  violation, not a finding — and it is the one mistake in this stage that cannot be walked back.
- **Absence of `X-Cache` or `Age` is not absence of a cache.** Timing-based detection found **5.8%
  of Tranco Top 50k sites running caches that advertise nothing in headers**. "No cache headers"
  belongs in the undetermined column, not the negative one.
- **A generic wordlist against a target with a recovered schema is pure cost.** Check for the schema
  first, every time; the ordering in signal 1 exists because each step up it removes requests.

## Outputs

- `@params` — every discovered name, deduped, with the entrypoint it was found on and how it was
  found (spec · schema · bundle · error body · traffic · bruteforce).
- Facts via `kb.py add`: the parser fingerprints from signal 6, the value-driven flag pass and what
  it found, the persistent-diff set's size, any WAF or rate-limit boundary you hit.
- Leads into `@target` and `@hypotheses`: flags that changed behaviour, parameters reflecting as a
  real delta, pages that reflect input but scan clean, redirect-family parameters sitting on an
  OAuth or SSO path.
- Coverage next to the data: which entrypoints were probed, which slices were invalidated and
  re-run, which were left.

## Exit criteria

Every read-the-app source above the bruteforce line was exhausted before any guessing started, and
the run says which sources existed at all. **The value-driven flag pass ran** and is reported
separately from the random-value pass — if it did not run, this skill has not covered its
highest-impact class and must say so rather than presenting the list as complete. Every reflection
claim is a delta against a stated baseline. No abort message is sitting unaddressed inside the
result set. The name set is reported as a bounded set, with the entrypoints it applies to.

## Next

Offer: `derive-properties` (parameter names and their entrypoints are one of its richest inputs —
a URL-typed parameter, an ID-shaped parameter or a bound request body is what selects a class) ·
`api-discovery` (if this run found itself guessing, a route table or schema removes most of the
guessing) · `javascript-analysis` (if bundles were not mined, the ordering says do that before more
bruteforce) · `vuln-hunt` on a specific entrypoint whose parameters imply a class.
