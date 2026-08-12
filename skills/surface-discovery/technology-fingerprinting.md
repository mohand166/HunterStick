---
name: technology-fingerprinting
description: Identity and version, or do not write it down. Use for "technology fingerprinting" and closely related asks.
---

# technology-fingerprinting — identity and version, or do not write it down

> Read `skills/shared/_recon-method.md` first — it holds the loop, the input rule and the tool contract.
> This file holds what is specific to fingerprinting.
>
> **This is a test of your ability to produce facts that select a technique.** The value is
> *framework identity and version*, and the number of distinct things parsing a request before it
> reaches code. A wall of generic tags — "nginx, jQuery, Google Analytics, HSTS" — is not a
> fingerprint; it is a list that selects nothing and costs the next skill time to read.

## Objective

For each distinct application on the estate, establish what it is, what version, and *how confident
you are and why*. Record the edge and the origin as **separate** stacks. Count the parsing layers.
**If a tech tag does not select a technique, do not record it.**

## Inputs

**Enrichment — each absent one narrows the run, none of them gates it:**

- `@raw.http` (optional, from `http-probing`) — headers, cookies, bodies, error pages and redirects
  you have already paid for. Mine this before sending anything; a second probe of an estate is
  traffic spent twice.
- `@clusters` (optional, from `host-correlation-and-clustering`) — fingerprint one representative
  per cluster. Without it you will fingerprint one shared front 4,000 times and call it an estate.
- `@raw.js` (optional, from `javascript-analysis`) — lockfiles, sourcemaps and bundle contents.
- `@js` (optional, from `javascript-analysis`) — normalized framework and library evidence. These
  JavaScript sources sit at the top of the confirmation ladder and outrank everything else here.
- `@net.ports` (optional, from `port-and-service-discovery`) — management planes carry the most
  precisely identifiable software on the target.

**As the selector, at least one of the following:**

- `@hunter.host` — one exact application the hunter named. Fingerprint only that host; existing raw
  artifacts are preferred but are not a prerequisite to observing it directly.
- `@hosts.live` (from `http-probing`) — the multi-host endpoint spine. Apply clustering when it
  exists so a shared front is not fingerprinted thousands of times.

## Signals — what to come back with

1. **Framework identity and version per distinct application, each carrying the rung of the
   confirmation ladder it came from.** Confidence is not a vibe; it is which artifact you read:

   **lockfiles > sourcemaps > static-asset hash > build IDs > error-page fingerprints > favicon >
   banner.**

   A lockfile or a sourcemap names exact versions. A hashed asset or a build ID pins a release. An
   error page identifies the framework and often the minor. A **favicon identifies the product, not
   the version** — it is a pivot, useful once you have a hash to pivot on, not an answer. A banner
   is the bottom rung: **LOW confidence**, always. "banner = version" is one of the recurring
   trusted-an-absolute mistakes, alongside "200 = alive" and "HIT = cached".
2. **`parser_layers` — the single most valuable derived field in the whole recon chain.**
   `parser_layers >= 2` gates six of the highest-severity classes of 2024–2026: request smuggling,
   path confusion, ACL bypass, cache poisoning, cache deception and 403 bypass — **all of which are
   the same bug (two components disagreeing) wearing different clothes**. Count it from multiple
   `Server`/`Via` hops, inconsistent error pages between paths on one host, and any evidence of a
   proxy in front of an origin. Detecting a CDN does not deprioritise a target; **it increments this
   counter.**
3. **The edge stack and the origin stack, as two separate fields.** Never attribute what the edge
   said to the code behind it. The `Server` header you read may have been written by a proxy that
   rewrote the origin's; the TLS stack, the header order and the error pages can all belong to a
   different vendor than the application.
4. **Versioned components that map to a known technique.** Next.js → the cache-poisoning chains.
   Apache httpd in front of anything → path and semantic confusion. Exposed WSDL/.NET SOAP → the
   SOAPwn class. Any PDF/document/preview renderer → the PDF.js class and, more generally, the
   highest hit-rate single feature type there is. DOMPurify with a version → a bypass question.
   These are the tags worth recording precisely because each one names a technique.
5. **Gadget-bearing third-party libraries, for presence not contents.** Google Tag Manager
   (`sequence` → `eval`, `event_callback` → `setTimeout`), GA (`hitCallback`), Adobe DTM
   (`cspNonce`, `bodyHiddenStyle` → `innerHTML`). **GTM/GA/DTM present ⇒ a prototype-pollution
   gadget is already loaded and you only need a source.** That is a technique selector; "uses Google
   Analytics" is not.
6. **The estate's mode, and the singletons against it.** A host earns manual attention when it is a
   **singleton on ≥2 independent axes** — unique body hash *and* unique address, a webserver
   differing from the estate mode, no recognised edge while everything else is fronted, a
   content-length in the far tail, a TLS fingerprint unlike the dominant one.
7. **What you could not identify, named as unidentified.** A blank is honest; a guess written in the
   same column as a lockfile-confirmed version is contamination.

## Known traps — measured, and each one has produced a confidently wrong stack

- **"No CDN/WAF detected" means "unrecognised", not "not fronted".** Detection fields only label
  providers the tool knows. On one estate the organisation's own Traffic Server fronted **98% of
  6,546 endpoints** and was never flagged once — so every `Server` value in that run was the edge's,
  recorded as if it were the origin's. Absence of the field is missing data; say so.
- **The probe defaults are a noise policy, not a capability list.** In the standard prober, body hash
  and header hash are on by default and **favicon, JARM, ASN, vhost and CSP probing are off** — the
  authors' own stated judgement is that the baseline value of probing is content-identity for
  deduplication, not fingerprinting, and their README says outright not to run the others as a
  blanket sweep. They are pivots. Reach for them once you have something to pivot *on*.
- **"WAF present ⇒ mature ⇒ skip" is unsupported, and the inverse is where the money was.** The CDN
  is frequently *the vulnerability*: the desync work found bugs **in** Cloudflare (24M sites), Akamai
  and Netlify for **$350k+**; the ChatGPT account-takeover existed *because* Cloudflare cached
  `/share/*`; TE.0 existed *because* GCLB parsed `Transfer-Encoding` differently from the backend.
  A WAF changes technique, not target.
- **"Missing security headers ⇒ immature ⇒ juicy" has no dataset behind it**, and the
  counter-evidence is that the largest recent payouts came from targets with maximal header hygiene.
  Headers are set by a platform team in an edge config; bugs live in application code written by
  someone else.
- **"Self-signed or expired cert ⇒ soft target" is folklore.** Cert state proxies for *"not managed
  by the web team"* — internal mTLS, health checks, IPMI, a k8s API — not for "vulnerable". Act only
  on the conjunction: self-signed **and** unique body hash **and** non-CDN **and** non-standard port.
- **Identifying a product is not identifying its famous bug.** Struts-shaped `.action`/`.do`
  endpoints appear in 18 disclosed reports: **9 XSS and zero RCE**, median payout $218. The
  fingerprint everyone reads as "RCE" measured as reflected XSS. Record the identity; do not import
  the reputation.
- **The HPP precedence table that every methodology copies is stale — sources directly contradict
  each other.** OWASP WSTG says Node/Express takes the *first* parameter; a 2024 re-test of live
  frameworks found Express **comma-concatenates**. Test the target rather than the table. Free stack
  tells while you are there: `name[]` array notation is accepted by PHP, Spring POST and Express but
  not Ruby, Go, Flask, Django or Tornado, and **Ruby uniquely accepts `;` as a delimiter** — the
  basis of Rails cache parameter cloaking.
- **Version specifics for Spring Boot Actuator are flagged as under-sourced in this repo's own
  research.** Record what you observe on the target; do not restate version-behaviour claims from
  memory as if they were established.

## Outputs

- `@tech` — one row per confirmed application or separately tracked host: edge stack · origin stack · framework · version ·
  ladder rung · confidence · evidence pointer · `parser_layers` · what is unidentified.
- Facts via `kb.py add`: the estate's stack mode, the singletons against it, the fronting picture,
  and any versioned component that names a technique.
- Leads into `@target` for anything whose identity implies a class worth naming.
- Note what this skill does **not** emit: attack-surface properties. `parser_layers` and the version
  rows are observations here; turning them into propertied entrypoints is `derive-properties`' job.

## Exit criteria

Every confirmed application—and every host in an unconfirmed similarity group—carries an identity
or an explicit "unidentified". Use representatives only after independent axes confirmed the
group. Edge and origin are recorded separately, and nothing attributes one to the other. Every
identity states the ladder rung it came from, so a banner guess can never be read as a lockfile
fact. `parser_layers` is computed wherever the evidence supports it. Nothing was recorded that does
not select a technique; if the row does not change what you would test, it should not exist.

## Next

Offer: `derive-properties` (turn stacks and parser layers into a propertied, testable surface — this
is what makes any of it actionable) · `component-inventory` (take the confirmed versions to known
vulnerabilities) · `javascript-analysis` (lockfiles and sourcemaps are the top of the ladder; if the
identity is currently banner-grade, this is how it gets promoted) · `content-discovery` on the paths
a confirmed product implies.
