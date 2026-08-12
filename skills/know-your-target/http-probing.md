---
name: http-probing
description: Which of these actually speak HTTP, and what do they say. Use for "http probing" and closely related asks.
---

# http-probing — which of these actually speak HTTP, and what do they say

> Read `skills/shared/_recon-method.md` first — it holds the loop, the input rule and the tool contract.
> This file holds what is specific to probing.
>
> **This is a test of your ability to turn a host list into a signal set.** The value is not "how
> many are up". It is the per-endpoint facts that steer everything after: what is gated, what is
> versioned, what is fronted, what is an application versus an echo of one shared edge.

## Objective

Probe every candidate for a live HTTP(S) service and capture what each one reveals. Produce a
clean list of what answers, plus the facts a hunter would act on. Leave the full JSON where later
skills can mine it instead of re-probing.

## Inputs

**Enrichment — each absent one narrows the run, none of them gates it:**

- `@net.ips` (optional, from `dns-analysis`) — the deduplicated address list. **Not optional in
  practice.** On one estate 879 of 6,546 live endpoints answered on an address with no DNS name
  at all. A name-driven probe cannot see those, and no later skill can either.
- `@net.ports` (optional, from `port-and-service-discovery`) — probe the non-standard ports it
  actually found. Without it you are guessing, and the guess is usually 8080/8443.

**As the selector, at least one of the following:**

- `@hunter.host` — one exact hostname the hunter named. Probe only that host and its explicitly
  named ports; do not require prior enumeration and do not widen it to the parent apex.
- `@hosts.resolved` (from `live-host-validation`) — names that resolve today. Prefer this to the
  full enumerated set: probing names that no longer resolve spends the budget on DNS failures.
- `@hosts.all` (from `subdomain-enumeration`) — fallback multi-host selector when resolution has
  not been run. DNS failures remain visible limitations rather than disappearing as dead HTTP.

## Signals — what to come back with

1. **The live set.** `scheme://host:port`, deduped. This is the input to almost everything later.
2. **IP-only responders.** Anything answering on a bare address. Each is a host whose name you
   have not found — often infrastructure that was never meant to be public.
3. **The gated surface.** 401 and 403. These are the highest-value unauthenticated leads on a
   mature target: someone put a control there, which means something is behind it.
4. **Versions in the clear.** `Server`, `X-Powered-By`, framework banners, JS library versions.
   A build string like `Jetty 9.4.57.v20241219` is an n-day selector, not a curiosity.
5. **Auth entrypoints.** Login, registration, password-reset and SSO landing pages — by shape,
   not just by path. These are where the account-adjacent classes live.
6. **Redirect destinations that leave the host.** Each is a *candidate*, never something you have
   probed. Reconcile before touching.
7. **Catch-all candidates.** Which exact responses repeat through the same observed IP. This is a
   correlation lead, not an app/backend count; confirmation belongs to clustering.

## Known traps — each of these has produced a confident wrong answer

- **CIDRs produce a silent zero.** httpx does not expand them. A four-address CIDR yielded nothing
  while the same addresses listed individually probed normally — no error, no warning.
  Expand ranges to addresses *before* probing.
- **Title is not identity on a shared edge.** One estate returned the same vendor title on 4,889 of
  6,546 endpoints. Deduping on title collapses the whole estate to nothing. A **body hash**
  discriminated properly there — its largest cluster was 159. Cluster on the hash.
- **"No CDN detected" is not "not fronted."** The probe only labels providers it recognises.
  The estate's private edge fronted 98% of its hosts and was never flagged. Absence of the field means
  unmatched, and you must say so rather than reporting the origin's server as the origin's.
- **Follow redirects on the same host only.** Unrestricted following will chase a 302 to a host
  nobody authorised, and the request is sent before you can reconcile it.
- **429 is a throttle, not a verdict.** One estate's edge returned 429 at **5 requests per
  second** across three hosts. A 429 in the output is neither "alive and interesting" nor "down".
- **A silent retry setting changes the request count.** If you promised a budget, know whether the
  tool is doubling it on failures.
- **The output file is usually not instead of stdout.** Most probers write the file *and* print
  every record, so a naive `| tee` copies the whole dataset into the log. One run produced a
  10.8 MB log around 3,991 lines of actual logging. Send stdout to `/dev/null` when `-o` is
  already capturing.

## Evidence to leave behind

Keep the full structured output on the VPS and record its path. `technology-fingerprinting`,
`url-collection`, `javascript-analysis` and `derive-properties` all re-read it rather than
re-probing — a second probe of an estate is traffic you already spent.

## Outputs

- `@hosts.live` — the clean deduped live list.
- Facts via `kb.py add`: the fronting picture, the gated count, versioned components, the
  catch-all shape, anything that breaks the estate's own conventions.
- Leads into `target.md` — gated hosts, admin-shaped names, auth entrypoints, IP-only responders.
- The raw structured output on the VPS, pointed at from `index.md`.

## Exit criteria

`@hosts.live` is populated and deduped; the IP-only responders are counted and not silently
merged into the name-driven set; the gated surface is counted; the fronting picture is recorded so
nobody later mistakes the edge for the origin. If the probe covered only part of the input — some
ports, some of the list — that is written down next to the count.

## Next

Offer, do not choose: `technology-fingerprinting` (deepen what the banners hinted at) ·
`derive-properties` (turn these endpoints into a propertied attack surface — this is what makes
them testable) · `port-and-service-discovery` (if you guessed at ports, stop guessing) ·
`content-discovery` on a specific gated or interesting host.
