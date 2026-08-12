# Flow — dead-end host

> A host that is alive and shows you nothing. No links, no forms, a 404 or a login splash on every
> path you try. Most hunters move on; the surface is usually there and simply **not linked**. This
> flow recovers surface from everywhere except the page itself.

## Situation
Host is live (200/403/404 consistently), and:
- no useful links in the response, and
- no forms, and
- the obvious paths (`/api`, `/admin`, `/login`) give nothing.

## Preconditions
- Host in `scope.md`.
- **Calibration proven first.** If a random path returns 200, run `broken-calibration.md` — on an
  uncalibrated host this flow produces pure noise.

## Steps — cheapest first, stop as soon as one pays off

1. **Archives and third-party memory.** Somebody indexed it when it had content.
   → `skills/surface-discovery/url-collection.md` (wayback, commoncrawl, urlscan, VT). **Zero traffic to
   the target.** Always first for exactly that reason.
2. **JavaScript.** If any bundle loads, routes and API bases are inside it.
   → `skills/surface-discovery/javascript-analysis.md`
3. **Virtual hosts and the edge.** The IP may serve something else entirely under a different
   `Host`, and the CDN may be hiding an origin.
   → `skills/know-your-target/live-host-validation.md` (vhost probing) + `dns-analysis` for the
   CNAME chain and origin candidates.
4. **Only now, fuzz.** With a *derived* wordlist — words from this target's own URLs, JS, DNS names
   and error text — not a generic list.
   → `skills/surface-discovery/content-discovery.md`. **Loud phase: selector + budget + pilot.**
5. **Reassess.** Anything found feeds `attack-surface.md` with properties — through
   `skills/context-and-prioritization/derive-properties.md`, which owns the closed vocabulary — then
   → `skills/context-and-prioritization/attack-surface-prioritization.md` on the new slice only.

## Aborts
- **Step 1 or 2 pays off richly** → the host is not a dead end. **Stop the flow** and re-enter at
  `spa-frontend` or `api-surface`. The premise is gone.
- Calibration breaks at step 4 → stop, repair, resume.
- No selector or budget for step 4 → choose and state a defensible bound, pilot one host, then
  continue the authorized flow while recording what the bound excludes.

## Cost
Steps 1–3: passive to light, tens of requests. Step 4 is the expensive one — a real content sweep is
thousands of requests and is the loudest thing in this workspace. **Never let step 4 start
implicitly.**

## Output
- `recon/urls.txt`, `recon/js-findings.md`, `recon/content/<host>.md`, `recon/dns.md` as applicable.
- New rows in `attack-surface.md` with observed properties.
- If everything comes back empty: say so **as a result**. "Four recovery methods, no surface" is a
  finding about the host, not a failure — and it stops you re-running this next week.

## Exit
Name what surface was recovered and from which source. If none, say the host is genuinely dark and
recommend triaging it out.
