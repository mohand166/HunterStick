# Flow — static site (triage out)

> Marketing pages, docs, CDN-fronted brochures. Most of a large estate is this. **This flow exists to
> end in "drop it" and to make that a recorded decision** rather than a host you keep half-looking at
> for three weeks.
>
> Four cheap checks first, because those are where static hosts most often break. **"Static" is a
> claim about the server, not about the page** — before you triage, confirm the page is not quietly
> dynamic on the client: a source map, an inline config blob, a `postMessage` listener, a DOM sink
> reading `location.*`, or a third-party script with its own origin. Any one of those and this is
> not a static site.

## Situation
- No forms, no login, no JSON, no state, and
- responses are cacheable and identical for every visitor, and
- the content is informational.

## Preconditions
Host in `scope.md`.

## Steps — all four are cheap; do them, then decide

1. **Takeover.** The one high-severity bug static hosts really have. Check the CNAME chain for a
   third-party service that no longer claims the name.
   → `skills/know-your-target/dns-analysis.md` → `playbooks/vulns/subdomain-takeover.md`
   Dangling ≠ exploitable — confirm the service actually permits claiming it before calling it
   anything.
2. **Cache.** Static + CDN is the natural home of cache deception and poisoning: unkeyed headers, a
   path-confusion suffix that gets cached, an origin that trusts `X-Forwarded-*`.
   → `playbooks/vulns/cache-poisoning.md`
3. **Storage behind it.** An S3/GCS/Azure origin serving the site is often listable or writable.
   → `skills/external-assets/cloud-asset-discovery.md`
4. **A bounded content check — not a fuzz.** Static hosts do break on files nobody meant to
   publish, and a build pipeline is what publishes them. But running content-discovery with a general
   wordlist against a CDN brochure is thousands of requests to learn nothing.

   So: **a short list, derived, and capped.** A few dozen candidates, not a few thousand —
   `.git/HEAD`, `.env`, `.DS_Store`, `/.well-known/`, source maps for each bundle the page
   actually loads, and the deploy leftovers this stack produces (`.map`, `.bak`, `~`, `.orig`,
   `.swp` against paths that already returned 200). Every candidate comes from something you
   observed on *this* host — a bundle it references, a path in its own HTML — never from a
   generic list.

   Calibrate first anyway: a CDN that answers 200 for everything makes all of it noise.
   → `skills/surface-discovery/content-discovery.md` for the method, with an explicit small selector.

   Two dozen requests. If it finds nothing, that is the fourth clean check and the triage below
   stands.

## Before triaging, rule out the client-side surface

Cheap, and it is what stops a real DOM XSS being written off as "a brochure page":

- `view-source` / the bundle: any `.map` file, any inline JSON config, any API key
- a `postMessage` listener, or a DOM sink fed from `location.hash` / `search` / `referrer`
- third-party scripts — their origin is not this host's, and their compromise is not your finding
- `Access-Control-Allow-Origin` on a static asset, and whether it reflects

If any of these is present, **stop and re-enter at `spa-frontend`.** Only when the page is inert do
the four checks below define the surface.

## Then triage — this is the actual deliverable
If all four come back clean, **write the host off explicitly**:
- a row in `tested.md` per class checked, with `result` and `fix_locus`, so it is never re-chased;
- a one-line note in `index.md` or `clusters.md`: *static, four checks clean, triaged out `<date>`*.

**Do not leave it unmarked.** An unmarked host is one you will reconsider every session, which is the
real cost — attention, not requests.

## Aborts
- Any dynamic behaviour appears — a form, a search box, a JSON response, a `Set-Cookie` — → **stop.
  It is not static.** Re-enter at `spa-frontend`, `api-surface` or `auth-app`.
- The "static" host is the *frontend* of an app whose API lives elsewhere → follow the API, and the
  frontend is not the target.

## Cost
Tens of requests. Minutes.

## Output
- `tested.md` rows for the four checks.
- An explicit triage note with a date.

## Exit
Say plainly: *"static, four checks clean, triaged out"* — or name which of the four paid off. Both
are results. Do not hedge a triage decision; a maybe means you will pay the attention cost again.
