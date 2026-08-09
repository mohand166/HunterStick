# Web-Cache Abuse — the method

> *(Merged: this file replaces the former `cache-poisoning` and `cache-deception` playbooks. Both
> are the same bug with the arrow reversed.)*
>
> **This is a test of your ability to find web-cache abuse** in the caching layer fronting the
> response the human names. One rule unifies both directions: **the cache key and the response body
> are computed from different things.** *Poisoning* — the key omits an input the body depends on, so
> **your content** lands in **everyone's** entry. *Deception* — the key says "static and public"
> while the body is **someone's authenticated page**, so **their data** lands under **your** key.
> Model the request down to the **cache store**, find the disagreement, and prove it **on a key only
> you can reach** — never on an entry real users are served. Work it with
> `playbooks/vulns/_master-vuln-hunting.md`.

---

## 1. Model the flow before you touch anything

**SOURCE** — depends on the direction:
- *Poisoning:* the input the app reads but the cache doesn't key on — `X-Forwarded-Host`,
  `X-Forwarded-Scheme`, `X-Host`, `X-Forwarded-For`, `X-Original-URL`, custom `X-*` headers, and
  query params the cache strips from the key while the app still reads them.
- *Deception:* the decorated URL the victim is led to request — a real authenticated path with a
  fake trailing segment (`/account/profile/nonexistent.css`).

**FEED** — the caching layer (CDN, reverse proxy, framework cache) and its key-construction and
path-normalization rules on the way in, then the app's own routing and templating/URL building on the
way back. Each hop can normalize `;`, `%2f`, `//`, `%00`, `..;/` differently.

**SINK** — the **cache store**: an entry that will be replayed to whoever requests that key next.

**CONTEXT** — the discriminator is **what each side computes from, and where the gap falls**:

| direction | the cache decides… | the origin decides… | the gap |
|---|---|---|---|
| **poisoning** | the key, from a *narrower* set than the request | the body, using an input the key omitted | your input persists into an entry others are served |
| **deception** | "cacheable/static", from a **suffix or prefix** rule (`*.css`, `/static/*`, `/api/.../export.json`) | routes on the **real base path**, ignoring the fake suffix, returning authenticated content | a victim's private body stored under a key you can re-request |

For poisoning also ask: is it *cacheable at all* (status, `Cache-Control`, `Set-Cookie`, method), and
*where does the unkeyed input land* — a reflected sink (XSS), a `Host`-built URL (redirect / resource
swap), a header? That decides impact. For deception also ask: does the cache's extension/prefix rule
**override** the `Cache-Control` the origin set, and is `private`/`no-store` even set on that
sensitive response?

**ROOT CAUSE** — one of: the app trusts a header the cache omits from the key · a cache-key
normalization quirk (case, trailing slash, `;`/`,` param delimiters, duplicate params, param
cloaking) · a "keyed-but-normalized" value collapsing distinct requests · `Cache-Control: public` on
a response that varies per request · the router tolerates arbitrary trailing segments · the cache's
extension/prefix rule overrides the origin's `private` · the two sides normalize a delimiter
differently (`;`, `%2f`, `//`, `%00`, `..;/`, `/account/profile;x.js`) · a prefix cache rule applied
to an endpoint that personalizes regardless of suffix. **That answer is your `fix_locus`** — the
specific cache rule plus the unkeyed input or route pair, so distinct keys count separately.

## 2. Derive the candidates — reason about the key, not a header or suffix wordlist

1. **Find the caching layer first.** `technologies.md` signals: `Age`, `X-Cache`, `CF-Cache-Status`,
   `Via`, `Cache-Control: public` on dynamic-looking pages; a CDN in the stack.
2. **For poisoning, ask what the response is built from.** Anything absolute in the body — a
   `<script src>`, a redirect `Location`, a CSP, an API config URL — was built from *something*, and
   that something is a candidate unkeyed input.
3. **For deception, start from authenticated, personalized responses** — profile, settings, account,
   an export/JSON API. If nothing private is in the body there is nothing to steal. Then ask **which
   of those routes tolerate a trailing segment**: framework routing that ignores extra path elements
   is the enabling condition, found by reading the app's own routes rather than by spraying suffixes.
4. **Include API/JSON endpoints**, not just HTML pages — the crowd rarely tests either direction there.
5. **Non-obvious surfaces (where dups are rare):** cache-key normalization quirks (case, trailing
   slash, `;`/`,` delimiters, duplicate params), **fat GET bodies**, "keyed-but-normalized" values,
   inputs reflected into cached `<script src>` / `Location` / CSP, path-normalization gaps between
   cache and origin, delimiter confusion (`/account/profile;x.js`), path-parameter tricks, and
   prefix-keyed rules where the origin personalizes regardless of the suffix.

## 3. Determine the context — before you cache or poison anything

Cheap probes only, every one on a URL carrying **your own unique token** so nothing you learn touches
a shared entry. Deception probes run authenticated as **your** account A; all read-only.

- **Is it cacheable, and is a shared cache in the path?** Two identical requests — a MISS then a HIT,
  plus `X-Cache` / `Age` / `CF-Cache-Status` on responses that *should* be private.
- **Which inputs are keyed?** (poisoning) Change one candidate at a time: a HIT means the input is
  unkeyed or normalized away, a MISS means it is part of the key.
- **Does `Vary` name the input?** If it does, the input is *keyed* — move on.
- **Where does the input surface?** (poisoning) Send a benign marker and find it in the body/headers
  before you care whether it caches.
- **Does the origin ignore the suffix?** (deception) Request `/account/profile/<token>.css` as A and
  check the body is A's profile — not a static file, a 404, or a login redirect.
- **What does the origin claim?** (deception) Read `Cache-Control` / `Set-Cookie` on that response —
  is `private` / `no-store` set at all?
- **Which delimiter survives?** Compare `;`, `%2f`, `//` and a plain extension on the same route —
  you are locating the normalization gap, not exploiting it yet.

## 4. Test → Confirm → Validate

**Accounts gate (deception):** two of your own accounts, or one account plus an unauthenticated
fetch. **Never a real victim.**

**TEST.** *Poisoning:* send the candidate header/param with a benign marker on your cache-buster URL
and look for the marker in the response. *Deception:* the §3 probe — A's private data returned for
`/account/profile/deception-<token>.css`. **Outcome: a hypothesis** — you have reflection or routing
tolerance, not caching.

**CONFIRM — both directions share one oracle shape: the thing you want must survive into a HIT on a
key you control.**
- *Poisoning:* **the injected value surviving from a MISS into a HIT.** Send the unkeyed input with
  the poison on `?cb=<random-token>`, then re-request the **same token URL** *without* the input; a
  HIT carrying your injected value proves the input is unkeyed *and* cached.
- *Deception:* **a cookieless re-request of the same URL returning A's private body from cache**
  (`X-Cache: HIT` / `Age` present). Re-request that same URL with no cookies (or as account B);
  getting A's private data back means the authenticated page was cached under an attacker-reachable
  key. The **unique token in the fake filename is a safety control**, not a formality — it is what
  guarantees the entry you create is addressable only by you.

Where the oracle inverts or lies:
- **Reflection on a MISS only** — if the injected value never survives to a HIT, it isn't cached;
  you've found reflection, not poisoning.
- **Your own browser/proxy cache faking a HIT** — verify via the CDN's `X-Cache` / `Age` from a fresh
  client, not local caching.
- **`Vary` correctly keying the input** — then it's *keyed*, not a vuln.
- **A debug/personal cache segment keyed to your session** — confirm a session-independent request
  also gets the poison (on your token URL) before claiming it.
- **Header reflected but HTML-encoded / not in an executable context** — reflection ≠ impact.
- **The origin returns a static file / 404 / login redirect** for the fake suffix — no deception,
  just normal static handling.
- **The cached response is already public** — caching a public page isn't a finding.
- **`Cache-Control: private` correctly honored**, so the response is never stored.
- **The cookieless request gets a fresh personalized-but-empty page (MISS)** — you proved
  cacheability, not cross-user exposure. Don't overclaim.

**VALIDATE — the least that proves impact.** *Poisoning:* prefer a **benign marker** (a harmless
reflected string, or a redirect to your own OOB host) over a live XSS payload. Impact is persisted
XSS/redirect/resource-swap served from cache to every user hitting the poisoned key; cache-key DoS
(poison with an error or oversized response); secret leakage if private responses get cached.
Severity scales with **how shared the key is** — argue it from the key, demonstrate on your token URL.
*Deception:* name *which private fields* the cached body leaks — session data, PII, a CSRF token, an
API key — demonstrated on your own account; anyone whose page lands under a deception URL has those
exposed to whoever re-requests the key → account takeover or data theft. Chains: unkeyed
`X-Forwarded-Host` + `Host`-built resource URL → cached script swap → mass XSS; request smuggling
(`request-smuggling.md`) → poison a *keyed* entry; cached CSRF token → CSRF; cached API key → broader
account access.

## 5. Safety, artifact, and PoC handoff

- **Only ever touch a cache key nobody else will request** — a unique, unguessable URL you own.
  Append a cache-buster you invent (`?cb=<random-token>`) or a unique token in the fake filename, so
  the entry you create is keyed to *you* and served to no one else.
  **PROVE the key includes it before you rely on it.** Plenty of caches strip, normalise or ignore
  the query string entirely — and on one of those your "private" URL *is* the shared entry, so the
  first poison candidate hits real users. The check is two requests and costs nothing: fetch
  `/path?cb=A`, then `/path?cb=B`, and compare `Age` / `X-Cache` / a body marker. If `?cb=B`
  returns the entry created by `?cb=A`, **the query is not in the key** — find a keyed input (a
  path segment, a `Vary` header, a distinct filename) or do not send the candidate at all.
- **Never** poison the bare production URL (`/`, the login page, a shared asset) that real users are
  served — that is an attack on real people. Never mass-request to force eviction of legitimate
  entries, and don't set a huge TTL you can't clear.
- **Never** craft a deception URL against a **real user's** resource, and never harvest another
  user's cached PII. Don't spray many extensions against sensitive endpoints on prod — it is noisy
  and risks caching real users' pages where IDs are guessable. A single self-account repro is enough.
- **Note the TTL** and let your poisoned *test* entry expire where possible; don't leave even your
  token URL poisoned longer than needed to capture evidence.
- **Store the artifact:** the request pair — the poison (or authed) request, then the
  clean/cookieless request showing `X-Cache: HIT` / `Age` and the injected value or private body.
  **No artifact → HYPOTHESIS, not FACT.** Redact private fields down to what proves they were exposed.
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): both requests to **Burp Repeater**, or
  a copy-pasteable `curl` pair — the trigger **and its clean control** — reproducible in one action
  from a clean session.

## 6. Log it

`targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` — principal matters for deception,
because "as A" and "cookieless" are the two halves of the test. Record the `fix_locus` from §1 (the
cache rule plus the unkeyed input or route pair). Log negatives *with the oracle used*: "reflected but
MISS-only", "keyed via `Vary`", "not cacheable", "cookieless re-request was a MISS".

**Novelty:** spraying `X-Forwarded-Host` at the homepage of a mainstream CDN'd site, and the textbook
`/account.css`, are the two most-reported instances and are usually already keyed, blocked, or fixed
(origin refuses the suffix, or the cache respects `private`). Novelty lives in **cache-key
normalization** bugs (delimiters, case, param cloaking), **unkeyed inputs on API/JSON endpoints**,
second-order inputs reflected into cached `Location` / `<script src>`, **path-normalization /
delimiter** variants (`;`, `%2f`, `..;/`, double-slash) that cache and origin normalize differently,
**prefix-based** rules on API/JSON endpoints, and caching layers on **acquired or less-trafficked**
hosts with inconsistent config.

## 7. Worked examples — the spine in one pass

**A. Poisoning.** *Model:* `technologies.md` shows a CDN with `X-Cache`/`Age` on a JSON API endpoint
whose body embeds an absolute URL built from a header — a surface the crowd rarely tests.
*Context:* decide *which inputs are keyed* — vary `X-Forwarded-Host` and check whether a cache HIT
still reflects it. The discriminator is a reflected value surviving MISS → HIT; reflection alone is
not poisoning. *Confirm:* request `/api/config?cb=<random-token>` with
`X-Forwarded-Host: marker.mine` (a benign marker, not live XSS), then re-request the **same token
URL** with no injected header; an `X-Cache: HIT` / `Age` response still carrying `marker.mine` is the
oracle firing — on an entry keyed to *my* token that no real user is served. I never poison the bare
`/api/config`. *PoC / fix_locus:* the poison request + the clean-request HIT as a pair; homepage
`X-Forwarded-Host` is keyed/blocked everywhere, an unkeyed input on this JSON endpoint is novel —
`fix_locus = /api/config cache rule + XFH`.

**B. Deception.** *Model:* a CDN caching by extension (`*.css`/`*.js`) while the app's router
tolerates arbitrary trailing segments, so `/account/profile/x.css` still returns the profile;
`accounts.md` gives me A and B. *Context:* the origin routes on the base path (authed data) while the
cache reads the `.css` suffix and stores it; the discriminator is a *cookieless* request getting A's
private body from cache, not mere cacheability. *Confirm:* as **my** account A, fetch
`/account/profile/deception-<token>.css` and check it contains A's data; then re-request that same
URL with no cookies. A's data returning with `X-Cache: HIT` / `Age` is the oracle — proven entirely
within my own account, no real victim's page ever cached, unique token throughout.
*PoC / fix_locus:* the authed body + the cookieless HIT as a pair; textbook `/account.css` is patched,
a delimiter variant like `/account/profile;x.css` on this router is fresh —
`fix_locus = profile route + .css rule`.
