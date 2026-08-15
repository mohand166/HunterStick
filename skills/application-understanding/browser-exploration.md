---
name: browser-exploration
description: Explore one application in a real, authenticated browser session — rendered routes, post-auth surface, runtime network traffic, storage, CSP — and validate client-side hypotheses (DOM XSS sinks, postMessage senders/receivers) with the smallest interactive proof. Use for "browse the app", "explore it logged in", "authenticated crawl", "use the browser / Chrome MCP / Burp", "validate this DOM XSS / postMessage finding in a browser".
---

# browser-exploration — the surface only a real, logged-in browser can show you

> Read `skills/shared/_recon-method.md` first — it holds the loop, the input rule and the tool contract.
> Runtime browsers come from `.mcp.json` (`chrome` — Playwright; `burp` — proxy history) or a
> hunter-driven browser proxied through `tooling.burp_proxy`; see `playbooks/system/mcp-tooling.md`.
>
> **Static recon reads what the server ships. This skill reads what the app does after login,
> after the router renders, after the bundle executes.** A crawler sees the shell; the browser
> sees the authenticated menu, the fetch the page actually makes, the token in localStorage, and
> whether `postMessage` really leaves the frame. Those are four things no `httpx`/`katana` run
> can produce — and each one has produced real bounties.

## Objective

Drive one application in a real browser — authenticated with a recorded principal when the
surface needs it — and come back with the signals below. Two modes, named before you start:

- **OBSERVE (default).** Navigate routes, read the DOM and the network log, inspect storage and
  headers. Nothing that changes server or persistent client state: no action buttons, no
  purchases, no invites. This is `application-mapping`'s rule, applied to a browser.
- **ACT (validation only, one action at a time).** Only when validating a named client-side
  hypothesis — send the postMessage the sender test names, set `location.hash` to the canary,
  click the one element the sink trace ends at. One variable, then read the result. Anything
  beyond the hypothesis's own action is a new decision for the hunter.

## Inputs

**Enrichment — each absent one narrows the run, none of them gates it:**

- `@accounts` (optional, from `init-target`) — **required the moment the run is authenticated.**
  A principal with `status = ready` and a resolvable credential reference; state which one you
  used in every artifact. Credentials come from the recorded principal, never from you. A
  logged-out pass over an authenticated app is a bounded result, not a substitute.
- `@app.current` (optional, from `application-mapping`) — routes the UI already reaches. The point of
  browsing is the **delta**: views that render only under client state the mapper never had.
- `@js` (optional, from `javascript-analysis`) — the declared route table and postMessage
  candidates. In the browser you confirm or refute what the bundle only suggested.
- `@tech` (optional, from `technology-fingerprinting`) — the framework decides where the router
  table lives in the DOM and what a route change looks like on the network.

**As the selector, at least one of the following:**

- `@hunter.host` — one exact application the hunter named. Browse it directly; no estate-wide
  inventory required first.
- `@hosts.live` (optional, from `http-probing`) — browse each live application as its own
  coverage unit, bounded by a stated budget.

## Signals — what to come back with

1. **The rendered route delta.** SPA routers hide views behind auth state, feature flags and
   deep-linkable URLs no page links. Drive the router (URL bar, in-app navigation), record every
   view that rendered but appears in no `@app.current` route list. Hand it to authz testing exactly
   like the bundle route delta — a view the UI guards but the API does not is the classic BOLA.
2. **The network log as the endpoint oracle.** The bundle *declares* fetches; the browser
   *proves* which fire, with what method, headers and body shape, after login. Capture the
   authenticated XHR/fetch set — proxied through Burp it imports cleanly (`import-http.py`);
   from Chrome MCP, export the HAR. This is the highest-yield artifact of the skill: an endpoint
   list the app itself vouches for, with the session attached.
3. **Token and session placement.** Where the auth material lives after login — cookie
   attributes (`Secure`, `HttpOnly`, `SameSite`, `__Host-`/`__Secure-` prefixes), localStorage vs
   sessionStorage vs memory, what the token is attached to (query parameter on a GET is itself a
   leak hypothesis). Also the login redirect chain: where the authorization response lands and
   what fragment/query it carries.
4. **postMessage senders — validated, not grepped.** Frame the app from an origin you control
   (a `data:` URL page or a local `http://127.0.0.1` listener) and *listen*: a sender that
   broadcasts a token to `'*'` will deliver it to you with zero interaction on many apps. Record
   the message's content type, what it carries, and the guard (if any) on the receiving side —
   `event.origin` checks vs the weaker `event.source` check, wildcard allowlists, unanchored
   regexes. This is the Microsoft variant-hunting pattern; senders are still under-hunted.
5. **DOM XSS source→sink, confirmed with a canary.** For a candidate from `@js` (or the URL
   itself): set the source to a canary string (`canary7f3a`), trigger the path, and observe
   whether the canary arrives in the sink's input — element text (safe), `innerHTML`/
   `document.write`/eval-shaped sinks (the finding), URL passed to `location`/`open`. DevTools
   breakpoints on the sink beat re-running with louder payloads: the question is *reachability*,
   and a canary that arrives unexecuted answers it without firing the sink.
6. **CSP and framing posture, as evidence.** `Content-Security-Policy` (and `-Report-Only`):
   `unsafe-inline`, wildcard schemes, gaps that decide whether a DOM XSS is exploitable or
   theoretical. `X-Frame-Options`/`frame-ancestors` absence is what made signal 4 possible —
   record it either way, it prices the postMessage finding.

## Known traps

- **A crawler is not a browser and neither is `curl`.** If the app is a JS shell, treat earlier
  non-browser probes of it as the shell's fingerprints, not the app's surface — the delta
  between them is this skill's input, not a contradiction.
- **The cache lies.** Disable it or hard-reload before reading the network log, or you are
  validating yesterday's bundle. Service workers extend the lie across reloads — unregister
  them for the session when testing delivery behavior, and say that you did.
- **Login is an ACT.** It is a state change on the account. It is authorized the moment the
  hunter supplies the principal for an authenticated run — that is what the account is for —
  but it goes in the run record, and anything the post-login landing page auto-plays (tour
  popups, notification writes) is OBSERVED, not driven further.
- **One tab per principal.** Two principals in one browser profile cross-contaminate cookies and
  localStorage and manufacture both false positives and false negatives. Separate profiles or
  containers, always, for any comparison.
- **HTTPS through Burp needs the CA cert** installed in the browser profile, or every request
  fails closed and the network log quietly empties — a missing log is a failure, not a quiet app.
- **`data:`-URL framing is your listener's origin, not the app's.** A sender guarded to
  `origin === 'https://app.example'` will correctly not deliver to it; record the guard rather
  than treating silence as absence. To test a weak guard, name the bypass you are attempting —
  that is ACT mode with one variable.
- **Screenshots and HARs are evidence, not context.** Large ones belong in `loot/` with pointers
   from the brain — the local/VPS split applies to browser artifacts like any other.

## Outputs

- **`@endpoints` contributions** — the authenticated XHR/fetch set with method and body shape,
  via `import-http.py` (Burp/HAR) or `tools/surface.py` for a normalized handoff. Runtime
  confirmation outranks bundle declaration; merge accordingly.
- **`@js` additions** — postMessage senders/receivers with their guards, confirmed DOM XSS
  source→sink paths with the canary evidence, CSP/framing posture per host.
- Facts via `kb.py add` — storage layout, cookie/token placement, CSP shape, framing posture,
  each with the artifact pointer (`observed` requires evidence).
- Hypotheses into `hypotheses.md` — anything ACT-mode would escalate (a canary that reached
  `innerHTML`, a token that arrived in your listener). Validation of *those* is a `vuln-hunt`
  decision, not a next click.
- The route delta → `@target` *Interesting leads*, same handoff as `javascript-analysis`.

## Exit criteria

The route delta is computed against `@app.current` (or its absence stated with the reason). The
authenticated network set was captured and merged, or the exact normalization step still pending
is named. Storage, CSP and framing posture are recorded with evidence pointers. Every postMessage
or DOM-XSS validation names its mode, its single variable, and stores the request/response or
DOM evidence — a canary that reached a sink with no artifact is a hypothesis, not a finding.
What was browsed, which principal was used, and what was deliberately not driven is written
down; "explored the app" over an unstated subset is not a result.

## Next

Offer, do not choose: `vuln-hunt` with `playbooks/vulns/xss.md` or the postMessage angle (a
confirmed canary path is exactly its entrypoint) · `application-mapping` (the route delta seeds
the real map) · `import-http.py` for the full capture · `derive-properties` once the
authenticated endpoint set is merged.
