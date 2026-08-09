---
name: authentication-surface-mapping
description: Map every way in, and every way the way in fails. Use for "authentication surface mapping" and closely related asks.
---

# authentication-surface-mapping — map every way in, and every way the way in fails

> Read `skills/_recon-method.md` first — it holds the loop, the input rule and the tool contract.
> This file holds what is specific to authentication.
>
> **This is a test of your ability to describe an authentication system precisely enough that
> someone else could attack it.** The value is not "there is a login page and it uses OAuth". It is
> the observable mechanics: what the cookie is scoped to, what the client is holding, which claims
> inside it the server appears to trust, and what each flow does when it *fails* — because the
> happy path is the one that was tested before shipping.

## Objective

Enumerate every authentication and session flow the target exposes, map each one's **error and
non-happy paths** as carefully as its success path, and record the mechanics that decide severity
for the classes that follow. This skill maps; it does not attack. Where a step would require sending
a crafted credential, record it as a named hypothesis and hand it to hunting.

## Inputs

**Enrichment — each absent one narrows the run, none of them gates it:**

- `@raw.http` (optional, from `http-probing`) — `Set-Cookie` lines, redirect chains,
  `WWW-Authenticate`, security headers. Most of signal 2 is already sitting in this artifact.
- `@js` (optional, from `javascript-analysis`) — the client's own auth code: token storage,
  refresh logic, IdP configuration, which claims it reads.
- `@endpoints` (optional, from `api-discovery`) — auth operations that no UI screen invokes;
  a recovered schema usually names the whole reset and MFA surface.
- `@urls` (optional, from `url-collection`) — historical callback URLs and legacy login paths.
- `@accounts` (optional, from `init-target`) — not required to map the surface. One principal lets
  you observe a real session and a real token; without one you still map every flow's shape, its
  error behaviour and the unauthenticated half of each handshake.

**As the selector, at least one of the following:**

- `@hunter.host` — one exact application the hunter named. Map its public authentication surface
  directly; missing prior HTTP or JavaScript artifacts narrows the evidence but does not block it.
- `@hosts.live` (from `http-probing`) — the live set whose auth-shaped entrypoints should be mapped.

## Signals — what to come back with

1. **The flow inventory, by shape rather than by path.** Login, registration, password reset,
   password change, email change, SSO/OAuth/SAML entry and callback, MFA enrolment and verification,
   "remember me", session refresh, logout, invite and activation, step-up for sensitive actions,
   and any legacy or mobile-only variant. Each with its endpoints and the order they are called in.
2. **Cookie scope and flags, verbatim.** **`Domain=.example.com` is the observation that decides
   whether an XSS on a throwaway subdomain is P1 or informational** — it is what makes cookie
   tossing and session theft across the estate possible at all. Record domain, path, `Secure`,
   `HttpOnly`, `SameSite` and lifetime per cookie, and note where the same session cookie appears
   across multiple hosts.
3. **What the client is holding, and what is inside it.** Where the session is a client-held token,
   record its structure and its claims — and flag any **role, tenant, plan or permission claim**.
   The reasoning is mechanical rather than measured: if an authorization input travels in something
   the client holds, the client holds part of an authorization decision, and whether the server
   re-derives it is exactly the question hunting should ask first. Treat this as the highest-signal
   observable in the stage and as a hypothesis, not a finding.
4. **The error and non-happy paths of every flow.** Wrong password, unknown user, expired token,
   reused token, cancelled consent, denied scope, mismatched state, back-navigation mid-flow,
   two tabs racing the same handshake. This is where the published work is — the 2024 OAuth
   technique is non-happy-path exploitation via `Referer`, not a broken happy path. A flow mapped
   only in success is half-mapped.
5. **The password reset sub-flow, in detail.** It is the highest-yield sub-flow in the whole
   surface. Record: is the code 4–6 digits; **is the verify step a different endpoint from the one
   the rate limiter sits on**; is it reachable over GraphQL where aliasing collapses N attempts into
   one request; is the token invalidated on use; is the reset link built from the `Host` or
   `X-Forwarded-Host` header; can the token leak via `Referer` on the landing page.
6. **The identity providers and the trust edges.** Which IdPs, which tenants, which redirect-URI
   allowlists, whether a `*.target` wildcard appears in an OAuth allowlist, whether accounts can
   exist under two providers with the same email, and what happens at the join.
7. **Where the token is accepted.** The same credential presented to a second service, a second
   version prefix or a second host is the version-drift question applied to auth. Missing `aud` or
   `iss` is what makes cross-service replay possible; record their presence or absence.
8. **Authorization decisions visible client-side.** Menu items, route guards, feature flags and
   plan gates rendered from client state. Each is a claim about what the server *should* enforce,
   and the list of them is a ready-made test list for the next skill.

## Known traps

- **[unsupported as a first move] `alg:none`.** Every maintained library rejects it, and leading
  with it wastes the first and most attentive pass over the token. The ordering that follows the
  mechanism is: **is the token verified at all** (flip one signature byte), then **is any
  authorization decision actually read from it**, then `kid` path or SQL injection, then `jku`/`x5u`
  pointing at a URL you control, then missing `aud`/`iss` enabling cross-service replay. That
  ordering is reasoned, not measured — hand it to hunting as an ordering, and note that every step
  in it is a *test*, not something this skill performs.
- **Status codes are not authorization truth.** A 200 with an empty array, a 403 that still writes,
  a 404 meaning "exists but not yours", and a **500 that means the handler ran before any auth
  check — which is louder than a 401**. Record the response body shape, not just the code.
- **A password reset sends real email to a real person.** Never trigger a reset for an address you
  do not own. Enumerating the flow's mechanics on your own address is mapping; firing it at a
  customer's address is not.
- **Repeated failed logins lock accounts — including accounts that are not yours.** Lockout
  behaviour is worth knowing and is cheap to trip accidentally; establish it on your own principal
  and stop, and treat anything that would lock a real user as out of bounds for a mapping run.
- **Mapping is not testing, and the line is the crafted credential.** Reading a cookie's `Domain`
  attribute is mapping. Flipping a signature byte, replaying a token at a second service, or
  submitting a code you do not have is `vuln-hunt`'s job with the hunter's authorisation. Write the
  hypothesis, do not run it here.
- **A single login form is rarely the whole surface.** Mobile and legacy clients often authenticate
  through a different endpoint with different controls, and it is the older path that skips the
  newer middleware. Look for the second login before concluding there is one.
- **The absence of an observable is not the absence of the mechanism.** No `Domain` attribute seen
  in your captured responses means you did not capture the response that set it — say "not
  observed", not "host-only".

## Outputs

- `@appmap` — the auth section of the per-app map: every flow, its endpoints, its call order, and
  its error paths.
- `@target` — the auth model in prose under the profile: session mechanism, cookie scoping across
  the estate, IdPs, where authorization inputs are client-held. FACT/HYPOTHESIS tagged.
- `@endpoints` — auth operations discovered here that were not in the API inventory.
- Facts via `kb.py add`: cookie scope per host, token structure and claim names, reset-flow
  mechanics, lockout and rate-limit behaviour observed, IdP inventory.
- Leads into `@hypotheses`: each client-held authorization claim, each reset-flow property from
  signal 5 that holds, any `*.target` wildcard in a redirect allowlist, any `Domain=.target` cookie
  paired with a large subdomain estate.

## Exit criteria

Every flow in signal 1 is either mapped or explicitly recorded as absent — "no SSO" is a finding
about the target and must be distinguishable from "did not look". **Every mapped flow has its error
paths written down**, not only its success path; a flow with a success path and no failure column is
incomplete and should be marked so. Cookie scope is recorded per cookie with the exact attributes
observed. Where a session token is client-held, its claims are listed and any authorization-bearing
claim is promoted to a hypothesis. Nothing in this run sent a crafted credential.

## Next

Offer: `application-mapping` (the flows you just mapped are half of an application map; roles,
tenancy and the state machines are the other half) · `derive-properties` (this skill is one of its
richest inputs — it is the only source for credential-dependent behaviour and the principal
dimension) · `api-discovery` (if the reset or MFA surface looks larger than the UI exposes, the
schema will name the rest) · `vuln-hunt` on a specific flow whose mechanics imply a class.
