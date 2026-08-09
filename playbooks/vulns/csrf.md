# Cross-Site Request Forgery (CSRF) — the method

> **This is a test of your ability to force a state-changing action cross-site** on the request the
> human names — the chain that makes a victim's browser perform an action they didn't intend. Model
> the request down to the **server-side CSRF check**: what the app relies on to prove intent (token,
> SameSite, custom header, content-type), what the browser will attach on its own, and where that
> proof is absent or forgeable off-origin. Confirm *real impact* — not every tokenless form. Thin
> class file; work it with `playbooks/vulns/_master-vuln-hunting.md`.

## 1. Model the trust relationship before you touch anything

**SOURCE** — an attacker-controlled page on a genuinely different origin: an auto-submitting HTML
form, an image/link navigation, a `fetch`.

**FEED** — the browser. It is the thing that supplies the credential, so the question is what it will
attach and under what conditions: an ambient session cookie (subject to `SameSite`), and whether the
request can be a **simple request** needing no CORS preflight.

**SINK** — the server-side handler that performs the state change, and the check it runs (or doesn't)
before doing so.

**CONTEXT** — the discriminator is **what the app treats as proof of intent, and whether an
off-origin page can produce it**:

- **Is auth purely an ambient cookie?** If it's a custom header or bearer token the browser won't
  auto-attach, CSRF usually doesn't apply — establish that first.
- **Is there an anti-CSRF token, and is it actually enforced?** Removed, blanked, reused, another
  user's — does the server still accept?
- **What `SameSite` value is on the auth cookie**, and does the real attack context (top-level
  navigation, same-site subdomain, a `None` cookie) defeat it?
- **Can the action be triggered by a simple request** (form-submittable method + content-type), so no
  preflight is needed? That is what makes it exploitable.

**ROOT CAUSE** — one of: no anti-CSRF token · a token present but **not validated** · a token in a
predictable place · a **GET endpoint that changes state** · a cookie without `SameSite` (or `None`)
in a context where it isn't defaulted safely, or a flow that *needs* cross-site cookies and so can't
rely on it · protection only on `POST` while the action also accepts `GET`/`PUT` · JSON-only
validation bypassed via `text/plain`/form content-type or a method-override header
(`X-HTTP-Method-Override`). **That answer is your `fix_locus`** — the specific endpoint +
missing check, so distinct forgeable actions count separately.

## 2. Derive the candidates — rank by what the forged action does

1. **Enumerate state-changing, cookie-authenticated requests:** profile/email/password change, fund
   transfer, role/permission change, delete, connect-integration, admin actions.
2. **Rank them by impact, not by whether a token is missing.** Impact *is* whatever the forged action
   does, so start where a takeover or a payment lives.
3. **Include the auth-flow variants:** **login CSRF** (forced login into the attacker's account, so
   the victim's data lands there) and **logout CSRF** — impact depends entirely on the flow.
4. **Look for the bypass shapes** rather than the absent token: a JSON endpoint that accepts a body
   an HTML form can produce (`text/plain` trick, or it ignores content-type) → forgeable without
   CORS; a method-override header; a state-changing `GET`.
5. **Check the GraphQL endpoint specifically.** Many accept `application/x-www-form-urlencoded` or
   ignore content-type entirely, which makes **every mutation** cross-origin postable from a plain
   HTML form — one missing check covering the whole schema at once. Same question for a REST
   transcoding gateway in front of gRPC, whose CSRF middleware may not match the native path's.

## 3. Determine the context — before you build a PoC

Cheap, one request each:

- **Strip the credential**: does the endpoint work without the session cookie? If yes, it isn't
  cookie-authenticated and this class doesn't apply.
- **Read the cookie flags** for `SameSite`, and note whether the app's own flows require cross-site
  cookies.
- **Replay with the token removed / blanked / another user's** and observe acceptance — that is the
  token-validation check, and it is a server-side replay, not yet a cross-site test.
- **Probe the content-type and method tolerance**: does the JSON handler accept `text/plain` or a
  form encoding? Does the action also accept `GET`/`PUT`, or a method-override header?

## 4. Test → Confirm → Validate

**Accounts gate:** use **two test accounts from `accounts.md`** — victim (yours) and attacker
(yours). Without them the honest result is `coverage = blocked (needs-account)`.

**TEST — does the server accept the request without the proof?** The §3 replay with the token
stripped. **Outcome: a hypothesis** — a same-origin replay is not a forgery.

**CONFIRM — the default oracle is the state change observed server-side, as the victim, driven from
a genuinely different origin.** Build the smallest **cross-origin** PoC (auto-submitting form /
`fetch`) that performs a benign, reversible change (e.g. a display-name field) on the victim account
while you are authenticated as the victim in the browser, with **no token / a stripped token**. That
end-to-end cross-site success is the proof. Where the oracle inverts or lies:

- **"No CSRF token" on an endpoint actually protected by `SameSite=Lax/Strict` defaults or by a
  non-cookie bearer token** — reproduce the forgery cross-site or it isn't one.
- **The endpoint reflects success in your same-site test but fails truly cross-origin** — always test
  from a genuinely different origin, not a same-site tab.
- **CORS being "misconfigured" ≠ CSRF** — a readable *response* needs CORS, but forging a *simple*
  request doesn't. Don't conflate them.
- **Login/logout CSRF with no meaningful impact on this app** — the primitive exists but proves
  nothing worth reporting.

**VALIDATE — the least that proves impact.** Prove the primitive on the harmless field, then tie
severity to the *specific* action it generalizes to, not to "CSRF exists": email/password change →
**account takeover**; role change → privilege escalation; fund/transfer → financial. Chains: login
CSRF → victim operates in the attacker's account (data capture) or the attacker pre-seeds state,
often with `oauth-oidc.md` forced-linking and `registration.md` pre-ATO; CSRF the email-change → then
`password-reset.md` to the new address → takeover even where the reset itself is solid.

## 5. Safety, artifact, and PoC handoff

- **Non-destructive:** pick a reversible, low-value action and revert it afterwards. **Never forge
  destructive actions (delete, transfer) against anyone** — confirm the *primitive* on a harmless
  field instead.
- **Don't run the PoC against real users.** Victim and attacker are both accounts you own.
- **Store the artifact:** the PoC page, plus the server-confirmed diff showing the change landed on
  the victim account. **No artifact → HYPOTHESIS, not FACT.**
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): the self-contained attacker-origin
  HTML page — that *is* the PoC — plus the forged request in **Burp Repeater** or as
  copy-pasteable `curl` with its token-stripped/token-present control pair.
- Respect the program's rate limit; a forgery PoC is a handful of requests, not a sweep.

## 6. Log it

`targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the `fix_locus` from §1 — the
specific endpoint + missing check. Log negatives *with the oracle used*: "accepted on same-site
replay but blocked cross-origin", "`SameSite=Strict` on the auth cookie", "bearer auth, not cookie".

**Novelty:** **reported to death / often dup or out-of-scope** — logout CSRF, CSRF on a no-impact
action (newsletter toggle), "form lacks CSRF token" with `SameSite` actually protecting it,
self-CSRF. Most programs exclude low/no-impact CSRF outright. **Novel:** CSRF on a **high-impact**
action that survives the app's real defenses — token **not validated**, a **method/content-type**
bypass around JSON protection, a **SameSite-defeating** context, or a login-CSRF chain into takeover.

## 7. Worked example — the spine in one pass

*Model / derive:* `endpoints.md` lists an email-change API taking a JSON body, authenticated purely
by the session cookie; `technologies.md` suggests the auth cookie is `SameSite=Lax`. `accounts.md`
gives victim and attacker accounts you own — and email-change is a takeover-grade action, so it
ranks first.
*Context:* `SameSite=Lax` blocks cross-site cookies on background subrequests but *not* on top-level
navigations, and it protects nothing if the endpoint accepts a simple request. If the JSON handler
also accepts `text/plain` (or ignores content-type), an HTML form can forge the body with no
preflight — the discriminator is whether the change lands server-side from an attacker origin with
the token absent.
*Hypothesis:* the email-change endpoint accepts a form-encodable `text/plain` body and doesn't
validate an anti-CSRF token, making it forgeable cross-site despite `SameSite=Lax`.
*Confirm:* from a genuinely different origin, auto-submit a form doing a *reversible* change (a
display-name field, not email) on my own victim account, token stripped; confirm the change
server-side, then revert. Prove the primitive on the harmless field before claiming the email path.
Save the PoC page + the server-confirmed diff.
*Dedup:* "form lacks CSRF token" with SameSite actually protecting it is the dup; a content-type
bypass defeating the JSON+SameSite defense on a takeover-grade action is the novelty —
`fix_locus = the email-change endpoint's token check / content-type handling`.
