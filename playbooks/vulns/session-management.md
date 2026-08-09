# Session Management — the method

> **This is a test of your ability to hijack a session or forge a token** in the auth flow the human
> names — the chain that lets you act as another user. Model where a token is **minted, presented
> and trusted**, understand what the server verifies before honoring it, and find where that trust
> is misplaced. Fixation, weak or predictable IDs, broken invalidation, JWT verification gaps and
> cookie flags are the seams. **Probe only sessions you own.** The value is a demonstrated trust
> failure, not a scanner's cookie-flag list. Work this with
> `playbooks/vulns/_master-vuln-hunting.md`.

---

## 1. Model the session before you touch anything

**SOURCE** — where does a token come from? `Set-Cookie` on login, a JWT minted by an IdP, an opaque
session ID, a "remember me" token, an API key acting as a session — and anything *you* can plant
before authentication.

**FEED** — what carries it, and who else sees it: the cookie jar (with its `Domain`/`Path` scope),
an `Authorization` header, `localStorage`/`sessionStorage`, a URL parameter. Note every hop that
could copy, refresh or leak the value.

**SINK** — the verify routine that decides "this request is that user": signature check, session
store lookup, claim validation. That routine, not the login page, is what you are testing.

**CONTEXT** — the discriminator here is **how the session is established, carried, rotated and
revoked**. Answer all four before probing:

| axis | the question | the failure it names |
|---|---|---|
| established | is the identifier **regenerated** at every privilege boundary (pre-login → post-login, step-up)? | **fixation** — a value set before auth still authenticates after |
| carried | opaque or JWT? which store? what `Domain`/`Path`/`HttpOnly`/`Secure`/`SameSite`? | cookie scope leaking to untrusted subdomains; XSS-stealable tokens |
| minted | is it random and long enough? | sequential / timestamp / short / low-entropy IDs; guessable "remember me"; predictable API keys |
| verified | for JWT: which `alg`, is the signature *actually* checked, are `exp`/`aud`/`iss` enforced? | `alg:none`, RS256→HS256 confusion (public key as HMAC secret), `kid` header injection (path/SQL/command to swap the key), brute-forceable weak HMAC secret |
| revoked | on logout / password change / MFA change / account disable, is it killed **server-side**? | client-only logout; no idle or absolute timeout |

**Enumerate every token store, every backend.** An app often holds **more than one** session — a
cookie for the primary API **plus** a `localStorage` JWT for a BaaS/sub-app backend
(Supabase/Firebase; see `baas-rls.md`). Ask of each: does logout clear *this* store and invalidate
*this* token, and is this backend's session **bound to the current primary identity**? A token
minted for user/role X that still authenticates after the primary session switched to user Y is
**cross-backend session inheritance** — a leftover higher-privilege token (e.g.
`facilitator`/`admin`) sitting in `localStorage` gets reused by the *next* primary-app user on a
shared browser, and it silently auto-refreshes.

**ROOT CAUSE** — one of: the identifier isn't rotated at a privilege boundary · the mint has too
little entropy · the algorithm isn't pinned or the signature isn't verified · a claim
(`exp`/`aud`/`iss`) isn't enforced · revocation is client-side only · one of several stores is never
cleared · a sub-app session isn't bound to the primary identity · the cookie's `Domain` is broader
than the trust boundary. **That answer is your `fix_locus`** — the specific mint / verify /
invalidate routine, so distinct token flaws count separately.

## 2. Derive the candidates — follow the tokens, not a checklist

1. **Inventory every credential the app holds** for one logged-in session: each cookie, each
   `localStorage`/`sessionStorage` entry, each header the JS attaches, across **every backend** — the
   primary API, BaaS sub-apps, anything with its own token and its own lifetime. Anything that
   survives a reload and rides on authenticated requests is a candidate.
2. **Enumerate the privilege boundaries**, because that's where rotation is supposed to happen:
   login, step-up/MFA, role switch, impersonation, password change.
3. **Enumerate the revocation events**: logout, password change, MFA change, account disable, session
   list "sign out other devices".
4. **Read `technologies.md`** for the auth stack (IdP, JWT library, session store) — it names the
   verify routine you are actually attacking.

## 3. Determine the context — cheap observations first

None of these forge anything; they locate you.

- **Capture pre-auth and post-auth values and compare.** Equality at a privilege boundary is the
  fixation signal — but first identify *which* token actually carries auth (see §4).
- **Decode the JWT header locally.** What `alg`, which claims? A local read, no request sent.
- **Read the raw `Set-Cookie`.** Attributes are a configuration observation, no exploitation needed;
  note whether `Domain` scopes the session to subdomains an attacker might control. **Time the
  lifetime** — is there an idle or absolute timeout at all?
- **Switch primary identity in the same browser** and re-check each sub-app's token to see whether it
  is rebound or inherited.

## 4. Test → Confirm → Validate

**Accounts gate:** use the **test accounts from `accounts.md`**. Identity-switch and cross-backend
inheritance tests need **≥2 principals** on the same browser; without them the honest result is
`coverage = blocked (needs-account)` — not "not vulnerable".

**TEST — does the token behave the way the model predicts?** The pre/post-auth comparison, the local
JWT decode, the replay after logout. **Outcome: a hypothesis.**

**CONFIRM — did the *server* honor it?** The **default oracle is a state-relevant authenticated
endpoint answering as the claimed identity while the request carries only the token under test, from
a clean session.** A `200` on a cached or public route is not the oracle. Concretely: replay the
captured token after logout or password change on an authenticated endpoint → still-200 means broken
invalidation; present a self-forged token to one authenticated endpoint and see the server act on it.
The oracle inverts or lies here — rule each out:

- A session value that *looks* unchanged while the server rotated a **second, real token** — identify
  which token actually carries auth before claiming fixation.
- "Still valid after logout" observed inside a **cache window** — reconfirm after a clear interval
  *and* against a state-changing action.
- **JWT `alg:none` "accepted" by a permissive decoder in your own tooling** but rejected by the
  server. Prove the *server* honored the forged token; your console is not evidence.
- Missing `HttpOnly` with **no XSS anywhere reachable** — a hardening note, low on its own. Report it
  chained to an XSS sink or don't lead with it.

**VALIDATE — the least that proves impact.** Predictable or replayable tokens and JWT forgery →
**session hijacking / account takeover**; forging the `sub`/`role` claim → privilege escalation to
admin. Fixation → ATO where the attacker can plant the pre-auth value (chains with XSS or a
URL/cookie-setting vector). Broken invalidation → persistence after the victim believes they logged
out or rotated their password. Chains: missing `HttpOnly` + XSS → session theft; broad cookie
`Domain` + subdomain takeover → session leak; JWT confusion → auth bypass across the whole API.
Prove one such action, self-scoped, then stop and say what you did not do.

## 5. Safety, artifact, and PoC handoff

- **Never hijack a real user's live session.** Every probe runs against a session you own.
- **Forge only for your own user id/role.** Never forge another user's `sub` against production to
  "prove" it beyond a minimal self-scoped check. **No brute force at scale** — no session-ID guessing
  sprees, no cracking a JWT secret with a giant wordlist against the live service.
- **Store the artifact** under `targets/<t>/raw/`: the pre/post-auth token pair, the replayed token
  with its post-logout 200, the forged token with the server's response, or the raw `Set-Cookie`.
  **No artifact → HYPOTHESIS, not FACT.** Redact the token bodies down to what the proof needs.
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): the request to **Burp Repeater**, or a
  copy-pasteable `curl` carrying the token under test **plus its control** (the same request without
  it, or with the post-logout token), reproducible in one action from a clean session. Respect the
  rate limit; announce anything loud first.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with `result`,
`coverage` and the **`fix_locus` from §1** — the specific mint / verify / invalidate routine, so
distinct token flaws count separately. Log negatives *with the oracle used*.

**Novelty.** Reported to death, and often dup or out-of-scope: cookie "missing
`Secure`/`HttpOnly`/`SameSite`" as a lone scanner finding, "session doesn't expire" with no
demonstrated impact, logout CSRF. Novel: genuine **session fixation at a privilege boundary**, **JWT
`alg:none` / confusion / `kid`-injection the server actually honors**, **server-side
non-invalidation** after logout or password change, and **predictable tokens you can *demonstrate*
guessing**.

## 7. Worked example — the spine in one pass

*Model / derive:* `technologies.md` notes a JWT-based API (bearer in `Authorization`), and the token
is the only credential attached to authenticated requests — so the verify routine is the sink. The
trust hinges on the server verifying the RS256 signature with the IdP's public key. Context axis =
**verified**.
*Context:* decode the header locally — no request sent. Your own `accounts.md` session's token shows
`alg: RS256` with `sub` and `role` claims: a stateless verifier you can probe locally first.
*Hypothesis:* the verify routine doesn't pin the algorithm, so an HS256 token signed with the RSA
public key (for *your own* `sub`) is accepted — the classic algorithm confusion.
*Confirm:* forge a token only for your own user id/role and present it to one authenticated endpoint.
The oracle is the *server* honoring it, not your local decoder accepting it. No forging another
user's `sub`, no wordlist secret-cracking against prod. Artifact = the forged token and the 200.
*Novelty:* lone "missing `HttpOnly`/`Secure`" scanner flags are dups; an alg-confusion forgery the
server accepts is auth-bypass-grade — `fix_locus = the JWT signature-verification routine (algorithm
not pinned)`.
