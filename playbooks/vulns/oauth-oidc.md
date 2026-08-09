# OAuth 2.0 / OIDC — the method

> **This is a test of your ability to steal an auth code or token → ATO** in the OAuth/OIDC flow the
> human names — the chain that diverts a `code`/`token` to you or links an account you don't own.
> Model what each hop establishes and what the next hop assumes: the authorization request, the
> redirect/callback, the token exchange, the account link. Then find where a boundary is matched
> loosely or skipped — `redirect_uri` matching, `state`/`nonce`, code handling and account linking
> are the seams. Use client/test accounts you own. Work it with
> `playbooks/vulns/_master-vuln-hunting.md`.

---

## 1. Model the flow before you touch anything

**SOURCE** — what you control in the authorization request (`redirect_uri`, `state`, `nonce`,
scope, client id), in the callback (the returned `code`/`token`/`state`), and at the linking step
(the email or identity you present).

**FEED** — the hops: `/authorize` → the redirect/callback → `/oauth/token` → the resource or
session, plus "Sign in with X", "Connect your account", and SSO onboarding.

**SINK** — where the credential lands and who acts on it: the callback endpoint that receives the
`code`, the token exchange, the identity the client attaches to a local account.

**CONTEXT** — the discriminator is **which hop established what, and what the next hop assumes**:
- `/authorize` establishes *where the code may be delivered*: is `redirect_uri` **exact-matched** or
  something looser? Enumerate what the whitelist really allows (subpaths, subdomains, ports, an
  open redirect on the host).
- The callback establishes *that this response belongs to this session*: is `state` present,
  unguessable and **bound to the session** on return? Is OIDC `nonce` enforced?
- The token exchange establishes *that this token was minted for this client*: does the server
  **verify the audience and the `id_token` signature**, and trust only a **verified** email/`sub`
  from the right IdP? Is the `code` single-use and client-bound?
- Linking establishes *that you own the identity*: on "connect account", is ownership of the linked
  identity/email **proven**, or assumed?

**ROOT CAUSE** — one of: **`redirect_uri` matched by prefix/substring instead of exactly**, or an
allowed `localhost`/wildcard/open-redirect on the whitelisted host, letting a `redirect_uri` swap
send the `code`/`token` to the attacker · **`state` missing or unvalidated** → login CSRF / forced
account-linking, or `nonce` missing on OIDC → replay · **code leakage** — the `code` in the Referer
to third-party assets on the callback page, in logs/analytics, or reusable because it is not
single-use or not client-bound · **implicit flow** leaking the `token` in the URL fragment — **not via
Referer** (fragments are never sent in an HTTP request) but via browser history, a page script
reading `location.hash` and forwarding it, or the fragment surviving a redirect chain, or a still-enabled legacy implicit grant · **token confusion / IdP trust** — an
access token from a different client/audience accepted ("passing the wrong token"), an unverified
`id_token` signature, an `email`/`sub` trusted without verifying the IdP asserted it or that the
email is verified · **account linking by email** without proving ownership → pre-ATO / hostile
linking. **That answer is your `fix_locus`** — the specific validation step (redirect matcher, state
check, token verifier, linker), so distinct flaws count separately.

## 2. Derive the candidates — enumerate hops and validators

1. **Capture one full legitimate flow**; list every hop, every parameter, and every host that sees
   the `code`.
2. **Probe the whitelist's real shape**: subpaths, extra params, ports, subdomains, look-alike
   hosts — and any open redirect *on the allowed host*, which turns a host-level match into a
   delivery to you (`open-redirect.md`).
3. **Enumerate what loads on the callback page** — third-party scripts, analytics, anything getting
   a Referer while the `code` is still in the URL.
4. **List every path that links an identity to an account**: onboarding, "connect", legacy routes.

## 3. Determine the context — before you divert anything

- **Use your own client registration** and a **benign attacker domain you control**, against your
  own identities (`accounts.md`).
- **Read what the flow actually enforces**: is `state` echoed or checked? Is PKCE present? Is the
  grant authorization-code or implicit?
- **Baseline a clean flow that succeeds**, so a later failure is informative.

## 4. Test → Confirm → Validate

**Accounts gate:** this class needs **≥2 identities you own** — one to play the "victim" side of a
link or a diverted callback and one to receive it — plus a domain you control. Without them the
honest result is `coverage = blocked (needs-account)` — not "not vulnerable".

**TEST — one probe per validator.** `redirect_uri`: append a subpath, an extra param, a look-alike
host, or an open redirect on the allowed host. `state`: drop or reuse it on the callback. `code`:
exchange it twice. Token confusion: present a token minted for one audience/client to another.
Linking: link an identity by an email you own via one path and see if it attaches to a different
account you own. **Outcome: a hypothesis.**

**CONFIRM — the default oracle is the credential *arriving where it shouldn't***: the `code`/`token`
landing on your own endpoint, or the link/login completing without the binding. Reflection is not
arrival. The oracle lies when:
- the `redirect_uri` value is reflected but the IdP still **rejects at delivery** — only a
  code/token actually arriving off-whitelist proves it;
- "missing state" is actually covered by a different anti-CSRF control (PKCE + session binding) —
  confirm the callback is genuinely forgeable end to end;
- an open redirect on the app does **not** carry the `code` — annoying, but not a token leak; check
  what actually rides the redirect;
- you decoded an `id_token` locally as unsigned but the server verifies it server-side — prove the
  **server** accepted the tampered token.

**VALIDATE — the least that proves impact,** self-scoped throughout. Impact: `redirect_uri` bypass,
code leak or token confusion → **account takeover** via stolen authorization; unverified-email
linking → pre-ATO and hostile account linking; missing `state` → forced account-linking / login CSRF
(the attacker's identity attached to the victim, or the victim logged into the attacker's account to
harvest data). Chains: an open redirect on the whitelisted host + OAuth → code exfil;
`registration.md` normalization + email-based linking → cross-account takeover; a leaked token +
`session-management.md` → persistent access.

## 5. Safety, artifact, and PoC handoff

- **Never actually redirect a real victim's `code`/`token` to yourself**, and **never link or take
  over an account you don't own.** Every step runs against your own identities and your own domain.
- This flow crosses into a **third-party identity provider** — keep probes to your own client
  registration and your own IdP accounts; do not experiment against the provider's other tenants.
- **Store the artifact**: the callback hit showing the credential arriving off-whitelist, plus the
  clean-flow baseline. **No artifact → HYPOTHESIS.** Redact the code/token to the minimum that
  proves delivery.
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): the crafted authorization URL, the
  observed callback, and the control request, in Burp Repeater or copy-pasteable `curl`.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the
`fix_locus` from §1 recorded as the specific validation step. Log negatives with the oracle used —
"reflected but not delivered" is a meaningful negative worth recording. **Dedup:** "missing state
parameter" with no demonstrated linking/CSRF impact, self-XSS on the consent screen, and a generic
open redirect unrelated to the token are reported to death and often out of scope. Novelty is a
**`redirect_uri` bypass that actually exfiltrates the `code`/`token`**, **token/audience
confusion**, **email-based account linking without ownership proof** (pre-ATO), a reusable `code`,
or an `id_token` signature that is never verified.

## 7. Worked example — the spine in one pass

*Model:* `endpoints.md` shows a "Sign in with X" flow whose `/authorize` takes a `redirect_uri` on
the app's own domain, and `technologies.md` notes an unrelated open redirect elsewhere on that same
whitelisted host. `/authorize` is supposed to establish where the code may be delivered — validated
by host or prefix rather than exact match, the whole host becomes "trusted". *Derive:* an open
redirect *on that host* can bounce the `code` onward off-domain. *Context:* you control a benign
attacker domain and have your own client/test accounts (`accounts.md`); the discriminator is whether
the `code` actually arrives at an endpoint you control, not whether the value is reflected.
*Hypothesis:* `redirect_uri` matching is host-level, letting the `code` pass through the on-host open
redirect to your domain — a code-exfil primitive. *Confirm:* run the flow against *your own* identity
with `redirect_uri` set to the whitelisted open-redirect URL pointing at your benign domain, and see
whether your endpoint receives the `code`. Never aim a real victim's code at yourself. *PoC:* the
callback hit showing the code. *fix_locus:* the `redirect_uri` validation (host/prefix instead of
exact) — "missing state, no impact" is reported to death; a matcher that chains an on-host open
redirect into real code exfiltration is the novelty.
