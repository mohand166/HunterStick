# Password Reset — the method

> **This is a test of your ability to reach account takeover via password reset** on the reset
> flow the human names — the chain that lets you set or steal another user's credential. Model the
> flow to the **token generation and the token-consuming check**: how the token is derived, where
> the link is built, and how it is bound to the requesting user — then find where that binding or
> that secrecy breaks. The value is a named break in the binding, not a spray at the reset form.
> Predictability, leakage, host-header poisoning and reset-to-takeover are the seams. Reset only
> accounts you own. Work this with `playbooks/vulns/_master-vuln-hunting.md`.

---

## 1. Model the reset chain before you touch anything

**SOURCE** — what you supply: the identifier on `/forgot-password`; the request headers
(`Host`, `X-Forwarded-Host`, `X-Forwarded-For`, `Referer`); and at the consume step, the token
plus anything shipped beside it (`email`, `user_id`, the new password).

**FEED** — what carries it: the reset request → the token generator → the **mail-templating layer
that builds the link** → the delivered mail → the token-consuming endpoint. API/GraphQL reset
mutations are the same chain on a different transport.

**SINK** — the token-consuming endpoint. It selects an account and writes a credential onto it.
That write is the effect; every earlier step exists only to decide *whose* account.

**CONTEXT — which step establishes what, and what the next step assumes.** Walk the flow once and
write down, per step, the fact it establishes and the fact its successor merely trusts:

| step | is supposed to establish | the next step assumes |
|---|---|---|
| request reset | which account the flow is for | the identifier resolves the same way login resolves it |
| generate token | a secret for one user, once, for a while | high entropy, single-use, time-bound, **bound to one specific user** |
| build the link | the origin the victim will click | the base URL came from fixed server config, not from a request header |
| deliver | only the mailbox owner sees the token | nothing on the reset page hands the token onward |
| consume | the bearer is that user | the target account is derived **solely from the token** |

Any step whose assumption is not established by its predecessor is the bug. The token is meant to be
high-entropy, single-use, time-bound and user-bound — **which of those four is missing?** And does
the consume step also read an attacker-controllable `email`/`id`? That is a takeover primitive alone.

**ROOT CAUSE** — one of: token short / sequential / timestamp-derived / base64 of the user id or
email · token never expires · single-use not enforced (replayable) · token not bound to the
requesting user (works for a different account) · the reset URL's base is built from a
request-controlled header → **host-header poisoning** · the token leaks to a third party (Referer
from the reset page, analytics query strings, redirects, the response body, logs) · the consume
step trusts a client-supplied `email`/`user_id` beside the token · the step can be skipped outright
(new password with no valid token) · an OTP/code short enough to guess with no attempt throttling ·
the token survives use, or survives a password change. **That answer is your `fix_locus`** — the
specific generation, validation or templating site.

## 2. Derive the candidates — reason about what the flow must do

1. **Enumerate the whole chain, not just `/forgot-password`.** The request endpoint, the
   token-consuming endpoint and the **mail-templating layer that builds the link** are three
   separate pieces of code; only one has to be wrong.
2. **Find the other reset paths.** API and GraphQL reset mutations, mobile clients, and admin- or
   support-initiated resets are the same flow with different (often thinner) validation.
3. **Ask where the base URL in the email comes from** — fixed server config or a request header.
   If *any* header influences it, poisoning is in play; that question alone selects the technique.
4. **List what the reset page loads.** Every third-party asset, beacon and redirect on it is a
   candidate leak path for the token sitting in the URL.
5. **Look at what else the reset invalidates** — sessions, MFA enrolment, old tokens. A reset that
   clears MFA is a second finding inside the first (`mfa.md`).

## 3. Determine the context — cheap probes on your own account first

Every probe here runs against **test accounts from `accounts.md` that you own**; none needs a victim.

- Request a reset for your own account and **inspect the token's structure and entropy**: length,
  charset, whether it decodes to something meaningful, whether two tokens issued back-to-back are
  related.
- **Expiry and single-use:** wait, then use it; use it, then use it again. One request each.
- **Where the link points:** read the actual delivered mail, not the HTTP response.
- **What leaks:** load the reset page in a proxied browser and read the outbound requests and
  `Referer` values.

## 4. Test → Confirm → Validate

**Accounts gate:** the cross-user binding test needs **≥2 principals** — two accounts you own, A and
B. Without them the honest result for that sub-case is `coverage = blocked (needs-account)`, not
"not vulnerable".

**TEST — is the assumption reachable?** Send the reset with a spoofed `Host`/`X-Forwarded-Host` set
to a **benign domain you control**. Generate a token for A and try to consume it for B. Submit the
consume step with an `email`/`id` that disagrees with the token. Submit a new password with no token
at all. **Outcome: a hypothesis.**

**CONFIRM — the default oracle is the mail actually delivered to an inbox you own, plus the
account's post-state.** Not the HTTP response. For poisoning, proof is the link *in your own inbox*
pointing at your benign domain — no need to phish anyone. For binding, proof is B's password
actually changing. **The oracle inverts or lies in these ways:**

- The `Host` header is reflected in the *response* but the **mailed link still uses the correct
  fixed domain** — only the mailed message counts; verify the actual message.
- A token that looks "non-expiring" is in fact invalidated on the next login or the next reset
  request — re-test through those paths before claiming it.
- A token that looks low-entropy (short) may be server-validated against a stored random secret.
  Structure alone is not predictability; **prove guessability** or don't claim it.
- A `Referer` leak to a first-party domain (same origin) is not a third-party exposure.

**VALIDATE — the least that proves takeover.** The poisoned link in your own mail, or A's token
resetting B. Stop there; you don't need to take over an account that isn't yours to show you could.

## 5. Safety — this class touches real accounts and real inboxes

- **Never** brute-force OTP codes against a real user, **never** trigger reset floods into other
  people's inboxes, and **never** actually take over an account that isn't yours.
- Spoof the host header only to a **benign domain you control**, and read the result in your own
  mailbox — the PoC ends at the poisoned link, not at a click. Use inboxes from `accounts.md`;
  both sides of a cross-user test must be yours.
- **Store the artifact**: the raw email source (where the poisoned link lives), the reset request
  pair, and the post-state showing whose credential changed. **No artifact → HYPOTHESIS, not
  FACT.** Redact the token value beyond what proves the point.
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`) — Burp Repeater or a copy-pasteable
  `curl` with its control request — plus the delivered mail.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the
`fix_locus` from §1 — name the *step* that failed (generator, templater, consumer), not just the
URL. Log negatives with the oracle used, so the next session knows whether you read the mail or only
the response.

**Novelty.** Reported to death, and often dup or out-of-scope: "no rate limit on the reset form",
user-enumeration via the reset response, reset links that don't expire *fast enough*, a token still
valid after an email change. Novel: **host-header poisoning that actually rewrites the mailed
link**, a token **not bound to the user** (cross-account reset), **step-skip / trusted-email**
takeover, a guessable short OTP with no throttle, or third-party **token leakage** via `Referer`.
Full **account takeover** is the standard high-severity outcome — reset is the classic ATO
primitive, so impact is usually clear once the flaw is proven. Chains: username enumeration
(`login.md`) picks targets → poisoned or leaked token → takeover; a normalization gap
(`registration.md`) → the reset lands on the wrong record; a reset that also clears MFA (`mfa.md`)
→ complete second-factor bypass.

**Worked example.** `technologies.md` flags a self-hosted mail-templating layer and the reset mail's
link domain isn't obviously pinned to a fixed config; `accounts.md` gives you an inbox you own and
you control a benign domain. *Model:* the whole question is **where the base URL comes from** —
hardcoded config or a request header — and the discriminator is the domain inside your own
delivered email, not what's reflected in the HTTP response. *Hypothesis:* the reset endpoint builds
the link from the request `Host`, so a spoofed header rewrites the link's origin while the valid
token rides along. *Test/confirm:* request a reset for *your own* account with `X-Forwarded-Host`
set to your benign domain, then read your inbox. Proof is the poisoned link in your own mail — no
victim, no token brute-force, no OTP spam; save the raw email source. *Novelty:* rate limiting and
reset-based enumeration are excluded everywhere; a header that genuinely rewrites the *mailed* link
is the ATO-grade finding — `fix_locus = base-URL construction in the reset mail templater`.
