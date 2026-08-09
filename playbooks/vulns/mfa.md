# Multi-Factor Authentication (MFA/2FA) — the method

> **This is a test of your ability to bypass MFA** in the challenge flow the human names — the
> chain that reaches a fully-authenticated session without the second factor. Model what the
> password step establishes, what the challenge step is supposed to add, and **what the session
> step assumes has already happened** — then find where the second factor can be skipped or its
> verdict flipped. Flow skipping, response tampering, backup/OTP flaws and remember-device are the
> seams. Test your own account. Work it with `playbooks/vulns/_master-vuln-hunting.md`.

---

## 1. Model the flow before you touch anything

**SOURCE** — what you can influence between password-accept and session-issue: the interim token,
the OTP field, the verify response the client reads, the "trust this device" cookie, the backup
code.

**FEED** — the MFA-challenge step itself: `/2fa/verify`, `/mfa/challenge`, TOTP/SMS/email-OTP
endpoints, push-approval, WebAuthn, plus the **backup-code** and **remember-this-device** paths —
and any parallel endpoint (API, mobile, legacy) that never challenges at all.

**SINK** — session issuance. Is MFA enforced server-side on the final session, or assumed? After
the password step, **what token/state exists, and what is it authorized to do *before* MFA
completes?**

**CONTEXT** — the discriminator is **which step establishes what, and what the next step assumes.**
The password step establishes "knows the secret". The challenge step is supposed to establish
"holds the factor". If the session step assumes the second because it saw the first, the factor is
decorative. Ask the same question of enroll/disable/recovery: do they re-verify the current factor,
or assume the session already means it?

**ROOT CAUSE** — one of: the app issues a partially-authenticated token after the password step and
then trusts the client to enforce MFA · a parallel endpoint never challenges · the verify endpoint
returns `{success:false}` and the client gates on it (or the status code / redirect is the only
gate) · the OTP is short with no attempt throttle, not bound to the session/user, or reusable ·
backup codes are sequential/low-entropy or don't invalidate on use · the remember-device cookie is
forgeable, guessable, or not bound to the user, so its presence alone skips MFA for anyone ·
enrolling a new factor or disabling MFA happens without re-challenge · the reset flow
(`password-reset.md`) silently clears MFA. **That answer is your `fix_locus`** — the specific
enforcement point, so distinct bypass paths count separately.

## 2. Derive the candidates — enumerate the ways to reach a session

1. **List every path from password to session**: web, API, mobile, legacy, SSO. The one that never
   renders an OTP screen is the first candidate.
2. **List every post-MFA resource** reachable with the interim token — the flow-skip test needs a
   genuinely MFA-gated resource, so pick it deliberately.
3. **Read what the browser actually checks** after `/verify` returns — a field, a status, a
   redirect. Whatever it is, that is the response-tamper candidate.
4. **Enumerate the factor's lifecycle**: issue, verify, replay, expire, backup code, remember
   device, enroll, disable, recover. Each edge is a separate test.

## 3. Determine the context — before you try to bypass

- **Capture the interim token** and note exactly when in the flow it appears.
- **Characterise the OTP**: how generated, how long, how many attempts allowed, bound to this login
  attempt, single-use? Same questions for backup codes.
- **Inspect the remember-device cookie's structure and binding** — is it tied to user + factor?
- **Confirm the target resource really is MFA-gated by design**, or a flow-skip result means nothing.

## 4. Test → Confirm → Validate

**Accounts gate:** you need **a test account you own with MFA enabled** (`accounts.md`), and the
transferability tests need a **second** account. Without them the honest result is `coverage =
blocked (needs-account)` — not "not vulnerable".

**TEST — the cheapest reachability probes.** Complete the password step, then request a post-MFA
endpoint directly with the interim token. Intercept the verify response for *your* account and flip
the gating field/status. Replay one OTP for single-use; use a code issued for session A in session
B for binding. A *few* wrong guesses to observe throttling. Try the remember-device cookie on a
second test account to see if it is transferable. **Outcome: a hypothesis.**

**CONFIRM — the default oracle is a fully-authenticated action, not a screen.** Perform an
authenticated request that only a completed-MFA session should be allowed to make. The oracle lies
when:
- the post-password page you reached is **not behind MFA by design** — confirm the resource is
  genuinely meant to require the second factor;
- the client shows "success" after tampering but the **server session is still un-elevated** —
  prove it with an authenticated action;
- a "reusable" code is actually rejected by the server on the second try and the client merely
  cached it;
- the remember-device cookie *is* properly bound and works only for your account — that is correct
  behaviour, not a bypass.

**VALIDATE — the least that proves impact.** One bypass, one authenticated action, on your own
account; stop there. MFA bypass negates the entire second-factor control → with a valid, leaked or
phished password it is **account takeover**, and critical on admin accounts. Chains: `login.md`
enumeration/weak password + MFA bypass → ATO; a `password-reset.md` flow that clears MFA → full
bypass; remember-device forgery + `session-management.md` → persistence in the victim's account.

## 5. Safety, artifact, and PoC handoff

- **Never brute-force OTPs against real users**, and never run a full guessing loop — a few
  attempts to observe throttling is the limit.
- **Never spam SMS or push.** That is toll-fraud and MFA-fatigue against real people, not testing.
- **Never disable a real user's MFA**, and never enroll a factor on an account you don't own.
- **Store the artifact**: the request/response for the bypass *and* the authenticated action that
  proves the session is real. **No artifact → HYPOTHESIS.** Redact codes and tokens the proof
  doesn't need.
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): Burp Repeater or copy-pasteable
  `curl` showing password-step → interim token → post-MFA request. If the PoC needs response
  interception, say so explicitly and show the server-side consequence.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the
`fix_locus` from §1 — record each enforcement point separately (session issuance, verify handler,
OTP binding, device cookie, enroll/disable). Log negatives with the oracle used. **Dedup:** "no rate
limit on the OTP field" (worth it *only* if it yields practical guessing), missing MFA on a
low-value action, and "SMS as a factor is insecure" (design, not a bug) are reported to death.
Novelty is **flow-skip** with an over-privileged interim token, a **response-tamper** bypass, OTP or
backup codes **not bound** to session/user or reusable, a forgeable **remember-device** cookie, or
**enroll/disable without re-challenge**.

## 7. Worked example — the spine in one pass

*Model:* `accounts.md` has a test account with TOTP enabled. The password step returns a session
token *before* the `/mfa/challenge` step and the client then renders the OTP screen — the interim
token already exists, so the real question is what it is *authorized* to do server-side before MFA
completes. *Derive:* if MFA is enforced only by the client showing the OTP screen, a post-MFA API
called directly with the interim token will be served; pick one genuinely MFA-gated endpoint.
*Context:* capture the interim token; confirm the chosen resource is meant to be behind the second
factor. *Hypothesis:* the interim token is over-privileged, and requesting an MFA-gated resource
with it — never touching the OTP — returns real data. *Confirm:* on your own account, complete only
the password step and replay the interim token against that one endpoint; served protected content
is the flow-skip bypass, confirmed with an authenticated action rather than a UI screen. No OTP
guessing, no SMS/push spam. *PoC:* the request/response pair. *fix_locus:* server-side MFA
enforcement on final session issuance — "no rate limit on the OTP field" is the reported-to-death
case; an over-privileged interim token that makes the second factor decorative is the novelty.
