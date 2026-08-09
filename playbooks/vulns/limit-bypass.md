# Limit / Quota Bypass — the method

> **This is a test of your ability to bypass a quota/rate/usage cap** on the metered action the
> human names — the request that does the same work but dodges the limit. Model the flow to the
> **counter/check**, work out what *dimension* the limiter keys on and how it derives that key from
> your request, then find where its assumption breaks. The bug is the identity the counter trusts —
> vary it, don't spray traffic. Thin class file; work it with
> `playbooks/vulns/_master-vuln-hunting.md`.

## 1. Model the counter before you touch anything

**ACTION** — the metered thing itself: rate limits (login/OTP/SMS/email sends), usage quotas (API
calls, free-tier actions, exports, invites, uploads), per-account caps ("3 per day"), abuse
throttles, trial limits, free-trial-per-user, spending/withdrawal caps.

**THE CHECK** — where does the limit live: at the edge (WAF/CDN/gateway) or in app code? Edge limits
often key on a normalized path or IP that an app-level equivalent endpoint sidesteps.

**CONTEXT — what the counter is keyed on.** This is the whole class; if it keys on something you
control or can vary, the cap leaks:

| dimension | the key | how it varies |
|---|---|---|
| **identity** | user id, IP, API key, device id, session | new account, `X-Forwarded-For`, rotate key → fresh quota |
| **request shape** | the exact path/method/param string | casing (`/API/Send` vs `/api/send`), trailing slash, path params, `?v=1`, HTTP vs HTTPS, HTTP/2 vs /1.1, extra query keys — if the limiter matches a differently-normalized string |
| **header** | `X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP`, `True-Client-IP`, `Client-IP` | trusted for the rate key, or for geo/quota |
| **endpoint** | which route the counter is attached to | a second route to the same action (GraphQL vs REST, v1 vs v2, mobile vs web API, bulk vs single) where only one is throttled |

**ROOT CAUSE** — the keying or normalization mismatch: the limiter and the router disagree about
what the request *is*, the limiter trusts a client-supplied identity, or one of several entry points
to the same action isn't attached to the counter. **That is your `fix_locus`** — each keying flaw is
a separate fix.

## 2. Derive the candidates — reason about entry points, not payloads

1. **List the metered actions** and, for each, ask **what does one unit past the cap actually
   cost or enable?** That decides whether it's worth a report before you spend a request.
2. **Does the same business action have more than one entry point, and are all of them throttled?**
   Enumerate them from JS, the mobile API, and the schema — this is where the counter is usually
   unattached.
3. **Read the recon tells**: `429`/`Retry-After` on some paths but not siblings; limits enforced at
   a gateway/CDN edge (bypassable by hitting the origin, or by a different edge behaviour);
   per-endpoint configs in JS.
4. **Ask whether normalization is consistent between the limiter and the router.** A mismatch — the
   limiter sees `/api/send`, the router also serves `/api/send/`, `/API/send` — is the bug.

## 3. Determine the context — establish the limit before you dodge it

- **Determine the counter's identity axis** by varying one thing at a time and watching whether the
  counter resets: IP? user? token? path string?
- **Establish the limit itself**: send legitimate requests on a **test account** until you hit the
  cap (`429`/error) — the smallest number that trips it. **That baseline is half the proof**, and
  without it a later success proves nothing.
- Determine whether enforcement is at the edge or in app code, because that predicts which dimension
  will work.

## 4. Test → Confirm → Validate

**TEST — does one varied request get through?** Same action, **one changed dimension** (casing,
trailing slash, added header, alternate endpoint, rotated key). **Outcome: a hypothesis.**

**CONFIRM — did the counter genuinely fail to count it?** The default oracle is the **established
cap versus the varied request succeeding past it**: the request that got the `429`/cap error, then
the identical-action request with the varied dimension returning success beyond that cap. Trip the
cap once, show one bypassing request succeeds — that's it.

Where the oracle inverts or lies:
- The two endpoints/casings aren't actually the same action — one does less, so it's a different
  feature, not a bypass.
- Soft limit vs hard limit: you got a warning, not enforcement — there was no real cap to bypass.
- The cap *is* per-IP by design (documented) and you "bypassed" it by changing IP, which is expected
  and low/no impact — check whether per-account enforcement also exists.
- `X-Forwarded-For` reflected in logs but *not* trusted for the rate key — spoofing changed nothing;
  confirm the counter actually reset.
- Caching returned a cached success that never hit the metered backend.
- A distributed limiter's eventual consistency briefly allowing a couple extra — that's slop, not a
  bypass (and it overlaps `race-conditions`; classify by mechanism).

**VALIDATE — the least that proves impact.** One bypassing request past an established cap. **No
flooding** — you're proving the counter can be evaded, not stress-testing.

**Impact & chaining.** Defeats anti-abuse: brute-force / credential-stuffing (login/OTP throttle
bypass → `authn`), enumeration, spam/cost amplification (SMS/email pumping), free-tier or trial
abuse, quota-based billing evasion, scraping past intended caps. Chains: OTP/2FA rate-limit bypass →
code brute-force → account takeover; export-quota bypass → bulk data harvest; trial-per-user cap
bypass → infinite free service (feeds `coupon-and-credit-abuse` / `payment-abuse`); usage-cap bypass
under concurrency → `race-conditions`.

## 5. Safety, artifact, and PoC handoff

- **No flooding, ever.** Trip the cap with the smallest number of requests that trips it, then send
  **one** bypassing request. Resource-limit testing is exactly where this class turns destructive.
- **Use test accounts.** If the metered action has real-world cost (SMS/email to real numbers, a
  paid API), prove the *counter reset* with the cheapest possible signal and stop — never generate
  real-world spam or cost.
- **Store the artifact**: the request that got the `429`/cap error, **plus** the identical-action
  request with the varied dimension returning success past the cap. The pair is the proof. **No
  artifact → HYPOTHESIS, not FACT.**
- **Ship a runnable PoC, never prose** (`playbooks/system/mcp-tooling.md`): both requests to Burp
  Repeater or as copy-pasteable `curl`, with the request count that established the cap stated
  explicitly. Respect the program's rate limit — establishing a cap is inherently loud, so budget
  and announce it first.

## 6. Log it

`targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the `fix_locus` from §1 — the
specific limiter config or normalization gap. Record **which dimension** you varied; identity,
path-shape and header are different cells with different answers. Log negatives *with the oracle
used* (what the established cap was, and what the varied request returned). **Novelty:** the
dup-prone version is "no rate limit on endpoint X" — often known or accepted-risk. The novel version
is a *specific normalization or keying mismatch*: limiter and router disagree, or one of two entry
points to the same action is unthrottled, or a trusted header lets you reset the counter. Name the
exact dimension and the mismatch. High-value, low-dup: bypasses on **security-relevant** throttles
(OTP, login, password reset, payment) beat bypasses on cosmetic limits — the impact is what makes it
non-noise.

## 7. Worked example

*Model:* `endpoints.md` shows OTP sends throttled at `POST /api/otp/send` (returns `429` after
3/hour), and the mobile client hits `POST /api/v2/otp/send` for the same action. `technologies.md`
notes an edge gateway in front of `/api/otp/*`. CONTEXT: the limiter almost certainly keys on the
exact path string at the edge — the request-shape/endpoint dimension.
*Derive:* the v2 route is a second entry point to the same business action; if it normalizes
differently — or isn't behind the same gateway rule — the same action dodges the counter.
*Context probe:* establish the cap on `/api/otp/send` first (baseline `429` at the 4th) on a test
account/number.
*Hypothesis:* the OTP cap is per-path; hitting the v2 (or `/API/otp/send/`) entry point resets the
quota for the identical send.
*Test → confirm:* send *one* identical request via the varied dimension and check it succeeds past
the cap. Minimal count, no SMS spam — one bypassing send is the proof.
*Artifact:* the `429` + the varied success.
*Dedup:* not "no rate limit" — a specific keying/normalization mismatch on a security-relevant
throttle (feeds OTP brute-force → ATO); `fix_locus = OTP rate-key normalization across
/api/otp/send entry points`.
