# Host Header Attacks — the method

> **This is a test of your ability to find Host header attacks** in the flow the human names — the
> chain that reaches reset-link poisoning and account takeover. Model the request to where the app
> builds an absolute URL from the **client-supplied Host / forwarding header**, work out which
> header it trusts as "this site's domain" and where that value lands (email link, redirect, cache
> key), then find where that trust breaks. The value is knowing *which* header the app trusts —
> not spraying `Host:` values everywhere. Thin class file; work it with
> `playbooks/vulns/_master-vuln-hunting.md`.

## 1. Model the flow before you touch anything

**SOURCE** — the header family the client controls: `Host`, `X-Forwarded-Host`,
`X-Forwarded-Server`, `X-Host`, `X-Forwarded-For`, `X-Original-URL`, `Forwarded`.

**FEED** — the proxy chain. Reverse proxies / load balancers / CDNs in front (signals in
`technologies.md`) add and rewrite forwarding headers; the app may over-trust what arrives. A
load balancer often rewrites `Host` while passing `X-Forwarded-*` through untouched — so *which
header survives to the app* is a separate question from which one you sent.

**SINK** — where the value lands:
- **Highest value:** absolute URLs built from the Host header — password-reset and
  email-verification links, invitation links, OAuth redirect construction, webhook callbacks. A
  poisoned link means the token goes to the attacker's domain.
- Cache keys (unkeyed Host variants → `cache-poisoning.md`), virtual-host routing, server-side
  redirects, SSRF via routing (`X-Forwarded-Host` reaching an internal proxy), and reflected Host in
  the response body or headers.

**CONTEXT — which header the app trusts, and whether the landing is in-band or blind.** That pair
decides the whole test:

| landing | how you observe it |
|---|---|
| response body / `Location` / `<base href>` | in-band — read the response |
| an email link (reset, verification, invite) | blind — out-of-band, read the received mail |
| a cache key | shared state — see `cache-poisoning.md` |
| routing to an internal service | out-of-band — a single callout to your listener |

Is there allow-listing / canonicalization, or is any Host accepted? Does an override header win
over the real `Host`?

**ROOT CAUSE** — the specific link-builder or routing rule that derives "this site's domain" from a
client-controlled header instead of configuration. **That is your `fix_locus`**, so distinct sinks
count separately.

## 2. Derive the candidates — reason about who builds absolute URLs

1. **Enumerate the flows that must emit an absolute URL**: password reset, email verification,
   invitations, OAuth redirect construction, webhook callbacks. Those are where the header becomes
   a security decision, not decoration.
2. **Then the reflective sinks**: server-side redirects, a `<base href>`, Host echoed in a body or
   header, and anything cache-keyed.
3. **Read the tech signals** — frameworks that read `Host` to build `base_url`, and every proxy/CDN
   layer in front, because each one is a chance for a different header to win.
4. Test the `Host` header and the `X-Forwarded-*` family **separately**; they are different
   candidates with different answers.

## 3. Determine the context — before you poison anything

- Establish which header the app actually trusts, one header at a time, holding the rest constant.
- Establish where the value lands, and therefore what your observation channel must be (§1 table) —
  decide this before sending, exactly as with any blind class.
- Establish whether the edge rewrites or validates the header before the app sees it; if it does,
  your injected value never reaches the sink.

## 4. Test → Confirm → Validate

**TEST — does an attacker-supplied value reach the app at all?** Send the request with a benign
attacker-controlled domain (a listener you own) in one target header. **Outcome: a hypothesis.**

**CONFIRM — did the poisoned value reach the security-relevant sink?** The default oracle depends on
the landing you identified in §1:

- **Reflected** in body / `Location` / `<base>` → read it directly from the response.
- **Blind (reset link)** → trigger the flow **for your own test account only**, then read the
  received link and confirm its host is your domain. That received link *is* the oracle.
- **Routing/SSRF** → a single OOB callout to your listener.

Where that oracle inverts or lies:
- The app reflects your Host but the link/token is still bound to the *real* domain server-side →
  cosmetic, not exploitable. Verify the token actually lands on your host.
- A load balancer rewrites/validates Host before the app sees it → your injected value never
  reached the sink. Confirm the *app*, not just the edge, honored it.
- Reflected Host with no security-relevant sink (echoed in an error page, no script/link context) →
  low or no impact; don't overstate.
- A cache "HIT" that's really just a normal cached response unrelated to your header.

**VALIDATE — the least that proves impact.** One benign, self-scoped observation is the finding.
Escalate only the minimum needed to demonstrate the takeover or SSRF reachability; don't pivot
deeper than that, and say what you did not do.

**Impact & chaining.** Password-reset poisoning → account takeover (chain with
`password-reset.md`). Routing / `X-Forwarded-Host` → SSRF to internal services (`ssrf.md`) or web
cache poisoning (`cache-poisoning.md`). Reflected Host in a script or link context → XSS or
open-redirect chains.

## 5. Safety, artifact, and PoC handoff

- **Never poison a real user's reset**, never trigger the flow against a victim's account, never
  mass-send emails or flood the mail system, and **never evict or pollute shared cache entries for
  real traffic**. Self-scoped, one observation.
- **Store the artifact**: the request with the injected header plus the observed landing — the
  response, or the received link, or the listener log. **No artifact → HYPOTHESIS, not FACT.**
  Redact what the proof doesn't need (the token itself rarely needs to appear in full).
- **Ship a runnable PoC, never prose** (`playbooks/system/mcp-tooling.md`): the request to Burp
  Repeater or a copy-pasteable `curl` **with its control request** (the same request with the honest
  header) so the difference is visible in one glance. Respect the program's rate limit.

## 6. Log it

`targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the `fix_locus` from §1 — the
specific link-builder or routing rule that trusts the header. Log negatives *with the oracle used*,
and record **which header** you tested: `Host` and `X-Forwarded-Host` on the same flow are different
cells. **Novelty:** "Host header is reflected" with no exploitable sink is reported to death and
usually triaged informational — skip it. Novelty lives in a **working reset/verification-link
poisoning to real ATO**, an **`X-Forwarded-Host` that survives the proxy to reach an internal sink**,
or a Host-keyed cache poisoning on a newly-discovered / acquisition host.

## 7. Worked example

*Model:* the app sits behind a CDN (`technologies.md`) and has a password-reset flow; `accounts.md`
gives me two test accounts. Reset emails contain an absolute link, so the `base_url` is built from a
client-controlled header — SINK = the reset link-builder, and that is the `fix_locus`.
*Derive:* the reset flow is the candidate because it *must* emit an absolute URL carrying a token.
*Context probe:* the link is blind (it arrives by email, not in the HTTP response), so the
discriminator is *the host in the received link*. I test `Host` and `X-Forwarded-Host` separately,
because the CDN usually rewrites `Host` but forwards `X-Forwarded-*` untouched.
*Hypothesis:* `X-Forwarded-Host` wins over the real `Host` when building the reset link, so the
token lands on my domain.
*Test → confirm:* trigger the reset **for my own account only**, adding
`X-Forwarded-Host: <listener-I-own>`, then read the email I receive and check the link's host.
Never fire the flow at another user's address; never mass-send. If my token lands on my host,
that's ATO-grade proof, self-scoped.
*Artifact:* the request + the received link.
*Dedup:* "Host is reflected in an error page" is triaged-to-death; a working `X-Forwarded-Host`
reset poisoning to real ATO is not — `fix_locus = reset link-builder`.
