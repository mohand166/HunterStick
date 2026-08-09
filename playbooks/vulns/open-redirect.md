# Open Redirect — the method

> **This is a test of your ability to find an open redirect** in the destination param the human
> names — the chain that reaches token theft or a credible phishing pivot. Model **which part of
> the destination you control** — scheme, host, path, or the whole URL — trace it to the redirect
> sink, and find where the validation breaks. On its own an open redirect is often low-value or a
> dup; the reason to hunt it is as a **chain link**, so reason about what it unlocks. Work it with
> `playbooks/vulns/_master-vuln-hunting.md`.

---

## 1. Model the redirect before you touch anything

**SOURCE** — the param that carries a destination: `redirect`, `return`, `returnTo`, `next`, `url`,
`dest`, `destination`, `continue`, `redirect_uri`, `callback`, `RelayState`, `image`, `u`.

**FEED** — the validator between the param and the navigation: an allowlist, a same-origin check, a
relative-only rule, a scheme filter. Identify exactly what is enforced so you can reason about a
bypass rather than guess.

**SINK** — where the destination lands: the HTTP `Location` header (server-side), a JS navigation
sink (`location = param`, a DOM sink), or a meta-refresh. That choice decides the test.

**CONTEXT** — the discriminator is **which part of the destination you control**. Control of the
path only is not a redirect; control of the host, or of enough of the prefix to escape the path
check (`//evil.com`, `https:evil.com`, `/\evil.com`, `@`-tricks, the allowed domain used as a
subdomain, a whitelisted host that itself redirects onward), is. And crucially: **what does a
redirect *here* enable?** Auth-flow token theft? SSRF? A more convincing phish? A no-impact redirect
on a marketing page is usually not worth reporting.

**ROOT CAUSE** — one of: no validation at all · a prefix/substring check that a scheme-relative or
backslash form escapes · a host allowlist that matches a substring or accepts the allowed domain as
a subdomain · a client-side sink that never validates · one shared validator reused by a
security-critical caller such as OAuth `redirect_uri`. **That answer is your `fix_locus`** — the
specific redirect builder or validator.

## 2. Derive the candidates — reason about who needs a destination

1. **Take the parameter names from the app's own artifacts** — `js-findings.md`, `parameters.txt`,
   the HTML, the JS bundle — rather than from a fixed list.
2. **Enumerate the flows that must carry a return destination**: login/logout, SSO, post-action
   redirects, email link trackers, language/region switchers.
3. **Include the non-obvious sinks**: redirects built in JavaScript (`location = param`), a
   `Location` header set from user input, meta-refresh, and `redirect_uri` in OAuth (see
   `oauth-oidc.md`).
4. **Ask which caller reuses the same validator.** A weak check shared with an auth flow is the
   finding; the bare hop usually isn't.

## 3. Determine the context — before you send a payload

- **Check `scope.md` first.** Many programs explicitly mark open redirect out-of-scope or N/A —
  find that out before spending time.
- **Locate the sink**: does the response carry a `Location`, or does a JS navigation fire? One
  legitimate request answers it.
- **Characterise the filter** with one benign value: is a relative path accepted, an absolute URL
  rejected, a scheme stripped? Pick the bypass from what is actually filtered, not from a wordlist
  (see `adaptive-tooling.md`).

## 4. Test → Confirm → Validate

**TEST — point the destination at a benign domain you control** and see what the validator does.
**Outcome: a hypothesis.**

**CONFIRM — the default oracle is an actual navigation off-origin**: a `302` with `Location:
https://yourdomain`, or the JS sink firing and the browser landing there. The oracle lies when:
- the redirect only reaches same-origin or relative paths — then it is not open;
- your value is reflected in the body but never navigated (no `Location`, no JS sink executes) —
  that is not a redirect;
- the hop works but carries nothing of value — see below.

**VALIDATE — prove the hop to your own domain, then frame the impact through the chain.** The value
is the chain: **OAuth/OIDC `redirect_uri` → auth code/token theft** (`oauth-oidc.md`), **SSRF** when
the redirect is followed server-side (`ssrf.md`), redirect-based **WAF/filter bypass**, credential
phishing off a trusted domain, and bypassing anti-CSRF/`state` flows. Frame impact through the
chain, not the bare hop — and where the chain is the point, show that the credential actually rides
the redirect.

## 5. Safety, artifact, and PoC handoff

- Non-destructive by nature — but **never actually harvest a victim token**. Demonstrate the hop to
  your own domain, with no real user involved.
- Use a **benign domain you control** as the destination; don't point a live auth flow at anything
  else.
- **Store the artifact**: the request and the response showing the `Location` (or the JS navigation
  evidence). **No artifact → HYPOTHESIS.**
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): a copy-pasteable `curl` or Burp
  Repeater request showing the redirect, **with the control** — the same param with a legitimate
  value — so the validator's behaviour is visible in one action.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the
`fix_locus` from §1 recorded as the specific redirect builder/validator — and note where else that
validator is reused, since that is where the severity lives. Log negatives with the oracle used
(reflected-but-not-navigated is a distinct negative from same-origin-only). **Dedup:** standalone
`?next=//evil.com` on a big program is a classic dup, or out of scope. Novelty is the redirect that
**breaks an OAuth flow to steal a code/token**, one reached by a **filter bypass** others missed, a
**DOM-based** one in JS, or one on an acquisition host.

## 7. Worked example — the spine in one pass

*Model:* the SSO login is `/login?returnTo=/dashboard` — a server-side `Location` redirect with what
looks like a path-only check, so the part of the destination I control is the path unless I can
escape it. `oauth-oidc.md` context shows the app also uses `redirect_uri` on an OAuth hop. *Derive:*
the real prize isn't this redirect but whether the same weak validation is reused on `redirect_uri`.
*Context:* confirm the sink is a `Location` header and that a relative path is what the filter
expects. *Hypothesis:* `returnTo=/\evil.com` or `returnTo=//evil.com` escapes the path check and
navigates cross-origin; if the OAuth `redirect_uri` shares that validator, the auth code leaks to my
domain. *Confirm:* set `returnTo=//<mydomain>/x` and confirm a `302 Location: //<mydomain>` — my own
domain, no victim involved. *PoC:* that request/response. Then reason about whether `redirect_uri`
reuses the check before escalating. *fix_locus:* the shared redirect validator — the bare redirect
may be a dup or out of scope, but `redirect_uri` token theft via the same flaw is a distinct,
high-value finding.
