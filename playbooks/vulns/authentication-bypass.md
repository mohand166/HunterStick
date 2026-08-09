# Authentication Bypass — the method

> *(Split from the former `login` playbook, which conflated two classes with different oracles and
> different account requirements. Its other half is `user-enumeration.md`.)*
>
> **This is a test of your ability to reach an authenticated session without the right secret** on
> the login flow the human names. Model what each step establishes and what the next step assumes,
> find where the **credential check** actually lives, and find the path that reaches session
> issuance without passing through it. Reason about the *logic* — a trusted client field, a param
> that flips the decision, an alternate path that skips a check, a default credential — **not**
> brute-forcing passwords; never lock out or spray real users. Work it with
> `playbooks/vulns/_master-vuln-hunting.md`.

---

## 1. Model the flow before you touch anything

**SOURCE** — the credentials, and everything else the client sends beside them: a `step`, `role`,
`verified` or `admin` field, an object the server returned and the client posts back, a remember-me
cookie, an API key.

**FEED** — which path carries them. The login endpoint and everything semantically equal to it: API
`/login`, `/token`, `/session`, a GraphQL `login` mutation, SSO/legacy `/signin`, mobile-app auth
endpoints that skip the web WAF. Where there are several ways to authenticate (SSO + local + API +
mobile), **the weakest path defines the security** — ask which one skips MFA, lockout, or a
verification step.

**SINK** — the credential check and the session issuance behind it. What exactly proves identity
here, and *where* is that decision made — server or client? What does the server return, and does the
client trust a field it shouldn't?

**CONTEXT** — the discriminator is **which step establishes what, and what the next step assumes.**
"Password accepted" and "session issued" are two decisions; how much the second assumes from the
first decides whether you get a bypass. Ask it per path, because each auth path answers differently.

**ROOT CAUSE** — one of: a parameter changes the auth decision (`admin=true`, `role`, `step`,
`verified`) · array/type juggling (`password[]=`) · the client trusts a returned `success:true` · an
alternate auth path skips a check (impersonation / "login as", magic-link, remember-me cookie,
API-key login) · the host still ships default or seeded creds. **That answer is your `fix_locus`** —
name the decision point, so distinct bypasses count separately.

## 2. Derive the candidates — enumerate auth paths, not passwords

1. **List every way to become authenticated and diff them**: web form, JSON API, GraphQL mutation,
   mobile endpoint, legacy `/signin`, SSO. A path that predates the current hardening is the
   highest-yield candidate.
2. **Find the parameters that could change the auth decision, and the fields the client trusts**,
   from the JS bundle and the API's own responses rather than by guessing names.
3. **For default / seeded creds**: admin panels, appliances, newly-discovered or acquired hosts,
   test/staging left public. Take the stack from `technologies.md` + recon and ask what ships by
   default for it, and whether this host is clearly not hardened.

## 3. Determine the context — before you send credentials

- **Which decision is server-side?** Walk one legitimate login end to end and note exactly what the
  browser checks before it treats you as logged in — that gap is where a client-trusted field lives.
- **Verify the negative case is real** (valid account, wrong password) so you know what rejection
  looks like before you try to defeat it.
- **Map which paths enforce which controls** — MFA, lockout, verification — one legitimate attempt
  each, so you know which path is weakest before you push on it.

## 4. Test → Confirm → Validate

**Accounts gate:** a bypass needs **an account you own to land in**. Without one the honest result is
`coverage = blocked (needs-account)` — not "not vulnerable".

**TEST — cheapest signal.** Flip the param, send the array, replay the trusted field, try the
alternate path. A handful of requests, not a wordlist. **Outcome: a hypothesis.**

**CONFIRM — the default oracle is an authenticated action you could not perform before, made
*after* the bypass.** A happy screen is not the oracle. The oracle lies when:
- a "bypass" fools only the client UI while the server still rejects the session — **prove you can
  make an authenticated request afterward**, not just that you saw a logged-in-looking page;
- a default cred works on a decommissioned/honeypot host or a deliberately public demo account —
  check scope, and whether it grants anything real;
- the session you obtain is anonymous/guest-scoped and simply *renders* as logged in.

**VALIDATE — the least that proves impact.** Land authenticated **as yourself** and perform one
authenticated action, then stop. For default creds, try the **documented default once**, only on a
host plainly in scope and non-production-critical, and **stop on success — do not pivot deeper.**
Auth bypass and default admin creds are the high-severity outcomes: account or full-admin takeover.
Chains: bypass → `session-management.md` for persistence; a bypass enabled by an enumeration oracle →
cite `user-enumeration.md` as the enabler.

## 5. Safety, artifact, and PoC handoff

- **Never brute-force, credential-stuff, or hammer a real user's account to lockout.** Absence of a
  rate limit is a config note, not the finding here.
- Use **test accounts from `accounts.md`** — never land in a real person's account, and never use a
  default credential to reach live customer data.
- **Store the artifact**: the bypass request/response **plus the authenticated action that proves the
  session is real**. **No artifact → HYPOTHESIS.** Redact credential values the proof doesn't need.
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): Burp Repeater or copy-pasteable `curl`
  **with its control request** — the rejected attempt and the accepted one side by side.

## 6. Log it

`targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the `fix_locus` from §1 — and the
entrypoint column must separate the auth *paths* (web form vs mobile API vs GraphQL), because they
are different code with different answers. Log negatives with the oracle used.

**Dedup:** "no rate limiting on login" and missing CAPTCHA are reported to death and explicitly
excluded by most programs — don't lead with them. Novelty is a *logic* bypass: a trusted client
field, a param that flips the auth decision, an alternate path skipping MFA or lockout, or default
creds on an acquired/forgotten host.

## 7. Worked example — the spine in one pass

*Model:* `endpoints.md` shows a web `/login` behind the WAF, and `technologies.md` notes a mobile API
`/api/v2/auth/token` that predates it — two feeds into the same credential check, the older one
possibly missing the hardening. *Derive:* list both paths and ask which controls each enforces.
*Context:* one legitimate login on each path, noting what the client checks before it treats me as
logged in. *Hypothesis:* the mobile path returns a `success` field the client trusts, or accepts a
`role` the web form never sends. *Confirm:* flip it on my own account, then — the actual oracle —
call an authenticated endpoint with the resulting session and see whether the **server** honours it.
*PoC:* the rejected and accepted requests plus the authenticated action. *fix_locus:* the session-issuance
branch in `/api/v2/auth/token` — the crowd fuzzed web `/login`; the weaker path is the older mobile one.
