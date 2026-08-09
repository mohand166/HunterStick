# User Enumeration — the method

> *(Split from the former `login` playbook, which conflated two classes with different oracles and
> different account requirements. Its other half is `authentication-bypass.md`.)*
>
> **This is a test of your ability to find a valid-account oracle** in the flow the human names —
> any channel where the application's behaviour differs by whether an identity exists. Model which
> decision runs for real accounts and not for others, then find where "is this a real user" and "is
> this the right secret" leak apart. Reason about the *channels* a response can differ on, not about
> guessing usernames; never lock out or spray real users. Work it with
> `playbooks/vulns/_master-vuln-hunting.md`.

---

## 1. Model the flow before you touch anything

**SOURCE** — the identity you supply: a username, an email, a phone number, an account id — anywhere
the app has to decide "does this exist" before deciding anything else.

**FEED** — every flow that takes an identity, not just login: registration, password reset, magic
link, MFA challenge, invite, "resend verification", SSO account-linking, and any API or mobile
endpoint semantically equal to them. Each is separate code and may answer differently.

**SINK** — the branch that runs *only* for existing accounts. That branch is the leak: a lookup, a
password comparison, a lockout counter, a mail send, an error path.

**CONTEXT** — the discriminator is **which channel carries the difference**. "Does this user exist"
and "is this secret right" are two decisions; how they sequence decides whether you get an oracle,
and *where* it surfaces. Enumerate the channels rather than assuming it's the error message:

| channel | what to compare |
|---|---|
| body / message | wording, an error code in JSON, field-level validation text |
| status | 200 vs 401 vs 403 vs 302 |
| headers | `Set-Cookie` presence, `WWW-Authenticate`, a rate-limit header set only for real users |
| redirect | different `Location` target for existing vs not |
| timing | a password hash compared only when the user exists — bcrypt on hit, short-circuit on miss |

**ROOT CAUSE** — one of: behaviour diverges by account existence on some channel · validation that
runs only for real accounts, e.g. "account locked" shown only to existing users · the password hash
is compared only when the user exists, making real users measurably slower. **That answer is your
`fix_locus`** — name the branch, so distinct oracles on distinct flows count separately.

## 2. Derive the candidates — enumerate flows and channels, not usernames

1. **List every flow that takes an identity** (login, reset, register, invite, MFA, resend, SSO
   linking) across every path (web, JSON API, GraphQL, mobile). The oracle rarely survives where the
   crowd already looked, so the scrubbed web login is the *least* promising.
2. **Enumerate the channels a response can differ on** — message, status, timing, cookies, redirect,
   headers — and diff them field by field rather than eyeballing the page.
3. **Look for branches that only run for real accounts** — lockout messaging, "check your email"
   wording, a verification-state hint, a differently-shaped JSON error.

## 3. Determine the context — before you read anything into a difference

- **Fix ground truth on identities**: from `accounts.md`, one known-valid user and one username whose
  non-existence *you* control. Without both you have no baseline to diff.
- **Verify the negative case is real** (valid account, wrong password) so the difference you find is
  about existence and not about something else.
- **Establish the normal variance** of the channel you plan to use — especially timing — before
  treating a gap as signal.

## 4. Test → Confirm → Validate

**Accounts gate:** enumeration needs **≥2 identities** — one valid, one known-invalid. Without them
the honest result is `coverage = blocked (needs-account)` — not "not vulnerable".

**TEST — cheapest signal.** A handful of paired requests, valid-user+wrong-pass vs invalid-user,
diffed field by field across every channel in §1. A handful, not a wordlist. **Outcome: a hypothesis.**

**CONFIRM — the default oracle is a stable, reproducible, *account-dependent* difference.** For
timing, that means a *small* controlled sample (e.g. 10–20 paired requests valid vs invalid) with
clear separation — report the delta **and the variance**, not one lucky sample. The oracle lies when:
- the difference is generic (same message, differing only by incidental whitespace or latency);
- the timing delta is network jitter or one cold cache — require repeatable separation;
- the "invalid" username you chose actually exists, or your "valid" account is in an unusual state
  (locked, unverified) that is doing the differentiating instead of existence.

**VALIDATE — the least that proves impact, and be honest about how much that is.** Enumeration alone
is usually **low / informational**. Its value is as an *enabler*, so report it chained with what it
unlocks: enumeration → weak reset (`password-reset.md`) → takeover; enumeration → MFA-target
selection (`mfa.md`); enumeration → targeted phishing or credential-stuffing lists. Demonstrate the
oracle on your two known identities and stop — do **not** build a user list.

## 5. Safety, artifact, and PoC handoff

- **Never harvest.** Proving the oracle takes two identities; producing a list of real users is
  exfiltration, not evidence, and it is the fastest way to turn a low-severity finding into an
  incident.
- **Never brute-force or hammer an account to lockout.** Timing work stays a small paired sample, not
  a flood. Absence of a rate limit is a config note, not this finding.
- Use **test accounts from `accounts.md`** and usernames whose status you control — never build the
  oracle against a real person's account, and never enumerate through a flow that emails real people.
- **Store the artifact**: the paired request/response diffed field by field, with the channel that
  differs called out explicitly. **No artifact → HYPOTHESIS.**
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): Burp Repeater or copy-pasteable `curl`
  **with its control request** — the valid-user and invalid-user calls side by side.

## 6. Log it

`targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the `fix_locus` from §1 — the
entrypoint column must separate both the *flow* (login vs reset vs register) and the *path* (web vs
mobile API vs GraphQL), because each is different code with a different answer. Log negatives with
the channel and oracle used.

**Dedup:** plain username enumeration via the login error message, and user-enum via the reset form,
are reported to death and explicitly excluded by most programs — don't lead with them. Novelty is a
**timing** oracle where the message is uniform, or enumeration leaking through a non-obvious channel
(cookie, redirect target, `WWW-Authenticate`, a JSON error code) or on a flow nobody diffs — invite,
MFA challenge, SSO linking, resend-verification.

## 7. Worked example — the spine in one pass

*Model:* `endpoints.md` shows a web `/login` with a uniform "invalid credentials" message, and
`technologies.md` notes a mobile API `/api/v2/auth/token` that predates it — two feeds into the same
lookup. *Derive:* the web message was clearly scrubbed, so enumeration there is a dup; the
discriminating question is whether the two paths diverge on a known-good vs known-bad username.
*Context:* `accounts.md` gives one valid user and one username known to be unregistered.
*Hypothesis:* `/api/v2/auth/token` returns a distinct error/status for existing vs non-existing users
(e.g. `USER_NOT_FOUND` vs `BAD_PASSWORD`). *Confirm:* ~4 paired requests to the API, diffing status,
JSON error code and `Set-Cookie` field by field; a stable account-dependent divergence is the oracle.
No wordlist, no lockout attempts, no list built. *PoC:* the request/response pair. *fix_locus:* the
error branch in `/api/v2/auth/token` — the crowd fuzzed web `/login`; the oracle lives on the older
mobile path that skips the WAF. *Report it chained* with the reset flow it makes exploitable.
