# Registration / Signup Abuse — the method

> **This is a test of your ability to force an account overwrite or a pre-account-takeover** in the
> signup flow the human names — the chain that lets you collide with, or seize, an identity you don't
> own. Model the request down to the **uniqueness check**: exactly which field the app keys identity
> on, and how it *normalizes* that field before comparing versus before delivering and before logging
> in — then find where those two disagree. Duplicates, overwrite, normalization gaps and verification
> skips are the seams. The value is a named delta between two normalizations, not a pile of test
> signups. Use test identities only. Work this with `playbooks/vulns/_master-vuln-hunting.md`.

---

## 1. Model the identity before you touch anything

**SOURCE** — the identity field you supply at signup: email, username, or an external ID from an SSO
provider or an invite.

**FEED** — every path that writes into the same identity table: `/register`, `/signup`,
invite-accept, "add team member", API and GraphQL create-user mutations, SSO-first-login
provisioning. Two write paths to one table is the shape that produces this class.

**SINK** — the **uniqueness check**: the comparison deciding two signups are the "same" account, and
the record it creates or updates as a result.

**CONTEXT — which step establishes what, and what the next step assumes.** The bug is a *delta*
between the string one step handles and the string another handles:

| step | is supposed to establish | the next step assumes |
|---|---|---|
| normalize input | one canonical form of the identity | the same normalization runs on every path |
| uniqueness check | this identity is not already taken | the string compared is the string login will resolve |
| create the record | a new, distinct account | it did not silently update an existing one |
| send verification | only the real owner can complete signup | the delivery address is the same string that was compared |
| verify | the owner controls this identity | every gated action re-checks that state server-side |

The high-yield deltas: **email normalization gaps** — `user@x.com` vs `User@x.com` vs
`user+tag@x.com` vs `us.er@gmail.com` (dots) vs unicode/homoglyph vs a trailing dot or whitespace vs
`user@x.com.` — where the uniqueness check and the delivery or lookup logic disagree.

**ROOT CAUSE** — one of: the uniqueness check compares a differently-normalized string than login or
delivery resolves · signing up an existing email **silently updates** that account instead of
rejecting · a second record is created that **collides on login** · the gap between "account created"
and "email verified" leaves real capability unlocked · verification can be skipped, replayed, or is
enforced client-side only · the app lets you register or claim an email you don't own, or
pre-provisions via SSO/invite so the real owner later logs into *your* seeded state. **That answer is
your `fix_locus`** — the specific comparison or provisioning code, so distinct normalization and
overwrite bugs count separately.

## 2. Derive the candidates — enumerate the write paths into one identity

1. **List every path that can create or provision an account** (the §1 FEED set). Each has its own
   normalization, and they need not agree. **Find the true uniqueness key** — email, username, or an
   external ID — and check whether the app keys on the same one everywhere.
2. **Ask whether verification state is server-enforced on every sensitive action**, or read once.
3. **Enumerate what an unverified account can already do.** Walk the product as an unverified
   identity and list which actions unlock; that list is the impact of any verification skip.
4. **Look for the pre-ATO surface**: anywhere you can attach *your* credential, OAuth identity or
   invite to an email you don't control, such that the real owner later inherits your foothold.
   **Compare the two records' capabilities** wherever a duplicate is possible — a colliding record
   that can do nothing is not the same finding as one that can.

## 3. Determine the context — cheap probes on inboxes you own

All of these run on **your own controlled inboxes** (aliases or a catch-all from `accounts.md`):

- **Register the base address**, then register variants of the *same* address you own — `TEST`,
  `te.st`, `test+1`, a trailing dot, trailing whitespace. One signup each. Do they collide, overwrite,
  or coexist? **Note which of reject / update / duplicate** the app does on an already-registered
  identity; the three outcomes need different follow-ups.
- **Read which string the verification mail was actually delivered to**, and compare it with the
  string the app stored and the string login accepts. That triple is the whole context.
- **Attempt one gated action before verifying**, to locate where verification state is read.

## 4. Test → Confirm → Validate

**Accounts gate:** the collision and pre-ATO cases need **≥2 identities you control** (two
addresses, or two write paths onto one address). Without them the honest result is
`coverage = blocked (needs-account)`, not "not vulnerable".

**TEST — provoke the delta.** Register a variant of an address you own and see whether it collides.
Create an account and attempt a gated action **without** clicking the link, or replay the
verification token. Seed an account for an address you own via one path (local signup), then arrive
via the other (SSO). **Outcome: a hypothesis.**

**CONFIRM — the default oracle is the post-state of the records themselves: whether two signups
produced one account or two, and whether either can act on the other's state.** Not the signup
response. For verification skips the oracle is the gated action **succeeding server-side**, not the
UI letting you click it. **The oracle inverts or lies in these ways:**

- Two "accounts" that are actually one record — the app deduped correctly. Confirm they have
  independent, colliding effects, not just a cosmetic second row.
- A "verification bypass" on an action never meant to be gated — **check the intended policy** first.
- Gmail dot or plus behaviour you *assumed*: test it, don't assume the provider's quirk equals the
  app's quirk. And a duplicate the **login flow later rejects anyway** is no real dual access.

**VALIDATE — the minimum that shows the collision is real.** Both account states side by side, or the
gated action completing server-side. Stop there.

## 5. Safety — this class touches real identities and real inboxes

- **Use only your own controlled inboxes** — never a stranger's email, and never squat on or overwrite
  a real user's identity to make the point.
- **Don't mass-create accounts** — that is spam and effectively a DoS on the identity table. **Don't
  trigger floods of verification mail** to third parties; every probe here sends real mail to a real
  mailbox, so keep the count to what the proof needs.
- **Non-destructive only.** If the only way to prove an overwrite would be to overwrite someone
  else's account, stop and report the hypothesis.
- **Store the artifact**: both account states (or the single merged record), the delivered mail
  showing which address it went to, and the gated action's server-side response. **No artifact →
  HYPOTHESIS, not FACT.** Redact anything the proof doesn't need.
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): Burp Repeater or copy-pasteable `curl`
  for both signups **with the control**, plus how to observe the collision.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the
`fix_locus` from §1 — the *comparison or provisioning site* and which pair of paths disagreed, not
just the endpoint. Log negatives with the oracle used and the exact variants tested.

**Novelty.** Reported to death, and often dup or out-of-scope: "no rate limit on signup", generic
email-verification-not-required for trivial actions, self-XSS in a profile field at registration,
no-CAPTCHA account spam. Novel: a concrete **normalization mismatch** between the uniqueness check
and login or delivery, a silent **overwrite** of an existing account, **pre-account-takeover** via
SSO or invite pre-provisioning, or a verification skip that unlocks a genuinely gated capability.
Impact: an email-normalization collision reaches account takeover or auth confusion (logging in as
or over another user); pre-ATO reaches full takeover once the victim joins; a verification bypass
reaches spoofed-identity actions, spam or abuse under a trusted domain, and bypasses of "verified
email" gates on other features. Chains: a normalization gap plus `password-reset.md` (the reset
lands on the wrong normalized record) → takeover; an unverified-action flaw plus `oauth-oidc.md`
account-linking → pre-ATO.

**Worked example.** The app keys accounts on email and `accounts.md` gives you a Gmail catch-all you
own; `endpoints.md` shows signup and a separate SSO "Sign in with Google" that provisions on first
login — **two write paths to the same identity table**. *Model:* the bug is a delta between the
string the uniqueness check compares and the string login/SSO resolves to. Gmail treats `us.er@` and
`user@` as one mailbox; if signup stores the dotted form verbatim but SSO normalizes dots away, the
two paths can key to different-then-colliding records, and the discriminator is whether both
variants coexist. *Hypothesis:* registering `us.er@gmail.com` locally and later arriving via SSO as
`user@gmail.com` resolves to the same account, so my pre-seeded local state (or the SSO identity)
attaches to a record I didn't intend — a pre-ATO/overwrite primitive. *Test/confirm:* using only your
own catch-all, register the dotted variant, then log in via SSO with the undotted variant, and
observe whether state carries over or a second record forms. Non-destructive, no third-party email
touched; save both account states. *Novelty:* the crowd reports "Gmail dots" as self-contained
enumeration trivia; the finding is the check-vs-SSO-resolver mismatch causing a cross-path collision
— `fix_locus = email normalization in the uniqueness check
vs the SSO provisioner`.
