# Business-Logic Abuse — the method

> *(Merged: this file replaces the former `workflow-abuse` and `state-machine-abuse` playbooks.
> Multi-step flows and object lifecycles are the same question asked at different granularity.)*
>
> **This is a test of your ability to find a broken business rule** in the flow, object or
> entitlement the human names. Name the rule the application intends to hold, find **where that
> rule actually lives**, then find the path that reaches the effect without passing through it. The
> bug is rarely a bad check — it is a check that lives in the wrong place, runs only for the wrong
> shape of input, or is trusted by someone who shouldn't be trusting it. Work this with
> `playbooks/vulns/_master-vuln-hunting.md`.

**Read this file every time.** Technique catalogues live in **`ref/workflow-abuse.md`** — open a
section only when its trigger fires:

| you observe | open `ref/workflow-abuse.md` § |
|---|---|
| The client seems to decide what you're allowed to do | **B1** response-side gating |
| A multi-step flow, or an object with a lifecycle | **B2** sequence, state, and who may drive it |
| A guard exists and looks correct | **B3** making the guard decline to run |
| Money, seats, quotas, coupons, thresholds, counters | **B4** numeric & aggregation invariants |
| A pending window, a reservation, a two-phase commit | **B5** reservation & double-spend |
| Something was revoked, deleted, cancelled or expired | **B6** teardown, decay & partial failure |
| A third party or downstream system consumes this state | **B7** trust boundaries between systems |
| Rate limits, CAPTCHAs, one-time tokens | **B8** anti-automation as a business rule |
| Writing it up, or judging whether it's real | **B9** impact, feasibility & non-findings |

---

## 1. Name the rule before you touch anything

**THE RULE** — state it in the application's own terms: *"a coupon applies once per account"*, *"only
the owner may approve"*, *"a trial converts to paid before access"*, *"three retailers on the free
plan"*, *"the account holder is emailed when their password changes"*. If you cannot state the rule
in one sentence, you are not ready to test it. The app usually tells you the rule itself — in UI
copy, a disabled control's tooltip, a settings screen, or the program's own policy page.

**WHERE THE RULE LIVES** — this is the whole class. Candidates:
- **In the client**, reading a value the server returned (**B1**) — the family that produced the
  corpus's highest-severity outcomes, and the one a request-only methodology cannot see.
- **On one path but not its sibling** — a different verb on the same URL, another entrypoint to the
  same object, REST vs GraphQL, bulk vs single, a legacy or convention-named route.
- **Inside a conditional the attacker controls, or behind an early `return`** (**B3**).
- **Bound to one input shape** — one parser, one encoding, one content-type, one field being present.
- **At write time, cached, and never re-derived at read time** (**B6**).
- **In the UI form only** — a number spinner standing in for a server-side constraint (**B4**).
- **In a second system that trusts an incomplete projection of this one** (**B7**).

**WHO MAY DRIVE IT** — separate *"is this transition legal?"* from *"who is allowed to make it?"*
In this corpus, **missing authorization on a perfectly legal transition paid out more often than an
illegal transition did**. Ask both, and ask the second first.

**WHAT CONSUMES IT** — who else reads this state, through what projection, and do they re-verify?
A price in a redirect to a payment processor; a balance a downstream system audits with one command;
a cached entitlement; a queued job that assumes the authorization it was scheduled with.

**ROOT CAUSE** — one of: never enforced server-side · enforced on one path only · the guard's own
precondition can be made false · the check ran for the canonical input shape only · authorization
derived once and cached · the endpoint performing the effect re-derives nothing · the counter is
keyed to something you control · nothing is reserved during a pending window · a second system
trusts an unsigned value. **That answer is your `fix_locus`.**

## 2. Derive candidates — enumerate doors, not steps

1. **List every endpoint that can reach the effect, and diff their guards.** This beats "which step
   can I skip". Include **verbs the UI never uses** — if a resource can be created and deleted, try
   `PUT`/`PATCH`. Include GraphQL vs REST, bulk vs single, mobile vs web, and convention-named
   siblings (`/edit`, `/admin`, `/preview`).
2. **Read the client bundle for what it knows but never sends** — field names in handler arguments,
   entitlement booleans, feature flags, restricted enum values. A disabled control's tooltip often
   names the exact value to send.
3. **Read the app's own statements of rules** — plan limits, settings thresholds, policy pages, help
   text. Each is a rule you can go and test.
4. **For a multi-step flow, walk it once legitimately and capture the trace** — you cannot abuse an
   order you haven't observed. But treat the trace as a *map of doors*, not as the thing to replay:
   the legitimate client never sends the interesting values.
5. **For an object with a lifecycle**, enumerate its statuses and the legal edges — then for each
   transition ask *who may drive it*, *is it idempotent*, and *what else does it write* (**B2**).

## 3. Establish the oracle *before* you test

**The response is not the proof, and for this class it is often actively misleading.** A price echoed
in a redirect is a hypothesis. A UI that unlocks after you edit a response proves only that you
fooled your own browser. Decide up front what durable effect you will observe:

- **A fresh, un-intercepted session** — log out, log back in, and see whether the change persisted.
- **The merchant/owner side** — the order record, the account page, the admin view.
- **A second identity** — did the victim's object actually change?
- **A side effect that had to happen** — an email, a notification, a counter, a ledger entry.
- **The absence of a side effect that should have happened** — no notification on a credential change.

## 4. Test → Confirm → Validate

**TEST — probe both directions.** *Request-side:* change the value, **remove a required field**, add
a field the UI hardcodes, flip the verb, skip or reorder a step, replay a completion token, send a
fractional, negative or absurd number. ***Response-side:* intercept what the server sends back and
flip the smallest decision field in it.** A request-only methodology is blind to a whole family of
bugs — the family that produced the corpus's account takeovers. **Outcome: a hypothesis.**

**CONFIRM — did the rule actually break?**
1. Observe the durable effect through the oracle from §3, in a clean session.
2. **Separate the two token properties.** "Single-use" and "bound to the right subject" fail
   independently — a token can be correctly one-time and still be accepted for someone else's
   object. Test them as two experiments, or you will pass one and report neither.
3. **Run it more than once.** Some findings need the action repeated, a privilege granted *then*
   revoked, a second walk of the flow, or a later session — the effect may arrive asynchronously or
   only on the next invocation.
4. **Check what else it touched.** The effect may land on a *linked* object rather than the one you
   acted on.

**VALIDATE — the smallest demonstration that proves the rule broke**, on your own objects, stopping
before any real-world settlement (§5). State plainly what you did not test: several strong corpus
reports were filed with the limitation declared up front, and were accepted.

## 5. Safety — this class touches money, inventory and third parties

**Read this before testing anything transactional.** The corpus normalises behaviour we will not
copy: a reporter took a production host down for over an hour, then re-triggered it the same evening,
and used the outage duration as the impact statement; others moved real funds on live exchanges,
claimed a real third-party merchant's listing, issued themselves a real certificate from a live
program, poisoned a shared cache affecting other tenants, ran Intruder with IP-rotation until "lots
of" password-reset emails went out, and incurred a real card charge. **Do not imitate any of that.**

- **Stop before settlement.** Prove price and quantity manipulation on a quote, a preview, or an
  unsubmitted cart. Do not capture payment, drive a real merchant's fulfilment, or move real funds.
- **Never degrade availability** to demonstrate a logic flaw — no quiesce, drain, flood or
  exhaustion. If your impact statement is an outage, you have gone too far.
- **Never send bulk mail or push work into a human review queue.** One corpus reporter proved a
  CAPTCHA bypass by hand and explicitly refused to run Intruder because it would flood a moderation
  dashboard — copy that.
- **Use your own objects and accounts.** Don't claim, delete or mutate a real third party's records
  to make a point.
- **One controlled attempt per hypothesis**, then stop and reason.
- **Store the artifact**: the legitimate trace, the abused trace, and the *oracle* evidence from a
  clean session. **No artifact → HYPOTHESIS.**
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`) — Burp Repeater or a copy-pasteable
  `curl`, plus the durable-effect evidence. If the PoC requires response interception, say so
  explicitly and show the server-side consequence.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the
`fix_locus` from §1 — name the *rule* and *where it should have lived*, not just the endpoint. Log
negatives with the oracle you used. Before writing up, apply the feasibility gate in **B9**: a state
that is technically reachable but costs years or thousands of dollars to reach is not a finding.
