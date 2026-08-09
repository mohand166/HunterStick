# Race Conditions (TOCTOU / limit-overrun) — the method

> **This is a test of your ability to find a race condition** in the limit or check-then-act the
> human names — the chain that reaches a limit overrun or a double-spend. Model the request down to
> the **check-then-act gap**: where the limit is validated, where it is applied, whether anything is
> reserved in between, and how the app reads-modifies-writes the counter or quota — then find where
> two operations interleave. You are proving that a limit meant to hold once holds zero times. The
> value is a named non-atomic pair, not "I sent 100 requests". Validate with **one controlled
> concurrent burst**, never a flood. Work this with `playbooks/vulns/_master-vuln-hunting.md`.

---

## 1. Model the window before you touch anything

**SOURCE** — the request that consumes a limited thing: a redemption, a withdrawal, a claim, a vote,
an accept, an increment.

**FEED** — the path from that request to the mutation: the guard (`if balance >= amount`,
`if not coupon.used`), any service hop between check and act, and the store that persists the change.

**SINK** — the mutation itself (`balance -=`, `coupon.used = true`, the seat allocated, the counter
incremented) and *what enforces uniqueness at that point*: a database constraint,
`SELECT ... FOR UPDATE`, an atomic decrement — or nothing but the code you already passed.

**CONTEXT — the window between check and use, and what is (not) reserved in it.** Answer these four
before sending anything; they decide whether a window even exists:

1. **Where exactly is the check, and where is the act?** If another request can slip between them,
   the window exists. Name both halves.
2. **What, if anything, is reserved during the window?** A row lock, a pending-state flag, a
   decrement-first pattern. If nothing is reserved, two requests that both pass the check both act.
3. **Who enforces uniqueness — the database or the application?** A unique constraint,
   `SELECT ... FOR UPDATE` or an atomic decrement does not race. Read-then-write in application
   logic does. **Only the latter is a candidate.**
4. **Is the operation idempotent by key?** A properly enforced idempotency key kills the race; an
   advisory one doesn't.

Then name **the single unit of over-grant**: one extra redemption, one seat, one cent over. That is
all you ever need to prove, and knowing it in advance keeps the test small.

**ROOT CAUSE** — one of: a uniqueness or limit rule enforced in application code rather than by a
database constraint · a read-modify-write on a counter or balance with no lock · an "already used?"
check that isn't atomic with the mark-used write · an idempotency key that is advisory rather than
enforced · a check service that is a different service from the act service · an
eventually-consistent store read before the write lands. **That answer is your `fix_locus`** — the
specific non-atomic operation, each a separate fix (a unique index, a lock, an atomic decrement).

## 2. Derive the candidates — find every "check a limit, then act"

1. **Enumerate the operations that consume something finite**: redeem a one-time coupon, withdraw or
   transfer balance, claim a limited-stock item, take the last seat or invite, apply credit, submit
   a vote or like once, accept a single-use invite, increment a usage counter, "you may do this N
   times".
2. **Prioritise by what one extra grant is worth.** Chase races on **money, single-use tokens and
   limited inventory**, where a single over-grant is a real loss. The **high-value shapes**:
   double-spend and over-withdraw, coupon/gift-card/invite reuse, inventory oversell, quota overrun,
   vote and rating inflation, referral-bonus double-grant.
3. **Read the behavioural signals**: a uniqueness rule enforced in application code rather than by a
   database constraint; a read-modify-write on a counter or balance; an "already used?" check;
   idempotency that looks advisory rather than enforced; anything that decrements a quota.
4. **Read the recon tells**: no unique index implied by the behaviour, eventually-consistent stores,
   microservices where the check service is not the act service, and — importantly — endpoints that
   return a balance or count **you can watch**. That last is your oracle; find it before the race.
5. **On GraphQL, aliasing is a LIMIT-BYPASS primitive — not a concurrency one.** N aliased copies
   ride in one HTTP request, which defeats any control counted *per request*. But the spec is
   explicit: **top-level `mutation` fields execute serially**, one after another. Aliased mutations
   do not race each other — they queue. (Query fields *may* execute in parallel, so an aliased
   *query* can race; a `mutation` block will not.)
   So use aliasing to prove **"the per-request limit is the only limit"**, and use real concurrency
   — parallel connections, or a single-packet attack over HTTP/2 — to prove **"the check and the
   act are not atomic."** They are different findings with different root causes; conflating them
   produces a report that triage can disprove by quoting the spec. Keep the alias count small
   either way.

## 3. Determine the context — establish the sequential baseline first

Before any concurrency, run the operation **sequentially** on a test account and record what
"working correctly" looks like:

- The first attempt succeeds; the second is rejected. Capture both.
- Read the resulting persistent state — the balance, the counter, the redeemed flag — through the
  endpoint you identified in §2. This is the state you will diff against.
- Note whether the rejection names a database constraint or an application check; the wording often
  answers §1's question 3. **Without this baseline you cannot claim concurrency caused anything.**

## 4. Test → Confirm → Validate

**TEST — one controlled burst.** Fire a *small* batch of concurrent requests — a handful, e.g. 2–10
— sent as close to simultaneously as possible (single-packet attack, or parallel connections),
**once**. A burst, not a flood: minimal count, one shot, on a test account. **Outcome: a hypothesis.**

**CONFIRM — the default oracle is the persistent over-limit state, not the count of `200`s.** The
proof is the smallest possible over-grant: the limit holding **twice (or N+1) when it should hold
once**, visible in the final balance, count or redeemed flag — against the §3 sequential baseline
where it held exactly once. **The oracle inverts or lies in these ways:**

- Two "successes" that are one effect reported twice in the *response* while the database committed
  once — verify the **persistent** effect (final balance or count), not two `200`s.
- The backend **does** have a unique constraint and a parallel request fails with a constraint or
  deadlock error — the protection working, not a race.
- Retries or at-least-once delivery making a single logical operation *look* duplicated — correlate
  by idempotency key or transaction id; or load-balanced caching returning stale counters that read
  as over-limit but were never persisted.
- "It worked once out of many" with no baseline. **Reproduce the win** to rule out coincidence.

**VALIDATE — one extra grant is the entire proof.** You never need scale. Stop at N+1.

## 5. Safety — a race can double-spend real money

- **Never loop the attack and never hammer for volume.** One burst per hypothesis, then stop and
  reason; repeated bursts are indistinguishable from a flood.
- **Never race real money or inventory** you would actually lose or that harms other users — a
  successful race on a live path takes value from the program or stock from a real customer. Use test
  accounts, sandbox balances and test coupons. **Reset or refund the state afterwards**, and say in
  the report what you changed.
- **If the smallest safe test would still cause real loss or affect others, stop and report the
  hypothesis** with the non-atomic pair named — a legitimate outcome, not a failure.
- **Store the artifact**: the sequential baseline (one success, one rejection), the concurrent run
  (two or more successes), and the over-limit state — balance below zero, coupon used twice, N+1
  claims. **No artifact → HYPOTHESIS, not FACT.**
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`) — the burst as Burp Repeater parallel
  requests or a copy-pasteable script, **with the sequential control beside it**, plus the
  final-state read. Announce and budget the burst against the rate limit before firing.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the
`fix_locus` from §1 — name the exact check-then-act pair and the missing atomicity guarantee, not
just the endpoint. Log negatives with the oracle used: whether you observed the persistent state or
only response codes.

**Novelty.** This is novel when tied to a *specific* non-atomic check you identified by reading the
app's behaviour — not "sent 100 requests and one thing looked weird". Your moat is naming the exact
check-then-act pair and the missing guarantee. The crowded, weak angle is racing a generic
like/follow counter for a tiny inflation: low-value and often known. Impact: financial —
double-spend, over-withdrawal, negative balance, oversell; single-use bypass — a coupon, gift card
or invite reused, which hands off to `coupon-and-credit-abuse` for the money framing; quota or limit
overrun via concurrency, which is `limit-bypass` territory; and vote, rating or inventory integrity.
Chains: race a state transition to reopen a terminal state (`state-machine-abuse`); race a workflow
grant step to double-apply it (`workflow-abuse`); race a price or credit application with
`payment-abuse`. The race is often the *mechanism* that makes another logic flaw exploitable.

**Worked example.** `endpoints.md` lists `POST /wallet/redeem-giftcard` and a `GET /wallet/balance`
you can watch. Behaviour suggests redemption is application logic: read the card, check
`if not card.redeemed`, then credit the balance and set `redeemed=true` — no unique constraint
implied. *Model:* the check (`not redeemed`) and the act (credit + mark redeemed) are almost
certainly non-atomic, nothing is reserved in between, and two requests arriving inside the window
both see `redeemed=false` and both credit. Uniqueness looks enforced in code, not by the database.
*Hypothesis:* firing the redeem twice concurrently credits a single test card's value twice.
*Context/confirm:* on a test account with a low-value test gift card, first establish the sequential
baseline — redeem succeeds once, the second attempt is rejected. Then, **once**, send 2–5 redeems as
a single simultaneous burst and re-read the balance; true means the balance was credited more than
once. One shot, not a flood; reset or refund afterwards. Save the baseline, the burst, and the
resulting balance. *Novelty:* it names the exact check-then-act pair lacking atomicity on a money
path rather than "I sent 100 requests" — `fix_locus = missing atomic redeem/lock in
/wallet/redeem-giftcard`.
