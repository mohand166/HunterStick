# Coupon & Credit Abuse — the method

> **This is a test of your ability to mint free credit or reuse a coupon** in the redemption flow the
> human names — the chain that grants more value than the rules allow via reuse, stacking, or
> farming. Model the flow to the **redemption/grant check**: work out the *intended* rules, where
> each one is enforced, and which one the server doesn't actually check. Test on your own accounts,
> never harvest real value. Thin class file; work it with
> `playbooks/vulns/_master-vuln-hunting.md`.

## 1. Model the rule before you touch anything

**SOURCE** — what you supply to the grant: a coupon code, a gift-card number, a referral link or
invite, a registration, a repeatable action that mints points.

**FEED** — the path from that input to the grant: normalization (case/whitespace/unicode), the
uniqueness/`used`-flag lookup, the cart/order total calculation, the payment step that may revalidate
everything.

**SINK** — where value is actually granted and persisted: the order total, a wallet/credit balance, a
points ledger, a refunded remainder.

**CONTEXT** — for a logic class the discriminator is **where the rule lives and when it fires**:

- **Which rules are intended?** Single-use? Per-customer? Min spend? Non-stackable? Expiry? One
  referral bonus per real new user? Derive them from the ToS/UI, then find which the server doesn't
  enforce.
- **Where is uniqueness/consumption enforced** — a server-side "used" flag bound to the code *and*
  the user, or a client check?
- **When is the code marked consumed** — at apply, or only at final payment (leaving a reuse window)?
- **Is the code normalized** (case/whitespace/unicode) *before* the used-check? A normalization gap
  is trivial reuse.
- **Can a discount/credit push a total ≤ 0?** What happens then — order free, or remainder refunded
  as usable credit?
- **For referrals:** what defines a "new user" the bonus pays for, and can the attacker manufacture
  that identity cheaply (email aliasing, disposable accounts)?

**ROOT CAUSE** — the specific unenforced rule: the used-flag binding, the normalization step, the
stack-check, the consume timing, the referral identity check. **That answer is your `fix_locus`** —
each is a separate fix, so name it exactly.

## 2. Derive the candidates — enumerate the value-granting flows

1. **List everything that grants value:** discounts, promo/coupon codes, gift cards, store credit,
   loyalty points, referral bonuses, sign-up credit, cashback, wallet balances, free-trial grants.
2. **Then enumerate the abuse shapes against each:**
   - **Reuse** — a "one per customer" / single-use code accepted twice: on the same account, after
     removing-and-reapplying, across accounts, or via case/whitespace variants (`SAVE10` vs `save10`
     vs ` SAVE10 `).
   - **Stacking** — multiple coupons on one order when only one is allowed; a coupon on top of an
     already-discounted item; percentage + fixed stacking driving a total to zero or negative; the
     same code applied to multiple line items.
   - **Farming / self-referral** — a referral bonus paid for inviting yourself (alias email, `+tag`,
     throwaway accounts), both referrer and referee credited then the account cancelled, sign-up
     credit farmed by mass registration, points minted by a repeatable action.
   - **Gift-card / credit logic** — check-balance vs redeem race (see `race-conditions`), applying a
     card whose value exceeds the order and getting the remainder as cash/credit, redeeming a
     cancelled/expired card, negative-value credit.
3. **Read the recon tells:** coupon validation done client-side, credit balance echoed in the API,
   referral links with predictable codes, "remove coupon" endpoints, per-order vs per-item discount
   application.
4. **Ask how many times one request can redeem.** A GraphQL alias batch applies the same code N
   times in a single request, which defeats a per-request check and races a per-code one at the
   same time. Keep N tiny — two redemptions of a single-use code prove it as well as fifty, and
   fifty is theft.

## 3. Determine the context — establish the rule first

Before you break anything, make the legitimate path show you the rule. **Redeem a *test* coupon
legitimately** and observe it marked used — that is your baseline and your control. From that one
loop, read off: whether the used-flag is written at apply or only after payment completes; how the
code is normalized when it echoes back in the cart/API; and whether the total applies per-order or
per-item, and what its floor is.

## 4. Test → Confirm → Validate

**Accounts gate:** test accounts, and test/non-production coupons where available. Without them the
honest result is `coverage = blocked (needs-account)`.

**TEST — break the rule once.** One single disallowed action against the baseline from §3:

- *Reuse:* apply → remove → reapply, or apply the same code on a second test order/account.
- *Stacking:* apply two non-stackable codes (or code + item discount) to one test order.
- *Farming:* complete **one** self-referral loop with a test alias.

**Outcome: a hypothesis** — the UI accepting it is not the grant.

**CONFIRM — the default oracle is extra value surviving to the *final total* or to a spendable
balance**, not the cart preview. True positive = discount granted again past its single-use rule;
both codes applied with a total lower than either alone; the bonus credited to a controllable
balance. Where the oracle inverts or lies:

- The discount shows in the cart but is **revalidated and stripped at payment** — the reuse was
  provisional.
- **"Stacking" the server silently caps** (applies the better one, not both) — check the actual
  total, not that both codes were accepted into the UI.
- A **test/staff coupon with intentionally relaxed rules** — confirm the code represents a real
  production promo, not a QA artifact.
- A referral bonus credited **pending** and clawed back on fraud checks / never becoming spendable —
  pending ≠ realized value.
- A case-variant "reuse" that actually hit a *different* real coupon code.
- **Balance display updated client-side** but not persisted server-side.

**VALIDATE — the least that proves impact.** A single loop proves the logic; do **not** run it at
scale to accumulate real value. Impact is direct financial loss: unlimited/duplicated discounts, free
orders, farmed credit spent toward purchases, gift-card value multiplication, negative totals →
self-credit. Frame the loss from the "extra value granted" artifact — don't actually extract it.
Chains: coupon stack + `payment-abuse` price tamper → negative order total → credit back; single-use
reuse under concurrency → `race-conditions`; referral farm + `limit-bypass` (defeat the per-user cap)
→ scaled credit minting; redeem a cancelled card via `state-machine-abuse` (reopen a terminal credit
state).

## 5. Safety, artifact, and PoC handoff

- **Never** redeem real gift-card value, never cash out farmed credit, never mass-register. Use test
  accounts and test/non-production coupons where available.
- **If proving it requires actually extracting money/credit, stop** at the "extra value granted"
  artifact and report the hypothesis.
- **Store the artifact:** the legit redemption (code marked used / one bonus) **plus** the abusive
  redemption (second grant / stacked total / duplicate bonus) showing value beyond the rule. **No
  artifact → HYPOTHESIS, not FACT.**
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): the redemption requests to **Burp
  Repeater**, or copy-pasteable `curl` for the abusive sequence **with the legitimate control
  request**, so the differential in the final total reads in one glance.
- Respect the program's rate limit — a farming loop run more than once is both loud and real value
  extraction.

## 6. Log it

`targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the `fix_locus` from §1 — the
specific enforcement gap (used-flag binding, stack-check, referral identity check), each a separate
fix. Log negatives *with the oracle used*: "stripped at payment", "server capped the stack", "bonus
stayed pending".

**Novelty:** "coupon works twice" on a big program is often already reported. Novelty is the
*specific* rule gap: a normalization mismatch in the used-check, a remove/reapply window,
discount-application *order* enabling negative totals, a referral "new user" definition that email
aliasing defeats, or a redeem-vs-consume timing gap. Because these bugs come from understanding
*this* promo system's rules, they're inherently hard to dup when you describe the precise unenforced
rule; a bare "code reusable" with no mechanism is the noise.

## 7. Worked example — the spine in one pass

*Model / derive:* `endpoints.md` shows `POST /cart/coupon` and a matching `DELETE /cart/coupon`
("remove coupon"); `WELCOME20` is a documented one-per-customer promo. The used-flag appears to be
written only at final payment, not at apply.
*Context:* the intended rule is single-use per customer, but consumption timing leaves a window — if
"used" is stamped at checkout while apply/remove is free, a remove-and-reapply (or a case/whitespace
variant dodging the used-check normalization) re-grants the discount.
*Hypothesis:* applying `WELCOME20`, removing it, and reapplying ` welcome20 ` re-grants the discount
past its one-per-customer rule.
*Confirm:* on a test account with a test promo, redeem legitimately and confirm it marks used (the
control); then do the single disallowed action (remove → reapply a variant) on one test order and
check the discount is granted again **and survives to the final total**, not just the cart preview.
One loop, no real value extracted.
*Dedup:* names the exact gap — normalization mismatch plus a redeem-vs-consume timing window — not
"coupon works twice"; `fix_locus = used-flag binding/normalization + consume timing in
/cart/coupon`.
