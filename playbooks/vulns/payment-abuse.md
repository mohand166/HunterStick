# Payment Abuse (price / amount tampering) — the method

> **This is a test of your ability to tamper with price, amount or currency** in the checkout or
> payment flow the human names — the chain that reaches a discounted, free, or inverted charge.
> Model the flow to the **server-side total/charge computation**: which money value the client
> sends, and which of those the server re-derives from something it owns versus reuses as given —
> then find the one it trusts but shouldn't. The value is a named trust gap on a named field, not
> a lowered `price=` at random. Validate in **sandbox/test-payment mode only** — never cause a real
> charge, refund or loss. Work this with `playbooks/vulns/_master-vuln-hunting.md`.

---

## 1. Model the money before you touch anything

**SOURCE** — every money-shaped field the client sends: `price`, `amount`, `unit_price`, `total`,
`quantity`, `currency`, a discount, a tax or shipping figure, an item id that implies a price.

**FEED** — the path from that request to the charge: cart state, coupon/tax/shipping math, any
intermediate total, the quote or order record, and the redirect or API call that hands a figure to
the payment provider.

**SINK** — the **authoritative charge computation**: where a final amount is fixed and a charge
intent (or payout, refund, credit) is created. Ask *which value the provider actually charges on* —
the cart, the order record, or the number in your request.

**CONTEXT — which value does the merchant re-verify, and which does it trust?** Build the answer
field by field before sending anything; it is the whole class:

| field | re-verified means | trusted means (the sink) |
|---|---|---|
| `price` / `unit_price` / `total` | looked up from a trusted catalog and recomputed | the submitted figure is honoured |
| `quantity` | sign, type and range validated | negative, zero, fractional or overflowing values accepted |
| `currency` | confirmed against the order or account currency | a swap bills the same number in a weaker unit |
| discount / tax / shipping | recomputed server-side at capture | an intermediate total you shaped survives to the charge |
| rounding / precision | one defined point and precision | per-line vs total rounding differ, and the seam leaks value |

If the server recomputes everything from a trusted catalog and ignores client money fields, there is
no bug. Every field in the "trusted" column is a candidate sink.

**ROOT CAUSE** — one of: the charge is derived from a total the client submitted rather than from
the cart on the server · a money field is echoed and honoured instead of looked up · no sign check
(negative amount, quantity or discount → credit instead of debit, refund abuse, a negative line item
cancelling a positive one) · no type or range check (fractional or huge quantity, overflow, a
quantity that flips a total's sign) · no currency validation (swap, or a mismatch between item and
charge currency) · rounding at more than one precision, per line then summed versus on the total ·
one path recomputes and its sibling doesn't. **That answer is your `fix_locus`** — the specific
endpoint and field that trusts client money; each is a separate fix.

## 2. Derive the candidates — every request where money crosses the boundary

1. **List the flows where a monetary value crosses from client to server**: add-to-cart, checkout,
   order create, subscription upgrade, top-up, donation, tip, payout/withdrawal, refund, invoice,
   quote/estimate. **Prioritise the secondary ones** — refund, payout, tip and quote got less
   scrutiny than checkout.
2. **Read the recon tells**: totals computed in client JS; prices in the DOM or an API response
   echoed back on submit; a payment provider integrated client-side; coupon, tax and shipping math
   done before submit. Each says a number the client holds may reach the charge.
3. **Trace every money field individually from request to charge** — which are echoed and which are
   recomputed. Two fields on the same endpoint can have different answers. Look especially for
   multi-item totals where one path recomputes and another doesn't, and for discount-then-price
   ordering, where the sequence itself is the flaw.

## 3. Determine the context — a legitimate transaction first

Before tampering anything, run the flow once legitimately in **test/sandbox mode** and capture:

- the legitimate request and the resulting total;
- the **charge intent** (or payout/refund object) the provider is given, and which figure it
  carries — this, not the cart echo, is what you will compare against;
- where rounding happens and at what precision — per line then summed, or on the total;
- whether any validation is visibly present for sign, range, type and currency.

## 4. Test → Confirm → Validate

**TEST — one money field at a time.** Resubmit the captured legitimate request with exactly one
field changed: a lower `price`, a `currency` swap, a negative discount or amount, a fractional or
negative quantity, a sub-cent figure. One controlled test per hypothesis, on a test account, ideally
on the cheapest or free test item. **Outcome: a hypothesis.**

**CONFIRM — the default oracle is the charge intent, not the cart echo.** The finding is that the
server *accepted a tampered money value* into the authoritative computation: the order total
reflects your figure, or a charge intent is created for the wrong amount. You do not need a real
settled charge to show that. **The oracle inverts or lies in these ways:**

- The server **echoes** your `price` in the response but **recomputes** the actual charge — the
  echo is cosmetic. Confirm what the *payment intent/charge* is for, not what the cart displays.
- The client-side total is decorative and the real total server-authoritative — you changed a display.
- **Sandbox behaves differently from prod**: test mode may skip validation prod enforces. Note the
  environment; a sandbox-only quirk may not reproduce live.
- A rounding "gain" of a sub-cent the provider truncates anyway — no real value moved; a currency
  swap the provider **rejects at settlement** — the accept was provisional; or discount and tax
  recalculated at capture, undoing your tampered intermediate total.

**VALIDATE — stop at the accepted-total artifact.** The minimum that proves impact is the server
honouring the manipulated amount. If the only way to confirm further would be a real charge or loss,
**stop and report the hypothesis** — do not push it to settlement.

## 5. Safety — read this before testing anything transactional

- **Use test/sandbox payment credentials or a test-mode order.** Never complete a real-money
  transaction to "prove" loss, never trigger a real refund or payout, and never move funds that
  actually leave the program's control.
- **Stop before settlement.** The manipulation being accepted is the finding; the money actually
  moving is an incident.
- **One controlled attempt per hypothesis**, then stop and reason.
- **Store the artifact**: the legitimate request and its total, the tampered request, and the
  response showing the server honoured the manipulated amount — the wrong order total, the charge
  intent for the wrong value, the negative applied. **No artifact → HYPOTHESIS, not FACT.**
  Redact card and account identifiers.
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): Burp Repeater or a copy-pasteable
  `curl` for both the legitimate and the tampered request, and state the environment you ran in.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the
`fix_locus` from §1 — log the **exact field** and the missing server-side recompute or validation,
not just the endpoint. Log negatives with the oracle used: whether you observed the cart echo or the
charge intent, because those are different depths of "not vulnerable".

**Novelty.** A naive "changed the price in the request" on a mature checkout is usually already
hardened or reported — the recompute is the first thing programs fix, and the primary checkout
`price` param is the crowded, low-dup-value angle. Novelty lives in the **seams**: currency,
rounding and precision mismatches; negative or fractional quantities; multi-item totals where one
path recomputes and another doesn't; discount-then-price ordering; and money fields on *secondary*
flows (refund, payout, tip, quote) that nobody audited. Impact is direct financial loss — buy at an
attacker-set price, free or near-free purchase, negative amount → self-credit or refund, currency
arbitrage, payout inflation — prime severity when a real charge would settle, but demonstrated with
the accepted-total artifact, not with real loss. Chains: price tamper + `coupon-and-credit-abuse`
(stack a discount onto an already-lowered price → negative total); tamper the amount then
`race-conditions` to apply it repeatedly; `state-machine-abuse` to mark a tampered order paid;
`workflow-abuse` to skip the server-side recompute step entirely.

**Worked example.** `endpoints.md` shows checkout recomputes item prices server-side (hardened), but
a *secondary* `POST /api/tips` on the order lets the client submit a `currency` field beside
`amount`, and the charge intent is built from that request. *Model:* the authoritative price lives in
the catalog for items, but the tip flow trusts client money fields directly — so `currency` sits in
the trusted column, and the question is whether the server confirms the tip currency matches the
order or account currency before charging. *Hypothesis:* `amount=500, currency=<weak-currency>` bills
500 of a far weaker unit than the account's intended currency — a currency-swap arbitrage on a
less-audited flow. *Test/confirm:* in sandbox/test-payment mode on a test account, submit the
legitimate tip and capture the total and intent, then resubmit with the currency swapped and check
whether the **charge intent** honours the swapped currency rather than normalising it. Stop at the
accepted-intent artifact — never settle a real charge; save legitimate versus tampered request and
response. *Novelty:* checkout `price` is picked over; this is a currency seam on a flow nobody
audited — `fix_locus = missing currency validation in POST /api/tips`.
