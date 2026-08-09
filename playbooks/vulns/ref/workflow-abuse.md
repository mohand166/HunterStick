# Business-Logic Abuse — reference layer

> **Lookup, not reading.** Open a section when its trigger fires; don't read this end to end.
> The method lives in `../workflow-abuse.md` — that one you read every time.
>
> Grounded in disclosed HackerOne reports (`knowledge/reports/workflow-abuse/`). `[#id]` =
> hackerone.com/reports/id.
>
> ⚠️ **Corpus warning — read this before trusting a count.** The upstream index
> (`TOPBUSINESSLOGIC.md`) is keyword-matched, not class-matched: roughly **half of the 175 fetched
> reports are not business-logic at all** (memory corruption, XSS, SSRF, curl parsing bugs, bare
> `bugs.php.net` links), swept in on words like "function" and "manipulation". Around **70 reports
> carry real logic content**, and all three independent miners reported this. So: the *shapes* below
> are evidence-backed, but any claim about what is "common" rests on a small, skewed sample.
>
> ⚠️ **Access:** many findings needed an admin role, a paid tier, a merchant account, a second
> organization, a jailbroken device, or a self-hosted install. Flagged where known, but assume a
> precondition until you've read the report.
>
> ⚠️ **Ethics:** several reporters drove real money, real third-party systems, bulk mail, or took
> production down. Those are marked **⛔ do not imitate**. See `../workflow-abuse.md` §5.
>
> ⚠️ **Disposition:** each cached report's `.json` carries a `substate`. Presence in this corpus is
> **not** acceptance — some cited reports were closed `informative`, `not-applicable` or `duplicate`,
> and are marked where known. Check `substate` before treating a technique as validated.

| § | trigger |
|---|---|
| **B1** | the client seems to decide what you're allowed to do |
| **B2** | sequence, state, and who may drive it |
| **B3** | making the guard decline to run |
| **B4** | numeric & aggregation invariants |
| **B5** | reservation & double-spend |
| **B6** | teardown, decay & partial failure |
| **B7** | trust boundaries between systems |
| **B8** | anti-automation as a business rule |
| **B9** | impact, feasibility & non-findings |
| **B10** | worked examples |

---

## B1. Response-side gating — the client decides on the server's behalf

**The biggest gap in the old playbooks: they were request-side only.** The server computes the right
answer and ships its *verdict* through the client, which draws the UI — and the follow-up write never
re-checks. This cluster is roughly a tenth of the usable corpus (about the same size as **B8**), so
it is not provably "the most common" shape — but **it owns the highest-severity outcomes here**,
including three account takeovers.

- **An OTP/verification response carrying a small verdict** — the strongest evidence in the corpus.
  A program's own summary: the service *"relied on client-side responses to determine the success of
  OTP verification"* [#3228888, critical, resolved]. Wrong OTP returned `status: 3`; changing it to
  `1` established the session [#2962527, DoD, resolved]; the same shape on registration produced a
  0-click takeover [#1994227]; on a login response, an admin portal [#1508661]; and again in
  [#1387320] and [#2061982], both resolved.
- A JSON blob of entitlement booleans (`is_active`, `is_pro`, `free_trial_claimed`…) rewritten
  wholesale `false`→`true` unlocked paid features and a redeemable reward [#1070510 — ⛔ the reporter
  redeemed a real physical-goods coupon; stop well before that].
- Blanking a list in the response (`{"merchants":[]}`) let a free-tier user re-pick their capped
  choices, repeatedly [#672487].
- A paywall implemented as a DOM attribute (`data-upgrade="true"`) — note the team reclassified this
  as *"more like bypassing client side access control than privilege escalation"*, which is exactly
  the trap below [#594080].
- Native clients: invoking the auth-success method directly in the runtime skipped a PIN screen
  [#80512 — closed **informative**; jailbroken device + runtime hooking].

**The tell:** a response whose body is mostly booleans, or a small verdict integer, *about you*.

**The trap, and it is the reason half this cluster closes informative:** a UI that unlocks proves
nothing. The oracle must be a fresh, un-intercepted session or a demonstrated server-side
consequence. The cleanest contrast is a *request-side* sibling: a free-plan user who set a Pro-only
`{"access_level":"read"}` in the request body, where a **second account really received viewer
rights** — server-side proof, no interception needed [#3591764, needs two accounts, free plan].

## B2. Sequence, state, and who may drive it

**Ask "who may drive this transition?" before "is this edge legal?"** — missing authorization on a
*legal* transition was the more productive question here.

- A state document exposed as a resource: `GET /api/application/state`, then `PUT` it back with a
  different value, unauthenticated [#993722 — ⛔ the reporter took a production host down for over an
  hour and used the outage as the impact; the *technique* is worth knowing, the demonstration is not].
- A legitimate operational plan replayed under a **different organization's** session [#1901713,
  needs two devices and a second org on a beta cloud].
- A legal edit driven by the wrong user [#141120].

**Idempotency of a legal edge.** Every edge legal, but the cycle unbounded and paying out each lap —
resolve → reopen → resolve minted reputation each time, and the credit landed on a **different**
object than the one transitioning [#36211, needs a program-member account]. Ask: *is this transition
idempotent, and what else does it write?*

**Object-creation side effects.** Buying a second licence mutated the first one's seat count and
expiry rather than creating an independent object [#2461737, informative, needed a real paid purchase]. Ask:
*does creating B mutate A?*

**Two-step creates.** An object that only exists after both requests: step 1 carried a literally
broken guard (`X-CSRF-TOKEN: Undefined`), step 2 had none, and nothing was visible until both fired
— a per-request scanner sees nothing [#169699].

**Flow donation — invert the direction.** A password-recovery link that logs you in *before* asking
for the new password: generate it for **your own** account and send it to the victim, who is silently
logged into your session [#809]. Any single-identity methodology structurally cannot find this.

**Object-kind as a second enum.** Authorization bound to the *declared* type while a different type
was saved [#404323].

**Consent scope < granted scope.** An OAuth scope that was not rendered on the consent screen, so the
victim approved less than they granted [#3713965, CVE-2026-9106].

**Note on the old edge list.** The former state-machine playbook led with `cancelled→shipped`,
`refunded→delivered`, `draft→published`, `expired→active`, `rejected→approved`, `unpaid→paid`.
**Not one of those appears anywhere in this corpus.** That may reflect the corpus's skew rather than
the technique's value — but treat the list as a memory aid, not a discovery procedure, and lead with
the questions above.

## B3. Making the guard decline to run

**Not "is the check wrong?" but "under what conditions does the check not run at all?"** The
highest-yield source-reading findings all came from this question.

- **Early return.** `validate_namespace_used_with_template` opened with `return unless project.group`
  — create the project in a *user* namespace and the entire authorization path is a no-op, while the
  dangerous parameters survive into the import service [#689314, needs an EE feature].
- **Guard conditioned on fields the attacker also controls.** The extension check ran only
  `if handler=='file' && logging_mode` — erase `logging_mode` and the guard is skipped while the save
  block still writes the handler and the attacker-chosen filename. The reporter drove it as two
  requests following the UI; reading the pasted code, one crafted request appears sufficient
  [#841947, admin panel — the two-request framing is the reporter's path, not a necessity].
- **Field-presence semantics, in both directions.** Deleting a required key made the check that
  validates it disappear entirely — removing `"code"` from a signup body returned success and a valid
  session [#3255473]. The inverse: a field the UI hardcodes had to be *explicitly sent* to reach new
  data, and omitting it returned an empty result that looks like a dead end [#2295958].
- **Guard bound to one input shape.** A CSRF check tied to the JSON parser path — drop the token and
  switch `Content-Type` to form-urlencoded [#1890310]. A rejection that fires only for authority-less
  URLs: `file://../` blocked, `file://localhost/../` fine [#3494098 — closed **not-applicable**; the reporter's argument is that the *false guarantee* is the harm].
- **Guard and effect resolve the identifier differently.** A trailing space defeated a string
  comparison while still resolving to the same group for the removal [#145745 — closed **informative**; self-hosted admin]; a
  cache key parsed from a URL by regex while the fetch resolved `/../` [#1848940 — ⛔ poisoned a
  shared cache affecting other tenants].
- **A guard that is present but broken-valued** looks enforced to a scanner [#169699].
- **Sibling verb on the same route.** CAPTCHA validated in the `POST` handler; the identical body via
  `PUT` accepted anything, unlimited [#206653]. And a resource the UI could only create and delete
  accepted `PATCH`, letting the reporter raise a key's role — reasoned by analogy from a sibling
  resource's verb surface [#2149124, needs a second privileged identity].

## B4. Numeric & aggregation invariants

Rules that are a *number*, with no step and no status.

- **One input, two formulas.** Seats used `Math.ceil`, price used `Math.floor` — `1.9` bought two
  seats at one seat's price [#1446090, team billing; reporter could not confirm settlement and said
  so].
- **Negative quantity in an aggregate.** A line item with `quantity: -1` reduced the order total;
  price, per-line total and grand total were all client-supplied and nothing was recomputed
  [#364843 — ⛔ a card charge really occurred, though against a program-supplied *test* store, not a
  live merchant].
- **Threshold counting events, not distinct principals.** "N reports deletes a comment" behaving as a
  simple counter, so one account clicking ten times sufficed [#1051734, non-default feature].
- **Counter keyed to something you control.** A notification/send limit defeated with rotating
  `X-Forwarded-For` [#1067533]. (A quota exceeded by parallel creates [#2682392] is filed by the
  program as a **race condition** — see `playbooks/vulns/race-conditions.md`.)
- **Allowance reachable by a second path** — a plan's member limit extended through the invitation
  flow with no upgrade [#295900, one-line report]; a free-tier retailer cap re-opened via B1
  [#672487].
- **Two representations of one value drifting.** A product priced in two currencies with a
  hardcoded, never-refreshed conversion [#1677155 — closed **informative**].
- **Integer width as an oracle.** Boundary ids (`/reports/2147483647` → 404 vs `…649` → error)
  fingerprint the type holding a counter before you assume an overflow is reachable [#132057].

## B5. Reservation & double-spend

**No race required.** Ask: *between initiation and settlement, what is held?*

A transfer to a vault sat **pending** without holding the main balance — spend the same funds
externally during the window, then approve, and the balance goes negative [#94925, informative]. Every status
involved was legal, so the old "is `unpaid→paid` legal?" lens asks entirely the wrong question.

⚠️ **This section rests on a single five-sentence report that was closed `informative` and carries no
artifact** [#94925 — ⛔ live exchange, real balance]. The *mechanism* (a pending state that reserves
nothing) is a sound thing to look for and generalises to any two-phase value movement; the claim that
such windows are typically human-scale rather than millisecond races is **my inference, not the
report's**. Treat this whole section as a hypothesis to test, not an evidenced pattern.

For the timing-sensitive variants — check-then-use where a name is resolved twice [#3432833
(informative), #1520931] — see `playbooks/vulns/race-conditions.md`.


## B6. Teardown, decay & partial failure

**The transition succeeds; the compensating action doesn't.** The old playbook hunted
`terminal→non-terminal` edges; the corpus's terminal-state bugs are the opposite — correct
transitions with incomplete teardown.

- Left a team, kept receiving report notifications and still rendered as a member [#63729]; a
  relationship never pruned on departure, so a later action notified 2,110 stale subscribers across
  21 programs [#442843 — the team's own writeup is the best incident post-mortem in the corpus].
- A deleted real name still shown in a hover tooltip on disclosed reports — the *primary* surface was
  correct [#127914]. Cached pages still rendering after logout [#158270]. A revoked WordPress
  capability retained in the session [#833782, needs admin to grant then revoke].
- **Time-decay:** authorization derived at write time, cached, never re-evaluated on the read/send
  path [#442843]. Ask: *was this permission derived once and remembered?*
- **The obligatory side effect that never fired** — a password change via a reset link sending no
  notification while the in-app change does [#149027 (informative), #92251]. Cheap to check; lands low, and often closes informative.
- **Partial failure with no rollback:** a contract distributing funds threw on the last transfer and
  the chain reverted, but the exchange had already credited the earlier ones — the oracle was the
  on-chain wallet being empty while the balance showed funds [#300748 — ⛔ real funds]. An import that
  errored to the admin left extracted `.php` files behind in a web-reachable directory [#236607,
  admin].
- **Validated at ingest, consumed unvalidated at egress.** A package cache checked `integrity` on the
  way *in* and retrieved by `name+version+sha1` on the way *out*; poison once and every future
  install resolves to the payload — surviving `rm -rf node_modules`, and executing `postinstall` even
  when the original was installed with `--ignore-scripts` [#703138, local tooling].

**Deleting is a fan-out, not a write.** After any revocation, enumerate the derived surfaces —
emails, tooltips, caches, sessions, exports — and check each.

## B7. Trust boundaries between systems

**Who else consumes this state, through what projection, and is that projection signed?**

- Price handed to a payment processor in a client-visible query string (`amount_1`, `shipping_1`)
  [#682344 — closed **duplicate** (real bug); ⛔ tampered a live checkout]; prices in a POSTed cart XML [#218748].
- A downstream integrator crediting value from an **incomplete projection**: a transfer with an
  enormous lock time displayed normally in the audit command exchanges used, so deposits were
  credited for outputs unspendable for millennia — the broken rule belonged to a *different party*
  than the program, and lived in what the command **omits** [#417515 — ⛔ real funds at two live
  exchanges].
- A flow that hands off mid-way to a differently-branded third-party host — worth checking, though in
  this instance the rate limit *did* follow the handoff and was defeated by IP rotation instead
  [#1691195].
- **Protocol trust inversion:** in `LOAD DATA LOCAL INFILE` the *server* names the file the client
  must read; a rogue server can request anything [#156511].

## B8. Anti-automation as a business rule

Rate limits, CAPTCHAs and one-time tokens are business rules with money behind them (email cost,
human review queues). Their failure modes are structural:

- CAPTCHA validated on one verb only [#206653].
- Counter keyed to the wrong dimension [#1067533].
- **Reusable "single-use" artifacts** — a reset link working repeatedly and never expiring after use
  [#92251]; a reusable `csrfmiddlewaretoken` enabling unbounded reset mail [#223525 — six lines, no
  PoC, but resolved]; an `authenticity_token` accepted 5+ times [#12782 — closed **not-applicable**];
  a claim that issued reset links stay simultaneously valid [#280529 — resolved, but the report
  argues from best practice and demonstrates nothing].
- **Bulk-mail is where this class goes wrong ethically.** One reporter ran Intruder with IP-rotation
  against a live host and reported "lots of emails of reset password" [#1691195 — ⛔ **do not
  imitate**; this is precisely what `../workflow-abuse.md` §5 forbids]. Contrast [#206653], who
  proved a CAPTCHA bypass by hand and refused to run Intruder because it would flood a moderation
  dashboard.
- **Token bound to the wrong subject** — an OTP legitimately issued to the attacker's own phone for
  *their* object, then replayed with the object id swapped to the victim's [#1330529 — ⛔ claimed a
  real third-party merchant's listing]. Single-use worked fine; binding didn't. **Test these two
  properties separately.**
- Credential lifetime as an unwritten rule — a "remember me" token valid for ~3651 days [#37822].

## B9. Impact, feasibility & non-findings

**Apply a feasibility gate.** A reputation integer-overflow path was arithmetically valid and closed
N/A because reaching it would take ~4,596 years [#132057]. Compute the cost-to-reach before writing
up.

**Declare your limits — it needn't cost you the report.** One reporter who could not confirm
settlement was still resolved [#1446090], as was one who wrote "it's difficult to say this bug
exists… but I suspect it does" [#17502, staging]. Honest counterweight: another limitation-declaring
report was closed **informative** [#2461737], so declaring limits is cheap insurance, not a
guarantee.

**Check the disposition before you copy a technique.** Every cached report's `.json` carries a
`substate` field (`resolved` / `informative` / `not-applicable` / `duplicate`). A report being in the
corpus does not mean the program accepted it — several cited above did not.

**Common non-findings in this corpus:**
- **Policy complaints with no attacker win** — a password-policy assertion [#255708, informative],
  "no check that the new password differs" [#1296597]. Note two apparent policy complaints were
  nonetheless **resolved** [#765031, #280529], and "back button shows cached pages after logout" was
  **resolved** in both instances [#7909, #158270] — so this category is about *your* evidence, not an
  automatic rejection.
- **Misreading a role matrix** as privilege escalation — closed as "permissions working as intended"
  [#280914]. Read the product's own role documentation first.
- **Admin acting on admin-generated data** — closed informative [#1661310].
- **The program's weakness label is not the bug class** — a report filed under "Business Logic
  Errors" was a C buffer truncation [#3473182]. Don't trust the label; read the content.
- **Your evidence contradicting your claim** — a report asserting buffer overflows whose own pasted
  Valgrind output read `ERROR SUMMARY: 0 errors` [#3337561, closed **not-applicable**]. If the artifact disagrees with the
  claim, there is no finding.

## B10. Worked examples

**A. Entitlement gated in the client.** A plan limits you to N of something. *Rule:* "free tier gets
N". *Where does it live?* Watch the response that draws the UI — if it carries booleans or a list
that the client uses to decide, that response *is* the access control (**B1**). *Test:* blank or flip
the field, then perform the write. *Oracle (§3):* log out, log back in with no proxy, and see whether
the change persisted [#672487]. *fix_locus =* "the write endpoint never re-derives the plan limit."

**B. A guarded commit with a sibling door.** *Rule:* "this action requires a CAPTCHA / a password /
2FA". *Derive (§2):* list every endpoint and **every verb** that reaches the same effect; diff their
guards. *Test:* the same body on the unguarded verb or path [#206653, #2149124]. *fix_locus =* the
specific handler missing the check — and check its siblings before filing.

**C. A number that two formulas disagree about.** *Rule:* "you pay per seat". *Test:* a fractional
value, then a negative one, then repeat add/remove cycles to see whether the inverse operation
reverses cleanly [#1446090, #364843]. *Oracle:* the **merchant-side** record, not the displayed
total — and stop before settlement (§5). *fix_locus =* "quantity is rounded differently for billing
than for provisioning."

**D. Something was revoked.** *Rule:* "leaving the team ends access". *Test:* hold the artifact
(session, subscription, link, cached page), then leave/revoke/delete, then replay — and enumerate the
derived surfaces rather than just the primary one [#63729, #442843, #833782]. *fix_locus =* the
teardown that never ran.
