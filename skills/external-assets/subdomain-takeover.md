---
name: subdomain-takeover
description: Adjudicate the dangling record without claiming it. Use for "subdomain takeover" and closely related asks.
---

# subdomain-takeover — adjudicate the dangling record without claiming it

> Read `skills/shared/_recon-method.md` first — it holds the loop, the input rule and the tool contract.
> This file holds what is specific to turning a dangling record into a defensible verdict.
>
> **This is a test of your ability to disprove your own hit, and to test a vendor's claim rather
> than look it up.** The value is a small set of candidates each carrying an *evidenced* answer to
> "would this name actually be claimable by someone else, and what does that reach" — including the
> ones you ruled out and why. It is **not** a count of fingerprint matches, and it is **not** a
> licence to register the resource: the confirmation is a fingerprint, always.

## Objective

Take the dangling candidates `dns-analysis` classified and decide, per candidate, whether the
third-party service will actually let a stranger claim that name — then record the evidence and the
escalation path that sets its severity. This skill adjudicates; it does not enumerate. Its two hard
constraints are that a fingerprint match is a hypothesis rather than a verdict, and that the
verdict is reached without taking the resource.

## Inputs

**Enrichment — each absent one narrows the run, none of them gates it:**

- `@roots` (optional, from `organization-and-roots`) — apex-level NS delegations. The dangling-NS
  class lives at the apex and subtree level, so a host-only candidate list will not contain it.
- `@hosts.all` (optional, from `subdomain-enumeration`) — the names that never resolved. If the
  enumerator resolve-and-discarded them, that class of candidate is already gone and the run should
  say so instead of reporting zero.
- `@raw.http` (optional, from `http-probing`) — cookie scope and CORS/CSP allowlists already
  observed. These do not find candidates; they decide what a confirmed one is *worth*.

**As the selector, at least one of the following:**

- `@hunter.host` — one exact candidate the hunter named. Begin by collecting its rcode, record, and
  complete CNAME/delegation chain; the hostname alone is a selector, never takeover evidence.
- `@net.dns` (from `dns-analysis`) — the candidates and the state that made each one a candidate:
  `NXDOMAIN` with a CNAME still in the answer section, `SERVFAIL`/`REFUSED` on a delegation, and
  CNAME chains terminating at a third-party provider.

## Signals — what to come back with

1. **Per candidate: the state, the exact record, and the vendor.** The evidence is the rcode
   together with the record still present in the answer — quote it, because a triager re-runs it.
2. **Whether the vendor's domain-ownership validation actually works — tested, not looked up.**
   This is the highest-value work in this skill and it is largely unexploited. DareShark tested the
   top 20 vendors: **18 of 20 issue a per-customer unique CNAME, and 16 of those have
   implementation errors** — the per-customer CNAME resolves onward to a **fixed** endpoint, and
   pointing a name straight at that fixed endpoint **passes validation**. Four distinct
   validation-bypass classes are documented. So "this provider verifies ownership" is a claim to
   falsify at the resolution layer, not a column to read off a table.
3. **Whether the name is user-selectable or auto-generated** — the second half of the classic
   filter, and the half that still holds.
4. **Dangling NS separately from dangling CNAME.** `SERVFAIL`/`REFUSED` is a class **no fingerprint
   list covers**, and its impact is authoritative control of the whole subtree rather than one
   hostname. Unit42 counted **1,974 dangling NS records under 1,659 root domains**.
5. **The escalation path, which is what sets severity.** OAuth/SSO redirect token capture ·
   `*.example.com` cookie theft · SameSite=Lax CSRF · CORS allowlist abuse · CSP allowlist bypass.
   A `Domain=.target` cookie is the single observation that decides whether a takeover on a
   throwaway name is a P1 or an informational — it is the precondition of the cookie-tossing class.
6. **The rejects and why.** A candidate ruled out with a stated reason is an output; a candidate
   silently dropped is a gap someone re-derives next month.

## Known traps — measured or sourced, each has produced a wrong report

- **The two-condition filter is necessary but not sufficient.** The classic rule — the service does
  not verify domain ownership **and** the subdomain name is user-selectable — is sourced, and the
  same source names HubSpot and Atlassian Statuspage as *not* vulnerable despite matching naive
  fingerprints. The measurement above overturns the safe half of that: **16 of the top 20 vendors'
  ownership-validation implementations are broken.** Condition (1) must be **tested per vendor**,
  not read off a list. A candidate dismissed because "that provider verifies ownership" is an
  untested dismissal.
- **The canonical fingerprint list is 18 months stale.** `can-i-take-over-xyz` shows
  `pushed_at: 2025-02-08` with **202 open issues** — no commit in roughly 18 months as of Aug 2026
  while 202 unresolved service submissions sit open. **Those 202 issues are the actual frontier.**
  Re-derive counts rather than quoting a summary: a grep of the repo gives **36 Vulnerable / 26 Not
  / 14 Edge case across 76 entries**, where a fetch-and-summarise pass had reported 57/23/13 of 93.
  The wrong numbers looked exactly as confident as the right ones.
- **Running the takeover template pack and reporting the hit is a liability.** Of one 73-template
  pack, **4 templates target services marked Not-vulnerable and 6 more target Edge-case — roughly
  14% of the pack is false-positive-prone by construction.** The pack is a candidate generator; the
  adjudication above is the skill.
- **"The class is dying" is folklore, and this reference contradicts itself about it — deliberately.**
  A practitioner pass recorded that the fingerprint canon had collapsed and the class was churning
  out. A later pass to peer-reviewed measurement overturned it: **DareShark (SIGMETRICS 2023)**
  scanned Tranco 1M → **11.4M subdomains over 101 rounds** and confirmed **10,351 dangling records
  across 2,096 apexes — explicitly "over 8× more than previous findings"** — with **~270 new per
  week**, 36.3% still vulnerable after a month, and **45.5% still receiving live queries** from 70M
  client addresses; **NSDI 2024** observed **20,904 actually-hijacked cloud resources**, a third
  persisting beyond 65 days, 75% used for blackhat SEO. **No measurement paper, vendor report or
  dataset was found claiming prevalence has fallen since 2019.** Where a practitioner claim and a
  measurement conflict, prefer the measurement — and know the conflict exists.
- **Prove by fingerprint; do not claim the resource.** AWS's customer penetration-testing policy
  explicitly lists **"S3 bucket takeover; Subdomain Takeover"** among *prohibited* activities.
  Claiming is prohibited, hostile to a third party if you guessed wrong, and unnecessary — triage
  accepts the fingerprint. Note the honest state of the sources: the same reference elsewhere says
  *"always attempt the claim"*, and the sourced reporting guidance says to hold the finding until
  the takeover is *reliably demonstrated* unless the program says otherwise. **Provider policy
  outranks the folk rule.** If a program explicitly asks for a live demonstration, that is the
  program's call to make in writing — not an inference you draw from a triage preference.
- **Do not spend the budget on MX or on address records.** Unit42's 317,000 unsafe dangling domains
  were **63.1% expired registrations, 36.9% code-hosting, the vast majority CNAME, and contained
  no dangling MX at all.** For the address-record variant the evidence pulls two ways: *Cloud
  Strife* (NDSS 2018, 130M domains and 767M domain→address mappings) found **more than 700,000
  domains pointing at free cloud addresses** with an attacker cost of **$31.06** to cycle the pool,
  yet the NSDI 2024 longitudinal study observed **zero IP-address takeovers** — attackers prefer
  CNAME because it is cheaper. The mechanism is demonstrated; the exploitation is not observed.
  Do not build the pipeline around it.

## Outputs

- Verdicts appended to `@net.dns` next to the candidates they adjudicate: candidate · state ·
  vendor · ownership-validation result **as tested** · name-selectability · verdict · evidence ·
  and, for rejects, the reason.
- Facts via `kb.py add`: which vendors this estate depends on and how each behaved when its
  validation was tested — that generalises to every other name pointing at the same vendor, and it
  is the durable output of the run.
- Leads into `@target` for confirmed candidates, with the escalation path and the cookie-scope
  observation that sets severity, promoted into `@hypotheses` where the reach is actually named.

## Exit criteria

Every candidate has a verdict, and every verdict names its evidence. Vendor ownership validation
was **tested at the resolution layer**, not looked up, or the candidate is explicitly marked
*undetermined* rather than *not vulnerable*. Dangling NS candidates are adjudicated separately from
dangling CNAME, because no fingerprint list covers them. **No resource was claimed**, and the
report says so. Where the input candidate set was already filtered upstream, that limitation sits
next to the count.

## Next

Offer, do not choose: `derive-properties` (a confirmed third-party delegation becomes a propertied
entrypoint there — this skill produces evidence, not attack surface) · `dns-analysis` re-run over
the roots (candidates appear at roughly 270 per week across a large corpus, so the delta is the
yield here, not the total) · `cloud-asset-discovery` (when the dangling target is a
provider-side storage or app resource, the provider-side surface is a different skill) ·
`organization-and-roots` (dangling NS is per-apex, so widening the apex set widens this class more
than grinding subdomains does) · `monitoring-and-diff` (the diffing discipline is sound; note
plainly that the *yield* of continuous monitoring is unproven — the article most often cited for it
provides no evidence).
