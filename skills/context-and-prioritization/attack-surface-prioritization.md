---
name: attack-surface-prioritization
description: Rank it, argue it, and never rank on the payout. Use for "attack surface prioritization" and closely related asks.
---

# attack-surface-prioritization — rank it, argue it, and never rank on the payout

> Read `skills/shared/_recon-method.md` first. This skill sends **no traffic**: it reads what
> `derive-properties` produced and orders it.
>
> **It runs only when the hunter asks the model to choose.** A human-named entrypoint goes straight
> to testing — ranking a target somebody already picked is ceremony, and re-ranking nobody asked
> for silently overrides a decision the hunter made with context no file holds.
>
> **This is a test of your ability to convert facts into judgement without laundering volume into
> confidence.** Properties are facts; rank is judgement. The value is a short ordered list where
> every row carries the reason it is where it is. A restatement of counts is not a ranking.

## Objective

Order the rows in `@surface` by how much testing value they carry, fill the rank and scoring
columns, and seed the top of the list into `@hypotheses` with the property that implied the class.
Rank by **greenfield-ness — how few people have seen this** — not by how much of it there is.

## Inputs

- `@surface` (from `derive-properties`) — the propertied rows. This skill fills `rank`, `score` and
  the scoring columns; it does **not** invent rows. A property that no artifact witnessed is a
  ranking built on a guess.
- `@clusters` (from `host-correlation-and-clustering`) — rank clusters, not names. N hosts sharing
  a cluster are one row, and the singletons are the inventory worth ordering.
- `@endpoints` (optional, from `cross-host-endpoint-reuse`) — routes confirmed on more than one
  host, and the controls that stop applying somewhere. A control gap outranks almost anything else
  in this list.
- `@scope` — what is in scope and what the program forbids. **Never rank on bounty**: payment is
  program policy and says nothing about whether a technique is applicable here.
- `@target` and `@tech` (optional) — architecture, acquisitions, stack identity with versions.
- `@app.current` (optional, from `application-mapping`) — roles, tenancy and flows for the exact
  selected host; the only source for
  the dimensions that most often decide rank.
- `@tested` (optional, from `vuln-hunt`) — so a resolved cell is not ranked back to the top.
- `lessons.md` (optional, workspace root, from the **hunter**) — cross-target lessons they
  promoted deliberately. Advisory weight only: a lesson adjusts a rank's argument, it never
  overrides what this target's own artifacts witnessed. Absent file = no cost.

## Signals — what to come back with

1. **The ordered rows, each with its one-line reason.** A rank with no argument is unreviewable and
   nobody can disagree with it, which is the problem.
2. **Greenfield-ness, and the proxy you used for it.** Source provenance is the cheapest one: a host
   that only one obscure source knew about is unindexed and probably untested, and it should
   outrank the flagship apex that every automated pipeline on the platform hits daily.
3. **Singletons on ≥2 independent axes, at the top.** They are the estate's forgotten hosts, and
   the clustering skill already computed them.
4. **Rows with two or more parser layers.** That single derived fact gates request smuggling, path
   confusion, ACL bypass, cache poisoning, cache deception and 403 bypass — six of the highest
   severity classes of 2024–2026, and all of them are the same bug (two components disagreeing)
   wearing different clothes. Detecting a CDN does not deprioritise a row; it **increments this
   counter**.
5. **Control gaps** — an operation reachable somewhere the control that guards it elsewhere does
   not reach. Evidence of a missing check outranks evidence of a large surface.
6. **The signal metrics, reported instead of the volume ones.** Singletons on ≥2 axes · distinct
   parameter names · entrypoints whose stack is confirmed by two independent artifact signals ·
   operations with an identified control gap.
7. **Rows you cannot read.** A row with no `undetermined` field is a row you cannot rank correctly —
   it looks complete and is merely unlabelled. List them separately and say what would resolve them.
8. **Where the evidence was too thin to rank at all**, named explicitly, with the skill that would
   thicken it. That is a better output than a confident ordering of nothing.

## Known traps — each of these produces an authoritative-looking list that misdirects hours

- **Volume metrics are download-size metrics.** "5,000 live hosts", "400,000 URLs", "40 technologies
  detected" are all reports of how much bandwidth you spent. None of them is evidence that anything
  is testable, and putting one at the top of a summary makes a thin surface look finished.
- **Never rank on bounty.** The payout table is the program's policy on what it will pay for, not
  the target's disposition to be broken. Rank on applicability and greenfield-ness; let the hunter
  apply their own economics afterwards.
- **Ranking by cluster size ranks the load balancer.** Forty names on one backend is one asset. If
  size enters the score at all it belongs to the *singleton* count, not the member count.
- **"Missing security headers ⇒ immature ⇒ juicy" has no dataset behind it**, and the
  counter-evidence is that recent large payouts came from targets with maximal header hygiene.
  Headers are set by a platform team on an edge config; bugs live in application code somebody else
  wrote.
- **"WAF or CDN present ⇒ mature ⇒ skip" is backwards.** The edge is frequently the vulnerability
  itself: desyncs found *in* Cloudflare, Akamai and Netlify for $350k+; the ChatGPT account-takeover
  existed *because* Cloudflare cached a path prefix; TE.0 existed *because* one load balancer parsed
  a header differently from the backend.
- **"Sequential IDs mean IDOR" and "`/api/admin/*` returning 200 means BFLA" are not ranking
  inputs.** OWASP frames the flaw as the missing check and explicitly warns against inferring
  privilege from a URL path. The real predictor is *an identifier in the request plus the object
  being reachable by a second principal* — which needs `@app.current`, not a path.
- **The parameter-family-to-payout mapping is unsupported.** Measured against 357 disclosed reports,
  only the redirect family survives, and even it converts to XSS about 1.75× more often than to
  open redirect; the `cmd`/`exec`/`debug` family produced **zero** RCE and the `xml`/`data` family
  **zero** XXE and **zero** deserialization. Use parameter names as triage ordering — where to spend
  fuzzing budget — never as a probability of a class.
- **Self-signed or expired certificates do not indicate a soft target.** They indicate a host the
  web team does not manage.
- **Ranking is not testing.** Every ranked row is still a hypothesis; the evidence gate applies
  unchanged, and this skill stops before any request is sent.
- **Re-ranking without being asked** overrides the hunter. Rows accumulate as skills run; ordering
  them is a separate, explicitly requested act.

## Outputs

- `@surface` with `rank`, `score`, the scoring columns and a `why` on every ranked row — the
  source→sink shape or the property that put it there.
- `@hypotheses` seeded from the top of the list, each with the property that implied its class and
  `status = open`.
- Facts via `kb.py add` for anything the ranking exposed about the target rather than about one
  row — a control that exists in one place and not another, a stack the estate uses only once.
- The run recorded with its `--limitations`: which slice was ranked, from which dated sources, and
  what it could not see.

## Exit criteria

The slice ranked is named, with its sources and its discovery gaps — no inventory is ever globally
complete and pretending otherwise is how ranking deadlocks. Every ranked row carries a reason and a
pointer. Rows that could not be read for want of an `undetermined` field are listed apart, not
ranked among the rest. No volume metric appears as a headline. Nothing was promoted into testing:
the hunter picks.

## Next

Offer: `vuln-hunt` on the top row, one entrypoint and one class · `generate-hypotheses` (if the
backlog needs more than the top of this list) · `application-mapping` (the only way to resolve the
role, tenant and state-machine dimensions that most `undetermined` fields are waiting on) ·
`derive-properties` again over a slice this ranking showed to be under-propertied.
