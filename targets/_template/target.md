# <TARGET> — Profile / Brain

> Prose you reason over. Everything here is tagged FACT / HYPOTHESIS / ASSUMPTION.
> Promote architecturally significant discoveries here as you learn them, so any
> future session understands the target without re-deriving it.

## Organization
- **Company:** <name>
- **Business:** <what they do — matters for business-logic bugs>
- **Owned orgs / brands / acquisitions:** <list — a top source of novel assets>  [HYPOTHESIS until confirmed]

## Architecture (build this up over recon)
- **Frontend:** <SPA framework / server-rendered / mobile>  [FACT: source]
- **Backend:** <language / framework>  [HYPOTHESIS: from headers]
- **APIs:** <REST / GraphQL / gRPC — base paths>
- **Auth model:** <session cookies / JWT / OAuth / SSO provider>
- **Infra / hosting:** <cloud provider, CDN, WAF>
- **Multi-tenancy:** <yes/no, how tenants are separated>

## Patterns — what you have learned about how THEY build

> **This section is why a month-long engagement beats a five-day one.** `observations.tsv` holds
> facts about individual hosts; this holds **generalisations about the estate** — and it is loaded
> every session, so it is the only place a conclusion makes the next session smarter.
>
> `tools/kb.py patterns <target>` proposes candidates by counting across the ledger. It never
> writes here: you decide which are real.

| pattern | evidence | first seen | last confirmed | what it predicts |
|---|---|---|---|---|
<!-- example row (not data): <e.g. staging always under `trunk.*`, same auth as prod> | <12/14 hosts> | <date> | <date> | <where to look for hosts you have not found> -->

### Exceptions — the interesting part
> A host that **breaks** a pattern is a lead, not noise. When a pattern holds for 20 hosts and
> fails for one, that one is where the assumption behind the pattern was never applied.

- <host · which pattern it breaks · why that is worth testing>

### Retired patterns
> A pattern that stopped being true is still knowledge. Record when and why rather than deleting
> it — "they moved staging off `trunk.*` in August" explains a whole class of stale findings.

- <pattern · held until <date> · what replaced it>

## What testing taught us
> Not results — **lessons**. A rejected hypothesis that sharpened the next one belongs here; the
> row in `tested.md` records that a probe happened, not what you understood afterwards.

- <e.g. "IDOR on /orders is framework-guarded — the guard is global, so the whole object-ref
  family is low-yield on this stack. Ruled out 6 candidate endpoints, not 1.">

## Key observations
- <notable things that shape where bugs likely are>

## Interesting leads (feed hypotheses.md)
- <specific things worth a deep dive>

## Known / likely already-reported
- <what the program has almost certainly already received — steer around these for novelty>
