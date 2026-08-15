# Cross-target lessons

> Copy to `lessons.md` (gitignored) and promote into it deliberately. This is the **hunter's**
> cross-target knowledge — how orgs build, how WAFs behave, what a pattern generalizes to. It is
> loaded only at orient/prioritize moments (`brief.py --resume` names it;
> `attack-surface-prioritization` reads it), never resident, and it is never written by a run.
>
> **What belongs here:** a pattern one target proved that plausibly transfers — each row carries
> its origin so it can be re-checked or retired. **What never belongs here:** target facts,
> endpoints, credentials, or anything a fix on one program would not generalize. A lesson with no
> origin is deleted at review time. Cap: **50 rows** — `brief.py --resume` warns past it, because
> a lessons file nobody reads protects nothing.

## Lessons

<!-- One row per promoted lesson. Promote by explicit decision when kb.py patterns or a run's
     result surfaces something generalizable: write the row, cite the origin target + date.
     Retire a row the moment a target refutes it — a wrong lesson is worse than none.
     Example (commented so parsers do not count it as data):
     | 7 | Their WAF normalizes quotes in JSON bodies but not in URL params — test the param form first | sql-injection variant ordering | acme · 2026-08 · R-041 | -->

| # | lesson | applies to | origin |
|---|---|---|---|
