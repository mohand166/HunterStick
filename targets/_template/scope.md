# <TARGET> — Scope

> **What the hunter said they are testing**, plus any standing constraints they set. This is
> context you reason with and route by — it decides *which brain* an asset belongs in and it holds
> the hunter's own binding instructions. It is **not** an execution veto: the hunter chose the
> target, so a skill they invoke with its required inputs present is not gated on how this file
> reads (`AGENTS.md` §*Scope is the hunter's*), and `run.py`/`preflight.py` never read it. What the
> allowlist *does* shape is **auto-derived traffic frontiers** — a capture being imported
> (`import-http.py`), a monitored or swept cohort (`monitor.py`/`sweep.py`), a crawl/fetch frontier
> (`chunks.py`) — so outside data does not get recorded or auto-fetched. It never vetoes a host the
> hunter names explicitly (e.g. `paths.py --host`, `calibrate.py --host`): that just warns.
>
> Initialization copies the hunter's statement below **verbatim**; it does not expand a company
> into domains or reinterpret a wildcard. If an asset is not unambiguously covered, record the
> ambiguity and ask — do not silently widen it.

## Supplied scope statement — verbatim

```text
TBD — blocking: the hunter has not supplied an authorization boundary
```

## Supplied exclusions — verbatim

```text
exclusions: none stated
```

`exclusions: none stated` does not mean `exclusions: none`. Ask before touching a surprising asset.

## Rules of engagement — verbatim where supplied

```text
TBD — blocking: program testing rules were not supplied
```

## Mechanical allowlist

> **Derived at init from the verbatim statement above — it is never the authority.** The tools that
> keep *outside data* out of the brain match against this list (`import-http.py`, `monitor.py`,
> `sweep.py` via `tools/scopelib.py`). `run.py` and `preflight.py` do **not** read it — scope does
> not gate execution. If this list ever disagrees with the verbatim statement, **the verbatim
> statement wins and this section is wrong.**
>
> One entry per line. `*.example.com` covers the apex and everything under it; a bare host covers
> only itself. An exclusion here is a *host or subtree*, never an apex that would cancel an
> inclusion.

### In scope

- TBD — blocking: derive from the verbatim statement above; the ingest tools match against it

### Out of scope

<!-- one host or subtree per line, e.g. `- \`admin.acme.com\``. Leave empty if the program states none. -->

> Exclusions that are not domain-shaped ("divested brands", "third-party SaaS") cannot be matched
> by any tool. Write them here anyway as prose; `monitor.py` names them and refuses to probe
> actively until you acknowledge they are unenforceable.

## Standing decisions — the hunter said so, and it holds across sessions

> **These live here, not in a separate ledger, because `scope.md` always loads and every session
> reads it.** A constraint recorded somewhere the next session does not read is a constraint that
> gets violated. This is the one part of scope that *does* bind you — but not as scope-policing:
> *"do not test payment actions"* is the **hunter's own instruction**, and honouring it is
> obeying them, exactly like honouring the class they named. The rest of this file is context;
> these rows are standing orders.
>
> Append-only. When a decision is reversed, mark it superseded with the date rather than deleting
> it; a decision that was true for three weeks explains three weeks of findings.

| date | decision | why | supersedes |
|---|---|---|---|
<!-- example row (not data): <YYYY-MM-DD> | <e.g. do not test payment actions — read-only on `/billing/*`> | <hunter's reason> | — -->

**Two kinds live here and they are not the same:**

- **Constraints** — *"no new accounts without confirmation"*, *"read-only on billing"*. These bind
  every later session because the hunter said so. If a task would cross one, say so and ask —
  you are checking their standing order, not vetoing their scope.
- **Interpretations** — *"treat `acme.com` as one host, not an apex"*. These resolve an ambiguity
  once. **Never silently re-interpret one in a later session** — if it looks wrong, say so and ask;
  do not quietly decide the other way.

Sequencing preferences (*"do 17 before 13"*) are **not** decisions — they are next actions and
belong in `index.md` under Awaiting.

## Normalized quick checks

> Convenience pointers, filled in as you read the program page. **None of them gate anything** —
> no tool reads this section, and `unknown` never stops a command. They exist so a later session
> can see what was established and what was assumed.

- **Required attribution header:** unknown — from `tools/config.py` unless the program says otherwise
- **Maximum request rate:** unknown — `defaults.rate_limit_rps` applies until the program states one
- **Account policy:** unknown
- **Sensitive-data rule:** unknown
- **Out-of-scope vulnerability classes:** exclusions: none stated

## Source

- **Supplied by:** <hunter / program page / private brief>
- **Program page:** <URL or none supplied>
- **Recorded:** <YYYY-MM-DD>
- **Evidence:** `scope-evidence.md`
