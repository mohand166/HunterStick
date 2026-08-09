# <TARGET> — Tested Log

> **One row per probe actually sent.** Two jobs, and they are not the same job:
> (1) never re-test the same thing, (2) group confirmed findings by **`fix_locus`** — the distinct
> code/config location a fix would touch.
>
> **`fix_locus` is the dedup key for FINDINGS, not for coverage.** Before a bug is confirmed the
> real fix locus is usually still a hypothesis, so `tools/coverage.py` deliberately does not key on
> it. Use it when deciding whether two confirmed findings are one report.

`result` = not-vuln | vuln | inconclusive | out-of-scope | not-applicable.
`coverage` = tested | partial | blocked | deferred. **`blocked` is not `not-vuln`** — an untested
cell and a cell you could not reach are different answers.
`principal` = which account / role / unauth the probe ran as.
`run_id` = the bounded run this probe belonged to (`runs.tsv`), so a probe can be
traced back to the selector, sources and limitations it was taken under.

## `variant` is what keeps this honest

**A cell is `entrypoint × class × principal × variant`.** Without a variant, one row claims the
whole class on that entrypoint — and `SQLi on POST /search` tested against `q` says nothing about:

- `filters[name]` in the JSON body reaching a different query builder
- an XML body reaching a different parser
- the older `/v1/search` handler still mounted
- a GraphQL resolver sharing the route

Name the input location, the parser, the handler version, or the technique. `coverage.py` reports
every variant-less row as **coarse** rather than counting it as complete.

For authorization, the variant is the *relationship*, not just the account — `user-b reads user-a's
object` does not resolve `user-a reads user-b's`, cross-tenant, same-tenant-other-member,
former-member, or share-recipient-reads-parent. Each is its own row.

## A resolved negative must be evidenced

`result = not-vuln` is the strongest claim here: it removes work from the list. `coverage.py`
**downgrades it to `partial` unless the row has both an `artifact_ptr` and a `method`.** An
unevidenced negative is an assertion, and a later session cannot tell the two apart.

| date | run_id | entrypoint | variant | class | principal | method | result | coverage | fix_locus | artifact_ptr |
|---|---|---|---|---|---|---|---|---|---|---|
| | | | | | | | | | | |

## Negative results worth remembering
- <"tried X on Y, solidly not vulnerable because Z" — so it is not re-chased>

## Reopened
> A resolved cell stops being true when the surface moves — a deploy, a new API version, an auth
> redesign, a new parameter. Add a fresh row rather than editing the old one; the history is
> evidence about the target, and `coverage.py` flags conflicting rows instead of letting the newest
> silently win.

- <date · cell · why it was reopened>
