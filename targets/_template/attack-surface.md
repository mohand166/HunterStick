# <TARGET> — Attack Surface (ranked)

> The recon→testing bridge. **Rows start at derive-properties** — a probed host is an entrypoint,
> appended with `rank` and `score` empty. `technology-fingerprinting`, `javascript-analysis`,
> `api-discovery` and `application-mapping` add classes and variants;
> **attack-surface-prioritization ranks what is already here.** An empty rank means not-yet-scored, which is
> not the same as unimportant. (`host-correlation-and-clustering` produces the clusters it
> links to.)

Signals: **exposure** · **sensitivity** · **tech_risk** · **dynamism** ·
**dup_likelihood** (higher = less likely already reported) · **linkage** (value from what
it connects to — cluster peers, leaks, pivots; score the full picture, not the row alone).

One row per candidate **`(entrypoint × vuln_class)`** (derive-properties). Group rows by entrypoint so its
full class coverage shows at a glance — an entrypoint is an entrypoint for *multiple* classes.

`principals` = every controlled account/role or `unauth` needed to resolve that class on this
entrypoint. Use the labels from `accounts.md`; a missing account remains named here and becomes a
visible `blocked (needs-account)` cell.

`properties` = the observed surface facts, from the closed vocabulary in
`playbooks/system/class-signals.md`. They are what makes applicability *computable*:
`tools/coverage.py <target-dir>` maps them to classes and flags any class implied by the
properties that this table never proposed. A free-text property matches nothing.

## `variants` — the column that stops a cell over-claiming

**Without it, one row claims a whole class on an entrypoint.** `sql-injection` on `POST /search`
tested against `q` says nothing about `filters[name]` in the body, an XML content-type reaching a
different parser, or a `/v1/search` handler still mounted. Coverage can see which variants you
*logged*; it cannot invent the ones nobody planned.

List what actually needs separate proof, separated by ` · ` — **as prose, not a table**, because
tools that count ranked entries read the tables in this file:

- **an injection class** → each input location: `q · sort · body.filters[name]`
- **a parser-sensitive class** (XXE, deserialization) → each content-type: `json · xml · multipart`
- **any class on a versioned API** → each mounted handler: `/v2 · /v1`
- **an authorization class** → the **relationship**, not the account:
  `b→a's object · cross-tenant · same-tenant-other-member · former-member · share-recipient→parent`

**Leaving it empty is allowed and is not free.** `coverage.py` reports the cell as *coarse* rather
than counting it complete — which is the honest state, not a pass.

| rank | entrypoint (host/endpoint/param/flow) | vuln_class | principals | variants | properties | exposure | sensitivity | tech_risk | dynamism | dup_likelihood | linkage | score | why (source→sink) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| | | | | | | | | | | | | |

## Backend clusters (host-correlation-and-clustering)
<!-- cluster id · member hosts · shared signals · linked facts — filled by host-correlation-and-clustering -->


## Notes
- <clusters, themes, "these all share the same backend", acquisition assets, etc.>
