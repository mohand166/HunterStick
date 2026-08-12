# Flow — huge estate

> Hundreds or thousands of live hosts. The instinct is to run everything against everything; that
> produces a number nobody can act on and a bill of millions of requests. **You do not assume 3,918
> names are 3,918 independent apps—or that six response groups are six backends. You correlate,
> confirm, then test representatives plus the outliers.**

## Situation
Live-host count in the hundreds or more, and no single application is obviously the target.

## Preconditions
- `recon/live-hosts.txt` exists and is not `missing`.
- **Calibration checked on a sample.** On an estate this size a soft-404 pattern inflates every
  downstream number by an order of magnitude. Sample ~10 hosts before trusting anything.

## Steps

1. **Fingerprint enough to group by.** → `skills/surface-discovery/technology-fingerprinting.md` — server,
   framework, headers, favicon hash, TLS cert, error-page shape.
2. **Cluster.** → `skills/context-and-prioritization/host-correlation-and-clustering.md`. Write `clusters.md`
   with a named representative per cluster.
   **A cluster is a HYPOTHESIS that these hosts behave alike — not a proven testing unit.** A
   shared server banner, favicon hash or TLS cert says they were built from one image; it says
   nothing about whether they share an authorization model, a tenant boundary, a config, or a
   deploy date. `trunk.` and `prod.` cluster together *precisely because* they are the same code —
   and the whole reason to look at them is that one of them is configured worse.
   So: test the representative first, then **prove the cluster before you inherit its result** —
   one differential probe per member (same request, compare status/length/auth behaviour). A member
   that answers differently is not a member. Only demonstrated shared behaviour justifies one
   `fix_locus`; until then a negative on the representative clears the representative.
3. **Hunt the outliers, not the mode.** The interesting hosts are the ones that *don't* fit: a lone
   different framework, a `dev.`/`stage.`/`canary.`/`trunk.` sibling of a production name, an
   admin/internal hostname, a 500 where everything else is 200. **Non-prod siblings of hardened
   production APIs are the single most productive pattern on a large estate** — same code, weaker
   controls, far less attention.
4. **Find the same endpoint on the weaker sibling.**
   → `skills/context-and-prioritization/cross-host-endpoint-reuse.md`. An object id obtained legitimately on prod,
   replayed against `trunk.`/`ha.`/per-DC instances, is the estate-scale authz test.
5. **If the hunter asks to rank, rank clusters, not hosts.** → `attack-surface-prioritization`, scoring per cluster.
6. **Then go deep on one.** Pick the top cluster's representative and switch to the flow that fits
   *it* — `api-surface`, `auth-app`, `spa-frontend`.

## Aborts
- Any loud skill without an explicit selector and budget → **pilot on one representative**, report
  yield and projected cost for the full set, ask. At this scale an omitted selector is the
  difference between 300 requests and 3 million.
- Clustering yields one giant undifferentiated group → the fingerprint is too coarse. Add a
  discriminator (favicon hash, error body, TLS SAN shape) before proceeding.
- The estate is mostly parked/CDN/marketing hosts → say so and shrink the working set explicitly.

## Cost
Steps 1–2 are one request per host — the only step that legitimately touches everything. Everything
after operates on representatives, which is the entire point.

## Output
- `clusters.md` — clusters, members, shared signals, representative.
- `attack-surface.md` — ranked **clusters**.
- The outlier list from step 3, named individually.

## Exit
Report the compression honestly: N live hosts → M unconfirmed similarity groups → C confirmed
testing units → the top 3 and why. If you sampled or capped anywhere, say where.
