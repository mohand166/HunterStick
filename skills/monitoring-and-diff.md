---
name: monitoring-and-diff
description: A small honest delta, cheaply, forever. Use for "monitoring and diff" and closely related asks.
---

# monitoring-and-diff — a small honest delta, cheaply, forever

> Read `skills/_recon-method.md` first — it holds the loop, the input rule and the tool contract.
> This file holds what is specific to snapshots and diffing.
>
> **This is a test of your ability to produce a delta that is real.** Diff **normalised content,
> never filenames**: hashed bundle filenames change on every deploy, so filename diffing emits one
> alert per deploy per host, and the failure mode that ends monitoring programmes is not a missed
> change — it is alert fatigue, after which nobody reads the delta at all.
>
> **Be honest about the yield.** The article most often cited for continuous monitoring provides no
> evidence that monitoring itself finds bugs. The diffing discipline is sound; the yield is
> unproven, and this skill will not claim otherwise. What *is* evidenced is narrower and still
> worth having: an endpoint that appears before its feature launches is less battle-tested code,
> and the cost of watching for one is near zero. **Run this as a cheap background process, not as a
> headline strategy.**

> **Enabling a monitor is the hunter's call — never an automatic follow-on to recon.** Having
> enumerated subdomains is not a trigger to schedule anything. A recon phase may *offer* this skill
> as a next action; it must never run `monitor.py enable` on its own. Scheduling recurring traffic
> against a target is a decision a human makes explicitly, once, per target — so wait to be asked,
> and only then install the cron.

## Objective

Re-capture the moving parts of recon on an interval, diff each snapshot against the previous good
one, and emit **only the delta** — scope-filtered, normalised, and small enough that a human still
reads it in six weeks. Snapshots are immutable; the delta goes to the brain, and folding it into
the surface stays with the model and the hunter.

`tools/monitor.py --active` implements exactly three dimensions, each its own immutable snapshot
with its own partial-run quarantine: **(1) subdomain names** (add/remove), **(2) status + tech on
every in-scope name** — so a host that *changed* (a gate that appeared or vanished, a tech that
shifted) surfaces, not only new names, and **(3) JS content** on the live 200s, keyed by the
filename with its content-hash normalised away but **hashed on the raw body**, so a changed key, id
or endpoint is never normalised into a false "unchanged" (the cost is that a build id baked into a
bundle diffs as `JS-CHANGED` — triage it, do not silence it). Discovered JS URLs are **candidates,
not approved requests**: the job validates scheme (`http`/`https`) and host (in-scope apex, not
excluded) *before* it fetches, records off-scope refs without touching them, and never sends the
attribution header off-scope. Ports, params and full request/response bodies are **not** watched by
the cron — those are heavier passes a human runs deliberately, and treating their silence as "quiet"
would be the dishonesty this skill exists to avoid.

## Inputs

- `@hosts.all` (from `subdomain-enumeration`) and `@hosts.live` (from `http-probing`) — the name and
  endpoint baselines.
- `@urls` (optional, from `url-collection`), `@params` (optional, from `parameter-discovery`),
  `@endpoints` (optional, from `api-discovery`) — the surface baselines. Each one absent is a
  dimension this monitor is blind to, not a dimension that is quiet.
- `@raw.snapshots` (optional, from `monitoring-and-diff`) — the previous snapshots. **Optional only
  on the first run, where it is absent by definition** — that run is a baseline, not a delta, and it
  must say so. On any later run a missing snapshot set is a broken monitor, not a first run.
- `@js` (optional, from `javascript-analysis`) — the route and chunk tables, which are the highest
  value thing to watch and the thing filename diffing destroys.
- `@scope` — enforced inside the job, not afterwards. A monitor that filters at review time has
  already sent the requests.

## Signals — what to come back with

1. **Additions and removals.** Removals only exist if snapshots are immutable — a rolling
   append-only baseline can only ever show additions, and a decommissioned host that has become a
   dangling CNAME is a removal.
2. **New endpoints that appear before the feature launches.** Less battle-tested code, reachable
   before the audit that ships with the launch. This is the genuinely evidenced case for running
   this at all.
3. **Changed behaviour on an unchanged path** — the normalised body changed, a gate appeared or
   disappeared, the error envelope shifted. A path that stopped requiring auth is worth more than a
   hundred new names.
4. **New entries in the client route or chunk table**, especially routes with no reachable UI.
5. **New names and new live endpoints**, scope-filtered before they are recorded and before
   anything probes them.
6. **Runs that were quarantined as partial**, named as such. A quarantined run is not a quiet
   period; it is a measurement you do not have.
7. **"Nothing changed" is a result**, and it is the common one. Report it as an observation with its
   interval, not as a failure to find anything.

## Known traps — this is a skill where the traps *are* the method

- **Filename diffing is the classic failure.** Content-hashed bundle names rotate on every deploy;
  diffing them produces a permanent stream of alerts that contain no information. Diff the
  **normalised content** of the bundle, and diff the route table it declares.
- **Normalise before diffing or the noise is permanent.** CSRF tokens, timestamps, build ids,
  session identifiers and rotating banners will differ on every single request. Build the
  subtraction set the way the parameter tools do — repeat the baseline request several times, keep
  what always differs, subtract it, and when a new diff appears, re-request and re-diff to see
  whether it reappears. A diff that does not reproduce was noise.
- **A partial run must be quarantined, not compared.** An expired API key returning 200 names where
  the previous snapshot held 55,200 publishes 55,000 phantom deletions, and then 55,000 phantom
  additions on the next run. Keep the data, refuse the delta, and log the failure — a ratio floor
  against the previous snapshot is what enforces this.
- **The first run is a baseline.** It has nothing to compare against and must report no delta.
- **Never overwrite a snapshot.** Every run writes its own dated file. Immutability is what makes
  removals visible and lets any two past runs be re-diffed when a question comes up later.
- **Program policy travels with the job, not with the hour it runs at.** Rate limit and attribution
  header on every request, because the programme requires them of every request. Active probing
  without a rate limit is refused, not defaulted.
- **Prose exclusions cannot be enforced mechanically.** "Divested brands" and bare company names in
  a scope file match no domain rule; a wildcard apex would otherwise authorise probing something
  the programme explicitly carved out. Surface them and require an acknowledgement.
- **A monitor running from a cloud box has an unmeasured false-negative rate.** Major CDNs blocklist
  common cloud provider ranges outright — blackhole, not throttle — and regional apexes are
  geofenced. Those hosts do not merely fail: they diff as **removals**, and the next successful run
  diffs them back as additions.
- **The delta is not a finding and not a ranking.** The job never scores, never files hypotheses and
  never tests. It accumulates the delta until a session reviews it, so nothing is lost in between.
- **Do not oversell it.** An interval that produces a large delta every time is usually measuring
  your own instability, not the target's change rate.

## Outputs

- `@raw.snapshots` — the new dated, immutable snapshot, plus the quarantined ones kept and labelled.
- The delta held for review — additions, removals and changed-content entries, scope-filtered —
  carried across sessions rather than reported once and lost.
- New rows appended to `@surface` **unranked and without properties**, plus leads into `@target`.
  This skill records that an entrypoint now exists; `derive-properties` assigns what it *is*, and
  `attack-surface-prioritization` decides where it sits. A monitoring run that guessed at
  properties would produce a row that reads complete on evidence it never gathered.
- Facts via `kb.py add` for what the delta shows about the target — a deploy cadence, a naming
  convention that changed, a control that appeared.
- The run recorded with its interval, its selector and its `--limitations`.

## Exit criteria

The diff ran against a previous snapshot that was **not** partial, or the run says which snapshot
it skipped and why. What was normalised away is stated, so nobody later reads a quiet delta as a
quiet target. Removals are visible, not just additions. Every new asset was scope-filtered before
it was recorded. Nothing was overwritten. A first run is labelled a baseline and reports no delta.
The delta is small enough that a human will actually read it — if it is not, the normalisation is
wrong and that is the thing to fix before the next interval.

## Next

Offer: `derive-properties` over the delta only (new rows, not the whole surface) ·
`attack-surface-prioritization` to re-rank the affected slice only, if the hunter asks ·
`cross-host-endpoint-reuse` when the delta added a host to an existing cluster · `vuln-hunt` on a
newly appeared endpoint whose properties already imply a class.
