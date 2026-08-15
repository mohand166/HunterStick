# &lt;TARGET&gt; — runbook

> The hunter's **standing order** for this target: an ordered bundle of steps approved once and
> edited only by the hunter. Invoked with *"run the runbook on &lt;target&gt;"*. Each step runs its
> own skill lifecycle — run opened, evidence persisted, exit criteria met — what is pre-authorized
> is the **sequence**, not a relaxation of any step's own contract.
>
> The runbook **may propose** a vuln-hunt in its closing brief; it **never starts one**. Steps are
> never added mid-run by the model — a new step is a hunter edit to this file.

<!-- Step rows: | # | when | step | selector | note |
     `when` is a condition from the fixed vocabulary: always · monitor-enabled ·
     components-present · recon-stale · findings-open · custom:<one line the model can evaluate>
     `step` names a skill slug, a flow, or one of the closing actions (closing-brief).
     `selector` bounds the step (hosts, top-N, apex); a dash means the step's own default.
     Example (commented, not data — parsers count rows):
     | 1 | always | run-flow | first-look | top-3 ranked hosts only |
-->

| # | when | step | selector | note |
|---|---|---|---|---|
| 1 | always | closing-brief | — | consolidated delta, re-ranked top-3, decisions worth the hunter's time |

## Standing notes

- (per-target constraints the hunter set: rate ceiling, which principal to use, what to skip,
  notify strict mode — anything here overrides the generic defaults for this runbook only)
