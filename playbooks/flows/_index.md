# Flows — one command, one situation

> A **flow** is a named response to a *situation*, not a sequence of phases. "The host is alive but
> everything 404s" is a situation. Experienced hunters recognize it in a second and know the four
> things to try; everyone else re-derives it every time, badly. That recognition is what these files
> hold.
>
> Phases answer **"how do I do X"**. Flows answer **"I am looking at this — what now"**.

---

## Why this does not break "one skill, then stop"

It looks like the auto-chaining the workspace forbids. The difference is who decided:

| | |
|---|---|
| `first-look` | scope is filled and `recon/` is empty | subdomain-enumeration → live-host-validation → http-probing → technology-fingerprinting, quiet — no portscan, no fuzzing. Ends with the first `attack-surface.md` rows |
| **forbidden** | you finish a phase and continue to the next one because it seemed natural |
| **a flow** | the human names a bundle whose steps, cost and abort points were **declared before it ran** |

One human decision still authorizes everything that happens. That is the whole distinction, and it
only holds if you keep the three rules below.

### 1. Two intents — read which one you were given
This is the contract in `skills/orchestration/run-flow.md`, and this index follows it, not the reverse.

- *"What should I run on acme?"* · *"this host 404s everything"* — a request for a
  **recommendation**. Name the flow, print its steps, cost and abort points, **and stop.**
  Choosing is theirs.
- *"Run the dead-end flow"* · *"run first-look on acme"* — **they already authorised the bundle.**
  Print what it will do, then **run it.** Asking again for permission they just gave is friction,
  not safety.

Either way, **print the steps first** — a flow that starts executing *while* describing itself is a
pipeline; one that describes itself and then runs what was named is the bundle they asked for.

### 2. Abort points are hard stops, not speed bumps
Even inside an authorised bundle, one thing stops the flow mid-way and the rest are carried
forward, not vetoed:

- **A required input missing** — the one hard stop. Name it, name the skill that produces it, stop.
  An *optional* input missing just narrows that step.
- **Calibration** — soft-404 or catch-all detected. Repair it, or carry the limitation forward
  explicitly onto every count the flow reports. Not a veto; a caveat that must travel.
- **Accounts** — a step needs ≥2 usable principals and `accounts.md` has fewer. Park that step as
  `coverage = blocked (needs-account)`; do not fake it with one account. The rest of the flow runs.
- **Loud step** — no selector or budget. Choose and state a defensible bound, pilot, then scale *that
  step*.
- **Surprise** — the flow's premise turned out false (you entered `dead-end-host` and found a
  sitemap). **Stop. The situation changed, so the flow is the wrong one.** This is the most
  important abort and the easiest to skip.

Scope is **not** on this list. It is context and routing, not a gate (`AGENTS.md` §*Scope is the
hunter's*); a standing constraint the hunter set is honoured as their instruction, per `scope.md`
§*Standing decisions*.

### 3. A flow never tests
Flows do recon, mapping and triage. They end by handing entrypoints to `vuln-hunt`, which stays
one-entrypoint-one-class. **No flow sends a payload.** Testing is where the human must be in the
loop for every unit, because that is where the traffic is.

---

## The situations

| flow | you are looking at | the move |
|---|---|---|
| [`broken-calibration`](broken-calibration.md) | 200-for-everything, or every path redirects | **repair first** — every discovery count is fiction until you do |
| [`dead-end-host`](dead-end-host.md) | live host, no links, no forms, everything 404s | recover surface that isn't linked: archives, JS, fuzzing, vhosts |
| [`spa-frontend`](spa-frontend.md) | the page is a JS bundle | the routes and the API contract are *in the bundle* — read it, don't fuzz |
| [`api-surface`](api-surface.md) | JSON responses, or a spec/introspection is available | take the contract; skip discovery entirely |
| [`no-signup`](no-signup.md) | no self-registration, no credentials obtainable | do every unauth class properly, park authz honestly |
| [`auth-app`](auth-app.md) | login exists and you can get accounts | accounts → auth surface → app map → two-principal work |
| [`huge-estate`](huge-estate.md) | hundreds or thousands of live hosts | cluster, pick representatives, never test N hosts |
| [`static-site`](static-site.md) | pure static, CDN-fronted, nothing dynamic | three cheap checks, then **triage it out and say so** |
| [`stale-return`](stale-return.md) | coming back to a target after weeks | what changed, what expired, what is still true |

`static-site` earns its place by ending in "drop this." A flow that tells you where **not** to spend
the afternoon is worth as much as one that finds work — most of a wildcard estate is not worth an
afternoon, and the counts never say so.

---

## Which flow applies — suggestion

```
tools/suggest-flows.py targets/<t>
```

It computes the situations it can prove from the brain and **names the ones it cannot**, with the
evidence that would settle each. It never guesses a situation from prose.

| situation | evidence | computable |
|---|---|---|
| `huge-estate` | live-host count | yes |
| `no-signup` | usable principals in `accounts.md` | yes |
| `stale-return` | `index.md` last-updated age | yes |
| unranked surface | `attack-surface.md` row count | yes |
| ranked-but-untested | ranked rows vs `tested.md` rows | yes |
| missing input | data-file state (`missing` ≠ `0` ≠ `prose`) | yes |
| `broken-calibration` | a recorded calibration result | only if one was recorded |
| `dead-end-host` · `spa-frontend` · `api-surface` · `static-site` | per-host response shape | **no — you must look** |

The last row is the honest part. Those four need someone to read a response, and the brain stores
prose there, not structure. The tool says so rather than inventing a verdict — a suggested flow you
cannot trace to evidence is worse than no suggestion.

## Writing a new flow

Keep it short. A flow is a decision, not a playbook: **Situation · Preconditions · Steps ·
Aborts · Cost · Output · Exit**, and every step points at an existing `skills/<slug>.md` or
`playbooks/workflows/*.md`. If a step needs procedure that doesn't exist yet, the procedure belongs
in a skill file, not in the flow. Flows that start explaining *how* have become playbooks, and then
there are two copies of the method to keep in sync.
