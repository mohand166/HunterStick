# Methodology — working reference

> Format of every line: **skill** — run it when you need X → it outputs Y → use Y on Z.
> Every skill in the library appears here; `tools/preflight.py <t> --list` prints the live list.
> Wide scope answers "where does this company hurt?"; single app answers "where does this
> application hurt?" — decided by what you named. Wide scope hands off to single app the moment
> the ranking names a winner; single app reaches back up only for a specific cross-host relation
> (reused endpoint, shared backend), never a full re-sweep.

## Wide scope — the estate

### A) Org mapping

1. **init-target** *(once, either mode)* — when nothing exists yet → outputs the brain scaffold
   (`targets/<t>/`, scope verbatim, no traffic) → everything below lives in it.
2. **organization-and-roots** — run first, when you named a company/program and need the actual
   perimeter → outputs `@roots` (root domains with ownership evidence; pivots include
   reverse-NS/reverse-DMARC, mobile app-store/AASA verified-domain bindings, WHOIS history,
   GitHub org/commit-email, M&A filings — the last two named with weaker confidence than the
   sourced pivots) → every enumeration below selects on it; guessing roots tests someone else's
   assets.
3. **cloud-asset-discovery** — when roots are known and you need what lives outside DNS →
   outputs `@cloud` (buckets, functions, metadata) → exposed-asset candidates and
   `cloud-misconfiguration` leads.
4. **repository-and-secret-recon** — when the org publishes code or secrets may be leaked →
   outputs `@repos` → valid-looking credentials and internal hostnames become `target.md` leads.

### B) Asset discovery

1. **subdomain-enumeration** (passive, runs by default: sources, CT, reverse-SNI cloud scans,
   Sonar, Validin, plus active cert-SAN and no-SNI-default-cert pulls off resolved IPs) — when a
   root exists and no verified host list does → outputs `@hosts.all`, wildcard-verified, the
   naming grammar and its exceptions, and a persisted target-derived wordlist (`@wordlists`) →
   feeds `dns-analysis` and liveness work; grammar exceptions go straight to leads.
2. **subdomain-enumeration** (gated: permutation at scale, VHost Host-header fuzzing) — when
   passive sources are exhausted and the naming grammar gives you something to guess → outputs
   new candidates, re-verified independently (permutation output is wildcard-echo-prone) →
   merges into `@hosts.all`; **this only runs if you name the technique or a flow already
   authorised it — a bare "enumerate subdomains" ask stops at the offer, not the traffic.**
   Estimate the payload budget before scaling either technique.
3. **dns-analysis** — when names exist and records are unexamined → outputs `@net.dns` +
   `@net.ips` + dangling-CNAME/dangling-NS candidates, Empty-Non-Terminal recursion targets,
   DNSSEC zone-walk exposure, `HTTPS`/`SVCB` origin-IP hints, and DKIM-selector findings →
   dangling names feed item 4; IPs feed item 5; a positive ENT feeds back into item 2's wordlist,
   scoped to that parent.
4. **subdomain-takeover** — when DNS left a dangling record pointing at an unset service →
   outputs adjudicated takeover candidates (proof needs a controlled registration — your call,
   not auto-run) → confirmed takeover is a finding with its `fix_locus`.
5. **asn-and-ip-discovery** — when you suspect owned IP space → outputs `@net.asn` (BGP-
   announced via bgp.tools/RIPEstat vs RDAP-registered kept apart — `asnmap` is not a live-BGP
   source, treat it as enriched RDAP; reverse-IP via Shodan's `hostnames` field substitutes for
   paid SecurityTrails) → new ranges re-enter subdomain enumeration.
6. **live-host-validation** — when names exist and liveness is unknown → outputs
   `@hosts.resolved` → saves the probing stage from dead names.
7. **http-probing** — when resolving hosts exist → outputs `@hosts.live` (status, title, tech,
   plus a default `gowitness` screenshot pass — body-hash clustering alone misses SPA-shell
   collisions) → **attack-surface.md rows start here**; also the monitoring baseline.
8. **port-and-service-discovery** — when non-HTTP services may exist → outputs `@net.ports` →
   unknown services become `target.md` leads, not guesses.

### C) Narrow to a shortlist

1. **technology-fingerprinting** — when live hosts exist and the stack is unknown → outputs
   `@tech` per host → decides which vuln classes are worth time; feeds `component-inventory`.
2. **component-inventory** — when the stack is known and versions aren't → outputs
   `@components` (`exact`/`bounded`/`unknown`) → run `tools/techwatch.py targets/<t>` on it.
3. **host-correlation-and-clustering** — when many live hosts and relations unknown → outputs
   `@clusters` → hosts sharing a backend become one row; feeds prioritization and chain
   analysis.
4. **derive-properties** — when endpoints/hosts exist with no properties → outputs `@surface`
   rows with properties → nothing selects a vuln class without this; it re-reads artifacts you
   already paid for.
5. **attack-surface-prioritization** — when properties exist and nothing is ranked → outputs
   the ranked shortlist → **pick a winner and switch to single-app mode**; also enable
   **monitoring-and-diff** on the estate before you go deep.
6. **recon-summary-and-handoff** — when the estate pass is done or you're handing off / coming
   back after a gap → outputs a coherent architecture summary and resumable state in
   `target.md`/`index.md` → the next session (or model) starts oriented instead of re-reading.

## Single app — one application

### A) Surface reading

1. **analyse-request** — when you're holding a Burp/HAR request and want to know what you're
   looking at → outputs the request's properties and where it fits the recorded surface →
   feeds `derive-properties` and endpoint rows; the fastest possible entry into a target.
2. **technology-fingerprinting** (on this host) — before anything else → outputs the stack →
   picks the vuln classes worth your time and the `component-hunt` catalog that applies.
3. **tech-analysis** — when the stack is named and you want what it *changes* → outputs
   target-specific hypotheses via the tech playbook → records hypotheses, never tests; feeds
   `component-hunt` and class selection.
4. **content-discovery** — when you need paths the UI doesn't link → outputs `@content` hits →
   new endpoints enter the inventory → `derive-properties`. Wordlist from this target's
   vocabulary; calibrate the soft-404 first or every 200 lies.
5. **javascript-analysis** — when first-party bundles exist (highest-yield read in web recon) →
   outputs the route delta (declared-but-unreachable routes), `@endpoints`, `@params`, gadget
   inventory, triaged secrets → route delta is the authz worklist; params feed item 8;
   registry-404 package ids feed `repository-and-secret-recon`.
6. **api-discovery** — when a spec/OpenAPI/GraphQL schema is suspected → outputs `@endpoints`
   with methods, auth and body shapes → contracts beat extraction; feeds `derive-properties`.
7. **url-collection** — for historical/archived URLs of this host → outputs `@urls` → old
   bundles and dead routes re-enter JS analysis and content discovery.
8. **parameter-discovery** — when endpoints are known but accepted parameters aren't → outputs
   `@params` → the wordlist content-discovery should have used; body shapes are the
   mass-assignment worklist.
9. **recover-js-chunks** (`tools/chunks.py`) — when webpack/Next code-splitting is present →
   recovers lazy chunks → re-run `javascript-analysis` on them.

### B) Understanding

1. **application-mapping** — when the app matters enough to test deeply → outputs `@app.current`
   (features, roles, trust boundaries, state machines) → the context every logic class reads.
2. **authentication-surface-mapping** — when any principal or signup exists → outputs the auth
   flow map → feeds `login` / `mfa` / `password-reset` / `oauth-oidc` hunts; account needs go to
   `accounts.md`.
3. **browser-exploration** — when the app is authenticated or JS-driven → outputs the rendered
   route delta, the authenticated fetch set, storage/CSP posture, postMessage/DOM evidence →
   captures import via `import-http.py` → endpoints; DOM findings go to `vuln-hunt`.
4. **user-flows.md** — record journeys as you find them (steps, principals, objects, states) →
   the source of state-machine / workflow / payment / race variants.
5. **cross-host-endpoint-reuse** — when the same API shows up on several hosts → outputs
   confirmed reuse plus the per-host control differences → the control that stops applying on
   the second host is the authz finding candidate.

### C) Hunt

1. **derive-properties** (this app's endpoints) — before any testing → outputs propertied rows
   → properties select the class; skipping this is the classic silent failure.
2. **attack-surface-prioritization** + `tools/coverage.py targets/<t>` — outputs tonight's
   entrypoint and the untested cells → hunt the top row, not what you happened to notice.
3. **vuln-hunt** (one entrypoint + one class) — `"Test IDOR on /api/orders using the recorded
   accounts"` → outputs `tested.md` rows (entrypoint × class × principal × variant) + findings
   with artifacts → negatives stop re-chasing; `fix_locus` dedups.
4. **component-hunt** — when the stack has known misconfigs (actuator, wp-json, `.env`) →
   outputs per-check coverage + hits as hypotheses with the class named → confirm via
   `vuln-hunt`.
5. **techwatch** (`tools/techwatch.py targets/<t>`) → n-day sweep — when a CVE drops or the
   runbook runs it → outputs `tech-watch.md` + a proposed cohort → pilot one host yourself,
   read it, then scale; one deployment = one finding.
6. **Chains** (`kb.py chains`, `target-graph.py --chains`) — when low-severity primitives
   accumulate → outputs PARTIAL/READY chain patterns naming the missing half → validating a
   chain is your explicit call.

## Continuous — both modes

1. **monitoring-and-diff** — enable on targets you keep working → outputs deltas (new names,
   status/tech flips, JS changes; CT-log streaming is a between-interval option, not a
   replacement dimension) → on each delta: re-derive properties on the affected slice only, then
   re-rank.
2. **Notifications** — `notify.channels` in `config.json` + `tools/notify.py test` → deltas,
   quarantines, failures, advisories and the runbook digest reach you.
3. **Runbook** — write `targets/<t>/runbook.md`, validate with `tools/runbook.py targets/<t>
   --check`, run with *"run the runbook on acme"* → one brief: what changed, top-3 entrypoints,
   the hunts worth starting.
4. **Lessons** — promote generalizable lessons into `lessons.md` (≤50 rows, origin cited) →
   sharper ranking on every target.
5. **Housekeeping** — after VPS work: `tools/progress.py targets/<t>`; periodically:
   *"reassess and patterns on acme"*; before trusting any surface: ask its age.

## Routers & meta — when you don't know which skill

1. **run-flow** — when you recognize a *situation* instead of a task ("this host 404s
   everything", "no signup", "it's a JS shell", "3,918 hosts", "everything returns 200") →
   `tools/suggest-flows.py <t> --why` recommends one situation flow, *"run the X flow"* runs
   it as one authorized bundle.
2. **compose-task** — when your ask matches no single skill ("extract JS from the 404s, pull
   params, test them") → decomposes into existing skills + minimal glue, one authorized
   objective.
3. **ground-a-playbook** — when your own reports/research should improve one skill or playbook
   → re-evaluates exactly that file → KEEP or IMPROVE; the corpus never loads during a hunt.

## Always

- Evidence or it didn't happen: no finding without a stored request/response.
- Depth = variants resolved or parked, never time spent (`tools/coverage.py` computes it).
- Dedup by `fix_locus`; one shared deployment is one finding.
- Two principals before any authz conclusion; blocked ≠ negative.
- State the age and the bounds of everything you rely on.
- A default sweep is a floor, not the finish: recon skills run their own non-default techniques
  (active cert pulls, DNSSEC checks, reverse-IP, mobile-AASA pivots, …) automatically where the
  traffic cost is ordinary. The one exception is anything that fuzzes or brute-forces the target
  — VHost, permutation at scale, content-discovery — which is only *offered*, never run, until
  you name the technique or authorise a flow that bundles it. A bare "enumerate subdomains" ask
  will not fuzz anything on its own; say so explicitly if that's what you want.
