# Target Knowledge-Base Schema

Every target is a self-contained knowledge base with **fixed, conventional paths** so
any skill always knows where each kind of data lives. To start a new target, say
**"Initialize a new target XYZ"** — `skills/setup/init-target.md` copies
`targets/_template/` to `targets/<slug>/`, seeds it, and asserts every path below exists.

The rule that makes the "memory" work: **paths are conventions, not guesses.** When the
human says "generate a wordlist from target data" or "test SQLi on this URL", you know
exactly which files hold the URLs, params, techs, and architecture — because they are
always in the same place.

---

## Local layout (the brain — curated, versionable)

```
targets/<target>/
  index.md            ← MANIFEST. Read first, every session. Last activity, pointers
                         to every file below, live counts, last-updated, VPS location.
  target.md           ← PROFILE / brain: org, architecture, backend techs, auth model,
                         key observations. Prose you reason over. (FACT/HYPOTHESIS tagged)
  scope.md            ← WHAT THE HUNTER SAID they are testing, verbatim, plus a derived
                        `## Mechanical allowlist` (### In scope / ### Out of scope) that the
                        INGEST tools (import-http/monitor/sweep) match against via scopelib.py
                        to keep outside data out. Context and routing, plus standing constraints
                        the hunter set — not an execution veto; run.py/preflight ignore it.
                        Verbatim wins if the allowlist ever disagrees.
  scope-evidence.md   ← provenance / exact policy snapshot when one was captured.
  accounts.md         ← test accounts, roles, and how to authenticate.

  recon/              ← NORMALIZED, curated recon data (small, greppable). Heavy raw
                        output lives on the VPS; these are the clean extracts.
    subdomains.txt      one hostname per line (deduped, sorted)
    live-hosts.txt      one live host/URL per line (scheme://host:port)
    ips-asn.md          IPs, CIDRs, ASNs, cloud ownership  (table, see below)
    ips.txt             DEDUPLICATED, scope-authorised IP scan list — one row per IP,
                        never per hostname. The scan unit for 06/07.
    dns.md              notable DNS records, CNAME chains, takeover candidates
    ports.md            open ports/services per host        (table)
    root-domains.md     apexes + ownership evidence         (table)
    technologies.md     per-host tech fingerprint           (table)
    components.md       versioned open-source inventory     (table)
    urls.txt            master list of every discovered URL (deduped)
    endpoints.md        notable/interesting endpoints        (table, see below)
    parameters.txt      every discovered parameter name (deduped)
    js-findings.md      secrets, routes, endpoints pulled from JS (table)
    content/            dir/content-discovery hits per host (one file per host)
    wordlists/          target-specific wordlists generated from the data above
    cloud.md            buckets, blobs, cloud assets
    repos.md            code repos, leaked secrets, org GitHub findings

  applications/<host[-port]>/  ← per-app deep map (created during app-mapping)
    map.md              features, user roles, trust boundaries, auth flow
    endpoints.md        app-specific endpoint inventory
    notes.md            working notes / observations

  attack-surface.md     ← RANKED inventory. The recon→testing bridge. Scored (see model).
  hypotheses.md         ← testing backlog: id · target · class · rationale · status
  tested.md             ← dedup log: what was tested, when, result, fix-locus key
  progress.md           ← GENERATED hunter view: scope-wide runs + per-host/IP commands/tests
  runbook.md            ← the hunter's saved standing order (optional; edited only by the hunter)
  tech-watch.md         ← GENERATED advisory-vs-stack report from tools/techwatch.py
  user-flows.md         ← journeys through the app: steps, principals, objects and state changes
  clusters.md           ← backend clusters (host-correlation-and-clustering); attack-surface.md links to these
  runs.tsv              ← APPEND-ONLY record of BOUNDED runs: run_id · phase · selector ·
                          sources · status · limitations · model. A phase is never globally done;
                          a run completes for its selector. `model` stamps which tier ran it
                          (cheap recon volume vs strong-model judgment) — audit metadata, never
                          a gate. `tools/kb.py run|runs`.
  observations.tsv      ← APPEND-ONLY ledger of everything the target ever showed you:
                          date · subject · predicate · object · confidence · source · evidence.
                          Facts a phase learns INCIDENTALLY go here, not into prose. Never
                          overwritten — a later observation supersedes an earlier one
                          visibly. `tools/kb.py reassess|chains` reads it.

  investigations/<lead>/ ← deep-dive working notes + artifacts for one lead
    chain.md              multi-entrypoint/class chain, approval gates, evidence links
  findings/
    draft/               work-in-progress writeups
    confirmed/           evidenced, reproducible findings (with artifacts)
    rejected/            disproven — kept so you don't re-chase them
  raw/                   ← pointers to / small copies of raw evidence. Big raw files
                           stay on the VPS; this holds request/response artifacts that
                           back FACTs and findings.
```

### Exact application context

The target brain is engagement-wide, but deep application knowledge is isolated by exact host and
optional port. Run `tools/app-context.py resolve targets/<t> <url-or-host>` before a one-app task;
it reads the identity from `map.md`, ignores `_host-template`, refuses to choose between ambiguous
port variants, and prints only that app's three files. `tools/brief.py <t> --host <subject>` and
`--resume --host` use the same resolver.

`@app.current` is therefore a dynamic role, not the whole `applications/` directory. Preflight
resolves it only when `--host` supplies the invocation subject. An existing sibling application or
the template cannot make it present. When a map is needed and absent,
`tools/app-context.py ensure targets/<t> <subject>` creates its scaffold atomically; the mapping
skill then fills it with evidence.

### The VPS side — what lives there, and why the split is where it is

```
~/targets/<target>/          (on the VPS — see config.json vps.workdir)
  raw/<phase>/               bulk tool output: js, urls, dns, fingerprint, subdomains, …
  jobs/<name>.sh             the phase scripts you run
  logs/<name>.log            their tee'd output
  loot/                      artifacts pulled during testing
```

**Nothing a job produces is written to the VPS home directory.** A script or log dropped in `~`
loses the one thing that makes it useful later — which engagement it belongs to
(`vps-execution.md` §tmux pattern creates them under `$T/jobs` and `$T/logs`).

**The split rule: local holds what you need to decide *what to do next*; the VPS holds what you
need to *re-derive* it.** Curated extracts (`recon/*.md`) are small and are read by attack-surface-prioritization,
`coverage.py` and `tools/brainlib.py` — they must be local. Bulk output (hundreds of MB of JS,
URLs, DNS) is re-derivable by re-running the phase — it stays on the VPS.

`tools/vps-sync.py status <target-dir>` enforces this mechanically — it names every local file
that breaks the rule instead of leaving it to discipline. `pull` and `push` move files across the
boundary in the allowed direction only; `demote` retires an oversized local list to a pointer.

The test that decides any ambiguous file: **if the VPS died tonight, could you still reason about
this target tomorrow?** The VPS is disposable infrastructure; the brain is not. A `.txt` list large
enough that you would never read it (`urls.txt` at 52 MB) fails that test in the other direction —
keep it on the VPS and record its **count plus a pointer** in `index.md` instead.

A fresh target ships the `.md` files as headed stubs (column order already correct) but **not**
the `.txt` list files — those appear only when the phase that produces them runs. That is
deliberate: a *missing* input must fail a phase's preflight loudly, whereas an empty placeholder
lets it "succeed" with zero results (`vps-execution.md` §Command robustness).

**Format convention:**
- Flat `.txt` (one item per line, sorted, deduped) for lists tools & wordlist-gen consume.
- Markdown tables for anything you *reason* over (schemas below).
- Prose markdown for analysis (`target.md`, app `notes.md`).

**Account readiness:** the `accounts.md` table uses
`label | role | username / email | credential_ref | tenant/org | status | notes`. Only
`status = ready` with a resolvable credential reference counts as a principal. A planned username,
role, or placeholder never opens the two-principal gate.

---

## Input roles — the one place a phase input is named

**This table is the authority.** A recon phase's `## Inputs` section declares a **role**
(`@hosts.resolved`), never a path (`recon/resolved.txt`). `tools/roles.py` resolves the role
through this table, and `tools/preflight.py` gates the run on what it resolves to.

Why the indirection exists, in one sentence: **a path written into 23 playbooks rots in 23 places.**
It happened here on every axis at once —

* Phase `18` declared bare `technologies.md`, `ips-asn.md`, `dns.md`, `js-findings.md` and
  `endpoints.md` with the `recon/` prefix missing. Preflight looked for
  `targets/<t>/technologies.md`, correctly reported `missing`, and **blocked the phase** — while
  every one of those files existed under `recon/`. The phase was un-runnable from the day it was
  written, for a typo.
* Phase `07` declared `recon/subdomains.txt` while its own body consumed `recon/resolved.txt`
  and `recon/ips.txt`. The gate checked a file the run never opened.
* The renumbering left **all seven** scope-filter temp paths carrying their old phase number
  (`07` said `-08-`, `03` said `-04-`, `09` said `-10-`).

A role has none of those failure modes: rename an artifact and you edit **one row here**.

| role | path (relative to `targets/<t>/`) | produced by |
|---|---|---|
| `@hunter.request` | `<supplied in the prompt>` | the hunter |
| `@hunter.task` | `<supplied in the prompt>` | the hunter |
| `@hunter.entrypoint` | `<supplied in the prompt>` | the hunter |
| `@hunter.class` | `<supplied in the prompt>` | the hunter |
| `@hunter.technology` | `<supplied in the prompt>` | the hunter |
| `@hunter.flow` | `<supplied in the prompt>` | the hunter |
| `@hunter.host` | `<supplied in the prompt>` | the hunter |
| `@hunter.ips` | `<supplied in the prompt>` | the hunter — one or more IPs, a CIDR, or a named group given directly in the request; takes priority over any inferred candidate set |
| `@scope` | `scope.md` | `init-target` |
| `@target` | `target.md` | `organization-and-roots` |
| `@accounts` | `accounts.md` | `init-target` (filled by the hunter) |
| `@hosts.all` | `recon/subdomains.txt` | `subdomain-enumeration` |
| `@hosts.resolved` | `recon/resolved.txt` | `live-host-validation` |
| `@hosts.live` | `recon/live-hosts.txt` | `http-probing` |
| `@net.dns` | `recon/dns.md` | `dns-analysis` |
| `@net.ips` | `recon/ips.txt` | `dns-analysis` |
| `@net.asn` | `recon/ips-asn.md` | `asn-and-ip-discovery` |
| `@net.ports` | `recon/ports.md` | `port-and-service-discovery` |
| `@roots` | `recon/root-domains.md` | `organization-and-roots` |
| `@tech` | `recon/technologies.md` | `technology-fingerprinting` |
| `@components` | `recon/components.md` | `component-inventory` |
| `@urls` | `recon/urls.txt` | `url-collection` |
| `@endpoints` | `recon/endpoints.md` | `javascript-analysis` / `api-discovery` / `application-mapping` |
| `@params` | `recon/parameters.txt` | `javascript-analysis` / `parameter-discovery` |
| `@js` | `recon/js-findings.md` | `javascript-analysis` |
| `@content` | `recon/content/` | `content-discovery` |
| `@wordlists` | `recon/wordlists/` | `content-discovery` / `parameter-discovery` / `subdomain-enumeration` (target-derived Host-header/vhost list) |
| `@cloud` | `recon/cloud.md` | `cloud-asset-discovery` |
| `@repos` | `recon/repos.md` | `repository-and-secret-recon` |
| `@app.current` | `<dynamic:application>` | `application-mapping` |
| `@clusters` | `clusters.md` | `host-correlation-and-clustering` |
| `@surface` | `attack-surface.md` | `derive-properties` |
| `@hypotheses` | `hypotheses.md` | `generate-hypotheses` |
| `@tested` | `tested.md` | `vuln-hunt` |
| `@raw.http` | `raw/http/` | `http-probing` |
| `@raw.js` | `raw/js/` | `javascript-analysis` |
| `@raw.snapshots` | `raw/snapshots/` | `monitoring-and-diff` |

### `@hunter.*` — the subject, which does not live in a file

Some skills act on something the hunter hands you in the prompt: a pasted request, an entrypoint,
a vuln class, a technology name. Those are **required inputs** — the skill is meaningless without
them — but no file check can find them, and a skill with no `## Inputs` at all is worse: it reports
*ready* whether or not the hunter supplied a subject.

So they are declared like any other role, and `preflight.py` reports them as **supplied** rather
than looking for a file. Three consequences worth stating:

* A `@hunter.*` role is a **contract with the invocation**, not with the brain. If it wasn't in the
  prompt, ask for it — that is the same single stopping rule, applied to the subject.
* It makes the alternative honest. `application-mapping` needs *an application*, which can come
  from the hunter (`@hunter.host`) **or** from recon (`@hosts.live`). Declaring only the recon
  artifact turned a skill that runs on a hunter-named host into one that demanded the whole
  pipeline first.
* It never resolves to a path, so nothing can accidentally read it as a file.

### How to write an `## Inputs` bullet

Role first, then who produces it **by slug — never by number**, then what it is for. Hedge a
non-gating input with `optional` or `if …`; `preflight.py` reads the hedge and downgrades it from
blocker to advisory.

```markdown
## Inputs
- `@hosts.resolved` (from `live-host-validation`) — every name that resolves, the probe set.
- `@net.ips` (from `dns-analysis`) — deduplicated, scope-authorised IPs. A host with no DNS
  name survives only here.
- `@net.ports` (optional, from `port-and-service-discovery`) — probe the non-standard HTTP
  ports it found, not just 80/443.
- `@scope` — confirm the hosts are in-scope before probing.
- VPS connection from gitignored `config.json`; remote working directory from `index.md`.
```

`config.json` and `index.md` stay literal on purpose: they are machine-level and manifest files,
not target artifacts, and `preflight.py` deliberately ignores them.

### Resolving a role in a command

Never hand-expand a role into a path in a shell line — that reintroduces exactly the static
name this table removes. Ask for it:

```sh
tools/roles.py path targets/<t> @hosts.resolved     # -> targets/<t>/recon/resolved.txt
tools/roles.py --list                               # every role and what it resolves to
```

Phase-scoped temp files derive their name from the phase **slug**, never a number, so a
renumbering cannot leave a stale `-08-` behind:

```sh
PHASE=http-probing
SCOPED=/tmp/<t>-$PHASE-scoped.txt
tools/scope-filter.py targets/<t> "$(tools/roles.py path targets/<t> @hosts.resolved)" \
    --out "$SCOPED"          # exits 1 if nothing survives
```

An unknown role is a **loud failure**, never a skipped input: `roles.py` exits 2 and names it,
and `preflight.py` reports it as a blocker. A typo'd role must never read as "nothing to check".

---

## File schemas (the tables)

Keep these column orders stable — later skills parse them.

**`recon/ips-asn.md`**
```
| ip | cidr | asn | org | cloud | hosts | source |
```

**`recon/ports.md`**
```
| host | ip | port | proto | service | version | notes | source |
```

**`recon/technologies.md`**
```
| host | server | framework | language | cdn/waf | cms | notable_libs | source |
```

**`recon/root-domains.md`** — organization-and-roots. One apex per row, each with its own evidence.
```
| apex | ownership | scope_status | evidence (source + date) | proves | confidence | notes |
```
`ownership` is `owned`/`divested`/`third-party`/`unresolved`; `scope_status` is
`in-scope`/`out-of-scope`/`not-listed`/`unknown`. **They are independent** — a domain can be owned
and out of scope. `evidence` must carry a date.

**`recon/components.md`** — component-inventory. The versioned inventory `kb.py cohort` selects on;
`notable_libs` above is a fingerprint and carries no version, which is why this file exists.
```
| host | component | version | precision | reachable | evidence | confidence | source |
```
`precision` is `exact` (a manifest or version constant) · `bounded` (narrowed by behaviour) ·
`unknown` (present, version not established). **`unknown` rows are excluded from a version-filtered
cohort and reported as excluded** — never guessed, never silently dropped.

**`recon/endpoints.md`**
```
| url | method | params | auth_required | content_type | tech/app | interesting_why | source |
```

**`recon/js-findings.md`**
```
| js_url | finding_type | value | severity_hint | verified | source |
```
(`finding_type` = api-endpoint | secret | token | internal-host | cloud-key | comment | route)

Secret-shaped rows are candidates, not vulnerabilities. `value` contains only the matcher kind,
safe field names and match count; never the value, its context, or a value-derived hash.
`severity_hint` stays `untriaged (scanner:<level>)` and `verified` stays `no` until the skill's
triage loop resolves them. Endpoint/route rows are the deterministic handoff to
`derive-properties`, which alone assigns supported properties and writes attack-surface rows.

### Vulnerability evidence filenames

Every vulnerability test stores one local evidence bundle at:

```text
raw/<run-id>-<class>-<case>/
  evidence.md             mandatory manifest: entrypoint, principal, variant, oracle,
                          redactions, command-record pointer, present files
  control-request.txt     normal/role-correct request, when the channel is HTTP/RPC
  control-response.txt    its real response
  test-request.txt        one-variable test request
  test-response.txt       its real response
  browser-evidence.md     optional DOM/navigation/message proof
  oob-callback.txt        optional unique callback log
  transport-evidence.txt  optional gRPC trailer or WebSocket-frame proof
```

`<case>` is a short entrypoint/variant slug; it prevents two variants in one run overwriting each
other. `evidence.md` always exists. Channel-specific files exist only when real evidence exists — a
browser-only test does not create empty HTTP placeholders. Credentials are replaced with
`<accounts.md:label>`. `tested.md.artifact_ptr` points to `evidence.md`, which in turn names the
individual files and the matching `logs/exec/<stamp>-<skill>-<tool>.json` record.

**`attack-surface.md`** (ranked; scoring model below) — one row per **candidate
`(entrypoint × vuln_class)`**, not per generic asset (derive-properties). Group rows by entrypoint so
its full class coverage is visible.
```
| rank | entrypoint (host/endpoint/param/flow) | vuln_class | principals | variants | properties | exposure | sensitivity | tech_risk | dynamism | dup_likelihood | linkage | score | why (source→sink) |

`variants` is what makes the plan resolvable: coverage keys on
**`entrypoint × class × principal × variant`**, and a variant is only ever expected if the plan
named it. Leave it empty and the cell resolves on the first probe of any kind — which is how a
class gets marked covered after one input was tried.
```

**`hypotheses.md`**
```
| id | target (url/func) | vuln_class | rationale (why plausible) | status | evidence_ptr |
```
`status` = open | testing | confirmed | rejected. `id` = H-001, H-002, …

**`tested.md`** — the coverage ledger; one row per **(entrypoint × vuln_class × principal)**
cell so it can represent what the master loop promises (per-class, per-principal coverage).
```
| date | run_id | entrypoint (url/param/func) | variant | vuln_class | principal (account/role/unauth) | method (what you did) | result | coverage | fix_locus | artifact_ptr |
```
`principals` (on `attack-surface.md`) = the account labels/roles or `unauth` required to resolve
that candidate. These are the expected cells that `tools/coverage.py` subtracts from `tested.md`;
without them, one account could falsely clear a two-account test.

`properties` (on `attack-surface.md`) = observed surface facts from the **closed** vocabulary in
`playbooks/system/class-signals.md`. They are what makes applicability computable rather than
recalled: `tools/coverage.py <target-dir>` maps properties → classes, subtracts `tested.md`, and
marks with `*` any class the properties imply that `attack-surface.md` never proposed. A free-text
property matches no class and silently contributes nothing, so keep to the vocabulary or extend it
in `class-signals.md` first.

`variant` = **what exactly you reached** — the input location, content-type, handler version, or
for authorization the *relationship* (`b→a's object`, `cross-tenant`). A row without one claims
the whole class on that entrypoint. The coverage cell is
**`entrypoint × class × principal × variant`**, and `attack-surface.md` declares the variants a
cell needs — coverage cannot invent ones nobody planned.

`fix_locus` = the distinct code/config location a fix would touch. **The dedup key for
*findings*, not for coverage** — before a bug is confirmed the real fix locus is a hypothesis, so
`coverage.py` deliberately does not key on it.
`result` = not-vuln | vuln | inconclusive | out-of-scope | not-applicable.
`coverage` = tested | partial | blocked | deferred
(e.g. needs-account) — an entrypoint is "done" only when every required
`(entrypoint × class × principal × variant)` cell has a resolved result. `principal` = which
account/role/unauth the probe ran as. `run_id` = tool/run identifier.

**`findings/confirmed/<slug>.md`** — one evidenced finding. Minimum shape:

```markdown
# <title: the flaw, not the payload>
class: <playbooks/vulns/…>  ·  principal: <account/role/unauth>  ·  date: <YYYY-MM-DD>
fix_locus: <the distinct code/config location a fix would touch — the dedup key>

## Impact
<what an attacker gains. An argument built on FACTs, never an assertion.>

## Reproduce
<the request, and its control request beside it. Burp Repeater or copy-pasteable curl,
reproducible in one action from a clean session. Credentials replaced by a placeholder.>

## Evidence
<artifact_ptr into raw/ — request AND response. No artifact → this is not a finding.>
```

Everything in it traces to a stored artifact. Severity is argued from impact. Program reward
information may help the human allocate time, but it is never evidence about exploitability.

---

## Attack-surface scoring model (used by attack-surface-prioritization)

Adapted from enterprise ASM regression models for bug-bounty use. Score each asset
0–3 on six signals; rank highest total first. These are **prioritization heuristics,
not proven predictors** — use judgment, don't worship the number.

| Signal | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| **Exposure / reachability** | internal only | auth-gated | public, static | public, interactive |
| **Sensitivity** | marketing/static | general app | user data / PII | auth, payments, admin, tenant boundary |
| **Tech risk & likely audit gap** | hardened, mainstream | mainstream | custom / older stack | custom auth, obscure/legacy, self-built |
| **Dynamism** | no params | few GET params | many params / forms | state-changing, file upload, complex workflow |
| **Dup-likelihood (inverted)** | obvious surface on a popular, mature program | popular / well-trodden | moderately explored | obscure asset / newly-added / acquisition |
| **Linkage / chain potential** | isolated, no connections | in a cluster but no clear leverage | shares backend/auth with a sensitive asset | pivot/enabler: leaks that unlock another asset, SSRF/redirect stepping-stone, shared tenant/auth with crown jewels |

Higher **dup-likelihood** score = *less* likely already-reported (newly discovered,
acquired-company, obscure). **Linkage** is the *full-picture* signal: an asset weak on
its own can be valuable for what it connects to — its cluster peers (host-correlation-and-clustering), endpoints
reused across hosts (cross-host-endpoint-reuse), a JS leak pointing elsewhere, or a chain/pivot role. Score
it from the whole map, not the row in isolation. Feed the ranked output into `hypotheses.md`.

---

## Manifest (`index.md`) — the active loop

`index.md` is not a static file. Every skill updates it. It must always answer, at a
glance: what target is this, what has been decided, what is blocking, when it was last
updated, and where the VPS working dir is. See `targets/_template/index.md` for the exact shape.

It holds **decisions and state, not counts.** A count copied into a manifest goes stale while
still reading as current, so ask the files instead: `wc -l` for a list, `tools/coverage.py
<target-dir>` for the surface, `tools/kb.py runs <target>` for what has actually been run.
**`missing` and `0` are different states** and must stay distinguishable: a missing file is a
preflight failure for the skill that needs it, an empty one is a real (if disappointing) result.
`tools/brainlib.py` computes both from the files rather than repeating a claim — the live console renders the distinction.

`progress.md` is also derived, but it is deliberately checked in with each brain so the hunter can
open one readable file. `tools/progress.py <target-dir>` regenerates it from the authoritative
`runs.tsv`, `tested.md`, and pulled `logs/exec/*.json`. The first table describes work over the
scope; each exact host/IP then gets its own table with the skill/class, tool or activity, redacted
command/options or manual method, input/wordlist hashes, outcome and evidence. A file-based or
set-based command whose members cannot be proved remains in the multi-asset/unresolved table; it
must never be expanded into guessed per-host coverage.

`<target>` is whichever target the human named. `targets/TARGETS.md` is the registry of what
exists — it is not a pointer, and nothing "switches" to a target.
