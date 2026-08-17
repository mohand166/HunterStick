# Changelog

This file records user-visible HunterStick changes by the date they were added. Entries are newest
first. Dates use `YYYY-MM-DD`; they describe repository changes, not target activity or releases.

## 2026-08-15

### Added

- **Exact per-application context.** Added `tools/app-context.py` and the shared `tools/applib.py`
  resolver. A URL, hostname, host:port, IPv4 address, or IPv6 address now selects one application
  brain under `applications/<host[-port]>/`. `ensure` creates the scaffold atomically.
- **Application-aware loading and preflight.** Added the dynamic `@app.current` role and `--host`
  support to `brief.py`, resume, `preflight.py`, and `roles.py`. One-app work loads only the
  selected app's `map.md`, `endpoints.md`, and `notes.md`; templates and sibling applications no
  longer satisfy the input.
- **Per-target progress view.** Added generated `progress.md` files and `tools/progress.py`. The
  view joins `runs.tsv`, `tested.md`, and pulled `logs/exec/*.json` into scope-wide and per-host/IP
  tables with redacted commands, options, input/wordlist hashes, results, and evidence pointers.
  Commands whose exact target cannot be proven remain under multi-asset/unresolved instead of
  being attributed to every host.
- **Progress lifecycle integration.** New targets include `progress.md`; closing a run and pulling
  VPS execution records regenerate it automatically, while failures report the manual recovery
  command without losing the underlying run or sync result.
- **Optional event notifications.** Added `tools/notify.py` and configurable webhook channels for
  monitor deltas, quarantined monitor runs, command completion/failure events, tech-watch
  matches, and the runbook digest. Delivery is best-effort, failed events use a bounded local
  spool, webhook URLs are treated as credentials, and strict mode redacts the target name sent to
  third parties. Channels live under `notify.channels` (any HTTP-POST webhook works; per-channel
  payload templates optional) and are verified with `tools/notify.py test`; the monitor cron job
  receives a standalone channel copy at `enable` time, written under the configured `vps.codedir`.
- **Browser-driven exploration.** Added the `browser-exploration` skill: authenticated crawling
  and interactive validation in a real browser via the configured Chrome/Burp MCP. Split into
  OBSERVE (default — rendered route deltas, the runtime XHR/fetch set, token and session
  placement, CSP and framing posture) and ACT (one-variable validation of named client-side
  hypotheses: postMessage senders, canary-traced DOM XSS source→sink). Feeds the endpoint and
  JS-artifact roles and hands confirmed paths to `vuln-hunt`.
- **Stack-specific active probing.** Added the `component-hunt` skill and a `## Checks` catalog
  to each of the five technology profiles (Spring Boot, WordPress, Laravel, Next.js, React).
  Each row is a probe contract — precondition, one read-only request, a discriminator that beats
  the status code, safety (presence-only rows are never downloaded or invoked), the class a hit
  becomes, and the fix locus. Version-gated CVEs deliberately stay with the n-day sweep;
  `tech/_shape.md` documents the catalog contract for future profiles.
- **Advisory watching against the recorded stack.** Added `tools/techwatch.py`: queries OSV and
  the CISA KEV feed against `recon/components.md`, writes `tech-watch.md` with a NEW-delta ledger
  (`logs/techwatch-seen.txt`), flags KEV entries, and lists unversioned and ecosystem-unmapped
  components instead of clearing them. Sends no traffic to the target and proposes a cohort
  sweep rather than running one; notifies on NEW matches.
- **Per-target runbook.** Added `targets/<t>/runbook.md` (the hunter's saved standing order,
  edited only by the hunter), `tools/runbook.py` (validates every step resolves and prints the
  ordered plan with live ready/blocked/condition state), and the `runbook` skill that executes
  the sequence as one authorized bundle ending in a single consolidated brief and one digest
  notification. The brief proposes hunts; it never starts them.
- **Cross-target lessons.** Added `lessons.example.md` (the live `lessons.md` is gitignored): a
  ≤50-row file of deliberately promoted hunter lessons with origin pointers, surfaced by
  `brief.py --resume` (with an over-cap warning) and read as advisory input by
  `attack-surface-prioritization`. Never written by a run; never resident in context.
- **Reverse-SNI passive source.** Subdomain enumeration now reads the published cloud-range
  SNI/certificate scans (kaeferjaeger) as an IP→certificate source for internal-CA and origin
  names CT logs cannot reach, with scope-boundary suffix matching (never substring grep),
  VPS-only bulk under the recorder, and dataset-name freshness recorded as a limitation.
- **Hunting methodology reference.** Added `METHODOLOGY.md` for the hunter: compact numbered
  lists organized by *want* — **wide scope** (org mapping, asset discovery including
  fuzzing/permutation/VHost, narrowing to a shortlist) and **single app** (surface reading
  including content discovery, JS/API/params, understanding, hunting) — every line in the form
  *run this skill when you need X → it outputs Y → use Y on Z*, plus continuous, routers-and-meta
  and always-rules sections. Every skill in the library is named so a hunter who wants X can
  find the skill that does it, and a new test enforces the file stays complete as skills are
  added.
- **Model-tier stamp on every run.** `runs.tsv` gains a `model` column: `kb.py run --model
  <tier>` (or config `runtime.model`, env `BBW_RUNTIME_MODEL`) records which model ran each
  unit, so the ledger, `progress.md`, and the dashboard's run history can answer *which tier
  found what* from real data — the measurement under cheap-model-for-volume /
  strong-model-for-judgment routing. Older brains migrate in place (header-only rewrite); an
  unstamped run reads as `—`, never blocks, and closing a run preserves its stamp.
- **Workspace dashboard SPA.** `tools/dashboard.py --all` now builds a root `dashboard.html`
  (gitignored): a sidebar lists every target with status chips (open runs, resume points,
  staleness, probes, surface), clicking one loads its dashboard into the main area with no
  reload (hash-routed, so refresh and back stay put). Each target view is restructured around
  what a hunter opens the page for — where we stand, what is running (open runs, resume points,
  tool failures), what has been run (the runs ledger), attack surface, testing state, the
  rendered `progress.md`, roots/DNS, the computed data inventory, and a brain-files state/age
  tab. One global search filters the active target's tables; the sidebar has its own target
  filter. Single-target rendering is unchanged (`recon-review.html`), and `accounts.md` is
  summarized — usable principals — never rendered, so credential references stay out of every
  generated page.
- **Deeper asset discovery guidance.** Subdomain enumeration now includes direct certificate-SAN
  collection from known IPs, company-matched and target-derived wordlists, and explicit VHost
  discovery inputs and calibration. ASN analysis now distinguishes RDAP registration from
  BGP-announced prefixes, while DNS analysis covers DNSSEC, NSEC, and bounded NSEC3 walking.
- **VHost fuzzing input contract.** Added the `@hunter.ips` role and extended `@wordlists` so
  VHost Host-header fuzzing resolves its IP and wordlist inputs the same required-input-present-
  or-stop way every other skill does — a ranked fallback (hunter-named IPs/group → attributed
  own-ASN/colo space → DNS-co-resolved addresses → the apex alone) plus explicit multi-IP
  budget-and-pilot discipline before it ever offers to scale past one address.
- **DNS record-type coverage.** `dns-analysis` now reads `HTTPS`/`SVCB` records for origin-IP
  hints leaking behind a CDN, DKIM selectors (a vendor fingerprint and a real crackable-key
  check), and domain-verification TXT tokens as a same-owner correlation signal, alongside the
  existing rcode classification and DNSSEC/NSEC coverage.
- **BGP and reverse-IP sourcing corrected.** `asn-and-ip-discovery` now pulls live BGP-announced
  prefixes from bgp.tools/RIPEstat rather than `asnmap` (a periodic IPtoASN snapshot with
  documented drift from the live table), substitutes Shodan's `hostnames` field for paid
  SecurityTrails reverse-IP lookups, and adds official cloud-provider IP-range files (AWS/Azure/
  GCP) plus RPKI ROA data as a third ownership-corroboration source distinguishing CDN-edge from
  customer-compute within one ASN. Two stale SecurityTrails references in `recon-toolkit.md` and
  `origin-exposure.md` now note it is a paid, unkeyed source rather than implying availability.
- **Scanning-dataset syntax and a JARM trap.** Documented Netlas/ZoomEye query syntax for the two
  engines already keyed in this project (previously unused beyond generic passive-source duty),
  and added JARM's missing false-positive trap (it clusters by TLS-library version, not by
  owner) alongside a note on JA4H's different, non-substitutable purpose.
- **Port-and-service coverage fix.** `port-and-service-discovery`'s reconciled scan-port list now
  actually includes the Kubernetes/Docker/etcd control-plane ports (6443, 2375/2376, 2379) the
  file's own disclosed-report data already named as the top hit generators, plus `zgrab2` and
  named unauthenticated endpoint probes (Redis `INFO`, Docker `/version`, Elasticsearch
  `/_cat/indices`, etc.) for the products it targets.
- **HTTP-probing depth.** `http-probing` now runs a default `gowitness` screenshot pass — catches
  SPA-shell collisions that body-hash clustering alone misses — plus a UA/Accept differential
  pass reusing that same clustering machinery, a response-timing existence-oracle signal distinct
  from the toolkit's existing cache-timing coverage, and per-host protocol (h1/h2) and
  `OPTIONS`/`Allow:` capture.
- **Organization-discovery expansion.** `organization-and-roots` gained mobile app-store/AASA
  verified-domain bindings (platform-verified, not claimed), WHOIS history distinct from the
  existing current-WHOIS/RDAP corroboration, GitHub org/commit-email discovery as entity
  expansion separate from `repository-and-secret-recon`'s secret-hunting scope, and M&A-filing
  and breach-data pivots — the latter two explicitly written with weaker evidence framing than
  the sourced pivots next to them, and breach data with an authorization caution ahead of the
  technique rather than as a plain step.
- **CT log monitoring option.** `monitoring-and-diff` now names CertStream/Cert Spotter as a
  between-interval complement to its existing periodic subdomain-name diff, not a replacement
  dimension.

### Changed

- Broad outcome requests such as “map the target's assets” now route to a situation flow such as
  `first-look`; narrow, explicitly named recon objectives continue to route to one skill.
- Recon completion now records whether applicable beyond-default techniques ran or why they did
  not apply. Loud wordlist-based fuzzing is named with its selector and estimated request volume
  and runs only when the hunter requests it or invokes a flow that includes it.
- `METHODOLOGY.md` refreshed against the additions above: the subdomain-enumeration passive/active
  split now states plainly that the gated techniques (permutation at scale, VHost fuzzing) require
  a named ask, and a new "Always" rule states the default-sweep-is-a-floor / fuzz-needs-consent
  principle as an operating rule for the hunter, not only as an implementation detail buried in one
  skill file.
- Application-mapping, authentication mapping, JavaScript analysis, URL collection, property
  derivation, and prioritization now consume the exact selected application context rather than
  the whole `applications/` directory.
- The runtime router gained rows for browser exploration, component hunting, the runbook, and
  advisory watching; the resident catalogue (`class-signals.md`) lists the new skills so orient
  and recommend can propose them; README replaced its "no external notifications" note with the
  notifications section and capability rows; FILEMAP, TOOLS, SKILL-OUTPUTS, and the target schema
  document the new files. The advertised skill count is now 35, enforced against the dispatchers
  the runtime actually exposes.
- README, FILEMAP, TOOLS, SKILL-OUTPUTS, the target schema, runtime instructions, and application
  templates were updated for the progress and per-application context models.

### Reliability

- Added regression coverage for application isolation, empty scaffolds, ambiguous ports, IPv6,
  atomic creation cleanup, host-aware preflight, and resume read sets.
- Added tests for the new capabilities: notify template rendering, channel-shape enforcement,
  spool-on-failure, and strict redaction; techwatch inventory parsing, ecosystem-mapping honesty,
  KEV flagging, and the seen-delta; runbook validation failures and plan markers; and the
  generated monitor job's notify wiring (events present, `vps.codedir` honored).
- Added `tools/netlib.py`, a verify-on TLS context that falls back to certifi only when the
  default store is empty — bare python.org installs ship a dead CA path that previously failed
  every outbound HTTPS call (webhooks included) with a certificate error.
- The repository audit now requires the target `progress.md` template, and configuration checks
  never print notification-channel credentials.

## 2026-08-12

### Changed

- Reorganized the skill library into task-oriented categories while preserving stable skill slugs
  and runtime discovery.
- Strengthened execution and public documentation so skills, tools, flows, outputs, and storage
  locations can be followed without relying on a numbered pipeline.
- Removed the obsolete standalone OAuth example flowchart after the detailed execution/context
  diagram became the canonical README visual.

## 2026-08-09

### Added

- Published the initial HunterStick workspace: focused recon and vulnerability skills, durable
  per-target context, the local-brain/VPS-raw split, evidence-backed execution, and the
  human-directed `resolve → run → persist → STOP` lifecycle.
