# File map — every folder, every file, and when it is used


> What each file *is*, and — the part a directory listing cannot tell you — **when it enters the
> model's context, and when it executes.** This workspace is deliberately not a framework: most of
> it is text that is read at a precise moment and otherwise costs nothing.

## How to read the "when" column

Three tiers of loading, one of execution. Nothing else is ever in context.

| tier | meaning |
|---|---|
| **ALWAYS** | read at the start of every session, on every model — **~28 KB / 4.5k words**: `AGENTS.md`, `orchestrator.md`, and `CLAUDE.md` on runtimes that auto-load it. Roughly 7–9k tokens; no tokenizer ships with this repo, so treat any figure as an estimate — recount with `wc -cw`. If it is not in this tier, the model does not know its contents, only that it exists. |
| **ORIENT** | `class-signals.md` (~20 KB) — loaded when the task is orient / suggest / "what next?" (request analysis, property derivation, coverage, recommending a class/phase/flow). For an **exactly named skill** it is not loaded, which is why the resident tier is small. |
| **TRIGGER** | loaded when a skill fires or the router matches what the human said. One file, then the model stops loading. |
| **ON DEMAND** | opened only when a step in an already-loaded file names it by path. Never preloaded. |
| **HUMAN** | never loaded by the model. Documentation, licence, CI. |
| **EXEC** | not read at all — *run*. A CLI the model or the human invokes. |

The single rule behind the tiering: `playbooks/` is 100+ files. Preloading it would spend the
context budget on files that will not be used. So when the task is to orient or recommend, one
*catalogue* (`class-signals.md`) loads — it names every class, phase and flow in one line each,
enough to **suggest** something the human did not ask for, never enough to substitute for the real
file. For an exactly named skill even that is skipped: you were told what to run.

---

## Root

| file | what it is | when |
|---|---|---|
| `AGENTS.md` | The canonical instruction set — identity, the load order, the router table, scope rules, the coverage model, the refusal list. The one file that must be read before anything else on any runtime. | **ALWAYS**, first |
| `CLAUDE.md` | A three-line pointer to `AGENTS.md`, existing only because Claude Code auto-loads this filename. Deliberately carries no rules of its own so the two can never drift. | **ALWAYS** (Claude Code auto-loads) |
| `README.md` | The GitHub front page and hunter guide: problem, architecture, setup by runtime, daily capabilities, monitoring, and deeper references. | **HUMAN** |
| `assets/banner.png` | The HunterStick banner displayed at the top of `README.md`. | **HUMAN** |
| `assets/logo.png` | The standalone HunterStick logo for project and publication use. | **HUMAN** |
| `assets/hunterstick-execution-context-flow.png` | The detailed human-directed execution and persistent-context diagram embedded in `README.md`. | **HUMAN** |
| `TOOLS.md` | Tool behavior grouped by hunting intent, with the execution/side-effect model and pointers to each CLI's live `--help`. | **HUMAN** |
| `CUSTOMIZE.md` | Maintainer guide for adding classes, skills, flows, integrations and deterministic tools without bloating runtime context. | **HUMAN** |
| `VALIDATION-ROUND-1.md` | Historical issue ledger from the first live harness validation. Explicitly not current operating instructions; retained because each regression has provenance. | **HUMAN** |
| `LICENSE` | MIT. | **HUMAN** |
| `config.example.json` | The shape of `config.json` with every value blank — researcher handle, required attribution header, VPS address, API keys. Copy it, fill it, never commit it. | **HUMAN** (copied once at setup) |
| `.gitignore` | The publication boundary, and load-bearing: it excludes every live target, `config.json`, `TARGETS.md` and the report corpus, so only the empty skeleton ships. | **HUMAN** |
| `.mcp.json` | Wires two MCP servers: `chrome` (Playwright, for rendering SPAs and reading the DOM) and `burp` (SSE on `127.0.0.1:9876`, for proxy history). | Read by the runtime at startup, not by the model |
| `FILEMAP.md` | This file. | **HUMAN** |

---

## `skills/` — the bodies · `.claude/skills/` — the pointers

**Thirty-two skills, one body each.** A skill body lives once at `skills/<name>.md`. Each
`.claude/skills/<name>/SKILL.md` carries only the frontmatter a runtime matches on plus a
one-line pointer, so Claude Code still auto-triggers on "http probe the estate" while every
other runtime — OpenCode, Codex, whatever the user switched to this week — dispatches to the
same file through the router table in `AGENTS.md`. No build step; `self-check.py` asserts the
two agree, because nothing regenerates one from the other.

There is no recon dispatcher. It used to be a 180-line wrapper routing 23 objectives; each
objective is now its own focused skill, which is the whole point — a focused prompt is the
mechanism, and a wrapper that routes 23 of them is a general prompt wearing a costume.

| group | skills |
|---|---|
| **shared method** | `_recon-method.md` — the loop every recon skill runs: find the installed tool, read its help, pilot, **verify the output shape**, adapt, scale. Skills carry objectives and traps; this carries the method. |
| **asset discovery** | `organization-and-roots` · `subdomain-enumeration` · `dns-analysis` · `asn-and-ip-discovery` · `subdomain-takeover` |
| **reachability** | `live-host-validation` · `port-and-service-discovery` · `http-probing` · `technology-fingerprinting` |
| **surface** | `url-collection` · `content-discovery` · `javascript-analysis` · `api-discovery` · `parameter-discovery` |
| **breadth** | `cloud-asset-discovery` · `repository-and-secret-recon` · `component-inventory` |
| **application** | `authentication-surface-mapping` · `application-mapping` |
| **the bridge** | **`derive-properties`** — turns entrypoints into propertied rows. Recon produces hosts; hunting consumes *entrypoints with properties*, because a property is what selects a class. Without it an estate of 46,358 hosts yields zero testable candidates, which is not hypothetical. |
| **synthesis** | `host-correlation-and-clustering` · `cross-host-endpoint-reuse` · `attack-surface-prioritization` · `recon-summary-and-handoff` · `monitoring-and-diff` |
| **testing & other** | `vuln-hunt` (dispatcher over the class library) · `analyse-request` · `run-flow` · `tech-analysis` · `ground-a-playbook` · `compose-task` |

---

## `.github/`

| file | what it is | when |
|---|---|---|
| `workflows/ci.yml` | The `workspace-integrity` job: runs `self-check.py`, the test suite, Python compilation and shell parsing on every push. The mechanical half of "nothing fails silently". | **HUMAN** / CI |

---

## `tools/` — the executable layer

None of these programs decide what to hunt: two are import-only helpers and the rest
compute, validate or record. The ones
that send traffic or change the brain append their exit code to `targets/<t>/logs/tools.tsv` via
`runlog`, so a failure survives the session that caused it; the read-only derivers (`target-graph.py`,
`graph.py`) compute a view and record nothing.

| file | what it is | when it runs |
|---|---|---|
| `brief.py` | The session brief. Lists every target with its phase, blockers and last activity; `--resume` prints where one was interrupted; `--rules` prints `AGENTS.md` verbatim for runtimes that cannot read files. | **EXEC** — first command of every session |
| `config.py` | The single source of truth for machine config — researcher handle, attribution header, VPS, API keys. `check` redacts secrets; an unset value is a named blocker, never a silent default. | **EXEC** — session start, and before anything needing credentials |
| `scopelib.py` | **The one scope parser**, imported by the twelve tools that read or route on scope. Normalizes invisible characters, separates `enumeration_roots()` (what may be widened from) from `authorises()` (what an asset is recorded against). It answers *what did the hunter name?* — `run.py` and `preflight.py` do not import it, because scope does not gate execution. | Imported, never run directly |
| `scope-filter.py` | Filters a host list down to what `scope.md` authorises, before a tool sees it. `--roots` prints the authorised enumeration seeds. | **EXEC** — between any two recon phases |
| `calibrate.py` | Performs the calibration gate instead of describing it: baseline plus three impossible paths, compared on status/length/words/redirect, verdict `clean`/`broken`/`unknown` with an evidence artifact. Exists because preflight enforced the gate, kb stored the verdict, and nothing produced one — so it read UNRECORDED for an entire engagement. | **EXEC** — before any discovery phase whose counts you intend to trust |
| `rdap-org.py` | Who an IP range is *registered* to — RDAP (JSON over HTTPS), the WHOIS replacement that needs no package and no sudo. `--expect <company>` makes corroboration mechanical: any row whose org does not match is reported UNCONFIRMED and the exit is non-zero. Exists because a scanner's ASN *label* is not evidence: on one estate it labelled 36 ASNs with the company name and RDAP refuted three — two registered to private individuals — whose 62 CIDRs were already in the scope allowlist. | **EXEC** — inside `asn-and-ip-discovery`, before any CIDR reaches `scope.md` |
| `wildcard-check.py` | Re-verifies a hostname list against DNS wildcards **independently of whatever produced it** — two impossible labels per parent, and every child of a parent that answers is dropped. Exists because a resolver's own filter is not enough: on one run puredns reported 11 wildcard roots, still left 21 artifacts in its output and missed 4 real parents. Exit 1 = wildcards filtered, 2 = could not check. | **EXEC** — after any brute/permutation stage, before results reach `recon/subdomains.txt` |
| `init-target.py` | Scaffolds a target brain atomically: builds in a temp dir and renames, so an interrupted run leaves nothing. Refuses to overwrite, asserts all 12 required files, derives the allowlist only from domain-shaped scope. | **EXEC** — once per target |
| `preflight.py` | *What does this skill have to work with?* Parses the skill's own `## Inputs` section rather than a second registry, resolves its roles, and reports what is present. The one thing it flags as blocking is a **missing required input** — the admission gate (exit 1: cannot run as asked). It does **not** gate on scope, accounts or calibration; the hunter decides those. A prompt-subject skill reports PROMPT-CHECK REQUIRED until `--provided` confirms the subject. | **EXEC** — before every skill |
| `graph.py` | The dependency graph, **computed** from each skill's `## Inputs` joined against the role table — `--entry` answers "where do I start", `--check` runs in CI. It replaced a hand-written graph in which every phase number was wrong after a renumbering, including a bullet that contradicted itself in one sentence; prose cannot be executed, so it drifted silently. | **EXEC** — when the next move is unclear |
| `roles.py` | Resolves an input role (`@hosts.resolved`) to a path through the one `## Input roles` table in `target-schema.md`. Exists because a path written into two dozen playbooks rots in two dozen places — `host-correlation-and-clustering` blocked on five filenames that were missing their `recon/` prefix, while every one of those files existed. An unknown role fails loudly with near misses. | **EXEC** — whenever a command needs a brain path |
| `vps.sh` | Runs a command on the VPS, or moves a file across the boundary. Replaces holding the connection in a shell variable, which works in bash and silently fails in zsh — the trap that has bitten this repo three times. Stable `argv[0]`, so it can be allowlisted once. | **EXEC** — every remote command |
| `target-graph.py` | Derives the engagement graph from the brain on demand (never stored): joins `kb.py`'s host trust-edges to the findings/hypotheses so a **low-sev primitive becomes a chain seed**. `--chains` names READY and PARTIAL chains (and the missing half to hunt); `--linkage <node>` is one blast radius. | **EXEC** — when reasoning about chains or prioritising by linkage |
| `vps-run.py` | **Local pre-dispatch layer for HTTP commands.** Runs where `config.json` is, so the privacy backstop actually fires: refuses researcher private identity anywhere and public attribution outside its designated header, rejects known-bad invocation contracts before SSH, injects that header only for CLIs whose syntax was verified, then dispatches `run.py` on the VPS. `--print` dry-runs; `--detach` starts the same direct scanner command in VPS tmux, keeping the contract visible. | **EXEC** — every HTTP command to a target |
| `run.py` | Executes and records a reproducible command: tool version, redacted argv plus real-argv hash, input hashes, duration, exit code, artifact size/hash. It restores user tool paths omitted by non-login SSH, refuses ungated target-HTTP CLIs, catches evidence-backed semantic invocation traps, and validates fresh JSON/JSONL output against built-in plus caller-declared fields. `--stdout-file` preserves direct argv for stdout-only tools. It validates interfaces, never scope/rate/method policy. | **EXEC** — underneath `vps-run.py` for HTTP; directly for non-HTTP commands |
| `record.py` | Writes something the hunter stated in the prompt into the brain, with provenance. The prompt is a legitimate source — it just is not durable, so this makes it one and preflight then passes because the fact exists. Refuses out-of-scope values. | **EXEC** — when a phase input was supplied conversationally |
| `paths.py` | Derives the host-stripped replay list from `endpoints.md`. Object ids collapse to `{id}`, so the same route on prod and staging is one row on two hosts — the `cross-host-endpoint-reuse` candidate. Derived, never maintained. | **EXEC** — after any skill that produces URLs |
| `chunks.py` | Parses saved JavaScript/HTML as untrusted text and derives a directed lazy-chunk graph, persistent frontier and in-scope high-confidence fetch list. It never evaluates scripts or sends traffic. | **EXEC** — inside `javascript-analysis` when code splitting is present |
| `surfacelib.py` | The canonical endpoint-table reader/writer. Accepts the old traffic-import table for compatibility but emits only the schema in `target-schema.md`; shared by import, JS/spec normalization and path derivation. | Imported, never run directly |
| `surface.py` | Reduces saved jsluice URL/secret JSONL and OpenAPI/Swagger artifacts into canonical endpoints, global parameters and safely redacted `js-findings.md` candidates. It stores no secret values/context, labels scanner severity as untriaged, and hands supported artifacts to `derive-properties` instead of inventing vulnerability classes. Offline and dry-run by default. | **EXEC** — after JS extraction or spec recovery |
| `runlog.py` | The append-only invocation log. Wraps every tool's `main()`, redacts credential-bearing arguments, and records the exit code. `--failures` answers "what broke while I was away?". | Imported by all tools; **EXEC** to read the log |
| `kb.py` | The observation and run ledgers. Appends facts with provenance (`observed` > `reported` > `inferred`), opens and closes runs, and computes `patterns`, `chains`, `cohort` and `reassess` across the whole history. | **EXEC** — before traffic (open run), after (record facts) |
| `coverage.py` | Subtracts `tested.md` from `attack-surface.md` and prints the cells nobody has tested, keyed on `entrypoint × class × principal × variant`. Fails loud on schema drift instead of quietly under-counting. | **EXEC** — when deciding what to test next |
| `cluster.py` | Groups an httpx JSONL run by exact body hash + observed IP as **unconfirmed response-similarity candidates**. It annotates likely edges/CDNs and catch-alls, but never calls the pair an app, deployment, duplicate, or `shares-backend` fact; a second independent axis must confirm it. | **EXEC** — after http-probing, for `host-correlation-and-clustering` |
| `suggest-flows.py` | Computes which flow applies from the brain's own numbers — and, with `--why`, states what it *cannot* determine. Never guesses. | **EXEC** — when the next move is unclear |
| `import-http.py` | Turns captured traffic (HAR, Burp XML, Burp sitemap) into structured endpoints in the brain. Refuses out-of-scope hosts rather than importing them. | **EXEC** — after a browsing/proxy session |
| `dashboard.py` | Renders one brain as a single self-contained HTML page: counts computed from the files, drift flagged, `missing` distinguished from `0`. | **EXEC** — on request |
| `monitor.py` | Installs, inspects and removes the VPS cron job for scheduled enumeration. `pending` shows what a scheduled run found that nobody has reviewed. | **EXEC** — on "monitor subdomains for X" |
| `sweep.py` | Runs one n-day check across a tech cohort selected by `kb.py cohort`. **Pilot-gated**: one host first, full output shown, before anything scales. | **EXEC** — when a public n-day lands |
| `vps-sync.py` | Enforces the local/VPS split — brain local, raw output remote — and moves files across it. `demote` pushes bulk back off the laptop. | **EXEC** — around remote phases |
| `self-check.py` | Validates the public skeleton without touching a live target: dead links, stale text, template integrity, and structural checks that verify **data flow** rather than mere presence. | **EXEC** — before publishing; runs in CI |

---

## `playbooks/system/` — the rules

| file | what it is | when |
|---|---|---|
| `orchestrator.md` | **Who the model is** — a security researcher, its actual edge, what it is accountable for — then the loop, the delegation rules and the boundary it does not cross. | **ALWAYS**, first |
| `class-signals.md` | The catalogue: surface property → the vuln classes it selects, signal → the recon skills, situation → 10 flows, one line each. The property vocabulary is closed and `coverage.py` enforces it. What lets the model suggest the thing the human did not ask for — loaded when orienting or recommending, skipped for an exactly named skill. | **ORIENT** |
| `target-schema.md` | The layout every brain obeys and what each column means, so the model always knows where to look and never invents a file. | **ON DEMAND** |
| `phase-routing.md` | The recon graph — a dependency graph, explicitly **not** a numbered pipeline. Maps a scope shape to its entry phase and each phase to what it unlocks. | **ON DEMAND** — when choosing a phase |
| `vps-execution.md` | The execution model: brain local, raw remote, loud-phase envelopes, command robustness, and the `run.py` contract. | **ON DEMAND** — before remote work |
| `vps-setup.md` | One-time bootstrap for a new VPS: toolchain, wordlists/resolvers, target directories, runner deployment and verification. | **ON DEMAND** — once per VPS |
| `adaptive-tooling.md` | Think, then configure: derive flags from the target's observed behaviour instead of pasting a remembered command line. | **ON DEMAND** — with any recon phase |
| `calibration-quirks.md` | Behaviours worth recognising a second time — soft 404s, WAF fingerprints, rate-limit shapes. Consult before re-deriving a discriminator from scratch. | **ON DEMAND** — before calibrating |
| `recon-toolkit.md` | Which tool for which task, current best-in-class, with the reason each is preferred. | **ON DEMAND** |
| `mcp-tooling.md` | Browser vs curl vs Burp — when rendering is required, when it is waste. | **ON DEMAND** |

---

## `playbooks/recon/` — retired

The 23 numbered phase files are **gone**. Each objective is now its own skill under `skills/`,
with its body in one place and its inputs declared as roles.

Numbering was the problem, not the organisation. It was treated as identity, so a renumbering
silently invalidated every cross-reference: the hand-written dependency graph ended up with
**every number wrong** — liveness attributed to the HTTP objective, prioritization off by one, a
reference to a phase that did not exist, and a bullet contradicting itself in one sentence. Slugs
cannot drift that way, and `tools/graph.py` now computes the graph rather than restating it.

`init-target` moved to `skills/init-target.md`; the directory no longer exists.

---

## `playbooks/flows/` — situation → bundle

A flow answers *"what do I do now?"*. It bundles phases and workflows for one situation.
**Flows never send payloads** — they recon and triage, then hand off to `vuln-hunt`. Each has the
same shape: Situation · Preconditions · Steps · Aborts · Cost · Output · Exit.

| file | what it is |
|---|---|
| `_index.md` | The ten flows, their trigger situations, and the rule that a flow is chosen by situation and not by preference. |
| `first-look.md` | The one-time orientation pass: 02→05→07→08. Quiet by design — no portscan, no fuzzing. Ends with the first `attack-surface.md` rows and a paragraph saying what the target *is*. |
| `api-surface.md` | A JSON/REST/GraphQL surface with no UI worth mapping. Schema first, then authz per principal. |
| `auth-app.md` | Credentials exist and the app has roles: the two-principal differential work that most authz findings come from. |
| `spa-frontend.md` | A JS-heavy client. Bundle first — routes and endpoints come out of the source, not the DOM. |
| `static-site.md` | Marketing and docs pages. Three cheap checks (takeover, cache, storage), then **triage out explicitly** so it is never re-chased. |
| `huge-estate.md` | Hundreds of hosts: cluster, test representatives, hunt the outliers. You do not test 3,918 hosts. |
| `no-signup.md` | No credentials available. A full day of legitimate unauth work, with the authz classes recorded as **blocked**, not tested. |
| `dead-end-host.md` | A host that keeps producing nothing. How to prove it is dead and record that, rather than half-looking at it for weeks. |
| `broken-calibration.md` | The baseline is wrong and every downstream number is inflated. Stop, re-derive the discriminator, re-run. |
| `stale-return.md` | Returning to a target after weeks: what changed, what expired, what the ledger says you already ruled out. |

---

## `playbooks/workflows/` — artifact/step → procedure

Where flows answer *"what now?"*, workflows answer *"how do I do this one thing properly?"*.
Unlike flows, some of these do send requests.

| file | what it is |
|---|---|
| `_index.md` | The workflow list and the flow/workflow distinction. |
| `analyse-request.md` | One raw HTTP request → entrypoints, principals, surface properties, candidate classes. |
| `compare-two-accounts.md` | The differential method: identical request, two principals, and what a difference in status, length or timing actually proves. |
| `investigate-endpoint.md` | Everything worth establishing about a single endpoint before choosing a class to test. |
| `investigate-asset.md` | The same, one level up: a host or service. |
| `investigate-api-surface.md` | Systematic coverage of an API: versions, methods, object ids, error shapes. |
| `investigate-graphql.md` | Introspection, aliasing, batching, field-level authorization. |
| `investigate-grpc.md` | Reflection, protobuf decoding, and testing a binary surface. |
| `generate-hypotheses.md` | Turns observations into ranked, testable statements with a stated expected signal. |
| `design-validation-test.md` | Designs the probe that would distinguish a hypothesis from its most likely benign explanation. |
| `read-response-signals.md` | What a status, length, timing or error body actually tells you — and what it does not. |
| `reassess-after-failure.md` | A probe returned nothing: which assumption failed, and what to change before trying again. |
| `import-traffic.md` | Getting HAR / Burp XML / sitemap data into the brain correctly, and what to check after. |
| `recover-js-chunks.md` | Fixed-point lazy-chunk recovery from saved artifacts: source ledger → local parse → scoped fetch frontier → repeat, without executing target JavaScript. |
| `research-component.md` | One component at a time: canonical name, version timeline, advisories, changelog, disclosed reports. Bounded to 4–6 sources with the cost stated. Output is hypotheses with an expected signal, never a finding. |
| `n-day-sweep.md` | A public n-day lands: select the cohort by tech, pilot on one host, then scale. |

---

## `playbooks/vulns/` — 48 class playbooks + 3 spine files

`vuln-hunt` loads `_master-vuln-hunting.md` **plus exactly one class file**. Never a family, never
two. Each class file follows the six-section spine in `_playbook-shape.md`.

| file | what it is |
|---|---|
| `_master-vuln-hunting.md` | The reasoning loop every class shares: entrypoint, principal, hypothesis, probe, signal, disposition. Loaded for **every** hunt. |
| `_index.md` | Families → classes. Consulted when the human names a family ("logic bugs") rather than a class. |
| `_playbook-shape.md` | The six-section spine every class file obeys, so the model always knows where the method is. |
| `idor-bola.md` | Object references a principal should not be able to resolve. The canonical two-principal differential class. |
| `function-level-authorization.md` | The endpoint exists for a role the caller does not hold — authorization checked at the object but not the function. |
| `multi-tenant-isolation.md` | Data crossing a tenant boundary that the application treats as absolute. |
| `privilege-escalation.md` | Moving from a lower role to a higher one within the application's own model. |
| `mass-assignment.md` | Binding a field the client was never meant to control — role, owner, price, verified. |
| `sql-injection.md` | Untrusted input reaching a SQL query. Method file; `ref/sql-injection.md` holds the lookup material. |
| `nosql-injection.md` | Operator and type confusion in document stores, where a string becomes a query object. |
| `ldap-injection.md` | Filter injection in directory lookups, usually behind a login or a user search. |
| `xpath-injection.md` | The same shape against XML document queries. |
| `command-injection.md` | Input reaching a shell or an exec call, directly or through an argument. |
| `template-injection.md` | Server-side template evaluation of user input — often a rendering feature, not a bug in the parser. |
| `deserialization.md` | Untrusted serialized objects reconstructed into live ones. |
| `xxe.md` | External entity resolution in an XML parser — file read, SSRF, or denial. |
| `ssrf.md` | Making the server fetch a destination the attacker chooses. Method file; `ref/ssrf.md` holds the lookup material. |
| `lfi-rfi.md` | Including a local or remote file through a path the application builds. |
| `path-traversal.md` | Escaping an intended directory — read, and sometimes write. |
| `file-upload.md` | Type, extension and content validation, and what the server does with the stored file afterwards. |
| `xss.md` | Injected script executing in another user's context. Method file; `ref/xss.md` holds the payload and sink material. |
| `dom-clobbering.md` | Named DOM elements shadowing globals a script depends on. |
| `postmessage.md` | Cross-origin message handlers that trust the sender or the payload. |
| `prototype-pollution.md` | Polluting `Object.prototype` so unrelated code changes behaviour — a gadget hunt as much as an injection. |
| `cors.md` | Origin reflection and credentialed cross-origin reads. |
| `csrf.md` | State-changing requests a third-party site can cause, and what the application relies on to prevent it. |
| `open-redirect.md` | Attacker-controlled redirect destinations, and what they chain into. |
| `host-header-attacks.md` | The application trusting `Host` or `X-Forwarded-*` for links, routing or cache keys. |
| `cache-poisoning.md` | Getting a harmful response stored and served to others via unkeyed input. |
| `cache-deception.md` | Getting a *private* response cached publicly through path confusion. |
| `request-smuggling.md` | Front-end and back-end disagreeing about where one request ends. |
| `websocket.md` | Origin checks, authentication at upgrade, and authorization per message. |
| `subdomain-takeover.md` | A DNS record pointing at a service that no longer claims the name — and confirming it is actually claimable. |
| `origin-exposure.md` | Reaching the origin directly and bypassing whatever the edge was enforcing. |
| `cloud-misconfiguration.md` | Buckets, metadata endpoints, over-broad roles and public snapshots. |
| `baas-rls.md` | Backend-as-a-service (Supabase, Firebase) with row-level security as the only authorization layer. |
| `authentication-bypass.md` | Reaching an authenticated state without completing authentication. |
| `login.md` | The login transaction itself: lockout, credential handling, response differences. |
| `registration.md` | Account creation: pre-takeover, verification bypass, duplicate identity. |
| `password-reset.md` | Token generation, delivery, binding and reuse — the classic pre-auth account takeover. |
| `mfa.md` | Second-factor enrolment, verification, bypass and remember-device handling. |
| `session-management.md` | Issuance, rotation, invalidation, and what survives a logout or a password change. |
| `oauth-oidc.md` | `redirect_uri` handling, state and PKCE, token audience, account linking. |
| `user-enumeration.md` | Distinguishing valid from invalid identities through response, timing or side effects. |
| `race-conditions.md` | Concurrent requests crossing a check-then-act window. |
| `state-machine-abuse.md` | Reaching a state through a transition the application did not intend. |
| `workflow-abuse.md` | Skipping, reordering or replaying steps in a multi-step business process. Method file; `ref/workflow-abuse.md` holds the lookup material. |
| `limit-bypass.md` | Quotas, rate limits and caps enforced somewhere the client can influence. |
| `payment-abuse.md` | Price, currency, quantity and totals trusted from the client, or recomputed inconsistently. |
| `coupon-and-credit-abuse.md` | Stacking, reuse and negative-value paths in discount and credit logic. |
| `llm-prompt-injection.md` | Untrusted content reaching a model that holds privileges or tools the attacker does not. |

### `playbooks/vulns/ref/`

| file | what it is | when |
|---|---|---|
| `idor-bola.md` · `sql-injection.md` · `ssrf.md` · `workflow-abuse.md` · `xss.md` | **Lookup, not reading.** Corpus-grounded payloads, bypasses and signal tables for the five classes that have been grounded so far. Each header states the corpus's bias; a file with no citations is marked `NOT corpus-grounded`. | **ON DEMAND** — one section, when its trigger fires |

---

## `playbooks/tech/` — stack → what it changes

Fingerprinting says *what* a host runs; these say what that **changes**. Loaded on demand when a
stack is identified, never resident. Each holds only what is untrue of web apps in general.

| file | what it is | when |
|---|---|---|
| `_analysis.md` | The dynamic engine: verify identity/mode, build a layered stack graph, locate controls, generate evidence-bound mechanism/configuration/seam hypotheses, rank and record them. | **TRIGGER** — every technology analysis |
| `_shape.md` | The nine-section spine for optional deep product profiles. Generic testing belongs in a class playbook; ecosystem breadth belongs in a family reference. | **ON DEMAND** |
| `_index.md` | Routes a fingerprint to a deep profile, one of six broad family lenses, or bounded live research. Product names are examples, not a coverage whitelist. | **ON DEMAND** — checked at `technology-fingerprinting` / `component-inventory` |
| `nextjs.md` | Image-optimiser SSRF, Server Actions as unrouted endpoints, `__NEXT_DATA__` leakage, `/_next/data/*.json` bypassing component auth. | **ON DEMAND** |
| `react.md` | The bundle is the source: hidden routes live on the API, `REACT_APP_*` is public by design, SPA hosts are a soft-404 by design. | **ON DEMAND** |
| `wordpress.md` | Plugins are the target, not core. `admin-ajax` `action=` routing, `nopriv_` handlers, `readme.txt` versions → the strongest n-day path here. | **ON DEMAND** |
| `laravel.md` | `.env`, Telescope, Horizon, `_method` verb override, route-model binding resolving objects before authz. | **ON DEMAND** |
| `spring-boot.md` | Separately configured Actuator/management surfaces and proxy-to-application path-normalisation seams. | **ON DEMAND** |
| `references/frontend-meta.md` | Deployment-mode and control lenses for browser frameworks, SSR/meta-frameworks and generated bundles. | **ON DEMAND** |
| `references/backend-frameworks.md` | Routing, binding, middleware, serialization, administration and ecosystem-component lenses across server frameworks. | **ON DEMAND** |
| `references/cms-commerce.md` | Core/extension/theme/content/media/commerce decomposition for CMS and commerce platforms. | **ON DEMAND** |
| `references/api-edge.md` | REST, GraphQL, gRPC, realtime, gateway, proxy and cache hop analysis. | **ON DEMAND** |
| `references/identity-baas.md` | OAuth/OIDC/SAML/session and BaaS policy-boundary analysis, including RLS, grants, storage rules and privileged SDKs. | **ON DEMAND** |
| `references/enterprise-infra.md` | Administrative products, CI/dev platforms, Java servers, appliances and web-server exposure lenses. | **ON DEMAND** |
| `references/live-research.md` | Bounded current-upstream workflow for unknown products, version-dependent defaults and advisory applicability. | **ON DEMAND** |

---

## `targets/` — the brains

One directory per engagement, each self-contained. Everything here except the template and the
example registry is gitignored: live scope, hostnames, credentials and findings never ship.

| file | what it is | when |
|---|---|---|
| `TARGETS.example.md` | The registry template, plus the rule that decides which target a request applies to. **There is no "active" target** — the human names it, or it is resolved from a host against each `scope.md`. | Copied to `TARGETS.md` on first init |
| `TARGETS.md` | The real registry (gitignored). One row per engagement. | **ALWAYS** when present |

### `targets/_template/` — the schema, as files

Copied by `init-target.py`. Every file exists from day one so a missing fact is visibly `TBD`
rather than an absent file nobody notices.

| file | what it is | when |
|---|---|---|
| `index.md` | The manifest: what exists, what state each phase is in, what is blocking, what happened last. Read first, every session, for the named target. | **ALWAYS** (for the named target) |
| `scope.md` | **What the hunter said they are testing**, verbatim, then the derived allowlist. Context you reason with and route by — it decides *which brain* an asset belongs in, not whether a skill may run. `run.py` and `preflight.py` do not read it at all. | **ALWAYS**; routing context, not a gate |
| `target.md` | The prose the model reasons over. Every line tagged FACT / HYPOTHESIS / ASSUMPTION so inference never hardens into belief. | **ALWAYS** |
| `accounts.md` | The principals. A row counts only if its credential actually resolves — `password: <set>` is a plan, not an account, and authz work stays blocked until two are real. | **when the task involves a principal** |
| `scope-evidence.md` | Where the scope statement came from and when, so a later disagreement is resolvable without re-reading the program page. | **ON DEMAND** — on a dispute, not every turn |
| `attack-surface.md` | The recon→testing bridge. **Rows start at `http-probing`** — a probed host is an entrypoint, appended unranked; `technology-fingerprinting`, `javascript-analysis`, `api-discovery` and `application-mapping` add classes and variants; `attack-surface-prioritization` ranks what is there. Its `variants` column is what makes a coverage cell resolvable. | **ON DEMAND** — from fingerprinting onward |
| `tested.md` | **One row per probe actually sent.** Evidence history, not intent. A row for something never touched makes `coverage.py` count a cell that does not exist. | **ON DEMAND** — written after every probe |
| `hypotheses.md` | Testable ideas, ranked, each with its expected signal. | **ON DEMAND** |
| `clusters.md` | `host-correlation-and-clustering` output: hosts that share a backend, and the representative to test first. A cluster is a hypothesis until a differential probe proves it. | **ON DEMAND** |
| `user-flows.md` | The journeys a real user takes through the application — the source of state-machine and workflow-abuse candidates. | **ON DEMAND** |
| `observations.tsv` | The append-only fact ledger: every fact the target ever showed, with provenance and timestamp. Disagreement is kept, not resolved — a `reported` nginx losing to an `observed` Rails means a proxy. | Written by `kb.py`; read by `patterns` / `chains` / `cohort` |
| `runs.tsv` | The append-only run ledger. A row opens **before** traffic with `status running`, so an interruption is visible. `run.py` notes a command with no open row rather than blocking it. | Written by `kb.py`; read by `run.py` |
| `logs/tools.tsv` | Every tool invocation and its exit code, appended by `runlog`. Answers "what failed while I was away?" across sessions. | Written by every tool |
| `recon/README.md` | What belongs in each recon file, and the `missing` ≠ `0` ≠ `prose` rule. | **ON DEMAND** |
| `recon/root-domains.md` | `organization-and-roots` — one apex per row with its own evidence: source, date, and what that source proves. `ownership` and `scope_status` are separate columns because they are separate questions — a domain can be owned and out of scope. Unresolved apexes are kept, each with the check that would settle it. |  |
| `recon/ips-asn.md` | `asn-and-ip-discovery` — owned netblocks and the hosts on them. |  |
| `recon/dns.md` | `dns-analysis` — a reasoning file, not a dump: notable records, CNAME chains, takeover candidates. |  |
| `recon/ports.md` | `port-and-service-discovery` — one row per open port; raw output stays on the VPS. |  |
| `recon/components.md` | `component-inventory` — one row per `(host, component, version)` with `precision` (`exact`/`bounded`/`unknown`) and reachability. What turns a published advisory into a cohort selector. |  |
| `recon/technologies.md` | `technology-fingerprinting` — one row per live host. Feeds clustering, tech-risk scoring and n-day cohorts. |  |
| `recon/endpoints.md` | The curated slice of the URL corpus from `url-collection`, `javascript-analysis`, `api-discovery`, `application-mapping` and `parameter-discovery` — the interesting ones, not all of them. |  |
| `recon/js-findings.md` | `javascript-analysis` — routes, endpoints, internal hosts and secrets from bundles. |  |
| `recon/cloud.md` | `cloud-asset-discovery` — buckets, blobs, functions and their access state. |  |
| `recon/repos.md` | `repository-and-secret-recon` — repos, exposed `.git`, dork hits. Secrets redacted. |  |
| `recon/content/` · `recon/wordlists/` | Content-discovery output, and wordlists **derived from this target's own vocabulary** — never a generic list. |  |
| `applications/_host-template/map.md` | `application-mapping` — copied to `applications/<host>/` when an app is deep-mapped. Routes, roles, state transitions. |  |
| `applications/_host-template/endpoints.md` | App-specific endpoints, including authenticated-only ones. |  |
| `applications/_host-template/notes.md` | Free-form mapping observations, every line tagged FACT / HYPOTHESIS / ASSUMPTION. |  |
| `investigations/README.md` | The `<lead>/` convention: one directory per lead being worked. |  |
| `investigations/chain.template.md` | For impact crossing more than one entrypoint or class — where individual probes become one finding. |  |
| `findings/{draft,confirmed,rejected}/` | Findings by disposition. **Rejected is kept**: it is what stops the same dead end being re-chased next month. |  |
| `raw/` | Local raw output — calibration baselines and small artifacts. Bulk belongs on the VPS. |  |
| `logs/exec/` | Written by `run.py`: one JSON record per command with tool version, redacted argv (credentials and researcher identity), input hashes, the host it ran on, exit code, artifact freshness/hash and structured-output validation — plus any configured identity category seen in the response. No scope hash or calibration pointer; those were the deleted policy engine. Answers *"why `-fs 2048`, three weeks ago?"* | Created on first run |

---

## `knowledge/` — local build-time input

| file | what it is | when |
|---|---|---|
| `README.md` | The simple knowledge loop: add reports/research under `knowledge/<subject>/`, re-evaluate one named skill/playbook, KEEP or IMPROVE it, record, stop. | **HUMAN** |
| `<subject>/` | User-supplied reports, research, notes or experiments for one skill/playbook. Entirely gitignored and never loaded during a hunt. | **BUILD-TIME**, only when `ground-a-playbook` is invoked |
| `MINED.tsv` | Gitignored source/destination hash ledger. Makes re-evaluation delta-based without becoming another runtime state store. | **EXEC**, local only |
| `reports/README.md` | Compatibility guide for older `knowledge/reports/<subject>/` collections and optional HackerOne helpers. | **HUMAN**, source-specific |
| `knowledge/tools/knowledge-status.py` | Reports NEW/CHANGED/EVALUATED/STALE source files and records a completed KEEP/IMPROVE decision. | **EXEC**, every knowledge evaluation |
| `knowledge/tools/h1-fetch.sh` · `check-citations.py` · `check-dispositions.py` | Optional HackerOne-style acquisition and integrity helpers. Config credentials are read through `tools/config.py`; ordinary knowledge use needs none of them. | **EXEC**, build-time and source-specific |

---

## `tests/`

| file | what it is | when |
|---|---|---|
| `test_tools.py` | The regression suite. Not coverage for its own sake — each one encodes a mistake that was actually made: scope widening through invisible characters, an out-of-scope URL typed into a command, a credential reaching an execution record, a per-minute rate compared against a per-second budget, a demoted file reading as `missing` and hard-blocking the phase that needed it, a run id derived from row count so every completed run burned one, a wildcard parent turning 33 phantom hosts into 'discoveries'. | **EXEC** — locally and in CI |

---

## Execution order — one full session

Where each piece actually enters, start to finish.

| # | what happens | files involved |
|---|---|---|
| 1 | Session opens | `AGENTS.md` → `orchestrator.md` (**ALWAYS**, ~28 KB); `class-signals.md` only when orienting/recommending |
| 2 | Orient | `tools/brief.py`, `tools/config.py check`, `TARGETS.md` |
| 3 | Human names a target | `targets/<t>/index.md` · `target.md` · `scope.md` · `accounts.md` |
| 4 | Human asks for something | a skill fires → **one** playbook loads |
| 5 | New target? | the router → `skills/init-target.md` → `tools/init-target.py` → the brain exists, then STOP |
| 6 | Before any traffic | `tools/preflight.py` (missing required input = stop) → `tools/kb.py run --status running` |
| 7 | Select the supplied subject | one exact host or the applicable recorded set; ingest tools reconcile newly discovered outside data |
| 8 | The command | HTTP: `tools/vps-run.py` → local privacy/attribution boundary → VPS `run.py`; non-HTTP: `run.py` directly. Both record evidence. |
| 9 | After | normalize into `recon/*`, `tools/kb.py add`, `reassess`, `patterns`, close the run |
| 10 | Decide next | `tools/coverage.py`, `tools/suggest-flows.py` |
| 11 | Test | `vuln-hunt` → `_master-vuln-hunting.md` + one class file → row in `tested.md` |
| 12 | Anything failed? | `tools/runlog.py --failures` |
| 13 | Over weeks | `kb.py patterns` / `chains` / `cohort`, `monitor.py pending`, `sweep.py` |

Steps 4–9 repeat, one scoped task at a time. The model loads one playbook per task and stops —
that is the whole reason a 100+ file library costs ~47 KB to have available.
