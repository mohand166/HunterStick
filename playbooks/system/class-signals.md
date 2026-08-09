# Class Signals — the catalogue

> **Loaded to orient or recommend — not for an exactly named skill (`AGENTS.md`), ~4k tokens.** One
> line per vuln class, recon skill, flow and workflow: enough to *suggest* and to *compute
> coverage*, never enough to test with. When something becomes the work, load its own file — that is
> the authority, this is the map.

Read in two directions. **surface → classes**: an entrypoint's observed properties imply which
classes are *applicable* — what `coverage.py` subtracts `tested.md` from, and what attack-surface-prioritization scores.
**class → description**: when the human names one class, the properties you observed surface the
others that fit. **Suggest, never substitute.**

**Applicable ≠ vulnerable ≠ worth testing.** A comma between properties means **OR**; `+` means
**AND** — `cacheable+unkeyed-input` does not match a merely cached page.

## Property vocabulary

Observable facts about a surface, recorded in `attack-surface.md`'s `properties` column. Keep the
vocabulary closed — a free-text property matches nothing and silently drops its classes.

| property | it means |
|---|---|
| `object-ref` | the request names an object — id, slug, uuid, path segment, opaque/encoded blob |
| `two-object` | it names **two** objects (transfer, share, assign, invite, merge, add-to) |
| `multi-tenant` | data is segregated by org / workspace / tenant |
| `role-gated` | behaviour differs by role, **or** the response/bundle enumerates roles, permissions or feature flags the current principal does not hold |
| `mass-bind` | a request body is bound to a model / object (JSON, form, protobuf message) |
| `recursive-merge` | attacker-controlled object keys reach a deep merge / clone / defaults operation |
| `reflects` | input appears somewhere in the response |
| `renders-html` | output becomes HTML, markdown, or rich text |
| `client-render` | a value is handled by client JS / reaches the DOM |
| `stored-then-rendered` | the value is persisted and shown again, possibly to someone else |
| `db-query` | input reaches a data query but the store is not fingerprinted yet |
| `sql-query` | the sink is known to be relational SQL |
| `document-query` | the sink is known to be a document/NoSQL query |
| `db-directory` | the query goes to a directory service — LDAP, AD |
| `db-xml` | the query goes to an XML document — XPath, XQuery |
| `os-or-exec` | input lands in a value the app plainly hands to another program — a hostname it pings, a filename it converts, a command/arg field, a format string |
| `template` | input is reflected into a server-rendered page or a named template/expression field, on a stack with a known template engine |
| `fetches-url` | the server retrieves a URL you influence (webhook, import, preview, thumbnail, SSO metadata) |
| `file-path` | input becomes a filesystem path or an include target |
| `file-upload` | it accepts a file |
| `xml-parser` | attacker-controlled XML reaches an XML parser |
| `object-deserializer` | an opaque binary/base64 blob round-trips through the client with a recognisable serialization prefix (`rO0`, `AAEAAAD`, `O:8:`, `gASV`) |
| `archive` | an uploaded or imported archive is unpacked |
| `redirect` | it takes a URL, `next`, `return_to` or equivalent |
| `identity-input` | it takes a username, email, phone, or account identifier |
| `session-issue` | it issues, renews, or revokes a session / token |
| `ambient-session` | a browser automatically attaches the credential, normally a cookie |
| `oauth` | OAuth, OIDC, SAML, or SSO account-linking is involved |
| `state-machine` | a multi-step flow where order or state matters |
| `state-changing` | the operation creates, updates, deletes, sends, or otherwise changes server state |
| `money` | payment, balance, credit, coupon, refund, or pricing |
| `per-request-limit` | a control counted per request — OTP, login attempt, coupon, quota, invite |
| `cross-origin` | CORS, `postMessage`, iframes, or WebSocket |
| `cacheable` | fronted by a CDN or cache (`Age`, `X-Cache`, `CF-Cache-Status`) |
| `unkeyed-input` | a header or parameter absent from the URL demonstrably changes the response body — observable in two requests, no cache-key knowledge needed |
| `host-header-trusted` | something in the response is built from `Host` / `X-Forwarded-*` |
| `http-hop` | at least two HTTP parsers/proxies handle the request before the application |
| `edge-protected` | a CDN, WAF, gateway, or network boundary protects the expected origin |
| `client-side-db` | the browser talks to a DB gateway directly (Supabase, Firebase, PostgREST, Appwrite) |
| `llm` | input reaches a model prompt or an agent's tool loop |
| `third-party-dns` | a CNAME / delegation points at an external provider |
| `cloud-asset` | a bucket, blob store, function, or metadata-bearing instance |
| `jwt` | the request carries a self-describing signed token — three base64url segments, with `alg`/`kid`/`jku` in its header |
| `bulk-operation` | one request carries N operations or N object ids — array body, GraphQL aliases, `/batch`, an import file |
| `async-job` | the call returns a handle and the real result arrives later from a status/result endpoint |
| `renders-document` | server-side rendering turns user-supplied content into a PDF, spreadsheet, image or screenshot |
| `principal-switch` | the surface changes who, or which tenant, you are acting as without re-authenticating |
| `graphql` `grpc` `websocket` | **transport only** — never a class by itself. These select a *lens* (see below), and the classes come from the other properties. |

---

## Vuln classes

`file` is `playbooks/vulns/<file>.md`. Each comma-separated expression is an alternative; every
property joined by `+` in the chosen expression must be present. Keep coarse single-property rules
only where that observation is itself enough to justify a candidate.

| class | properties | what it is |
|---|---|---|
| `idor-bola` | `object-ref, two-object, multi-tenant, bulk-operation, async-job` | the object-owner check ran against the wrong noun, or not at all |
| `function-level-authorization` | `role-gated, principal-switch` | the *operation* is unprotected, independent of which object it names |
| `privilege-escalation` | `role-gated+mass-bind, role-gated+session-issue, jwt+role-gated, principal-switch` | a lower principal acquires a higher one's capabilities |
| `multi-tenant-isolation` | `multi-tenant, principal-switch` | tenancy is the boundary that breaks — data crosses org/workspace lines |
| `mass-assignment` | `mass-bind, bulk-operation` | the body binds a field the caller was never meant to set |
| `baas-rls` | `client-side-db` | the browser hits the DB gateway directly and RLS/security-rules are the only authz |
| `sql-injection` | `sql-query, db-query` | a value changes the *structure* of a SQL query |
| `nosql-injection` | `document-query, db-query+mass-bind` | an operator or type coercion changes a document-store query's meaning |
| `ldap-injection` | `db-directory` | a value changes an LDAP filter's structure |
| `xpath-injection` | `db-xml` | a value changes an XPath/XQuery expression |
| `command-injection` | `os-or-exec` | input reaches a shell or exec boundary |
| `template-injection` | `template, renders-document` | input is *evaluated* by a template engine rather than inserted into one |
| `deserialization` | `object-deserializer` | attacker bytes become live objects and a gadget chain runs |
| `xxe` | `xml-parser` | an XML parser resolves an external entity you declared |
| `lfi-rfi` | `file-path+template` | an include target is attacker-controlled |
| `path-traversal` | `file-path, file-upload+archive, renders-document` | a path escapes its intended root |
| `file-upload` | `file-upload` | what you upload gets stored, served, or parsed in a way it shouldn't be |
| `ssrf` | `fetches-url, renders-document` | you choose where the server sends a request, and it goes somewhere it shouldn't |
| `host-header-attacks` | `host-header-trusted` | the response is built from a host value the request controls |
| `request-smuggling` | `http-hop` | front-end and back-end disagree on where a request ends |
| `cache-poisoning` | `cacheable+unkeyed-input` | the cache key and the response body are computed from different things (poisoning **and** deception) |
| `origin-exposure` | `edge-protected+cloud-asset, edge-protected+host-header-trusted` | the origin is reachable past the edge that was protecting it |
| `xss` | `reflects, renders-html, client-render, stored-then-rendered` | script runs in another principal's origin |
| `dom-clobbering` | `client-render+renders-html` | injected *markup* overwrites the JS variables the page reads |
| `prototype-pollution` | `recursive-merge` | a `__proto__`-style key changes objects the app never wrote |
| `postmessage` | `cross-origin+client-render` | a message handler trusts an origin it shouldn't, or sends to one it shouldn't |
| `cors` | `cross-origin` | the origin reflection or credential policy hands data to any site |
| `csrf` | `state-changing+ambient-session` | a state-changing action rides the victim's ambient session |
| `open-redirect` | `redirect` | the app sends the victim to a destination you choose |
| `websocket` | `websocket` | the socket's handshake authz, origin check, or message authz is missing |
| `authentication-bypass` | `session-issue+identity-input, jwt` | you reach an authenticated session without the right secret |
| `user-enumeration` | `identity-input` | behaviour differs by whether an identity exists |
| `registration` | `identity-input, state-machine` | signup grants something it shouldn't — verification, tenancy, a taken identity |
| `password-reset` | `identity-input+session-issue+state-machine` | the reset token, its delivery, or its binding is weak |
| `mfa` | `session-issue+per-request-limit+state-machine` | the second factor can be skipped, replayed, brute-forced, or re-targeted |
| `session-management` | `session-issue, jwt, principal-switch` | the session outlives, out-scopes, or out-travels what it should |
| `oauth-oidc` | `oauth, jwt` | the flow's `state`, `redirect_uri`, code binding, or token audience is broken |
| `workflow-abuse` | `state-machine, async-job` | the business rule is bypassed by using the app in an order it didn't expect |
| `race-conditions` | `state-changing+per-request-limit, state-changing+money, bulk-operation, async-job` | a check and its use are not atomic |
| `limit-bypass` | `per-request-limit, bulk-operation` | a per-request control is defeated by batching, casing, a second route, or a reset |
| `payment-abuse` | `money` | price, currency, quantity, or refund is client-trusted |
| `coupon-and-credit-abuse` | `money+per-request-limit, money+bulk-operation` | a single-use value is used more than once, or for more than it's worth |
| `subdomain-takeover` | `third-party-dns` | a delegation points at a provider resource nobody owns any more |
| `cloud-misconfiguration` | `cloud-asset` | a bucket, function, or metadata surface is readable/writable by the wrong principal |
| `llm-prompt-injection` | `llm` | untrusted text reaches a prompt and steers the model's tools or output |

**Stubs (pointers, not classes):** `cache-deception` → `cache-poisoning` · `state-machine-abuse` →
`workflow-abuse` · `login` → `authentication-bypass` + `user-enumeration`.

**Transport lenses** — `playbooks/workflows/investigate-graphql.md` · `investigate-grpc.md` ·
`investigate-api-surface.md`. They describe *how to see* a surface — recovering the contract, the oracle's quirks, batching mechanics. They never
replace a class: an IDOR over gRPC is `idor-bola`, and it must be findable from the IDOR playbook.
When a transport property is present, add the lens **alongside** the classes the other properties
imply, never instead of them.

---

## Recon skills

Same idea, other half of the workspace: when analysis shows a **missing input**, name the phase that
produces it. The dependency graph and archetype routing live in `phase-routing.md` — this is only
the signal → phase lookup.

| you notice | run |
|---|---|
| the human named a **company**, not a domain | `organization-and-roots` |
| one root domain, no host list | `subdomain-enumeration` |
| hosts but no records / takeover check | `dns-analysis` |
| you suspect owned IP space | `asn-and-ip-discovery` |
| a host list nobody has resolved | `live-host-validation` |
| non-HTTP services may exist | `port-and-service-discovery` |
| live hosts but no status/title/tech | `http-probing` |
| you're guessing at the stack | `technology-fingerprinting` |
| no URL corpus to mine | `url-collection` |
| the URL corpus is thin, paths unknown | `content-discovery` |
| bundles unread — the highest-yield gap | `javascript-analysis` |
| an API exists but no contract | `api-discovery` |
| endpoints known, parameters not | `parameter-discovery` |
| buckets / functions / metadata untested | `cloud-asset-discovery` |
| the org publishes code, or secrets may be leaked | `repository-and-secret-recon` |
| auth flows unmapped, or you need accounts | `authentication-surface-mapping` |
| a single app needs a real map | `application-mapping` |
| many hosts, unknown which share a backend | `host-correlation-and-clustering` |
| the same API appears on several hosts | `cross-host-endpoint-reuse` |
| endpoints collected but the surface has **no properties** — nothing selects a class | `derive-properties` |
| recon done, nothing ranked — **the gate into testing** | `attack-surface-prioritization` |
| recon needs to be handed off or resumed | `recon-summary-and-handoff` |
| the target is live and changing | `monitoring-and-diff` |
| a stack is fingerprinted but no component has a **version** — n-day work is blocked | `component-inventory` |
| a stack is named or fingerprinted and you need what it **changes** | `tech-analysis` |
| `dns-analysis` left a **dangling record** or takeover candidate unadjudicated | `subdomain-takeover` |

`derive-properties` is the row that most often goes unnoticed, because nothing fails without it:
recon keeps producing hosts and the attack surface stays empty, so every class looks inapplicable
and hunting has nothing to select on. It sends **no traffic** — it re-reads artifacts already paid
for. A target with thousands of live endpoints and zero propertied rows is not a quiet target; it
is this row, unrun.

---

## Flows — situation → bundle

The third catalogue. A **class** answers *what could be wrong here*; a **phase** answers *what input
am I missing*; a **flow** answers *I am looking at this whole thing — what now*. Recognising the
situation is most of the skill, so the situations are listed here rather than only inside
`playbooks/flows/_index.md`, which you would have to already be opening to read.

| what you are looking at | run | note |
|---|---|---|
| a target with scope filled and `recon/` empty — the first thing you run | `first-look` | 02→05→07→08. Quiet: no portscan, no fuzzing |
| a random invented path returns **200**, or everything 301s the same way | `broken-calibration` | **first.** Every discovery count is fiction until repaired |
| live host, no links, no forms, everything 404s | `dead-end-host` | archives → JS → vhosts → *then* fuzz |
| the HTML body is a shell and a bundle | `spa-frontend` | the API contract is inside the JS; do not fuzz |
| JSON responses, or a spec / introspection answers | `api-surface` | take the contract, skip discovery |
| no self-registration and no credentials obtainable | `no-signup` | unauth classes properly; authz parked as `blocked (needs-account)` |
| a login exists and accounts are obtainable | `auth-app` | two principals → map → diff |
| hundreds or thousands of live hosts | `huge-estate` | cluster; test representatives and the outliers |
| no forms, no state, cacheable, informational | `static-site` | three checks, then **triage it out** and record that |
| returning to a target after weeks | `stale-return` | still true / expired / new |

`tools/suggest-flows.py <target>` proves the ones it can from structured data and names the four it
**cannot** (`dead-end-host`, `spa-frontend`, `api-surface`, `static-site` all need someone to look
at a live response). A flow declares its steps, cost and abort points first; a named flow then runs
without asking again, while *"what should I run?"* recommends and stops (`skills/run-flow.md`). It
never sends a payload.

## Workflows — artifact or step → procedure

The fourth catalogue, and the smallest. A **flow** is triggered by a *situation*; a **workflow** by
an **artifact you are holding** or a **step you are inside**. Full map + the flows-vs-workflows line:
`playbooks/workflows/_index.md`.

| you have / you are | run |
|---|---|
| a pasted raw HTTP request | `analyse-request` |
| a request/response **pair** to squeeze | `read-response-signals` |
| a HAR or Burp export | `import-traffic` |
| saved entry bundles from a code-split app | `recover-js-chunks` |
| an HTTP/JSON API you are **testing** (not mapping) | `investigate-api-surface` |
| GraphQL / gRPC as the transport | `investigate-graphql` · `investigate-grpc` |
| two principals and an authz question | `compare-two-accounts` |
| about to probe, no oracle declared yet | `design-validation-test` |
| observations that are not yet a backlog | `generate-hypotheses` |
| one host / one endpoint worth a deep dive | `investigate-asset` · `investigate-endpoint` |
| a negative or inconclusive result | `reassess-after-failure` |
| several runs done, nothing generalised yet | `kb.py patterns` → promote to `target.md` §Patterns |
| a public n-day and a fingerprinted cohort | `research-component` | you hold a component + version and need what is publicly known | bounded: 4–6 sources, one component. Output is **hypotheses**, never findings |
| `n-day-sweep` — **pilot-gated, sends checks** |

## Tech files — stack → what it changes

The fifth catalogue. A **class** is what could be wrong; a **phase** is what input is missing; a
**flow** is what to do now; a **workflow** is how to do one thing properly. A **tech file** is what
this particular stack changes about all four.

Loaded on demand, never resident. Check `playbooks/tech/_index.md` whenever a stack is fingerprinted
(`08`), a component is pinned (`23`), or the hunter names an app. Every recognized stack enters
through `tech/_analysis.md`: verify its deployment mode, build the multi-layer stack graph, then
load one deep profile and/or the matching family lens. A deep profile is extra precision, not the
coverage boundary.

| if the stack is | read | because it changes |
|---|---|---|
| Next.js — `__NEXT_DATA__`, `/_next/` | `tech/nextjs.md` | image-optimiser `ssrf`, Server Actions as unrouted endpoints, SSR props leakage |
| React SPA — `data-reactroot`, one bundle | `tech/react.md` | the bundle *is* the source; hidden routes are live on the API |
| WordPress — `/wp-content/`, `/wp-json/` | `tech/wordpress.md` | plugins are the target, not core; `admin-ajax` `action=` routing |
| Laravel — `laravel_session`, a `419` | `tech/laravel.md` | `.env`, Telescope, `_method` override, route-model binding |
| Spring Boot — `/actuator`, Whitelabel error | `tech/spring-boot.md` | conditional management-plane exposure; proxy/application path-normalisation seams |
| any other framework, CMS, API/gateway, IdP, BaaS or enterprise product | `tech/_index.md` → one `tech/references/*.md` family lens | dynamic mechanism/configuration/seam analysis; live upstream research when identity, version or defaults matter |

The written product names are routing examples, not a whitelist. An unlisted or proprietary stack
is classified by its role and routed through the closest family lens plus bounded live research.
Never invent a remembered default merely because no deep profile exists.

## How to use it in a turn

1. **The human names a class.** Do that class. Then read the entrypoint's `properties` and say which
   *other* classes they imply that `tested.md` has no row for — as conditional next actions, not as
   a detour.
2. **The human asks "what should I test here?"** Read `properties` for that entrypoint from
   `attack-surface.md`, resolve to classes here, subtract what `tested.md` already covers, and rank
   the remainder by attack-surface-prioritization's score. Run `tools/coverage.py <target-dir>` rather than eyeballing.
3. **A property you observed isn't recorded.** Add it to `attack-surface.md` first — the coverage
   number is only as honest as the properties behind it.
4. **A required input is missing.** Name the recon skill, don't improvise around the gap.
5. **You are looking at a whole host or estate, not one entrypoint.** That is a *situation*, not a
   class — match it against §Flows above before reaching for a phase. "This host 404s everything"
   has a known four-step answer; re-deriving it each time is how the cheap steps get skipped.
