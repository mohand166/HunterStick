# Investigate an API Surface — the workflow

> *A **lens**, not a vuln class — it lives in `workflows/` because it tells you how to reason about
> an HTTP/JSON API as an API. Specific sinks defer to their own class files in `playbooks/vulns/`.*
>
> **This is a test of your ability to find a verb/authz/IDOR flaw** on the API the human names —
> the chain that reaches another user's data or an unauthorized action. Model **which principal
> reaches which operation on which resource**, understand what the contract *assumes* a caller can
> do, and find where that assumption breaks. This is the lens for testing an HTTP/JSON API *as an
> API* — its verbs, versions and parsers. Specific sinks defer to their own class files:
> `playbooks/vulns/idor-bola.md`, `playbooks/vulns/mass-assignment.md`, the injection classes,
> `playbooks/vulns/function-level-authorization.md`.
> The value is a named route+verb gap you reasoned to, not a scanner's "Swagger exposed". Work this
> with `playbooks/vulns/_master-vuln-hunting.md`.
>
> **Not `playbooks/flows/api-surface.md`.** That flow *recovers the contract* and never
> tests; this is the lens you use once you are testing what it found.

---

## 1. Model the flow before you touch anything

**SOURCE** — the whole request is the source, but the parts that matter to this class are the ones
routing depends on: the **method**, the **path** including its version segment, the **identity**
(token, cookie, API key), the `Content-Type`, and method-override headers.

**FEED** — what carries the request to the handler: gateway or WAF → router → version prefix → body
parser (JSON, XML, form, multipart) → framework model binding. Each hop can accept a request the
next hop's checks were never written for.

**SINK** — the handler that finally acts, and from what position: does it read, write or delete, and
does it act on an object belonging to the caller or to anyone?

**CONTEXT** — the discriminator here is **which principal reaches which operation on which
resource**. Vary one axis at a time:

| axis | what varies | what a gap here opens |
|---|---|---|
| principal | anon · low-priv token · other tenant · admin | authorization bypass |
| operation | `GET` vs `PUT`/`PATCH`/`DELETE`/`OPTIONS`/`HEAD`, `X-HTTP-Method-Override` | verb tampering |
| version | `/v1` vs `/v3`; a route only the mobile/JS client knows | legacy handler with the old checks |
| body dialect | JSON · XML · form · multipart · `+json` suffix | parser-differential code paths |
| resource | id/slug/UUID in path or body; writable fields | IDOR · mass assignment |

**ROOT CAUSE** — *why* couldn't the check hold? One of: authz bound to a route rather than to the
verb · an older version left routed with its older checks · a route no web client calls, so the web
tier's filter never covered it · two parsers on one route reaching different code · the object
reference never joined to the caller's tenant · fields writable that the contract never declared.
**That answer is your `fix_locus`** — the exact route+verb, or the version-specific handler, so
distinct gaps count separately instead of collapsing into "the API".

## 2. Derive the candidates — get the contract, don't crawl

1. **Pull the spec if it's exposed.** OpenAPI/Swagger (`/swagger.json`, `/openapi.json`), WADL,
   Postman collections leaked in JS — it hands you every route, param, auth scheme and role.
   Spec-driven testing (enumerate the declared operations, then probe the authz on each) is where
   crowd-missed bugs live. **No spec → build one** from the JS bundle and mobile app
   (`javascript-analysis`, `api-discovery`).
2. **Where the surface lives:** anything under `/api`, `/v1..vN`, `/rest`, `/internal`, `/mobile`,
   `/partner`; JSON or `+json` responses; `graphql`-adjacent REST.
3. **Prefer the non-obvious surface — that's where dups are rare:** undocumented or *older API
   versions still routed* (`/v1` left up after `/v3` shipped, carrying the old authz), endpoints
   referenced only in mobile apps or JS bundles and never in the web UI, verb-tampering gaps (`GET`
   guarded but `PUT`/`PATCH`/`DELETE` not, or `HEAD`/`OPTIONS`/method-override headers slipping past
   a filter), and content-type/parser quirks (an XML body on a JSON route hitting different code,
   `+json` suffix confusion, form vs JSON parsing).
4. **Per endpoint, ask:** which verbs does it *actually* accept versus document? Where does authz
   live — per route, per verb, or per object? Is `/v1` of this route still live with weaker checks?
   Which parsers accept the body?
5. **Then hand off.** Map object references (ids, slugs, UUIDs) → IDOR surface; map writable fields
   → mass-assignment surface; apply the specific class file to each.

## 3. Determine the context — before you change anything

Cheap, one request each. **`GET`/`HEAD`/`OPTIONS` only — those do not mutate.** If a probe
below would use `PUT`, `PATCH` or `DELETE`, it is not a probe: it is a test with a side
effect, and it needs the same approval as any other state change:

- **Verb reachability.** Re-issue a route you may `GET` as `PUT`/`PATCH`/`DELETE`/`OPTIONS`, and
  again via `X-HTTP-Method-Override`, and read *how* it refuses — a `405`/`501` is a different
  answer from a `403`, and both differ from it quietly working.
- **Version reachability.** Request the old-version or JS-only path with your low-priv token and see
  whether it resolves at all, before asking what it returns.
- **Parser reachability.** Resend the same logical request switching `Content-Type`
  (JSON ↔ XML ↔ form) and see whether the route still handles it, and whether handling *diverges*.
- **Principal reachability.** Send the same request anonymously, as a low-priv token, and as another
  tenant, so you know which axis you are actually varying later.

## 4. Test → Confirm → Validate

**Accounts gate:** the authz and IDOR half of this class needs **≥2 principals** you control.
Without them the honest result is `coverage = blocked (needs-account)` — not "not vulnerable".

**TEST — does the request reach a handler it shouldn't?** A verb, version, parser or principal
change from §3 answered by something other than a clean refusal. **Outcome: a hypothesis.**

**CONFIRM — did the guarded operation actually execute?** The **default oracle is that the effect is
observable through the legitimate path**: the guarded verb's write shows up when you re-read the
resource normally, or the legacy/undocumented route returns an object the current route refuses for
the same token. A status code is not the oracle. Rule these out before claiming:

- **`405 Method Not Allowed` or `501` means the verb was *rejected*** — the control working, not a
  bypass.
- **`OPTIONS`/CORS preflight succeeding is not the real method executing.** Confirm the actual verb
  performed the action.
- An "undocumented" endpoint that returns `401`/`403` **consistently** is properly guarded.
- A parser difference that only changes the **error message**, not the executed logic, is noise.
- A **stale spec** lists routes that 404 — absence isn't a bug; presence with weak authz is.
- An idempotent-looking `PUT` that a **WAF reflected or blocked** is not server-side execution.

**VALIDATE — the least that proves impact.** One reversible change to your *own* resource showing
the guarded verb executes; one benign non-own record read showing cross-tenant reach. Never mutate
or delete another party's data to prove it, never enumerate ids to size impact, and say what you did
not do. Severity is whatever the reached sink allows: verb tampering → unauthorized write/delete;
old-version routes → cross-tenant read/write and authz bypass; parser quirks → XXE, injection or
mass assignment. Chains worth naming: spec leak → hidden admin ops → function-level authz bypass;
old `/v1` + IDOR → cross-tenant takeover; content-type switch → XXE → SSRF. Apply those class files
rather than improvising the escalation here.

## 5. Safety, artifact, and PoC handoff

- **Self-target and revert.** Prove mutating verbs against your own resource with a benign,
  reversible change. **Never** destructive verbs on shared or other-tenant objects.
- **No bulk enumeration to "prove scale," no floods.** One reversible request against your own
  object, or one benign non-own object.
- **Store the artifact** under `targets/<t>/raw/`: the request/response pair with the varied axis
  (verb, version, `Content-Type`) plus its control. **No artifact → HYPOTHESIS, not FACT.**
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): candidate and confirmed requests to
  **Burp Repeater**, or a copy-pasteable `curl` carrying every required header including the
  program's mandated bug-bounty header — **with the paired control request**, so the divergence is
  visible in one glance. Reproducible in one action from a clean session.
- Respect the rate limit; a spec-driven sweep across every declared operation is a **loud** activity
  — budget it and say what it will cost before running it.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with `result`,
`coverage` and the **`fix_locus` from §1** — the exact route+verb or version-specific handler. The
principal column carries weight here: "as anon", "as low-priv token", "as other tenant" are
different cells with different answers. Log negatives *with the oracle used*.

**Novelty.** Generic "API returns verbose errors" and "Swagger exposed" are common dups. Novelty
lives in a **specific verb the authz layer forgot**, a **still-routed legacy version** with the old
checks, **JS/mobile-only endpoints** the crawler never saw, and **parser-differential** behaviour
between content-types on the same route.

## 7. Worked example — the spine in one pass

*Model / derive:* `recon/endpoints.md` shows the app calls `/v3/orders/{id}` but a leaked JS bundle still
references `/v1/orders/{id}` — a candidate from the bundle, not a crawl, since the web UI never calls
`/v1`. `recon/dns.md` confirms the same host routes both. The `/v3` handler enforces per-object tenant
authz; `/v1` predates that check and is still routed. Context axis = **version**;
`fix_locus = /v1/orders handler (authz)`.
*Context:* request the `/v1` path with the account-B token and confirm it resolves at all.
*Hypothesis:* `/v1/orders/{id}` carries the old, weaker authz and leaks cross-tenant order data.
*Confirm:* request one benign non-own order id via `/v1` and via `/v3` with the same account-B token.
`/v1` returning data that `/v3` refuses is the oracle — a still-routed legacy handler, not a new
injection. One reversible read, no id enumeration; artifact = both pairs, version varied.
*Novelty:* "Swagger exposed" is a dup; a JS-only legacy version the crawler never hit is not.
