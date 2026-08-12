---
name: analyse-request
description: Analyze a pasted raw HTTP request as a bug-bounty entrypoint. Use when the human pastes a Burp, DevTools, mobile-proxy, curl, or raw HTTP request and asks what to test, what vulnerabilities apply, or to analyze/analyse the request. Routes directly to the request-analysis workflow without recon.
---

# Analyse a Request — the workflow

> **In one line, the discipline this workflow enforces:**
>
> - reconcile its host against every target's `scope.md` only to decide **which brain** it belongs
>   in — routing, never a stop; the hunter pasted it, which is the authorisation;
> - remove live credentials from all durable artifacts and keep only an approved secret reference;
> - derive observed properties before candidate classes;
> - store the placeholdered control request and candidate rows;
> - do not send traffic or mark anything tested during analysis;
> - present the ranked candidates, then stop for the human to choose one.

> *A **lens**, not a vuln class. The human pastes a raw HTTP request — from Burp, from devtools,
> from a mobile proxy — and wants to know what it is worth testing for. This turns one request into
> a scored set of candidate classes, records it as a real entrypoint, and hands off to `vuln-hunt`.*
>
> **Have the response too?** `read-response-signals.md` squeezes a request/response *pair* for
> behaviour, tech and auth signals after this workflow has placed the entrypoint.
>
> **This is the human-directed entry point.** They already decided what they are looking at, so no
> gate applies — not prioritization, and not scope. What still binds you is **the artifact rule**:
> every claim carries the request/response that proves it.

---

## Inputs

- `@hunter.request` — **the raw HTTP request itself.** This is the subject; without it there is
  nothing to analyse and the skill must ask rather than improvise one.
- `@scope` (optional) — only to decide *which brain* the entrypoint belongs in, not whether you
  may look at it.
- `@surface` (optional) — if the entrypoint is already known, extend its row instead of writing
  a second one.

## 1. Which brain does this belong in?

Extract the host from the request line and `Host:` header, and reconcile it against each
`targets/*/scope.md`. You are answering **where this gets recorded**, not whether you may read it —
the hunter pasted the request, which is the authorisation.

| outcome | what you do |
|---|---|
| matches one target | that is the brain. Continue. |
| matches an **out-of-scope** entry | say so in one sentence, then continue with what they asked. Record it where they named. |
| matches no target | say it belongs to no existing brain, pick the one they named (or scaffold it), and note the host so the decision is recorded once. |
| matches two targets | ask which — not for permission, but because writing to the wrong brain corrupts two engagements. |

This step routes; it never stops. The only thing that stops this skill is a missing
`@hunter.request` — with no request there is nothing to analyse.

## 2. Strip the credential before anything else

A pasted request carries a live session — that is why it was pasted. Handle it once, correctly:

- Store the session in an approved local secret store, then put only its **reference** in
  `accounts.md` under the named principal it represents (`user-a`, `admin`, whatever it is).
  If that principal already exists, update the reference and capture date — a stale token is
  diagnosed as stale, not mistaken for a fixed vulnerability.
- Everywhere else — the entrypoint row, the artifact, the PoC — the request is stored with the
  token **replaced by a placeholder plus a pointer**: `Cookie: SID=<accounts.md:user-a>`.
- **Never echo the value** into a log, a summary, a report, or the transcript.

## 3. Read the request as a source→sink model

Do not skim it for parameter names. Answer the six questions from
`playbooks/vulns/_playbook-shape.md`:

- **SOURCE** — every part you control: path segments, query, body, headers, cookies, the
  `Content-Type`, and the *names* as well as the values.
- **FEED** — what stands between this request and the handler: a CDN, a WAF, an API gateway, a
  version prefix, a body parser, a transcoding layer.
- **SINK** — what the operation actually does. A read? A write? A state change? Does it name an
  object belonging to someone else? Does it move money?
- **CONTEXT** — which principal sent it, and what the server assumes about them because of it.
- **What is missing** — a CSRF token? an idempotency key? a tenant id where you would expect one?
  Absences are as informative as fields.

**Transport matters for addressing, not for the bug.** A GraphQL mutation, a gRPC method and a REST
route are the same reasoning; see `investigate-graphql.md` / `investigate-grpc.md` for recovering
the contract, and `_master-vuln-hunting.md` §"the transport is not the class".

## 4. Derive the properties, then the classes

Assign properties from the **closed vocabulary** in `playbooks/system/class-signals.md` — only what
you can actually observe in the request:

| you see in the request | property |
|---|---|
| an id, uuid, slug, path segment or opaque blob naming an object | `object-ref` |
| **two** objects named (transfer, share, assign, invite, add-to) | `two-object` |
| an org / workspace / tenant id | `multi-tenant` |
| a JSON/form/protobuf body that appears bound to a model | `mass-bind` |
| a value you expect to see echoed back | `reflects` |
| a filter, sort, search or lookup parameter | `db-query` |
| a URL, callback, webhook or import source | `fetches-url` |
| a filename or path | `file-path` |
| a multipart upload or file body | `file-upload` |
| an archive that the feature unpacks | `archive` |
| a `next` / `return_to` / redirect target | `redirect` |
| a username, email or phone | `identity-input` |
| a price, quantity, currency, coupon or balance | `money` |
| a step / status / state field | `state-machine` |
| an operation that creates, updates, deletes, sends, or submits | `state-changing` |
| `Set-Cookie`, a bearer, or a token being issued | `session-issue` |
| a browser-attached cookie authenticates the request | `ambient-session` |
| OAuth/OIDC/SAML parameters or an SSO callback | `oauth` |
| an OTP, quota, invite or attempt counter | `per-request-limit` |
| an operation whose invariant may fail under parallel calls | `state-changing` plus `per-request-limit`, `money`, `bulk-operation` or `async-job` — whichever you can actually observe. `concurrency` was removed from the vocabulary: it was true of every state-changing request and so selected nothing |
| `Origin`, `Referer`-dependence, or a WS upgrade | `cross-origin` |
| a WebSocket upgrade | `websocket` |
| `Age`, `X-Cache`, `CF-Cache-Status` on the response | `cacheable` |
| attacker input affects a response but is absent from the observed cache key | `unkeyed-input` |
| an observed response value is built from `Host` / `X-Forwarded-*` | `host-header-trusted` |

Resolve those to candidate classes through `class-signals.md`. **Rank them** by how directly the
request evidences the property — an explicit `order_id` in the path is stronger evidence for
`idor-bola` than a generic `q=` is for `sql-injection`.

Say plainly what you **cannot** tell from the request alone. A single request rarely reveals whether
the value reaches a template, whether the response is cached, or what a second principal would see.
Those are hypotheses to test, not properties to record.

## 5. Record it as a real entrypoint

**This is what keeps coverage honest.** Write one row per candidate into `attack-surface.md`:

```
| rank | entrypoint | vuln_class | principals | variants | properties | exposure | sensitivity | tech_risk | dynamism | dup_likelihood | linkage | score | why (source→sink) |
```

The entrypoint is the **method + path** (`POST /v3/merchants/{mId}/orders`), not the full URL with
values. `principals` names the captured account plus `unauth` or other controlled accounts needed
for the candidate's differential; an unavailable required account remains a blocked cell rather
than disappearing. `why` carries the source→sink reasoning in one line. Score with the six-signal model from
`attack-surface-prioritization`, **on request only** — the ranking is coarse here because there is no recon behind
it, and that is fine; say so rather than inventing precision.

An entrypoint that never lands in `attack-surface.md` is invisible to `tools/coverage.py` — which
means "what haven't I tested" silently stops describing reality. That is the whole reason this step
exists rather than jumping straight to testing.

## 6. Hand off

Present the ranked candidates with one line of reasoning each, and **stop**. The human picks.

Then it is an ordinary `vuln-hunt` run: `_master-vuln-hunting.md` + the one class file, Test →
Confirm → Validate against an oracle declared before you look, artifact stored, row in `tested.md`
as `(entrypoint × class × principal × variant)` with its `fix_locus`.

**Store the request itself** to `targets/<t>/raw/` now, credential placeholdered — it is the control
request every later test will be compared against.

## 7. Log it

- `attack-surface.md` — the candidate rows from §5.
- `accounts.md` — the principal from §2, if new.
- `scope.md` — only if the human authorized a host that was not listed.
- `targets/<t>/raw/<slug>-request.txt` — the pasted request, placeholdered.
- Nothing goes in `tested.md` yet. **Analysis is not a test.** A row there means a probe was sent.
