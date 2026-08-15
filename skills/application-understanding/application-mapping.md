---
name: application-mapping
description: What this application *does*, who may do it, and where the oracle is. Use for "application mapping" and closely related asks.
---

# application-mapping — what this application *does*, who may do it, and where the oracle is

> Read `skills/shared/_recon-method.md` first — it holds the loop, the input rule and the tool contract.
> This file holds what is specific to mapping one application.
>
> **This is a test of your ability to describe a product as a set of operations, principals and
> boundaries.** The value is not a sitemap or a screenshot tour. It is the four things nothing else
> in recon can produce: the features that do dangerous work on your behalf, the state machines, the
> gap between what the API supports and what the UI invokes, and — when principals exist — a
> principal diff that tells you what *should* have been denied.

## Objective

Map one application: its features, its flows and state machines, its trust boundaries, and the
operations it exposes versus the operations it uses. Produce a per-app map a hunter can attack from,
and be explicit about which conclusions the available principals could and could not support.

## Inputs

**Enrichment — each absent one narrows the run, none of them gates it:**

- `@js` (optional, from `javascript-analysis`) — the route table and the client's call sites. **The
  chunk and route table names routes with no reachable UI**, and the delta between declared routes and
  UI-reachable routes is a deliverable in its own right.
- `@endpoints` (optional, from `api-discovery`) — the operation set. Without it you can still map
  from traffic; with it you get the surface diff in signal 4 for free.
- `@app.current` (optional) — a previous map selected from the exact `@hunter.host`, so this run
  reports what changed without loading a sibling application.
- `@accounts` (optional, from `init-target`) — principals. **Not a gate on this skill.** See below.

**As the selector, at least one of the following:**

- `@hunter.host` — an application the hunter named. Sufficient on its own: this skill runs
  unauthenticated, and public flows, registration, password reset, client routes, API shape and
  visible state machines are all mappable from one host.
- `@hosts.live` (from `http-probing`) — pick the application from the live set instead.

## Accounts: an input for part of this, never a gate on the whole

Run this skill with no account at all. Unauthenticated you can map: every public flow, registration
and its validation rules, password reset, the client-side route table including routes no menu
links to, the API's shape and its error behaviour, which operations answer without a session and how
they refuse, the visible state machines, and every feature in signal 1 that is reachable before
login. That is most of the map, and it is what makes the rest cheap when a principal arrives.

Two specific conclusions require principals, and there the rule is hard:
**two accounts is the minimum viable configuration, and two *organisations* is what finds P1s.**
With one account there is no oracle for "this should have been denied", so BOLA, BFLA, cross-tenant
leakage and invite/role escalation cannot be concluded either way. **A single-account "no finding"
on BOLA is a false negative dressed as a result — mark it *unverifiable*, never *clean*.** This is
reasoned from the mechanism rather than measured, and the mechanism is airtight: a comparison needs
two things to compare.

When you reach one of those steps without the principals it needs, say exactly that at that point —
"the role matrix needs a second account in a second org; I have one" — and stop that branch. Then
carry on with the rest of the map. Do not present accounts as a precondition for the skill.

## Signals — what to come back with

1. **Features classified by what they do with data, not by what they are called.** The ones that
   have their own hit rates:
   - **Anything that fetches a user-supplied URL** — webhooks, importers, "preview this link",
     avatar-from-URL, SSO metadata fetch, PDF-from-URL. Record two properties per feature, because
     they decide severity entirely: **does it follow redirects**, and **does it return the body**
     (blind versus full-read).
   - **Any document, PDF, preview or thumbnail generator** — the highest hit-rate single feature
     type there is; the renderer is a parser that honours `file://`, metadata IPs and template
     syntax.
   - **AI/LLM-backed features** — the fastest-growing surface and absent from most recon. Valid AI
     findings rose **210% year on year** and prompt injection **540%** across 580k+ validated
     vulnerabilities. Map every place user text reaches a model, every tool or action the model can
     invoke, and every place model output is rendered or executed.
   - File upload and its storage/serving origin · import and export · impersonation and
     "log in as" · billing, credits and quota · sharing, invites and public links · webhooks
     outbound · anything that emails or messages a third party.
2. **The state machines.** Order → paid → shipped → refunded. Invite → accepted → member → removed.
   Draft → submitted → approved. Trial → active → cancelled. For each: the states, the legal
   transitions, who may cause each, and **which transitions are enforced server-side versus merely
   not offered by the UI**.
3. **The surface diff — the BFLA list.** **The gap between the operations the API supports and the
   operations the UI actually invokes IS the BFLA list.** Compute it: operations from `@endpoints`
   and the route table, minus operations observed in captured traffic during a full UI walk. Every
   row is an operation someone built and nobody exercises.
4. **The role matrix, built by DIFF rather than enumeration.** Walk every screen as the **lowest**
   role while capturing traffic, then walk it as the **highest**. The diff is the BFLA test list.
   That is O(2 walks), not O(roles × endpoints) — the enumeration version of this is why role
   matrices usually get abandoned half-built. (Needs two roles; see the accounts section.)
5. **The tenancy model.** Where the tenant identifier lives — subdomain, path, header, token claim,
   or nowhere visible. Which objects are tenant-scoped and which are global. Whether a user can
   belong to two tenants, and what happens at the seam. Cross-tenant conclusions need two orgs.
6. **Invites, sharpened.** *"Anything with an invite is a bug"* is too loose to act on. The four
   questions are: **who may invite · what role may be assigned · is the token bound to the invited
   email address · is it revoked when the member is removed.** Answer all four or say which you
   could not.
7. **Trust boundaries.** Where the app hands off to another origin, another service, a third-party
   embed, a payment provider, a support widget, a CDN-served bundle. Each boundary is a place two
   systems must agree, and each is where the interesting failures live.
8. **The routes with no reachable UI**, listed separately from the sitemap. They are the highest-
   value rows in this whole output because nobody clicked them into existence during QA either.

## Known traps

- **Concluding "no BOLA" from one account.** Covered above and repeated here because it is the
  single most common false result this skill produces. Unverifiable is an honest answer; clean is a
  lie the hunter will act on.
- **Status codes as authorization truth.** A 200 with an empty array, a 403 that still performed the
  write, a 404 that means "exists but not yours", a **500 meaning the handler ran before any auth
  check**. Diff bodies and side effects, not codes.
- **A crawler in an authenticated application is a destructive tool.** It will send invitations,
  delete objects, cancel subscriptions, generate invoices and email real people. Walk the app
  deliberately, or bound the crawler to safe methods and say what you bounded.
- **Mapping in a shared or production tenant affects real users.** Prefer your own org. Where the
  program supplies a shared test tenant, treat other people's objects as out of bounds even when
  they are reachable — reachability is the finding, not the licence.
- **Client-side plan gating is usually low bounty.** Report it when the gated feature is *itself* a
  security boundary — SSO enforcement, audit logs, IP allowlist — not for "export to CSV". This is
  judgement about triage, not a measured payout rule.
- **The UI walk is not the surface.** A map built only from what the UI does reproduces exactly the
  paths QA already covered. Signals 3 and 8 exist to break that, and a run that skips them has
  produced a user manual.
- **"The API supports it" needs evidence, not inference from a path name.** Inferring privilege from
  a URL path is the error OWASP explicitly warns against; an operation belongs in the surface diff
  because a spec, a schema, a route table or captured traffic witnessed it.
- **AI features are easy to map shallowly.** "There is a chatbot" is not a map. What can the model
  read, what can it call, whose data is in its context, and where does its output land.

## Outputs

- `@app.current` — `applications/<host[-port]>/`: `map.md` (features, roles, trust boundaries, state machines,
  auth flow), `endpoints.md` (app-specific operations, including ones the UI never invokes),
  `notes.md`. Resolve or create it with `tools/app-context.py ensure targets/<t> <host-or-url>`;
  never copy the template by guessing a directory name.
- `@endpoints` — operations discovered here that the API inventory did not have.
- Facts via `kb.py add`: the tenancy model, the role set, each URL-fetching feature with its two
  properties, each renderer, each AI-backed feature, the invite answers.
- Leads into `@hypotheses`: every row of the surface diff, every route with no reachable UI, every
  SSRF-candidate feature, every state transition enforced only in the client, every invite question
  that answered badly.
- **A coverage statement naming which conclusions the available principals could not support.**

## Exit criteria

The feature inventory covers signal 1's categories or explicitly says a category is absent. The
state machines are written down with their transitions. **The surface diff exists as a list** — if
`@endpoints` was unavailable, that is recorded as the reason rather than the diff being silently
skipped. Routes with no reachable UI are listed separately. Every conclusion that required a second
principal or a second org is either supported by one or marked unverifiable by name. The map is
specific enough that someone who has never seen the app could pick a target from it.

## Next

Offer: `derive-properties` (this is its richest input and the **only** source for the role, tenancy
and state-machine dimensions — without this map those properties are undetermined across the whole
surface) · `authentication-surface-mapping` (if the auth flows here were mapped only as far as the
app needed) · `api-discovery` (to close the surface diff where the operation set is incomplete) ·
`vuln-hunt` on a specific feature — the URL-fetchers, the renderers and the surface-diff rows are
already hypotheses.
