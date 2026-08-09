# Cross-Site Scripting (XSS) — the method

> **This is a test of your ability to run script in another principal's context** via the input the
> human names. Three questions decide every XSS, in this order: **where does my value end up**
> (which may be nowhere you can see), **what does it need to execute there**, and **how do I get a
> victim to that state**. The third is not an afterthought — for reflected XSS in the corpus it is
> often *the whole finding*. Reason about the flow; don't spray `<script>alert(1)</script>` at every field. Prove
> execution with a harmless marker. Work this with `playbooks/vulns/_master-vuln-hunting.md`.

**Read this file every time.** Technique catalogues live in **`ref/xss.md`** — open a section only
when its trigger fires:

| you observe | open `ref/xss.md` § |
|---|---|
| It reflects, but you can't make a victim send it | **X1** delivery primitives — the reflected-XSS bottleneck |
| Your value is stored and you can't see it render | **X2** enumerate the consumers |
| The value never touches the server | **X3** DOM sources, sinks, and the trust check |
| You need to know what breaks out of a given context | **X4** contexts & encoding failures |
| A filter, WAF or sanitizer is in the way | **X5** bypasses |
| A CSP is blocking your payload | **X6** CSP is per-endpoint, and gadgets beat it |
| Nothing hits the server — what do you even attach? | **X7** proving execution, and the artifact problem |
| It looks clean and you're about to move on | **X8** false negatives |
| Judging severity or duplication | **X9** safety & ethics · **X10** novelty |

---

## 1. Model the flow before you touch anything

**SOURCE** — where attacker-controlled data enters. Far wider than the request: query/path/body/
headers/cookies · client-side `location.*`, `document.referrer`, `window.name`, `postMessage` ·
**and, in the corpus, also** a filename, a clipboard MIME type, `localStorage` the site's own JS
wrote, a cookie a sibling origin set, an OG tag on a page you host, a JSON/RSS/SVG document the page
fetches from a host you choose, an import archive, an Android Intent extra, and an ad or extension
running in the origin (**X3**).
*Not from the corpus, from mechanics:* a value the page renders out of a **GraphQL response or a
WebSocket frame** is the same source, and reaches the DOM without ever appearing in an HTML
response you can grep for a marker.

**FEED** — every hop between source and screen, because each can encode, decode, mangle or
re-parse: framework binding · a sanitizer · a markdown/rich-text pipeline · **storage** · an export
or email renderer · a second parser. The bug is often in a transform that runs *after* the
sanitizer.

**SINK** — where it becomes markup or script. Not only `innerHTML`/`document.write`: a
`javascript:` URL assigned to `location`/`href`/`src`/`window.open`, a template compiler, a
sanitizer's own scratch element, `Function`/`eval` reached through a polluted prototype, response
headers that make an upload render as a document.

**CONTEXT** — the discriminator, and it differs by variant:

| variant | the gap that makes it exploitable |
|---|---|
| **reflected** | you can reach the sink, but **can you make a victim's browser send it?** Delivery is usually the hard half (**X1**) |
| **stored** | the value renders in **a surface you didn't inject into and often can't see** — an export, an email, an admin panel, another role's view (**X2**) |
| **DOM** | when the sink is a `postMessage` handler, the **trust check** — the origin test — is usually the bug rather than the sink; more broadly, a scheme check or host comparison is a first-class suspect (**X3**) |

Also ask, always: **what activation does this context require** — a click, a hover, an `accesskey`
chord, a middle-click, a second page load — and **which browser**. Several corpus bugs execute in
exactly one engine.

**ROOT CAUSE** — one of: no encoding at all in a non-templated corner (an error renderer, a vendored
example file, a debug echo) · the wrong encoder for the context · a *validator* with a semantic gap
(substring instead of prefix, a schema missing live keys) · a post-sanitization transform that
re-opens the injection · a parser differential · a missing scheme allowlist on a URL · an origin
check that isn't one · response headers that make content render. **That answer is your `fix_locus`.**

## 2. Derive the candidates

1. **Read the client bundle.** The single most productive move in the corpus. Grep for sink names,
   `addEventListener("message"`, `URLSearchParams`/`query.get(`, and `switch` on a URL param —
   parameters the UI never sends, and whole hidden render branches, live there.
2. **Fuzz names and keys, not just values** — a multipart field *name*, a JSON property name, a
   prototype key.
3. **For stored: plant a unique marker, then go hunting for where it surfaced** — exports, emails,
   notifications, admin views, PDFs, logs, another role's page. Enumerate consumers; do not assume
   the render site is the injection site (**X2**).
4. **For DOM: work sink → source.** Find the dangerous call, then trace backwards to what feeds it,
   then ask what checks sit in between.
5. **Fingerprint embedded components and third-party scripts.** A version + a CVE tells you a bug
   exists; you still have to locate the input yourself. Audit every `<script src>` you don't own.
6. **Check the shipped artifact, not the repo** — vendored `examples/` and demo pages get built into
   releases after being deleted from source.

## 3. Determine the context — before you write a payload

- **Send a benign marker and find every place it lands.** One value often reflects into several
  contexts on one page; a payload must be valid at whichever one executes first.
- **Read what encoding actually ran** — and test both quote characters independently. An app that
  escapes `"` and not `'` reads as sanitized.
- **Establish the activation** the context needs before assuming it's unexploitable.
- **Check CSP on the exact vulnerable path**, not on `/` (**X6**).
- **Note the browser** you're testing in, and plan to re-test in at least one other engine.

## 4. Test → Confirm → Validate

**TEST — does my input reach a sink?** A marker in the response, in the stored object, or observed
at the sink via a breakpoint. **Outcome: a hypothesis** — reflection is not execution, and for DOM
and `javascript:`-URL sinks there may be **no reflection at all**.

**CONFIRM — the oracle is execution in the target's origin, plus a delivery path.**
1. **Execution**, shown with a harmless marker that proves the *origin* (`alert(document.domain)`
   beats `alert(1)`), or an equivalent inert signal — a callback, a same-origin request, a console
   error proving the markup parsed.
2. **Delivery** — and this is a first-class part of the finding, not a footnote. A reflection you
   cannot deliver is an open sub-problem, not a dead end (**X1**). **"Self-XSS" means the victim
   must paste it into their own session.** A POST-only reflection on a form with no CSRF token, a
   framable page, a clipboard write, a delegation feature, a login-CSRF — all of these are delivery,
   and all of them turned "self-XSS" into accepted findings in the corpus.
3. **The right principal.** For stored bugs, the interesting execution is often in a role you cannot
   observe from your own account (**X2**, **X7**).

**VALIDATE — the least that proves impact.** Prefer a marker over a live payload. Where cookies are
`HttpOnly`, pivot to a same-origin action — read a CSRF token and perform one privileged request —
rather than claiming theft you can't do. If CSP blocks script, ask what *markup alone* achieves
here: an off-origin form, a meta-refresh, a full-viewport overlay (**X6**). That is a real finding,
not a consolation prize.

## 5. Safety — this corpus repeatedly does what we will not

Multiple reports in this corpus fired live payloads at **real, non-consenting people** — a blind
payload in a stranger's admin mailbox, live fake login forms left on public wiki pages, a claimed
abandoned S3 bucket other tenants also referenced, a production CDN asset overwritten. **Do not
imitate any of it.**

- **Never fire at a real user, admin or support agent.** Two of your own accounts, or a local
  instance. If you don't know where a stored value renders, that is a reason to use an **inert**
  marker (a `console.log`, a DNS callback, a same-origin 404) — not a reason to use `alert`.
- **Keep stored payloads inside objects you own and can delete**, prefer private objects, and remove
  them after triage. Never leave a live payload on a public multi-tenant page.
- **Never claim an abandoned third-party namespace** (an S3 bucket, an expired domain) whose other
  consumers you haven't enumerated — you may be taking over other people's sites.
- **Never overwrite a shared or production asset** to demonstrate a bug.
- **Store the artifact.** For DOM bugs nothing may hit the server, so the artifact is the code path:
  the sink line, a stack trace, a self-contained attacker page, and any **server-visible
  consequence** the payload caused (**X7**).
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): the request or attacker page in Burp
  Repeater or as a copy-pasteable file, the browser and version, and the exact activation required.

## 6. Log it

`targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` — principal matters enormously here,
because stored XSS frequently renders only for a role you don't hold. Record the `fix_locus` from
§1, and log negatives **with the browser and the surfaces you checked** — "not vulnerable in Chrome
on the page I injected into" is a different claim from "not vulnerable". Novelty: **X10**.
