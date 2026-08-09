# CORS Misconfiguration — the method

> **This is a test of your ability to find a CORS misconfiguration** on the endpoint the human
> names — the chain that reaches cross-origin read of sensitive authenticated data. Model how the
> app derives its `Access-Control-Allow-Origin` from the request `Origin` and pairs it with
> credentials, then find where that derivation breaks. A permissive ACAO only matters if it lets a
> *foreign origin read a sensitive, credentialed response* — prove readability of real protected
> data; a lax header on a public endpoint is not a bug. Work it with
> `playbooks/vulns/_master-vuln-hunting.md`.

## 1. Model the trust relationship before you touch anything

**SOURCE** — the `Origin` request header you control, and (for the `null` case) the context that
produces it: a sandboxed iframe, a `data:` document, a redirect.

**FEED** — the code or middleware that turns that `Origin` into an ACAO value: an echo, an allowlist
comparison, a regex. Note any CDN/proxy in the path that may add or rewrite the header.

**SINK** — the response headers the browser enforces on: `Access-Control-Allow-Origin` (ACAO) and
`Access-Control-Allow-Credentials` (ACAC) — and, behind them, a body that is private to the victim's
session.

**CONTEXT** — the discriminator is **what the browser will attach and what it will then let script
read**. Three things must hold together, and the dangerous patterns are the ways they do:

- **Origin reflection** — ACAO echoes whatever `Origin` you send, *with* ACAC `true`.
- **`null` origin** — ACAO `null` + credentials, reachable from a sandboxed iframe / `data:` /
  redirect.
- **Weak allowlist regex** — `startsWith`/`endsWith`/substring/unanchored regex:
  `trusted.com.evil.com`, `evil-trusted.com`, `trusted.com` as a subdomain of yours.
- **Wildcard subdomains** trusting an origin you can get XSS or subdomain-takeover on.
- And the response must actually be **sensitive and credentialed**: if it returns the same public
  data with or without the session cookie, there is nothing to steal. Note ACAO `*` **with**
  credentials is rejected by browsers — `*` alone (no creds) is usually low/no impact unless the data
  is sensitive and unauthenticated.

**ROOT CAUSE** — the specific CORS policy that reflects, allows `null`, or matches loosely, paired
with a credentialed sensitive response. **That answer is your `fix_locus`** — the specific policy +
endpoint, so distinct misconfigurations count separately.

## 2. Derive the candidates — reason from what's worth stealing

1. **Start from endpoints returning session-scoped data over CORS**: API hosts (`api.`),
   account/profile, tokens/keys, `/me`, settings, internal JSON services, GraphQL.
2. **Rank by what the body carries** — an email, an API token, a CSRF token. The value of the bug is
   the field, not the header.
3. **Tech signals**: microservice APIs, SSO/token endpoints, permissive CORS middleware.
4. **Prefer newly-found or acquired hosts** the crowd hasn't hit; the flagship API is the contested
   surface.

## 3. Determine the context — fingerprint the allowlist first

Cheap, read-only, one request each — you are locating the matching logic, not exploiting it:

- Send `Origin: https://evil.example` and read ACAO/ACAC off the response.
- Probe the allowlist logic with `evil.com`, `victim.com.evil.com`, `eviltrusted.com`, `null`, a
  trusted subdomain, and `http` vs `https` — see which the server accepts. This is what reveals
  `startsWith` / substring / regex flaws.
- Fetch the endpoint **with and without** the session cookie and diff the bodies — that tells you
  whether there is anything private to steal before you build a PoC.

## 4. Test → Confirm → Validate

**Accounts gate:** you need a second principal you own to play the victim. Always victimize **your
own test account**, never a real user.

**TEST — does the header come back permissive?** The §3 probe: ACAO reflecting your origin (or
`null`). **Outcome: a hypothesis** — headers on the wire are not a browser read.

**CONFIRM — the default oracle is a real cross-origin `fetch` reading the private body**, backed by
the header proof. Two steps: **(1) header proof** — the request with an attacker `Origin` *plus*
credentials returns ACAO=attacker/`null` **and** ACAC=`true`; **(2) read proof** — a small
attacker-hosted page does `fetch(target, {credentials:"include"})` **using your own test account as
the victim** and logs the parsed response (e.g. your own email or token) to prove readability. Where
the oracle inverts or lies:

- **ACAO `*` without credentials on public data** → browsers won't send cookies; usually no impact.
  Don't report reflexively.
- **ACAO reflects your origin but ACAC is absent/`false`** → cross-origin JS can't read a credentialed
  response; impact limited to non-credentialed/public data.
- **The endpoint returns identical data with no session** → nothing sensitive to steal.
- **A CDN/proxy reflecting `Origin` in a way the actual browser fetch won't honor** — this is why the
  oracle is a real cross-origin `fetch`, not just `curl` headers.
- **Preflight allowed but the actual method/credentials still blocked server-side.**
- **Reflected `Origin` in a non-CORS header** (e.g. logged) mistaken for ACAO.

**VALIDATE — the least that proves impact.** Record only enough of the private field to prove it was
readable. Impact: cross-origin theft of session-scoped data — PII, API tokens, CSRF tokens, account
details — often **account takeover** (steal a CSRF token via CORS, then forge a state-changing
request; or steal an API key directly). Chains: CORS read of a CSRF token → CSRF on a protected
action; `null`-origin CORS reached via a sandboxed-iframe/redirect gadget; weak-regex CORS trusting a
subdomain you can take over or XSS. Escalate the minimum needed to show the private read.

## 5. Safety, artifact, and PoC handoff

- **Never** mass-harvest data or target real users' sessions. One request + one PoC fetch page
  against your own account is the whole proof.
- Redact the private field down to the fragment that proves readability.
- **Store the artifact:** the raw request/response showing the headers, **and** the PoC page plus its
  console output showing the cross-origin read. **No artifact → HYPOTHESIS, not FACT.**
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): the header request to **Burp
  Repeater** or as copy-pasteable `curl`, **plus** the self-contained HTML page performing the
  credentialed `fetch` — the page is the PoC, a prose description is not.
- Respect the program's rate limit; allowlist fingerprinting is a handful of requests, not a sweep.

## 6. Log it

`targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the `fix_locus` from §1 — the
specific CORS policy/endpoint. Log negatives *with the oracle used*: "ACAO reflected, ACAC false",
"identical body without session", "browser fetch blocked despite curl headers".

**Novelty:** plain "ACAO reflects Origin" scanner reports on a public endpoint are classic dups /
often-informational. Novelty is proving a **credentialed, sensitive read** (a real ATO path), a
**weak-allowlist bypass** (substring/regex/`null`) on an auth API, or CORS on a **newly-found or
acquired host** the crowd hasn't hit.

## 7. Worked example — the spine in one pass

*Model / derive:* recon found `api.target.com/v1/me` returning the logged-in user's email and a CSRF
token as JSON (`technologies.md`: microservice API with permissive CORS middleware) — a body worth
stealing.
*Context:* the question isn't "does ACAO reflect" but "can a foreign origin read a *credentialed,
sensitive* response". The discriminating probe pairs an attacker `Origin` *with* the session cookie;
if ACAO echoes my origin **and** ACAC is `true`, the browser will expose the body. Also test
`victim.com.evil.com` / `null` to fingerprint substring vs strict allowlist.
*Hypothesis:* `/v1/me` reflects `Origin` with credentials, so any origin can read the victim's email
+ CSRF token cross-origin.
*Confirm:* (1) header proof — request with `Origin: https://evil.example` + my own test account's
cookies returns ACAO=that origin, ACAC=true. (2) read proof — an attacker-hosted page does
`fetch('/v1/me',{credentials:'include'})` **against my own second test account** and logs just enough
of the email to show readability. Never a real user. Save raw headers + PoC console output.
*Dedup:* a proven credentialed sensitive read (real ATO path via the CSRF token), not a scanner "ACAO
reflects on public endpoint" dup — `fix_locus = CORS policy on /v1/me`.
