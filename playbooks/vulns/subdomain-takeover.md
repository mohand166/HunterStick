# Subdomain Takeover — the method

> **This is a test of your ability to claim a dangling host** the human names — the chain that lets
> you serve content on the target's own name. Model the DNS record down to the third-party resource
> it points at, understand whether that resource is still owned or *unclaimed*, and find where the
> binding broke. A dangling record aimed at an unclaimed provider resource lets you claim it. The
> recon candidates already live in `recon/dns.md` — you are *confirming and safely claiming*, not
> re-scanning. The value is a demonstrated claim you hand straight back, plus the trust chain it
> unlocks. Work this with `playbooks/vulns/_master-vuln-hunting.md`.

---

## 1. Model the binding before you touch anything

**SOURCE** — the DNS record in the target's zone: a `CNAME`, `A`, `NS`, `MX`, or an `SPF include:`.

**FEED** — the resolution chain that record starts. Follow every hop: a `CNAME` may chain through
intermediates, and an *intermediate* hop can be the unclaimed one even when the last hop looks fine.

**SINK** — the third-party resource the chain lands on: an S3 bucket, a CloudFront distribution, a
GitHub/GitLab Pages site, an Azure resource (`*.azurewebsites.net`, `*.trafficmanager.net`,
`*.blob.core.windows.net`), Heroku, Fastly, Netlify, Vercel, Shopify, Zendesk, Fastmail, Surge,
Read the Docs, Tumblr, Cargo, Helpscout, and others — or a mail/SaaS tenant.

**CONTEXT** — the discriminator is **what the dangling record points at and whether that provider
lets you claim it**. Two independent questions, and you need a yes to both:

| question | how you answer it |
|---|---|
| does the record still point at a resource that no longer exists? | resolve the chain and read the provider's response: `NXDOMAIN`, `NoSuchBucket`, "There isn't a GitHub Pages site here", a 404 carrying the provider's claim banner |
| is that resource **actually claimable by you**? | match the response against the known service fingerprint (EdOverflow's can-i-take-over-xyz list) — some 404s are the app being down while the account is still owned, which is *not* takeover |

**Record type sets the blast radius**, so record it: a web `CNAME` gets you a page; a dangling **NS**
delegation gets you the whole zone; a dangling `MX` or `SPF include:` gets you mail as the domain.

**ROOT CAUSE** — a resource was decommissioned at the provider and the DNS record pointing at it was
never removed. Name *which* record and *which* provider. **That answer is your `fix_locus`** — the
specific dangling record, so distinct hosts count separately.

**Scope first.** Confirm the host is in `scope.md`, and that claiming it cannot disrupt a real,
still-owned service. **Ambiguous ownership → stop and ask.**

## 2. Derive the candidates — start from recon, not from a scan

1. **Start from `recon/dns.md`** (from dns-analysis): every host → dangling target → suspected service is
   already logged as a HYPOTHESIS. This file turns those candidates into confirmed findings; you
   rarely start from zero.
2. **Prefer the non-obvious surface — that's where dups are rare:** dangling **NS** delegation
   (full-zone takeover), `MX` / `SPF include:` pointing at an unclaimed mail or SaaS tenant (email
   spoofing), `CNAME` chains where an *intermediate* hop is unclaimed, and **acquired-company or
   freshly-discovered** hosts whose SaaS was decommissioned but whose DNS was not.
3. **Look past web records.** Most candidate lists are web `CNAME`s only; the mail and delegation
   records are the under-tested half of the same zone.

## 3. Determine the context — resolve before you register

Cheap and safe; nothing is claimed yet.

- **Resolve the full chain** and record every hop, not just the final answer.
- **Fetch the provider host** and capture the exact body — the claim banner is the fingerprint that
  discriminates *claimable* from *merely down*.
- **Match the fingerprint** against the known takeover signature for that service before concluding
  anything.
- **Re-resolve against a trusted resolver** and corroborate, so you are not reading a cached or stale
  answer.
- **Check for wildcard / catch-all DNS** on the zone (see dns-analysis), which makes arbitrary names
  resolve to unrelated infrastructure.

## 4. Test → Confirm → Validate

**TEST — does the record dangle?** The chain resolves to a provider resource returning an unclaimed
signature. **Outcome: a hypothesis** — and often a strong enough one to stop at (see §5).

**CONFIRM — can *you* claim it?** The **default oracle is the target's own subdomain serving content
you control**: register the specific resource the dangling record names — the S3 bucket of the exact
missing name, the GitHub Pages repo with the matching CNAME — under **your own** provider account,
serve one innocuous proof file, then fetch `https://<sub.target>/…token…` and capture the target name
resolving to your content. Nothing short of that fetch is confirmation.

The oracle inverts or lies here — rule each out:

- **404 ≠ takeover.** Many providers 404 for a still-owned-but-empty resource; only a *claimable*
  fingerprint counts. Verify against the service's known takeover signature.
- The provider has since **blocked same-name re-registration** (S3 and others added protections) —
  the record dangles but cannot actually be claimed; that is not a takeover.
- **Wildcard DNS / catch-all** makes the name resolve to unrelated infrastructure.
- The resource is **owned by the target on a different account** — down, not takeoverable.
- A **shared CNAME to a live multi-tenant host** where you cannot control your vhost.
- A **cached or stale resolver answer** — re-resolve against a trusted resolver and corroborate.

**VALIDATE — the least that proves impact.** The token file fetched over the target name is the
whole proof. Severity comes from the chain, not the page: arbitrary content on a trusted subdomain →
convincing phishing, and where the parent domain scopes cookies, CORS, `postMessage` or an OAuth
`redirect_uri` to `*.target`, escalate to **session theft, auth-flow abuse or same-site trust
bypass**. Dangling NS → whole-zone control. Dangling `SPF include:`/`MX` → send and receive mail as
the domain. Chains: takeover → cookie scoped to the parent domain → session hijack; → OAuth
`redirect_uri` allowlisting `*.target` → token theft; → CORS/`postMessage` origin trust → data
exfiltration. **The takeover is the primitive; the chain is the severity** — argue the chain, don't
execute it against real users.

## 5. Safety, artifact, and PoC handoff

- **Claiming infrastructure is the dangerous part of this class.** Serve a single **innocuous proof
  file** — a plain page or text with a unique token and your contact
  (`bugbounty-poc-<token>.txt`) — no JS, no cookies, nothing that interacts with real users.
- **Do not** serve malicious content, capture visitor traffic or cookies, phish, or leave the claim
  up longer than needed. **Release it after evidence and say so in the report.** The name belongs to
  the target; you are holding it only long enough to prove it was holdable.
- **If claiming would be intrusive, or ownership is uncertain, stop at the fingerprint** — dangling
  record plus provider unclaimed banner is a strong HYPOTHESIS. Get human go-ahead before claiming,
  per `dns-analysis` and the system safety rules.
- **Store the artifact** under `targets/<t>/raw/`: the DNS record and full chain, the provider's
  "unclaimed" fingerprint, and (post-claim) the target subdomain serving your token file.
  **No artifact → HYPOTHESIS, not FACT.**
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): the resolution command and the
  copy-pasteable `curl` against the target name that returns your token, plus the pre-claim control
  showing the provider banner — reproducible in one action.
- Respect the rate limit; mass re-resolution across a large zone is a **loud** activity — budget it
  and announce it first.

## 6. Log it

Every candidate goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with `result`,
`coverage` and the **`fix_locus` from §1** — the specific dangling record, so distinct hosts count
separately. Log negatives *with the oracle used* ("fingerprint matched but provider blocks re-
registration" is a different negative from "record resolves to a live tenant").

**Novelty.** A dangling `CNAME` on a mainstream program's obvious host is frequently already
reported or already reclaimed. Novelty lives in **NS/MX/SPF** takeovers rather than web `CNAME`s,
**intermediate-hop** dangles in a chain, **acquired-company or freshly-discovered** hosts, and
takeovers whose real value is a **cookie/OAuth/CORS chain you actually demonstrate** rather than a
bare "I can host a page".

## 7. Worked example — the spine in one pass

*Model / derive:* `recon/dns.md` logged `docs.acquired-co.target` as a HYPOTHESIS — a `CNAME` to a
`*.github.io` Pages host returning "There isn't a GitHub Pages site here"; an acquired-company host
still in `scope.md`, from recon's acquisition sweep rather than the flagship domain. The record
dangles at an unclaimed Pages repo.
*Context:* that 404 banner is GitHub's *claimable* fingerprint, not a generic app-down 404 — matched
against the known service signature, and re-resolved against a trusted resolver.
*Hypothesis:* the Pages repo the record names is unregistered and claimable by me.
*Confirm:* create that Pages repo under my own account with the exact CNAME and serve one innocuous
`bugbounty-poc-<token>.txt` (no JS, no cookies, no visitor capture); fetch
`https://docs.acquired-co.target/…token…` and capture the target name serving my content — then
**release the claim**. Artifact = the DNS chain, the unclaimed fingerprint, the served token page.
*Novelty:* obvious CNAMEs on the flagship domain are reclaimed or reported; an acquired-co host whose
DNS was never cleaned up is the finding — `fix_locus = docs.acquired-co.target dangling CNAME`.
