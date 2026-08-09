# Origin IP / Backend Exposure — the method

> **This is a test of your ability to find the origin behind the edge** for the asset the human
> names — the chain that reaches the backend directly, bypassing the WAF/CDN. Model **what the edge
> is supposed to be hiding and enforcing**, trace where the real IP leaks out of DNS history, mail
> records, certs or errors, and prove that reaching the backend directly bypasses the edge's
> protections. Mostly passive discovery, with careful non-flooding confirmation. Work it with
> `playbooks/vulns/_master-vuln-hunting.md`.

---

## 1. Model the edge before you touch anything

**SOURCE** — the leak channels that can name the backend: DNS history (`SecurityTrails`/`crt.sh`/
passive DNS) showing the pre-CDN A record; SPF/MX records or mail headers revealing the mail server
on the same host; `crt.sh` certificate SANs mapping to direct-hosted subdomains; server-status or
error pages echoing an internal IP; SSRF or verbose stack traces leaking it; a
`dev`/`staging`/`origin`/`direct` subdomain pointed straight at the backend; default vhost
responses; favicon/JARM/content hashes on services like Shodan/Censys matching the origin.

**FEED** — the CDN/WAF fronting the asset (Cloudflare, Akamai, Fastly, etc.). Tech signals from
`technologies.md`: edge headers (`CF-RAY`, `Server: cloudflare`, `X-Served-By`), a WAF challenge on
the main host — the very protection you are bypassing.

**SINK** — the origin backend itself, reached with the real `Host` header and TLS SNI.

**CONTEXT** — the discriminator is **what the edge is supposed to be hiding, and what it enforces
that the origin doesn't**: WAF filtering, rate limiting, DDoS absorption, IP/geo allowlisting, auth
at the edge. Exposure only matters if bypassing the edge *gains* you something — reaching a blocked
path, dodging a WAF rule, defeating a rate limit. Second question: is the origin **firewalled to
accept CDN IPs only** (the correct config)? If so, the leak is informational, not exploitable — say
so.

**ROOT CAUSE** — the specific leak vector (DNS history, mail records, cert SANs, an error page, a
direct-pointed subdomain, SSRF) **plus the missing origin firewall** that lets the leaked address be
used. **That answer is your `fix_locus`** — record both halves, so distinct issues count separately.

## 2. Derive the candidates — passive first

1. **Establish that there is an edge to bypass** and what it enforces, from the response headers and
   the challenge behaviour.
2. **Work the passive leak channels in order of cost**: DNS history, cert SANs, SPF/MX, then
   fingerprint matches on services like Shodan/Censys. Passive DNS plus one confirming request is
   the whole footprint.
3. **Look for hosts that were never behind the edge**: `dev`, `staging`, `origin`, `direct`
   subdomains, and acquired infrastructure that nobody re-fronted.
4. **Note the leaks that come from the app itself** — server-status pages, verbose stack traces,
   SSRF responses — since those are the non-obvious ones where dups are rare.

## 3. Determine the context — before you touch the candidate

- **Name what the edge blocks**, concretely: a WAF-rejected marker payload, a rate-limited endpoint,
  an IP/geo rule, an edge auth control. Without a named protection there is no impact to prove.
- **Baseline the edge-served response**: body hash, unique markers, `Set-Cookie`, app-specific
  content.
- **Check whether the candidate is plausibly the backend at all** — a CDN IP, a shared-hosting
  address or a parked host is not.

## 4. Test → Confirm → Validate

**TEST — one direct request.** Request the candidate IP with the correct `Host` header
(`curl --resolve host:443:<ip>` or `-H 'Host: ...'`), over TLS with proper SNI. **Outcome: a
hypothesis.**

**CONFIRM — the default oracle is response identity**: compare body hash, unique markers,
`Set-Cookie` and app-specific content against the edge-served version. **Same app + no edge =
confirmed origin.** The oracle lies when:
- the IP is a **stale DNS-history address** that no longer hosts the app (parked or reassigned) —
  verify it serves the *current* app before claiming it;
- it is a **shared-hosting or load-balancer IP** returning a default or `403` vhost page for every
  `Host` — that is not the origin;
- the origin correctly **allowlists CDN IPs only**, so your direct request is refused — the IP is
  "known" but not reachable; that is informational, downgrade the impact;
- you matched a **CDN** IP rather than the backend, and are still hitting the edge;
- a `staging` host looks like the origin but is a separate, isolated environment.

**VALIDATE — one benign protection bypass.** A request the WAF blocks at the edge (a harmless marker
payload) succeeding against the origin, or an edge-rate-limited endpoint answering without the
edge's limit — a *single* request each, just enough to show the edge is bypassable. Direct origin
access **nullifies the edge**: WAF-filtered attacks land unfiltered, rate/auth/geo controls are
skipped, and the backend is exposed to targeted DoS. On its own, exposure is often
*informational→low* unless a concrete bypass is shown — the impact comes from **what the edge was
blocking**. Chains: origin exposure + a WAF-blocked injection (`sql-injection.md`, `xss.md`) → the
block evaporates; + edge-only auth or allowlisting → unauthenticated backend access; + request
smuggling or host-header routing for deeper reach.

## 5. Safety, artifact, and PoC handoff

- **Never launch load or volume against the origin.** Bypassing the CDN removes the DDoS cushion, so
  flooding it is a real outage.
- **Never run a full exploit through the origin** just to prove the point, and **don't brute-force
  whole IP ranges noisily.** Passive DNS plus one confirming request is the footprint.
- Confirm identity by **comparison, not by attacking**.
- **Store the artifact**: the two responses (edge versus direct-IP with `Host`) and the single
  bypass demonstration. **No artifact → HYPOTHESIS.**
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): the `curl --resolve` command **with
  its edge-served control request**, plus the one blocked-at-the-edge request that the origin
  answers. Announce and budget the confirmation step — it is the loud part of an otherwise passive
  class.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the
`fix_locus` from §1 recorded as **leak vector + missing origin ACL**. Log negatives with the oracle
used — "IP known but CDN-allowlisted" is a valuable negative, not a blank. **Dedup:** "I found your
Cloudflare origin IP" with no demonstrated bypass is a low-value, often-duplicated informational
report, and many programs consider it out of scope or already known. Novelty lives in **pairing** the
exposure with a *concrete* protection bypass (a WAF rule or auth control that exists only at the
edge), origins exposing **internal-only apps or admin panels**, and origins reached via
**non-obvious leaks** (SSRF, SPF/mail, cert SANs) on acquired infrastructure.

## 7. Worked example — the spine in one pass

*Model:* the main host is behind Cloudflare (`CF-RAY`, a WAF challenge per `technologies.md`), so the
edge is hiding the backend and enforcing WAF filtering and rate limits. *Derive:* passive DNS history
(`SecurityTrails`/`crt.sh`) shows a pre-CDN A record and the MX/SPF points at the same IP — a
plausible origin leak, discovered passively. *Context:* exposure only matters if bypassing the edge
*gains* something, so note what the edge protects first; then the discriminator for identity is
whether that IP *serves the same app* when I send the real `Host` — a shared-host IP that 403s every
`Host` is not the origin. *Hypothesis:* the leaked IP is the true origin and is not firewalled to
CDN-only, so it answers directly and skips the WAF. *Confirm:* one `curl --resolve host:443:<ip>`
with correct SNI/`Host`, comparing body hash, `Set-Cookie` and unique markers to the edge-served
version; a match = origin. Then **one** benign request that the edge WAF blocks but the origin
answers. No volumetric load — that removes the DDoS cushion — and no IP-range brute force. *PoC:*
edge-versus-direct responses plus the single bypass. *fix_locus:* DNS-history leak + missing origin
ACL — "I found your origin IP" alone is a dup or informational; pairing it with a concrete WAF-rule
bypass is the novelty.
