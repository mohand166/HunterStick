---
name: live-host-validation
description: Which of these names are real, and where they actually live. Use for "live host validation" and closely related asks.
---

# live-host-validation — which of these names are real, and where they actually live

> Read `skills/_recon-method.md` first — it holds the loop, the input rule and the tool contract.
> This file holds what is specific to validation.
>
> **This is a test of your ability to decide what "dead" means.** The value is not the count that
> answered. It is the split: which names sit on shared edge space and which on something that looks
> like an origin, how many addresses a single name is hiding, and which *non*-resolving names are
> still reachable. A name deleted here is a name no later skill can ever look at again.

## Objective

For every enumerated name, establish whether it resolves, to how many addresses, and whether
anything is listening — **per address, not per name**. Keep what does not resolve, because it is
still a `Host:` value. Record who owns each address, because that decides whether port scanning and
origin work are worth their packets.

## Inputs

**Enrichment — each absent one narrows the run, none of them gates it:**

- `@net.dns` (optional, from `dns-analysis`) — rcodes, CNAME chains and the wildcard parents. With
  it you are confirming; without it you are re-resolving and will collapse four DNS states into two.
- `@net.ips` (optional, from `dns-analysis`) — the deduplicated address list, so you validate the
  addresses a name resolves to rather than the name.
- `@net.asn` (optional, from `asn-and-ip-discovery`) — ownership. Not strictly required to run, but
  without it every "this host is live" claim is silent about whether you reached the target or a CDN
  that answers for a million customers.

**As the selector, at least one of the following:**

- `@hunter.host` — one exact hostname the hunter named. Resolve and validate only that name; do not
  require subdomain enumeration and do not widen it to siblings or the parent apex.
- `@hosts.all` (from `subdomain-enumeration`) — the enumerated name set. If it was produced by a
  stage that resolved-and-discarded, say so: the non-resolving names are already gone and the two
  most valuable states below cannot be recovered from it.

## Signals — what to come back with

1. **The resolving set**, deduped, with wildcard artifacts removed rather than counted as hosts.
2. **The (name × address) pairs, not one row per name.** Multiple frontends behind one name is the
   normal case, and it is measured: a disclosed vulnerability *"only had a 30% chance of being
   found on any given scan"* because DNS round-robin fronted three servers and only one was vulnerable.
   Validating a name once samples one backend at random. Enumerate the pairs and carry them forward.
3. **The non-resolving names, kept.** A name with no public record is not a dead end — it is a
   `Host:` header value. A server reached by IP still routes on `Host`, so internal-only,
   split-horizon and RFC1918-resolving names are reachable whenever they share an address with a
   public site. Passive sources only ever see names that were resolvable or certificated, which
   makes this a class of asset subdomain enumeration structurally cannot find.
4. **The certificate presented on each scanned address.** This is the highest-value single artifact
   in the whole stage, and it beats CT logs because a cert read off an IP was frequently never in a
   CT log at all — self-signed, internal CA, private PKI. Read out:
   - CN/SAN of `*.corp`, `*.internal`, `.local`, a bare hostname or an RFC1918 literal → an internal
     service exposed by mistake. Highest signal available here.
   - issuer is an internal or self-signed CA → same conclusion.
   - a SAN carrying a hostname you have never seen → a new asset **and** a `Host:` candidate.
   - a cert on a raw address whose SAN matches a CDN-fronted apex → you are looking at the origin.
   - a valid cert on a management-plane port → an admin surface, not the application.
5. **The ownership split** — which addresses are shared CDN space and which look like origin. This
   is the gate on the next stage, not a footnote.
6. **Your vantage point and what it could not see.** Named blind spot, not a caveat (see traps).
7. **The private-address names.** An A record into RFC1918 fingerprints an internal-only hostname
   that leaked into a public zone: a topology leak and a ready-made SSRF target list. Prevalence is
   measured — 635,954 FQDNs resolve into `10/8` — but **no study measures downstream exploitation**,
   and the top contributors are `amazonaws.com` (57,457 variants) and `rackspace.net` (36,368), so
   most of the population is cloud-tenant noise. Record it; do not price it.

## Known traps — measured, and each one produces a confident wrong answer

- **Scanning from a cloud VPS produces false negatives you cannot see.** Akamai and Cloudflare
  blocklist DigitalOcean and AWS ranges *outright* — blackhole, not rate-limit — and regional apexes
  are geofenced. There is no error to notice: the host is simply "down". Any pipeline that marks
  hosts dead from a cloud box has an unmeasured false-negative rate. The documented mitigation is
  residential egress, very low concurrency, rotating UA and source addresses in the target's own
  geography, and it is expensive: one full apex scan run that way took **a week and a half**.
- **A wildcard makes dead names look alive, live.** `shopify.com` answers a random label with
  `23.227.38.33` — and `vpn.shopify.com` and `autodiscover.shopify.com` both "resolve" to that same
  address. They are the wildcard, not assets, and a pipeline without filtering hands `vpn.` forward
  as a priority finding. Wildcards are also per-level. The disambiguator is cheap: **same address +
  different body hashes ⇒ vhost routing (valuable); same address + same body ⇒ wildcard (noise).**
- **Three DNS states get thrown away as "dead" and each is a finding.** `NXDOMAIN` *with a CNAME
  still in the answer section* is the dangling-CNAME primitive — that conjunction is literally the
  matcher, not a 404 body string. `SERVFAIL`/`REFUSED` is lame delegation, i.e. dangling NS, the
  takeover class no fingerprint list covers (1,974 dangling NS under 1,659 root domains in one
  study). `NOERROR` with zero answers is an Empty Non-Terminal — a label with no records but live
  descendants, so it is a **directive to recurse**, not a miss; `_spf.paypal.com` and
  `slc.paypal.com` both behave this way with live children.
- **Enumerators have a resolve-and-discard mode that runs inside discovery**, and it deletes the
  NXDOMAIN hits that are the takeover signal before you ever see them. Carry the full passive set in
  and let the rcode decide.
- **Liveness on a shared edge address tells you nothing about the target.** Akamai space "is not
  going to respond with an application level header"; thousands of unrelated names sit on one
  address. "Alive" there means the CDN is alive.
- **IPv6 is effectively unscannable**, so an address-driven view of the estate is structurally
  incomplete wherever the target has moved to it. Say so rather than implying the address list is
  the estate.

## Outputs

- `@hosts.resolved` — clean, deduped, wildcard-verified.
- The (name × address) pairs, with the multi-address names flagged, where `http-probing` and
  `port-and-service-discovery` can consume them.
- The non-resolving names retained as `Host:` candidates — into `@target` under *Interesting
  leads*, never deleted.
- Facts via `kb.py add`: the CDN-versus-origin split with counts, wildcard parents observed, the
  certificate anomalies (internal CN, private CA, RFC1918 SAN) with the address they were read
  from, and the vantage point you scanned from together with what it is known to miss.

## Exit criteria

`@hosts.resolved` is populated and wildcard-verified independently of whatever produced it. Names
with multiple addresses are recorded as pairs and counted, so nobody downstream believes one probe
covered the backend set. The non-resolving names still exist somewhere. Certificates read off
addresses are recorded with their inferences. The ownership split is written down — because the
next stage's cost and legitimacy both depend on it. The vantage point and its blind spots are
stated; "N hosts are dead" without that sentence is not a result.

## Next

Offer, do not choose: `http-probing` (what actually speaks HTTP, and what it says) ·
`port-and-service-discovery` (only against addresses you established the target owns) ·
`dns-analysis` (re-run it if the rcodes were collapsed here and the takeover states were lost) ·
`derive-properties` (but not from this alone — a resolved name is not yet an entrypoint; it needs
something probed first).
