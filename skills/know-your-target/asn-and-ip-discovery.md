---
name: asn-and-ip-discovery
description: Decide whether address space is even the right unit here. Use for "asn and ip discovery" and closely related asks.
---

# asn-and-ip-discovery — decide whether address space is even the right unit here

> Read `skills/shared/_recon-method.md` first — it holds the loop, the input rule and the tool contract.
> This file holds what is specific to address-space discovery.
>
> **This is a test of your ability to refuse a stage.** This is the one recon skill whose most
> common correct outcome is *"the target does not own meaningful address space, so this produces an
> inventory of somebody else's edge"* — said explicitly, with the ownership split that proves it.
> The value is netblocks you can attribute and the certificates presented on them. It is **not** a
> list of CIDRs: on CDN-fronted SaaS that list is Cloudflare's, and reporting it as the target's
> address surface is a false claim every later skill inherits.

## Objective

Establish who actually owns the addresses this target resolves to. If a meaningful share sits in
space registered to the organisation — an own ASN, a colo range, legacy datacentre allocations —
map those netblocks and the hosts on them, because that is where the non-CDN, non-standard,
under-probed estate lives. If the estate is provider-fronted, say so with the split that shows it,
do the cert-based work that still pays there, and stop rather than manufacturing coverage.

The sourced position is blunt. Assetnote: *"there's just so much infrastructure … using WAFs, CDNs,
TLS-SNI routing, vhost-based routing — internet-wide discovery really doesn't work that well."*
Named blind spots: host-header routing putting thousands of subdomains on one address, shared CDN
space where the addresses will not answer with an application-level header at all, path-based
routing, and IPv6 being unscannable. Their stated preference is the **name** over the address,
because only the name lets you send the right `Host` and SNI.

## Inputs

- `@net.ips` (from `dns-analysis`) — the resolved addresses. **This is the precondition, not an
  optional enrichment**: reverse-mapping these to their registered owner is what computes the
  ownership split that decides whether the rest of this skill should run.
- `@roots` (from `organization-and-roots`) — the org identity strings. Registry search is by org
  name, not by domain, so without these you are searching for a brand string and accepting whatever
  a scanner labelled.
- `@scope` (from `init-target`) — when the program hands over CIDRs directly, this skill is the
  **entry point** rather than a conditional one, and scope is then the primary input.
- `@raw.http` (optional, from `http-probing`) — the fronting picture already observed. Remember
  that an unrecognised front is reported as no front at all, so absence of a provider label is not
  evidence of own infrastructure.

## Signals — what to come back with

1. **The ownership split, first and before any sweep.** What fraction of the resolved addresses sit
   in space registered to the organisation versus a provider, computed against the registry rather
   than against a tool's ASN label. This number *is* the decision, and it belongs in the report
   whichever way it comes out.
2. **Attributed netblocks** — range, registered org string, and the corroborating signal. Two
   signals before a range becomes authorised, same rule as `organization-and-roots`.
3. **Colo, legacy and acquisition-era ranges.** On an own-ASN estate this is the payload of the
   whole skill: address space that predates the current platform, running things the current
   platform team does not own.
4. **Certificates presented on scanned addresses — the cloud-native replacement for netblock
   sweeping.** Scanning-based cert data reads the certificate actually served on an address and
   port, so it surfaces certificates that were **never in a CT log**: self-signed, internal CA,
   private PKI. The decision table:

   | observed on a scanned address:port | inference |
   |---|---|
   | SAN carries a hostname you have never seen | new asset — **and a `Host:` candidate** |
   | CN/SAN is `*.corp`, `*.internal`, `.local`, a bare hostname, or a private-IP literal | **internal service exposed by mistake — the highest-signal single artifact available here** |
   | issuer is an internal or self-signed CA | same |
   | cert on a raw address whose SAN matches a CDN-fronted apex | **the origin** |
   | valid cert on a management-plane port | admin surface, not the application |
   | expired or mismatched | forgotten host; correlates with staging and takeover debris |

   Searching a scanning dataset for the target **plus the keyword `internal`** is specifically
   called out as surfacing properties that never appeared in previous searches.
5. **Origin candidates, with the precondition tested.** The ordered signal list is: SSRF or any
   outbound-forcing feature (the only *deterministic* method — the origin reports its own egress
   address) · historical DNS · CT SANs, which often carry the origin address or an internal
   hostname · favicon-hash pivoting on a scanning dataset · `Received:` headers from a
   password-reset email · unique-string pivoting on copyright lines, tag-manager IDs and custom
   headers. SPF records and CSP headers are origin-adjacent leaks for the same reason: mail almost
   never goes through the CDN, and CSP allowlists name internal services.
6. **What you are declaring out of bounds** — the provider edge ranges you will not sweep, named,
   so nobody later reads their absence as coverage.

## Known traps — measured or sourced, each costs real time

- **A scanner's ASN label is not ownership evidence.** `tools/rdap-org.py` exists because of a
  measured case on this repo: an ASN-mapping tool labelled 36 ASNs with the target's name, the
  registry confirmed 33 and **refuted three** — one belonged to a different corporate entity and
  **two were registered to private individuals** — after their 62 CIDRs had already been written
  into the scope allowlist on the strength of the label. Corroborate before a range is authorised;
  the failure mode here is sending packets to a stranger.
- **Scanning provider space inventories the provider.** Shared CDN addresses will not answer with
  an application-level header, one address fronts thousands of unrelated customer names, and IPv6
  is not sweepable at all. Every open port on an edge address belongs to the edge. The result is
  not merely low-yield — presented as "the target's exposed services" it is wrong.
- **Scanning from a cloud VPS produces false negatives you cannot see.** Akamai and Cloudflare
  **blocklist DigitalOcean and AWS ranges outright — blackhole, not rate-limit** — and regional
  apexes are geofenced on top of that. The documented mitigation is residential proxies, low
  concurrency, rotating user agents and source addresses in the target's geography, after which a
  full apex scan took **a week and a half**. Anything marked dead from a cloud box carries an
  unmeasured false-negative rate, and that sentence belongs in the run's limitations.
- **Deduplicate by address, not by hostname.** Kettle documented a vulnerability that *"only
  had a 30% chance of being found on any given scan"* because DNS round-robin fronted three servers
  behind one name and only one was vulnerable. Probing per name is not thoroughness — it is a
  coverage gap you cannot measure. The same research triggered callbacks from **27 DoD servers**
  merely by sending an incorrect `Host` header.
- **Origin exposure is an enabler, not a payday — and it has a precondition most write-ups omit.**
  Many origins do not filter by source address and will serve full content when hit directly, but
  **if the origin firewalls to CDN ranges none of this converts.** So run the cheap test first:
  request the candidate address with the correct `Host` and diff — a documented end-to-end case used
  a **403-vs-200 differential** as its confirmation, and its honest outcome was an
  `/.well-known/acme-challenge/` listing, low severity, **no bounty**. It is worth what you can
  reach through it.
- **Sweep budget is not linear in what it feels like.** Roughly **500 hostnames ≈ 6 minutes**
  against **23,000+ addresses ≈ 5+ hours** on an aggressive timing profile — which is why expanding
  an attributed `/16` into a full sweep is an afternoon, not a step. And a fast sweep trades
  accuracy for rate by its own documentation: **a surprising open port from a fast scan is a
  hypothesis until it is re-verified slowly.**

## Outputs

- `@net.asn` — the ownership split, the attributed netblocks with their evidence, the ranges
  explicitly excluded as provider space, and the certificate observations with their inferences.
- Facts via `kb.py add`: whether this target is own-ASN or provider-fronted and on what evidence —
  this single fact changes what `port-and-service-discovery` and `http-probing` should be pointed
  at, and it is the fact most often re-derived from scratch.
- Leads into `@target`: internal-looking certificate names, origin candidates with the result of
  the `Host`-diff precondition test, addresses answering with no name.
- **A stated verdict when the answer is "not worth running here"** — that is a result, recorded
  with its split, not an empty run.

## Exit criteria

The ownership split is computed from registry data and stated **before** any sweep was launched.
Every attributed range carries two independent signals or is labelled a candidate. Provider ranges
are named as excluded rather than silently skipped. If the estate is provider-fronted, the report
says so plainly and the cert-based work is what was actually done. Any sweep that ran declares its
selector, its budget and what it left out, and any host marked unreachable from a cloud box is
marked *unmeasured*, not *dead*.

## Next

Offer, do not choose: `port-and-service-discovery` (**only** over attributed own space — pointed at
provider edge ranges it measures the provider) · `http-probing` (bare addresses with no name are
endpoints nothing name-driven will ever reach) · `subdomain-enumeration` or `dns-analysis` (the
certificate SANs you just collected are new names and new roots, and they re-enter the graph there)
· `derive-properties` (turning any of this into a testable, propertied surface happens there, not
here).
