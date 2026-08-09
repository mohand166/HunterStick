---
name: port-and-service-discovery
description: What else is listening, and whether it is even theirs. Use for "port and service discovery" and closely related asks.
---

# port-and-service-discovery — what else is listening, and whether it is even theirs

> Read `skills/_recon-method.md` first — it holds the loop, the input rule and the tool contract.
> This file holds what is specific to scanning ports.
>
> **This is a test of your ability to spend packets on the right addresses and then say what you did
> not cover.** The value is a small set of services nobody expected to be reachable, tied back to a
> name you can send. It is not a port table. An open-port count on addresses you never established
> the target owns is a bill, not a result.

## Objective

Find the listening services on addresses the target actually controls, identify what is running,
and map each open port back to a name so the next stage can send the right `Host` and SNI. State the
coverage tier you ran and what it structurally excludes.

## Inputs

- `@net.ips` (from `dns-analysis`) — the addresses to scan. This skill consumes addresses; it does
  not discover them.
- `@net.asn` (from `asn-and-ip-discovery`) — ownership. Treat this as required in practice: without
  it you cannot separate an origin from a CDN edge, and scanning the edge is scanning the CDN.
- `@hosts.resolved` (optional, from `live-host-validation`) — the (name × address) pairs, so an open
  port becomes a probeable endpoint instead of an orphan tuple.
- `@scope` (from `init-target`) — many programs scope names and not address ranges. Check before you
  scan an address, not after.

## Signals — what to come back with

1. **The open-port inventory per address, with the coverage tier stated next to it.** The tier is
   part of the finding: "top-1000, plus a web-service high-port list" is a result; "we scanned the
   ports" is not.
2. **Management and orchestration planes on application hosts.** This is where the disclosed reports
   actually are — named products, not raw datastores (see the reconciled rule below).
3. **Non-HTTP services.** In a 14,832-report disclosed corpus, ssh appears 56 times, smtp 51, ftp 42
   — more than any datastore. They are rarely the bug themselves, but they name the estate's
   management path.
4. **The certificate on every open TLS port**, read exactly as `live-host-validation` reads it: an
   internal CN, a private-CA issuer or an RFC1918 SAN on a management port is the single most
   informative artifact this stage produces. A valid cert on 8443/9200/5601 is an admin plane, not
   the application.
5. **The name to send at each open port.** A port with no name attached is half a finding — see the
   disclosed routing case in the traps.
6. **What you excluded and why** — CDN-owned addresses skipped, the tier's known blind spots, the
   fraction of the address set you actually reached inside the budget.

## The coverage tradeoff, measured

Computed over Nmap's own `nmap-services` frequency data, reproducing its published figures:
**top-10 TCP = 50% of open-port frequency mass · top-100 = 78% · top-1000 = 93%**, and 99% needs
3,328 ports. So top-100 → top-1000 is a **10× cost for +15 points**, and top-1000 → full range is a
**65× cost for +7 points** — with no evidence that the 7% contains bounty-paying bugs.

**This reference contradicts itself here, and the contradiction is load-bearing.** An earlier pass
argued that a curated datastore list is the prize *precisely because* it is excluded: Redis (rank
1,683), Mongo (2,841), Docker API (2,903), k8s API (4,867), Kibana (5,112), etcd (7,382), memcached
(8,317) all sit outside top-1000, and kubelet 10250, RabbitMQ management 15672 and Hadoop 50070 are
**absent from `nmap-services` entirely**, so no top-N will ever reach them. The whole class sums to
0.0113% of frequency mass. A later, better-sourced pass measured the disclosed corpus instead and
found those same classics at **2–7 mentions each in 14,832 reports** (Redis 2, memcached 3, Kibana
3, Elasticsearch 5, MongoDB 7) — near-zero yield. What *does* generate disclosed reports is named
products: **Jira 29 · Kubernetes 24 · Docker 23 · Grafana 21 · Jenkins 17** — and those live on
8080/8443/3000/9090/8090/10250, just outside top-100 but comfortably **inside top-1000**.

**Reconciled rule:** top-1000 as the default, plus a targeted web-service high-port list
(8000–8010, 8080–8090, 8443, 3000, 9090, 9200, 9000, 10250, 5000, 7001). Full range only with a
reason you can state. **The datastore-port framing is a prior, not a measurement** — it is
well-formed and it is what the disclosed corpus fails to support, so run those ports if they are
cheap, but do not budget against them. No ranked port→finding dataset exists in any source
consulted; anyone publishing one is extrapolating.

The one clean port-driven case study with a figure attached: **9200 Elasticsearch, $3,000** —
unauthenticated, a single search query returning usernames, emails, passwords and tokens.

## Known traps — measured, and each one costs either hours or credibility

- **Never port-scan CDN addresses.** Every open port on an edge address belongs to the provider,
  not the target. The standard scanner ships a CDN-exclusion mode and **essentially nobody turns it
  on**, so the default output of a naive run is a survey of Cloudflare.
- **A fast-scan open port is a hypothesis, not a fact.** The scanner's own documentation states that
  increasing the rate increases false positives. Re-verify anything surprising slowly, against that
  single address, before it enters `@net.ports` — a fabricated open port propagates into every
  downstream probe and nobody re-checks it.
- **Non-root silently degrades SYN to CONNECT.** Different technique, different results, no warning
  and a clean exit. The tool's docs assume it is running as root on a VPS; check which mode you
  actually got before comparing two runs.
- **A port that is not internet-facing can still be the finding.** A disclosed Traffic Server Overseer
  Port on **8082 paid $15,000 and then $5,000 — and it was not reachable from the internet.** It was
  reachable only *through* a Host-header routing bug. Port recon and vhost recon **compound**;
  neither alone would have found it, and a port stage that discards the name set cannot participate.
- **The ranking you are relying on is by internet-wide prevalence, not by "probability of something
  unauthenticated".** That is why the interesting ports are missing from it, and it is not a bug in
  the tool — it is the wrong objective function for hunting.
- **Budget is the real constraint and it is measured:** ~500 hostnames ≈ 6 minutes, but **23,000+
  addresses ≈ 5+ hours** at a high rate. A full-range sweep of a large estate is usually
  unaffordable, and re-scanning 22/80/443/53/8080 is pure cost when `http-probing` already covers
  them.
- **There is a zero-packet first pass.** Some scanners have a passive mode that reads ports,
  hostnames, CPEs and known vulns out of Shodan's InternetDB **with no packets sent to the target**.
  On a noisy-is-bad target, or as a cheap sanity check on an active run, it is free.
- **IPv6 is unscannable at estate scale.** Address-driven discovery is structurally blind to it.
  That is a coverage statement to record, not a caveat to omit.

## Outputs

- `@net.ports` — address, port, service, the name(s) that route there, and the confidence (fast scan
  versus re-verified).
- Facts via `kb.py add`: the coverage tier and its exclusions, the count of CDN addresses skipped,
  management planes found, and anything whose service disagrees with the estate's convention.
- Leads into `@target` — orchestration and admin ports, unauthenticated-looking services, certs with
  internal CNs or private-CA issuers.
- The raw scan output on the VPS, pointed at from `index.md`, so nobody re-scans to re-read it.

## Exit criteria

`@net.ports` exists with the coverage tier recorded beside it. CDN-owned addresses were excluded and
the count is stated. Every surprising open port was re-verified slowly, and rows are marked with
which kind of observation they are. Open ports are mapped back to names, not left as bare tuples.
The fraction of the address set that the budget actually reached is written down next to the result;
a partial sweep reported as "the estate" is a false coverage claim every later decision inherits.

## Next

Offer: `http-probing` (probe the non-standard ports you just found, with the right `Host` and SNI —
this is where a port becomes an endpoint) · `technology-fingerprinting` (management planes are the
most identifiable software on the estate) · `asn-and-ip-discovery` (if you could not tell whose
address you were scanning, that gap is the thing to fix before scanning more) · `derive-properties`
(turn the reachable services into a propertied surface — properties are its job, not this one's).
