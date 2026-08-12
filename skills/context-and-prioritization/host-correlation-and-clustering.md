---
name: host-correlation-and-clustering
description: How many assets are actually here, and which name is the stale one. Use for "host correlation and clustering" and closely related asks.
---

# host-correlation-and-clustering — how many assets are actually here, and which name is the stale one

> Read `skills/shared/_recon-method.md` first — it holds the loop, the input rule and the tool contract.
> This file holds what is specific to clustering.
>
> **This is a test of your ability to collapse N names into the number of distinct assets, and
> then to find the ones that refused to collapse.** The value is the singleton list. A host count
> is a download size; the count of *things that are actually different* is the inventory, and the
> difference between the two is usually an order of magnitude.
>
> This is economically load-bearing, not an efficiency trick. Repeated responses identify where to
> correlate first, but a body hash and an edge IP do not prove one application. Deduplication is a
> conclusion only after an independent application/origin signal agrees; otherwise it hides the
> exact stale or misconfigured host this skill is meant to find.

## Objective

Group live endpoints into correlation candidates, then hand forward confirmed clusters and the
**singletons** — hosts that matched nothing after independent axes were compared. Begin with the
pair `(body hash, observed host_ip)`, never the body hash alone, but do not call the pair a backend,
deployment, application, or duplicate. Mostly read artifacts already paid for; collect a
correlation signal actively only when it is not on disk.

`tools/cluster.py` mechanises the pair-keyed reduction over the httpx run — pipe the raw JSON to it
(`ssh vps 'cat ~/targets/<t>/raw/http/*.json' | tools/cluster.py`, or `--from <file>`) and it prints
response-similarity candidates (annotated `[cdn]`/`[edge-ip]`) plus likely catch-all/parked buckets;
`--write targets/<t>` records `recon/clusters.md`. It is a first-pass reduction only — read its
groups, then add the axes below (CNAME chains, certs, application 404s, routes, cookies). Record a
cluster or `shares-backend` edge only after at least one independent application/origin axis agrees.

## Inputs

- `@hosts.live` (from `http-probing`) — the endpoints to cluster. A host cannot be clustered
  against itself, so this skill is inherently whole-set: a one-host selector produces nothing.
- `@raw.http` (from `http-probing`) — body hash, header hash, `Server`, content-length, title,
  cookie names. This is the substrate. Without it there is nothing to cluster on, and re-probing an
  estate is traffic you already spent.
- `@net.ips` (from `dns-analysis`) — the **other half of the cluster key**. With only the body half
  the whole discrimination below collapses, and you will merge twelve deployments into one.
- `@net.dns` (optional, from `dns-analysis`) — CNAME targets; a chain is a supplier inventory and
  a strong correlation axis.
- `@tech` (optional, from `technology-fingerprinting`) — stack and version per host, another axis.
- `@scope` — this skill discovers candidates; each is in scope only once it matches.

## Signals — what to come back with

1. **The candidate map, initially keyed on the pair.** Candidate id · members · which axes agreed ·
   what is known about any member. A fact on one member is a lead for the others, never yet a fact
   about all of them.
2. **The singleton inventory.** Hosts that matched no cluster. This is the real asset count and the
   headline number of this skill — report it next to the raw host count, not instead of it.
3. **Singletons on ≥2 independent axes** — the manual-attention list. Unique body hash *and* unique
   IP; webserver differing from the estate mode; no CDN attribution while everything else is
   fronted; content-length in the far tail; TLS-stack fingerprint differing from the dominant one.
   A single-axis singleton is mostly noise; two axes is a host somebody forgot.
4. **Stale-deployment candidates.** An identical body across twelve IPs is twelve deployments, and
   the interesting question is which one is behind. Version banners, header sets and cookie names
   that differ *within* one body-identical group are the tell.
5. **Vhost routing, distinguished from wildcard.** Same IP + different body hashes is consistent
   with vhost routing. Same IP + identical body is consistent with a wildcard, shared shell, WAF,
   or edge response. Calibrate and confirm; neither arrow is proof.
6. **Shared edge separated from shared backend.** Which hosts look alike because one CDN answers
   for all of them, and which look alike because one application does.
7. **The reporting consequence**, written down only for confirmed clusters: which independent axes
   justify treating members as one fix locus. Unconfirmed groups remain separate targets.

## Known traps — each of these has merged two estates into one, or split one into forty

- **Body hash alone is the wrong key, and the pair is still only a signal.** Identical body across N
  hosts on one observed IP may be one application, one CDN response, one WAF block, or one generic
  shell. The same body across twelve IPs may be deployments or distributed edge responses. Name
  what was observed; confirm the architecture separately.
- **Exact hashing is defeated by the page itself.** A CSRF token, a timestamp or a build id in the
  body changes md5 on every request, so exact hashing reports every host as unique. Near-duplicate
  hashing (simhash) at Hamming distance ≤3 is what works — httpx and feroxbuster converged on the
  same threshold independently, both citing Manku et al., WWW 2007.
- **Title is not identity on a shared edge.** One estate returned the same vendor title on 4,889 of
  6,546 endpoints; deduping on title collapses the whole estate to nothing. A body hash
  discriminated properly there — its largest cluster was 159.
- **A shared CDN IP is not a shared backend.** Edge headers and edge addresses make unrelated hosts
  look identical. Classify the edge out first, and require an origin-level axis — cert, cookie
  name, application 404 — before merging. "No CDN detected" means *unrecognised provider*, not
  *not fronted*: one estate's own edge fronted 98% of it and was never flagged.
- **On an SPA-heavy estate the body bytes are the same because the shell is the same.** Every route
  ships one near-empty document and a bundle. Cluster on a **perceptual hash of screenshots**
  instead of body bytes there, or you will collapse the entire product into one row.
- **A framework-default favicon clusters half the internet.** Weight it low, and never as one of
  the two axes that promotes a singleton.
- **Wildcards manufacture members.** Names that "resolve" to a wildcard address are the wildcard,
  not assets — on one live zone `vpn.` and `autodiscover.` both resolved to the same wildcard IP.
  Wildcards are also per-level.
- **"Self-signed or expired cert ⇒ soft target" is unsupported.** Cert state proxies for "not
  managed by the web team" — internal mTLS, health checks, IPMI, a k8s API — not for vulnerable.
  Act on it only in conjunction with a unique body hash, no CDN and a non-standard port.
- **Over-merging is worse than under-merging**, because a merged host is never looked at again.
  When one axis agrees and another disagrees, keep the hosts separate and record the weak link.

## Outputs

- `@clusters` — cluster id · members · agreeing axes · the representative you would test · the
  linked facts. Singletons listed explicitly, with which axes made them singular.
- Facts via `kb.py add`: the estate's real asset count versus its host count, the fronting picture,
  the vhost-routing IPs, any body-identical group whose members disagree on version.
- Leads into `@target` — the singletons on ≥2 axes, and any stale member of a body-identical group.
- Coverage: how many live endpoints had no usable body or IP evidence and were therefore
  unclusterable. They are not singletons; they are unmeasured, and the two must not merge.

## Exit criteria

Every live endpoint is in a confirmed cluster, an unconfirmed similarity group, listed as a
singleton, or explicitly marked unclusterable for want of evidence. The candidate key and every
confirmation axis are stated. The singleton-on-≥2-axes list exists and is short enough to act on.
Report confirmed cluster count separately from host count; never present raw body/IP pair count as
the real asset count. If the run covered part of the live set, that is written next to the count.

## Next

Offer, do not choose: `cross-host-endpoint-reuse` (replay the target's own routes inside each
cluster — this is what clusters are *for*) · `derive-properties` (property the singletons, which is
the surface worth propertying) · `attack-surface-prioritization` (rank clusters, never names, when
the hunter asks the model to choose) · `http-probing` again if `@raw.http` lacked the fields the
key needs.
