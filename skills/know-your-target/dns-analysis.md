---
name: dns-analysis
description: The records, and the three "dead" answers that are actually findings. Use for "dns analysis" and closely related asks.
---

# dns-analysis — the records, and the three "dead" answers that are actually findings

> Read `skills/shared/_recon-method.md` first — it holds the loop, the input rule and the tool contract.
> This file holds what is specific to resolving records and reading what the resolver said.
>
> **This is a test of your ability to keep information a resolver hands you and a pipeline throws
> away.** The value is not "which names resolved". It is the four possible answers, three of which
> carry a finding, plus the vendor inventory a chain of CNAMEs and a TXT record hand you for free.
> A run that emits only an address list has discarded most of what it paid for.

## Objective

Resolve records for the names and roots you were given, and classify **every** answer rather than
partitioning into resolved/unresolved. Produce the deduplicated address set later skills probe, the
takeover candidate set, the supplier inventory implied by the CNAME and TXT records, and the
wildcard picture that decides whether any generated-name list can be trusted.

## Inputs

**Enrichment — each absent one narrows the run, none of them gates it:**

- `@roots` (optional, from `organization-and-roots`) — apex-level records (SPF, DMARC, CAA, NS, MX)
  are per root, not per host. Without roots, a one-host run claims only that host and explicitly
  leaves apex-only signals unmeasured.
- `@scope` (optional, from `init-target`) — so the address set you emit is already filtered to what
  is authorised, before anything downstream sweeps it.

**As the selector, at least one of the following:**

- `@hunter.host` — one exact hostname or apex the hunter named. Query only that name; do not infer
  an estate-wide selector from its parent domain.
- `@hosts.all` (from `subdomain-enumeration`) — the **full** enumerated set, including names that
  did not resolve. Names that failed to resolve are the input to the highest-value class this skill
  produces; a set that has already been resolve-and-discarded cannot produce it.
- `@roots` (from `organization-and-roots`) — the selected apex set when the objective is apex-level
  DNS rather than enumerated-host analysis.

## Signals — what to come back with

1. **The deduplicated address set.** This is what `http-probing` and `asn-and-ip-discovery`
   consume. Keep the name→address mapping, not just the addresses: a name is what lets you send the
   right `Host` and SNI, and on SNI-routed infrastructure the address alone reaches nothing.
2. **`NXDOMAIN` with a CNAME still in the answer section.** This is the dangling-CNAME primitive,
   and it is an *rcode plus a record*, not a string in a 404 body — nuclei's own matcher is exactly
   that conjunction. Anything that reduced this name to "did not resolve" has deleted the finding.
3. **`SERVFAIL` / `REFUSED` on a delegation.** Lame delegation → **dangling NS**, the takeover class
   **no fingerprint list covers**, and the impact is authoritative control of the entire subtree
   rather than one hostname. Unit42 counted **1,974 dangling NS records under 1,659 root domains**.
4. **`NOERROR` with zero answers.** An Empty Non-Terminal: a label with no records of its own but
   live descendants. It is a **directive to recurse**, not a miss — `_spf.paypal.com` and
   `slc.paypal.com` were both observed in this state with live children beneath them. The
   distinguishing signal is the **rcode itself**, not answer-section emptiness — `NXDOMAIN` and
   `NOERROR`-zero-answers both print nothing to parse, and only one of them is a lead; read the
   status field the installed resolver actually exposes (`dig`'s `status:` header line; check
   `dnsx --help`/its JSON output for the equivalent field before parsing one) rather than
   inferring from "no answer" alone. **Acting on it**: an ENT parent is positive proof its branch
   is populated, so re-scope the wordlist you already built to `*.<ENT-parent>` and re-fuzz —
   narrower and higher-yield than a blind full-domain sweep, because this isn't a guess, it's
   evidence. Also grep your own already-collected candidates for that suffix (the child is
   sometimes already sitting in CT/JS-mining output, just never connected to this parent), and
   try a CT-log wildcard search on the exact suffix (`%.<ENT-parent>` on crt.sh's identity
   search). This composes: a child turned up by the re-fuzz can itself be another ENT one level
   down, and the same loop runs again there.
5. **The wildcard state, per level.** Three-way, not binary — see the traps. Record it as a property
   of each parent, because wildcards exist at one level and not another.
6. **The CNAME chain as a supplier inventory.** Each hop names a vendor the organisation pays. That
   inventory selects which login portals, tenant subdomains and provider-side misconfigurations are
   worth hunting, and it is a more durable output than the individual records.
7. **SPF / DMARC / TXT contents.** Third-party senders, the org's own internal naming for them, and
   `ip4:` blocks. Where those blocks are genuinely the organisation's own, a reverse-PTR sweep over
   them is the highest signal-per-request technique in this stage: on `paypal.com` it ran end to
   end in about ten seconds and produced `mx0`–`mx17.slc.paypal.com` and **`ipnpb.paypal.com`, a
   live postback API**, from names the org's own "third-party 1–4" convention emitted and no
   wordlist or CT log would ever produce. Read the limit in the traps before budgeting it.
   **Domain-verification TXT tokens** (`google-site-verification=`, `MS=`,
   `facebook-domain-verification=`, and similar) are a second, separate pivot inside the same
   record set: the token prefix names the SaaS product in use, and the **same token value**
   appearing on two different apexes is a same-owner correlation signal independent of DNS/cert
   evidence — worth grepping for explicitly, not just reading past on the way to SPF/DMARC.
8. **CAA `issuewild` at the apex.** A `*.example.com` certificate emits **one** CT entry, not one
   per host, so this record decides whether CT is near-complete: wildcards forbidden → every host
   needs its own leaf cert → **brute force buys almost nothing**; `issuewild` naming CAs or absent
   → **CT can be blind to whole subtrees and permutation is the only path**. Observed:
   `hackerone.com` forbids wildcards; `github.com` and `gitlab.com` name CAs; `paypal.com`,
   `shopify.com`, `airbnb.com` and `uber.com` publish no `issuewild` at all. The *mechanism* is
   sourced and airtight; stating it as a **rule** is this reference's own synthesis — nobody else
   appears to publish it, so treat it as a strong prior, not a law.
9. **RFC1918 addresses in public DNS**, and **NS delegation oddities** — a subtree delegated
   somewhere the rest of the estate is not.
10. **DNSSEC posture, and zone-walk exposure where it is signed.** Check `dig +dnssec` for
    `RRSIG`/`NSEC`/`NSEC3` before spending any budget on either path. A zone signed with plain
    `NSEC` proves non-existence by returning the literal next name in canonical order — the
    denial-of-existence record doubles as a zone listing, no guessing required. `NSEC3` hashes
    owner names instead, so the same walk becomes offline hash-cracking against a wordlist
    (`nsec3walker`, `nsec3map`), and whether that pays off depends on the zone's iteration count and
    salt. *The mechanism above is textbook DNSSEC behavior; how rare plain `NSEC` is on a real
    target today is this reference's own read of the current landscape, not a cited study — treat
    it as a strong prior, not a law, the same caveat signal 8 carries for `issuewild`.*
11. **`HTTPS`/`SVCB` records (RFC 9460, finalized November 2023).** A record type most tooling does
    not query yet. Where present, its `ipv4hint`/`ipv6hint` parameters can name the origin server's
    real address directly — published in DNS specifically to speed up connection setup, and a leak
    channel behind a CDN structurally identical to the no-SNI default-cert leak in
    `subdomain-enumeration.md`, just via a different record. Query it explicitly (`dig <name> HTTPS`
    / `dig <name> SVCB`); nothing else in this file's checklist surfaces it. The mechanism is
    primary-sourced (the RFC, vendor engineering docs); no disclosed report yet ties a leaked hint to
    a finding, so treat a hit as a strong lead, not proof, the same hedge already applied to the
    no-SNI technique.
12. **DKIM selectors** (`<selector>._domainkey.<domain>` TXT records) — a second identity axis SPF/
    DMARC do not cover. Dual value: the selector and key parameters are a vendor/ESP fingerprint like
    the CNAME-chain inventory above, and a sub-1024-bit RSA DKIM key is an actual crackable
    vulnerability, not just a fingerprint. Selectors must be guessed (common ones: `default`,
    `google`, `selector1`/`selector2`, `k1`) — `dkimsc4n`-class tools wordlist this. Practitioner-
    sourced, not disclosed-report-grounded; the RSA-key-strength angle is the part worth the extra
    query.

## Known traps — measured, each has produced a confident wrong answer

- **The wildcard trap is live and it promotes exactly the names you want to be real.** Probing a
  random label: `paypal.com` → **NXDOMAIN** (no wildcard, generated names trustworthy) ·
  `hackerone.com` → **NOERROR with no answer** (ENT-like — *not* a wildcard, and collapsing it into
  one is how legitimate parents get condemned) · `shopify.com` → **NOERROR → 23.227.38.33**
  (wildcard). The consequence, observed: **`vpn.shopify.com` and `autodiscover.shopify.com` both
  "resolve" to that wildcard address — they are the wildcard, not assets.** A pipeline without
  filtering hands `vpn.` forward as a high-priority finding. Wildcards are **per level**, and the
  disambiguator downstream is **same address + different body hashes ⇒ vhost routing (valuable),
  not a wildcard (noise)**. `tools/wildcard-check.py` runs the independent two-impossible-labels
  check.
- **The upstream enumerator may have already destroyed the takeover signal.** Passive enumerators
  commonly offer a resolve-and-discard mode that drops non-resolving names inside the passive
  stage. That deletes precisely the `NXDOMAIN` hits signal 2 depends on. Carry the full passive set
  into this skill and let the rcode decide — and if the set you were handed was already filtered,
  say so rather than reporting zero candidates.
- **The SPF→`ip4:`→PTR technique does not generalise the way it reads.** It worked on PayPal
  because those were *PayPal's own* blocks. Measured sprawl says the common case is the opposite:
  **66.9% of SPF-publishing domains use `include:`**, chains run 10+ levels, and **34.7% authorise
  more than 100,000 IPv4 addresses** — all of it SaaS vendors' shared mail infrastructure, which is
  **almost always out of scope**. That is a real finding about the technique: **the recon value of
  an `include:` chain is vendor inventory, not address space.** Sweep only blocks you can attribute
  to the organisation itself.
- **A private address in public DNS is a fingerprint, not a finding.** Prevalence is measured —
  **635,954 unique FQDNs resolve into `10/8`**, ~1.3M names across the private ranges — but the top
  contributors are `amazonaws.com` (57,457 variants) and `rackspace.net` (36,368), i.e. mostly
  cloud-tenant noise rather than enterprise internal DNS. **No study measures downstream
  exploitation.** Treat it as evidence of an internal-only hostname that leaked into a public zone —
  a topology leak and an SSRF target list — and nothing more until something is tested.
- **AXFR is worth two seconds and no expectation.** **8.2% of ~4M nameservers allow transfers, but
  those serve only 0.4% of domains**, and they are structurally absent from Cloudflare, Route 53
  and Azure DNS. In a 14,832-report disclosed corpus, **exactly one report mentions AXFR — from
  2016, paid $0**, with no disclosure from 2024–2026. Keep the check; delete the plan built on it.
- **A name that does not resolve at all is not a dead end — it is a `Host:` header value.** A
  server reached by address still routes on `Host`, so an internal-only or split-horizon name is
  reachable if it shares an address with a public site. Passive sources only ever see names that
  were resolvable or certificated, so **this is a class of asset enumeration structurally cannot
  find.** Keep non-resolving names; do not delete them because this skill could not resolve them.
- **NSEC3 zone walking is a hash-cracking budget question, not a free zone dump.** Estimate the
  crack cost — iteration count, salt, wordlist size — before committing, the same discipline as the
  permutation-tool budget trap in `subdomain-enumeration`. It also fails silently: a zone with
  adequate NSEC3 parameters looks identical whether you spent one minute on it or one hour.

## Outputs

- `@net.ips` — deduplicated addresses, scope-filtered, with the name→address mapping preserved.
- `@net.dns` — the records, the four-way rcode classification with the candidates called out, the
  per-level wildcard picture, the CNAME/vendor inventory, SPF/DMARC/CAA contents.
- Facts via `kb.py add`: the wildcard parents, the `issuewild` state and what it implies for
  enumeration effort, the vendor list, any delegation that breaks the estate's convention.
- Leads into `@target` — dangling candidates, private-IP names, ENT parents worth recursing into.

## Exit criteria

Every answer is classified into one of the four states rather than into resolved/unresolved, and
the three finding-bearing states are counted separately. The wildcard picture is verified
independently of whatever produced the host list, per level. `@net.ips` is deduped and
scope-filtered. The `issuewild` state is recorded for every root, because it is what the next
enumeration run should be budgeted against. Where the input set had already been filtered upstream,
that limitation is written next to the candidate count.

## Next

Offer: `subdomain-takeover` (if any name landed in one of the three finding-bearing states — that
skill adjudicates them; a fingerprint match is not a verdict) · `http-probing` (turn the address
and name set into live endpoints) · `subdomain-enumeration` re-run with permutation, **if**
`issuewild` says wildcards are permitted and CT is therefore blind to subtrees ·
`asn-and-ip-discovery` (**only** if the addresses cluster into space the organisation itself is
registered for) · `derive-properties` (a confirmed third-party delegation becomes a propertied
entrypoint there, not here).
