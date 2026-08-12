---
name: organization-and-roots
description: From a company name to the apexes that are actually theirs. Use for "organization and roots" and closely related asks.
---

# organization-and-roots — from a company name to the apexes that are actually theirs

> Read `skills/shared/_recon-method.md` first — it holds the loop, the input rule and the tool contract.
> This file holds what is specific to establishing what the organisation owns.
>
> **This is a test of your ability to expand sideways instead of downwards.** The value is a proven
> apex set with the evidence behind each entry, and an authorisation column that is kept separate
> from the ownership column. It is *not* a count of domains: a root you cannot attribute is a guess
> that every later skill inherits, and a root you can attribute but are not authorised to touch is
> a packet you must not send.

## Objective

Turn a company, brand or single known domain into the set of apexes the organisation actually
controls — including the ones acquisitions and regional markets left behind — with a recorded
reason for each, and with ownership and authorisation stated as two different facts. Also capture
the org identity strings (RIR/WHOIS org names, certificate `O=` values, nameserver and mail
identifiers) that every later pivot reuses.

Expansion at the apex outranks grinding under one apex. Haddix reports running **no DNS brute force
at all** on a live target, preferring to learn the naming grammar by hand and expand at the apex
level: reverse-DMARC gave him **12 undiscovered apexes**, reverse-nameserver gave **6,000–8,000
hosts** to hand-filter. JR0ch17 goes further and advises against wide automation outright, working
from API docs, job descriptions, developer accounts and engineering blogs instead. Both positions
are sourced; neither is a licence to skip evidence.

## Inputs

- The **company, brand or seed domain** — from the hunter, or from `@scope` when the program
  names an entity rather than a domain. This skill *creates* the root set; it does not consume one.
- `@scope` (from `init-target`) — the authorisation boundary. Ownership and authorisation are
  separate columns, and this is the only source for the second one.
- `@target` (optional, from a previous run of this skill) — so this run reports what is **new**
  and does not re-derive settled attribution.
- `@raw.http` (optional, from `http-probing`) — CSP allowlists and redirect destinations already
  captured. CSP headers are a sourced origin-adjacent leak: the allowlist names internal services
  and third-party hosts. Reading them as an *apex-expansion* pivot is judgement, not a measured
  technique — treat each name as a candidate requiring its own attribution.
- `@net.dns` (optional, from `dns-analysis`) — SPF, DMARC and NS records already collected, which
  are the raw material for the reverse pivots below.

## Signals — what to come back with

1. **The apex set, one row per root, with an ownership evidence column and a separate
   authorisation column.** Require **two independent signals** before calling a root theirs — a
   registrant string plus a certificate `O=`, a shared nameserver plus a DMARC endpoint. One signal
   is a hypothesis.
2. **The org identity strings themselves.** RIR/WHOIS org names, certificate subject `O=`,
   nameserver hostnames, the DMARC `rua` destination, the mail-sending naming convention. These are
   the pivot keys `asn-and-ip-discovery` and `repository-and-secret-recon` reuse; not recording
   them means re-deriving them.
3. **Acquisitions and their retained apexes.** An acquired company's domains keep resolving for
   years, run on the acquirer's DNS but nobody's roadmap, and are the greenfield of this stage —
   they have not been enumerated by everyone else because they are not the brand people search for.
4. **Regional and ccTLD variants.** Same product, different market, usually a different team and an
   older stack. Also the place where a name looks dead and is not — see the traps.
5. **Brands and products that never became a subdomain of the flagship.** A standalone marketing
   apex, a campaign domain, a developer-portal domain.
6. **The naming and hosting convention across apexes** — who registers them, which registrar, which
   nameservers, which mail provider. A root that breaks the convention was set up by someone
   outside the process, and that is where mistakes live.
7. **Coverage honesty.** Which pivots ran, which needed a paid dataset you do not have, and
   therefore the knowable margin by which the root set is incomplete. Apex diversity is the metric
   here; subdomain count is an anti-metric.

## Known traps — measured or sourced, each costs real time

- **Reverse-nameserver is a lead generator, not an answer.** The one figure attached to it is
  Haddix's **6,000–8,000 hosts to hand-filter** from a single pivot. Budget the filtering, not the
  query — and if you cannot afford the filtering, say what fraction you filtered rather than
  handing the raw pivot output forward as "roots".
- **A pivot on shared infrastructure returns the provider's customers, not the target.** The
  measured version of this is SPF: **56.5% of 12.8M domains publish SPF, 66.9% use `include:`, and
  34.7% authorise more than 100,000 IPv4 addresses**, with chains running 10+ levels — because
  those addresses belong to SaaS vendors' shared mail infrastructure. The same failure mode applies
  to any pivot key that is a provider's string rather than the organisation's own. Require the
  string to be unique to the org before you pivot on it.
- **Regional apexes can read as dead from the box you are scanning from.** Akamai and Cloudflare
  **blocklist DigitalOcean and AWS ranges outright — blackhole, not rate-limit** — and regional
  apexes are additionally geofenced. Haddix's mitigation was residential proxies, low concurrency,
  rotating user agents and source IPs in the target's own geography, and a full apex scan then took
  **a week and a half**. A ccTLD you marked unreachable from a cloud VPS is unmeasured, not absent.
- **The most-cited methodology for this stage is partly empty or fabricated.** TBHM's public repo
  carries a `### Reconassiance` heading with **zero files under it**, so anything quoting "TBHM
  recon" as text is secondhand. A widely-circulated blog attributes *"manual testing is dead"* to
  Haddix — the exact opposite of his recorded position — with invented commands. And the
  *"passive enumeration finds 60–80% of discoverable subdomains"* figure that appears in several
  2025–26 write-ups **has no study behind it**. Do not plan coverage against it.
- **Ownership evidence from a scanner's label is not ownership evidence.** This repo's own
  `tools/rdap-org.py` exists because of it: an ASN-mapping tool labelled 36 ASNs with the target's
  name, RDAP confirmed 33 and **refuted three** — one belonging to a different corporate entity,
  two registered to private individuals — after their CIDRs had already been written into the scope
  allowlist. Corroborate the label against the registry before a range becomes authorised.

## Outputs

- `@roots` — one row per apex: the root, the ownership evidence (≥2 signals, named), the
  authorisation state, and how it was found.
- `@target` — the entity map, the acquisitions, the org identity strings, the hosting convention
  and its exceptions, plus anything that looks worth testing under *Interesting leads*.
- Facts via `kb.py add` for each pivot that ran and what it yielded, and for any root that is owned
  but explicitly **not** authorised, so nobody re-discovers it and probes it.

## Exit criteria

Every apex in `@roots` carries at least two independent ownership signals or is labelled a
candidate. Authorisation is recorded per root and is not inferred from ownership. The org identity
strings are written down where the next skill can pivot on them. Which pivots ran — and which were
skipped for want of a dataset — is stated, so the incompleteness is knowable rather than implied.

## Next

Offer, do not choose: `subdomain-enumeration` (per authorised root — start with the acquisitions
and regional apexes, which nobody else has ground) · `dns-analysis` (apex records for every new
root; it is also what tells you whether brute force under a root is worth running at all) ·
`asn-and-ip-discovery` (**only** if the org strings and registry data suggest they run their own
address space — it is near-worthless against CDN-fronted SaaS) · `repository-and-secret-recon`
(the org identity strings map directly onto code-hosting orgs and employee accounts).
