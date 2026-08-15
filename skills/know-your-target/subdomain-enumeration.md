---
name: subdomain-enumeration
description: Find the names, prove they resolve, keep the ones that are real. Use for "subdomain enumeration" and closely related asks.
---

# subdomain-enumeration — find the names, prove they resolve, keep the ones that are real

> Read `skills/shared/_recon-method.md` first — it holds the loop, the input rule and the tool contract.
>
> **This is a test of your ability to find the *complete* name surface and then not lie about it.**
> Enumeration is easy; the discipline is in what you refuse to keep. A wildcard record turns every
> guess into a "discovery", and a list inflated that way poisons every skill downstream, because a
> phantom host looks exactly like a find until someone tries to test it.

## Objective

Discover the hostnames under the authorised roots, establish which actually resolve, remove what
only appears to, and hand forward a clean deduped set plus what you learned about how this
organisation names things.

## Inputs

- The **roots** — from `@scope`, or from `@target` when earlier research widened them, or from
  the hunter directly. This skill *creates* a host list; it does not consume one.
- `@hosts.all` (optional) — a previous run's output, so this run reports what is **new** rather
  than restating the total.

## Signals — what to come back with

1. **The clean resolving set**, deduped and wildcard-verified.
2. **What is genuinely new** since the last run. On an estate that has been enumerated before,
   the delta is the finding; the total is bookkeeping.
3. **The naming grammar.** How do they build hostnames — environment prefixes, datacenter codes,
   product-then-region, per-tenant subdomains? This is the highest-value output of this skill and
   the one most often thrown away. It tells the next run what to guess and tells a hunter which
   names are anomalies.
4. **The exceptions.** A name that breaks the grammar is worth more than a hundred that follow it.
   A staging name sitting on the flagship apex, where every other non-production host hides behind
   an internal code, is a mistake someone made — and mistakes are where bugs live.
5. **Names that assert privilege or money** — admin, billing, partner, internal, vpn, jump,
   bastion — and named infrastructure with known default-credential histories.
6. **Coverage honesty.** Which sources ran, which were skipped for want of a key, and therefore
   the *knowable* margin by which this is incomplete.
7. **Rapid7 Project Sonar (FDNS/RDNS) as a passive source, where budget allows.** A bulk
   internet-wide forward/reverse DNS scan dataset, published as Parquet at
   `s3://rapid7-opendata/fdns/any/v1/` and queryable via AWS Athena for cents, or via
   `Cgboal/SonarSearch`. It catches hosts that resolve but never had a public TLS cert issued —
   invisible to every CT-log-dependent source in the stack above, including this skill's own
   default sweep. This is the dataset James Kettle's "Cracking the Lens" research used to build a
   ~50,000-host candidate set; treat it as a real source to name in coverage honesty, not a
   theoretical one.
8. **Reverse-SNI names, with their cloud IPs.** Every other source here walks name→record or
   name→certificate; the published cloud-range SNI/cert scans at
   `kaeferjaeger.gay/?dir=sni-ip-ranges` walk **IP→certificate**, so they surface what CT and
   passive DNS structurally cannot: names on self-signed or internal-CA certificates (staging,
   internal tooling), and origin hostnames behind load balancers whose edge never shows them.
   Coverage is five providers (Amazon, Google, Microsoft, Oracle, DigitalOcean) and freshness
   varies per folder — record the dataset file date as a run limitation; internal names rot
   slowly but they rot. Each hit is a `(name, IP, provider)` triple: free correlation evidence
   for `asn-and-ip-discovery` and `host-correlation-and-clustering` (via `kb.py add`), and a
   name that no longer resolves but sits on a cloud IP is a dangling-name lead for
   `dns-analysis`/takeover. Bulk stays on the VPS: download under `run.py` so the dataset is
   hashed and the run reproducible, filter remotely with a **scope-boundary suffix match**
   (`scopelib.py`'s anchored logic — never `grep -F .acme.com`, which is substring matching and
   drags in other tenants' names on shared ranges), and pull only the extract into the brain.
9. **Validin as a passive-source name distinct from subfinder's own list.** Aggregates 650+ OSINT
   sources with IP↔domain↔cert↔favicon-hash pivoting in one place — not a replacement for the
   sources above, an additional one to name in coverage honesty when it ran (or was skipped for
   want of a key).

## Beyond DNS-based discovery

DNS-based discovery (passive sources, brute force, permutation) structurally cannot find a name
that exists only as an HTTP routing rule with no public DNS record of its own — the server answers
for it on the `Host` header, and nothing else ever points at it. The first two steps below are
ordinary-volume and run by default like the rest of this skill. **The third sends a wordlist at the
target and is gated — offered, never silently run.**

1. **Pull certificate SANs directly off the IP, not only from passive/CT sources.** One TLS
   handshake per already-known IP — the same low-volume default `live-host-validation`'s per-address
   cert read already uses, not fuzzing. Beats CT logs whenever the cert is short-lived, internal-CA-
   issued, or otherwise never logged publicly. Do it here too, as early as an IP is known: the names
   it yields seed the wordlist in step 2, not just more rows for `@hosts.all`. **Also try the
   handshake with no SNI at all** — a second connection, still one handshake, still ordinary-volume.
   A server that falls back to a default/first-configured certificate when SNI is absent can leak
   the real customer domain in that default cert's SAN, a positive confirmation signal distinct
   from (and requiring neither) a Host-header response diff. Practitioner-documented, not yet
   independently verified at scale — treat a hit as a strong lead, not proof, until corroborated.
2. **Build the wordlist in three layers**, and persist it under the `@wordlists` role
   (`recon/wordlists/`, per `target-schema.md`) — zero target traffic, this is local/offline
   construction:
   - a large generic Host-header/subdomain list — whatever is actually installed; find it, don't
     assume it.
   - a **company-matched** list — seeded from the org's own name, product names, brands and
     acquisitions already recorded in `@target`/`kb.py`, not the generic list with the company name
     typed in once.
   - a **self-generated** list built from *this run's own evidence* — labels already in `@hosts.all`
     plus the naming grammar this skill already extracts as its highest-value signal (above). This is
     the layer that finds what nobody else's list contains, because it is the target teaching you its
     own vocabulary. `alterx` (already in the pdtm install set) is the current maintained tool for
     this specifically — a pattern-based permutation DSL that takes the discovered labels and lets
     you write the grammar's rules explicitly, rather than relying on one tool's hardcoded strategy
     the way older altdns/gotator-class tools do.
   - Persisted under `@wordlists` so the next run, and step 3 below, extend it instead of
     regenerating it from nothing — this happens regardless of whether step 3 ever fires.
3. **Offer VHost fuzzing; do not run it on a bare enumeration ask.** This step has its own inputs,
   resolved the same way — required-input-present-or-stop — as any other skill in this workspace,
   never invented from nothing:

   **IPs — at least one of, in priority order:**
   - `@hunter.ips` — one or more IPs, a CIDR, or a named group the hunter gave **directly in the
     request** ("vhost fuzz 10.0.4.0/24", "fuzz the app-tier IPs"). Highest priority: an explicit
     hunter choice overrides any inferred candidate set, including all three below. A "named group"
     is whatever the hunter points at — a labelled subset already sitting in `@net.ips`
     (`recon/ips.txt`) or `@net.asn` (`recon/ips-asn.md`), or IPs typed straight into the prompt.
   - `@net.asn` (from `asn-and-ip-discovery`, if it ran) — attributed own-ASN/colo netblock
     addresses, preferring ones with **no name mapped to them yet** (genuinely new surface, not a
     re-fuzz). Provider/CDN edge addresses are excluded on principle — fuzzing them just enumerates
     the provider's other customers, the conclusion that skill's own traps already state.
   - `@net.ips` (from `dns-analysis`, if it ran) — any address that **more than one distinct name
     in `@hosts.all` already resolves to.** Two names sharing one IP is the cheap, immediately-
     available prior that the box does host-based routing, before any response evidence exists.
     (`host-correlation-and-clustering` does the rigorous version with body-hash evidence, but needs
     `http-probing` first; this DNS-only grouping is what is on hand at enumeration time, and is
     superseded by the richer one wherever available.)
   - **Falling back to this run's own resolution alone**, with none of the above run yet: the
     resolved address of the primary/apex application, and nothing wider.

   **Wordlist — at least one of:** a hunter-named wordlist given directly in the request, or the
   persisted `@wordlists` artifact from step 2.

   **If neither an IP source nor a wordlist resolves, this step cannot run — say so and stop,** the
   same one stopping condition every skill in this workspace uses: name what is missing, name what
   would produce it (`dns-analysis` for `@net.ips`, `asn-and-ip-discovery` for `@net.asn`, step 2
   above for the wordlist), or ask the hunter to name the IP(s)/wordlist directly. Do not invent a
   candidate set to avoid saying this — "one plausible IP, nothing wider" from a small, simple
   estate is a complete answer, not a shortfall, and is different from having nothing at all.

   **Multiple IPs are supported, and the offer must state the multiplier, not just the technique.**
   Wordlist size × IP count is the real request volume — fuzzing five IPs is five times the traffic
   of fuzzing one, not one step. Say the candidate count and the resulting total before naming a
   scale to run. Where the pool is more than a handful (an attributed `/24`, or a hunter-named
   group that large), pilot 2–3 representative addresses first and report yield before offering the
   rest — the same selector-and-budget discipline `_recon-method.md` requires of every fan-out
   stage.

   Fuzzing the `Host` header against a target IP is real traffic-volume work regardless of how the
   inputs resolved — the same category as `content-discovery`, and it follows the same rule
   `dead-end-host` states for it: *"never let this phase start implicitly."* A request phrased as
   "run subdomain enum on acme.com" does **not** imply consent to send a wordlist, even when
   `@hunter.ips` was given for some other reason — naming an IP is not the same as authorising a
   fuzz against it. Name the technique, the specific IP(s), the wordlist size and layer composition,
   and stop there — run it only when the hunter names the technique itself ("vhost fuzz it",
   "brute force the Host header") or a flow they already authorised bundles it (`dead-end-host`
   step 3). Where it does run: confirm a hit by a **distinct** response — status, body hash, or
   length — against a baseline request carrying a nonsense `Host` on the *same* IP, never by DNS
   resolution; a name discovered this way may never resolve at all and still belongs in
   `@hosts.all`. **The false-positive trap is the same shape as the wildcard trap below**: a server
   that returns its default vhost for every unmatched `Host` makes every guess look like a hit
   unless you diff against that baseline first.

   **On TLS, set SNI to the candidate name too, not just the `Host` header.** A server that
   validates SNI and terminates the handshake before any HTTP request is processed is invisible to
   Host-header-only fuzzing (ffuf/gobuster vhost mode) no matter how good the baseline diff is —
   the connection never gets far enough to answer HTTP at all. Where the fuzzer supports it, drive
   SNI from the same wordlist as the Host header, per candidate. Practitioner-documented technique,
   not independently verified at scale — a real gap in Host-header-only fuzzing worth knowing, not
   a guaranteed win.

## Known traps — measured, each cost hours

- **The resolver's own wildcard filter is not sufficient.** On one estate it reported 11 wildcard
  roots, still left 21 artifacts in its output, and **missed 4 real wildcard parents**. 33 of 395
  permutation "discoveries" were echoes. Re-verify independently after any generated-name stage,
  with two impossible controls per parent — `tools/wildcard-check.py` does exactly this.
- **Permutation tools scale quadratically in "enrich" modes.** One build estimated **393,639,743**
  payloads from 7,721 seeds, versus 5,373,816 plain. It does not hang; it simply cannot finish, and
  the dedup needs more memory than a small VPS has. Estimate first, using the tool's own estimator,
  and gate on a budget you can actually spend.
- **A documented flag can be non-functional.** One permutation tool's list-input flag is advertised
  in its help and fails on every form; the input only works on stdin. This is why the method file
  says pilot before scaling.
- **A missing wordlist reads exactly like a clean result.** Check the file exists and is non-empty
  before the run, or a brute-force stage reports a confident zero.
- **Passive coverage is bounded by keys.** Sources you have no key for return nothing, silently.
  Say which ran; the gap is knowable and belongs in the limitations.
- **Machine-generated names are not service hosts.** IP-encoded and per-instance infrastructure
  records inflate counts and are almost never testable. Count them separately rather than deleting
  them — they describe the infrastructure even when they are not targets.
- **Overwriting a job script while it runs corrupts the run.** The shell reads scripts
  incrementally and resumes at a byte offset into the *new* file. Launch long jobs from a stamped
  copy.
- **A reverse-SNI or Sonar hit is a candidate, not a host.** Dataset rows carry a name and an IP
  from scan day — no liveness, no wildcard context. They enter the same wildcard-verify and
  resolve pipeline as any other source; trusting the dataset because "it proved the name exists"
  is how a phantom survives into `@hosts.all`.
- **A CT-log entry can outlive the ownership it was issued under.** A cert stays valid (and stays
  in CT logs) after the domain it was issued for changes hands — measured at roughly 3% of certs
  issued for newly-registered domains in one academic dataset. A CT-derived hostname is evidence
  the name existed under *some* owner at issuance time, not proof the current target still controls
  it. Where a finding hinges on current ownership, cross-check the cert's issuance date against the
  domain's current registration date before trusting it — the same discipline as not trusting a
  scanner's ASN label without RDAP corroboration.

## Outputs

- `@hosts.all` — clean, deduped, resolving **plus** any `Host`-header-only names confirmed by a
  distinct response rather than DNS.
- The naming grammar, its exceptions and the privilege-asserting names → `@target` (Patterns,
  Exceptions, Interesting leads).
- The target-specific wordlist (company-matched + self-generated layers) under `@wordlists`
  (`recon/wordlists/`), so later runs, a hunter naming it directly, and vhost/permutation stages all
  extend the same artifact instead of regenerating it.
- Facts via `kb.py add` for wildcard parents found, sources that ran, and the new-versus-total split.

## Exit criteria

The set is deduped and independently wildcard-verified — not merely filtered by the tool that
produced it. The delta against the previous run is stated. The naming grammar is written down where
the next run can use it. Which sources ran, and which could not, is recorded. **Where the target
presented TLS on a resolved IP, the SAN was pulled directly from the handshake — or the run says
why not** (this is ordinary-volume, default-on). **The target-derived wordlist was built and
persisted, or the run says why not** (also default-on, zero traffic). **VHost fuzzing was *offered*
by name, with the IP(s) and wordlist it would use, whether or not it ran** — it runs only on a
direct ask or a flow's authorisation, and a bare enumeration request that never mentions it is a
correctly finished run, not an incomplete one. A skipped ordinary-volume technique is a stated
sentence, never silence, per `_recon-method.md`; a not-run fuzz/brute-force technique is the
default, and the offer is what must be stated.

## Next

Offer: `dns-analysis` (resolve records, find dangling CNAMEs and the takeover candidates; its
DNSSEC/`issuewild` read also says whether CT is blind to whole subtrees, which decides how hard the
permutation/vhost pass in this skill should push) · `live-host-validation` (which of these answer
anything) · `http-probing` (straight to what speaks HTTP, if the estate is small enough that
liveness adds nothing) · `javascript-analysis` on any live app (bundle-mined hostnames feed back
into `@hosts.all` **and** the self-generated wordlist layer above — this is a loop, not a one-shot) ·
re-run this skill with a source or wordlist that was missing.
