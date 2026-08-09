---
name: cloud-asset-discovery
description: The ground moved twice, and the old method now searches a closed set. Use for "cloud asset discovery" and closely related asks.
---

# cloud-asset-discovery — the ground moved twice, and the old method now searches a closed set

> Read `skills/_recon-method.md` first — it holds the loop, the input rule and the tool contract.
> This file holds what is specific to cloud assets.
>
> **This is a test of your ability to stop doing the thing everyone still does.** Value here is a
> named cloud resource with a *consumer* — who reads it, who writes it, what trusts it. Non-value
> is a permutation run against a namespace that structurally cannot contain new infrastructure, and
> a report on a key the vendor documents as public.

## Objective

Find the cloud-hosted resources this organisation actually owns — buckets, BaaS projects, function
URLs, service-created artifacts — and establish for each one what it holds, who consumes it, and
whether it is readable or **writeable**. Derive names where the evidence lets you compute them
instead of guessing them. Record what you could not reach, and why.

## Inputs

- `@roots` (from `organization-and-roots`) — the authorised apexes and the organisation's naming
  vocabulary. Without this you are guessing at a company, not enumerating a target.
- `@js` (from `javascript-analysis`) — the highest-yield input in this skill. BaaS configuration
  blocks, function-URL hosts and bucket references live in first-party bundles, and nothing in DNS
  or CT will ever show you them.
- `@urls` (optional, from `url-collection`) — historical references to storage hosts and asset
  origins the site no longer serves from.
- `@net.dns` (optional, from `dns-analysis`) — CNAMEs pointing at provider infrastructure, which is
  both the cloud inventory and the takeover-candidate list.
- `@repos` (optional, from `repository-and-secret-recon`) — public code carrying account
  identifiers in ARNs. This is what converts name-guessing into name-computing.
- `@scope` (from `init-target`) — which providers and which asset classes the program actually
  authorises. Cloud assets are where third-party property is easiest to hit by accident.

## Signals — what to come back with

1. **BaaS projects and their rules.** Firebase and equivalents are the real open bucket of 2024+.
   FireWreck scanned 5.5M domains down to ~550k candidate instances and found **~900 vulnerable**,
   exposing **125M records including 20.2M plaintext passwords**. That is a **0.16% hit rate** —
   which is exactly why a report on a config block alone is noise. The `apiKey` is public by
   design; **the finding is always the rules, never the key.** Come back with what an anonymous or
   newly-registered principal can actually read and write, not with the config.
2. **Writeability, separated from readability.** These are not one signal and they are not one
   severity band. Public read of nothing sensitive is informational. **Public write on a bucket
   that serves JS to the production origin is a stored-XSS-to-ATO chain.** Before you write a word
   of a report, answer: **who consumes this bucket?** If you cannot name the consumer, you have an
   inventory row, not a finding.
3. **Account identifiers.** The AWS account ID is the most underrated primitive in this stage: it
   turns "guess a name" into "compute one", because service-created resources follow deterministic
   patterns keyed on account and region (`cf-templates-*`, `aws-glue-assets-{acct}-{region}`,
   `sagemaker-{region}-{acct}`). Harvest IDs from `arn:aws:iam::` occurrences in public code and
   from access-key identifiers. AWS fixed five such patterns in 2024 — **the durable lesson is the
   pattern class, not those five strings**, so look for the shape wherever a service names a
   resource on the customer's behalf.
4. **Function URLs.** `https://<id>.lambda-url.<region>.on.aws` is an API with no gateway in front
   of it: no WAF, no authorizer, no throttling. `AuthType` is either `AWS_IAM` or **`NONE`**, and a
   console-created URL with CORS ticked allows **all origins** by default. They surface in JS
   bundles and mobile binaries; CT logs are useless for them.
5. **Takeover candidates, by fingerprint.** The still-vulnerable set is narrow — S3 website
   endpoints, Elastic Beanstalk, Bitbucket, Cargo Collective, Pantheon, Readme.io, Uberflip,
   WordPress. Come back with the CNAME, the provider response and the fingerprint that matched.
6. **Metadata-service exposure priors.** IMDSv2-by-default (2024) is **not retroactive** and does
   not prevent anyone launching v1-enabled instances. The older the workload fingerprint, the
   higher the IMDSv1 prior. On serverless and container platforms the credentials endpoint is a
   different address entirely, so a v1-shaped test proves nothing there.
7. **Coverage honesty.** Which providers you covered, which you did not, and which asset classes
   were excluded by scope rather than by absence.

## Known traps

- **Bucket name-guessing died twice, and most methodology has absorbed neither.** April 2023: Block
  Public Access is auto-enabled and ACLs auto-disabled for **all new buckets**, with *no change for
  existing buckets* — so the open population is a **fixed, shrinking, pre-2023 cohort**. March
  2026: S3 introduced **account-regional namespaces**, where a new bucket name need only be unique
  within an account and region. **Permutation can no longer reach new infrastructure at all.**
  Run legacy name lists **one-shot, never as a standing job**, and label the result as archaeology.
- **"8.7% of S3 buckets are still open" is unsupported.** It traces to a social post citing an
  index whose denominator is *the buckets it had already indexed*. Survivorship-biased; do not use
  it as a base rate, and do not repeat it in a report.
- **Proving a takeover by claiming the resource is prohibited, not clever.** AWS's own customer
  penetration-testing policy lists **"S3 bucket takeover; Subdomain Takeover"** among prohibited
  activities. Registering the name is also hostile to a third party if you guessed the owner wrong,
  and it is unnecessary: triage accepts the fingerprint. **Fingerprint, never claim.**
- **A public-by-design key is not a finding.** BaaS API keys, browser map keys, publishable payment
  keys and error-reporting DSNs are documented as safe to embed. Reporting one is an instant N/A
  and a triage-reputation cost. Report the missing restriction or the permissive rule instead.
- **The 2019 takeover fingerprint list is mostly dead weight.** Managed load balancers, the major
  CDNs, GitHub Pages, Google Cloud Storage, Heroku, Netlify, Shopify, Statuspage, Webflow and
  Zendesk are no longer takeable via the classic dangling-CNAME path. Scanning for them is the
  definition of volume without signal. But note the standing correction in the research: *provider
  added domain verification* does **not** by itself mean the provider is safe — verify the current
  state of the specific service rather than trusting either list wholesale.
- **A cloud resource is often not the target's property.** A bucket referenced by the site may
  belong to a vendor, an agency or a customer. Establish ownership before you test it, and treat
  ambiguity as out of scope until the program says otherwise.
- **CT logs and DNS do not see most of this surface.** Function URLs, BaaS projects and storage
  accessed by direct URL leave no name in the zone. If your only sources were passive DNS and
  certificates, say so — the gap is knowable and it is large.

## Outputs

- `@cloud` — one row per resource: provider · resource identity · how it was discovered · read
  state · **write state** · the named consumer, or explicitly none established.
- Facts via `kb.py add` — the provider mix, account identifiers recovered and how, BaaS projects
  and their rule posture, function URLs and their auth type. `observed` needs an evidence pointer.
- Leads into `@target` — writeable resources, unauthenticated function URLs, takeover candidates
  with their fingerprint, and any resource whose consumer is the production origin.
- Coverage note recorded next to the data: providers covered, asset classes skipped, and the fact
  that any name-guessing stage could only have reached legacy assets.

## Exit criteria

Every resource row names its provider, its discovery source and its **read/write state separately**
— a row that only says "public" has not finished. Every BaaS project is characterised by its rules
rather than by its config block. Any takeover candidate is recorded as a fingerprint, with no
resource claimed. If a name-guessing pass ran, it is marked one-shot and legacy-only. What you did
not cover is written down beside what you did.

## Next

Offer, do not choose: `derive-properties` (turn these resources and function URLs into propertied
entrypoints — this is what makes them testable) · `repository-and-secret-recon` (account
identifiers and provider credentials live in code, and each stage feeds the other) ·
`javascript-analysis` (if the bundles were not mined, the highest-yield input to this skill is
still unread) · `vuln-hunt` on a specific writeable resource or unauthenticated function URL.
