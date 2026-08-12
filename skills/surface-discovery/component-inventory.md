---
name: component-inventory
description: What is this built out of, at which version, and how sure are you. Use for "component inventory" and closely related asks.
---

# component-inventory — what is this built out of, at which version, and how sure are you

> Read `skills/shared/_recon-method.md` first — it holds the loop, the input rule and the tool contract.
> This file holds what is specific to components and versions.
>
> **This is the n-day *selector*.** `technology-fingerprinting` answers *what stack is this* —
> nginx, Rails, a CDN. That is an identity with no version column, and nothing can select a cohort
> on it. This skill produces rows something can act on: `(host, component, version, precision)`.
> Value is a version with the evidence that established it. Non-value is a plausible list of what
> the organisation probably uses, assembled by searching the web first and matching afterwards.

## Objective

Produce one row per `(host, component, version, precision)` with the artifact that established each
version, so a published advisory can be turned into a selector instead of a guess. Most of this is
extraction from evidence already collected, not research: the web is used at the end, to pin the
component's canonical identity and to check whether a pinned version falls inside an affected
range.

## Inputs

**Enrichment — each absent one narrows the run, none of them gates it:**

- `@tech` (optional, from `technology-fingerprinting`) — the starting set of identities. Treat it
  as a list of things to version, not as an answer.
- `@raw.http` (optional, from `http-probing`) — headers, error pages and asset URLs already paid for.
  Nearly every banner-level signal is already in here; re-probing to get it is traffic spent twice.
- `@js` (optional, from `javascript-analysis`) — normalized bundle findings and version constants.
- `@raw.js` (optional, from `javascript-analysis`) — sourcemaps and vendored library trees. Together
  with the normalized findings, this is the richest source of exact versions on a modern
  application.
- `@content` (optional, from `content-discovery`) — manifests, lockfiles and changelogs that
  shipped by accident.
- `@endpoints` (optional, from `api-discovery`) — build-info and health endpoints where the
  application states its own version.

**As the selector, at least one of the following:**

- `@hunter.host` — one exact application the hunter named. Inventory only components attributable
  to that host; absence of prior artifacts lowers precision rather than blocking the run.
- `@hosts.live` (from `http-probing`) — the multi-host set the component rows attach to.

## Signals — what to come back with

1. **Rows, not prose.** `(host, component, version, precision, evidence)`. The evidence pointer is
   part of the row, not a footnote: a version with no artifact behind it cannot be re-checked and
   will be re-derived wrongly by the next person.
2. **Graded precision, never assumed.** Confidence is a property of the *source*, in this order:
   lockfiles and manifests · sourcemaps and bundled version constants · static-asset hashes
   matching a known release · build identifiers · error-page fingerprints · favicon (which gives
   the **product**, not the version) · banners, which are LOW. Record which rung produced the row.
3. **`precision: unknown` as real data.** It means *present, version not established* — which is a
   different fact from absent, and the difference is load-bearing. A component known to be present
   at an unknown version is a candidate for one targeted follow-up; a component nobody has seen is
   not. Never leave it blank, never fill it from a release date, and never let it silently merge
   into the exact set.
4. **The components nobody fingerprints.** The rich-text editor, the PDF generator, the image
   resizer, the SSO library, the GraphQL server, the file-upload widget, the XML parser. Stack
   fingerprinting names the framework and stops; n-days live in the parts the framework pulled in.
5. **Two independent artifact-level signals before anything acts on a version.** Backported patches
   exist inside affected ranges — a distribution or a vendor can ship a fixed build that still
   reports an affected version string. **Version enumeration establishes candidacy, never
   exploitability.** One banner is a hypothesis; a banner plus a matching asset hash is a selector.
6. **Where n-day genuinely pays: latency.** Internet-facing appliances and management interfaces
   within hours to days of a disclosure. Running public templates weeks later competes on a latency
   you do not have, against everyone else running the same templates. If the disclosure is old, the
   inventory is still worth building — but say plainly that the sweep is unlikely to be first.
7. **The three counts, unmerged.** How many components are exact, how many bounded, how many
   unknown. Merging them into "N components identified" destroys the only number that matters.

## Known traps

- **A banner is a claim, not an observation of code.** Products lie, proxies rewrite, and operators
  set the header by hand. Banner-only rows belong at the bottom rung and must be labelled there.
- **[FOLKLORE, unproven either way] that banner-detected known-vulns convert at scale.** It is
  repeated everywhere and there is no published data supporting or refuting it. Do not build a
  workload on it and do not report it as a rationale.
- **A vendored copy lies about its version.** Forked and patched libraries keep the upstream
  version string long after the vulnerable code was fixed — or long after it was kept.
- **A library present in a bundle is not necessarily reachable.** Tree-shaking, dead code and
  admin-only paths mean present ≠ exploitable. The inventory records presence; reachability is a
  separate question, and it is not this skill's to answer.
- **A CDN-hosted library belongs to the CDN, not the target.** Record where each asset is served
  from, or the inventory quietly attributes third-party infrastructure to the program.
- **A version inferred from a release date is not a version.** It is a guess with a number in it,
  and it produces sweeps against hosts that were never affected — traffic spent for nothing against
  a program that counts requests.
- **Searching the web first inverts the method.** Research-led inventories describe what a company
  of this shape probably runs. Extraction-led inventories describe what this estate actually
  serves. Only the second one can be evidenced.
- **A row that never reaches the ledger is invisible to selection.** The table is for humans; the
  recorded facts are what a cohort query reads. Writing only the table is the most common way this
  skill's output ends up unused.
- **Fingerprint drift.** A component identity that no longer matches how advisories name it will
  never match a selector. Pin the canonical name at the same time as the version.

## Outputs

- `@components` — one row per `(host, component, version, precision, evidence)`, with the source
  rung that established the version and where the asset was served from.
- Facts via `kb.py add` for every row that has a version, so cohort selection can read them.
  `observed` requires the evidence pointer.
- Leads into `@target` — components that are exact, widely deployed and old; and any internet-facing
  appliance whose version is close to a recent disclosure.
- The three counts (exact · bounded · unknown), recorded unmerged, plus which hosts were not covered.

## Exit criteria

Every row carries a precision grade and an evidence pointer, and `unknown` appears where it is
true. The exact, bounded and unknown counts are reported separately. Nothing has been promoted to
"vulnerable" on a single version signal. The rows exist as recorded facts, not only as a table.
Which hosts and which artifact types were not examined is written down beside the counts.

## Next

Offer, do not choose: `derive-properties` (turn versioned components into propertied entrypoints —
this is what makes them testable) · `host-correlation-and-clustering` (a shared component set is a
much stronger cluster signal than a shared banner) · `technology-fingerprinting` (if the identity
set was thin, this skill had nothing to version) · `content-discovery` on a specific host where one
targeted path would settle an `unknown` into an exact version.
