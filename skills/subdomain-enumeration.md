---
name: subdomain-enumeration
description: Find the names, prove they resolve, keep the ones that are real. Use for "subdomain enumeration" and closely related asks.
---

# subdomain-enumeration — find the names, prove they resolve, keep the ones that are real

> Read `skills/_recon-method.md` first — it holds the loop, the input rule and the tool contract.
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

## Outputs

- `@hosts.all` — clean, deduped, resolving.
- The naming grammar, its exceptions and the privilege-asserting names → `@target` (Patterns,
  Exceptions, Interesting leads).
- Facts via `kb.py add` for wildcard parents found, sources that ran, and the new-versus-total split.

## Exit criteria

The set is deduped and independently wildcard-verified — not merely filtered by the tool that
produced it. The delta against the previous run is stated. The naming grammar is written down where
the next run can use it. Which sources ran, and which could not, is recorded.

## Next

Offer: `dns-analysis` (resolve records, find dangling CNAMEs and the takeover candidates) ·
`live-host-validation` (which of these answer anything) · `http-probing` (straight to what speaks
HTTP, if the estate is small enough that liveness adds nothing) · re-run this skill with a source
or wordlist that was missing.
