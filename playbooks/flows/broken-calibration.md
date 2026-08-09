# Flow — broken calibration

> **Run this before any other flow when it applies.** A host that answers 200 to a path you invented
> is not a host with content; it is a host with no 404. Every number produced after that point is
> fiction, and the fiction is *confident* — 40,000 "discovered" paths that are one wildcard handler.

## Situation
- A random, certainly-nonexistent path returns **200**, or
- every path **301/302s to the same place** with the same content length, or
- content discovery just returned an implausible hit rate (>20% on a real app).

## Preconditions
One live host. Nothing else. This flow is cheap and runs before the expensive ones.

## Steps

1. **Establish the baseline.** Request 3 paths that cannot exist (long random strings, one with a
   plausible extension). Record status, length, and a content hash for each.
2. **Find the discriminator.** Compare against a path you know exists. What actually differs —
   status, byte length, a title string, a redirect target, a header, response time? One reliable
   difference is enough; write it down as a rule.
   → `playbooks/system/adaptive-tooling.md` (calibrate, never paste flags blind)
3. **Check whether the quirk is already known.** `playbooks/system/calibration-quirks.md`. If this
   stack has burned someone before, the discriminator may already be written.
4. **Encode it in the tool.** `ffuf -fs`, `-fc`, `-fr`, or a filter on the recorded hash. Prove it:
   re-run the 3 impossible paths through the filter and confirm **zero** survive.
5. **Re-derive any count taken before this.** Content-discovery, parameter and endpoint numbers
   produced pre-calibration are void. Mark them so in `index.md` — do not leave them looking real.

## Aborts
- Cannot find any discriminator → **STOP.** Say the host is not safely fuzzable and why. Guessing a
  filter is how you get 40,000 phantom hits.
- The quirk is a property of the whole stack, not this host → append it to `calibration-quirks.md`
  before continuing, so the next target inherits it.

## Cost
~10 requests. The cheapest flow here, and the one that decides whether every later number is real.

## Output
- The discriminator recorded in `index.md` (or `applications/<host>/notes.md` if host-specific).
- `calibration-quirks.md` appended when the quirk generalizes.
- Any voided counts explicitly marked as void.

## Exit
State the discriminator and what it filters. Then the flow you were originally going to run is
unblocked — name it and stop.
