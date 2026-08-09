# Research a Component — what is publicly known, at this version

> You have a component and a version from `recon/components.md`. This establishes what the world
> already knows about it, and turns that into **hypotheses with a probe attached** — never into a
> finding.
>
> **The output of research is a claim someone else made.** It is `reported` at best. A CVE that
> says "affects < 3.6.0" plus a bundle that says `3.4.1` is `inferred`: the version could be
> vendored, the code path could be unreachable, the fix could be backported. The probe is what
> decides, and this workflow ends before the probe.

## When
- `component-inventory` produced a component with an **exact** or **bounded** version, and it is widely
  deployed, old, or both.
- A public n-day lands and you want to know whether this target is in range.
- A component is unfamiliar and you need to know what it *does* before you can guess how it breaks.

**Not** for the framework everyone already fingerprints. Rails and nginx are patched; the PDF
generator nobody names is not.

## Preconditions
- A row in `recon/components.md` with `precision` ≠ `unknown`. Researching an unknown version
  produces a list of every CVE the component ever had, which is the same as no list.
- The component is served by an **in-scope** host. A CDN-hosted library is the CDN's.

## Cost — state it before you start
Web research is the most expensive thing in this workspace. Bound it explicitly:

- **4–6 sources per component**, not "everything relevant"
- **one component per invocation** — a batch produces a wall of text nobody reads
- roughly 15–40k tokens depending on how much changelog you have to read

Say the bound out loud, and say what you dropped if you hit it. A silently truncated search reads
exactly like a thorough one.

## Steps

1. **Establish the canonical identity.** The name in a bundle is not the name in an advisory —
   `jquery` vs `jQuery` vs `jquery-ui`, `pdf.js` vs `pdfjs-dist`. Get the package identifier the
   ecosystem actually uses, because every later lookup keys on it.
2. **Get the version timeline.** Current stable, and the release that fixed each known issue. The
   useful artifact is *fixed-in*, not *affected* — `fixed in 3.6.0` is what `--version-lt` takes.
3. **Read the four source types, in this order.** Stop when the answer is settled:
   - the project's **security advisory page or `SECURITY.md`** — authoritative, and usually states
     the affected range precisely
   - the **changelog / release notes** between the pinned version and the fix — this is where
     silently-patched bugs live, the ones with no CVE
   - **GitHub issues and PRs** touching the affected code — often carry a working reproduction
   - **disclosed reports** mentioning the component — how it was actually exploited in an app,
     which is the part advisories never say
4. **Decide reachability, honestly.** For each candidate issue: which entrypoint on *this* target
   would reach that code? If you cannot name one, the hypothesis is *"the component is present"*,
   not *"the target is vulnerable"*. Say which one it is.
5. **Write hypotheses, not findings.** One row per candidate in `hypotheses.md`, each carrying:
   - the component, the pinned version, and the fixed-in version
   - the entrypoint you believe reaches it
   - **the expected signal** — what the response looks like if this is real, and what it looks
     like if the version was backported
   - the source URL for every claim
6. **Record the research itself in the ledger,** so the next session does not repeat it:
   ```
   tools/kb.py add <target> --subject <component> --predicate has-advisory \
       --object "CVE-… fixed in 3.6.0" --confidence reported --source "<url>"
   ```
   This is the caching. Research is expensive once and free thereafter — but only if it is written
   down where `kb.py` will find it.

## Then, if a cohort exists
A component on one host is a test. A component on forty hosts is a sweep:
```
tools/kb.py cohort <target> --tech <component> --version-lt <fixed-in> --out /tmp/cohort.txt
tools/sweep.py <target> --cohort /tmp/cohort.txt --rate <limit> --nuclei <template>
```
`sweep.py` is pilot-gated: one host, full output shown, before anything scales.
→ `playbooks/workflows/n-day-sweep.md`

## Aborts
- **The advisory has no affected range**, only "upgrade" → you cannot build a version selector.
  Record it as unbounded and test the entrypoint directly instead.
- **The component is vendored or forked** → the version string is not evidence. Move it to the
  vendored section of `components.md` and test behaviour rather than version.
- **Everything you find is a denial-of-service issue** → out of scope for essentially every
  program, and testing it is the fastest way to get removed from one. Stop.
- **The version is `unknown`** → you are in the wrong workflow; finish component-inventory for this component.

## Output
- `hypotheses.md` — candidates with entrypoint, expected signal and source URL
- `observations.tsv` — the advisory facts, `reported`, with URLs, so this is never re-researched
- `recon/components.md` — the `fixed-in` version added to the row

## Exit
Say plainly what was established and what was not: *"pdf.js 2.11 pinned exact, fixed-in 2.16 for
CVE-…, reachable via the export endpoint on 3 hosts — hypothesis written, not tested."* If the
research settled nothing, say that too. **"No known issues at this version" is a result**, and it
is worth recording so nobody spends the tokens again.
