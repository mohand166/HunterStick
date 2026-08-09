# Adaptive Tooling — think, then configure

**There are no hardcoded tool recipes in this workspace.** Every example command in a
recon/vuln skill is a *starting point*, not a fixed incantation. You choose and reframe
tool options based on how *this* target actually behaves. A tool is only as good as the
signal you configure it to isolate — and the right signal is discovered, not assumed.

This is the same researcher discipline as the vuln loop: observe → hypothesize about the
right discriminator → configure the tool to expose it → verify → iterate.

---

## The loop for configuring any tool

> **`tools/calibrate.py` performs steps 1-2 and records the verdict.** It requests the
> baseline plus three paths that cannot exist, compares status/length/words/redirect, and
> emits the `kb.py add --predicate calibration` line with an evidence artifact. Reach for it
> before doing this by hand — the gate went UNRECORDED for a whole engagement precisely
> because satisfying it was manual.

1. **Calibrate a baseline.** Before fuzzing/scanning, send a *known-valid* and a
   *known-invalid* request and record every response dimension: status, content-length,
   word count, line count, response time, redirect target, distinctive body markers.
   You cannot filter signal from noise until you know what noise looks like *here*.
2. **Pick the discriminator.** Decide which dimension actually separates hit from miss
   on this target. It is often **not** the status code.
3. **Configure the tool to isolate it.** Set match/filter options to that dimension.
   Re-frame the tool the moment the target's behavior changes.
4. **Verify a sample.** Manually confirm a few "hits" are real before trusting the run.
5. **Iterate.** If the target adapts (rate-limits, starts returning a WAF page), recalibrate.

---

## Worked example — ffuf against a soft-404 backend

You're doing content discovery and the backend returns **`200 OK` for every path**
(SPA catch-all / soft-404). Default `-mc 200` matches everything → useless.

- **Calibrate:** request a real path and a random one. You observe valid pages are
  ~14 KB and the catch-all is a constant ~2,048 bytes.
- **Discriminator:** content-length, not status.
- **Reframe ffuf:** filter out the catch-all size instead of matching status —
  `ffuf -w corpus.txt -u https://host/FUZZ -fs 2048` (or `-fw`/`-fl` if size varies but
  word/line count is stable; `-ac` to auto-calibrate; regex `-fr` on a catch-all marker
  if the body is dynamic).
- **Verify:** open two "hits" — confirm they're distinct real pages, not padded 404s.

The point isn't the flags — it's that you *noticed the 200-for-everything behavior and
changed your detection strategy to match it.* Do that for every tool.

---

## Same thinking, other tools (illustrative, not prescriptive)

- **httpx** — the flags depend on the job: liveness vs tech-fingerprint vs favicon-hash
  vs screenshot vs cert-SAN extraction each need different options. Ask "what signal am I
  collecting right now?" and select accordingly; don't run one bloated invocation for
  everything.
- **nuclei** — scope templates to what recon actually found (tags/severity/tech) rather
  than firing everything; tune concurrency/rate to the target's tolerance.
- **katana / crawlers** — depth, JS-parsing, scope, and out-of-scope filtering change per
  target size and whether it's an SPA.
- **naabu / nmap** — top-ports sweep vs full/service-version scan are different phases
  with different rate/noise trade-offs.
- **arjun / param mining** — the wordlist and the "changed behavior" heuristic depend on
  whether the endpoint reflects, errors, or silently ignores unknown params.

---

## Seen it before?

`calibration-quirks.md` is the cross-target log of behaviours that already broke someone's output
— soft-404s, catch-all redirects, edge-provider oddities — with the discriminator that fixed each.
**Read it when the calibration gate fires**, and **append to it** when a quirk you hit is a
property of the stack rather than of one host.

## Wordlists are selected inputs, not defaults

Choose the list from the target's evidence: route tables and schemas first, then paths and names
from its URLs, JavaScript, components and prior runs, then a technology-specific installed list.
A small generic directory list is the fallback. A request for **paths, not files** means exactly
that: no extension expansion, backup-name multiplication or filename corpus unless the hunter
changes the objective.

When the applicable external list is not installed, download it on the VPS during the run instead
of substituting an unrelated list or stopping. Record the source URL and retrieval date in the run
note; verify the file is nonempty and inspect a sample before use. Passing it to `run.py` records
its content hash with the command, so a later session can identify the exact bytes that produced
the result. Reusable vocabulary derived from the target belongs in `recon/wordlists/`; large public
corpora stay in the VPS wordlist store.

## Rules

- Never paste a command without knowing what each flag does *for this target*.
- When a skill shows a command, treat it as a labeled default and adapt it.
- If you changed a tool's configuration in response to observed behavior, **say so** in
  your summary (it's part of the evidence trail).
- If you couldn't find a reliable discriminator, report that honestly — don't ship a run
  you know is full of false positives.
