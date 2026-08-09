# Calibration Quirks — behaviours worth recognizing again

> Cross-target memory for the **calibration gate**. `adaptive-tooling.md` is the *method* — how to
> calibrate any tool against any target. This file is the *log*: specific behaviours that already
> broke someone's output once, and the discriminator that fixed it.
>
> It exists because **an uncalibrated tool is a random-number generator with a progress bar**, and
> the same handful of quirks recur across targets that share a stack or an edge provider. The
> second time you meet one, recognizing it should cost seconds.

**Write here when** a calibration step surprised you *and* the surprise is a property of the
stack/edge rather than of that one host — i.e. you expect to meet it again. Anything target-specific
belongs in `targets/<t>/target.md`, not here.

**Read here when** the calibration gate fires (soft-404, catch-all redirect, WAF interference) —
before you go and re-derive a discriminator someone already found.

---

## Entry format

```markdown
## <quirk, in one line>
seen on: <target slug(s)> · stack/edge: <nginx · Akamai · Cloudflare · ATS · Envoy · …>

**What it does to output** — e.g. "catch-all 301 to /home for every unknown path, identical
content-length, so every wordlist entry looks like a hit."

**The discriminator** — what actually separates real from fake: response length, a header, a
timing band, a body token, a differing redirect target.

**Which phases it breaks if missed** — e.g. 11 content-discovery, 13 api-discovery,
14 parameter-discovery. Their counts become fiction, and 21 then ranks that fiction.
```

Keep each entry to those four lines. A quirk that needs an essay is a target note, not a pattern.

---

## Entries

*(empty — add the first one the next time the calibration gate fires)*

---

## The two that justify the file

Not yet observed here, but they are the canonical shapes, and they are why the gate exists at all:

- **Soft-404** — the host answers `200` for a path that cannot exist. Every content-discovery hit
  is a false positive. Discriminate on **body length or a body token**, never on status.
- **Catch-all redirect** — `301` to a marketing or login page for everything unknown, with an
  identical content-length. Looks like a clean 404 regime to a tool that only reads status codes.

Both have the same failure signature: **the counts look great and mean nothing.** Establish the
baseline with a path you *know* cannot exist (a random string) before trusting any discovery run.
