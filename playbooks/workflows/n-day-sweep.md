# n-day sweep — one check across a tech cohort

> *A public vulnerability drops. You have a fingerprinted estate. Which of your hosts is
> affected?* That is a legitimate and standard question — and it is also the easiest way in this
> workspace to send thousands of attack requests by accident.
>
> The shape is fixed and the tooling enforces it:
> **select by fingerprint → PILOT one host → a human reads it → scale → confirm individually.**

---

## Why a cohort is not a spray

Rule 4 says *no mass requests*. A cohort sweep looks exactly like the thing that forbids. The
distinction that makes it legitimate:

| | |
|---|---|
| **spraying** | firing a payload at everything because you can, hoping something sticks |
| **a cohort** | a set selected by evidence — *these hosts run this version* — checked with one discriminator that is expected to be negative almost everywhere |

If you cannot say **why each host is in the cohort**, you are spraying. `kb.py cohort` prints the
evidence per host for exactly this reason.

## 1. Select — no traffic at all

```
tools/kb.py cohort targets/<t> --tech "Ruby on Rails" --version-lt 7.0.5 --out /tmp/c.txt
```

Read what it tells you, because two of its warnings change what a sweep can prove:

- **`reported` vs `observed`.** A banner is set by whatever is in front of the app and can be
  wrong in both directions. A cohort built from banners means a clean sweep has **not** cleared
  the hosts whose banner lied.
- **Unversioned hosts are excluded from a version filter and listed separately.** *Unversioned is
  not "not vulnerable."* Fingerprint them before writing them off — that list is often where the
  finding actually is, because everyone else's tooling silently dropped it too.

If the cohort is empty, stop. An empty sweep is not a clean sweep; it means you have no tech data,
which is a recon gap, not a result.

## 2. Pick a discriminator, not an exploit

The check must answer *"is this host affected"* without doing damage. In order of preference:

1. **Version confirmation** — the app tells you its version, or a behaviour differs between
   patched and unpatched. Cheapest, safest, and usually sufficient to build the cohort down to a
   handful.
2. **A benign behavioural difference** — a parse quirk, an error shape, a header only the
   vulnerable code path emits.
3. **Out-of-band callback** — a unique per-host subdomain so a hit is attributable. Correct for
   the Log4j class, where nothing observable comes back in-band.
4. **Actual exploitation** — **not here.** That is a single-host `vuln-hunt` run with a stored
   artifact, after the sweep has narrowed the field.

`tools/sweep.py` refuses a check containing file deletion, disk writes, reverse shells, pipes to a
shell, fork bombs, or destructive SQL. Not advice — it exits 2. A destructive check is bad once
and catastrophic across a cohort.

## 3. Pilot — one host, and you read the output

```
tools/sweep.py targets/<t> --cohort /tmp/c.txt --rate <program limit> \
    --header '<required header>' --nuclei CVE-2024-XXXXX
```

Without `--scale` it touches exactly one host and prints everything. Two questions the pilot
exists to answer, and only a human can:

- **Did the check discriminate, or would it match anything?** A template that fires on every 200
  will "find" the whole cohort.
- **Is a hit here real, or the app's normal behaviour?** This is where soft-404s and catch-all
  routes turn a sweep into fiction.

A check that is wrong is wrong once in a pilot and N times at scale.

## 4. Scale — deliberately awkward

```
tools/sweep.py … --scale --yes
```

`--scale` alone is refused; it needs `--yes` as well, and it tells you the host count first. The
rate limit and the attribution header travel on every request. Raw output stays on the VPS under
`raw/sweeps/`.

## 5. Hits are HYPOTHESES

Everything the sweep finds is written to `hypotheses.md`, flagged as hypotheses, with a pointer to
the raw output. **Nothing goes to `tested.md` and nothing goes to `findings/`.**

A scanner match is a reason to go and look. Confirmation is a separate, manual, one-host job:
`vuln-hunt` with the class file, an oracle declared before you look, and a stored
request/response. Only then does a row appear in `tested.md` with its `fix_locus`.

**Dedup matters more than usual here.** Twelve hosts affected by one CVE, all patched by the same
deployment, is **one** `fix_locus` — one finding, not twelve. Reporting it twelve times is how a
researcher gets a reputation rather than a bounty. If they are genuinely separate deployments with
separate owners, that is a different answer — but you have to establish it, not assume it.

## 6. Record what a clean sweep actually proved

If nothing hit, write that down with its limits: *which* cohort, built from *what* evidence, on
*what* date, with *which* check. "We swept for X and found nothing" is worth keeping only if a
future reader can tell whether the cohort was trustworthy.

## Exit
Report: cohort size and how it was built, the pilot verdict, hits as hypotheses, and the hosts you
**could not** place in or out of the cohort. That last set is the honest part of any sweep.
