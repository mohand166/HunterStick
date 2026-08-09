# Import captured traffic — HAR, Burp XML, sitemap

> *A **lens**, not a vuln class. The human hands you an hour of browsing: a HAR from devtools, a
> Burp "Save items" export, a sitemap dump. Turn it into structured surface the rest of the
> workspace can compute over.*
>
> **This is the human-directed entry point at bulk.** Same rules as `analyse-request.md`, applied
> to hundreds of requests instead of one: **the importer stops on an unrecognised host**,
> credentials are stripped once and correctly, and **an import is not a test**.

---

## Why this matters more than it looks

Manual browsing is the only input that never became structured surface. You click through an app,
Burp records 900 requests, and none of it reaches `attack-surface.md` — so `tools/coverage.py`
keeps confidently describing a surface that is missing everything you actually looked at. The
"untested" list is only honest if the *tested-able* list is complete.

## 1. Run it

```
tools/import-http.py targets/<t> capture.har            # dry run — always first
tools/import-http.py targets/<t> capture.har --write
```

Dry run is the default and there is no reason to skip it. Read the three sections it prints
before writing anything.

## 2. Which hosts land in the brain — the importer stops, and that is correct

This is **not** a scope gate on your work; nothing here decides what you may test. It protects the
*brain* from recording traffic you never meant to attribute to this target — which is a data
integrity rule, and the reason it lives in the importer rather than in a skill.

Every host in the capture is reconciled against `scope.md`, and the report separates
*"not in scope.md"* from *"explicitly out of scope"*. **A capture with an unrecognised host does
not import until you say where it belongs.**

This will fire constantly and that is the point: you had other tabs open, your own webmail was
loading, a CDN you never listed served an asset. Decide explicitly each time —

- authorized but unlisted → add it to `scope.md`, so the decision is recorded once;
- genuinely unrelated → `--allow-unscoped`, which **skips** those hosts and imports the rest.

Never blanket `--allow-unscoped` to make the message go away. The list it prints is the only
place you will see that your browser talked to something you did not intend to record.

## 3. Credentials — handled once, correctly

The tool names the credential *kinds* present (`bearer`, `cookie:SID`, `set-cookie`) and **never
prints or writes a value**. What it cannot do is know which principal they represent — that is
yours:

- put the session into `accounts.md` as the **named principal** (`user-a`, `admin`), with the
  capture date, so a stale token is later diagnosed as stale rather than mistaken for a fix;
- everywhere else the request is stored with `<accounts.md:user-a>` in its place.

A capture containing `set-cookie` tells you where sessions are *issued* — record that host's
`auth` observation; it is usually the most interesting host in the file.

## 4. What it derives, and what it deliberately does not

**Endpoints are templated.** `/orders/1837` and `/orders/9921` collapse to `/orders/{id}` with a
`seen` count. Without that a 900-request capture becomes 900 rows of noise and the file stops
being readable. The observed values are kept as evidence that the segment is an object reference.

**Properties come from the request shape**, using the `class-signals.md` vocabulary — `object-ref`,
`two-object`, `money`, `mass-bind`, `fetches-url`, `session-issue`, `cacheable`, and so on. Two id
segments in one path (`/orders/{id}/transfer/{id}`) is `two-object`, which is the strongest
single signal for authorization work in this whole workspace.

It writes `recon/endpoints.md` and host-level rows in `observations.tsv`. It does **not** write:

| not written | why |
|---|---|
| `accounts.md` | it never stores a credential; you name the principal |
| `attack-surface.md` | scoring is attack-surface-prioritization's job, on evidence — not an importer's guess |
| `tested.md` | **an import is not a test.** A row there means a probe was sent |

## 5. After

1. `tools/kb.py reassess targets/<t>` — what did this change? New hosts, new `serves`/`auth`
   observations, derived views now older than the evidence.
2. Append the new endpoints to `attack-surface.md` with `rank` **empty**. Scoring them is
   `attack-surface-prioritization`.
   Imported endpoints often rank high: they are real, exercised, authenticated flows, not guesses
   from a wordlist.
3. Only then `vuln-hunt`, one entrypoint and one class.

Re-importing the same capture is safe — it reports `0 not already in the brain` and writes
nothing.

## Exit
Report three numbers: hosts in scope, distinct endpoints, and **how many were new**. The third is
the only one that means anything.
